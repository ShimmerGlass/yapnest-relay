package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"sync"
	"time"
)

const (
	apnsProduction = "https://api.push.apple.com"
	apnsSandbox    = "https://api.sandbox.push.apple.com"
	// Apple refuses tokens older than an hour and too-frequent new ones: renew well within the hour.
	tokenLifetime = 40 * time.Minute
)

// apns sends alerts through Apple's HTTP/2 API, signed with a .p8 key (token-based authentication).
type apns struct {
	key        *ecdsa.PrivateKey
	keyID      string
	teamID     string
	topic      string // the app's bundle id
	production string
	sandbox    string
	client     *http.Client
	metrics    *metrics // may be nil

	mu       sync.Mutex
	token    string
	issuedAt time.Time
}

func parseP8(data []byte) (*ecdsa.PrivateKey, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, errors.New("the APNs key isn't PEM")
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("the APNs key: %w", err)
	}
	key, ok := parsed.(*ecdsa.PrivateKey)
	if !ok {
		return nil, errors.New("the APNs key isn't an EC key")
	}
	return key, nil
}

// pushError is Apple's refusal. Gone means the token will never work again: the app was removed, or the token
// belongs to another environment. Refusals that blame the relay's own topic or key (DeviceTokenNotForTopic,
// TopicDisallowed) hit every token, so they aren't Gone.
type pushError struct {
	Status int
	Reason string
}

func (e *pushError) Error() string { return fmt.Sprintf("APNs %d %s", e.Status, e.Reason) }

func (e *pushError) Gone() bool {
	switch e.Reason {
	case "Unregistered", "BadDeviceToken":
		return true
	}
	return e.Status == http.StatusGone
}

// outcome is the refusal as a metrics label. A dead token counts as gone even though Apple answers some of them
// with a 400 or 403.
func (e *pushError) outcome() string {
	switch {
	case e.Gone():
		return "gone"
	case e.Status == http.StatusForbidden:
		return "forbidden"
	case e.Status == http.StatusTooManyRequests:
		return "too_many"
	case e.Status >= 500:
		return "server_error"
	}
	return "bad_request"
}

// The alert carries no content: the app's notification service extension fetches and decrypts the message,
// then replaces it. mutable-content is what wakes the extension.
var alertPayload = []byte(`{"aps":{"alert":{"title":"Yapnest","body":"New message"},"sound":"default","mutable-content":1}}`)

// noMessagePayload is the alert for a publish whose summary says it announces no message: ejabberd sends none for
// what has no body (a read marker, a reaction, a presence, a call). The extension shows nothing for it when it can't
// fetch, where it would show "New message" for one that may be a message. Only that bit of the summary goes to Apple.
var noMessagePayload = []byte(`{"aps":{"alert":{"title":"Yapnest","body":"New message"},"sound":"default","mutable-content":1},"noMessage":true}`)

// A background push has nothing to show: it only wakes the app itself, not the notification extension, for a
// publish the server didn't think important.
var backgroundPayload = []byte(`{"aps":{"content-available":1}}`)

// push sends an alert, or with background a silent push that wakes the app without showing anything. noMessage
// marks an alert for a publish that announces no message (noMessagePayload).
func (a *apns) push(ctx context.Context, r registration, background, noMessage bool) error {
	token, err := a.providerToken()
	if err != nil {
		return err
	}
	err = a.send(ctx, r, token, background, noMessage)
	var refused *pushError
	if errors.As(err, &refused) && refused.Reason == "ExpiredProviderToken" {
		// Sign a new one, unless another push already did, and try once more. InvalidProviderToken is not
		// retried: the key, key id or team is wrong, and signing again for every push would only get the relay
		// refused for renewing too often.
		a.mu.Lock()
		if a.token == token {
			a.token = ""
		}
		a.mu.Unlock()
		if token, err = a.providerToken(); err != nil {
			return err
		}
		err = a.send(ctx, r, token, background, noMessage)
	}
	return err
}

// send is one request to APNs, authenticated with the provider token.
func (a *apns) send(ctx context.Context, r registration, token string, background, noMessage bool) error {
	env := r.environment()
	base := a.production
	if r.Sandbox {
		base = a.sandbox
	}
	var payload []byte
	var pushType, priority string
	var expiration int64
	if background {
		// Apple requires priority 5 for a background push. It expires at once (0: tried once, never stored), as a
		// wake for a phone that was offline has nothing to catch up on that a later push wouldn't, and a stored one
		// would only be delivered late and count against the app's throttled background budget.
		payload, pushType, priority, expiration = backgroundPayload, "background", "5", 0
	} else {
		// Apple keeps the latest alert for a phone that's offline, for a day.
		payload, pushType, priority = alertPayload, "alert", "10"
		if noMessage {
			payload = noMessagePayload
		}
		expiration = time.Now().Add(24 * time.Hour).Unix()
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, base+"/3/device/"+hex.EncodeToString(r.Token), bytes.NewReader(payload))
	if err != nil {
		return withoutURL(err)
	}
	req.Header.Set("authorization", "bearer "+token)
	req.Header.Set("apns-topic", a.topic)
	req.Header.Set("apns-push-type", pushType)
	req.Header.Set("apns-priority", priority)
	req.Header.Set("apns-expiration", strconv.FormatInt(expiration, 10))

	start := time.Now()
	resp, err := a.client.Do(req)
	if err != nil {
		a.metrics.apnsRequest(env, "network_error", time.Since(start))
		return withoutURL(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusOK {
		a.metrics.apnsRequest(env, "ok", time.Since(start))
		return nil
	}
	var body struct{ Reason string }
	_ = json.NewDecoder(resp.Body).Decode(&body)
	refusal := &pushError{Status: resp.StatusCode, Reason: body.Reason}
	a.metrics.apnsRequest(env, refusal.outcome(), time.Since(start))
	return refusal
}

// withoutURL drops the URL from a request's error: it holds the device token, and the error ends up in the logs.
func withoutURL(err error) error {
	var ue *url.Error
	if errors.As(err, &ue) {
		err = ue.Err
	}
	return fmt.Errorf("APNs request: %w", err)
}

// providerToken is the ES256 JWT Apple authenticates the relay with, reused until it nears its expiry.
func (a *apns) providerToken() (string, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.token != "" && time.Since(a.issuedAt) < tokenLifetime {
		return a.token, nil
	}
	now := time.Now()
	header, _ := json.Marshal(map[string]string{"alg": "ES256", "kid": a.keyID})
	claims, _ := json.Marshal(map[string]any{"iss": a.teamID, "iat": now.Unix()})
	enc := base64.RawURLEncoding
	signed := enc.EncodeToString(header) + "." + enc.EncodeToString(claims)
	digest := sha256.Sum256([]byte(signed))
	r, s, err := ecdsa.Sign(rand.Reader, a.key, digest[:])
	if err != nil {
		return "", err
	}
	// JWS wants r and s as fixed-size big-endian integers, not ASN.1.
	sig := make([]byte, 64)
	r.FillBytes(sig[:32])
	s.FillBytes(sig[32:])
	a.token = signed + "." + enc.EncodeToString(sig)
	a.issuedAt = now
	return a.token, nil
}
