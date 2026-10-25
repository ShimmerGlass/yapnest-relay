package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"encoding/xml"
	"fmt"
	"io"
	"log"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

var testToken = bytes.Repeat([]byte{0xab}, 32)

func testSealer(t *testing.T) *sealer {
	s, err := newSealer(bytes.Repeat([]byte{7}, 32))
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestNodeRoundTrip(t *testing.T) {
	s := testSealer(t)
	reg := registration{Token: testToken, Sandbox: true, Owner: "Alice@Example.org/phone"}
	node, err := s.seal(reg)
	if err != nil {
		t.Fatal(err)
	}
	got, err := s.open(node)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got.Token, testToken) || !got.Sandbox || got.Owner != "alice@example.org" {
		t.Fatalf("got %+v", got)
	}

	// Registering again gives the same node, so the server replaces it rather than adding one.
	again, _ := s.seal(registration{Token: testToken, Sandbox: true, Owner: "alice@example.org"})
	if again != node {
		t.Fatal("sealing isn't deterministic")
	}
	other, _ := s.seal(registration{Token: testToken, Owner: "alice@example.org"})
	if other == node {
		t.Fatal("the environment doesn't change the node")
	}
}

func TestNodeTampering(t *testing.T) {
	s := testSealer(t)
	node, _ := s.seal(registration{Token: testToken, Owner: "alice@example.org"})
	raw, _ := base64.RawURLEncoding.DecodeString(node)
	raw[len(raw)-1] ^= 1
	for _, bad := range []string{"", "not base64!", base64.RawURLEncoding.EncodeToString(raw), "AAAA"} {
		if _, err := s.open(bad); err == nil {
			t.Errorf("opened %q", bad)
		}
	}
	otherKey, _ := newSealer(bytes.Repeat([]byte{8}, 32))
	if _, err := otherKey.open(node); err == nil {
		t.Error("opened with another key")
	}
}

func TestProviderToken(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der, _ := x509.MarshalPKCS8PrivateKey(key)
	parsed, err := parseP8(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
	if err != nil {
		t.Fatal(err)
	}
	a := &apns{key: parsed, keyID: "KEY123", teamID: "TEAM456"}
	token, err := a.providerToken()
	if err != nil {
		t.Fatal(err)
	}
	if !verifyES256(token, &key.PublicKey) {
		t.Fatal("bad signature")
	}
	parts := strings.Split(token, ".")
	header, _ := base64.RawURLEncoding.DecodeString(parts[0])
	claims, _ := base64.RawURLEncoding.DecodeString(parts[1])
	if string(header) != `{"alg":"ES256","kid":"KEY123"}` || !strings.Contains(string(claims), `"iss":"TEAM456"`) {
		t.Fatalf("header %s claims %s", header, claims)
	}
	if again, _ := a.providerToken(); again != token {
		t.Fatal("token not reused")
	}
}

func verifyES256(token string, pub *ecdsa.PublicKey) bool {
	i := strings.LastIndexByte(token, '.')
	sig, err := base64.RawURLEncoding.DecodeString(token[i+1:])
	if err != nil || len(sig) != 64 {
		return false
	}
	digest := sha256.Sum256([]byte(token[:i]))
	return ecdsa.Verify(pub, digest[:], new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:]))
}

// fakeServer is an XMPP server's component listener: it checks the handshake, then lets the test exchange
// stanzas with the component.
type fakeServer struct {
	t      *testing.T
	ln     net.Listener
	secret string
	conn   net.Conn
	dec    *xml.Decoder
	ready  chan struct{}
}

func newFakeServer(t *testing.T, secret string) *fakeServer {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s := &fakeServer{t: t, ln: ln, secret: secret, ready: make(chan struct{})}
	go s.accept()
	t.Cleanup(func() { ln.Close() })
	return s
}

func (s *fakeServer) accept() {
	conn, err := s.ln.Accept()
	if err != nil {
		return
	}
	s.conn = conn
	s.dec = xml.NewDecoder(conn)
	if _, err := nextElement(s.dec); err != nil {
		return
	}
	fmt.Fprintf(conn, "<stream:stream xmlns='%s' xmlns:stream='%s' from='push.example' id='abc123'>", nsComponent, nsStreams)
	var hs struct {
		Value string `xml:",chardata"`
	}
	start, _ := nextElement(s.dec)
	if err := s.dec.DecodeElement(&hs, &start); err != nil {
		return
	}
	want := sha1.Sum([]byte("abc123" + s.secret))
	if hs.Value != hex.EncodeToString(want[:]) {
		fmt.Fprint(conn, "<stream:error><not-authorized xmlns='urn:ietf:params:xml:ns:xmpp-streams'/></stream:error>")
		conn.Close()
		return
	}
	fmt.Fprint(conn, "<handshake/>")
	close(s.ready)
}

// exchange sends an iq and returns the component's answer.
func (s *fakeServer) exchange(iq string) stanza {
	s.t.Helper()
	select {
	case <-s.ready:
	case <-time.After(5 * time.Second):
		s.t.Fatal("component never connected")
	}
	if _, err := io.WriteString(s.conn, iq); err != nil {
		s.t.Fatal(err)
	}
	_ = s.conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	start, err := nextElement(s.dec)
	if err != nil {
		s.t.Fatal(err)
	}
	var st stanza
	if err := s.dec.DecodeElement(&st, &start); err != nil {
		s.t.Fatal(err)
	}
	return st
}

// publishXML is the pubsub payload of a push notification to node, with a summary that must stay out of the push.
func publishXML(node string) string {
	return fmt.Sprintf(`<pubsub xmlns='%s'><publish node='%s'><item>
		<notification xmlns='%s'><x xmlns='%s'>
		<field var='FORM_TYPE'><value>urn:xmpp:push:summary</value></field>
		<field var='last-message-body'><value>the secret plan</value></field>
		</x></notification></item></publish></pubsub>`, nsPubsub, node, nsPush, nsData)
}

// fakeAPNs records pushes and answers with the status the test sets.
type fakeAPNs struct {
	mu     sync.Mutex
	paths  []string
	header http.Header
	body   string
	status int
	reason string
	auths  []string // the authorization of each request
	// answers are the next responses, used before status and reason.
	answers []fakeAnswer
}

type fakeAnswer struct {
	status int
	reason string
}

func (f *fakeAPNs) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	f.mu.Lock()
	defer f.mu.Unlock()
	f.paths = append(f.paths, r.URL.Path)
	f.header, f.body = r.Header, string(body)
	f.auths = append(f.auths, r.Header.Get("authorization"))
	answer := fakeAnswer{f.status, f.reason}
	if len(f.answers) > 0 {
		answer, f.answers = f.answers[0], f.answers[1:]
	}
	if answer.status != 0 {
		w.WriteHeader(answer.status)
		fmt.Fprintf(w, `{"reason":%q}`, answer.reason)
	}
}

func TestEndToEnd(t *testing.T) {
	// The privacy policy says the relay keeps nothing about who uses it, so its
	// logs must never name an account or a device.
	logs := captureLogs(t)
	defer func() {
		out := logs.String()
		sum := sha256.Sum256(testToken)
		for _, secret := range []string{"alice", "mallory", "example.org", hex.EncodeToString(testToken), hex.EncodeToString(sum[:4])} {
			if strings.Contains(out, secret) {
				t.Errorf("the logs name %q:\n%s", secret, out)
			}
		}
	}()

	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	fake := &fakeAPNs{}
	production, sandbox := httptest.NewUnstartedServer(fake), httptest.NewUnstartedServer(fake)
	for _, s := range []*httptest.Server{production, sandbox} {
		s.EnableHTTP2 = true
		s.StartTLS()
		t.Cleanup(s.Close)
	}
	sandbox.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.URL.Path = "/sandbox" + r.URL.Path
		fake.ServeHTTP(w, r)
	})

	server := newFakeServer(t, "s3cret")
	m := newMetrics()
	prom := m.reg
	c := &component{domain: "push.example", server: server.ln.Addr().String(), secret: "s3cret", metrics: m}
	r := &relay{
		domain: "push.example",
		nodes:  testSealer(t),
		apns: &apns{key: key, keyID: "K", teamID: "T", topic: "fr.yapnest.app",
			production: production.URL, sandbox: sandbox.URL, client: production.Client(), metrics: m},
		send:    c.send,
		metrics: m,
	}
	m.trackThrottle(r)
	c.handle = r.handle
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go c.run(ctx)

	info := server.exchange(`<iq type='get' id='d1' from='alice@example.org/phone' to='push.example'><query xmlns='http://jabber.org/protocol/disco#info'/></iq>`)
	if info.Type != "result" || !strings.Contains(string(info.Inner), "urn:xmpp:push:0") {
		t.Fatalf("disco: %+v %s", info, info.Inner)
	}

	// The app registers its token.
	reg := server.exchange(fmt.Sprintf(`<iq type='set' id='r1' from='alice@example.org/phone' to='push.example'>
		<command xmlns='%s' node='%s' action='execute'>
		<x xmlns='%s' type='submit'><field var='token'><value>%x</value></field>
		<field var='environment'><value>sandbox</value></field></x></command></iq>`, nsCommands, registerNode, nsData, testToken))
	var result struct {
		Status string   `xml:"status,attr"`
		Fields []string `xml:"x>field>value"`
	}
	if err := xml.Unmarshal(reg.Inner, &result); err != nil || reg.Type != "result" || result.Status != "completed" || len(result.Fields) != 1 {
		t.Fatalf("register: %+v %s", reg, reg.Inner)
	}
	node := result.Fields[0]
	waitFor(t, "the component to count as connected", func() bool { return metricValue(t, prom, "yapnest_relay_component_connected") == 1 })
	expect(t, prom, 1, "yapnest_relay_registrations_total", "environment", "sandbox", "result", "ok")
	expect(t, prom, 1, "yapnest_relay_component_connects_total", "result", "ok")

	// Registrations that fail are counted by what was wrong, not by whose they were.
	register := func(id, form string) stanza {
		return server.exchange(fmt.Sprintf(`<iq type='set' id='%s' from='alice@example.org/phone' to='push.example'>
			<command xmlns='%s' node='%s' action='execute'>
			<x xmlns='%s' type='submit'>%s</x></command></iq>`, id, nsCommands, registerNode, nsData, form))
	}
	if got := register("r2", `<field var='token'><value>not hex</value></field>`); got.Type != "error" {
		t.Fatalf("bad token: %s", got.Inner)
	}
	if got := register("r3", fmt.Sprintf(`<field var='token'><value>%x</value></field><field var='environment'><value>moon</value></field>`, testToken)); got.Type != "error" {
		t.Fatalf("bad environment: %s", got.Inner)
	}
	expect(t, prom, 1, "yapnest_relay_registrations_total", "environment", "production", "result", "bad_token")
	expect(t, prom, 1, "yapnest_relay_registrations_total", "environment", "unknown", "result", "bad_form")

	// Its server publishes a notification; the summary stays out of the push.
	publish := func(id, from, node string) stanza {
		return server.exchange(fmt.Sprintf(`<iq type='set' id='%s' from='%s' to='push.example'>%s</iq>`, id, from, publishXML(node)))
	}
	if got := publish("p1", "alice@example.org", node); got.Type != "result" {
		t.Fatalf("publish: %+v %s", got, got.Inner)
	}
	fake.mu.Lock()
	if len(fake.paths) != 1 || fake.paths[0] != "/sandbox/3/device/"+hex.EncodeToString(testToken) {
		t.Fatalf("paths %v", fake.paths)
	}
	if fake.header.Get("apns-topic") != "fr.yapnest.app" || fake.header.Get("apns-push-type") != "alert" ||
		!verifyES256(strings.TrimPrefix(fake.header.Get("authorization"), "bearer "), &key.PublicKey) {
		t.Fatalf("headers %v", fake.header)
	}
	if strings.Contains(fake.body, "secret plan") || !strings.Contains(fake.body, `"mutable-content":1`) {
		t.Fatalf("body %s", fake.body)
	}
	fake.mu.Unlock()
	expect(t, prom, 1, "yapnest_relay_publishes_total", "result", "sent")
	expect(t, prom, 1, "yapnest_relay_apns_requests_total", "environment", "sandbox", "outcome", "ok")
	if n := histogramCount(t, prom, "yapnest_relay_apns_request_duration_seconds", "environment", "sandbox"); n != 1 {
		t.Fatalf("%d timed requests", n)
	}

	// ejabberd publishes as the server.
	if got := publish("p2", "example.org", node); got.Type != "result" {
		t.Fatalf("publish from the server: %s", got.Inner)
	}
	// Others can't use the node.
	if got := publish("p3", "mallory@evil.example", node); got.Type != "error" || !strings.Contains(string(got.Inner), "forbidden") {
		t.Fatalf("stranger: %+v %s", got, got.Inner)
	}
	if got := publish("p4", "alice@example.org", "bogus"); got.Type != "error" || !strings.Contains(string(got.Inner), "item-not-found") {
		t.Fatalf("bogus node: %s", got.Inner)
	}
	expect(t, prom, 2, "yapnest_relay_publishes_total", "result", "sent")
	expect(t, prom, 1, "yapnest_relay_publishes_total", "result", "unauthorized")
	expect(t, prom, 1, "yapnest_relay_publishes_total", "result", "bad_node")

	// A removed app: the server should drop the target.
	fake.mu.Lock()
	fake.status, fake.reason = http.StatusGone, "Unregistered"
	fake.mu.Unlock()
	if got := publish("p5", "alice@example.org", node); got.Type != "error" || !strings.Contains(string(got.Inner), "item-not-found") {
		t.Fatalf("gone: %s", got.Inner)
	}
	// Apple having trouble: try again later.
	fake.mu.Lock()
	fake.status, fake.reason = http.StatusServiceUnavailable, "ServiceUnavailable"
	fake.mu.Unlock()
	if got := publish("p6", "alice@example.org", node); got.Type != "error" || !strings.Contains(string(got.Inner), "type=\"wait\"") {
		t.Fatalf("unavailable: %s", got.Inner)
	}
	expect(t, prom, 1, "yapnest_relay_publishes_total", "result", "gone")
	expect(t, prom, 1, "yapnest_relay_publishes_total", "result", "error")
	expect(t, prom, 2, "yapnest_relay_apns_requests_total", "environment", "sandbox", "outcome", "ok")
	expect(t, prom, 1, "yapnest_relay_apns_requests_total", "environment", "sandbox", "outcome", "gone")
	expect(t, prom, 1, "yapnest_relay_apns_requests_total", "environment", "sandbox", "outcome", "server_error")
	expect(t, prom, 0, "yapnest_relay_apns_requests_total", "environment", "production", "outcome", "ok")

	// What Prometheus scrapes names no account, server, device or node either.
	scrape := httptest.NewServer(m.handler())
	defer scrape.Close()
	resp, err := http.Get(scrape.URL + "/metrics")
	if err != nil {
		t.Fatal(err)
	}
	exposition, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if !strings.Contains(string(exposition), "yapnest_relay_publishes_total") {
		t.Fatalf("not the metrics:\n%s", exposition)
	}
	for _, secret := range []string{"alice", "mallory", "example.org", "evil.example", hex.EncodeToString(testToken), node, "secret plan"} {
		if strings.Contains(string(exposition), secret) {
			t.Errorf("the metrics name %q", secret)
		}
	}

	if got := server.exchange(`<iq type='get' id='x1' from='alice@example.org/phone' to='push.example'><vCard xmlns='vcard-temp'/></iq>`); got.Type != "error" {
		t.Fatalf("unknown iq: %+v", got)
	}
}

func TestRegistrationForm(t *testing.T) {
	var sent []string
	r := &relay{domain: "push.example", nodes: testSealer(t), send: func(s string) error { sent = append(sent, s); return nil }}
	r.handle(stanza{XMLName: xml.Name{Local: "iq"}, Type: "set", ID: "c1", From: "bob@example.org/pad", To: "push.example",
		Inner: []byte(`<command xmlns='http://jabber.org/protocol/commands' node='register-push-apns' action='execute'/>`)})
	if len(sent) != 1 || !strings.Contains(sent[0], "status=\"executing\"") || !strings.Contains(sent[0], "var=\"token\"") {
		t.Fatalf("sent %v", sent)
	}
	r.handle(stanza{XMLName: xml.Name{Local: "iq"}, Type: "set", ID: "c2", From: "bob@example.org/pad", To: "push.example",
		Inner: []byte(`<command xmlns='http://jabber.org/protocol/commands' node='register-push-apns'><x xmlns='jabber:x:data' type='submit'><field var='token'><value>zz</value></field></x></command>`)})
	if len(sent) != 2 || !strings.Contains(sent[1], "bad-request") {
		t.Fatalf("sent %v", sent)
	}
}

func TestBadHandshake(t *testing.T) {
	server := newFakeServer(t, "right")
	m := newMetrics()
	reg := m.reg
	c := &component{domain: "push.example", server: server.ln.Addr().String(), secret: "wrong", handle: func(stanza) {}, metrics: m}
	err := c.session(context.Background())
	if err == nil || !strings.Contains(err.Error(), "not-authorized") {
		t.Fatalf("err %v", err)
	}
	expect(t, reg, 1, "yapnest_relay_component_connects_total", "result", "error")
	expect(t, reg, 0, "yapnest_relay_component_connected")
}

func TestConnectedFollowsTheConnection(t *testing.T) {
	server := newFakeServer(t, "s3cret")
	m := newMetrics()
	reg := m.reg
	c := &component{domain: "push.example", server: server.ln.Addr().String(), secret: "s3cret", handle: func(stanza) {}, metrics: m}
	health := httptest.NewServer(m.handler())
	defer health.Close()
	status := func() int {
		resp, err := http.Get(health.URL + "/healthz")
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}
	if got := status(); got != http.StatusServiceUnavailable {
		t.Fatalf("healthz %d before connecting", got)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go c.run(ctx)
	waitFor(t, "the component to connect", func() bool { return metricValue(t, reg, "yapnest_relay_component_connected") == 1 })
	if got := status(); got != http.StatusOK {
		t.Fatalf("healthz %d while connected", got)
	}

	server.conn.Close()
	waitFor(t, "the component to notice", func() bool { return metricValue(t, reg, "yapnest_relay_component_connected") == 0 })
	if got := status(); got != http.StatusServiceUnavailable {
		t.Fatalf("healthz %d after disconnecting", got)
	}
}

func TestAPNsFailures(t *testing.T) {
	a, fake, srv := testAPNs(t)
	a.metrics = newMetrics()
	reg := a.metrics.reg

	seen := map[string]float64{}
	for _, c := range []struct {
		status  int
		reason  string
		outcome string
	}{
		{http.StatusBadRequest, "PayloadEmpty", "bad_request"},
		{http.StatusBadRequest, "BadDeviceToken", "gone"},
		{http.StatusBadRequest, "DeviceTokenNotForTopic", "bad_request"},
		{http.StatusBadRequest, "TopicDisallowed", "bad_request"},
		{http.StatusForbidden, "InvalidProviderToken", "forbidden"},
		{http.StatusGone, "Unregistered", "gone"},
		{http.StatusTooManyRequests, "TooManyRequests", "too_many"},
		{http.StatusInternalServerError, "InternalServerError", "server_error"},
	} {
		fake.mu.Lock()
		fake.status, fake.reason = c.status, c.reason
		fake.mu.Unlock()
		if err := a.push(context.Background(), registration{Token: testToken}); err == nil {
			t.Fatalf("%s: no error", c.reason)
		}
		seen[c.outcome]++
		expect(t, reg, seen[c.outcome], "yapnest_relay_apns_requests_total", "environment", "production", "outcome", c.outcome)
	}

	// Nothing answers: a network error, still timed.
	srv.Close()
	err := a.push(context.Background(), registration{Token: testToken, Sandbox: true})
	if err == nil {
		t.Fatal("no error without a server")
	}
	if strings.Contains(err.Error(), hex.EncodeToString(testToken)) {
		t.Fatalf("the error names the device token: %v", err)
	}
	expect(t, reg, 1, "yapnest_relay_apns_requests_total", "environment", "sandbox", "outcome", "network_error")
	if n := histogramCount(t, reg, "yapnest_relay_apns_request_duration_seconds", "environment", "sandbox"); n != 1 {
		t.Fatalf("%d timed requests", n)
	}
}

// find returns the metric named name whose labels are exactly the given pairs.
func find(t *testing.T, reg *prometheus.Registry, name string, labels ...string) (found bool, value float64, count uint64) {
	t.Helper()
	families, err := reg.Gather()
	if err != nil {
		t.Fatal(err)
	}
	for _, family := range families {
		if family.GetName() != name {
			continue
		}
	metric:
		for _, metric := range family.GetMetric() {
			if len(metric.GetLabel()) != len(labels)/2 {
				continue
			}
			for i := 0; i < len(labels); i += 2 {
				ok := false
				for _, l := range metric.GetLabel() {
					ok = ok || (l.GetName() == labels[i] && l.GetValue() == labels[i+1])
				}
				if !ok {
					continue metric
				}
			}
			switch {
			case metric.Counter != nil:
				return true, metric.Counter.GetValue(), 0
			case metric.Gauge != nil:
				return true, metric.Gauge.GetValue(), 0
			case metric.Histogram != nil:
				return true, 0, metric.Histogram.GetSampleCount()
			}
		}
	}
	return false, 0, 0
}

func metricValue(t *testing.T, reg *prometheus.Registry, name string, labels ...string) float64 {
	t.Helper()
	found, v, _ := find(t, reg, name, labels...)
	if !found {
		t.Fatalf("no metric %s %v", name, labels)
	}
	return v
}

func histogramCount(t *testing.T, reg *prometheus.Registry, name string, labels ...string) uint64 {
	t.Helper()
	found, _, n := find(t, reg, name, labels...)
	if !found {
		t.Fatalf("no metric %s %v", name, labels)
	}
	return n
}

func expect(t *testing.T, reg *prometheus.Registry, want float64, name string, labels ...string) {
	t.Helper()
	// The counters move on other goroutines a moment after the reply that triggered them.
	var found bool
	var got float64
	if !poll(2*time.Second, func() bool {
		found, got, _ = find(t, reg, name, labels...)
		return found && got == want
	}) {
		t.Fatalf("%s %v = %v (found %v), want %v", name, labels, got, found, want)
	}
}

func waitFor(t *testing.T, what string, done func() bool) {
	t.Helper()
	if !poll(5*time.Second, done) {
		t.Fatalf("timed out waiting for %s", what)
	}
}

// poll calls done until it returns true, and reports whether that happened within timeout.
func poll(timeout time.Duration, done func() bool) bool {
	deadline := time.Now().Add(timeout)
	for !done() {
		if time.Now().After(deadline) {
			return false
		}
		time.Sleep(10 * time.Millisecond)
	}
	return true
}

type countingPusher struct {
	mu    sync.Mutex
	count int
	// fail, when set, is asked for the error of each push, given its number from 1.
	fail func(n int) error
}

func (p *countingPusher) push(context.Context, registration) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.count++
	if p.fail != nil {
		return p.fail(p.count)
	}
	return nil
}

func (p *countingPusher) pushes() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.count
}

// A burst gets one push at once and one after the window, for what came after the first.
func TestBurstsArePushedTwice(t *testing.T) {
	pusher := &countingPusher{}
	r, reg, publish := throttledRelay(t, pusher, 200*time.Millisecond)
	r.metrics.trackThrottle(r)
	for range 5 {
		if reply := publish(); !strings.Contains(reply, "type=\"result\"") {
			t.Errorf("reply %s", reply)
		}
	}
	if got := pusher.pushes(); got != 1 {
		t.Fatalf("%d pushes at once", got)
	}
	expect(t, reg, 1, "yapnest_relay_publishes_total", "result", "sent")
	expect(t, reg, 4, "yapnest_relay_publishes_total", "result", "coalesced")
	expect(t, reg, 0, "yapnest_relay_publishes_total", "result", "trailing")
	expect(t, reg, 1, "yapnest_relay_throttled_devices")
	waitFor(t, "the push at the window's end", func() bool { return pusher.pushes() == 2 })
	expect(t, reg, 1, "yapnest_relay_publishes_total", "result", "trailing")

	// Quiet for a window: the next one goes out at once.
	waitFor(t, "the window to pass", func() bool { return r.throttled() == 0 })
	publish()
	if got := pusher.pushes(); got != 3 {
		t.Fatalf("%d pushes after a quiet window", got)
	}
}

// captureLogs sends slog's output to a buffer for the rest of the test. Setting slog's default redirects the log
// package too, which restoring slog's own default doesn't undo.
func captureLogs(t *testing.T) *syncBuffer {
	logs := &syncBuffer{}
	old, out, flags := slog.Default(), log.Writer(), log.Flags()
	slog.SetDefault(slog.New(slog.NewTextHandler(logs, nil)))
	t.Cleanup(func() {
		slog.SetDefault(old)
		log.SetOutput(out)
		log.SetFlags(flags)
	})
	return logs
}

// syncBuffer is a buffer the relay's goroutines can log into while the test reads it.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// throttledRelay is a relay that pushes through pusher at most once per window. publish publishes to one node and
// returns the reply.
func throttledRelay(t *testing.T, pusher pusher, window time.Duration) (r *relay, reg *prometheus.Registry, publish func() string) {
	s := testSealer(t)
	node, _ := s.seal(registration{Token: testToken, Owner: "alice@example.org"})
	var mu sync.Mutex
	var replies []string
	r = &relay{domain: "push.example", nodes: s, apns: pusher, window: window, metrics: newMetrics(),
		send: func(x string) error { mu.Lock(); replies = append(replies, x); mu.Unlock(); return nil }}
	publish = func() string {
		mu.Lock()
		before := len(replies)
		mu.Unlock()
		r.handle(stanza{XMLName: xml.Name{Local: "iq"}, Type: "set", ID: "p", From: "example.org", To: "push.example",
			Inner: []byte(publishXML(node))})
		mu.Lock()
		defer mu.Unlock()
		// Publishes may run side by side: each one adds its own reply.
		if len(replies) <= before {
			t.Errorf("a publish got no reply")
			return ""
		}
		return replies[len(replies)-1]
	}
	return r, r.metrics.reg, publish
}

// drainWithin drains r, and reports whether that finished before timeout.
func drainWithin(r *relay, timeout time.Duration) bool {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	r.drain(ctx)
	return ctx.Err() == nil
}

// Shutting down pushes what is waiting for its window instead of dropping it.
func TestDrainPushesTrailing(t *testing.T) {
	pusher := &countingPusher{}
	r, reg, publish := throttledRelay(t, pusher, time.Minute)
	for range 3 {
		publish()
	}
	if got := pusher.pushes(); got != 1 {
		t.Fatalf("%d pushes at once", got)
	}
	drainWithin(r, 5*time.Second)
	if got := pusher.pushes(); got != 2 {
		t.Fatalf("%d pushes after draining", got)
	}
	expect(t, reg, 1, "yapnest_relay_publishes_total", "result", "trailing")

	// A publish during the shutdown isn't left waiting either.
	publish()
	if got := pusher.pushes(); got != 3 {
		t.Fatalf("%d pushes for a publish while draining", got)
	}
}

// A trailing push APNs says is dead counts as gone, and the server's next publish learns it.
func TestTrailingGone(t *testing.T) {
	pusher := &countingPusher{fail: func(n int) error {
		if n >= 2 {
			return &pushError{Status: http.StatusGone, Reason: "Unregistered"}
		}
		return nil
	}}
	r, reg, publish := throttledRelay(t, pusher, time.Minute)
	publish()
	publish()
	drainWithin(r, 5*time.Second)
	expect(t, reg, 1, "yapnest_relay_publishes_total", "result", "gone")
	expect(t, reg, 0, "yapnest_relay_publishes_total", "result", "error")

	// The throttle forgot the device, so this is pushed at once, and refused again.
	if got := publish(); !strings.Contains(got, "item-not-found") {
		t.Fatalf("the next publish got %s", got)
	}
	if got := pusher.pushes(); got != 3 {
		t.Fatalf("%d pushes: the next publish should go out at once", got)
	}
}

// A network error names the APNs URL, which holds the device token: it must stay out of the logs.
func TestNetworkErrorLogsNoToken(t *testing.T) {
	logs := captureLogs(t)

	a, _, srv := testAPNs(t)
	srv.Close()
	_, _, publish := throttledRelay(t, a, time.Minute)
	if got := publish(); !strings.Contains(got, "internal-server-error") {
		t.Fatalf("reply %s", got)
	}
	out := logs.String()
	if !strings.Contains(out, "push failed") || strings.Contains(out, hex.EncodeToString(testToken)) {
		t.Fatalf("logs:\n%s", out)
	}
}

// Shutting down waits for a push already on its way to APNs.
func TestDrainWaitsForPushes(t *testing.T) {
	started, release := make(chan struct{}), make(chan struct{})
	pusher := &countingPusher{fail: func(int) error {
		close(started)
		<-release
		return nil
	}}
	r, _, publish := throttledRelay(t, pusher, time.Minute)
	go publish()
	<-started
	drained := make(chan struct{})
	go func() {
		drainWithin(r, 5*time.Second)
		close(drained)
	}()
	select {
	case <-drained:
		t.Fatal("drain didn't wait for the push")
	case <-time.After(100 * time.Millisecond):
	}
	close(release)
	select {
	case <-drained:
	case <-time.After(5 * time.Second):
		t.Fatal("drain didn't end with the push")
	}
}

// A push found gone while a trailing one was scheduled leaves that one in the throttle, where drain finds it.
func TestGoneKeepsTrailingPush(t *testing.T) {
	started, release := make(chan struct{}), make(chan struct{})
	pusher := &countingPusher{fail: func(n int) error {
		if n == 1 {
			close(started)
			<-release
		}
		return &pushError{Status: http.StatusGone, Reason: "Unregistered"}
	}}
	r, reg, publish := throttledRelay(t, pusher, time.Minute)
	first := make(chan string)
	go func() { first <- publish() }()
	<-started
	if got := publish(); !strings.Contains(got, "type=\"result\"") {
		t.Fatalf("the second publish got %s", got)
	}
	close(release)
	if got := <-first; !strings.Contains(got, "item-not-found") {
		t.Fatalf("the first publish got %s", got)
	}
	if !drainWithin(r, 2*time.Second) {
		t.Fatal("drain waited for a push it couldn't find")
	}
	if got := pusher.pushes(); got != 2 {
		t.Fatalf("%d pushes", got)
	}
	expect(t, reg, 2, "yapnest_relay_publishes_total", "result", "gone")
	if got := r.throttled(); got != 0 {
		t.Fatalf("%v devices still throttled", got)
	}
}

// Whatever the sender puts in id, from or the disco node comes back as the same text in a well-formed iq.
func TestRepliesEscapeHostileValues(t *testing.T) {
	const hostile = `a'b"c<d>&amp;e`
	var sent []string
	r := &relay{domain: "push.example", nodes: testSealer(t), send: func(s string) error { sent = append(sent, s); return nil }}
	r.handle(stanza{XMLName: xml.Name{Local: "iq"}, Type: "get", ID: hostile, From: hostile, To: hostile,
		Inner: []byte(`<query xmlns='` + nsDiscoItems + `' node='&apos;&quot;&lt;&amp;'/>`)})
	if len(sent) != 1 {
		t.Fatalf("sent %v", sent)
	}
	var got struct {
		XMLName xml.Name
		Type    string `xml:"type,attr"`
		ID      string `xml:"id,attr"`
		From    string `xml:"from,attr"`
		To      string `xml:"to,attr"`
		Query   struct {
			XMLName xml.Name
			Node    string `xml:"node,attr"`
		} `xml:"query"`
	}
	if err := xml.Unmarshal([]byte(sent[0]), &got); err != nil {
		t.Fatalf("not well-formed: %v: %s", err, sent[0])
	}
	if got.XMLName.Local != "iq" || got.Type != "result" || got.ID != hostile || got.From != hostile || got.To != hostile {
		t.Fatalf("iq %+v", got)
	}
	if got.Query.XMLName.Space != nsDiscoItems || got.Query.Node != `'"<&` {
		t.Fatalf("query %+v", got.Query)
	}
}

func TestErrorAndResultReplies(t *testing.T) {
	var sent []string
	r := &relay{domain: "push.example", nodes: testSealer(t), send: func(s string) error { sent = append(sent, s); return nil }}
	r.handle(stanza{XMLName: xml.Name{Local: "iq"}, Type: "get", ID: "e1", From: "bob@example.org", Inner: []byte(`<vCard xmlns='vcard-temp'/>`)})
	r.handle(stanza{XMLName: xml.Name{Local: "iq"}, Type: "get", ID: "e2", From: "bob@example.org", Inner: []byte(`<ping xmlns='` + nsPing + `'/>`)})
	if len(sent) != 2 {
		t.Fatalf("sent %v", sent)
	}
	type reply struct {
		Type  string `xml:"type,attr"`
		From  string `xml:"from,attr"`
		Error *struct {
			Type      string `xml:"type,attr"`
			Condition struct {
				XMLName xml.Name
			} `xml:",any"`
		} `xml:"error"`
	}
	var failure, success reply
	if err := xml.Unmarshal([]byte(sent[0]), &failure); err != nil {
		t.Fatal(err)
	}
	if failure.Type != "error" || failure.From != "push.example" || failure.Error == nil || failure.Error.Type != "cancel" ||
		failure.Error.Condition.XMLName != (xml.Name{Space: nsStanzas, Local: "service-unavailable"}) {
		t.Fatalf("error reply %s", sent[0])
	}
	if err := xml.Unmarshal([]byte(sent[1]), &success); err != nil {
		t.Fatal(err)
	}
	if success.Type != "result" || success.Error != nil {
		t.Fatalf("result reply %s", sent[1])
	}
}
