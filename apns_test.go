package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"maps"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// testAPNs is an apns client for a fake APNs server, which the test may close early.
func testAPNs(t *testing.T) (*apns, *fakeAPNs, *httptest.Server) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	fake := &fakeAPNs{}
	srv := httptest.NewUnstartedServer(fake)
	srv.EnableHTTP2 = true
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return &apns{key: key, keyID: "K", teamID: "T", topic: "t", production: srv.URL, sandbox: srv.URL, client: srv.Client()}, fake, srv
}

// An expired provider token is replaced and the push retried once.
func TestExpiredProviderTokenIsRenewed(t *testing.T) {
	a, fake, _ := testAPNs(t)
	fake.answers = []fakeAnswer{{http.StatusForbidden, "ExpiredProviderToken"}}
	if err := a.push(context.Background(), registration{Token: testToken}, false); err != nil {
		t.Fatal(err)
	}
	fake.mu.Lock()
	defer fake.mu.Unlock()
	if len(fake.auths) != 2 || fake.auths[0] == fake.auths[1] {
		t.Fatalf("authorizations %v", fake.auths)
	}
}

// An invalid one isn't: a new signature from the same key wouldn't help, and renewing too often is refused too.
func TestInvalidProviderTokenIsKept(t *testing.T) {
	a, fake, _ := testAPNs(t)
	fake.answers = []fakeAnswer{{http.StatusForbidden, "InvalidProviderToken"}, {http.StatusForbidden, "InvalidProviderToken"}}
	for range 2 {
		if err := a.push(context.Background(), registration{Token: testToken}, false); err == nil {
			t.Fatal("no error")
		}
	}
	fake.mu.Lock()
	defer fake.mu.Unlock()
	if len(fake.auths) != 2 || fake.auths[0] != fake.auths[1] {
		t.Fatalf("authorizations %v", fake.auths)
	}
}

// An alert is a high priority push, kept a day for an offline phone; a background one is the quiet kind Apple
// allows only at priority 5, and isn't stored.
func TestPushTypes(t *testing.T) {
	a, fake, _ := testAPNs(t)
	for _, background := range []bool{false, true} {
		if err := a.push(context.Background(), registration{Token: testToken}, background); err != nil {
			t.Fatal(err)
		}
		fake.mu.Lock()
		got := map[string]string{"type": fake.header.Get("apns-push-type"), "priority": fake.header.Get("apns-priority"),
			"expiration": fake.header.Get("apns-expiration"), "body": fake.body}
		fake.mu.Unlock()
		if background {
			want := map[string]string{"type": "background", "priority": "5", "expiration": "0", "body": `{"aps":{"content-available":1}}`}
			if !maps.Equal(got, want) {
				t.Errorf("background push %v, want %v", got, want)
			}
			continue
		}
		if got["type"] != "alert" || got["priority"] != "10" || got["expiration"] == "0" || !strings.Contains(got["body"], `"mutable-content":1`) {
			t.Errorf("alert push %v", got)
		}
	}
}
