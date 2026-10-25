package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"net/http"
	"net/http/httptest"
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
	if err := a.push(context.Background(), registration{Token: testToken}); err != nil {
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
		if err := a.push(context.Background(), registration{Token: testToken}); err == nil {
			t.Fatal("no error")
		}
	}
	fake.mu.Lock()
	defer fake.mu.Unlock()
	if len(fake.auths) != 2 || fake.auths[0] != fake.auths[1] {
		t.Fatalf("authorizations %v", fake.auths)
	}
}
