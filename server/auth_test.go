/*
The MIT License (MIT)

Copyright (c) 2026 xenofex7
*/

package server

import (
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// buildAuthTestServer wires up a Server with an htpasswd file, a meta
// store, and a single user "alice" with password "longenoughpw".
// Returns the server plus a handler that returns 200 once auth passes.
func buildAuthTestServer(t *testing.T) (*Server, http.HandlerFunc) {
	t.Helper()
	dir := t.TempDir()
	htp := filepath.Join(dir, "htpasswd")

	s := &Server{
		authHtpasswd: htp,
		logger:       log.New(os.Stderr, "test ", 0),
	}
	meta, err := newUserMetaStore(metaPathFor(htp))
	if err != nil {
		t.Fatalf("meta store: %v", err)
	}
	s.userMeta = meta
	s.users = newUserStore(htp, s.reloadHtpasswdFile, func(name string) error {
		return s.userMeta.Delete(name)
	})
	if err := s.users.Add("alice", "longenoughpw"); err != nil {
		t.Fatalf("seed user: %v", err)
	}
	// Wait for any async token-touch goroutines before the test's
	// TempDir cleanup kicks in. Otherwise a late write can race the
	// RemoveAll and fail the test with "directory not empty".
	t.Cleanup(func() { s.authBgTasks.Wait() })

	ok := func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}
	return s, s.basicAuthHandler(http.HandlerFunc(ok))
}

func TestBasicAuthHandlerAcceptsPassword(t *testing.T) {
	_, h := buildAuthTestServer(t)

	req := httptest.NewRequest("GET", "/", nil)
	req.SetBasicAuth("alice", "longenoughpw")
	rec := httptest.NewRecorder()
	h(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("password should authenticate, got %d", rec.Code)
	}
}

func TestBasicAuthHandlerRejectsWrongPassword(t *testing.T) {
	_, h := buildAuthTestServer(t)

	req := httptest.NewRequest("GET", "/", nil)
	req.SetBasicAuth("alice", "wrongwrongwrong")
	rec := httptest.NewRecorder()
	h(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("wrong password should 401, got %d", rec.Code)
	}
}

func TestBasicAuthHandlerAcceptsAPIToken(t *testing.T) {
	s, h := buildAuthTestServer(t)

	wire, _, err := s.userMeta.CreateAPIToken("alice", "test", nil)
	if err != nil {
		t.Fatalf("create token: %v", err)
	}

	req := httptest.NewRequest("GET", "/", nil)
	req.SetBasicAuth("alice", wire)
	rec := httptest.NewRecorder()
	h(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("api token should authenticate, got %d", rec.Code)
	}
}

func TestBasicAuthHandlerRejectsTokenForOtherUser(t *testing.T) {
	s, h := buildAuthTestServer(t)
	if err := s.users.Add("bob", "longenoughpw"); err != nil {
		t.Fatal(err)
	}
	wire, _, err := s.userMeta.CreateAPIToken("alice", "test", nil)
	if err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest("GET", "/", nil)
	req.SetBasicAuth("bob", wire)
	rec := httptest.NewRecorder()
	h(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("token bound to alice must not work for bob, got %d", rec.Code)
	}
}

// A password that happens to look like a token must not authenticate.
// Otherwise an attacker could probe for token-shaped passwords by
// spraying the htpasswd path and we'd silently fall back to it.
func TestBasicAuthHandlerTokenShapedPasswordDoesNotFallBack(t *testing.T) {
	s, h := buildAuthTestServer(t)
	tokenLooking := "tk_aaaaaaa.bbbbbbbbbbbbbbb"
	if err := s.users.SetPassword("alice", tokenLooking); err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest("GET", "/", nil)
	req.SetBasicAuth("alice", tokenLooking)
	rec := httptest.NewRecorder()
	h(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("token-shaped password must not authenticate, got %d", rec.Code)
	}
}

func TestBasicAuthHandlerExpiredToken(t *testing.T) {
	s, h := buildAuthTestServer(t)
	past := time.Now().Add(-time.Hour)
	wire, _, err := s.userMeta.CreateAPIToken("alice", "old", &past)
	if err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest("GET", "/", nil)
	req.SetBasicAuth("alice", wire)
	rec := httptest.NewRecorder()
	h(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expired token must 401, got %d", rec.Code)
	}
}

func TestBasicAuthHandlerUserDeleteRemovesTokens(t *testing.T) {
	s, h := buildAuthTestServer(t)
	if err := s.users.Add("bob", "longenoughpw"); err != nil {
		t.Fatal(err)
	}
	wire, _, err := s.userMeta.CreateAPIToken("bob", "laptop", nil)
	if err != nil {
		t.Fatal(err)
	}

	// Sanity: token works.
	req := httptest.NewRequest("GET", "/", nil)
	req.SetBasicAuth("bob", wire)
	rec := httptest.NewRecorder()
	h(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("precondition failed: token should work, got %d", rec.Code)
	}

	if err := s.users.Delete("bob", "alice"); err != nil {
		t.Fatalf("delete bob: %v", err)
	}
	if s.userMeta.Has("bob") {
		t.Fatal("bob's meta record should be removed by the delete hook")
	}

	req2 := httptest.NewRequest("GET", "/", nil)
	req2.SetBasicAuth("bob", wire)
	rec2 := httptest.NewRecorder()
	h(rec2, req2)
	if rec2.Code != http.StatusUnauthorized {
		t.Fatalf("token must stop working after user delete, got %d", rec2.Code)
	}
}
