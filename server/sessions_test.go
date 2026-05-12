/*
The MIT License (MIT)

Copyright (c) 2026 xenofex7
*/

package server

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestSessionCreateAndGet(t *testing.T) {
	s := newSessionStore(time.Hour, 24*time.Hour)
	sess, err := s.Create("alice", false)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if sess.Username != "alice" || sess.ID == "" || sess.PendingMFA {
		t.Fatalf("unexpected session: %+v", sess)
	}

	got, err := s.Get(sess.ID)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.Username != "alice" {
		t.Fatalf("wrong user: %+v", got)
	}
}

func TestSessionGetUnknown(t *testing.T) {
	s := newSessionStore(time.Hour, 24*time.Hour)
	if _, err := s.Get(""); !errors.Is(err, errSessionNotFound) {
		t.Fatalf("empty ID: %v", err)
	}
	if _, err := s.Get("nope"); !errors.Is(err, errSessionNotFound) {
		t.Fatalf("unknown ID: %v", err)
	}
}

func TestSessionSlidingExpiry(t *testing.T) {
	s := newSessionStore(time.Minute, time.Hour)

	t0 := time.Now().UTC()
	clock := t0
	s.now = func() time.Time { return clock }

	sess, _ := s.Create("alice", false)

	// 30s in: still valid, ExpiresAt should slide forward.
	clock = t0.Add(30 * time.Second)
	got, err := s.Get(sess.ID)
	if err != nil {
		t.Fatalf("get within idle: %v", err)
	}
	if !got.ExpiresAt.After(t0.Add(time.Minute)) {
		t.Fatalf("ExpiresAt should slide: %v", got.ExpiresAt)
	}

	// 90s past last touch: expired, should be evicted.
	clock = clock.Add(2 * time.Minute)
	if _, err := s.Get(sess.ID); !errors.Is(err, errSessionNotFound) {
		t.Fatalf("expected expiry, got %v", err)
	}
}

func TestSessionMaxLifetimeCapsSliding(t *testing.T) {
	s := newSessionStore(time.Minute, 2*time.Minute)

	t0 := time.Now().UTC()
	clock := t0
	s.now = func() time.Time { return clock }

	sess, _ := s.Create("alice", false)

	// Touch right under the idle limit repeatedly, but cross max
	// lifetime — Get must refuse it anyway.
	for i := 0; i < 5; i++ {
		clock = clock.Add(30 * time.Second)
		if _, err := s.Get(sess.ID); err != nil {
			break
		}
	}
	clock = t0.Add(3 * time.Minute)
	if _, err := s.Get(sess.ID); !errors.Is(err, errSessionNotFound) {
		t.Fatalf("max lifetime should kick in regardless of activity, got %v", err)
	}
}

func TestSessionPromoteRotatesID(t *testing.T) {
	s := newSessionStore(time.Hour, 24*time.Hour)
	pending, _ := s.Create("alice", true)
	if !pending.PendingMFA {
		t.Fatal("create with pendingMFA should set the flag")
	}

	full, err := s.Promote(pending.ID)
	if err != nil {
		t.Fatalf("promote: %v", err)
	}
	if full.ID == pending.ID {
		t.Fatal("Promote must rotate the ID to prevent fixation")
	}
	if full.PendingMFA {
		t.Fatal("promoted session should be fully authenticated")
	}
	if _, err := s.Get(pending.ID); !errors.Is(err, errSessionNotFound) {
		t.Fatalf("old ID must be invalid after promote, got %v", err)
	}
	if _, err := s.Get(full.ID); err != nil {
		t.Fatalf("new ID should work: %v", err)
	}
}

func TestSessionDestroy(t *testing.T) {
	s := newSessionStore(time.Hour, 24*time.Hour)
	sess, _ := s.Create("alice", false)
	s.Destroy(sess.ID)
	if _, err := s.Get(sess.ID); !errors.Is(err, errSessionNotFound) {
		t.Fatalf("destroyed session should be gone, got %v", err)
	}
	// No panic for unknown or empty IDs.
	s.Destroy("")
	s.Destroy("missing")
}

func TestSessionDestroyAllFor(t *testing.T) {
	s := newSessionStore(time.Hour, 24*time.Hour)
	a1, _ := s.Create("alice", false)
	a2, _ := s.Create("alice", false)
	b, _ := s.Create("bob", false)

	s.DestroyAllFor("alice")
	for _, id := range []string{a1.ID, a2.ID} {
		if _, err := s.Get(id); !errors.Is(err, errSessionNotFound) {
			t.Fatalf("alice session %s should be gone", id)
		}
	}
	if _, err := s.Get(b.ID); err != nil {
		t.Fatalf("bob session should survive: %v", err)
	}
}

func TestSessionSweepRemovesExpired(t *testing.T) {
	s := newSessionStore(time.Minute, time.Hour)
	t0 := time.Now().UTC()
	clock := t0
	s.now = func() time.Time { return clock }

	for i := 0; i < 3; i++ {
		if _, err := s.Create("alice", false); err != nil {
			t.Fatal(err)
		}
	}
	if s.Count() != 3 {
		t.Fatalf("expected 3, got %d", s.Count())
	}

	clock = t0.Add(2 * time.Minute)
	if s.Count() != 0 {
		t.Fatalf("expected sweep to clear expired sessions, got %d", s.Count())
	}
}

func TestSessionConcurrentCreates(t *testing.T) {
	s := newSessionStore(time.Hour, 24*time.Hour)
	const n = 50
	var wg sync.WaitGroup
	wg.Add(n)
	for i := 0; i < n; i++ {
		go func() {
			defer wg.Done()
			if _, err := s.Create("alice", false); err != nil {
				t.Errorf("create: %v", err)
			}
		}()
	}
	wg.Wait()
	if s.Count() != n {
		t.Fatalf("expected %d sessions, got %d", n, s.Count())
	}
}

func TestSessionCookieRoundTrip(t *testing.T) {
	rec := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "https://example.com/", nil)
	setSessionCookie(rec, r, "abc123", time.Hour)

	cookies := rec.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatalf("expected one cookie, got %d", len(cookies))
	}
	c := cookies[0]
	if c.Name != sessionCookieName || c.Value != "abc123" {
		t.Fatalf("bad cookie: %+v", c)
	}
	if !c.HttpOnly || !c.Secure || c.SameSite != http.SameSiteLaxMode {
		t.Fatalf("missing security flags: %+v", c)
	}

	// Read back through readSessionCookie.
	req := httptest.NewRequest("GET", "/", nil)
	req.AddCookie(c)
	if got := readSessionCookie(req); got != "abc123" {
		t.Fatalf("readSessionCookie: %q", got)
	}
}

func TestSessionCookieSecureRespectsScheme(t *testing.T) {
	rec := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "http://example.com/", nil) // plain HTTP
	setSessionCookie(rec, r, "abc", time.Hour)
	if rec.Result().Cookies()[0].Secure {
		t.Fatal("plain HTTP must not set Secure (cookie would never come back)")
	}

	rec = httptest.NewRecorder()
	r = httptest.NewRequest("GET", "http://example.com/", nil)
	r.Header.Set("X-Forwarded-Proto", "https")
	setSessionCookie(rec, r, "abc", time.Hour)
	if !rec.Result().Cookies()[0].Secure {
		t.Fatal("X-Forwarded-Proto=https should mark Secure (TLS-terminating proxy)")
	}
}

func TestSessionCookieDeletion(t *testing.T) {
	rec := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "https://example.com/", nil)
	setSessionCookie(rec, r, "", 0)
	header := rec.Header().Get("Set-Cookie")
	if !strings.Contains(header, "Max-Age=0") && !strings.Contains(header, "Max-Age=-1") {
		t.Fatalf("expected expiry header, got %q", header)
	}
}

func TestSessionStoreStartStop(t *testing.T) {
	s := newSessionStore(time.Minute, time.Hour)
	stop := s.Start()
	stop()
	// Second stop is a no-op.
	stop()
}
