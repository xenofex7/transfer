/*
The MIT License (MIT)

Copyright (c) 2026 xenofex7
*/

package server

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestWebAuthHandlerRedirectsUnauthenticated(t *testing.T) {
	s := &Server{sessions: newSessionStore(time.Hour, 24*time.Hour)}
	called := false
	h := s.webAuthHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
	}))

	req := httptest.NewRequest("GET", "/admin/files?x=1", nil)
	rec := httptest.NewRecorder()
	h(rec, req)
	if called {
		t.Fatal("handler must not run without auth")
	}
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("expected 303, got %d", rec.Code)
	}
	loc := rec.Header().Get("Location")
	if !strings.HasPrefix(loc, "/login?next=") {
		t.Fatalf("expected /login?next=, got %q", loc)
	}
	// Original URL must round-trip through the next= param.
	if !strings.Contains(loc, "%2Fadmin%2Ffiles%3Fx%3D1") {
		t.Fatalf("next= should carry the original URL: %q", loc)
	}
}

func TestWebAuthHandlerRedirectsPendingMFA(t *testing.T) {
	s := &Server{sessions: newSessionStore(time.Hour, 24*time.Hour)}
	pending, _ := s.sessions.Create("alice", true)

	h := s.webAuthHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("pending session must not reach the inner handler")
	}))
	req := httptest.NewRequest("GET", "/admin/files", nil)
	req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: pending.ID})
	rec := httptest.NewRecorder()
	h(rec, req)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("expected 303, got %d", rec.Code)
	}
}

func TestWebAuthHandlerPassesContextUser(t *testing.T) {
	s := &Server{sessions: newSessionStore(time.Hour, 24*time.Hour)}
	full, _ := s.sessions.Create("alice", false)

	var seen string
	h := s.webAuthHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = authUserFromContext(r.Context())
	}))
	req := httptest.NewRequest("GET", "/admin/files", nil)
	req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: full.ID})
	rec := httptest.NewRecorder()
	h(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	if seen != "alice" {
		t.Fatalf("expected user in context, got %q", seen)
	}
}

func TestCurrentUserFromRequestPrefersContext(t *testing.T) {
	req := httptest.NewRequest("GET", "/", nil)
	req.SetBasicAuth("basic-user", "x")
	req = req.WithContext(withAuthUser(req.Context(), "ctx-user"))
	if got := currentUserFromRequest(req); got != "ctx-user" {
		t.Fatalf("expected context user to win, got %q", got)
	}
}

func TestCurrentUserFromRequestFallsBackToBasic(t *testing.T) {
	req := httptest.NewRequest("GET", "/", nil)
	req.SetBasicAuth("basic-user", "x")
	if got := currentUserFromRequest(req); got != "basic-user" {
		t.Fatalf("expected basic auth fallback, got %q", got)
	}
}

func TestWebAuthHandlerRequireTOTPRedirectsToSetup(t *testing.T) {
	s := newTestServerWithUser(t, "alice", "longenoughpw")
	s.sessions = newSessionStore(time.Hour, 24*time.Hour)
	s.authRequireTOTP = true

	full, _ := s.sessions.Create("alice", false)

	h := s.webAuthHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("user without TOTP must not reach the protected handler")
	}))
	req := httptest.NewRequest("GET", "/admin/files", nil)
	req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: full.ID})
	rec := httptest.NewRecorder()
	h(rec, req)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("expected 303, got %d", rec.Code)
	}
	if rec.Header().Get("Location") != "/account/2fa/setup" {
		t.Fatalf("expected redirect to setup, got %q", rec.Header().Get("Location"))
	}
}

func TestWebAuthHandlerRequireTOTPExemptsSetupAndLogout(t *testing.T) {
	s := newTestServerWithUser(t, "alice", "longenoughpw")
	s.sessions = newSessionStore(time.Hour, 24*time.Hour)
	s.authRequireTOTP = true
	full, _ := s.sessions.Create("alice", false)

	for _, path := range []string{"/account/2fa/setup", "/logout"} {
		called := false
		h := s.webAuthHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			called = true
		}))
		req := httptest.NewRequest("GET", path, nil)
		req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: full.ID})
		rec := httptest.NewRecorder()
		h(rec, req)
		if !called {
			t.Fatalf("path %s must be exempt from 2FA enforcement", path)
		}
	}
}

func TestWebAuthHandlerRequireTOTPLetsEnrolledUserThrough(t *testing.T) {
	s := newTestServerWithUser(t, "alice", "longenoughpw")
	s.sessions = newSessionStore(time.Hour, 24*time.Hour)
	s.authRequireTOTP = true
	enr, _ := s.startTOTPEnrollment("alice")
	c := currentTOTPCode(t, enr.Secret)
	if _, err := s.finishTOTPEnrollment("alice", enr.Secret, c); err != nil {
		t.Fatal(err)
	}
	full, _ := s.sessions.Create("alice", false)

	called := false
	h := s.webAuthHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
	}))
	req := httptest.NewRequest("GET", "/admin/files", nil)
	req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: full.ID})
	rec := httptest.NewRecorder()
	h(rec, req)
	if !called {
		t.Fatalf("enrolled user should reach the handler, got %d", rec.Code)
	}
}

func TestWebAuthHandlerFallsBackWithoutSessionStore(t *testing.T) {
	s := &Server{} // no session store, no users — basic auth disabled too
	called := false
	h := s.webAuthHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
	}))
	req := httptest.NewRequest("GET", "/x", nil)
	rec := httptest.NewRecorder()
	h(rec, req)
	if !called {
		t.Fatal("with no auth configured at all, request should pass through")
	}
}
