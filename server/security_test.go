/*
The MIT License (MIT)

Copyright (c) 2026 xenofex7
*/

package server

import (
	"bytes"
	"fmt"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/mux"
)

func startTestSession(t *testing.T, s *Server, user string) *session {
	t.Helper()
	if s.sessions == nil {
		s.sessions = newSessionStore(time.Hour, 24*time.Hour)
		t.Cleanup(s.sessions.Start())
	}
	sess, err := s.sessions.Create(user, false)
	if err != nil {
		t.Fatal(err)
	}
	return sess
}

func sessionPost(path string, form url.Values, sess *session) *http.Request {
	req := httptest.NewRequest("POST", path, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: sess.ID})
	return req
}

func startTestThrottle(t *testing.T, s *Server) {
	t.Helper()
	s.authThrottle = newAuthThrottle()
}

type csrfCase struct {
	name    string
	method  string
	path    string
	vars    map[string]string
	setup   func(t *testing.T, s *Server)
	handler func(s *Server) http.HandlerFunc
	request func(path string, csrf string, sess *session) *http.Request
	changed func(s *Server) bool
}

func formRequest(fields url.Values) func(string, string, *session) *http.Request {
	return func(path, csrf string, sess *session) *http.Request {
		form := url.Values{}
		for k, v := range fields {
			form[k] = v
		}
		if csrf != "" {
			form.Set("csrf", csrf)
		}
		return sessionPost(path, form, sess)
	}
}

func userListed(s *Server, name string) bool {
	names, _ := s.users.List()
	return slices.Contains(names, name)
}

func adminCSRFCases() []csrfCase {
	return []csrfCase{
		{
			name:    "add user",
			path:    "/admin/users",
			handler: func(s *Server) http.HandlerFunc { return s.adminUsersAddHandler },
			request: formRequest(url.Values{"username": {"bob"}, "password": {"longenoughpw"}}),
			changed: func(s *Server) bool { return userListed(s, "bob") },
		},
		{
			name:    "reset password",
			path:    "/admin/users/alice/password",
			vars:    map[string]string{"name": "alice"},
			handler: func(s *Server) http.HandlerFunc { return s.adminUsersResetHandler },
			request: formRequest(url.Values{"password": {"anotherlongpw"}}),
			changed: func(s *Server) bool { return s.verifyPassword("alice", "anotherlongpw") },
		},
		{
			name: "delete user",
			path: "/admin/users/bob/delete",
			vars: map[string]string{"name": "bob"},
			setup: func(t *testing.T, s *Server) {
				if err := s.users.Add("bob", "longenoughpw"); err != nil {
					t.Fatal(err)
				}
			},
			handler: func(s *Server) http.HandlerFunc { return s.adminUsersDeleteHandler },
			request: formRequest(nil),
			changed: func(s *Server) bool { return !userListed(s, "bob") },
		},
		{
			name:    "save settings",
			path:    "/admin/settings",
			handler: func(s *Server) http.HandlerFunc { return s.adminSettingsPostHandler },
			request: formRequest(url.Values{"tagline": {"changed"}, "theme": {DefaultTheme}}),
			changed: func(s *Server) bool { return s.settings.Get().Tagline == "changed" },
		},
		{
			name:    "toggle heartbeat",
			path:    "/admin/settings/heartbeat",
			handler: func(s *Server) http.HandlerFunc { return s.adminHeartbeatHandler },
			request: formRequest(url.Values{"enabled": {"false"}}),
			changed: func(s *Server) bool { return s.settings.Get().HeartbeatEnabled != nil },
		},
		{
			name:    "upload logo",
			path:    "/admin/branding/logo",
			vars:    map[string]string{"slot": "logo"},
			handler: func(s *Server) http.HandlerFunc { return s.adminBrandingUploadHandler },
			request: func(path, csrf string, sess *session) *http.Request {
				body := &bytes.Buffer{}
				mw := multipart.NewWriter(body)
				if csrf != "" {
					_ = mw.WriteField("csrf", csrf)
				}
				fw, _ := mw.CreateFormFile("file", "logo.png")
				_, _ = fw.Write([]byte("\x89PNG\r\n\x1a\nfake-but-small"))
				_ = mw.Close()
				req := httptest.NewRequest("POST", path, body)
				req.Header.Set("Content-Type", mw.FormDataContentType())
				req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: sess.ID})
				return req
			},
			changed: func(s *Server) bool { return s.branding.Get(BrandingLogo).exists },
		},
		{
			name: "delete secret",
			path: "/admin/secrets/secretaaaa/delete",
			vars: map[string]string{"id": "secretaaaa"},
			setup: func(t *testing.T, s *Server) {
				if err := s.secrets.Create("secretaaaa", testRecord(time.Hour)); err != nil {
					t.Fatal(err)
				}
			},
			handler: func(s *Server) http.HandlerFunc { return s.adminSecretsDeleteHandler },
			request: formRequest(nil),
			changed: func(s *Server) bool { return !s.secrets.Peek("secretaaaa") },
		},
	}
}

func newCSRFTestServer(t *testing.T) *Server {
	t.Helper()
	s := newTestServerWithUser(t, "alice", "longenoughpw")
	loadEmbeddedTemplates(s.logger)
	settings, err := newSettingsStore(filepath.Join(t.TempDir(), ".settings.json"), Settings{Tagline: "boot"})
	if err != nil {
		t.Fatal(err)
	}
	s.settings = settings
	s.brandingDir = t.TempDir()
	if s.branding, err = newBrandingStore(s.brandingDir); err != nil {
		t.Fatal(err)
	}
	s.secrets = newTestSecretStore(t)
	return s
}

func TestAdminPostsRequireCSRFToken(t *testing.T) {
	for _, c := range adminCSRFCases() {
		for _, mode := range []string{"missing", "foreign", "valid"} {
			t.Run(c.name+"/"+mode, func(t *testing.T) {
				s := newCSRFTestServer(t)
				if c.setup != nil {
					c.setup(t, s)
				}
				sess := startTestSession(t, s, "alice")
				token := ""
				switch mode {
				case "foreign":
					other := startTestSession(t, s, "alice")
					token = csrfTokenFor(other.ID)
				case "valid":
					token = csrfTokenFor(sess.ID)
				}

				req := c.request(c.path, token, sess)
				if c.vars != nil {
					req = mux.SetURLVars(req, c.vars)
				}
				rec := httptest.NewRecorder()
				s.webAuthHandler(c.handler(s)).ServeHTTP(rec, req)

				if rec.Code != http.StatusSeeOther {
					t.Fatalf("expected 303, got %d", rec.Code)
				}
				if got, want := c.changed(s), mode == "valid"; got != want {
					t.Fatalf("state changed = %v, want %v", got, want)
				}
			})
		}
	}
}

func TestAdminTemplatesCarryCSRFToken(t *testing.T) {
	s := newCSRFTestServer(t)
	if err := s.users.Add("bob", "longenoughpw"); err != nil {
		t.Fatal(err)
	}
	sess := startTestSession(t, s, "alice")
	want := `name="csrf" value="` + csrfTokenFor(sess.ID) + `"`

	for _, page := range []struct {
		path     string
		h        http.HandlerFunc
		minForms int
	}{
		{"/admin/users", s.adminUsersGetHandler, 5},
		{"/admin/settings", s.adminSettingsGetHandler, 5},
	} {
		path := page.path
		req := httptest.NewRequest("GET", path, nil)
		req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: sess.ID})
		rec := httptest.NewRecorder()
		s.webAuthHandler(page.h).ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("%s: expected 200, got %d", path, rec.Code)
		}
		body := rec.Body.String()
		forms := strings.Count(body, "<form")
		if forms < page.minForms {
			t.Fatalf("%s: expected at least %d forms, got %d", path, page.minForms, forms)
		}
		if got := strings.Count(body, want); got != forms {
			t.Errorf("%s: %d of %d forms carry the session CSRF token", path, got, forms)
		}
	}
}

func enrolTOTP(t *testing.T, s *Server, user string) {
	t.Helper()
	enr, err := s.startTOTPEnrollment(user)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.finishTOTPEnrollment(user, enr.Secret, currentTOTPCode(t, enr.Secret)); err != nil {
		t.Fatal(err)
	}
}

func basicAuthStatus(h http.Handler, user, pass string) int {
	req := httptest.NewRequest("PUT", "/x.txt", nil)
	req.SetBasicAuth(user, pass)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec.Code
}

func TestBasicAuthPasswordRejectedWhenTOTPEnabled(t *testing.T) {
	s, h := buildAuthTestServer(t)
	enrolTOTP(t, s, "alice")

	if got := basicAuthStatus(h, "alice", "longenoughpw"); got != http.StatusUnauthorized {
		t.Fatalf("password with TOTP enabled: expected 401, got %d", got)
	}
	wire, _, err := s.userMeta.CreateAPIToken("alice", "ci", nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := basicAuthStatus(h, "alice", wire); got != http.StatusOK {
		t.Fatalf("api token with TOTP enabled: expected 200, got %d", got)
	}
}

func TestBasicAuthPasswordRejectedWhenTOTPRequired(t *testing.T) {
	s, h := buildAuthTestServer(t)
	s.authRequireTOTP = true

	if got := basicAuthStatus(h, "alice", "longenoughpw"); got != http.StatusUnauthorized {
		t.Fatalf("password while 2FA is required: expected 401, got %d", got)
	}
	wire, _, err := s.userMeta.CreateAPIToken("alice", "ci", nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := basicAuthStatus(h, "alice", wire); got != http.StatusOK {
		t.Fatalf("api token while 2FA is required: expected 200, got %d", got)
	}
}

func TestBasicAuthThrottlesFailedAttempts(t *testing.T) {
	s, h := buildAuthTestServer(t)
	startTestThrottle(t, s)

	for i := 0; i < authFailureBurst; i++ {
		if got := basicAuthStatus(h, "alice", "wrong"); got != http.StatusUnauthorized {
			t.Fatalf("attempt %d: expected 401, got %d", i+1, got)
		}
	}
	if got := basicAuthStatus(h, "alice", "longenoughpw"); got != http.StatusTooManyRequests {
		t.Fatalf("after %d failures: expected 429, got %d", authFailureBurst, got)
	}
}

func TestBasicAuthWithoutCredentialsIsNotCounted(t *testing.T) {
	s, h := buildAuthTestServer(t)
	startTestThrottle(t, s)

	for i := 0; i < authFailureBurst+5; i++ {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest("PUT", "/x.txt", nil))
	}
	if got := basicAuthStatus(h, "alice", "longenoughpw"); got != http.StatusOK {
		t.Fatalf("credential-less probes must not lock the caller out, got %d", got)
	}
}

func loginAttempt(a *authTestSetup, remote, user, pass string) *httptest.ResponseRecorder {
	form := url.Values{"csrf": {csrfTokenFor("")}, "username": {user}, "password": {pass}}
	req := httptest.NewRequest("POST", "/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.RemoteAddr = remote
	rec := httptest.NewRecorder()
	a.handler.ServeHTTP(rec, req)
	return rec
}

func TestLoginThrottlesPerIP(t *testing.T) {
	a := newAuthTestSetup(t)
	startTestThrottle(t, a.server)

	for i := 0; i < authFailureBurst; i++ {
		loginAttempt(a, "203.0.113.5:1000", fmt.Sprintf("user%d", i), "wrong")
	}
	if id := sessionIDFromResponse(loginAttempt(a, "203.0.113.5:1000", "alice", "longenoughpw")); id != "" {
		t.Fatal("blocked IP must not get a session even with the right password")
	}
	if id := sessionIDFromResponse(loginAttempt(a, "203.0.113.6:1000", "alice", "longenoughpw")); id == "" {
		t.Fatal("another IP must still be able to sign in")
	}
}

func TestLoginThrottlesPerUserAcrossIPs(t *testing.T) {
	a := newAuthTestSetup(t)
	startTestThrottle(t, a.server)

	for i := 0; i < authFailureBurst; i++ {
		loginAttempt(a, fmt.Sprintf("198.51.100.%d:1000", i+1), "alice", "wrong")
	}
	if id := sessionIDFromResponse(loginAttempt(a, "192.0.2.1:1000", "alice", "longenoughpw")); id != "" {
		t.Fatal("a user under a distributed guessing attack must be throttled")
	}
}

func TestLoginTOTPFailuresSurviveNewLogin(t *testing.T) {
	a := newAuthTestSetup(t)
	startTestThrottle(t, a.server)
	enrolTOTP(t, a.server, "alice")

	failed := 0
	for failed < authFailureBurst {
		sess, err := a.server.sessions.Create("alice", true)
		if err != nil {
			t.Fatal(err)
		}
		for i := 0; i < maxMFAAttempts-1 && failed < authFailureBurst; i++ {
			form := url.Values{"csrf": {csrfTokenFor(sess.ID)}, "code": {"notacode"}}
			postForm(a.handler, "/login/totp", form, cookieFor(sess.ID))
			failed++
		}
	}

	sess, _ := a.server.sessions.Create("alice", true)
	form := url.Values{"csrf": {csrfTokenFor(sess.ID)}, "code": {"notacode"}}
	rec := postForm(a.handler, "/login/totp", form, cookieFor(sess.ID))
	if pending, err := a.server.sessions.Get(sess.ID); err != nil || !pending.PendingMFA {
		t.Fatal("blocked request must leave the pending session untouched")
	}
	if loc := rec.Header().Get("Location"); !strings.HasPrefix(loc, "/login/totp") {
		t.Fatalf("expected redirect back to /login/totp, got %q", loc)
	}
	if got := a.server.sessions.RecordMFAAttempt(sess.ID); got != 1 {
		t.Fatalf("blocked request must not consume a per-session attempt, counter is %d", got)
	}
}

func TestUnlockThrottlesWrongPasswords(t *testing.T) {
	s, path := seedProtected(t)
	startTestThrottle(t, s)

	for i := 0; i < authFailureBurst; i++ {
		rec := httptest.NewRecorder()
		s.unlockHandler(rec, fileRequest("POST", path, url.Values{"password": {"nope"}}.Encode()))
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("attempt %d: expected 401, got %d", i+1, rec.Code)
		}
	}
	rec := httptest.NewRecorder()
	s.unlockHandler(rec, fileRequest("POST", path, url.Values{"password": {"s3cret"}}.Encode()))
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("after %d failures: expected 429, got %d", authFailureBurst, rec.Code)
	}
	if len(rec.Result().Cookies()) != 0 {
		t.Fatal("blocked unlock must not set the unlock cookie")
	}
}
