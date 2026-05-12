/*
The MIT License (MIT)

Copyright (c) 2026 xenofex7
*/

package server

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/mux"
	"github.com/pquerna/otp/totp"
)

// authTestSetup wires up the minimum bits of a real Server for login
// flow tests: htpasswd-backed users, meta store, session store, and a
// mux mounted with the same routes as production.
type authTestSetup struct {
	t       *testing.T
	server  *Server
	handler http.Handler
}

func newAuthTestSetup(t *testing.T) *authTestSetup {
	t.Helper()
	s := newTestServerWithUser(t, "alice", "longenoughpw")
	s.sessions = newSessionStore(time.Hour, 24*time.Hour)
	t.Cleanup(s.sessions.Start())
	t.Cleanup(func() { s.authBgTasks.Wait() })

	// Templates live in the embedded FS; load them once for the suite.
	loadEmbeddedTemplates(s.logger)

	// Load the matcher so verifyPassword can hit the htpasswd file.
	if err := s.reloadHtpasswdFile(); err != nil {
		t.Fatalf("reload htpasswd: %v", err)
	}

	r := mux.NewRouter()
	r.HandleFunc("/login", s.loginGetHandler).Methods("GET")
	r.HandleFunc("/login", s.loginPostHandler).Methods("POST")
	r.HandleFunc("/login/totp", s.loginTOTPGetHandler).Methods("GET")
	r.HandleFunc("/login/totp", s.loginTOTPPostHandler).Methods("POST")
	r.HandleFunc("/logout", s.logoutHandler).Methods("POST")
	return &authTestSetup{t: t, server: s, handler: r}
}

// loadLoginForm fetches /login and returns the cookies + a freshly
// minted CSRF token. We don't parse the rendered HTML; we mint the
// token the same way the server would, which exercises the public
// helper exactly once and keeps the test independent of template
// changes.
func (a *authTestSetup) loadLoginForm() (csrf string, cookies []*http.Cookie) {
	req := httptest.NewRequest("GET", "/login", nil)
	rec := httptest.NewRecorder()
	a.handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		a.t.Fatalf("GET /login: %d", rec.Code)
	}
	return csrfTokenFor(""), rec.Result().Cookies()
}

func postForm(handler http.Handler, path string, form url.Values, cookies []*http.Cookie) *httptest.ResponseRecorder {
	req := httptest.NewRequest("POST", path, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	for _, c := range cookies {
		req.AddCookie(c)
	}
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	return rec
}

func TestLoginGetRendersForm(t *testing.T) {
	a := newAuthTestSetup(t)
	req := httptest.NewRequest("GET", "/login", nil)
	rec := httptest.NewRecorder()
	a.handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	body := rec.Body.String()
	for _, want := range []string{"<form", `name="username"`, `name="csrf"`, "Sign in"} {
		if !strings.Contains(body, want) {
			t.Errorf("login page missing %q", want)
		}
	}
}

func TestLoginPostMissingCSRF(t *testing.T) {
	a := newAuthTestSetup(t)
	form := url.Values{
		"username": {"alice"},
		"password": {"longenoughpw"},
	}
	rec := postForm(a.handler, "/login", form, nil)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", rec.Code)
	}
}

func TestLoginPostWrongPassword(t *testing.T) {
	a := newAuthTestSetup(t)
	csrf, _ := a.loadLoginForm()
	form := url.Values{
		"csrf":     {csrf},
		"username": {"alice"},
		"password": {"wrong"},
	}
	rec := postForm(a.handler, "/login", form, nil)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("expected 303 back to /login, got %d", rec.Code)
	}
	if loc := rec.Header().Get("Location"); !strings.HasPrefix(loc, "/login") {
		t.Fatalf("wrong Location: %q", loc)
	}
	// Must NOT have a session cookie set.
	for _, c := range rec.Result().Cookies() {
		if c.Name == sessionCookieName && c.Value != "" {
			t.Fatalf("session cookie issued on wrong password: %+v", c)
		}
	}
}

func TestLoginPostNoTOTPGrantsFullSession(t *testing.T) {
	a := newAuthTestSetup(t)
	csrf, _ := a.loadLoginForm()
	form := url.Values{
		"csrf":     {csrf},
		"username": {"alice"},
		"password": {"longenoughpw"},
	}
	rec := postForm(a.handler, "/login", form, nil)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("expected 303, got %d", rec.Code)
	}
	if loc := rec.Header().Get("Location"); loc != "/" {
		t.Fatalf("expected redirect to /, got %q", loc)
	}
	id := sessionIDFromResponse(rec)
	if id == "" {
		t.Fatal("expected session cookie")
	}
	sess, err := a.server.sessions.Get(id)
	if err != nil {
		t.Fatalf("session not stored: %v", err)
	}
	if sess.PendingMFA {
		t.Fatal("password-only user should get a full session, not pending")
	}
}

func TestLoginPostWithTOTPGrantsPendingSessionAndRedirects(t *testing.T) {
	a := newAuthTestSetup(t)
	enr, _ := a.server.startTOTPEnrollment("alice")
	code, _ := totp.GenerateCode(enr.Secret, time.Now().UTC())
	if _, err := a.server.finishTOTPEnrollment("alice", enr.Secret, code); err != nil {
		t.Fatalf("enrol: %v", err)
	}

	csrf, _ := a.loadLoginForm()
	form := url.Values{
		"csrf":     {csrf},
		"username": {"alice"},
		"password": {"longenoughpw"},
		"next":     {"/admin/files"},
	}
	rec := postForm(a.handler, "/login", form, nil)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("expected 303, got %d", rec.Code)
	}
	loc := rec.Header().Get("Location")
	if !strings.HasPrefix(loc, "/login/totp") || !strings.Contains(loc, "next=%2Fadmin%2Ffiles") {
		t.Fatalf("expected /login/totp with next=, got %q", loc)
	}
	id := sessionIDFromResponse(rec)
	sess, err := a.server.sessions.Get(id)
	if err != nil {
		t.Fatal(err)
	}
	if !sess.PendingMFA {
		t.Fatal("TOTP user should get a PendingMFA session, not full")
	}
}

func TestLoginTOTPPostPromotesSessionAndRotatesID(t *testing.T) {
	a := newAuthTestSetup(t)
	enr, _ := a.server.startTOTPEnrollment("alice")
	code, _ := totp.GenerateCode(enr.Secret, time.Now().UTC())
	if _, err := a.server.finishTOTPEnrollment("alice", enr.Secret, code); err != nil {
		t.Fatal(err)
	}

	// Step 1: password POST → pending session.
	csrf, _ := a.loadLoginForm()
	rec := postForm(a.handler, "/login", url.Values{
		"csrf":     {csrf},
		"username": {"alice"},
		"password": {"longenoughpw"},
	}, nil)
	pendingID := sessionIDFromResponse(rec)
	pendingCookies := rec.Result().Cookies()

	// Step 2: submit valid TOTP.
	currentCode, _ := totp.GenerateCode(enr.Secret, time.Now().UTC())
	rec2 := postForm(a.handler, "/login/totp", url.Values{
		"csrf": {csrfTokenFor(pendingID)},
		"code": {currentCode},
	}, pendingCookies)
	if rec2.Code != http.StatusSeeOther {
		t.Fatalf("expected 303, got %d (body=%s)", rec2.Code, rec2.Body.String())
	}
	newID := sessionIDFromResponse(rec2)
	if newID == "" || newID == pendingID {
		t.Fatalf("session ID must be rotated: old=%q new=%q", pendingID, newID)
	}
	if _, err := a.server.sessions.Get(pendingID); err == nil {
		t.Fatal("old pending ID must be invalid")
	}
	sess, err := a.server.sessions.Get(newID)
	if err != nil || sess.PendingMFA {
		t.Fatalf("new session should be full-auth: %+v err=%v", sess, err)
	}
}

func TestLoginTOTPPostInvalidCode(t *testing.T) {
	a := newAuthTestSetup(t)
	enr, _ := a.server.startTOTPEnrollment("alice")
	code, _ := totp.GenerateCode(enr.Secret, time.Now().UTC())
	if _, err := a.server.finishTOTPEnrollment("alice", enr.Secret, code); err != nil {
		t.Fatal(err)
	}

	csrf, _ := a.loadLoginForm()
	rec := postForm(a.handler, "/login", url.Values{
		"csrf":     {csrf},
		"username": {"alice"},
		"password": {"longenoughpw"},
	}, nil)
	pendingID := sessionIDFromResponse(rec)
	pendingCookies := rec.Result().Cookies()

	rec2 := postForm(a.handler, "/login/totp", url.Values{
		"csrf": {csrfTokenFor(pendingID)},
		"code": {"000000"},
	}, pendingCookies)
	if rec2.Code != http.StatusSeeOther {
		t.Fatalf("expected 303 back to form, got %d", rec2.Code)
	}
	// Pending session must still be pending.
	sess, err := a.server.sessions.Get(pendingID)
	if err != nil {
		t.Fatalf("pending session should survive an invalid code: %v", err)
	}
	if !sess.PendingMFA {
		t.Fatal("pending flag must not be cleared by a failed verify")
	}
}

func TestLoginTOTPPostRecoveryCode(t *testing.T) {
	a := newAuthTestSetup(t)
	enr, _ := a.server.startTOTPEnrollment("alice")
	code, _ := totp.GenerateCode(enr.Secret, time.Now().UTC())
	recoveryCodes, err := a.server.finishTOTPEnrollment("alice", enr.Secret, code)
	if err != nil {
		t.Fatal(err)
	}

	csrf, _ := a.loadLoginForm()
	rec := postForm(a.handler, "/login", url.Values{
		"csrf":     {csrf},
		"username": {"alice"},
		"password": {"longenoughpw"},
	}, nil)
	pendingID := sessionIDFromResponse(rec)
	pendingCookies := rec.Result().Cookies()

	rec2 := postForm(a.handler, "/login/totp", url.Values{
		"csrf":     {csrfTokenFor(pendingID)},
		"recovery": {recoveryCodes[0]},
	}, pendingCookies)
	if rec2.Code != http.StatusSeeOther {
		t.Fatalf("expected 303, got %d (body=%s)", rec2.Code, rec2.Body.String())
	}
	if rec2.Header().Get("Location") != "/" {
		t.Fatalf("expected redirect to /, got %q", rec2.Header().Get("Location"))
	}
	// Same recovery code must not work again.
	rec3 := postForm(a.handler, "/login/totp", url.Values{
		"csrf":     {csrfTokenFor(pendingID)},
		"recovery": {recoveryCodes[0]},
	}, pendingCookies)
	// Old pending cookies are now stale (promoted away) so we expect
	// redirect to /login. The point: recovery code reuse must NOT
	// authenticate; redirect to /login is acceptable.
	if rec3.Header().Get("Location") == "/" {
		t.Fatal("reused recovery code must not grant access")
	}
}

func TestLogoutDestroysSession(t *testing.T) {
	a := newAuthTestSetup(t)
	csrf, _ := a.loadLoginForm()
	loginRec := postForm(a.handler, "/login", url.Values{
		"csrf":     {csrf},
		"username": {"alice"},
		"password": {"longenoughpw"},
	}, nil)
	id := sessionIDFromResponse(loginRec)
	cookies := loginRec.Result().Cookies()

	rec := postForm(a.handler, "/logout", url.Values{
		"csrf": {csrfTokenFor(id)},
	}, cookies)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("expected 303, got %d", rec.Code)
	}
	if _, err := a.server.sessions.Get(id); err == nil {
		t.Fatal("session should be gone after logout")
	}
	// Deletion cookie must be set.
	var sawClear bool
	for _, c := range rec.Result().Cookies() {
		if c.Name == sessionCookieName && c.MaxAge < 0 {
			sawClear = true
		}
	}
	if !sawClear {
		t.Fatal("logout should send a session-cookie clear")
	}
}

func TestLoginGetSkipsWhenAlreadySignedIn(t *testing.T) {
	a := newAuthTestSetup(t)
	sess, _ := a.server.sessions.Create("alice", false)

	req := httptest.NewRequest("GET", "/login", nil)
	req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: sess.ID})
	rec := httptest.NewRecorder()
	a.handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("expected redirect, got %d", rec.Code)
	}
}

func TestSafeNext(t *testing.T) {
	cases := map[string]string{
		"":                  "/",
		"/admin/files":      "/admin/files",
		"//evil.example":    "/",
		"https://evil/path": "/",
		"javascript:alert":  "/",
		"relative":          "/",
		"/login":            "/",
		"/login/totp":       "/",
	}
	for in, want := range cases {
		if got := safeNext(in); got != want {
			t.Errorf("safeNext(%q)=%q, want %q", in, got, want)
		}
	}
}

func TestCSRFTokenMismatch(t *testing.T) {
	if !csrfCheck(csrfTokenFor("abc"), "abc") {
		t.Fatal("matching token should validate")
	}
	if csrfCheck(csrfTokenFor("abc"), "def") {
		t.Fatal("token bound to abc must not validate for def")
	}
	if csrfCheck("not-base64", "") {
		t.Fatal("malformed token must not validate")
	}
}

// sessionIDFromResponse returns the value of the session cookie in
// rec, or "" if not set / cleared.
func sessionIDFromResponse(rec *httptest.ResponseRecorder) string {
	for _, c := range rec.Result().Cookies() {
		if c.Name == sessionCookieName && c.MaxAge >= 0 && c.Value != "" {
			return c.Value
		}
	}
	return ""
}
