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

func newAccountTestSetup(t *testing.T) (*authTestSetup, *session) {
	t.Helper()
	a := newAuthTestSetup(t)
	r := a.handler.(*mux.Router)
	// Same wrapping as production — the account handlers themselves
	// return 401 on an unauthenticated request; webAuthHandler turns
	// that into the /login redirect users actually see.
	r.Handle("/account", a.server.webAuthHandler(http.HandlerFunc(a.server.accountGetHandler))).Methods("GET")
	r.Handle("/account/2fa/setup", a.server.webAuthHandler(http.HandlerFunc(a.server.account2FASetupGetHandler))).Methods("GET")
	r.Handle("/account/2fa/setup", a.server.webAuthHandler(http.HandlerFunc(a.server.account2FASetupPostHandler))).Methods("POST")
	r.Handle("/account/2fa/disable", a.server.webAuthHandler(http.HandlerFunc(a.server.account2FADisablePostHandler))).Methods("POST")
	r.Handle("/account/2fa/recovery/regenerate", a.server.webAuthHandler(http.HandlerFunc(a.server.account2FARecoveryRegenPostHandler))).Methods("POST")
	r.Handle("/account/tokens", a.server.webAuthHandler(http.HandlerFunc(a.server.accountTokenCreatePostHandler))).Methods("POST")
	r.Handle("/account/tokens/{id}/delete", a.server.webAuthHandler(http.HandlerFunc(a.server.accountTokenDeletePostHandler))).Methods("POST")

	sess, err := a.server.sessions.Create("alice", false)
	if err != nil {
		t.Fatal(err)
	}
	return a, sess
}

func cookieFor(id string) []*http.Cookie {
	return []*http.Cookie{{Name: sessionCookieName, Value: id}}
}

func TestAccountGetRedirectsWithoutSession(t *testing.T) {
	a, _ := newAccountTestSetup(t)
	rec := httptest.NewRecorder()
	a.handler.ServeHTTP(rec, httptest.NewRequest("GET", "/account", nil))
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("expected 303, got %d", rec.Code)
	}
	if !strings.HasPrefix(rec.Header().Get("Location"), "/login") {
		t.Fatalf("expected /login redirect, got %q", rec.Header().Get("Location"))
	}
}

func TestAccountGetRendersOverview(t *testing.T) {
	a, sess := newAccountTestSetup(t)
	req := httptest.NewRequest("GET", "/account", nil)
	for _, c := range cookieFor(sess.ID) {
		req.AddCookie(c)
	}
	rec := httptest.NewRecorder()
	a.handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	body := rec.Body.String()
	for _, want := range []string{"alice", "API tokens", "Two-factor"} {
		if !strings.Contains(body, want) {
			t.Errorf("account page missing %q", want)
		}
	}
}

func TestAccount2FASetupRendersQR(t *testing.T) {
	a, sess := newAccountTestSetup(t)
	req := httptest.NewRequest("GET", "/account/2fa/setup", nil)
	for _, c := range cookieFor(sess.ID) {
		req.AddCookie(c)
	}
	rec := httptest.NewRecorder()
	a.handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "data:image/png;base64,") {
		t.Fatal("expected inline QR PNG")
	}
	if !strings.Contains(body, `name="secret"`) {
		t.Fatal("expected hidden secret field")
	}
}

func TestAccount2FASetupFinishCreatesEnrolment(t *testing.T) {
	a, sess := newAccountTestSetup(t)
	enr, err := a.server.startTOTPEnrollment("alice")
	if err != nil {
		t.Fatal(err)
	}
	code, _ := totp.GenerateCode(enr.Secret, time.Now().UTC())

	rec := postForm(a.handler, "/account/2fa/setup", url.Values{
		"csrf":   {csrfTokenFor(sess.ID)},
		"secret": {enr.Secret},
		"code":   {code},
	}, cookieFor(sess.ID))
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 (rendered recovery codes), got %d body=%s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "recovery") {
		t.Fatal("expected recovery codes page")
	}
	m, _ := a.server.userMeta.Get("alice")
	if !m.TOTPEnabled {
		t.Fatal("TOTP should be enabled after a valid finish POST")
	}
}

func TestAccount2FASetupWrongCSRF(t *testing.T) {
	a, sess := newAccountTestSetup(t)
	rec := postForm(a.handler, "/account/2fa/setup", url.Values{
		"csrf":   {"bogus"},
		"secret": {"AAAA"},
		"code":   {"123456"},
	}, cookieFor(sess.ID))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", rec.Code)
	}
}

func TestAccount2FADisableRequiresValidCode(t *testing.T) {
	a, sess := newAccountTestSetup(t)
	enr, _ := a.server.startTOTPEnrollment("alice")
	c, _ := totp.GenerateCode(enr.Secret, time.Now().UTC())
	if _, err := a.server.finishTOTPEnrollment("alice", enr.Secret, c); err != nil {
		t.Fatal(err)
	}

	// Wrong code → still enabled.
	postForm(a.handler, "/account/2fa/disable", url.Values{
		"csrf": {csrfTokenFor(sess.ID)},
		"code": {"000000"},
	}, cookieFor(sess.ID))
	m, _ := a.server.userMeta.Get("alice")
	if !m.TOTPEnabled {
		t.Fatal("invalid code must not disable")
	}

	// Right code → disabled.
	current, _ := totp.GenerateCode(enr.Secret, time.Now().UTC())
	postForm(a.handler, "/account/2fa/disable", url.Values{
		"csrf": {csrfTokenFor(sess.ID)},
		"code": {current},
	}, cookieFor(sess.ID))
	m, _ = a.server.userMeta.Get("alice")
	if m.TOTPEnabled {
		t.Fatal("valid code should disable")
	}
}

func TestAccountTokenCreateAndDelete(t *testing.T) {
	a, sess := newAccountTestSetup(t)

	rec := postForm(a.handler, "/account/tokens", url.Values{
		"csrf": {csrfTokenFor(sess.ID)},
		"name": {"laptop"},
	}, cookieFor(sess.ID))
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 (rendered new-token page), got %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "tk_") {
		t.Fatal("expected the cleartext token to be rendered exactly once")
	}

	tokens := a.server.userMeta.ListAPITokens("alice")
	if len(tokens) != 1 {
		t.Fatalf("expected 1 token, got %d", len(tokens))
	}
	id := tokens[0].ID

	rec2 := postForm(a.handler, "/account/tokens/"+id+"/delete", url.Values{
		"csrf": {csrfTokenFor(sess.ID)},
	}, cookieFor(sess.ID))
	if rec2.Code != http.StatusSeeOther {
		t.Fatalf("expected 303 after delete, got %d", rec2.Code)
	}
	if got := a.server.userMeta.ListAPITokens("alice"); len(got) != 0 {
		t.Fatalf("expected token to be gone, got %d", len(got))
	}
}

func TestAccountTokenCreateExpiry(t *testing.T) {
	a, sess := newAccountTestSetup(t)
	postForm(a.handler, "/account/tokens", url.Values{
		"csrf":         {csrfTokenFor(sess.ID)},
		"name":         {"shortlived"},
		"expires_days": {"7"},
	}, cookieFor(sess.ID))
	tokens := a.server.userMeta.ListAPITokens("alice")
	if len(tokens) != 1 || tokens[0].ExpiresAt == nil {
		t.Fatalf("expected expiring token, got %+v", tokens)
	}
	exp := time.Until(*tokens[0].ExpiresAt)
	if exp < 6*24*time.Hour || exp > 8*24*time.Hour {
		t.Fatalf("expiry should be ~7 days, got %v", exp)
	}
}
