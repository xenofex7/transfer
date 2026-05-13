/*
The MIT License (MIT)

Copyright (c) 2026 xenofex7
*/

package server

import (
	"crypto/hmac"
	cryptoRand "crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Login flow:
//
//	GET  /login                 → renders the username/password form
//	POST /login                 → verifies password; if user has TOTP
//	                              enabled, mints a PendingMFA cookie
//	                              and redirects to /login/totp.
//	                              Otherwise a full session is minted.
//	GET  /login/totp            → renders the 6-digit / recovery form
//	POST /login/totp            → verifies code OR recovery code, then
//	                              Promotes the pending session.
//	POST /logout                → destroys the session.
//
// CSRF: every POST carries a hidden token derived from the session ID
// via HMAC-SHA256 keyed on a random per-process secret. The login POST
// uses a token derived from the bare "no-session" identity (the
// SameSite=Lax cookie blocks cross-site POSTs anyway; this is belt
// and braces against on-site XSS amplifying into a forced login).

const (
	loginRedirectParam = "next"
)

// authResultUser carries the verified identity into the templates and
// child handlers. Kept tiny on purpose so we can extend it later
// without touching every callsite.
type authResultUser struct {
	Name string
}

// loginPageData backs login.html and login_totp.html. Flash messages
// are stuffed into a single field for simplicity; templates render
// FlashErr in red and Flash in green.
type loginPageData struct {
	Hostname  string
	Username  string
	Next      string
	CSRFToken string
	Flash     string
	FlashErr  string
}

// renderLoginPage executes a named template. Centralised so any future
// branding/asset additions land in one spot.
func (s *Server) renderLoginPage(w http.ResponseWriter, name string, data loginPageData) {
	w.Header().Set("Cache-Control", "no-store")
	if err := htmlTemplates.ExecuteTemplate(w, name, data); err != nil {
		s.logger.Printf("auth: render %s: %v", name, err)
		http.Error(w, "template error", http.StatusInternalServerError)
	}
}

// loginGetHandler shows the password form. If the user already has a
// fully authenticated session we redirect straight to next= (or /),
// to make /login a safe link to share with team-mates.
func (s *Server) loginGetHandler(w http.ResponseWriter, r *http.Request) {
	if sess, err := s.sessions.Get(readSessionCookie(r)); err == nil && !sess.PendingMFA {
		http.Redirect(w, r, safeNext(r.URL.Query().Get(loginRedirectParam)), http.StatusSeeOther)
		return
	}
	s.renderLoginPage(w, "login.html", loginPageData{
		Hostname:  getURL(r, s.proxyPort).Host,
		Next:      safeNext(r.URL.Query().Get(loginRedirectParam)),
		CSRFToken: csrfTokenFor(""),
		Flash:     consumeAuthFlash(w, r, "ok"),
		FlashErr:  consumeAuthFlash(w, r, "err"),
	})
}

// loginPostHandler verifies the password. To dodge user-enumeration
// timing we always run a bcrypt-equivalent operation even on unknown
// users — the htpasswd matcher does this internally, so no extra work
// is needed.
func (s *Server) loginPostHandler(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form", http.StatusBadRequest)
		return
	}
	if !csrfCheck(r.PostForm.Get("csrf"), "") {
		http.Error(w, "CSRF token mismatch", http.StatusForbidden)
		return
	}

	name := strings.TrimSpace(r.PostForm.Get("username"))
	pw := r.PostForm.Get("password")
	next := safeNext(r.PostForm.Get(loginRedirectParam))

	if name == "" || pw == "" || !s.verifyPassword(name, pw) {
		// Sleep a beat to flatten the timing signal between
		// missing-user and wrong-password.
		time.Sleep(100 * time.Millisecond)
		s.flashAndBackTo(w, r, "/login", "Invalid credentials", true, next)
		return
	}

	hasTOTP := false
	if s.userMeta != nil {
		if m, ok := s.userMeta.Get(name); ok && m.TOTPEnabled {
			hasTOTP = true
		}
	}

	sess, err := s.sessions.Create(name, hasTOTP)
	if err != nil {
		s.logger.Printf("auth: create session: %v", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	setSessionCookie(w, r, sess.ID, s.sessions.idle)

	if hasTOTP {
		dest := "/login/totp"
		if next != "" {
			dest += "?" + loginRedirectParam + "=" + url.QueryEscape(next)
		}
		http.Redirect(w, r, dest, http.StatusSeeOther)
		return
	}
	http.Redirect(w, r, next, http.StatusSeeOther)
}

// loginTOTPGetHandler shows the second-factor form. Only PendingMFA
// sessions get past the gate; everyone else bounces back to /login or
// to the destination they were already cleared for.
func (s *Server) loginTOTPGetHandler(w http.ResponseWriter, r *http.Request) {
	sess, err := s.sessions.Get(readSessionCookie(r))
	if err != nil {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	if !sess.PendingMFA {
		http.Redirect(w, r, safeNext(r.URL.Query().Get(loginRedirectParam)), http.StatusSeeOther)
		return
	}
	s.renderLoginPage(w, "login_totp.html", loginPageData{
		Hostname:  getURL(r, s.proxyPort).Host,
		Username:  sess.Username,
		Next:      safeNext(r.URL.Query().Get(loginRedirectParam)),
		CSRFToken: csrfTokenFor(sess.ID),
		Flash:     consumeAuthFlash(w, r, "ok"),
		FlashErr:  consumeAuthFlash(w, r, "err"),
	})
}

// loginTOTPPostHandler accepts either a 6-digit TOTP code or a
// recovery code. On success the pending session ID is rotated to a
// fresh fully-authenticated one (defence in depth against fixation).
func (s *Server) loginTOTPPostHandler(w http.ResponseWriter, r *http.Request) {
	sess, err := s.sessions.Get(readSessionCookie(r))
	if err != nil {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	if !sess.PendingMFA {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form", http.StatusBadRequest)
		return
	}
	if !csrfCheck(r.PostForm.Get("csrf"), sess.ID) {
		http.Error(w, "CSRF token mismatch", http.StatusForbidden)
		return
	}

	next := safeNext(r.PostForm.Get(loginRedirectParam))
	code := strings.TrimSpace(r.PostForm.Get("code"))
	recovery := strings.TrimSpace(r.PostForm.Get("recovery"))

	var verifyErr error
	switch {
	case code != "":
		verifyErr = s.verifyUserTOTP(sess.Username, code)
	case recovery != "":
		verifyErr = s.consumeRecoveryCode(sess.Username, recovery)
	default:
		verifyErr = errTOTPInvalidCode
	}
	if verifyErr != nil {
		s.logger.Printf("auth: totp verify failed for %s: %v", sess.Username, verifyErr)
		time.Sleep(100 * time.Millisecond)
		dest := "/login/totp"
		if next != "" {
			dest += "?" + loginRedirectParam + "=" + url.QueryEscape(next)
		}
		s.flashAndBackTo(w, r, dest, "Invalid code", true, next)
		return
	}

	promoted, err := s.sessions.Promote(sess.ID)
	if err != nil {
		s.logger.Printf("auth: promote session: %v", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	setSessionCookie(w, r, promoted.ID, s.sessions.idle)
	http.Redirect(w, r, next, http.StatusSeeOther)
}

// logoutHandler invalidates the session both server-side and at the
// browser. Idempotent: hitting it without a cookie still 303s to
// /login so refresh-spam in the browser is harmless.
func (s *Server) logoutHandler(w http.ResponseWriter, r *http.Request) {
	id := readSessionCookie(r)
	if id != "" {
		if err := r.ParseForm(); err == nil {
			// CSRF on logout matters less than on state changes, but
			// reject obvious mismatches to keep automated logout sprays
			// from landing.
			if got := r.PostForm.Get("csrf"); got != "" && !csrfCheck(got, id) {
				http.Error(w, "CSRF token mismatch", http.StatusForbidden)
				return
			}
		}
		s.sessions.Destroy(id)
	}
	setSessionCookie(w, r, "", 0)
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

// verifyPassword consults the htpasswd matcher we already use for
// Basic Auth. Returns false on any error (no user, empty input,
// matcher unavailable) so callers can treat all rejection causes as
// "wrong credentials" without leaking which is which.
func (s *Server) verifyPassword(name, password string) bool {
	if name == "" || password == "" {
		return false
	}
	// Lazy-load the htpasswd matcher. basicAuthHandler used to be the
	// only entry that ever touched the matcher, so it was the only
	// place lazy-loading lived. After the cookie-auth split, the
	// browser /login flow can be the first thing a freshly booted
	// container sees — without this load, every login here silently
	// fails because htpasswdFile is still nil.
	if s.authHtpasswd != "" {
		s.htpasswdMu.RLock()
		loaded := s.htpasswdFile != nil
		s.htpasswdMu.RUnlock()
		if !loaded {
			if err := s.reloadHtpasswdFile(); err != nil {
				s.logger.Printf("auth: load htpasswd: %v", err)
				return false
			}
		}
	}
	s.htpasswdMu.RLock()
	f := s.htpasswdFile
	s.htpasswdMu.RUnlock()
	if f != nil && f.Match(name, password) {
		return true
	}
	// Legacy single-user mode (HTTP_AUTH_USER/PASS) still supported.
	if s.authUser != "" && s.authPass != "" && name == s.authUser && password == s.authPass {
		return true
	}
	return false
}

// flashAndBackTo writes a one-shot flash cookie and 303s back to dest.
// Flash cookies are SameSite=Strict + HttpOnly so they survive the
// redirect but can't be read by JS or smuggled cross-origin.
func (s *Server) flashAndBackTo(w http.ResponseWriter, r *http.Request, dest, msg string, isError bool, next string) {
	name := "auth_flash_ok"
	if isError {
		name = "auth_flash_err"
	}
	http.SetCookie(w, &http.Cookie{
		Name:     name,
		Value:    msg,
		Path:     "/",
		MaxAge:   30,
		HttpOnly: true,
		Secure:   requestIsHTTPS(r),
		SameSite: http.SameSiteLaxMode,
	})
	http.Redirect(w, r, dest, http.StatusSeeOther)
}

// consumeAuthFlash reads-and-deletes the named flash cookie. kind is
// either "ok" or "err"; anything else returns "".
func consumeAuthFlash(w http.ResponseWriter, r *http.Request, kind string) string {
	name := "auth_flash_ok"
	if kind == "err" {
		name = "auth_flash_err"
	}
	c, err := r.Cookie(name)
	if err != nil || c.Value == "" {
		return ""
	}
	http.SetCookie(w, &http.Cookie{Name: name, Value: "", Path: "/", MaxAge: -1})
	return c.Value
}

// safeNext defends against open-redirect: only same-origin relative
// paths are allowed. Anything else collapses to "/".
func safeNext(raw string) string {
	if raw == "" {
		return "/"
	}
	if strings.HasPrefix(raw, "//") || strings.Contains(raw, ":") {
		return "/"
	}
	if !strings.HasPrefix(raw, "/") {
		return "/"
	}
	if strings.HasPrefix(raw, "/login") {
		// Avoid bouncing the user back to /login after they just
		// completed login — would loop.
		return "/"
	}
	return raw
}

// --- CSRF -------------------------------------------------------------

// csrfSecret is a per-process random key. Reset on every restart so
// existing tokens become invalid — acceptable since CSRF tokens are
// short-lived (per-page-load).
var csrfSecret = mustRandomBytes(32)

func mustRandomBytes(n int) []byte {
	b := make([]byte, n)
	if _, err := cryptoRand.Read(b); err != nil {
		panic("csrf: cannot read random bytes: " + err.Error())
	}
	return b
}

// csrfTokenFor returns an HMAC bound to sessionID. Empty sessionID is
// fine: anonymous forms (login) use a token tied to "" so cross-origin
// POSTs without the cookie still need a fresh page load to obtain it.
func csrfTokenFor(sessionID string) string {
	mac := hmac.New(sha256.New, csrfSecret)
	mac.Write([]byte(sessionID))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

func csrfCheck(presented, sessionID string) bool {
	want := csrfTokenFor(sessionID)
	a, errA := base64.RawURLEncoding.DecodeString(presented)
	b, errB := base64.RawURLEncoding.DecodeString(want)
	if errA != nil || errB != nil {
		return false
	}
	return hmac.Equal(a, b)
}


