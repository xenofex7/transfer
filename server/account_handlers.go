/*
The MIT License (MIT)

Copyright (c) 2026 xenofex7
*/

package server

import (
	"encoding/base64"
	"errors"
	htmlTemplate "html/template"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gorilla/mux"
	qrcode "github.com/skip2/go-qrcode"
)

// Account flow:
//
//	GET  /account                          → overview: TOTP status,
//	                                          recovery code count,
//	                                          API token list
//	GET  /account/2fa/setup                → QR code + first-code form
//	POST /account/2fa/setup                → finish enrolment, render
//	                                          one-shot recovery codes
//	POST /account/2fa/disable              → wipe TOTP after a valid
//	                                          code (re-auth in-flow)
//	POST /account/2fa/recovery/regenerate  → mint fresh recovery codes
//	POST /account/tokens                   → create a new API token,
//	                                          render cleartext once
//	POST /account/tokens/{id}/delete       → revoke a token
//
// All routes go through requireFullSession so they are unreachable
// without a fully authenticated cookie. Mutating POSTs check the CSRF
// token bound to the session ID.

// accountPageData backs account.html. We pre-format timestamps so the
// template stays free of any date math.
type accountPageData struct {
	Hostname       string
	CurrentUser    string
	CSRFToken      string
	TOTPEnabled    bool
	TOTPEnabledAt  string
	RecoveryLeft   int
	Tokens         []accountTokenRow
	Flash          string
	FlashErr       string
	NewToken       string // displayed exactly once after creation
	NewRecovery    []string
}

type accountTokenRow struct {
	ID         string
	Name       string
	CreatedAt  string
	LastUsedAt string
	ExpiresAt  string
}

type totpSetupPageData struct {
	Hostname    string
	CurrentUser string
	CSRFToken   string
	Secret      string
	// QRDataURL must be marked safe because html/template otherwise
	// sanitises data: URIs in src= to #ZgotmplZ. The string itself is
	// produced from a base64 encoding of bytes we generated, so there
	// is no untrusted content to escape.
	QRDataURL htmlTemplate.URL
	URL       string
	FlashErr  string
}

type totpDonePageData struct {
	Hostname    string
	CurrentUser string
	Codes       []string
}

func (s *Server) accountGetHandler(w http.ResponseWriter, r *http.Request) {
	sess, ok := s.requireFullSession(w, r)
	if !ok {
		return
	}
	data := s.buildAccountData(r, sess.Username)
	data.Flash = consumeAuthFlash(w, r, "ok")
	data.FlashErr = consumeAuthFlash(w, r, "err")
	w.Header().Set("Cache-Control", "no-store")
	if err := htmlTemplates.ExecuteTemplate(w, "account.html", data); err != nil {
		s.logger.Printf("account: render: %v", err)
		http.Error(w, "template error", http.StatusInternalServerError)
	}
}

// buildAccountData reads the meta store and assembles the
// presentation-ready struct. Times are rendered in UTC ISO-ish form;
// the UI can localise client-side if it wants to.
func (s *Server) buildAccountData(r *http.Request, username string) accountPageData {
	data := accountPageData{
		Hostname:    getURL(r, s.proxyPort).Host,
		CurrentUser: username,
		CSRFToken:   csrfTokenFor(readSessionCookie(r)),
	}
	if s.userMeta == nil {
		return data
	}
	if m, ok := s.userMeta.Get(username); ok {
		data.TOTPEnabled = m.TOTPEnabled
		if m.TOTPEnabledAt != nil {
			data.TOTPEnabledAt = m.TOTPEnabledAt.Format(time.RFC3339)
		}
		data.RecoveryLeft = len(m.RecoveryHashes)
		for _, tok := range m.APITokens {
			row := accountTokenRow{
				ID:        tok.ID,
				Name:      tok.Name,
				CreatedAt: tok.CreatedAt.Format(time.RFC3339),
			}
			if tok.LastUsedAt != nil {
				row.LastUsedAt = tok.LastUsedAt.Format(time.RFC3339)
			}
			if tok.ExpiresAt != nil {
				row.ExpiresAt = tok.ExpiresAt.Format(time.RFC3339)
			}
			data.Tokens = append(data.Tokens, row)
		}
	}
	return data
}

func (s *Server) account2FASetupGetHandler(w http.ResponseWriter, r *http.Request) {
	sess, ok := s.requireFullSession(w, r)
	if !ok {
		return
	}
	enr, err := s.startTOTPEnrollment(sess.Username)
	if err != nil {
		if errors.Is(err, errTOTPAlreadyEnrolled) {
			s.flashAndBackTo(w, r, "/account", "Two-factor is already enabled. Disable it first to re-enrol.", true, "")
			return
		}
		s.logger.Printf("account: start totp: %v", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	png, err := qrcode.Encode(enr.URL, qrcode.Medium, 256)
	if err != nil {
		s.logger.Printf("account: qr encode: %v", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	data := totpSetupPageData{
		Hostname:    getURL(r, s.proxyPort).Host,
		CurrentUser: sess.Username,
		CSRFToken:   csrfTokenFor(sess.ID),
		Secret:      enr.Secret,
		URL:         enr.URL,
		QRDataURL:   htmlTemplate.URL("data:image/png;base64," + base64.StdEncoding.EncodeToString(png)),
		FlashErr:    consumeAuthFlash(w, r, "err"),
	}
	w.Header().Set("Cache-Control", "no-store")
	if err := htmlTemplates.ExecuteTemplate(w, "account_2fa_setup.html", data); err != nil {
		s.logger.Printf("account: render setup: %v", err)
		http.Error(w, "template error", http.StatusInternalServerError)
	}
}

func (s *Server) account2FASetupPostHandler(w http.ResponseWriter, r *http.Request) {
	sess, ok := s.requireFullSession(w, r)
	if !ok {
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
	secret := strings.TrimSpace(r.PostForm.Get("secret"))
	code := strings.TrimSpace(r.PostForm.Get("code"))
	if secret == "" || code == "" {
		s.flashAndBackTo(w, r, "/account/2fa/setup", "Enter the code from your authenticator", true, "")
		return
	}

	codes, err := s.finishTOTPEnrollment(sess.Username, secret, code)
	if err != nil {
		s.flashAndBackTo(w, r, "/account/2fa/setup", "Could not enable 2FA: "+err.Error(), true, "")
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	if err := htmlTemplates.ExecuteTemplate(w, "account_2fa_done.html", totpDonePageData{
		Hostname:    getURL(r, s.proxyPort).Host,
		CurrentUser: sess.Username,
		Codes:       codes,
	}); err != nil {
		s.logger.Printf("account: render done: %v", err)
		http.Error(w, "template error", http.StatusInternalServerError)
	}
}

func (s *Server) account2FADisablePostHandler(w http.ResponseWriter, r *http.Request) {
	sess, ok := s.requireFullSession(w, r)
	if !ok {
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
	// Re-auth: require a currently valid TOTP code (or a recovery
	// code) so a session hijacker can't disable 2FA on its own.
	code := strings.TrimSpace(r.PostForm.Get("code"))
	recovery := strings.TrimSpace(r.PostForm.Get("recovery"))
	switch {
	case code != "":
		if err := s.verifyUserTOTP(sess.Username, code); err != nil {
			s.flashAndBackTo(w, r, "/account", "Disable failed: invalid code", true, "")
			return
		}
	case recovery != "":
		if err := s.consumeRecoveryCode(sess.Username, recovery); err != nil {
			s.flashAndBackTo(w, r, "/account", "Disable failed: invalid recovery code", true, "")
			return
		}
	default:
		s.flashAndBackTo(w, r, "/account", "Provide a code to confirm disabling 2FA", true, "")
		return
	}
	if err := s.disableTOTP(sess.Username); err != nil {
		s.flashAndBackTo(w, r, "/account", "Disable failed: "+err.Error(), true, "")
		return
	}
	s.flashAndBackTo(w, r, "/account", "Two-factor authentication disabled", false, "")
}

func (s *Server) account2FARecoveryRegenPostHandler(w http.ResponseWriter, r *http.Request) {
	sess, ok := s.requireFullSession(w, r)
	if !ok {
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
	// Same re-auth gate as disable: present a current code so a
	// hijacked session can't print a fresh sheet and walk off with it.
	code := strings.TrimSpace(r.PostForm.Get("code"))
	if code == "" || s.verifyUserTOTP(sess.Username, code) != nil {
		s.flashAndBackTo(w, r, "/account", "Regenerate failed: invalid code", true, "")
		return
	}
	codes, err := s.regenerateRecoveryCodes(sess.Username)
	if err != nil {
		s.flashAndBackTo(w, r, "/account", "Regenerate failed: "+err.Error(), true, "")
		return
	}
	data := s.buildAccountData(r, sess.Username)
	data.NewRecovery = codes
	data.Flash = "New recovery codes generated. Save them now — they will not be shown again."
	w.Header().Set("Cache-Control", "no-store")
	if err := htmlTemplates.ExecuteTemplate(w, "account.html", data); err != nil {
		s.logger.Printf("account: render recovery: %v", err)
	}
}

func (s *Server) accountTokenCreatePostHandler(w http.ResponseWriter, r *http.Request) {
	sess, ok := s.requireFullSession(w, r)
	if !ok {
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
	name := strings.TrimSpace(r.PostForm.Get("name"))
	var expiresAt *time.Time
	if days := strings.TrimSpace(r.PostForm.Get("expires_days")); days != "" {
		n, err := strconv.Atoi(days)
		if err != nil || n <= 0 || n > 3650 {
			s.flashAndBackTo(w, r, "/account", "Expiry must be between 1 and 3650 days", true, "")
			return
		}
		t := time.Now().UTC().Add(time.Duration(n) * 24 * time.Hour)
		expiresAt = &t
	}
	wire, _, err := s.userMeta.CreateAPIToken(sess.Username, name, expiresAt)
	if err != nil {
		s.flashAndBackTo(w, r, "/account", "Token create failed: "+err.Error(), true, "")
		return
	}
	data := s.buildAccountData(r, sess.Username)
	data.NewToken = wire
	data.Flash = "Token created. Copy it now — it will not be shown again."
	w.Header().Set("Cache-Control", "no-store")
	if err := htmlTemplates.ExecuteTemplate(w, "account.html", data); err != nil {
		s.logger.Printf("account: render token: %v", err)
	}
}

func (s *Server) accountTokenDeletePostHandler(w http.ResponseWriter, r *http.Request) {
	sess, ok := s.requireFullSession(w, r)
	if !ok {
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
	id := mux.Vars(r)["id"]
	if id == "" {
		s.flashAndBackTo(w, r, "/account", "Token id required", true, "")
		return
	}
	if err := s.userMeta.DeleteAPIToken(sess.Username, id); err != nil {
		s.flashAndBackTo(w, r, "/account", "Token delete failed: "+err.Error(), true, "")
		return
	}
	s.flashAndBackTo(w, r, "/account", "Token revoked", false, "")
}
