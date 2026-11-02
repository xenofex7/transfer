/*
The MIT License (MIT)

Copyright (c) 2026 xenofex7
*/

package server

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"net/http"

	"github.com/gorilla/mux"
	"golang.org/x/crypto/bcrypt"
)

const (
	passwordHeader   = "X-Password"
	maxUploadPassLen = 256
)

func hashUploadPassword(pw string) (string, error) {
	h, err := bcrypt.GenerateFromPassword([]byte(pw), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	return string(h), nil
}

func (m metadata) passwordMatches(pw string) bool {
	return pw != "" && bcrypt.CompareHashAndPassword([]byte(m.PasswordHash), []byte(pw)) == nil
}

func unlockCookieName(token string) string {
	return "unlock_" + token
}

// unlockValue is an HMAC keyed with the bcrypt hash itself, so a cookie
// stays valid exactly as long as the upload keeps that password.
func unlockValue(m metadata, token, filename string) string {
	mac := hmac.New(sha256.New, []byte(m.PasswordHash))
	mac.Write([]byte(token + "/" + filename))
	return hex.EncodeToString(mac.Sum(nil))
}

func (s *Server) passwordSatisfied(r *http.Request, m metadata, token, filename string) (satisfied, throttled bool) {
	if m.PasswordHash == "" {
		return true, false
	}
	c, err := r.Cookie(unlockCookieName(token))
	if err == nil && hmac.Equal([]byte(c.Value), []byte(unlockValue(m, token, filename))) {
		return true, false
	}
	pw := r.Header.Get(passwordHeader)
	if pw == "" {
		return false, false
	}
	attempt, allowed := s.authThrottle.begin(fileKey(token, filename))
	if !allowed {
		return false, true
	}
	if !m.passwordMatches(pw) {
		return false, false
	}
	attempt.succeeded()
	return true, false
}

func (s *Server) renderLockedPage(w http.ResponseWriter, r *http.Request, filename, errMsg string) {
	data := struct {
		Filename   string
		Hostname   string
		Error      string
		WebAddress string
	}{
		filename,
		getURL(r, s.proxyPort).Host,
		errMsg,
		resolveWebAddress(r, s.proxyPath, s.proxyPort),
	}
	w.Header().Set("Cache-Control", "no-store")
	if err := htmlTemplates.ExecuteTemplate(w, "download.locked.html", data); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

// unlockHandler takes the password form of the locked download page,
// sets the unlock cookie and renders the preview right away. A redirect
// would arrive with a same-path Referer, which the preview matcher
// treats as a direct download.
func (s *Server) unlockHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	token := vars["token"]
	filename := vars["filename"]

	m, err := s.checkMetadata(r.Context(), token, filename, false)
	if err != nil {
		http.Error(w, http.StatusText(http.StatusNotFound), http.StatusNotFound)
		return
	}
	if m.PasswordHash == "" {
		http.Redirect(w, r, r.URL.Path, http.StatusSeeOther)
		return
	}
	attempt, allowed := s.authThrottle.begin(fileKey(token, filename))
	if !allowed {
		w.WriteHeader(http.StatusTooManyRequests)
		s.renderLockedPage(w, r, filename, tooManyAttempts)
		return
	}
	pw := ""
	if err := r.ParseForm(); err == nil {
		pw = r.PostForm.Get("password")
	}
	if !m.passwordMatches(pw) {
		w.WriteHeader(http.StatusUnauthorized)
		s.renderLockedPage(w, r, filename, "Wrong password")
		return
	}
	attempt.succeeded()
	http.SetCookie(w, &http.Cookie{
		Name:     unlockCookieName(token),
		Value:    unlockValue(m, token, filename),
		Path:     "/",
		MaxAge:   3600,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})
	r.Header.Set(passwordHeader, pw)
	s.previewHandler(w, r)
}
