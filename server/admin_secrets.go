/*
The MIT License (MIT)

Copyright (c) 2026 xenofex7
*/

package server

import (
	"net/http"
	"time"

	"github.com/gorilla/mux"
)

type adminSecretRow struct {
	ID           string
	ShortID      string
	Creator      string
	CreatedAt    time.Time
	CreatedHuman string
	ExpiresAt    time.Time
	ExpiresHuman string
}

type adminSecretsData struct {
	Hostname    string
	CurrentUser string
	CSRFToken   string
	Enabled     bool
	Rows        []adminSecretRow
	Total       int
	Flash       string
	FlashError  string
}

const (
	secretsFlashOK  = "secrets_flash_ok"
	secretsFlashErr = "secrets_flash_err"
)

func (s *Server) adminSecretsHandler(w http.ResponseWriter, r *http.Request) {
	data := adminSecretsData{
		Hostname:    getURL(r, s.proxyPort).Host,
		CurrentUser: currentUserFromRequest(r),
		Enabled:     s.secrets != nil,
	}
	if sess, ok := s.sessionForRequest(r); ok {
		data.CSRFToken = csrfTokenFor(sess.ID)
	}
	if c, err := r.Cookie(secretsFlashOK); err == nil && c.Value != "" {
		data.Flash = c.Value
		http.SetCookie(w, &http.Cookie{Name: secretsFlashOK, Value: "", Path: "/admin/secrets", MaxAge: -1})
	}
	if c, err := r.Cookie(secretsFlashErr); err == nil && c.Value != "" {
		data.FlashError = c.Value
		http.SetCookie(w, &http.Cookie{Name: secretsFlashErr, Value: "", Path: "/admin/secrets", MaxAge: -1})
	}

	if s.secrets != nil {
		entries, err := s.secrets.List()
		if err != nil {
			s.logger.Printf("admin: secrets.List: %v", err)
			data.FlashError = "Could not list secrets: " + err.Error()
		}
		data.Rows = make([]adminSecretRow, 0, len(entries))
		for _, e := range entries {
			data.Rows = append(data.Rows, adminSecretRow{
				ID:           e.ID,
				ShortID:      e.ID[:8],
				Creator:      e.Creator,
				CreatedAt:    e.CreatedAt,
				CreatedHuman: e.CreatedAt.Format("2006-01-02 15:04"),
				ExpiresAt:    e.ExpiresAt,
				ExpiresHuman: formatRetention(time.Until(e.ExpiresAt)),
			})
		}
		data.Total = len(data.Rows)
	}

	w.Header().Set("Cache-Control", "no-store")
	if err := htmlTemplates.ExecuteTemplate(w, "admin_secrets.html", data); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func (s *Server) adminSecretsDeleteHandler(w http.ResponseWriter, r *http.Request) {
	if s.secrets == nil {
		s.secretsFlashAndRedirect(w, r, "Secrets are disabled on this server", true)
		return
	}
	if err := r.ParseForm(); err != nil {
		s.secretsFlashAndRedirect(w, r, "Invalid request", true)
		return
	}
	if !s.sessionCSRFValid(r) {
		s.secretsFlashAndRedirect(w, r, invalidFormToken, true)
		return
	}
	id := mux.Vars(r)["id"]
	if err := s.secrets.Delete(id); err != nil {
		s.secretsFlashAndRedirect(w, r, "Delete failed: "+err.Error(), true)
		return
	}
	s.secretsFlashAndRedirect(w, r, "Secret deleted", false)
}

func (s *Server) secretsFlashAndRedirect(w http.ResponseWriter, r *http.Request, msg string, isError bool) {
	name := secretsFlashOK
	if isError {
		name = secretsFlashErr
	}
	http.SetCookie(w, &http.Cookie{
		Name:     name,
		Value:    msg,
		Path:     "/admin/secrets",
		MaxAge:   30,
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
	})
	http.Redirect(w, r, "/admin/secrets", http.StatusSeeOther)
}
