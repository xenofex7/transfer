/*
The MIT License (MIT)

Copyright (c) 2026 xenofex7
*/

package server

import (
	"net/http"
	"net/mail"
	"strings"
)

// adminSettingsData is the template context for settings.html.
type adminSettingsData struct {
	Hostname     string
	Tagline      string
	EmailContact string
	Saved        bool
	Error        string
}

func (s *Server) adminSettingsGetHandler(w http.ResponseWriter, r *http.Request) {
	cfg := s.settings.Get()
	s.renderSettings(w, r, adminSettingsData{
		Hostname:     getURL(r, s.proxyPort).Host,
		Tagline:      cfg.Tagline,
		EmailContact: cfg.EmailContact,
	})
}

func (s *Server) adminSettingsPostHandler(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Invalid form", http.StatusBadRequest)
		return
	}

	var next Settings
	if r.PostForm.Get("reset") != "" {
		next = Settings{Tagline: DefaultTagline, EmailContact: ""}
	} else {
		next.Tagline = strings.TrimSpace(r.PostForm.Get("tagline"))
		next.EmailContact = strings.TrimSpace(r.PostForm.Get("email_contact"))
	}

	if len(next.Tagline) > 200 || len(next.EmailContact) > 200 {
		s.renderSettings(w, r, adminSettingsData{
			Hostname:     getURL(r, s.proxyPort).Host,
			Tagline:      next.Tagline,
			EmailContact: next.EmailContact,
			Error:        "Values must be 200 characters or fewer.",
		})
		return
	}
	if next.EmailContact != "" {
		if _, err := mail.ParseAddress(next.EmailContact); err != nil {
			s.renderSettings(w, r, adminSettingsData{
				Hostname:     getURL(r, s.proxyPort).Host,
				Tagline:      next.Tagline,
				EmailContact: next.EmailContact,
				Error:        "Contact email is not a valid address.",
			})
			return
		}
	}

	if err := s.settings.Set(next); err != nil {
		s.logger.Printf("admin: settings.Set: %v", err)
		s.renderSettings(w, r, adminSettingsData{
			Hostname:     getURL(r, s.proxyPort).Host,
			Tagline:      next.Tagline,
			EmailContact: next.EmailContact,
			Error:        "Could not persist settings: " + err.Error(),
		})
		return
	}

	s.renderSettings(w, r, adminSettingsData{
		Hostname:     getURL(r, s.proxyPort).Host,
		Tagline:      next.Tagline,
		EmailContact: next.EmailContact,
		Saved:        true,
	})
}

func (s *Server) renderSettings(w http.ResponseWriter, _ *http.Request, data adminSettingsData) {
	w.Header().Set("Cache-Control", "no-store")
	if err := htmlTemplates.ExecuteTemplate(w, "settings.html", data); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}
