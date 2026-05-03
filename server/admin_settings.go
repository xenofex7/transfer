/*
The MIT License (MIT)

Copyright (c) 2026 xenofex7
*/

package server

import (
	"net/http"
	"net/mail"
	"path/filepath"
	"strings"

	"github.com/gorilla/mux"
)

// adminSettingsData is the template context for settings.html.
type adminSettingsData struct {
	Hostname        string
	Tagline         string
	EmailContact    string
	Theme           string
	HasLogo         bool
	HasFavicon      bool
	BrandingEnabled bool
	// Flash + FlashError are one-shot messages surfaced via toast on the
	// next GET render. They come from the settings_flash_* cookies that
	// flashAndRedirect sets after a successful POST or upload.
	Flash      string
	FlashError string
}

func (s *Server) adminSettingsGetHandler(w http.ResponseWriter, r *http.Request) {
	cfg := s.settings.Get()
	data := s.settingsData(r, cfg.Tagline, cfg.EmailContact, cfg.Theme)
	if c, err := r.Cookie("settings_flash_ok"); err == nil && c.Value != "" {
		data.Flash = c.Value
		http.SetCookie(w, &http.Cookie{Name: "settings_flash_ok", Value: "", Path: "/admin/settings", MaxAge: -1})
	}
	if c, err := r.Cookie("settings_flash_err"); err == nil && c.Value != "" {
		data.FlashError = c.Value
		http.SetCookie(w, &http.Cookie{Name: "settings_flash_err", Value: "", Path: "/admin/settings", MaxAge: -1})
	}
	s.renderSettings(w, r, data)
}

func (s *Server) adminSettingsPostHandler(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		s.flashAndRedirect(w, r, "Invalid form submission", true)
		return
	}

	var next Settings
	if r.PostForm.Get("reset") != "" {
		next = Settings{Tagline: DefaultTagline, EmailContact: "", Theme: DefaultTheme}
	} else {
		next.Tagline = strings.TrimSpace(r.PostForm.Get("tagline"))
		next.EmailContact = strings.TrimSpace(r.PostForm.Get("email_contact"))
		next.Theme = strings.TrimSpace(r.PostForm.Get("theme"))
		if !ValidThemes[next.Theme] {
			next.Theme = DefaultTheme
		}
	}

	if len(next.Tagline) > 200 || len(next.EmailContact) > 200 {
		s.flashAndRedirect(w, r, "Values must be 200 characters or fewer.", true)
		return
	}
	if next.EmailContact != "" {
		if _, err := mail.ParseAddress(next.EmailContact); err != nil {
			s.flashAndRedirect(w, r, "Contact email is not a valid address.", true)
			return
		}
	}

	if err := s.settings.Set(next); err != nil {
		s.logger.Printf("admin: settings.Set: %v", err)
		s.flashAndRedirect(w, r, "Could not persist settings: "+err.Error(), true)
		return
	}

	if r.PostForm.Get("reset") != "" {
		s.flashAndRedirect(w, r, "Settings reset to defaults", false)
	} else {
		s.flashAndRedirect(w, r, "Settings saved", false)
	}
}

func (s *Server) renderSettings(w http.ResponseWriter, _ *http.Request, data adminSettingsData) {
	w.Header().Set("Cache-Control", "no-store")
	if err := htmlTemplates.ExecuteTemplate(w, "settings.html", data); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

// settingsData centralises the template-context construction so every code
// path renders the same hostname / branding-state info.
func (s *Server) settingsData(r *http.Request, tagline, email, theme string) adminSettingsData {
	d := adminSettingsData{
		Hostname:        getURL(r, s.proxyPort).Host,
		Tagline:         tagline,
		EmailContact:    email,
		Theme:           theme,
		BrandingEnabled: s.branding != nil && s.brandingDir != "",
	}
	if s.branding != nil {
		d.HasLogo = s.branding.Get(BrandingLogo).exists
		d.HasFavicon = s.branding.Get(BrandingFavicon).exists
	}
	return d
}

// adminBrandingUploadHandler accepts a multipart upload of a single image
// for the given slot, validates extension and size via brandingStore.Save,
// then redirects back to the settings page with a flash result.
func (s *Server) adminBrandingUploadHandler(w http.ResponseWriter, r *http.Request) {
	slot := BrandingSlot(mux.Vars(r)["slot"])
	if s.branding == nil || s.brandingDir == "" {
		s.flashAndRedirect(w, r, "Branding storage not configured.", true)
		return
	}

	if err := r.ParseMultipartForm(MaxBrandingBytes + 1<<10); err != nil {
		s.flashAndRedirect(w, r, "Could not parse upload: "+err.Error(), true)
		return
	}
	file, header, err := r.FormFile("file")
	if err != nil {
		s.flashAndRedirect(w, r, "No file in upload.", true)
		return
	}
	defer func() { _ = file.Close() }()

	ext := strings.ToLower(filepath.Ext(header.Filename))
	if err := s.branding.Save(slot, ext, file); err != nil {
		s.flashAndRedirect(w, r, err.Error(), true)
		return
	}
	s.flashAndRedirect(w, r, strings.Title(string(slot))+" updated", false) //nolint:staticcheck // strings.Title is fine for ASCII slot names
}

// adminBrandingDeleteHandler removes the custom file for slot, restoring
// the embedded fallback.
func (s *Server) adminBrandingDeleteHandler(w http.ResponseWriter, r *http.Request) {
	slot := BrandingSlot(mux.Vars(r)["slot"])
	if s.branding == nil {
		http.Error(w, "branding store not configured", http.StatusServiceUnavailable)
		return
	}
	if err := s.branding.Delete(slot); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// flashAndRedirect sets a one-shot cookie the GET handler reads to surface
// success/error messages as toasts, then redirects back to /admin/settings.
func (s *Server) flashAndRedirect(w http.ResponseWriter, r *http.Request, msg string, isError bool) {
	name := "settings_flash_ok"
	if isError {
		name = "settings_flash_err"
	}
	http.SetCookie(w, &http.Cookie{
		Name:     name,
		Value:    msg,
		Path:     "/admin/settings",
		MaxAge:   30,
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
	})
	http.Redirect(w, r, "/admin/settings", http.StatusSeeOther)
}
