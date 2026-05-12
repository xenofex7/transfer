/*
The MIT License (MIT)

Copyright (c) 2026 xenofex7
*/

package server

import (
	"errors"
	"net/http"
	"strings"

	"github.com/gorilla/mux"
)

// adminUsersData is the template context for users.html.
type adminUsersData struct {
	Hostname    string
	CurrentUser string
	Users       []adminUserRow
	Available   bool
	Flash       string
	FlashError  string
}

type adminUserRow struct {
	Name      string
	IsCurrent bool
}

func (s *Server) adminUsersGetHandler(w http.ResponseWriter, r *http.Request) {
	data := s.usersData(r)
	if c, err := r.Cookie("users_flash_ok"); err == nil && c.Value != "" {
		data.Flash = c.Value
		http.SetCookie(w, &http.Cookie{Name: "users_flash_ok", Value: "", Path: "/admin/users", MaxAge: -1})
	}
	if c, err := r.Cookie("users_flash_err"); err == nil && c.Value != "" {
		data.FlashError = c.Value
		http.SetCookie(w, &http.Cookie{Name: "users_flash_err", Value: "", Path: "/admin/users", MaxAge: -1})
	}
	w.Header().Set("Cache-Control", "no-store")
	if err := htmlTemplates.ExecuteTemplate(w, "users.html", data); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func (s *Server) adminUsersAddHandler(w http.ResponseWriter, r *http.Request) {
	if s.users == nil {
		s.usersFlashAndRedirect(w, r, errStoreUnavailable.Error(), true)
		return
	}
	if err := r.ParseForm(); err != nil {
		s.usersFlashAndRedirect(w, r, "Invalid form submission", true)
		return
	}
	name := strings.TrimSpace(r.PostForm.Get("username"))
	pw := r.PostForm.Get("password")
	if err := s.users.Add(name, pw); err != nil {
		s.usersFlashAndRedirect(w, r, "Could not add user: "+err.Error(), true)
		return
	}
	s.usersFlashAndRedirect(w, r, "User "+name+" added", false)
}

func (s *Server) adminUsersResetHandler(w http.ResponseWriter, r *http.Request) {
	if s.users == nil {
		s.usersFlashAndRedirect(w, r, errStoreUnavailable.Error(), true)
		return
	}
	if err := r.ParseForm(); err != nil {
		s.usersFlashAndRedirect(w, r, "Invalid form submission", true)
		return
	}
	name := mux.Vars(r)["name"]
	pw := r.PostForm.Get("password")
	if err := s.users.SetPassword(name, pw); err != nil {
		status := http.StatusBadRequest
		if errors.Is(err, errUserNotFound) {
			status = http.StatusNotFound
		}
		s.logger.Printf("admin: reset %s: %v (%d)", name, err, status)
		s.usersFlashAndRedirect(w, r, "Reset failed: "+err.Error(), true)
		return
	}
	s.usersFlashAndRedirect(w, r, "Password for "+name+" updated", false)
}

func (s *Server) adminUsersDeleteHandler(w http.ResponseWriter, r *http.Request) {
	if s.users == nil {
		s.usersFlashAndRedirect(w, r, errStoreUnavailable.Error(), true)
		return
	}
	name := mux.Vars(r)["name"]
	current := currentUserFromRequest(r)
	if err := s.users.Delete(name, current); err != nil {
		s.usersFlashAndRedirect(w, r, "Delete failed: "+err.Error(), true)
		return
	}
	s.usersFlashAndRedirect(w, r, "User "+name+" deleted", false)
}

func (s *Server) usersData(r *http.Request) adminUsersData {
	current := currentUserFromRequest(r)
	d := adminUsersData{
		Hostname:    getURL(r, s.proxyPort).Host,
		CurrentUser: current,
		Available:   s.users != nil,
	}
	if s.users == nil {
		return d
	}
	names, err := s.users.List()
	if err != nil {
		s.logger.Printf("admin: users.List: %v", err)
		d.FlashError = "Could not read user list: " + err.Error()
		return d
	}
	d.Users = make([]adminUserRow, 0, len(names))
	for _, n := range names {
		d.Users = append(d.Users, adminUserRow{Name: n, IsCurrent: n == current})
	}
	return d
}

func (s *Server) usersFlashAndRedirect(w http.ResponseWriter, r *http.Request, msg string, isError bool) {
	name := "users_flash_ok"
	if isError {
		name = "users_flash_err"
	}
	http.SetCookie(w, &http.Cookie{
		Name:     name,
		Value:    msg,
		Path:     "/admin/users",
		MaxAge:   30,
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
	})
	http.Redirect(w, r, "/admin/users", http.StatusSeeOther)
}
