/*
The MIT License (MIT)

Copyright (c) 2026 xenofex7
*/

package server

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestChangelogRequiresSession(t *testing.T) {
	Changelog = []byte("# Changelog\n")
	s := &Server{sessions: newSessionStore(time.Hour, 24*time.Hour)}
	pending, _ := s.sessions.Create("alice", true)
	full, _ := s.sessions.Create("alice", false)

	cases := []struct {
		name   string
		cookie string
		want   int
	}{
		{"anonymous", "", http.StatusUnauthorized},
		{"pending MFA", pending.ID, http.StatusUnauthorized},
		{"signed in", full.ID, http.StatusOK},
	}
	for _, c := range cases {
		req := httptest.NewRequest("GET", "/changelog.json", nil)
		if c.cookie != "" {
			req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: c.cookie})
		}
		rec := httptest.NewRecorder()
		s.changelogHandler(rec, req)
		if rec.Code != c.want {
			t.Fatalf("%s: expected %d, got %d", c.name, c.want, rec.Code)
		}
	}
}
