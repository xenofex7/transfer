/*
The MIT License (MIT)

Copyright (c) 2026 xenofex7
*/

package server

import (
	"encoding/json"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"testing"
)

func TestSettingsStoreUsesBootstrapWhenFileMissing(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".settings.json")

	s, err := newSettingsStore(path, Settings{Tagline: "boot", EmailContact: "a@b"})
	if err != nil {
		t.Fatal(err)
	}
	got := s.Get()
	if got.Tagline != "boot" || got.EmailContact != "a@b" {
		t.Fatalf("bootstrap not used: %+v", got)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("expected no file written before Set, got err=%v", err)
	}
}

func TestSettingsStorePersistedFileWinsOverBootstrap(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".settings.json")
	if err := os.WriteFile(path, []byte(`{"tagline":"saved","email_contact":"x@y"}`), 0o600); err != nil {
		t.Fatal(err)
	}

	s, err := newSettingsStore(path, Settings{Tagline: "boot", EmailContact: "boot@b"})
	if err != nil {
		t.Fatal(err)
	}
	got := s.Get()
	if got.Tagline != "saved" || got.EmailContact != "x@y" {
		t.Fatalf("file did not win: %+v", got)
	}
}

func TestSettingsStoreSetWritesAtomically(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".settings.json")
	s, err := newSettingsStore(path, Settings{Tagline: "boot"})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Set(Settings{Tagline: "new", EmailContact: "ops@example.com"}); err != nil {
		t.Fatal(err)
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var on Settings
	if err := json.Unmarshal(raw, &on); err != nil {
		t.Fatal(err)
	}
	if on.Tagline != "new" || on.EmailContact != "ops@example.com" {
		t.Fatalf("disk state wrong: %+v", on)
	}

	// no leftover .settings-*.json tempfiles
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		name := e.Name()
		if name != ".settings.json" {
			t.Errorf("unexpected leftover file: %s", name)
		}
	}
}

func TestSettingsStoreEmptyValuesAreHonored(t *testing.T) {
	// An admin who clears the tagline / contact email expects them to stay
	// hidden - the bootstrap default must NOT win after a restart.
	dir := t.TempDir()
	path := filepath.Join(dir, ".settings.json")
	if err := os.WriteFile(path, []byte(`{"tagline":"","email_contact":""}`), 0o600); err != nil {
		t.Fatal(err)
	}

	s, err := newSettingsStore(path, Settings{Tagline: "boot", EmailContact: "x@y"})
	if err != nil {
		t.Fatal(err)
	}
	got := s.Get()
	if got.Tagline != "" {
		t.Fatalf("expected empty tagline to survive, got %q", got.Tagline)
	}
	if got.EmailContact != "" {
		t.Fatalf("expected empty email, got %q", got.EmailContact)
	}
}

func TestAdminSettingsSaveKeepsHeartbeatChoice(t *testing.T) {
	store, err := newSettingsStore(filepath.Join(t.TempDir(), ".settings.json"), Settings{})
	if err != nil {
		t.Fatal(err)
	}
	off := false
	if err := store.Set(Settings{Tagline: "old", HeartbeatEnabled: &off}); err != nil {
		t.Fatal(err)
	}
	s := &Server{settings: store, logger: log.New(io.Discard, "", 0)}
	sess := startTestSession(t, s, "alice")

	for _, form := range []url.Values{
		{"tagline": {"new"}, "theme": {DefaultTheme}},
		{"reset": {"1"}},
	} {
		form.Set("csrf", csrfTokenFor(sess.ID))
		req := sessionPost("/admin/settings", form, sess)
		rec := httptest.NewRecorder()
		s.adminSettingsPostHandler(rec, req)
		if rec.Code != http.StatusSeeOther {
			t.Fatalf("expected 303, got %d", rec.Code)
		}
		if got := store.Get().HeartbeatEnabled; got == nil || *got {
			t.Fatalf("heartbeat opt-out lost after saving %v: %v", form, got)
		}
		if store.Get().Tagline == "old" {
			t.Fatalf("settings were not saved for %v", form)
		}
	}
}

func TestContactHref(t *testing.T) {
	cases := map[string]string{
		"":                              "",
		"ops@example.com":               "mailto:ops@example.com",
		"https://github.com/o/r/issues": "https://github.com/o/r/issues",
	}
	for in, want := range cases {
		if got := contactHref(in); got != want {
			t.Errorf("contactHref(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestValidContact(t *testing.T) {
	for _, c := range []string{"ops@example.com", "https://github.com/o/r/issues"} {
		if !validContact(c) {
			t.Errorf("expected %q to be valid", c)
		}
	}
	for _, c := range []string{"not an address", "http://example.com", "https://", "javascript:alert(1)"} {
		if validContact(c) {
			t.Errorf("expected %q to be rejected", c)
		}
	}
}

func TestAdminSettingsPrivacyURL(t *testing.T) {
	store, err := newSettingsStore(filepath.Join(t.TempDir(), ".settings.json"), Settings{})
	if err != nil {
		t.Fatal(err)
	}
	s := &Server{settings: store, logger: log.New(io.Discard, "", 0)}
	sess := startTestSession(t, s, "alice")

	post := func(privacy string) {
		t.Helper()
		form := url.Values{"theme": {DefaultTheme}, "privacy_url": {privacy}, "csrf": {csrfTokenFor(sess.ID)}}
		rec := httptest.NewRecorder()
		s.adminSettingsPostHandler(rec, sessionPost("/admin/settings", form, sess))
		if rec.Code != http.StatusSeeOther {
			t.Fatalf("expected 303, got %d", rec.Code)
		}
	}

	post(" https://example.com/privacy/ ")
	if got := store.Get().PrivacyURL; got != "https://example.com/privacy/" {
		t.Fatalf("privacy URL not saved: %q", got)
	}
	for _, bad := range []string{"http://example.com/privacy", "javascript:alert(1)", "ops@example.com"} {
		post(bad)
		if got := store.Get().PrivacyURL; got != "https://example.com/privacy/" {
			t.Fatalf("%q replaced the privacy URL with %q", bad, got)
		}
	}
	post("")
	if got := store.Get().PrivacyURL; got != "" {
		t.Fatalf("privacy URL not cleared: %q", got)
	}
}

func TestValidHTTPSURL(t *testing.T) {
	if !validHTTPSURL("https://example.com/privacy") {
		t.Error("expected https link to be valid")
	}
	for _, c := range []string{"", "http://example.com", "https://", "javascript:alert(1)", "//example.com"} {
		if validHTTPSURL(c) {
			t.Errorf("expected %q to be rejected", c)
		}
	}
}
