/*
The MIT License (MIT)

Copyright (c) 2026 xenofex7
*/

package server

import (
	"encoding/json"
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
