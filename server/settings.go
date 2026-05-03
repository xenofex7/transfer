/*
The MIT License (MIT)

Copyright (c) 2026 xenofex7
*/

package server

import (
	"encoding/json"
	"errors"
	"os"
	"sync"
	"sync/atomic"
)

// activeSettings is the package-level handle the template functions read so
// every page can render the operator-configured theme default without each
// handler having to thread it through its data struct.
var activeSettings atomic.Pointer[settingsStore]

// DefaultTagline is the homepage tagline used when nothing else is set.
const DefaultTagline = "WeTransfer - aber lokal!"

// DefaultTheme is the initial theme served to first-time visitors before
// they pick one for themselves via the toggle.
const DefaultTheme = "system"

// ValidThemes lists the values Settings.Theme accepts.
var ValidThemes = map[string]bool{"system": true, "light": true, "dark": true}

// Settings holds the runtime-mutable configuration that an operator can edit
// from the admin UI. Every field here is persisted to disk so it survives
// restarts and overrides the corresponding ENV / CLI default.
type Settings struct {
	Tagline      string `json:"tagline"`
	EmailContact string `json:"email_contact"`
	Theme        string `json:"theme"`
}

// settingsStore loads, returns and persists Settings. All access goes through
// the RWMutex so handlers can call Get on every request without contention.
type settingsStore struct {
	path string

	mu      sync.RWMutex
	current Settings
}

// newSettingsStore returns a store rooted at path. If the file is missing the
// store starts with bootstrap as the in-memory state and writes it on the
// first Set. If the file exists its contents win over bootstrap so admin
// edits survive a restart.
func newSettingsStore(path string, bootstrap Settings) (*settingsStore, error) {
	s := &settingsStore{path: path, current: bootstrap}
	if path == "" {
		return s, nil
	}

	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return s, nil
		}
		return nil, err
	}

	var loaded Settings
	if err := json.Unmarshal(data, &loaded); err != nil {
		return nil, err
	}
	// Persisted file wins outright for free-form text fields. Empty values
	// are honored - admin may have intentionally cleared the tagline or
	// contact link.
	// Theme is a closed enum; an unset / unknown value (e.g. settings.json
	// from before the field existed) falls back to the bootstrap default.
	if !ValidThemes[loaded.Theme] {
		loaded.Theme = bootstrap.Theme
	}
	s.current = loaded
	return s, nil
}

// Get returns a copy of the current settings under read-lock.
func (s *settingsStore) Get() Settings {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.current
}

// Set replaces the in-memory settings and writes them to disk atomically.
// The on-disk file is replaced via tempfile + rename so a crash mid-write
// can never leave the JSON truncated.
func (s *settingsStore) Set(next Settings) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.current = next
	return s.persistLocked()
}

func (s *settingsStore) persistLocked() error {
	if s.path == "" {
		return nil
	}
	data, err := json.MarshalIndent(s.current, "", "  ")
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(s.dir(), ".settings-*.json")
	if err != nil {
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmp.Name())
		return err
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmp.Name())
		return err
	}
	return os.Rename(tmp.Name(), s.path)
}

func (s *settingsStore) dir() string {
	for i := len(s.path) - 1; i >= 0; i-- {
		if s.path[i] == '/' {
			return s.path[:i]
		}
	}
	return "."
}
