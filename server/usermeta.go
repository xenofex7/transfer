/*
The MIT License (MIT)

Copyright (c) 2026 xenofex7
*/

package server

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// userMetaFormatVersion is the on-disk schema version. Bump on any
// breaking change to userMetaFile so we can refuse to start instead of
// silently dropping fields.
const userMetaFormatVersion = 1

var (
	errUserMetaUnavailable = errors.New("user metadata store not configured")
	errUserMetaVersion     = errors.New("user metadata file: unsupported version")
)

// userMeta is the per-user record holding factors beyond the password:
// TOTP enrolment, recovery codes, and API tokens used for headless
// (CLI/curl) clients. Recovery codes and token secrets are stored as
// bcrypt hashes — never the cleartext. The struct is exported in JSON
// shape only; callers must use userMetaStore to mutate it.
type userMeta struct {
	TOTPSecret     string     `json:"totp_secret,omitempty"`
	TOTPEnabled    bool       `json:"totp_enabled,omitempty"`
	TOTPEnabledAt  *time.Time `json:"totp_enabled_at,omitempty"`
	RecoveryHashes []string   `json:"recovery_hashes,omitempty"`
	APITokens      []apiToken `json:"api_tokens,omitempty"`
}

// apiToken is a single named credential a user can present via HTTP
// Basic Auth in place of their password. Hash is bcrypt over the
// cleartext secret. ID is a short random identifier safe to display in
// the UI; the secret itself is only returned to the user once at
// creation time.
type apiToken struct {
	ID         string     `json:"id"`
	Name       string     `json:"name"`
	Hash       string     `json:"hash"`
	CreatedAt  time.Time  `json:"created_at"`
	LastUsedAt *time.Time `json:"last_used_at,omitempty"`
	ExpiresAt  *time.Time `json:"expires_at,omitempty"`
}

// userMetaFile is the persisted shape of the metadata store.
type userMetaFile struct {
	Version int                  `json:"version"`
	Users   map[string]*userMeta `json:"users"`
}

// userMetaStore persists per-user authentication metadata. Reads are
// served from an in-memory snapshot; every successful mutation rewrites
// the snapshot under lock and atomically renames the on-disk file.
// Missing files are treated as empty so a fresh install needs no setup
// step.
type userMetaStore struct {
	mu    sync.RWMutex
	path  string
	cache map[string]*userMeta
}

func newUserMetaStore(path string) (*userMetaStore, error) {
	if path == "" {
		return nil, nil
	}
	s := &userMetaStore{path: path, cache: map[string]*userMeta{}}
	if err := s.load(); err != nil {
		return nil, err
	}
	return s, nil
}

// metaPathFor returns the conventional metadata file path next to a
// given htpasswd file. Returns "" when the input is empty.
func metaPathFor(htpasswdPath string) string {
	if htpasswdPath == "" {
		return ""
	}
	return htpasswdPath + ".meta.json"
}

// load reads the on-disk file into the in-memory cache. Caller must
// hold no lock; load takes the write lock itself. A missing file leaves
// the cache empty without error.
func (s *userMetaStore) load() error {
	f, err := os.Open(s.path)
	if err != nil {
		if os.IsNotExist(err) {
			s.mu.Lock()
			s.cache = map[string]*userMeta{}
			s.mu.Unlock()
			return nil
		}
		return err
	}
	defer func() { _ = f.Close() }()

	data, err := io.ReadAll(f)
	if err != nil {
		return err
	}

	cache := map[string]*userMeta{}
	if len(data) > 0 {
		var file userMetaFile
		if err := json.Unmarshal(data, &file); err != nil {
			return fmt.Errorf("parse user metadata: %w", err)
		}
		if file.Version != 0 && file.Version != userMetaFormatVersion {
			return fmt.Errorf("%w: %d", errUserMetaVersion, file.Version)
		}
		for name, m := range file.Users {
			if m == nil {
				continue
			}
			cache[name] = m
		}
	}

	s.mu.Lock()
	s.cache = cache
	s.mu.Unlock()
	return nil
}

// Get returns a deep copy of the user's metadata. Returns (zero, false)
// if no record exists for the name; callers should treat that as
// "default, no extra factors".
func (s *userMetaStore) Get(name string) (userMeta, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	m, ok := s.cache[name]
	if !ok || m == nil {
		return userMeta{}, false
	}
	return cloneUserMeta(*m), true
}

// Has reports whether a metadata record exists for name (even an empty
// one). Useful for telling "user has no TOTP" apart from "user does not
// exist in the meta store at all".
func (s *userMetaStore) Has(name string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	_, ok := s.cache[name]
	return ok
}

// Save replaces (or inserts) the metadata record for name and persists
// the whole file atomically. Passing a zero-value userMeta is allowed
// and writes an empty record — to remove a user, use Delete.
func (s *userMetaStore) Save(name string, m userMeta) error {
	if err := validateUsername(name); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	cp := cloneUserMeta(m)
	s.cache[name] = &cp
	return s.persistLocked()
}

// Update reads, mutates, and writes a user's metadata in a single
// critical section so concurrent token-adds and TOTP-enables can't
// clobber each other. The mutate fn receives a pointer to a fresh copy
// and may freely modify it; an error from fn aborts the write.
func (s *userMetaStore) Update(name string, mutate func(*userMeta) error) error {
	if err := validateUsername(name); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	current := userMeta{}
	if existing, ok := s.cache[name]; ok && existing != nil {
		current = cloneUserMeta(*existing)
	}
	if err := mutate(&current); err != nil {
		return err
	}
	s.cache[name] = &current
	return s.persistLocked()
}

// Delete removes any metadata record for name. No error if the user has
// no record. Intended to be called from userStore.Delete so cleanup is
// automatic and we never leak orphan TOTP secrets or tokens.
func (s *userMetaStore) Delete(name string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.cache[name]; !ok {
		return nil
	}
	delete(s.cache, name)
	return s.persistLocked()
}

// Rename moves a record from oldName to newName, preserving TOTP and
// tokens. No-op if oldName has no record. Reserved for a future
// rename-user flow; included now so callers can rely on it.
func (s *userMetaStore) Rename(oldName, newName string) error {
	if err := validateUsername(newName); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	m, ok := s.cache[oldName]
	if !ok {
		return nil
	}
	if _, exists := s.cache[newName]; exists {
		return errUserExists
	}
	delete(s.cache, oldName)
	s.cache[newName] = m
	return s.persistLocked()
}

// persistLocked serialises s.cache to disk under the existing write
// lock. Writes go to a sibling temp file and are committed via atomic
// rename so a crash between truncate and write never leaves the live
// file partially overwritten.
func (s *userMetaStore) persistLocked() error {
	file := userMetaFile{
		Version: userMetaFormatVersion,
		Users:   make(map[string]*userMeta, len(s.cache)),
	}
	for name, m := range s.cache {
		if m == nil {
			continue
		}
		cp := cloneUserMeta(*m)
		file.Users[name] = &cp
	}
	data, err := json.MarshalIndent(file, "", "  ")
	if err != nil {
		return err
	}

	dir := filepath.Dir(s.path)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".usermeta-*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	cleanup := true
	defer func() {
		if cleanup {
			_ = os.Remove(tmpName)
		}
	}()

	w := bufio.NewWriter(tmp)
	if _, err := w.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := w.Flush(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Chmod(tmpName, 0o600); err != nil {
		return err
	}
	if err := os.Rename(tmpName, s.path); err != nil {
		return err
	}
	cleanup = false
	return nil
}

func cloneUserMeta(m userMeta) userMeta {
	cp := m
	if m.TOTPEnabledAt != nil {
		t := *m.TOTPEnabledAt
		cp.TOTPEnabledAt = &t
	}
	if m.RecoveryHashes != nil {
		cp.RecoveryHashes = append([]string(nil), m.RecoveryHashes...)
	}
	if m.APITokens != nil {
		cp.APITokens = make([]apiToken, len(m.APITokens))
		for i, t := range m.APITokens {
			cp.APITokens[i] = cloneAPIToken(t)
		}
	}
	return cp
}

func cloneAPIToken(t apiToken) apiToken {
	cp := t
	if t.LastUsedAt != nil {
		v := *t.LastUsedAt
		cp.LastUsedAt = &v
	}
	if t.ExpiresAt != nil {
		v := *t.ExpiresAt
		cp.ExpiresAt = &v
	}
	return cp
}
