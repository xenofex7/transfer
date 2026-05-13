/*
The MIT License (MIT)

Copyright (c) 2026 xenofex7
*/

package server

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"

	"github.com/tg123/go-htpasswd"
	"golang.org/x/crypto/bcrypt"
)

const (
	userMinPasswordLen = 8
	userMaxPasswordLen = 256
	userMaxNameLen     = 64
)

// userBcryptCost is a var rather than a const so tests can lower it to
// bcrypt.MinCost. Production keeps it at 12 (current OWASP guidance).
// Lowering it in tests cuts the suite from minutes to seconds under
// the race detector, where bcrypt is the dominant cost.
var userBcryptCost = 12

var (
	errUserNotFound      = errors.New("user not found")
	errUserExists        = errors.New("user already exists")
	errInvalidUsername   = errors.New("username may only contain letters, digits, dot, dash and underscore (1-64 chars)")
	errInvalidPassword   = fmt.Errorf("password must be %d-%d characters", userMinPasswordLen, userMaxPasswordLen)
	errLastUser          = errors.New("cannot remove the last remaining user")
	errSelfDelete        = errors.New("cannot delete the user you are signed in as")
	errStoreUnavailable  = errors.New("user store not configured")
	usernamePatternMatch = regexp.MustCompile(`^[A-Za-z0-9._-]+$`)
)

// userStore manages an htpasswd file: reading the user list, adding,
// updating and removing users with bcrypt hashes. Writes are serialised
// through an in-process mutex and committed via temp-file + atomic
// rename so a crash never leaves a partial file behind. After every
// successful mutation the live htpasswd matcher is reloaded.
type userStore struct {
	mu       sync.Mutex
	path     string
	reload   func() error
	onDelete func(name string) error
}

// newUserStore returns a store backed by the htpasswd file at path.
// reload is invoked after every successful mutation so the live matcher
// stays in sync with the file. onDelete is invoked after a successful
// Delete with the removed name; use it to clean up sidecar state such
// as TOTP secrets and API tokens. Both callbacks may be nil.
func newUserStore(path string, reload func() error, onDelete func(name string) error) *userStore {
	if path == "" {
		return nil
	}
	return &userStore{path: path, reload: reload, onDelete: onDelete}
}

// List returns the usernames in the file, sorted.
func (us *userStore) List() ([]string, error) {
	us.mu.Lock()
	defer us.mu.Unlock()
	names, _, err := us.readLocked()
	if err != nil {
		return nil, err
	}
	sort.Strings(names)
	return names, nil
}

// Has reports whether name exists.
func (us *userStore) Has(name string) (bool, error) {
	us.mu.Lock()
	defer us.mu.Unlock()
	_, m, err := us.readLocked()
	if err != nil {
		return false, err
	}
	_, ok := m[name]
	return ok, nil
}

// Add creates a user. Fails if the user already exists.
func (us *userStore) Add(name, password string) error {
	if err := validateUsername(name); err != nil {
		return err
	}
	if err := validatePassword(password); err != nil {
		return err
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(password), userBcryptCost)
	if err != nil {
		return err
	}

	us.mu.Lock()
	defer us.mu.Unlock()

	names, m, err := us.readLocked()
	if err != nil {
		return err
	}
	if _, ok := m[name]; ok {
		return errUserExists
	}
	names = append(names, name)
	m[name] = string(hash)
	return us.writeLocked(names, m)
}

// SetPassword replaces the password hash for name.
func (us *userStore) SetPassword(name, password string) error {
	if err := validateUsername(name); err != nil {
		return err
	}
	if err := validatePassword(password); err != nil {
		return err
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(password), userBcryptCost)
	if err != nil {
		return err
	}

	us.mu.Lock()
	defer us.mu.Unlock()

	names, m, err := us.readLocked()
	if err != nil {
		return err
	}
	if _, ok := m[name]; !ok {
		return errUserNotFound
	}
	m[name] = string(hash)
	return us.writeLocked(names, m)
}

// Delete removes name. Refuses to remove the last user, and refuses to
// remove `self` if non-empty (lockout guard against self-delete).
func (us *userStore) Delete(name, self string) error {
	if err := validateUsername(name); err != nil {
		return err
	}
	if self != "" && name == self {
		return errSelfDelete
	}

	us.mu.Lock()
	defer us.mu.Unlock()

	names, m, err := us.readLocked()
	if err != nil {
		return err
	}
	if _, ok := m[name]; !ok {
		return errUserNotFound
	}
	if len(m) <= 1 {
		return errLastUser
	}
	delete(m, name)
	out := make([]string, 0, len(names))
	for _, n := range names {
		if n != name {
			out = append(out, n)
		}
	}
	if err := us.writeLocked(out, m); err != nil {
		return err
	}
	if us.onDelete != nil {
		if err := us.onDelete(name); err != nil {
			return err
		}
	}
	return nil
}

// readLocked parses the htpasswd file. Returns the usernames in file
// order plus a name->raw-line map. Missing files are treated as empty.
func (us *userStore) readLocked() ([]string, map[string]string, error) {
	f, err := os.Open(us.path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, map[string]string{}, nil
		}
		return nil, nil, err
	}
	defer func() { _ = f.Close() }()

	var names []string
	m := map[string]string{}
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 64*1024), 1<<20)
	for scanner.Scan() {
		line := strings.TrimRight(scanner.Text(), "\r")
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		idx := strings.IndexByte(line, ':')
		if idx <= 0 {
			continue
		}
		name := line[:idx]
		hash := line[idx+1:]
		if _, exists := m[name]; exists {
			continue
		}
		names = append(names, name)
		m[name] = hash
	}
	if err := scanner.Err(); err != nil {
		return nil, nil, err
	}
	return names, m, nil
}

// writeLocked serialises names+m to a temp file in the same directory
// and atomically renames it over the destination. Triggers reload of
// the in-memory matcher on success.
func (us *userStore) writeLocked(names []string, m map[string]string) error {
	dir := filepath.Dir(us.path)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".htpasswd-*.tmp")
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
	for _, n := range names {
		if _, err := fmt.Fprintf(w, "%s:%s\n", n, m[n]); err != nil {
			_ = tmp.Close()
			return err
		}
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
	if err := os.Chmod(tmpName, 0o640); err != nil {
		return err
	}
	if err := os.Rename(tmpName, us.path); err != nil {
		return err
	}
	cleanup = false
	if us.reload != nil {
		if err := us.reload(); err != nil {
			return err
		}
	}
	return nil
}

func validateUsername(name string) error {
	if name == "" || len(name) > userMaxNameLen {
		return errInvalidUsername
	}
	if !usernamePatternMatch.MatchString(name) {
		return errInvalidUsername
	}
	return nil
}

func validatePassword(pw string) error {
	if len(pw) < userMinPasswordLen || len(pw) > userMaxPasswordLen {
		return errInvalidPassword
	}
	return nil
}

// reloadHtpasswdFile rebuilds the in-memory matcher used by basicAuthHandler.
// Safe to call when no file is configured (no-op).
func (s *Server) reloadHtpasswdFile() error {
	if s.authHtpasswd == "" {
		return nil
	}
	f, err := htpasswd.New(s.authHtpasswd, htpasswd.DefaultSystems, nil)
	if err != nil {
		return err
	}
	s.htpasswdMu.Lock()
	s.htpasswdFile = f
	s.htpasswdMu.Unlock()
	return nil
}
