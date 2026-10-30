/*
The MIT License (MIT)

Copyright (c) 2026 xenofex7
*/

package server

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/mux"
)

// One-time secrets: short texts (passwords, credentials) that can be
// retrieved exactly once. The server only ever stores ciphertext -
// encryption and decryption happen in the browser (AES-256-GCM) and the
// key travels in the URL fragment, which never reaches the server.

const (
	// anonSecretTTL and authSecretTTL are how long an unopened secret
	// stays retrievable for guests and signed-in users.
	anonSecretTTL = 24 * time.Hour
	authSecretTTL = 7 * 24 * time.Hour
	// maxSecretCiphertext caps the stored base64 payload (roughly 24 KB
	// of plaintext - plenty for passwords and credentials).
	maxSecretCiphertext = 32 * 1024
)

// secretRecord is what ends up on disk, one JSON file per secret.
type secretRecord struct {
	Ciphertext string    `json:"ciphertext"`
	CreatedAt  time.Time `json:"createdAt"`
	ExpiresAt  time.Time `json:"expiresAt"`
	Creator    string    `json:"creator,omitempty"`
}

// secretStore persists one-time secrets inside a dot-directory in
// basedir. Dot-directories are invisible to storage List/Purge, so
// secrets never show up in the admin files view.
type secretStore struct {
	dir string
	mu  sync.Mutex
}

// newSecretStore returns nil (feature disabled) for an empty dir.
func newSecretStore(dir string) (*secretStore, error) {
	if dir == "" {
		return nil, nil
	}
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, err
	}
	return &secretStore{dir: dir}, nil
}

var errSecretGone = errors.New("secret not found, already viewed or expired")

// secretID returns a 32-char hex id from crypto/rand. Secret ids must
// not be predictable: guessing one burns the secret for its recipient.
func secretID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b)
}

// secretIDPattern guards filepath.Join against traversal; ids are built
// from token() so they are always alphanumeric.
var secretIDPattern = regexp.MustCompile(`^[0-9a-zA-Z]{8,128}$`)

func (st *secretStore) path(id string) string {
	return filepath.Join(st.dir, id+".json")
}

func (st *secretStore) Create(id string, rec secretRecord) error {
	b, err := json.Marshal(rec)
	if err != nil {
		return err
	}
	st.mu.Lock()
	defer st.mu.Unlock()
	return os.WriteFile(st.path(id), b, 0600)
}

// Peek reports whether the secret is still available without consuming it.
func (st *secretStore) Peek(id string) bool {
	st.mu.Lock()
	defer st.mu.Unlock()
	_, err := st.load(id)
	return err == nil
}

// Take returns the secret exactly once: the record is deleted before the
// ciphertext is handed to the caller.
func (st *secretStore) Take(id string) (secretRecord, error) {
	st.mu.Lock()
	defer st.mu.Unlock()
	rec, err := st.load(id)
	if err != nil {
		return secretRecord{}, err
	}
	if err := os.Remove(st.path(id)); err != nil {
		return secretRecord{}, err
	}
	return rec, nil
}

// load reads and validates a record; expired files are deleted lazily.
// Caller must hold mu.
func (st *secretStore) load(id string) (secretRecord, error) {
	if !secretIDPattern.MatchString(id) {
		return secretRecord{}, errSecretGone
	}
	b, err := os.ReadFile(st.path(id))
	if err != nil {
		return secretRecord{}, errSecretGone
	}
	var rec secretRecord
	if err := json.Unmarshal(b, &rec); err != nil {
		return secretRecord{}, errSecretGone
	}
	if time.Now().After(rec.ExpiresAt) {
		_ = os.Remove(st.path(id))
		return secretRecord{}, errSecretGone
	}
	return rec, nil
}

// secretEntry is what the admin list shows: everything except the ciphertext.
type secretEntry struct {
	ID        string
	CreatedAt time.Time
	ExpiresAt time.Time
	Creator   string
}

// List returns the unexpired secrets, newest first.
func (st *secretStore) List() ([]secretEntry, error) {
	st.mu.Lock()
	defer st.mu.Unlock()
	entries, err := os.ReadDir(st.dir)
	if err != nil {
		return nil, err
	}
	out := make([]secretEntry, 0, len(entries))
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".json") {
			continue
		}
		id := strings.TrimSuffix(name, ".json")
		rec, lErr := st.load(id)
		if lErr != nil {
			continue
		}
		out = append(out, secretEntry{ID: id, CreatedAt: rec.CreatedAt, ExpiresAt: rec.ExpiresAt, Creator: rec.Creator})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.After(out[j].CreatedAt) })
	return out, nil
}

// Delete removes an unopened secret; unknown ids report errSecretGone.
func (st *secretStore) Delete(id string) error {
	st.mu.Lock()
	defer st.mu.Unlock()
	if _, err := st.load(id); err != nil {
		return err
	}
	return os.Remove(st.path(id))
}

// PurgeExpired sweeps the directory; wired into the server purge loop.
func (st *secretStore) PurgeExpired() error {
	st.mu.Lock()
	defer st.mu.Unlock()
	entries, err := os.ReadDir(st.dir)
	if err != nil {
		return err
	}
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".json") {
			continue
		}
		p := filepath.Join(st.dir, name)
		b, rErr := os.ReadFile(p)
		if rErr != nil {
			continue
		}
		var rec secretRecord
		if json.Unmarshal(b, &rec) != nil || time.Now().After(rec.ExpiresAt) {
			_ = os.Remove(p)
		}
	}
	return nil
}

// secretCreateHandler accepts a JSON body {"ciphertext": "<base64>"} and
// answers {"id": ..., "url": ...}. The client appends "#<key>" itself.
func (s *Server) secretCreateHandler(w http.ResponseWriter, r *http.Request) {
	if s.secrets == nil {
		http.Error(w, http.StatusText(http.StatusNotFound), http.StatusNotFound)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxSecretCiphertext+1024)

	var req struct {
		Ciphertext string `json:"ciphertext"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}
	if req.Ciphertext == "" || len(req.Ciphertext) > maxSecretCiphertext {
		http.Error(w, "Secret is empty or too large", http.StatusBadRequest)
		return
	}
	if _, err := base64.StdEncoding.DecodeString(req.Ciphertext); err != nil {
		http.Error(w, "Ciphertext must be base64", http.StatusBadRequest)
		return
	}

	id := secretID()
	creator := currentUserFromRequest(r)
	rec := secretRecord{
		Ciphertext: req.Ciphertext,
		CreatedAt:  time.Now(),
		ExpiresAt:  time.Now().Add(secretTTLFor(creator)),
		Creator:    creator,
	}
	if err := s.secrets.Create(id, rec); err != nil {
		s.logger.Printf("secret create: %v", err)
		http.Error(w, "Could not save secret", http.StatusInternalServerError)
		return
	}

	relativeURL, _ := url.Parse(path.Join(s.proxyPath, "secret", id))
	resolvedURL := resolveURL(r, relativeURL, s.proxyPort)

	s.logger.Printf("Secret created %s", id)

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{"id": id, "url": resolvedURL})
}

func secretTTLFor(user string) time.Duration {
	if user == "" {
		return anonSecretTTL
	}
	return authSecretTTL
}

// secretPageHandler renders the reveal page. It never consumes the
// secret, so link-preview bots fetching the URL cannot burn the single
// view; consumption only happens on the explicit reveal POST.
func (s *Server) secretPageHandler(w http.ResponseWriter, r *http.Request) {
	if s.secrets == nil {
		http.Error(w, http.StatusText(http.StatusNotFound), http.StatusNotFound)
		return
	}
	id := mux.Vars(r)["id"]

	data := struct {
		Hostname  string
		ID        string
		Available bool
	}{
		Hostname:  getURL(r, s.proxyPort).Host,
		ID:        id,
		Available: s.secrets.Peek(id),
	}

	w.Header().Set("Cache-Control", "no-store")
	if err := htmlTemplates.ExecuteTemplate(w, "secret.html", data); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

// secretRevealHandler hands out the ciphertext exactly once and deletes
// the record. Possession of the link is the authorization.
func (s *Server) secretRevealHandler(w http.ResponseWriter, r *http.Request) {
	if s.secrets == nil {
		http.Error(w, http.StatusText(http.StatusNotFound), http.StatusNotFound)
		return
	}
	id := mux.Vars(r)["id"]

	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "application/json")

	rec, err := s.secrets.Take(id)
	if err != nil {
		w.WriteHeader(http.StatusNotFound)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "gone"})
		return
	}

	s.logger.Printf("Secret revealed %s", id)
	_ = json.NewEncoder(w).Encode(map[string]string{"ciphertext": rec.Ciphertext})
}
