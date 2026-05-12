/*
The MIT License (MIT)

Copyright (c) 2026 xenofex7
*/

package server

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func newTestMetaStore(t *testing.T) (*userMetaStore, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "users.meta.json")
	ms, err := newUserMetaStore(path)
	if err != nil {
		t.Fatalf("newUserMetaStore: %v", err)
	}
	if ms == nil {
		t.Fatal("expected non-nil store")
	}
	return ms, path
}

func TestUserMetaPathFor(t *testing.T) {
	if got := metaPathFor(""); got != "" {
		t.Fatalf("expected empty for empty input, got %q", got)
	}
	if got := metaPathFor("/srv/htpasswd"); got != "/srv/htpasswd.meta.json" {
		t.Fatalf("unexpected sibling path: %q", got)
	}
}

func TestUserMetaSaveAndGet(t *testing.T) {
	ms, _ := newTestMetaStore(t)

	if _, ok := ms.Get("alice"); ok {
		t.Fatal("get on empty store should be (zero,false)")
	}
	if ms.Has("alice") {
		t.Fatal("Has on empty store should be false")
	}

	now := time.Now().UTC().Truncate(time.Second)
	rec := userMeta{
		TOTPSecret:    "BASE32SECRET",
		TOTPEnabled:   true,
		TOTPEnabledAt: &now,
		APITokens: []apiToken{
			{ID: "tok_1", Name: "laptop", Hash: "hash1", CreatedAt: now},
		},
	}
	if err := ms.Save("alice", rec); err != nil {
		t.Fatalf("save: %v", err)
	}

	got, ok := ms.Get("alice")
	if !ok {
		t.Fatal("alice should exist after save")
	}
	if got.TOTPSecret != "BASE32SECRET" || !got.TOTPEnabled {
		t.Fatalf("unexpected meta: %+v", got)
	}
	if len(got.APITokens) != 1 || got.APITokens[0].ID != "tok_1" {
		t.Fatalf("tokens not persisted: %+v", got.APITokens)
	}
}

func TestUserMetaGetReturnsCopy(t *testing.T) {
	ms, _ := newTestMetaStore(t)
	if err := ms.Save("alice", userMeta{APITokens: []apiToken{{ID: "tok_1", Hash: "h"}}}); err != nil {
		t.Fatal(err)
	}
	got, _ := ms.Get("alice")
	got.APITokens[0].Hash = "tampered"

	again, _ := ms.Get("alice")
	if again.APITokens[0].Hash != "h" {
		t.Fatalf("Get returned a shared slice — store was mutated externally")
	}
}

func TestUserMetaUpdate(t *testing.T) {
	ms, _ := newTestMetaStore(t)

	err := ms.Update("alice", func(m *userMeta) error {
		m.APITokens = append(m.APITokens, apiToken{ID: "a", Hash: "h1"})
		return nil
	})
	if err != nil {
		t.Fatalf("update: %v", err)
	}
	err = ms.Update("alice", func(m *userMeta) error {
		m.APITokens = append(m.APITokens, apiToken{ID: "b", Hash: "h2"})
		return nil
	})
	if err != nil {
		t.Fatalf("update 2: %v", err)
	}
	got, _ := ms.Get("alice")
	if len(got.APITokens) != 2 {
		t.Fatalf("expected 2 tokens after sequential updates, got %d", len(got.APITokens))
	}
}

func TestUserMetaUpdateErrorAborts(t *testing.T) {
	ms, _ := newTestMetaStore(t)
	if err := ms.Save("alice", userMeta{TOTPSecret: "keep"}); err != nil {
		t.Fatal(err)
	}
	sentinel := errors.New("nope")
	err := ms.Update("alice", func(m *userMeta) error {
		m.TOTPSecret = "changed"
		return sentinel
	})
	if !errors.Is(err, sentinel) {
		t.Fatalf("expected sentinel, got %v", err)
	}
	got, _ := ms.Get("alice")
	if got.TOTPSecret != "keep" {
		t.Fatalf("mutation should be aborted, got %+v", got)
	}
}

func TestUserMetaDelete(t *testing.T) {
	ms, _ := newTestMetaStore(t)
	if err := ms.Save("alice", userMeta{TOTPEnabled: true}); err != nil {
		t.Fatal(err)
	}
	if err := ms.Delete("alice"); err != nil {
		t.Fatal(err)
	}
	if _, ok := ms.Get("alice"); ok {
		t.Fatal("alice should be gone after delete")
	}
	// Delete on missing user is a no-op.
	if err := ms.Delete("alice"); err != nil {
		t.Fatalf("delete on missing should be no-op, got %v", err)
	}
}

func TestUserMetaPersistAcrossReload(t *testing.T) {
	ms, path := newTestMetaStore(t)
	if err := ms.Save("alice", userMeta{TOTPSecret: "S", TOTPEnabled: true}); err != nil {
		t.Fatal(err)
	}

	again, err := newUserMetaStore(path)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	got, ok := again.Get("alice")
	if !ok || got.TOTPSecret != "S" || !got.TOTPEnabled {
		t.Fatalf("state not persisted across reload: %+v ok=%v", got, ok)
	}
}

func TestUserMetaMissingFileIsEmpty(t *testing.T) {
	path := filepath.Join(t.TempDir(), "absent.json")
	ms, err := newUserMetaStore(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := ms.Get("alice"); ok {
		t.Fatal("missing file should mean empty store")
	}
	// First save must create the file with the expected version.
	if err := ms.Save("alice", userMeta{}); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var file userMetaFile
	if err := json.Unmarshal(raw, &file); err != nil {
		t.Fatalf("file isn't valid JSON: %v", err)
	}
	if file.Version != userMetaFormatVersion {
		t.Fatalf("expected version %d, got %d", userMetaFormatVersion, file.Version)
	}
}

func TestUserMetaRejectsUnknownVersion(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "meta.json")
	if err := os.WriteFile(path, []byte(`{"version":999,"users":{}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := newUserMetaStore(path); !errors.Is(err, errUserMetaVersion) {
		t.Fatalf("expected errUserMetaVersion, got %v", err)
	}
}

func TestUserMetaRename(t *testing.T) {
	ms, _ := newTestMetaStore(t)
	if err := ms.Save("alice", userMeta{TOTPSecret: "S"}); err != nil {
		t.Fatal(err)
	}
	if err := ms.Rename("alice", "alice2"); err != nil {
		t.Fatal(err)
	}
	if _, ok := ms.Get("alice"); ok {
		t.Fatal("old name should be gone")
	}
	got, ok := ms.Get("alice2")
	if !ok || got.TOTPSecret != "S" {
		t.Fatalf("rename lost data: ok=%v meta=%+v", ok, got)
	}

	if err := ms.Save("bob", userMeta{}); err != nil {
		t.Fatal(err)
	}
	if err := ms.Rename("alice2", "bob"); !errors.Is(err, errUserExists) {
		t.Fatalf("rename onto existing should fail, got %v", err)
	}
}

func TestUserMetaNilForEmptyPath(t *testing.T) {
	ms, err := newUserMetaStore("")
	if err != nil {
		t.Fatal(err)
	}
	if ms != nil {
		t.Fatal("expected nil store for empty path")
	}
}

func TestUserMetaConcurrentUpdates(t *testing.T) {
	ms, _ := newTestMetaStore(t)
	const n = 30
	var wg sync.WaitGroup
	wg.Add(n)
	for i := 0; i < n; i++ {
		i := i
		go func() {
			defer wg.Done()
			_ = ms.Update("alice", func(m *userMeta) error {
				m.APITokens = append(m.APITokens, apiToken{ID: tokID(i), Hash: "h"})
				return nil
			})
		}()
	}
	wg.Wait()
	got, _ := ms.Get("alice")
	if len(got.APITokens) != n {
		t.Fatalf("expected %d tokens after concurrent updates, got %d", n, len(got.APITokens))
	}
}

func tokID(i int) string {
	return "tok_" + string(rune('a'+i%26)) + string(rune('a'+(i/26)%26))
}
