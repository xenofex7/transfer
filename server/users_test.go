/*
The MIT License (MIT)

Copyright (c) 2026 xenofex7
*/

package server

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"sync"
	"testing"

	"github.com/tg123/go-htpasswd"
	"golang.org/x/crypto/bcrypt"
)

func newTestStore(t *testing.T) (*userStore, string, *int) {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "htpasswd")
	reloads := 0
	us := newUserStore(path, func() error {
		reloads++
		return nil
	}, nil)
	if us == nil {
		t.Fatal("store nil")
	}
	return us, path, &reloads
}

func TestUserStoreAddListMatch(t *testing.T) {
	us, path, reloads := newTestStore(t)

	if err := us.Add("alice", "correcthorsebattery"); err != nil {
		t.Fatalf("add: %v", err)
	}
	if err := us.Add("bob", "anotherlongpass"); err != nil {
		t.Fatalf("add bob: %v", err)
	}
	if *reloads != 2 {
		t.Fatalf("expected 2 reloads, got %d", *reloads)
	}

	names, err := us.List()
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(names, []string{"alice", "bob"}) {
		t.Fatalf("unexpected list: %v", names)
	}

	// File is loadable and matches via the htpasswd lib.
	f, err := htpasswd.New(path, htpasswd.DefaultSystems, nil)
	if err != nil {
		t.Fatalf("htpasswd parse: %v", err)
	}
	if !f.Match("alice", "correcthorsebattery") {
		t.Fatal("alice should match")
	}
	if f.Match("alice", "wrong") {
		t.Fatal("wrong password matched")
	}
}

func TestUserStoreDuplicateRejected(t *testing.T) {
	us, _, _ := newTestStore(t)
	if err := us.Add("alice", "longenoughpw"); err != nil {
		t.Fatal(err)
	}
	if err := us.Add("alice", "longenoughpw"); !errors.Is(err, errUserExists) {
		t.Fatalf("expected errUserExists, got %v", err)
	}
}

func TestUserStoreSetPassword(t *testing.T) {
	us, path, _ := newTestStore(t)
	if err := us.Add("alice", "firstpassword"); err != nil {
		t.Fatal(err)
	}
	if err := us.SetPassword("alice", "secondpassword"); err != nil {
		t.Fatal(err)
	}
	f, _ := htpasswd.New(path, htpasswd.DefaultSystems, nil)
	if f.Match("alice", "firstpassword") {
		t.Fatal("old password should not match anymore")
	}
	if !f.Match("alice", "secondpassword") {
		t.Fatal("new password should match")
	}

	if err := us.SetPassword("ghost", "longenoughpw"); !errors.Is(err, errUserNotFound) {
		t.Fatalf("expected errUserNotFound, got %v", err)
	}
}

func TestUserStoreDeleteGuards(t *testing.T) {
	us, _, _ := newTestStore(t)
	deleted := ""
	us.onDelete = func(name string) error {
		deleted = name
		return nil
	}
	if err := us.Add("alice", "longenoughpw"); err != nil {
		t.Fatal(err)
	}

	// last user
	if err := us.Delete("alice", ""); !errors.Is(err, errLastUser) {
		t.Fatalf("expected errLastUser, got %v", err)
	}

	if err := us.Add("bob", "longenoughpw"); err != nil {
		t.Fatal(err)
	}

	// self-delete
	if err := us.Delete("alice", "alice"); !errors.Is(err, errSelfDelete) {
		t.Fatalf("expected errSelfDelete, got %v", err)
	}

	// success path
	if err := us.Delete("bob", "alice"); err != nil {
		t.Fatalf("delete bob: %v", err)
	}
	if deleted != "bob" {
		t.Fatalf("onDelete hook not invoked with bob, got %q", deleted)
	}
	names, _ := us.List()
	if !reflect.DeepEqual(names, []string{"alice"}) {
		t.Fatalf("unexpected list after delete: %v", names)
	}

	if err := us.Delete("ghost", "alice"); !errors.Is(err, errUserNotFound) {
		t.Fatalf("expected errUserNotFound, got %v", err)
	}
}

func TestUserStoreValidation(t *testing.T) {
	us, _, _ := newTestStore(t)
	cases := []struct {
		name, pw string
		want     error
	}{
		{"", "longenoughpw", errInvalidUsername},
		{"bad space", "longenoughpw", errInvalidUsername},
		{"alice", "short", errInvalidPassword},
	}
	for _, c := range cases {
		if err := us.Add(c.name, c.pw); !errors.Is(err, c.want) {
			t.Errorf("Add(%q,%q) -> %v, want %v", c.name, c.pw, err, c.want)
		}
	}
}

func TestUserStoreConcurrentAdds(t *testing.T) {
	us, path, _ := newTestStore(t)
	const n = 25
	var wg sync.WaitGroup
	wg.Add(n)
	errs := make(chan error, n)
	for i := 0; i < n; i++ {
		i := i
		go func() {
			defer wg.Done()
			errs <- us.Add(userN(i), "longenoughpw")
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("concurrent add: %v", err)
		}
	}
	names, _ := us.List()
	if len(names) != n {
		t.Fatalf("expected %d users, got %d", n, len(names))
	}
	// File is well-formed.
	if _, err := htpasswd.New(path, htpasswd.DefaultSystems, nil); err != nil {
		t.Fatalf("htpasswd parse: %v", err)
	}
}

func TestUserStorePreservesExternallyAddedHashes(t *testing.T) {
	us, path, _ := newTestStore(t)

	// Pre-seed a file as if produced by `htpasswd -B` outside the UI.
	hash, _ := bcrypt.GenerateFromPassword([]byte("preseed-pass"), bcrypt.MinCost)
	if err := os.WriteFile(path, []byte("legacy:"+string(hash)+"\n"), 0o640); err != nil {
		t.Fatal(err)
	}

	if err := us.Add("alice", "longenoughpw"); err != nil {
		t.Fatal(err)
	}
	f, _ := htpasswd.New(path, htpasswd.DefaultSystems, nil)
	if !f.Match("legacy", "preseed-pass") {
		t.Fatal("pre-seeded hash should still match after Add")
	}
}

func userN(i int) string {
	const alpha = "abcdefghijklmnopqrstuvwxyz"
	return string(alpha[i%len(alpha)]) + string(alpha[(i/len(alpha))%len(alpha)]) + "_" + string(rune('0'+i%10))
}
