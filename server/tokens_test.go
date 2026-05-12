/*
The MIT License (MIT)

Copyright (c) 2026 xenofex7
*/

package server

import (
	"errors"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestLooksLikeAPIToken(t *testing.T) {
	cases := map[string]bool{
		"":              false,
		"plainpassword": false,
		"tk_":           false,
		"tk_abc":        false,
		"tk_abc.xyz":    true,
		"tk_abc.":       false,
		"tk_.xyz":       false,
		"prefixtk_a.b":  false,
	}
	for in, want := range cases {
		if got := looksLikeAPIToken(in); got != want {
			t.Errorf("looksLikeAPIToken(%q) = %v, want %v", in, got, want)
		}
	}
}

func TestParseAPIToken(t *testing.T) {
	id, secret, err := parseAPIToken("tk_abc.xyz123")
	if err != nil {
		t.Fatal(err)
	}
	if id != "abc" || secret != "xyz123" {
		t.Fatalf("unexpected parse: id=%q secret=%q", id, secret)
	}
	for _, bad := range []string{"", "abc.xyz", "tk_.xyz", "tk_abc.", "tk_abc", "tk_abc."} {
		if _, _, err := parseAPIToken(bad); err == nil {
			t.Errorf("parseAPIToken(%q) should fail", bad)
		}
	}
}

func TestCreateAndVerifyAPIToken(t *testing.T) {
	ms, _ := newTestMetaStore(t)

	wire, tok, err := ms.CreateAPIToken("alice", "laptop", nil)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if !strings.HasPrefix(wire, "tk_") || !strings.Contains(wire, ".") {
		t.Fatalf("wire token misformatted: %q", wire)
	}
	if tok.Hash == "" {
		t.Fatal("returned record should still carry the hash for the store")
	}

	got, err := ms.VerifyAPIToken("alice", wire)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if got.ID != tok.ID || got.Name != "laptop" {
		t.Fatalf("verify returned wrong token: %+v", got)
	}
	if got.Hash != "" {
		t.Fatal("verify must strip the hash before returning")
	}
}

func TestVerifyAPITokenWrongSecret(t *testing.T) {
	ms, _ := newTestMetaStore(t)
	wire, _, err := ms.CreateAPIToken("alice", "laptop", nil)
	if err != nil {
		t.Fatal(err)
	}

	// Truncate the secret to invalidate it but keep the ID intact so we
	// hit the bcrypt comparison branch.
	dot := strings.Index(wire, ".")
	tampered := wire[:dot+1] + "wrong"
	if _, err := ms.VerifyAPIToken("alice", tampered); !errors.Is(err, errAPITokenNotFound) {
		t.Fatalf("expected errAPITokenNotFound, got %v", err)
	}
}

func TestVerifyAPITokenUnknownUser(t *testing.T) {
	ms, _ := newTestMetaStore(t)
	wire, _, err := ms.CreateAPIToken("alice", "laptop", nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ms.VerifyAPIToken("bob", wire); !errors.Is(err, errAPITokenNotFound) {
		t.Fatalf("token under wrong user should fail, got %v", err)
	}
}

func TestVerifyAPITokenExpired(t *testing.T) {
	ms, _ := newTestMetaStore(t)
	past := time.Now().Add(-time.Hour)
	wire, _, err := ms.CreateAPIToken("alice", "laptop", &past)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ms.VerifyAPIToken("alice", wire); !errors.Is(err, errAPITokenExpired) {
		t.Fatalf("expected errAPITokenExpired, got %v", err)
	}
}

func TestDeleteAPIToken(t *testing.T) {
	ms, _ := newTestMetaStore(t)
	wire, tok, err := ms.CreateAPIToken("alice", "laptop", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := ms.DeleteAPIToken("alice", tok.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := ms.VerifyAPIToken("alice", wire); !errors.Is(err, errAPITokenNotFound) {
		t.Fatalf("deleted token should not verify, got %v", err)
	}
	if err := ms.DeleteAPIToken("alice", tok.ID); !errors.Is(err, errAPITokenNotFound) {
		t.Fatalf("second delete should report not found, got %v", err)
	}
}

func TestTouchAPIToken(t *testing.T) {
	ms, _ := newTestMetaStore(t)
	_, tok, err := ms.CreateAPIToken("alice", "laptop", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := ms.TouchAPIToken("alice", tok.ID); err != nil {
		t.Fatal(err)
	}
	got, _ := ms.Get("alice")
	if len(got.APITokens) != 1 || got.APITokens[0].LastUsedAt == nil {
		t.Fatalf("touch did not set LastUsedAt: %+v", got.APITokens)
	}
}

func TestListAPITokensStripsHash(t *testing.T) {
	ms, _ := newTestMetaStore(t)
	if _, _, err := ms.CreateAPIToken("alice", "laptop", nil); err != nil {
		t.Fatal(err)
	}
	for _, tok := range ms.ListAPITokens("alice") {
		if tok.Hash != "" {
			t.Fatalf("hash leaked into list output: %+v", tok)
		}
	}
}

func TestCreateAPITokenValidatesName(t *testing.T) {
	ms, _ := newTestMetaStore(t)
	if _, _, err := ms.CreateAPIToken("alice", "", nil); !errors.Is(err, errAPITokenNameRequired) {
		t.Fatalf("empty name should be rejected, got %v", err)
	}
	if _, _, err := ms.CreateAPIToken("alice", strings.Repeat("x", apiTokenMaxNameLen+1), nil); !errors.Is(err, errAPITokenNameTooLong) {
		t.Fatalf("too-long name should be rejected, got %v", err)
	}
}

func TestCreateAPITokenEnforcesLimit(t *testing.T) {
	ms, _ := newTestMetaStore(t)
	for i := 0; i < apiTokenMaxPerUser; i++ {
		if _, _, err := ms.CreateAPIToken("alice", "t", nil); err != nil {
			t.Fatalf("create %d: %v", i, err)
		}
	}
	if _, _, err := ms.CreateAPIToken("alice", "overflow", nil); !errors.Is(err, errAPITokenTooMany) {
		t.Fatalf("expected errAPITokenTooMany, got %v", err)
	}
}

func TestAPITokenConcurrentCreate(t *testing.T) {
	ms, _ := newTestMetaStore(t)
	const n = 16
	var wg sync.WaitGroup
	wg.Add(n)
	for i := 0; i < n; i++ {
		go func() {
			defer wg.Done()
			if _, _, err := ms.CreateAPIToken("alice", "concurrent", nil); err != nil {
				t.Errorf("create: %v", err)
			}
		}()
	}
	wg.Wait()
	got, _ := ms.Get("alice")
	if len(got.APITokens) != n {
		t.Fatalf("expected %d tokens, got %d", n, len(got.APITokens))
	}
}
