package storage

import (
	"context"
	"io"
	"log"
	"os"
	"strings"
	"testing"
)

func newTestStorage(t *testing.T) *LocalStorage {
	t.Helper()
	dir := t.TempDir()
	logger := log.New(io.Discard, "", 0)
	s, err := NewLocalStorage(dir, logger)
	if err != nil {
		t.Fatalf("NewLocalStorage: %v", err)
	}
	return s
}

func TestLocalStoragePutGetRoundTrip(t *testing.T) {
	s := newTestStorage(t)
	ctx := context.Background()
	want := "hello world"

	if err := s.Put(ctx, "tok", "hello.txt", strings.NewReader(want), "text/plain", uint64(len(want))); err != nil {
		t.Fatalf("Put: %v", err)
	}

	if cl, err := s.Head(ctx, "tok", "hello.txt"); err != nil {
		t.Fatalf("Head: %v", err)
	} else if cl != uint64(len(want)) {
		t.Errorf("Head: got %d, want %d", cl, len(want))
	}

	rc, _, err := s.Get(ctx, "tok", "hello.txt", nil)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	defer func() { _ = rc.Close() }()

	got, err := io.ReadAll(rc)
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	if string(got) != want {
		t.Errorf("payload: got %q, want %q", got, want)
	}
}

func TestLocalStorageDeleteRemovesFile(t *testing.T) {
	s := newTestStorage(t)
	ctx := context.Background()

	if err := s.Put(ctx, "tok", "bye.txt", strings.NewReader("bye"), "text/plain", 3); err != nil {
		t.Fatalf("Put: %v", err)
	}
	if err := s.Delete(ctx, "tok", "bye.txt"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, err := s.Head(ctx, "tok", "bye.txt"); err == nil || !s.IsNotExist(err) {
		t.Errorf("Head after Delete: want IsNotExist, got %v", err)
	}
}

func TestLocalStorageHeadOnMissing(t *testing.T) {
	s := newTestStorage(t)
	_, err := s.Head(context.Background(), "nope", "missing.txt")
	if err == nil {
		t.Fatal("Head on missing file: expected error")
	}
	if !s.IsNotExist(err) {
		t.Errorf("Head on missing file: want IsNotExist, got %v", err)
	}
}

func TestLocalStorageType(t *testing.T) {
	if got := newTestStorage(t).Type(); got != "local" {
		t.Errorf("Type: got %q, want %q", got, "local")
	}
}

func TestLocalStorageListFindsBothFiles(t *testing.T) {
	s := newTestStorage(t)
	ctx := context.Background()

	if err := s.Put(ctx, "tokenA", "alpha.txt", strings.NewReader("aaa"), "text/plain", 3); err != nil {
		t.Fatalf("Put alpha: %v", err)
	}
	if err := s.Put(ctx, "tokenA", "alpha.txt.metadata", strings.NewReader(`{"ContentType":"text/plain","Downloads":3}`), "text/json", 0); err != nil {
		t.Fatalf("Put alpha metadata: %v", err)
	}
	if err := s.Put(ctx, "tokenB", "beta.bin", strings.NewReader("bb"), "application/octet-stream", 2); err != nil {
		t.Fatalf("Put beta: %v", err)
	}

	entries, err := s.List(ctx)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if got := len(entries); got != 2 {
		t.Fatalf("entry count: got %d, want 2", got)
	}

	byToken := map[string]ListEntry{}
	for _, e := range entries {
		byToken[e.Token] = e
	}
	if _, ok := byToken["tokenA"]; !ok {
		t.Fatal("missing tokenA in List output")
	}
	if string(byToken["tokenA"].Metadata) == "" {
		t.Error("tokenA metadata blob is empty; expected raw JSON")
	}
	if string(byToken["tokenB"].Metadata) != "" {
		t.Errorf("tokenB had no metadata file but List returned %q", byToken["tokenB"].Metadata)
	}
}

func TestLocalStorageListMissingDirReturnsEmpty(t *testing.T) {
	logger := log.New(io.Discard, "", 0)
	s, _ := NewLocalStorage(t.TempDir()+"/does-not-exist", logger)

	entries, err := s.List(context.Background())
	if err != nil {
		t.Fatalf("List on missing basedir: %v", err)
	}
	if len(entries) != 0 {
		t.Errorf("expected zero entries, got %d", len(entries))
	}
}

// Ensure t.TempDir cleanup works as expected.
func TestLocalStorageBasedirIsolated(t *testing.T) {
	a := newTestStorage(t)
	b := newTestStorage(t)
	if a.basedir == b.basedir {
		t.Fatal("two NewLocalStorage instances share a basedir")
	}
	if _, err := os.Stat(a.basedir); err != nil {
		t.Fatalf("basedir not created: %v", err)
	}
}

func TestLocalStoragePurge(t *testing.T) {
	s := newTestStorage(t)
	ctx := context.Background()

	put := func(token, name, meta string) {
		t.Helper()
		if err := s.Put(ctx, token, name, strings.NewReader("x"), "text/plain", 1); err != nil {
			t.Fatalf("Put %s/%s: %v", token, name, err)
		}
		if meta != "" {
			if err := s.Put(ctx, token, name+".metadata", strings.NewReader(meta), "text/json", uint64(len(meta))); err != nil {
				t.Fatalf("Put metadata %s/%s: %v", token, name, err)
			}
		}
	}

	put("tokexp", "gone.txt", `{"MaxDate":"2001-01-01T00:00:00Z"}`)
	put("tokfut", "keep.txt", `{"MaxDate":"2999-01-01T00:00:00Z"}`)
	put("toknil", "nodate.txt", `{"MaxDate":"0001-01-01T00:00:00Z"}`)
	put("tokraw", "nometa.txt", "")

	// Dotfiles/dirs at the top level must survive any purge.
	if err := os.WriteFile(s.basedir+"/.settings.json", []byte("{}"), 0600); err != nil {
		t.Fatalf("write settings: %v", err)
	}

	if err := s.Purge(ctx, 360*24*3600*1e9); err != nil {
		t.Fatalf("Purge: %v", err)
	}

	if _, err := s.Head(ctx, "tokexp", "gone.txt"); !os.IsNotExist(err) {
		t.Errorf("expired file should be purged, got err=%v", err)
	}
	if _, err := os.Stat(s.basedir + "/tokexp/gone.txt.metadata"); !os.IsNotExist(err) {
		t.Errorf("expired metadata should be purged, got err=%v", err)
	}
	for _, f := range [][2]string{{"tokfut", "keep.txt"}, {"toknil", "nodate.txt"}, {"tokraw", "nometa.txt"}} {
		if _, err := s.Head(ctx, f[0], f[1]); err != nil {
			t.Errorf("%s/%s should survive purge: %v", f[0], f[1], err)
		}
	}
	if _, err := os.Stat(s.basedir + "/.settings.json"); err != nil {
		t.Errorf(".settings.json should survive purge: %v", err)
	}
}
