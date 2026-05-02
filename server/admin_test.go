package server

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/dutchcoders/transfer.sh/server/storage"
	"github.com/gorilla/mux"
)

// adminTestServer wires up just enough of Server for the admin handler to
// run end-to-end against a real LocalStorage in a temp dir.
func adminTestServer(t *testing.T) (*Server, *storage.LocalStorage) {
	t.Helper()
	loadEmbeddedTemplates(nil)
	store, err := storage.NewLocalStorage(t.TempDir(), log.New(io.Discard, "", 0))
	if err != nil {
		t.Fatalf("NewLocalStorage: %v", err)
	}
	return &Server{
		storage:           store,
		logger:            log.New(io.Discard, "", 0),
		randomTokenLength: 6,
		locks:             sync.Map{},
	}, store
}

// seedFile writes a file plus its accompanying .metadata next to it via the
// real storage backend. Returns the metadata used.
func seedFile(t *testing.T, store *storage.LocalStorage, token, name, content string, m metadata) {
	t.Helper()
	ctx := context.Background()
	if err := store.Put(ctx, token, name, strings.NewReader(content), m.ContentType, uint64(len(content))); err != nil {
		t.Fatalf("Put %s: %v", name, err)
	}
	buf := &bytes.Buffer{}
	if err := json.NewEncoder(buf).Encode(m); err != nil {
		t.Fatalf("encode metadata: %v", err)
	}
	if err := store.Put(ctx, token, name+".metadata", buf, "text/json", uint64(buf.Len())); err != nil {
		t.Fatalf("Put metadata: %v", err)
	}
}

func TestAdminFilesHandlerListsUploadedFiles(t *testing.T) {
	srv, store := adminTestServer(t)

	seedFile(t, store, "AAA111", "report.pdf", "fake-pdf", metadata{
		ContentType:   "application/pdf",
		Downloads:     2,
		MaxDownloads:  10,
		MaxDate:       time.Now().Add(72 * time.Hour),
		DeletionToken: "DEL-123",
	})
	seedFile(t, store, "BBB222", "image.png", "fake-png", metadata{
		ContentType:   "image/png",
		Downloads:     0,
		MaxDownloads:  -1,
		DeletionToken: "DEL-456",
	})

	req := httptest.NewRequest(http.MethodGet, "/admin/files", nil)
	req = mux.SetURLVars(req, nil)
	rec := httptest.NewRecorder()
	srv.adminFilesHandler(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status: got %d, want 200", rec.Code)
	}
	body := rec.Body.String()
	for _, want := range []string{
		"report.pdf",
		"image.png",
		"AAA111",
		"BBB222",
		"DEL-123",
		"DEL-456",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("body missing %q", want)
		}
	}
}

func TestAdminFilesHandlerEmpty(t *testing.T) {
	srv, _ := adminTestServer(t)

	req := httptest.NewRequest(http.MethodGet, "/admin/files", nil)
	rec := httptest.NewRecorder()
	srv.adminFilesHandler(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status: got %d, want 200; body: %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "No files yet") {
		t.Error("empty state did not render the 'No files yet' message")
	}
}

func TestRemainingDownloadsLabel(t *testing.T) {
	cases := []struct {
		m    metadata
		want string
	}{
		{metadata{MaxDownloads: -1}, "unlimited"},
		{metadata{MaxDownloads: 10, Downloads: 3}, "7 / 10"},
		{metadata{MaxDownloads: 5, Downloads: 5}, "0 / 5"},
		{metadata{MaxDownloads: 5, Downloads: 99}, "0 / 5"},
	}
	for _, c := range cases {
		if got := remainingDownloadsLabel(c.m); got != c.want {
			t.Errorf("remainingDownloadsLabel(%+v) = %q, want %q", c.m, got, c.want)
		}
	}
}

func TestExpiresLabel(t *testing.T) {
	cases := []struct {
		name string
		m    metadata
		want string
	}{
		{"zero MaxDate falls through to default", metadata{}, "auto-purge default"},
		{"already expired", metadata{MaxDate: time.Now().Add(-time.Hour)}, "expired"},
		{"under one hour", metadata{MaxDate: time.Now().Add(30 * time.Minute)}, "<1h"},
	}
	for _, c := range cases {
		if got := expiresLabel(c.m); got != c.want {
			t.Errorf("%s: got %q, want %q", c.name, got, c.want)
		}
	}
}
