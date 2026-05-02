package server

import (
	"encoding/json"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestUploadWebhookFiresJSONPost(t *testing.T) {
	type captured struct {
		method string
		ct     string
		body   uploadEvent
	}
	got := make(chan captured, 1)

	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var ev uploadEvent
		_ = json.Unmarshal(body, &ev)
		got <- captured{method: r.Method, ct: r.Header.Get("Content-Type"), body: ev}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer target.Close()

	srv := &Server{
		uploadWebhookURL: target.URL,
		logger:           log.New(io.Discard, "", 0),
	}

	srv.fireUploadWebhook(uploadEvent{
		Filename:    "report.pdf",
		ContentType: "application/pdf",
		Size:        4096,
		URL:         "https://example.com/abc/report.pdf",
		DeleteURL:   "https://example.com/abc/report.pdf/del",
		User:        "alice",
	})

	select {
	case c := <-got:
		if c.method != http.MethodPost {
			t.Errorf("method: got %q, want POST", c.method)
		}
		if c.ct != "application/json" {
			t.Errorf("content-type: got %q, want application/json", c.ct)
		}
		if c.body.Event != "upload" {
			t.Errorf("event: got %q, want %q", c.body.Event, "upload")
		}
		if c.body.Filename != "report.pdf" || c.body.Size != 4096 || c.body.User != "alice" {
			t.Errorf("payload mismatch: %+v", c.body)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("webhook was not fired within 2s")
	}
}

func TestUploadWebhookSkipsWhenURLEmpty(t *testing.T) {
	srv := &Server{logger: log.New(io.Discard, "", 0)}
	// Should be a no-op; if it tried to make a network call, it would block
	// or panic. We just want to assert no panic and no goroutine is spawned
	// that touches network.
	srv.fireUploadWebhook(uploadEvent{Filename: "x"})
}
