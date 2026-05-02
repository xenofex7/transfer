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

type capturedWebhook struct {
	method string
	ct     string
	auth   string
	body   uploadEvent
}

func captureWebhook(t *testing.T, srv *Server, fire func(*Server)) capturedWebhook {
	t.Helper()
	got := make(chan capturedWebhook, 1)
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var ev uploadEvent
		_ = json.Unmarshal(body, &ev)
		got <- capturedWebhook{
			method: r.Method,
			ct:     r.Header.Get("Content-Type"),
			auth:   r.Header.Get("Authorization"),
			body:   ev,
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(target.Close)

	srv.uploadWebhookURL = target.URL
	srv.logger = log.New(io.Discard, "", 0)
	fire(srv)

	select {
	case c := <-got:
		return c
	case <-time.After(2 * time.Second):
		t.Fatal("webhook was not fired within 2s")
	}
	return capturedWebhook{}
}

func TestUploadWebhookFiresJSONPost(t *testing.T) {
	srv := &Server{}
	c := captureWebhook(t, srv, func(s *Server) {
		s.fireUploadWebhook(uploadEvent{
			Filename:    "report.pdf",
			ContentType: "application/pdf",
			Size:        4096,
			URL:         "https://example.com/abc/report.pdf",
			DeleteURL:   "https://example.com/abc/report.pdf/del",
			User:        "alice",
		})
	})

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
}

func TestDownloadWebhookEvent(t *testing.T) {
	srv := &Server{}
	c := captureWebhook(t, srv, func(s *Server) {
		s.fireDownloadWebhook(uploadEvent{Filename: "doc.txt", Downloads: 3})
	})
	if c.body.Event != "download" {
		t.Errorf("event: got %q, want download", c.body.Event)
	}
	if c.body.Downloads != 3 {
		t.Errorf("downloads: got %d, want 3", c.body.Downloads)
	}
}

func TestDeleteWebhookEvent(t *testing.T) {
	srv := &Server{}
	c := captureWebhook(t, srv, func(s *Server) {
		s.fireDeleteWebhook(uploadEvent{Filename: "doc.txt", User: "bob", Downloads: 7})
	})
	if c.body.Event != "delete" {
		t.Errorf("event: got %q, want delete", c.body.Event)
	}
	if c.body.User != "bob" || c.body.Downloads != 7 {
		t.Errorf("payload mismatch: %+v", c.body)
	}
}

func TestWebhookSendsBearerToken(t *testing.T) {
	srv := &Server{webhookToken: "s3cret"}
	c := captureWebhook(t, srv, func(s *Server) {
		s.fireUploadWebhook(uploadEvent{Filename: "x"})
	})
	if c.auth != "Bearer s3cret" {
		t.Errorf("authorization: got %q, want %q", c.auth, "Bearer s3cret")
	}
}

func TestWebhookOmitsAuthWhenTokenEmpty(t *testing.T) {
	srv := &Server{}
	c := captureWebhook(t, srv, func(s *Server) {
		s.fireUploadWebhook(uploadEvent{Filename: "x"})
	})
	if c.auth != "" {
		t.Errorf("authorization should be empty, got %q", c.auth)
	}
}

func TestUploadWebhookSkipsWhenURLEmpty(t *testing.T) {
	srv := &Server{logger: log.New(io.Discard, "", 0)}
	srv.fireUploadWebhook(uploadEvent{Filename: "x"})
	srv.fireDownloadWebhook(uploadEvent{Filename: "x"})
	srv.fireDeleteWebhook(uploadEvent{Filename: "x"})
}
