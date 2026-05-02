/*
The MIT License (MIT)

Copyright (c) 2026 xenofex7
*/

package server

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"time"
)

// uploadEvent is the JSON payload posted to the configured webhook on every
// upload, download or delete. The shape is intentionally small and stable;
// downstream chat integrations (Slack, Discord, Mattermost, Teams ...) can
// map it onto their own request format with a tiny adapter.
type uploadEvent struct {
	Event       string `json:"event"`
	Filename    string `json:"filename"`
	ContentType string `json:"content_type,omitempty"`
	Size        int64  `json:"size,omitempty"`
	URL         string `json:"url,omitempty"`
	DeleteURL   string `json:"delete_url,omitempty"`
	User        string `json:"user,omitempty"`
	Downloads   int    `json:"downloads,omitempty"`
}

// fireUploadWebhook sends an "upload" event. Kept for callers that already
// use the convenience.
func (s *Server) fireUploadWebhook(ev uploadEvent) {
	ev.Event = "upload"
	s.fireWebhook(ev)
}

// fireDownloadWebhook sends a "download" event.
func (s *Server) fireDownloadWebhook(ev uploadEvent) {
	ev.Event = "download"
	s.fireWebhook(ev)
}

// fireDeleteWebhook sends a "delete" event.
func (s *Server) fireDeleteWebhook(ev uploadEvent) {
	ev.Event = "delete"
	s.fireWebhook(ev)
}

// fireWebhook posts the event in a background goroutine. Failures are logged
// and swallowed - the user-facing operation has already succeeded by the
// time we get here, and the webhook is best-effort.
func (s *Server) fireWebhook(ev uploadEvent) {
	if s.uploadWebhookURL == "" {
		return
	}
	if ev.Event == "" {
		ev.Event = "upload"
	}

	url := s.uploadWebhookURL
	token := s.webhookToken

	go func(url, token string, ev uploadEvent) {
		body, err := json.Marshal(ev)
		if err != nil {
			s.logger.Printf("webhook: marshal: %v", err)
			return
		}

		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
		if err != nil {
			s.logger.Printf("webhook: build request: %v", err)
			return
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("User-Agent", "transfer.sh-webhook/1")
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}

		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			s.logger.Printf("webhook: post %s: %v", url, err)
			return
		}
		defer func() { _ = resp.Body.Close() }()

		if resp.StatusCode >= 400 {
			s.logger.Printf("webhook: %s returned %d for event %q", url, resp.StatusCode, ev.Event)
		}
	}(url, token, ev)
}
