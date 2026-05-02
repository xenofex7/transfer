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

// uploadEvent is the JSON payload posted to the configured upload webhook.
// The shape is intentionally small and stable; downstream chat integrations
// (Slack/Discord/Mattermost/etc.) can map it to their own format.
type uploadEvent struct {
	Event       string `json:"event"`
	Filename    string `json:"filename"`
	ContentType string `json:"content_type"`
	Size        int64  `json:"size"`
	URL         string `json:"url"`
	DeleteURL   string `json:"delete_url"`
	User        string `json:"user,omitempty"`
}

// fireUploadWebhook posts the event in a background goroutine. Failures are
// logged and swallowed - the upload itself has already been persisted and
// the webhook is best-effort.
func (s *Server) fireUploadWebhook(ev uploadEvent) {
	if s.uploadWebhookURL == "" {
		return
	}
	ev.Event = "upload"

	go func(url string, ev uploadEvent) {
		body, err := json.Marshal(ev)
		if err != nil {
			s.logger.Printf("upload webhook: marshal: %v", err)
			return
		}

		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
		if err != nil {
			s.logger.Printf("upload webhook: build request: %v", err)
			return
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("User-Agent", "transfer.sh-webhook/1")

		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			s.logger.Printf("upload webhook: post %s: %v", url, err)
			return
		}
		defer func() { _ = resp.Body.Close() }()

		if resp.StatusCode >= 400 {
			s.logger.Printf("upload webhook: %s returned %d", url, resp.StatusCode)
		}
	}(s.uploadWebhookURL, ev)
}
