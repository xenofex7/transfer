package server

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/mux"
)

const day = 24 * time.Hour

func TestExpiryAfter(t *testing.T) {
	base := time.Date(2026, 11, 3, 12, 0, 0, 0, time.UTC)
	cases := []struct {
		name   string
		days   int
		maxTTL time.Duration
		want   time.Duration
	}{
		{"requested below cap", 30, 180 * day, 30 * day},
		{"requested above cap", 365, 180 * day, 180 * day},
		{"requested equals cap", 180, 180 * day, 180 * day},
		{"requested one above cap", 181, 180 * day, 180 * day},
		{"default uses cap", 0, 180 * day, 180 * day},
		{"negative uses cap", -5, 180 * day, 180 * day},
		{"cap not a whole day", 1, 36 * time.Hour, day},
		{"overflowing request capped", 1 << 50, 180 * day, 180 * day},
		{"no cap", 30, 0, 30 * day},
		{"negative cap means no cap", 30, -time.Hour, 30 * day},
	}
	for _, c := range cases {
		if got := expiryAfter(base, c.days, c.maxTTL); !got.Equal(base.Add(c.want)) {
			t.Errorf("%s: got %v, want %v", c.name, got.Sub(base), c.want)
		}
	}
	for _, maxTTL := range []time.Duration{0, -time.Hour} {
		if got := expiryAfter(base, 0, maxTTL); !got.IsZero() {
			t.Errorf("no request and cap %v: got %v, want zero", maxTTL, got)
		}
	}
}

func TestMetadataForRequestMaxDays(t *testing.T) {
	s := &Server{randomTokenLength: 6, anonUploadTTL: day, authUploadTTL: 180 * day}

	upload := func(user, maxDays string) metadata {
		t.Helper()
		r := httptest.NewRequest("PUT", "/a.txt", nil)
		if user != "" {
			r = r.WithContext(context.WithValue(r.Context(), authContextKey{}, user))
		}
		if maxDays != "" {
			r.Header.Set("Max-Days", maxDays)
		}
		m, err := s.metadataForRequest("text/plain", 1, r)
		if err != nil {
			t.Fatalf("metadataForRequest: %v", err)
		}
		if m.UploadedAt.IsZero() || time.Since(m.UploadedAt) > time.Minute {
			t.Fatalf("UploadedAt not set to now: %v", m.UploadedAt)
		}
		return m
	}

	cases := []struct {
		user, maxDays string
		want          time.Duration
	}{
		{"dev", "30", 30 * day},
		{"dev", "999", 180 * day},
		{"dev", "", 180 * day},
		{"dev", "junk", 180 * day},
		{"", "30", day},
		{"", "", day},
	}
	for _, c := range cases {
		m := upload(c.user, c.maxDays)
		if got := m.MaxDate.Sub(m.UploadedAt); got != c.want {
			t.Errorf("user %q Max-Days %q: expiry after %v, want %v", c.user, c.maxDays, got, c.want)
		}
	}
}

func TestUploadOptionsMaxDays(t *testing.T) {
	s, store := adminTestServer(t)
	s.anonUploadTTL = day
	s.authUploadTTL = 180 * day
	uploadedAt := time.Now().Add(-10 * day).Truncate(time.Second)
	original := uploadedAt.Add(180 * day)

	seed := func(m metadata) {
		t.Helper()
		m.ContentType, m.MaxDownloads, m.DeletionToken = "text/plain", -1, "del456"
		seedFile(t, store, "tok123", "doc.txt", "hello", m)
	}
	patch := func(body string) (int, metadata) {
		t.Helper()
		req := httptest.NewRequest("PATCH", "/tok123/doc.txt/del456", strings.NewReader(body))
		req = mux.SetURLVars(req, map[string]string{"token": "tok123", "filename": "doc.txt", "deletionToken": "del456"})
		rec := httptest.NewRecorder()
		s.uploadOptionsHandler(rec, req)
		rc, _, err := store.Get(context.Background(), "tok123", "doc.txt.metadata", nil)
		if err != nil {
			t.Fatalf("read metadata: %v", err)
		}
		defer func() { _ = rc.Close() }()
		buf := &bytes.Buffer{}
		_, _ = buf.ReadFrom(rc)
		var m metadata
		if err := json.Unmarshal(buf.Bytes(), &m); err != nil {
			t.Fatalf("decode metadata: %v", err)
		}
		return rec.Code, m
	}

	seed(metadata{Uploader: "dev", UploadedAt: uploadedAt, MaxDate: original})
	for _, c := range []struct {
		body string
		want time.Time
	}{
		{`{"maxDays":30}`, uploadedAt.Add(30 * day)},
		{`{"maxDays":9999}`, uploadedAt.Add(180 * day)},
		{`{"maxDays":30}`, uploadedAt.Add(30 * day)},
		{`{"maxDays":0}`, uploadedAt.Add(180 * day)},
	} {
		code, m := patch(c.body)
		if code != http.StatusNoContent || !m.MaxDate.Equal(c.want) {
			t.Errorf("%s: got %d and %v, want 204 and %v", c.body, code, m.MaxDate, c.want)
		}
	}

	custom := uploadedAt.Add(40 * day)
	seed(metadata{Uploader: "dev", UploadedAt: uploadedAt, MaxDate: custom})
	if code, m := patch(`{"maxDownloads":2}`); code != http.StatusNoContent || !m.MaxDate.Equal(custom) || m.MaxDownloads != 2 {
		t.Errorf("omitted maxDays: got %d, %v, max %d, want 204 with expiry unchanged at %v", code, m.MaxDate, m.MaxDownloads, custom)
	}

	seed(metadata{Uploader: "dev", UploadedAt: uploadedAt, MaxDate: original})
	if code, m := patch(`{"maxDays":5}`); code != http.StatusBadRequest || !m.MaxDate.Equal(original) {
		t.Errorf("past date: got %d and %v, want 400 and unchanged %v", code, m.MaxDate, original)
	}

	guestUpload := time.Now().Truncate(time.Second)
	seed(metadata{UploadedAt: guestUpload, MaxDate: guestUpload.Add(day)})
	if code, m := patch(`{"maxDays":30}`); code != http.StatusNoContent || !m.MaxDate.Equal(guestUpload.Add(day)) {
		t.Errorf("guest upload: got %d and %v, want 204 capped at %v", code, m.MaxDate, guestUpload.Add(day))
	}

	seed(metadata{Uploader: "dev", MaxDate: original})
	before := time.Now()
	code, m := patch(`{"maxDays":3}`)
	if code != http.StatusNoContent || m.MaxDate.Before(before.Add(3*day)) || m.MaxDate.After(time.Now().Add(3*day)) {
		t.Errorf("legacy upload without UploadedAt: got %d and %v, want 204 and about now + 3 days", code, m.MaxDate)
	}
	if !m.MaxDate.Equal(m.UploadedAt.Add(3 * day)) {
		t.Fatalf("legacy upload: UploadedAt %v not persisted as the base of %v", m.UploadedAt, m.MaxDate)
	}
	firstBase := m.UploadedAt
	time.Sleep(10 * time.Millisecond)
	if _, m := patch(`{"maxDays":0}`); !m.UploadedAt.Equal(firstBase) || !m.MaxDate.Equal(firstBase.Add(180*day)) {
		t.Errorf("legacy upload re-edited: base moved from %v to %v, expiry %v", firstBase, m.UploadedAt, m.MaxDate)
	}

	s.authUploadTTL = 0
	seed(metadata{Uploader: "dev", UploadedAt: uploadedAt})
	if code, m := patch(`{"maxDays":0}`); code != http.StatusNoContent || !m.MaxDate.IsZero() {
		t.Errorf("no TTL, default: got %d and %v, want 204 and no expiry", code, m.MaxDate)
	}
	if code, m := patch(`{"maxDays":30}`); code != http.StatusNoContent || !m.MaxDate.Equal(uploadedAt.Add(30*day)) {
		t.Errorf("no TTL, 30 days: got %d and %v, want 204 and %v", code, m.MaxDate, uploadedAt.Add(30*day))
	}
}
