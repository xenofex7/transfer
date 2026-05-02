/*
The MIT License (MIT)

Copyright (c) 2026 xenofex7
*/

package server

import (
	"encoding/json"
	"net/http"
	"net/url"
	"path"
	"sort"
	"strconv"
	"time"
)

// adminFileRow is the per-file row rendered in the admin file list.
type adminFileRow struct {
	Token              string
	Filename           string
	ContentType        string
	Size               int64
	SizeHuman          string
	UploadedAt         time.Time
	UploadedHuman      string
	Downloads          int
	MaxDownloads       int
	Remaining          string
	LastDownloadedAt   time.Time
	LastDownloadHuman  string
	ExpiresAt          time.Time
	ExpiresHuman       string
	URL                string
	DeleteURL          string
	Expired            bool
}

// adminFilesData is the template context for admin.html.
type adminFilesData struct {
	Hostname string
	Rows     []adminFileRow
	Total    int
	Recent   []adminDeletion
}

// adminDeletion is a single past deletion (filled in Phase C). Empty in Phase A.
type adminDeletion struct {
	Filename  string
	Token     string
	DeletedAt time.Time
	Downloads int
	User      string
}

func (s *Server) adminFilesHandler(w http.ResponseWriter, r *http.Request) {
	entries, err := s.storage.List(r.Context())
	if err != nil {
		s.logger.Printf("admin: storage.List: %v", err)
		http.Error(w, "Could not list files", http.StatusInternalServerError)
		return
	}

	rows := make([]adminFileRow, 0, len(entries))
	for _, e := range entries {
		row := adminFileRow{
			Token:         e.Token,
			Filename:      e.Filename,
			Size:          e.Size,
			SizeHuman:     formatSize(e.Size),
			UploadedAt:    e.UploadedAt,
			UploadedHuman: e.UploadedAt.Format("2006-01-02 15:04"),
		}

		var meta metadata
		if len(e.Metadata) > 0 {
			if err := json.Unmarshal(e.Metadata, &meta); err == nil {
				row.ContentType = meta.ContentType
				row.Downloads = meta.Downloads
				row.MaxDownloads = meta.MaxDownloads
				row.Remaining = remainingDownloadsLabel(meta)
				row.ExpiresAt = meta.MaxDate
				row.ExpiresHuman = expiresLabel(meta)
				row.Expired = !meta.MaxDate.IsZero() && time.Now().After(meta.MaxDate)
				row.LastDownloadedAt = meta.LastDownloadedAt
				row.LastDownloadHuman = lastDownloadLabel(meta.LastDownloadedAt)

				escFilename := url.PathEscape(e.Filename)
				rel, _ := url.Parse(path.Join(s.proxyPath, e.Token, escFilename))
				del, _ := url.Parse(path.Join(s.proxyPath, e.Token, escFilename, meta.DeletionToken))
				row.URL = resolveURL(r, rel, s.proxyPort)
				row.DeleteURL = resolveURL(r, del, s.proxyPort)
			}
		}

		rows = append(rows, row)
	}

	// Newest first - List already sorts but be defensive in case of clock skew.
	sort.SliceStable(rows, func(i, j int) bool { return rows[i].UploadedAt.After(rows[j].UploadedAt) })

	data := adminFilesData{
		Hostname: getURL(r, s.proxyPort).Host,
		Rows:     rows,
		Total:    len(rows),
		Recent:   s.recentDeletions(),
	}

	w.Header().Set("Cache-Control", "no-store")
	if err := htmlTemplates.ExecuteTemplate(w, "admin.html", data); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

// remainingDownloadsLabel formats how many downloads are still allowed.
func remainingDownloadsLabel(m metadata) string {
	if m.MaxDownloads == -1 {
		return "unlimited"
	}
	left := m.MaxDownloads - m.Downloads
	if left < 0 {
		left = 0
	}
	return strconv.Itoa(left) + " / " + strconv.Itoa(m.MaxDownloads)
}

// lastDownloadLabel renders a relative-time string for the most recent
// download, or a placeholder for files that have never been downloaded.
func lastDownloadLabel(t time.Time) string {
	if t.IsZero() {
		return "never"
	}
	since := time.Since(t)
	switch {
	case since < time.Minute:
		return "just now"
	case since < time.Hour:
		mins := int(since.Minutes())
		if mins == 1 {
			return "1 min ago"
		}
		return strconv.Itoa(mins) + " min ago"
	case since < 24*time.Hour:
		hours := int(since.Hours())
		if hours == 1 {
			return "1h ago"
		}
		return strconv.Itoa(hours) + "h ago"
	case since < 7*24*time.Hour:
		days := int(since.Hours() / 24)
		if days == 1 {
			return "1 day ago"
		}
		return strconv.Itoa(days) + " days ago"
	default:
		return t.Format("2006-01-02")
	}
}

// expiresLabel formats the auto-purge date for the dashboard.
func expiresLabel(m metadata) string {
	if m.MaxDate.IsZero() {
		return "auto-purge default"
	}
	delta := time.Until(m.MaxDate)
	if delta < 0 {
		return "expired"
	}
	days := int(delta.Hours() / 24)
	if days < 1 {
		hours := int(delta.Hours())
		if hours < 1 {
			return "<1h"
		}
		return strconv.Itoa(hours) + "h"
	}
	if days == 1 {
		return "1 day"
	}
	return strconv.Itoa(days) + " days"
}

// recentDeletions is wired in Phase C. Returns nil here so the template stays
// simple.
func (s *Server) recentDeletions() []adminDeletion {
	return nil
}
