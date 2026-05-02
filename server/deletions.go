/*
The MIT License (MIT)

Copyright (c) 2026 xenofex7
*/

package server

import (
	"bufio"
	"encoding/json"
	"errors"
	"io"
	"os"
	"sync"
	"time"
)

// DeletionRecord describes one past deletion of an uploaded file.
type DeletionRecord struct {
	DeletedAt time.Time `json:"deleted_at"`
	Token     string    `json:"token"`
	Filename  string    `json:"filename"`
	Size      int64     `json:"size,omitempty"`
	Downloads int       `json:"downloads,omitempty"`
	User      string    `json:"user,omitempty"`
}

// deletionLog is a small append-only JSON-lines log of deletions. Reads are
// best-effort and tolerate truncated trailing lines (e.g. after a crash).
type deletionLog struct {
	path string
	mu   sync.Mutex

	// Maximum lines to retain on disk. When exceeded the file is rewritten
	// keeping only the most recent entries.
	maxLines int
}

// newDeletionLog returns a log writer rooted at path. If path is empty the
// returned log is a no-op (used when basedir is unknown).
func newDeletionLog(path string) *deletionLog {
	return &deletionLog{path: path, maxLines: 1000}
}

// Append writes one record to the log. Errors are returned to the caller but
// most call sites only log them - a missed deletion entry should not block
// the response to the user.
func (l *deletionLog) Append(rec DeletionRecord) error {
	if l == nil || l.path == "" {
		return nil
	}
	if rec.DeletedAt.IsZero() {
		rec.DeletedAt = time.Now()
	}

	body, err := json.Marshal(rec)
	if err != nil {
		return err
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	f, err := os.OpenFile(l.path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.Write(append(body, '\n')); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}

	return l.trim()
}

// Recent returns the last n entries, newest first. Reads the entire file
// into memory; with maxLines=1000 and ~150 bytes per record that's at
// most ~150 KB.
func (l *deletionLog) Recent(n int) ([]DeletionRecord, error) {
	if l == nil || l.path == "" || n <= 0 {
		return nil, nil
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	f, err := os.Open(l.path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	defer func() { _ = f.Close() }()

	var all []DeletionRecord
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}
		var rec DeletionRecord
		if err := json.Unmarshal(line, &rec); err != nil {
			// Tolerate corrupt entries (e.g. partial write); skip them.
			continue
		}
		all = append(all, rec)
	}
	if err := scanner.Err(); err != nil && err != io.ErrUnexpectedEOF {
		return nil, err
	}

	// Newest first.
	out := make([]DeletionRecord, 0, n)
	for i := len(all) - 1; i >= 0 && len(out) < n; i-- {
		out = append(out, all[i])
	}
	return out, nil
}

// trim rewrites the log to its last maxLines entries when it grows past
// 2*maxLines. Caller holds l.mu.
func (l *deletionLog) trim() error {
	if l.maxLines <= 0 {
		return nil
	}

	f, err := os.Open(l.path)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()

	count := 0
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for scanner.Scan() {
		count++
	}
	if scanner.Err() != nil {
		return scanner.Err()
	}
	if count <= 2*l.maxLines {
		return nil
	}

	// Re-open to read again, this time keeping only the tail.
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return err
	}

	keep := make([][]byte, 0, l.maxLines)
	scanner = bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for scanner.Scan() {
		// Keep a copy because Scanner reuses its buffer.
		line := append([]byte(nil), scanner.Bytes()...)
		keep = append(keep, line)
		if len(keep) > l.maxLines {
			keep = keep[1:]
		}
	}
	if scanner.Err() != nil {
		return scanner.Err()
	}

	tmp := l.path + ".tmp"
	out, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	w := bufio.NewWriter(out)
	for _, line := range keep {
		if _, err := w.Write(append(line, '\n')); err != nil {
			_ = out.Close()
			return err
		}
	}
	if err := w.Flush(); err != nil {
		_ = out.Close()
		return err
	}
	if err := out.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, l.path)
}
