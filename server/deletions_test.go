package server

import (
	"path/filepath"
	"testing"
	"time"
)

func newTestDeletionLog(t *testing.T) *deletionLog {
	t.Helper()
	return newDeletionLog(filepath.Join(t.TempDir(), ".deletions.jsonl"))
}

func TestDeletionLogAppendAndRecent(t *testing.T) {
	l := newTestDeletionLog(t)

	for i, name := range []string{"alpha.txt", "beta.txt", "gamma.txt"} {
		if err := l.Append(DeletionRecord{
			Token:     "TKN" + string('A'+rune(i)),
			Filename:  name,
			Downloads: i,
			User:      "alice",
		}); err != nil {
			t.Fatalf("append %s: %v", name, err)
		}
	}

	recent, err := l.Recent(10)
	if err != nil {
		t.Fatalf("Recent: %v", err)
	}
	if len(recent) != 3 {
		t.Fatalf("Recent: got %d, want 3", len(recent))
	}

	// Newest first.
	if recent[0].Filename != "gamma.txt" {
		t.Errorf("recent[0]: got %q, want gamma.txt", recent[0].Filename)
	}
	if recent[2].Filename != "alpha.txt" {
		t.Errorf("recent[2]: got %q, want alpha.txt", recent[2].Filename)
	}

	if recent[0].DeletedAt.IsZero() {
		t.Error("DeletedAt was not auto-stamped")
	}
}

func TestDeletionLogRecentEmpty(t *testing.T) {
	l := newTestDeletionLog(t)
	got, err := l.Recent(50)
	if err != nil {
		t.Fatalf("Recent on missing file: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("expected empty result, got %d", len(got))
	}
}

func TestDeletionLogIsNoopWhenPathEmpty(t *testing.T) {
	l := newDeletionLog("")
	if err := l.Append(DeletionRecord{Filename: "x"}); err != nil {
		t.Errorf("Append on empty path should be no-op, got %v", err)
	}
	if got, _ := l.Recent(10); got != nil {
		t.Error("Recent on empty path should be nil")
	}
}

func TestDeletionLogTrimsAtThreshold(t *testing.T) {
	l := newTestDeletionLog(t)
	l.maxLines = 5 // small threshold for the test

	// Append 14 entries; trim only kicks in past 2*maxLines (=10) so after
	// the 11th write we should drop down to maxLines (5) entries.
	for i := 0; i < 14; i++ {
		if err := l.Append(DeletionRecord{
			Filename:  "f.txt",
			Downloads: i,
			DeletedAt: time.Now().Add(time.Duration(i) * time.Millisecond),
		}); err != nil {
			t.Fatalf("append %d: %v", i, err)
		}
	}

	recent, err := l.Recent(100)
	if err != nil {
		t.Fatalf("Recent: %v", err)
	}
	if len(recent) > 2*l.maxLines {
		t.Errorf("expected <= %d records, got %d", 2*l.maxLines, len(recent))
	}
	if recent[0].Downloads != 13 {
		t.Errorf("newest entry should have Downloads=13, got %d", recent[0].Downloads)
	}
}
