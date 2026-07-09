package server

import (
	"encoding/json"
	"io"
	"log"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/mux"
)

func newTestSecretStore(t *testing.T) *secretStore {
	t.Helper()
	st, err := newSecretStore(filepath.Join(t.TempDir(), ".secrets"))
	if err != nil {
		t.Fatalf("newSecretStore: %v", err)
	}
	return st
}

func testRecord(ttl time.Duration) secretRecord {
	return secretRecord{
		Ciphertext: "Y2lwaGVydGV4dA==",
		CreatedAt:  time.Now(),
		ExpiresAt:  time.Now().Add(ttl),
	}
}

func TestSecretStoreTakeOnce(t *testing.T) {
	st := newTestSecretStore(t)

	if err := st.Create("abcdefgh42", testRecord(time.Hour)); err != nil {
		t.Fatalf("Create: %v", err)
	}
	if !st.Peek("abcdefgh42") {
		t.Fatal("Peek: expected secret to be available")
	}
	// Peek must not consume.
	if !st.Peek("abcdefgh42") {
		t.Fatal("Peek consumed the secret")
	}

	rec, err := st.Take("abcdefgh42")
	if err != nil {
		t.Fatalf("Take: %v", err)
	}
	if rec.Ciphertext != "Y2lwaGVydGV4dA==" {
		t.Errorf("Take: got ciphertext %q", rec.Ciphertext)
	}

	if st.Peek("abcdefgh42") {
		t.Error("Peek after Take: secret should be gone")
	}
	if _, err := st.Take("abcdefgh42"); err == nil {
		t.Error("second Take should fail")
	}
}

func TestSecretStoreExpiry(t *testing.T) {
	st := newTestSecretStore(t)

	if err := st.Create("expiredsecret1", testRecord(-time.Minute)); err != nil {
		t.Fatalf("Create: %v", err)
	}
	if st.Peek("expiredsecret1") {
		t.Error("Peek: expired secret should not be available")
	}
	if _, err := os.Stat(st.path("expiredsecret1")); !os.IsNotExist(err) {
		t.Error("expired secret file should have been removed lazily")
	}
}

func TestSecretStoreRejectsBadIDs(t *testing.T) {
	st := newTestSecretStore(t)

	for _, id := range []string{"", "short", "../../etc/passwd", "a/b", "id with space"} {
		if _, err := st.Take(id); err == nil {
			t.Errorf("Take(%q) should fail", id)
		}
	}
}

func TestSecretStorePurgeExpired(t *testing.T) {
	st := newTestSecretStore(t)

	if err := st.Create("freshsecret42", testRecord(time.Hour)); err != nil {
		t.Fatalf("Create: %v", err)
	}
	if err := st.Create("stalesecret42", testRecord(-time.Minute)); err != nil {
		t.Fatalf("Create: %v", err)
	}

	if err := st.PurgeExpired(); err != nil {
		t.Fatalf("PurgeExpired: %v", err)
	}

	if !st.Peek("freshsecret42") {
		t.Error("fresh secret should survive the purge")
	}
	if _, err := os.Stat(st.path("stalesecret42")); !os.IsNotExist(err) {
		t.Error("stale secret should be purged")
	}
}

func newSecretTestServer(t *testing.T) *Server {
	t.Helper()
	srvr, err := New(
		Logger(log.New(io.Discard, "", 0)),
		RandomTokenLength(10),
		SecretsDir(filepath.Join(t.TempDir(), ".secrets")),
	)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return srvr
}

func TestSecretCreateAndRevealFlow(t *testing.T) {
	srvr := newSecretTestServer(t)

	// Create.
	req := httptest.NewRequest("POST", "http://127.0.0.1/secret",
		strings.NewReader(`{"ciphertext":"Y2lwaGVydGV4dA=="}`))
	w := httptest.NewRecorder()
	srvr.secretCreateHandler(w, req)

	if w.Code != 200 {
		t.Fatalf("create: got status %d: %s", w.Code, w.Body.String())
	}
	var created struct{ ID, URL string }
	if err := json.NewDecoder(w.Body).Decode(&created); err != nil {
		t.Fatalf("create: decode response: %v", err)
	}
	if created.ID == "" || !strings.HasSuffix(created.URL, "/secret/"+created.ID) {
		t.Fatalf("create: unexpected response %+v", created)
	}

	// Reveal consumes.
	req = httptest.NewRequest("POST", "http://127.0.0.1/secret/"+created.ID+"/reveal", nil)
	req = mux.SetURLVars(req, map[string]string{"id": created.ID})
	w = httptest.NewRecorder()
	srvr.secretRevealHandler(w, req)

	if w.Code != 200 {
		t.Fatalf("reveal: got status %d", w.Code)
	}
	var revealed struct{ Ciphertext string }
	if err := json.NewDecoder(w.Body).Decode(&revealed); err != nil {
		t.Fatalf("reveal: decode response: %v", err)
	}
	if revealed.Ciphertext != "Y2lwaGVydGV4dA==" {
		t.Errorf("reveal: got ciphertext %q", revealed.Ciphertext)
	}

	// Second reveal is gone.
	req = httptest.NewRequest("POST", "http://127.0.0.1/secret/"+created.ID+"/reveal", nil)
	req = mux.SetURLVars(req, map[string]string{"id": created.ID})
	w = httptest.NewRecorder()
	srvr.secretRevealHandler(w, req)

	if w.Code != 404 {
		t.Errorf("second reveal: got status %d, want 404", w.Code)
	}
}

func TestSecretCreateRejectsBadInput(t *testing.T) {
	srvr := newSecretTestServer(t)

	cases := map[string]string{
		"empty ciphertext": `{"ciphertext":""}`,
		"not base64":       `{"ciphertext":"not/base64!!"}`,
		"not json":         `garbage`,
		"too large":        `{"ciphertext":"` + strings.Repeat("QUFB", maxSecretCiphertext/4+1) + `"}`,
	}
	for name, body := range cases {
		req := httptest.NewRequest("POST", "http://127.0.0.1/secret", strings.NewReader(body))
		w := httptest.NewRecorder()
		srvr.secretCreateHandler(w, req)
		if w.Code != 400 {
			t.Errorf("%s: got status %d, want 400", name, w.Code)
		}
	}
}

func TestSecretHandlersDisabledWithoutDir(t *testing.T) {
	srvr, err := New(
		Logger(log.New(io.Discard, "", 0)),
		RandomTokenLength(10),
	)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	req := httptest.NewRequest("POST", "http://127.0.0.1/secret",
		strings.NewReader(`{"ciphertext":"Y2lwaGVydGV4dA=="}`))
	w := httptest.NewRecorder()
	srvr.secretCreateHandler(w, req)
	if w.Code != 404 {
		t.Errorf("create on disabled feature: got status %d, want 404", w.Code)
	}
}
