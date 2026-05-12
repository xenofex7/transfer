/*
The MIT License (MIT)

Copyright (c) 2026 xenofex7
*/

package server

import (
	"errors"
	"log"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/pquerna/otp/totp"
)

// newTestServerWithUser returns a Server wired up with a meta store
// and a single user. Use it for the TOTP enrolment / verification
// paths so we exercise the same code the real handlers will hit.
func newTestServerWithUser(t *testing.T, name, password string) *Server {
	t.Helper()
	dir := t.TempDir()
	htp := filepath.Join(dir, "htpasswd")
	s := &Server{
		authHtpasswd: htp,
		logger:       log.New(os.Stderr, "test ", 0),
	}
	meta, err := newUserMetaStore(metaPathFor(htp))
	if err != nil {
		t.Fatalf("meta: %v", err)
	}
	s.userMeta = meta
	s.users = newUserStore(htp, s.reloadHtpasswdFile, func(n string) error {
		return s.userMeta.Delete(n)
	})
	if err := s.users.Add(name, password); err != nil {
		t.Fatalf("add user: %v", err)
	}
	return s
}

func currentTOTPCode(t *testing.T, secret string) string {
	t.Helper()
	code, err := totp.GenerateCode(secret, time.Now().UTC())
	if err != nil {
		t.Fatalf("generate code: %v", err)
	}
	return code
}

func TestStartTOTPEnrollment(t *testing.T) {
	s := newTestServerWithUser(t, "alice", "longenoughpw")
	enr, err := s.startTOTPEnrollment("alice")
	if err != nil {
		t.Fatalf("start: %v", err)
	}
	if enr.Secret == "" || !strings.HasPrefix(enr.URL, "otpauth://") {
		t.Fatalf("bad enrolment: %+v", enr)
	}
	if !strings.Contains(enr.URL, "alice") || !strings.Contains(enr.URL, "transfer.sh") {
		t.Fatalf("URL missing issuer/account: %s", enr.URL)
	}
	// Starting enrolment should NOT touch the meta store; the secret
	// only lands there after the user verifies a code.
	if s.userMeta.Has("alice") {
		t.Fatal("startTOTPEnrollment must not persist anything")
	}
}

func TestFinishTOTPEnrollment(t *testing.T) {
	s := newTestServerWithUser(t, "alice", "longenoughpw")
	enr, err := s.startTOTPEnrollment("alice")
	if err != nil {
		t.Fatal(err)
	}
	code := currentTOTPCode(t, enr.Secret)

	codes, err := s.finishTOTPEnrollment("alice", enr.Secret, code)
	if err != nil {
		t.Fatalf("finish: %v", err)
	}
	if len(codes) != recoveryCodeCount {
		t.Fatalf("expected %d recovery codes, got %d", recoveryCodeCount, len(codes))
	}
	for _, c := range codes {
		if len(c) != 19 || strings.Count(c, "-") != 3 {
			t.Fatalf("recovery code malformed: %q", c)
		}
	}

	m, ok := s.userMeta.Get("alice")
	if !ok || !m.TOTPEnabled || m.TOTPSecret != enr.Secret || len(m.RecoveryHashes) != recoveryCodeCount {
		t.Fatalf("meta not persisted: %+v ok=%v", m, ok)
	}
	// Recovery codes must be stored hashed, not cleartext.
	for _, h := range m.RecoveryHashes {
		for _, c := range codes {
			if h == c {
				t.Fatal("recovery code stored as cleartext")
			}
		}
	}
}

func TestFinishTOTPEnrollmentRejectsWrongCode(t *testing.T) {
	s := newTestServerWithUser(t, "alice", "longenoughpw")
	enr, _ := s.startTOTPEnrollment("alice")
	if _, err := s.finishTOTPEnrollment("alice", enr.Secret, "000000"); !errors.Is(err, errTOTPInvalidCode) {
		t.Fatalf("expected errTOTPInvalidCode, got %v", err)
	}
	// Failed finish must leave the user un-enrolled.
	if m, ok := s.userMeta.Get("alice"); ok && m.TOTPEnabled {
		t.Fatal("failed finish should not enable TOTP")
	}
}

func TestStartTOTPEnrollmentRejectsAlreadyEnrolled(t *testing.T) {
	s := newTestServerWithUser(t, "alice", "longenoughpw")
	enr, _ := s.startTOTPEnrollment("alice")
	if _, err := s.finishTOTPEnrollment("alice", enr.Secret, currentTOTPCode(t, enr.Secret)); err != nil {
		t.Fatal(err)
	}
	if _, err := s.startTOTPEnrollment("alice"); !errors.Is(err, errTOTPAlreadyEnrolled) {
		t.Fatalf("expected errTOTPAlreadyEnrolled, got %v", err)
	}
}

func TestVerifyUserTOTP(t *testing.T) {
	s := newTestServerWithUser(t, "alice", "longenoughpw")
	enr, _ := s.startTOTPEnrollment("alice")
	if _, err := s.finishTOTPEnrollment("alice", enr.Secret, currentTOTPCode(t, enr.Secret)); err != nil {
		t.Fatal(err)
	}

	if err := s.verifyUserTOTP("alice", currentTOTPCode(t, enr.Secret)); err != nil {
		t.Fatalf("current code should verify: %v", err)
	}
	if err := s.verifyUserTOTP("alice", "000000"); !errors.Is(err, errTOTPInvalidCode) {
		t.Fatalf("wrong code should fail: %v", err)
	}
	if err := s.verifyUserTOTP("bob", "anything"); !errors.Is(err, errTOTPNotEnrolled) {
		t.Fatalf("unknown user should report not enrolled: %v", err)
	}
}

func TestDisableTOTP(t *testing.T) {
	s := newTestServerWithUser(t, "alice", "longenoughpw")
	enr, _ := s.startTOTPEnrollment("alice")
	if _, err := s.finishTOTPEnrollment("alice", enr.Secret, currentTOTPCode(t, enr.Secret)); err != nil {
		t.Fatal(err)
	}
	if err := s.disableTOTP("alice"); err != nil {
		t.Fatal(err)
	}
	m, _ := s.userMeta.Get("alice")
	if m.TOTPEnabled || m.TOTPSecret != "" || len(m.RecoveryHashes) != 0 {
		t.Fatalf("disable should wipe TOTP state: %+v", m)
	}
	if err := s.disableTOTP("alice"); !errors.Is(err, errTOTPNotEnrolled) {
		t.Fatalf("second disable should report not enrolled: %v", err)
	}
}

func TestConsumeRecoveryCode(t *testing.T) {
	s := newTestServerWithUser(t, "alice", "longenoughpw")
	enr, _ := s.startTOTPEnrollment("alice")
	codes, err := s.finishTOTPEnrollment("alice", enr.Secret, currentTOTPCode(t, enr.Secret))
	if err != nil {
		t.Fatal(err)
	}

	// First consume succeeds.
	if err := s.consumeRecoveryCode("alice", codes[0]); err != nil {
		t.Fatalf("first consume: %v", err)
	}
	// Same code must not work twice.
	if err := s.consumeRecoveryCode("alice", codes[0]); !errors.Is(err, errRecoveryInvalidCode) {
		t.Fatalf("reuse should fail, got %v", err)
	}
	// Lower-case and spaced variants normalise to the same code.
	if err := s.consumeRecoveryCode("alice", " "+strings.ToLower(codes[1])+" "); err != nil {
		t.Fatalf("lowercase/spaced should still work: %v", err)
	}
	// Garbage fails.
	if err := s.consumeRecoveryCode("alice", "AAAA-BBBB-CCCC-DDDD"); !errors.Is(err, errRecoveryInvalidCode) {
		t.Fatalf("random code should fail, got %v", err)
	}
	// Two consumed, eight left.
	m, _ := s.userMeta.Get("alice")
	if len(m.RecoveryHashes) != recoveryCodeCount-2 {
		t.Fatalf("expected %d remaining, got %d", recoveryCodeCount-2, len(m.RecoveryHashes))
	}
}

func TestRegenerateRecoveryCodes(t *testing.T) {
	s := newTestServerWithUser(t, "alice", "longenoughpw")
	enr, _ := s.startTOTPEnrollment("alice")
	original, err := s.finishTOTPEnrollment("alice", enr.Secret, currentTOTPCode(t, enr.Secret))
	if err != nil {
		t.Fatal(err)
	}

	fresh, err := s.regenerateRecoveryCodes("alice")
	if err != nil {
		t.Fatal(err)
	}
	if len(fresh) != recoveryCodeCount {
		t.Fatalf("expected %d codes, got %d", recoveryCodeCount, len(fresh))
	}
	// Old codes must no longer work.
	if err := s.consumeRecoveryCode("alice", original[0]); !errors.Is(err, errRecoveryInvalidCode) {
		t.Fatalf("regen should invalidate old codes, got %v", err)
	}
	if err := s.consumeRecoveryCode("alice", fresh[0]); err != nil {
		t.Fatalf("new code should work: %v", err)
	}
}

func TestRegenerateRecoveryCodesRequiresEnrolled(t *testing.T) {
	s := newTestServerWithUser(t, "alice", "longenoughpw")
	if _, err := s.regenerateRecoveryCodes("alice"); !errors.Is(err, errTOTPNotEnrolled) {
		t.Fatalf("expected errTOTPNotEnrolled, got %v", err)
	}
}

func TestNormalizeRecoveryCode(t *testing.T) {
	cases := map[string]string{
		"AAAA-BBBB-CCCC-DDDD":   "AAAA-BBBB-CCCC-DDDD",
		"aaaa-bbbb-cccc-dddd":   "AAAA-BBBB-CCCC-DDDD",
		" AAAA BBBB CCCC DDDD ": "AAAA-BBBB-CCCC-DDDD",
		"AAAABBBBCCCCDDDD":      "AAAA-BBBB-CCCC-DDDD",
		"short":                 "",
		"":                      "",
	}
	for in, want := range cases {
		if got := normalizeRecoveryCode(in); got != want {
			t.Errorf("normalize(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestUserDeleteAlsoWipesTOTP(t *testing.T) {
	s := newTestServerWithUser(t, "alice", "longenoughpw")
	if err := s.users.Add("bob", "longenoughpw"); err != nil {
		t.Fatal(err)
	}
	enr, _ := s.startTOTPEnrollment("bob")
	if _, err := s.finishTOTPEnrollment("bob", enr.Secret, currentTOTPCode(t, enr.Secret)); err != nil {
		t.Fatal(err)
	}
	if err := s.users.Delete("bob", "alice"); err != nil {
		t.Fatal(err)
	}
	if s.userMeta.Has("bob") {
		t.Fatal("bob's TOTP secret must be gone after user delete")
	}
}
