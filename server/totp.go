/*
The MIT License (MIT)

Copyright (c) 2026 xenofex7
*/

package server

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base32"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
	"golang.org/x/crypto/bcrypt"
)

// TOTP and recovery-code parameters. The defaults match the authenticator
// apps in the wild (Google Authenticator, 1Password, Authy): 6 digits,
// SHA1, 30-second step. Don't change these without coordinating a user
// re-enrolment — installed apps cache the algorithm at enrolment time.
const (
	totpDigits     = otp.DigitsSix
	totpAlgorithm  = otp.AlgorithmSHA1
	totpPeriod     = uint(30)
	totpSecretSize = uint(20) // 160 bits, the RFC 6238 default
	totpSkew       = uint(1)  // accept +/- one step to cover clock drift

	recoveryCodeCount      = 10
	recoveryCodeBytes      = 8 // 16 hex chars, formatted as XXXX-XXXX-XXXX-XXXX
	recoveryCodeBcryptCost = 12
)

var (
	errTOTPNotEnrolled     = errors.New("TOTP is not enabled for this user")
	errTOTPAlreadyEnrolled = errors.New("TOTP is already enabled for this user")
	errTOTPInvalidCode     = errors.New("invalid TOTP code")
	errRecoveryInvalidCode = errors.New("invalid recovery code")
	errRecoveryExhausted   = errors.New("no recovery codes remaining")
)

// totpIssuer is what the user sees as the account label in their
// authenticator app. Kept as a var so tests and future branding can
// override it.
var totpIssuer = "transfer.sh"

// TOTPEnrollment is a pending TOTP setup: a fresh secret + the
// otpauth:// URL the UI renders as a QR code. The user scans it, types
// the first generated code into a verify form, and only then do we
// persist the secret as enabled. Keeping the unverified secret in the
// session (not the meta store) prevents half-finished setups from
// locking users out.
type TOTPEnrollment struct {
	Secret string
	URL    string
}

// startTOTPEnrollment creates a new secret/URL pair for username.
// Returns an error if username already has TOTP enabled — callers
// should disable first if they want to rotate.
func (s *Server) startTOTPEnrollment(username string) (TOTPEnrollment, error) {
	if s.userMeta == nil {
		return TOTPEnrollment{}, errUserMetaUnavailable
	}
	if m, ok := s.userMeta.Get(username); ok && m.TOTPEnabled {
		return TOTPEnrollment{}, errTOTPAlreadyEnrolled
	}
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      totpIssuer,
		AccountName: username,
		Period:      totpPeriod,
		SecretSize:  totpSecretSize,
		Digits:      totpDigits,
		Algorithm:   totpAlgorithm,
	})
	if err != nil {
		return TOTPEnrollment{}, fmt.Errorf("generate totp: %w", err)
	}
	return TOTPEnrollment{Secret: key.Secret(), URL: key.URL()}, nil
}

// finishTOTPEnrollment persists secret as username's TOTP factor once
// the user has proved possession by entering a matching code. Returns
// the freshly minted recovery codes — the only time the cleartext
// codes leave the server, so the caller must surface them to the user
// immediately.
func (s *Server) finishTOTPEnrollment(username, secret, code string) ([]string, error) {
	if s.userMeta == nil {
		return nil, errUserMetaUnavailable
	}
	if !verifyTOTP(secret, code) {
		return nil, errTOTPInvalidCode
	}
	codes, hashes, err := newRecoveryCodes(recoveryCodeCount)
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	err = s.userMeta.Update(username, func(m *userMeta) error {
		if m.TOTPEnabled {
			return errTOTPAlreadyEnrolled
		}
		m.TOTPSecret = secret
		m.TOTPEnabled = true
		m.TOTPEnabledAt = &now
		m.RecoveryHashes = hashes
		return nil
	})
	if err != nil {
		return nil, err
	}
	return codes, nil
}

// disableTOTP removes username's TOTP factor and recovery codes. The
// caller is expected to re-authenticate the user (password + valid
// code, or recovery code) before invoking this — the function itself
// does not gate that.
func (s *Server) disableTOTP(username string) error {
	if s.userMeta == nil {
		return errUserMetaUnavailable
	}
	return s.userMeta.Update(username, func(m *userMeta) error {
		if !m.TOTPEnabled {
			return errTOTPNotEnrolled
		}
		m.TOTPSecret = ""
		m.TOTPEnabled = false
		m.TOTPEnabledAt = nil
		m.RecoveryHashes = nil
		return nil
	})
}

// regenerateRecoveryCodes mints a fresh set of recovery codes for
// username, invalidating any previous unused ones. Used after a
// recovery-code login or by an explicit "regenerate" UI action so a
// leaked sheet stops working.
func (s *Server) regenerateRecoveryCodes(username string) ([]string, error) {
	if s.userMeta == nil {
		return nil, errUserMetaUnavailable
	}
	codes, hashes, err := newRecoveryCodes(recoveryCodeCount)
	if err != nil {
		return nil, err
	}
	err = s.userMeta.Update(username, func(m *userMeta) error {
		if !m.TOTPEnabled {
			return errTOTPNotEnrolled
		}
		m.RecoveryHashes = hashes
		return nil
	})
	if err != nil {
		return nil, err
	}
	return codes, nil
}

// verifyUserTOTP checks code against username's enabled TOTP secret.
// Returns errTOTPNotEnrolled if the user has no TOTP set up;
// errTOTPInvalidCode if the code is wrong or expired.
func (s *Server) verifyUserTOTP(username, code string) error {
	if s.userMeta == nil {
		return errUserMetaUnavailable
	}
	m, ok := s.userMeta.Get(username)
	if !ok || !m.TOTPEnabled {
		return errTOTPNotEnrolled
	}
	if !verifyTOTP(m.TOTPSecret, code) {
		return errTOTPInvalidCode
	}
	return nil
}

// consumeRecoveryCode walks username's stored hashes, removes the
// first one matching code, and persists the trimmed list. Returns
// errRecoveryInvalidCode on no match. Recovery codes are single-use by
// design; consuming one is how that's enforced.
func (s *Server) consumeRecoveryCode(username, code string) error {
	if s.userMeta == nil {
		return errUserMetaUnavailable
	}
	candidate := normalizeRecoveryCode(code)
	if candidate == "" {
		return errRecoveryInvalidCode
	}
	return s.userMeta.Update(username, func(m *userMeta) error {
		if !m.TOTPEnabled {
			return errTOTPNotEnrolled
		}
		if len(m.RecoveryHashes) == 0 {
			return errRecoveryExhausted
		}
		for i, hash := range m.RecoveryHashes {
			if err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(candidate)); err == nil {
				m.RecoveryHashes = append(m.RecoveryHashes[:i], m.RecoveryHashes[i+1:]...)
				return nil
			}
		}
		return errRecoveryInvalidCode
	})
}

// verifyTOTP is the algorithm-agnostic check used by both the login
// flow and the enrolment confirmation. Splitting it out keeps the
// pquerna/otp options in one place.
func verifyTOTP(secret, code string) bool {
	code = strings.TrimSpace(code)
	if code == "" || secret == "" {
		return false
	}
	ok, err := totp.ValidateCustom(code, secret, time.Now().UTC(), totp.ValidateOpts{
		Period:    totpPeriod,
		Skew:      totpSkew,
		Digits:    totpDigits,
		Algorithm: totpAlgorithm,
	})
	return err == nil && ok
}

// newRecoveryCodes returns count fresh codes (display form) plus their
// bcrypt hashes (storage form). Display form is XXXX-XXXX-XXXX-XXXX
// using base32 without padding — short enough to type, no ambiguous
// characters in the base32 alphabet, no need to worry about case
// since we normalise on consumption.
func newRecoveryCodes(count int) (display []string, hashes []string, err error) {
	display = make([]string, 0, count)
	hashes = make([]string, 0, count)
	for i := 0; i < count; i++ {
		raw := make([]byte, recoveryCodeBytes)
		if _, err := rand.Read(raw); err != nil {
			return nil, nil, err
		}
		code := formatRecoveryCode(raw)
		hash, err := bcrypt.GenerateFromPassword([]byte(code), recoveryCodeBcryptCost)
		if err != nil {
			return nil, nil, err
		}
		display = append(display, code)
		hashes = append(hashes, string(hash))
	}
	return display, hashes, nil
}

// formatRecoveryCode renders raw entropy as four base32 groups of four
// characters separated by dashes. Always uppercase so it's easy to
// read off paper.
func formatRecoveryCode(raw []byte) string {
	enc := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(raw)
	enc = strings.ToUpper(enc)
	// recoveryCodeBytes = 8 → 13 base32 chars; pad to 16 so we can
	// chunk into four groups of four for readability.
	for len(enc) < 16 {
		enc += "0"
	}
	enc = enc[:16]
	return enc[0:4] + "-" + enc[4:8] + "-" + enc[8:12] + "-" + enc[12:16]
}

// normalizeRecoveryCode strips whitespace and dashes and uppercases
// the result so users can type codes loosely. Returns "" if the
// cleaned form isn't the expected length.
func normalizeRecoveryCode(in string) string {
	cleaned := strings.Map(func(r rune) rune {
		switch {
		case r == ' ' || r == '-' || r == '\t':
			return -1
		case r >= 'a' && r <= 'z':
			return r - ('a' - 'A')
		default:
			return r
		}
	}, in)
	if len(cleaned) != 16 {
		return ""
	}
	// Reinsert dashes so the candidate matches what was hashed at
	// enrolment time. Using a small constant-time comparison here is
	// overkill (bcrypt itself is constant-time on the secret), but
	// cheap insurance against subtle.ConstantTimeCompare-style
	// regressions if anyone ever refactors this path.
	formatted := cleaned[0:4] + "-" + cleaned[4:8] + "-" + cleaned[8:12] + "-" + cleaned[12:16]
	if subtle.ConstantTimeEq(int32(len(formatted)), 19) != 1 {
		return ""
	}
	return formatted
}
