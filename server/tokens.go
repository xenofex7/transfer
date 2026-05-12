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

	"golang.org/x/crypto/bcrypt"
)

// API tokens are credentials a user can present via HTTP Basic Auth in
// place of their password. The wire format is
//
//	tk_<id>.<secret>
//
// where <id> is a short public identifier we use to index into the
// user's token list (avoids bcrypt-comparing the secret against every
// stored token) and <secret> is the high-entropy part the user keeps
// confidential. Only the bcrypt hash of <secret> is stored on disk;
// <id> is stored in cleartext so we can show it in the UI.
const (
	apiTokenPrefix    = "tk_"
	apiTokenSeparator = "."
	apiTokenIDBytes   = 5  // 8 chars in base32
	apiTokenSecretLen = 30 // 30 random bytes ~ 48 base32 chars
	apiTokenMaxNameLen = 64
	apiTokenBcryptCost = 12
	apiTokenMaxPerUser = 32
)

var (
	errInvalidAPIToken      = errors.New("invalid API token format")
	errAPITokenNotFound     = errors.New("API token not found")
	errAPITokenExpired      = errors.New("API token expired")
	errAPITokenNameTooLong  = errors.New("API token name too long")
	errAPITokenTooMany      = fmt.Errorf("user already has the maximum of %d API tokens", apiTokenMaxPerUser)
	errAPITokenNameRequired = errors.New("API token name required")

	tokenEncoding = base32.StdEncoding.WithPadding(base32.NoPadding)
)

// looksLikeAPIToken reports whether a credential string is shaped like
// an API token. Used by the auth middleware to decide between the
// password code path and the token code path without doing a real
// validation up front. Requires non-empty ID and secret on either side
// of the separator, otherwise a bare "tk_." would route to the token
// path.
func looksLikeAPIToken(s string) bool {
	if !strings.HasPrefix(s, apiTokenPrefix) {
		return false
	}
	rest := strings.TrimPrefix(s, apiTokenPrefix)
	idx := strings.Index(rest, apiTokenSeparator)
	return idx > 0 && idx < len(rest)-1
}

// parseAPIToken splits a wire token into its public ID and secret
// components. Returns errInvalidAPIToken on any malformed input.
func parseAPIToken(s string) (id, secret string, err error) {
	if !strings.HasPrefix(s, apiTokenPrefix) {
		return "", "", errInvalidAPIToken
	}
	rest := strings.TrimPrefix(s, apiTokenPrefix)
	idx := strings.Index(rest, apiTokenSeparator)
	if idx <= 0 || idx == len(rest)-1 {
		return "", "", errInvalidAPIToken
	}
	return rest[:idx], rest[idx+1:], nil
}

// generateAPIToken produces a fresh (id, secret) pair using
// crypto/rand. Both are base32 strings without padding so they are
// safe in headers and easy to copy.
func generateAPIToken() (id, secret string, err error) {
	idBytes := make([]byte, apiTokenIDBytes)
	if _, err := rand.Read(idBytes); err != nil {
		return "", "", err
	}
	secretBytes := make([]byte, apiTokenSecretLen)
	if _, err := rand.Read(secretBytes); err != nil {
		return "", "", err
	}
	return strings.ToLower(tokenEncoding.EncodeToString(idBytes)),
		tokenEncoding.EncodeToString(secretBytes), nil
}

// formatAPIToken assembles the wire form a user copies into their
// client. Always pairs with parseAPIToken.
func formatAPIToken(id, secret string) string {
	return apiTokenPrefix + id + apiTokenSeparator + secret
}

// CreateAPIToken adds a new token for username and returns the wire
// representation exactly once. The secret is bcrypt-hashed before
// storage; there is no way to recover it later. expiresAt may be nil
// for tokens that don't expire.
func (s *userMetaStore) CreateAPIToken(username, tokenName string, expiresAt *time.Time) (wire string, created apiToken, err error) {
	tokenName = strings.TrimSpace(tokenName)
	if tokenName == "" {
		return "", apiToken{}, errAPITokenNameRequired
	}
	if len(tokenName) > apiTokenMaxNameLen {
		return "", apiToken{}, errAPITokenNameTooLong
	}

	id, secret, err := generateAPIToken()
	if err != nil {
		return "", apiToken{}, err
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(secret), apiTokenBcryptCost)
	if err != nil {
		return "", apiToken{}, err
	}

	now := time.Now().UTC()
	tok := apiToken{
		ID:        id,
		Name:      tokenName,
		Hash:      string(hash),
		CreatedAt: now,
		ExpiresAt: expiresAt,
	}

	err = s.Update(username, func(m *userMeta) error {
		if len(m.APITokens) >= apiTokenMaxPerUser {
			return errAPITokenTooMany
		}
		// IDs are random so a collision is astronomically unlikely, but
		// guard anyway since the cost is trivial.
		for _, existing := range m.APITokens {
			if existing.ID == id {
				return errors.New("token ID collision, retry")
			}
		}
		m.APITokens = append(m.APITokens, tok)
		return nil
	})
	if err != nil {
		return "", apiToken{}, err
	}
	return formatAPIToken(id, secret), tok, nil
}

// VerifyAPIToken looks up presented against username's tokens. Returns
// the matched token record on success (with the bcrypt hash zeroed out
// so callers don't accidentally log it). Returns errAPITokenExpired
// when the token is past its ExpiresAt, even if the secret matches.
func (s *userMetaStore) VerifyAPIToken(username, presented string) (apiToken, error) {
	id, secret, err := parseAPIToken(presented)
	if err != nil {
		return apiToken{}, err
	}
	m, ok := s.Get(username)
	if !ok {
		return apiToken{}, errAPITokenNotFound
	}
	for _, tok := range m.APITokens {
		// constant-time compare on the ID avoids leaking which IDs exist
		// via response timing even though IDs are not secret.
		if subtle.ConstantTimeCompare([]byte(tok.ID), []byte(id)) != 1 {
			continue
		}
		if err := bcrypt.CompareHashAndPassword([]byte(tok.Hash), []byte(secret)); err != nil {
			return apiToken{}, errAPITokenNotFound
		}
		if tok.ExpiresAt != nil && time.Now().After(*tok.ExpiresAt) {
			return apiToken{}, errAPITokenExpired
		}
		tok.Hash = ""
		return tok, nil
	}
	return apiToken{}, errAPITokenNotFound
}

// TouchAPIToken records a successful use of (username, id) by updating
// LastUsedAt. Best-effort: errors are returned for the caller to log
// but should never block the request.
func (s *userMetaStore) TouchAPIToken(username, id string) error {
	now := time.Now().UTC()
	return s.Update(username, func(m *userMeta) error {
		for i := range m.APITokens {
			if m.APITokens[i].ID == id {
				m.APITokens[i].LastUsedAt = &now
				return nil
			}
		}
		return errAPITokenNotFound
	})
}

// DeleteAPIToken removes the token identified by id from username's
// token list. Returns errAPITokenNotFound if no such token exists.
func (s *userMetaStore) DeleteAPIToken(username, id string) error {
	return s.Update(username, func(m *userMeta) error {
		for i, tok := range m.APITokens {
			if tok.ID == id {
				m.APITokens = append(m.APITokens[:i], m.APITokens[i+1:]...)
				return nil
			}
		}
		return errAPITokenNotFound
	})
}

// ListAPITokens returns username's tokens with the bcrypt hash stripped
// so they're safe to render in the UI. Order is creation order.
func (s *userMetaStore) ListAPITokens(username string) []apiToken {
	m, ok := s.Get(username)
	if !ok {
		return nil
	}
	out := make([]apiToken, len(m.APITokens))
	for i, tok := range m.APITokens {
		tok.Hash = ""
		out[i] = tok
	}
	return out
}
