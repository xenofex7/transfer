/*
The MIT License (MIT)

Copyright (c) 2026 xenofex7
*/

package server

import (
	"os"
	"testing"

	"golang.org/x/crypto/bcrypt"
)

// TestMain lowers bcrypt costs across the suite so the race detector
// doesn't push runtime past go test's default 10-minute deadline. Cost
// 12 is the production value (see users.go, totp.go, tokens.go); cost
// 4 (bcrypt.MinCost) is still cryptographically valid for test
// fixtures — we never persist these hashes anywhere observable.
func TestMain(m *testing.M) {
	userBcryptCost = bcrypt.MinCost
	recoveryCodeBcryptCost = bcrypt.MinCost
	apiTokenBcryptCost = bcrypt.MinCost
	os.Exit(m.Run())
}
