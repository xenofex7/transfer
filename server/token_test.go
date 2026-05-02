package server

import (
	"strings"
	"testing"
)

func TestTokenLength(t *testing.T) {
	for _, n := range []int{1, 6, 10, 32, 128} {
		if got := len(token(n)); got != n {
			t.Errorf("token(%d): got length %d, want %d", n, got, n)
		}
	}
}

func TestTokenAlphabet(t *testing.T) {
	tok := token(256)
	for _, r := range tok {
		if !strings.ContainsRune(SYMBOLS, r) {
			t.Fatalf("token contains unexpected character %q", r)
		}
	}
}

func TestTokenRandomness(t *testing.T) {
	// Two consecutive 32-char tokens being identical would imply a broken
	// PRNG seed. The probability of a true collision over a 62-character
	// alphabet at length 32 is ~62^-32, so this is a fine smoke test.
	a := token(32)
	b := token(32)
	if a == b {
		t.Fatalf("two consecutive tokens are identical: %q", a)
	}
}

func BenchmarkTokenConcat(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_ = token(5) + token(5)
	}
}

func BenchmarkTokenLonger(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_ = token(10)
	}
}
