/*
The MIT License (MIT)

Copyright (c) 2026 xenofex7
*/

package server

import (
	"bytes"
	"strings"
	"testing"
)

func TestBrandingStoreFallsBackToEmbedded(t *testing.T) {
	dir := t.TempDir()
	b, err := newBrandingStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	if got := b.LogoURL(); !strings.HasPrefix(got, "/images/logo.png") {
		t.Fatalf("expected embedded URL, got %s", got)
	}
	if got := b.FaviconURL(); !strings.HasPrefix(got, "/favicon.ico") {
		t.Fatalf("expected embedded favicon URL, got %s", got)
	}
}

func TestBrandingStoreSaveServesCustomURL(t *testing.T) {
	dir := t.TempDir()
	b, err := newBrandingStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := b.Save(BrandingLogo, ".png", bytes.NewReader([]byte("\x89PNG\r\n\x1a\nfake-but-small"))); err != nil {
		t.Fatal(err)
	}
	url := b.LogoURL()
	if !strings.HasPrefix(url, "/branding/logo?v=") {
		t.Fatalf("expected /branding/logo URL, got %s", url)
	}
}

func TestBrandingStoreReplacesPreviousExtension(t *testing.T) {
	dir := t.TempDir()
	b, err := newBrandingStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := b.Save(BrandingLogo, ".png", bytes.NewReader([]byte("first"))); err != nil {
		t.Fatal(err)
	}
	if err := b.Save(BrandingLogo, ".svg", bytes.NewReader([]byte("<svg/>"))); err != nil {
		t.Fatal(err)
	}
	got := b.Get(BrandingLogo)
	if got.contentType != "image/svg+xml" {
		t.Fatalf("expected svg content-type after replacement, got %s", got.contentType)
	}
}

func TestBrandingStoreRejectsBadExtension(t *testing.T) {
	dir := t.TempDir()
	b, _ := newBrandingStore(dir)
	if err := b.Save(BrandingLogo, ".exe", bytes.NewReader([]byte("nope"))); err == nil {
		t.Fatal("expected error for .exe upload")
	}
}

func TestBrandingStoreRejectsOversizeFile(t *testing.T) {
	dir := t.TempDir()
	b, _ := newBrandingStore(dir)
	big := bytes.Repeat([]byte("x"), MaxBrandingBytes+1)
	if err := b.Save(BrandingLogo, ".png", bytes.NewReader(big)); err == nil {
		t.Fatal("expected size error")
	}
	if got := b.LogoURL(); !strings.HasPrefix(got, "/images/logo.png") {
		t.Fatalf("expected fallback after rejected upload, got %s", got)
	}
}

func TestBrandingStoreDeleteRevertsToEmbedded(t *testing.T) {
	dir := t.TempDir()
	b, _ := newBrandingStore(dir)
	_ = b.Save(BrandingLogo, ".png", bytes.NewReader([]byte("data")))
	if !strings.HasPrefix(b.LogoURL(), "/branding/logo") {
		t.Fatal("setup: custom not active")
	}
	if err := b.Delete(BrandingLogo); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(b.LogoURL(), "/images/logo.png") {
		t.Fatalf("expected embedded fallback after delete, got %s", b.LogoURL())
	}
}
