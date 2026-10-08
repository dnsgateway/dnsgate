package keys_test

import (
	"context"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/dnsgateway/dnsgate/internal/keys"
)

func TestGenerateWritesOwnerOnlyPEMFilesNamedByKeyID(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "keys")

	gen, err := keys.Generate(dir, "2026-10")
	if err != nil {
		t.Fatal(err)
	}

	if gen.SigningKeyID != "sig-2026-10" || gen.EncryptionKeyID != "enc-2026-10" {
		t.Errorf("key IDs = %q, %q, want sig-2026-10, enc-2026-10", gen.SigningKeyID, gen.EncryptionKeyID)
	}

	want := []string{
		filepath.Join(dir, "sig-2026-10.pem"),
		filepath.Join(dir, "sig-2026-10.pub.pem"),
		filepath.Join(dir, "enc-2026-10.pem"),
		filepath.Join(dir, "enc-2026-10.pub.pem"),
	}

	if len(gen.Files) != len(want) {
		t.Fatalf("Files = %v, want %v", gen.Files, want)
	}

	for i, path := range want {
		if gen.Files[i] != path {
			t.Errorf("Files[%d] = %q, want %q", i, gen.Files[i], path)
		}

		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}

		if perm := info.Mode().Perm(); perm != 0o600 {
			t.Errorf("%s mode = %o, want 600", path, perm)
		}

		// Plain PEM without headers, so OpenSSL and other tools read it.
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}

		block, rest := pem.Decode(data)
		if block == nil || len(block.Headers) != 0 || len(rest) != 0 {
			t.Errorf("%s is not a single header-free PEM block", path)
		}
	}

	info, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}

	if perm := info.Mode().Perm(); perm != 0o700 {
		t.Errorf("key directory mode = %o, want 700", perm)
	}
}

func TestGenerateRefusesToOverwriteKeys(t *testing.T) {
	dir := t.TempDir()

	if _, err := keys.Generate(dir, "2026-10"); err != nil {
		t.Fatal(err)
	}

	before, err := os.ReadFile(filepath.Join(dir, "sig-2026-10.pem"))
	if err != nil {
		t.Fatal(err)
	}

	if _, err := keys.Generate(dir, "2026-10"); err == nil {
		t.Fatal("second Generate with the same key IDs succeeded, want an error")
	}

	after, err := os.ReadFile(filepath.Join(dir, "sig-2026-10.pem"))
	if err != nil {
		t.Fatal(err)
	}

	if string(before) != string(after) {
		t.Error("existing signing key was overwritten")
	}
}

func TestGenerateRejectsUnsafeSuffix(t *testing.T) {
	for _, suffix := range []string{"", "../x", "a/b", "a b"} {
		if _, err := keys.Generate(t.TempDir(), suffix); err == nil {
			t.Errorf("Generate(suffix %q) succeeded, want an error", suffix)
		}
	}
}

func TestLoadedKeysSignAndAgreeUnderTheirKeyIDs(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()

	if _, err := keys.Generate(dir, "2026-10"); err != nil {
		t.Fatal(err)
	}

	src, err := keys.LoadFiles(filepath.Join(dir, "sig-2026-10.pem"), filepath.Join(dir, "enc-2026-10.pem"))
	if err != nil {
		t.Fatal(err)
	}

	if got := src.SigningKeyID(); got != "sig-2026-10" {
		t.Errorf("SigningKeyID = %q, want sig-2026-10", got)
	}

	msg := []byte("claims")

	sig, err := src.Sign(ctx, msg)
	if err != nil {
		t.Fatal(err)
	}

	pub, err := src.VerificationKey("sig-2026-10")
	if err != nil {
		t.Fatal(err)
	}

	if !ed25519.Verify(pub, msg, sig) {
		t.Error("signature does not verify under the loaded verification key")
	}

	if _, err := src.VerificationKey("sig-other"); !errors.Is(err, keys.ErrUnknownKey) {
		t.Errorf("VerificationKey(unknown) error = %v, want ErrUnknownKey", err)
	}

	kid, encPub := src.EncryptionKey()
	if kid != "enc-2026-10" {
		t.Errorf("EncryptionKey kid = %q, want enc-2026-10", kid)
	}

	eph, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	want, err := eph.ECDH(encPub)
	if err != nil {
		t.Fatal(err)
	}

	got, err := src.SharedSecret(ctx, "enc-2026-10", eph.PublicKey())
	if err != nil {
		t.Fatal(err)
	}

	if string(got) != string(want) {
		t.Error("SharedSecret differs from the ephemeral side's ECDH result")
	}

	if _, err := src.SharedSecret(ctx, "enc-other", eph.PublicKey()); !errors.Is(err, keys.ErrUnknownKey) {
		t.Errorf("SharedSecret(unknown) error = %v, want ErrUnknownKey", err)
	}
}

func TestLoadFilesRejectsLooseOrSwappedKeys(t *testing.T) {
	dir := t.TempDir()

	if _, err := keys.Generate(dir, "2026-10"); err != nil {
		t.Fatal(err)
	}

	sig := filepath.Join(dir, "sig-2026-10.pem")
	enc := filepath.Join(dir, "enc-2026-10.pem")

	if _, err := keys.LoadFiles(enc, sig); err == nil {
		t.Error("LoadFiles with swapped key files succeeded, want an error")
	}

	if _, err := keys.LoadFiles(filepath.Join(dir, "missing.pem"), enc); err == nil {
		t.Error("LoadFiles with a missing key file succeeded, want an error")
	}

	if err := os.Chmod(sig, 0o644); err != nil {
		t.Fatal(err)
	}

	if _, err := keys.LoadFiles(sig, enc); err == nil {
		t.Error("LoadFiles with a group/world-readable signing key succeeded, want an error")
	}
}
