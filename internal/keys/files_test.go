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
	"time"

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
	dir := filepath.Join(t.TempDir(), "keys")

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

func TestGenerateRefusesADirectoryOthersCanReach(t *testing.T) {
	dir := t.TempDir()

	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}

	if _, err := keys.Generate(dir, "2026-10"); err == nil {
		t.Fatal("Generate into a mode 755 directory succeeded, want an error")
	}

	if entries, _ := os.ReadDir(dir); len(entries) != 0 {
		t.Errorf("Generate left %d files in the refused directory", len(entries))
	}
}

func TestGenerateLeavesNoPartialKeySetOnFailure(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "keys")
	existing := filepath.Join(dir, "enc-2026-10.pub.pem")

	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}

	// The last file Generate writes is taken, so it fails after writing the
	// others.
	if err := os.WriteFile(existing, []byte("someone else's"), 0o600); err != nil {
		t.Fatal(err)
	}

	if _, err := keys.Generate(dir, "2026-10"); err == nil {
		t.Fatal("Generate succeeded over an existing key file, want an error")
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}

	if len(entries) != 1 || entries[0].Name() != "enc-2026-10.pub.pem" {
		t.Errorf("directory holds %v, want only the pre-existing file", entries)
	}

	if data, _ := os.ReadFile(existing); string(data) != "someone else's" {
		t.Error("pre-existing file was changed")
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
	dir := filepath.Join(t.TempDir(), "keys")

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

func TestLoadFilesRejectsMisnamedKeyFiles(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "keys")

	if _, err := keys.Generate(dir, "2026-10"); err != nil {
		t.Fatal(err)
	}

	sig := filepath.Join(dir, "sig-2026-10.pem")
	enc := filepath.Join(dir, "enc-2026-10.pem")

	copyKey := func(t *testing.T, from, name string) string {
		t.Helper()

		data, err := os.ReadFile(from)
		if err != nil {
			t.Fatal(err)
		}

		to := filepath.Join(dir, name)
		if err := os.WriteFile(to, data, 0o600); err != nil {
			t.Fatal(err)
		}

		return to
	}

	cases := map[string][2]string{
		"signing kid without prefix":       {copyKey(t, sig, "signing.pem"), enc},
		"signing kid with encryption form": {copyKey(t, sig, "enc-2026-09.pem"), enc},
		"signing kid with bad suffix":      {copyKey(t, sig, "sig-.hidden.pem"), enc},
		"encryption kid without prefix":    {sig, copyKey(t, enc, "2026-10.pem")},
		"encryption kid with signing form": {sig, copyKey(t, enc, "sig-2026-09.pem")},
	}

	for name, files := range cases {
		if _, err := keys.LoadFiles(files[0], files[1]); err == nil {
			t.Errorf("%s: LoadFiles(%s, %s) succeeded, want an error", name, files[0], files[1])
		}
	}
}

func TestLoadFilesRejectsLooseOrSwappedKeys(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "keys")

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

func TestDecryptionKeyAgreesUntilItsRetirementDeadline(t *testing.T) {
	ctx := context.Background()
	dir := filepath.Join(t.TempDir(), "keys")

	for _, suffix := range []string{"2026-10", "2026-11"} {
		if _, err := keys.Generate(dir, suffix); err != nil {
			t.Fatal(err)
		}
	}

	now := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	retireAt := now.Add(time.Hour)

	src, err := keys.LoadFiles(filepath.Join(dir, "sig-2026-10.pem"), filepath.Join(dir, "enc-2026-11.pem"),
		keys.WithDecryptionKey(filepath.Join(dir, "enc-2026-10.pem"), retireAt),
		keys.WithClock(func() time.Time { return now }))
	if err != nil {
		t.Fatal(err)
	}

	if kid, _ := src.EncryptionKey(); kid != "enc-2026-11" {
		t.Errorf("EncryptionKey kid = %q, want the current key enc-2026-11", kid)
	}

	eph, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := src.SharedSecret(ctx, "enc-2026-10", eph.PublicKey()); err != nil {
		t.Errorf("SharedSecret under the decryption key before its deadline: %v", err)
	}

	now = retireAt

	if _, err := src.SharedSecret(ctx, "enc-2026-10", eph.PublicKey()); !errors.Is(err, keys.ErrRetiredKey) {
		t.Errorf("SharedSecret under a retired key error = %v, want ErrRetiredKey", err)
	}

	if _, err := src.SharedSecret(ctx, "enc-2026-11", eph.PublicKey()); err != nil {
		t.Errorf("SharedSecret under the current key: %v", err)
	}
}

func TestLoadFilesRejectsBadDecryptionKeys(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "keys")

	for _, suffix := range []string{"2026-10", "2026-11"} {
		if _, err := keys.Generate(dir, suffix); err != nil {
			t.Fatal(err)
		}
	}

	sig := filepath.Join(dir, "sig-2026-10.pem")
	enc := filepath.Join(dir, "enc-2026-11.pem")
	old := filepath.Join(dir, "enc-2026-10.pem")
	retireAt := time.Now().Add(time.Hour)

	for name, path := range map[string]string{
		"the current key": enc,
		"a signing key":   filepath.Join(dir, "sig-2026-11.pem"),
		"a missing file":  filepath.Join(dir, "enc-missing.pem"),
		"a public key":    filepath.Join(dir, "enc-2026-10.pub.pem"),
	} {
		if _, err := keys.LoadFiles(sig, enc, keys.WithDecryptionKey(path, retireAt)); err == nil {
			t.Errorf("LoadFiles with %s as a decryption key succeeded, want an error", name)
		}
	}

	if _, err := keys.LoadFiles(sig, enc, keys.WithDecryptionKey(old, retireAt), keys.WithDecryptionKey(old, retireAt)); err == nil {
		t.Error("LoadFiles with the same decryption key twice succeeded, want an error")
	}

	if err := os.Chmod(old, 0o640); err != nil {
		t.Fatal(err)
	}

	if _, err := keys.LoadFiles(sig, enc, keys.WithDecryptionKey(old, retireAt)); err == nil {
		t.Error("LoadFiles with a group-readable decryption key succeeded, want an error")
	}
}
