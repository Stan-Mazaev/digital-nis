package crypto

import (
	"bytes"
	"testing"
)

func TestStreebog256_Length(t *testing.T) {
	g := NewGOSTProvider()
	h := g.Streebog256([]byte("test"))
	if len(h) != StreebogSize {
		t.Fatalf("Streebog256: got %d bytes, want %d", len(h), StreebogSize)
	}
}

func TestStreebog512_Length(t *testing.T) {
	g := NewGOSTProvider()
	h := g.Streebog512([]byte("test"))
	if len(h) != Streebog512Size {
		t.Fatalf("Streebog512: got %d bytes, want %d", len(h), Streebog512Size)
	}
}

func TestStreebog256_Deterministic(t *testing.T) {
	g := NewGOSTProvider()
	in := []byte("Цифровая НИС — тест детерминизма")
	h1 := g.Streebog256(in)
	h2 := g.Streebog256(in)
	if !bytes.Equal(h1, h2) {
		t.Fatal("Streebog256 not deterministic")
	}
}

func TestStreebog256_DifferentInputs(t *testing.T) {
	g := NewGOSTProvider()
	h1 := g.Streebog256([]byte("a"))
	h2 := g.Streebog256([]byte("b"))
	if bytes.Equal(h1, h2) {
		t.Fatal("different inputs produced identical hash")
	}
}

func TestStreebog256_EmptyInput(t *testing.T) {
	g := NewGOSTProvider()
	h := g.Streebog256(nil)
	if len(h) != StreebogSize {
		t.Fatalf("empty input: got %d bytes, want %d", len(h), StreebogSize)
	}
}

func TestGOST3410_SignVerify_Roundtrip(t *testing.T) {
	g := NewGOSTProvider()
	priv, pub, err := g.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	digest := g.Streebog256([]byte("hello NIS"))
	sig, err := g.SignGOST3410(priv, digest)
	if err != nil {
		t.Fatalf("SignGOST3410: %v", err)
	}
	if len(sig) != GOST3410SignatureSize {
		t.Fatalf("sig size = %d, want %d", len(sig), GOST3410SignatureSize)
	}
	ok, err := g.VerifyGOST3410(pub, digest, sig)
	if err != nil {
		t.Fatalf("VerifyGOST3410: %v", err)
	}
	if !ok {
		t.Fatal("valid signature rejected")
	}
}

func TestGOST3410_RejectTamperedDigest(t *testing.T) {
	g := NewGOSTProvider()
	priv, pub, _ := g.GenerateKeyPair()
	digest := g.Streebog256([]byte("hello NIS"))
	sig, _ := g.SignGOST3410(priv, digest)

	tampered := make([]byte, len(digest))
	copy(tampered, digest)
	tampered[0] ^= 0x01

	ok, err := g.VerifyGOST3410(pub, tampered, sig)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if ok {
		t.Fatal("tampered digest accepted")
	}
}

func TestGOST3410_RejectWrongKey(t *testing.T) {
	g := NewGOSTProvider()
	priv1, _, _ := g.GenerateKeyPair()
	_, pub2, _ := g.GenerateKeyPair()

	digest := g.Streebog256([]byte("hello NIS"))
	sig, _ := g.SignGOST3410(priv1, digest)

	ok, _ := g.VerifyGOST3410(pub2, digest, sig)
	if ok {
		t.Fatal("signature verified with wrong public key")
	}
}

func TestGOST3410_WrongDigestSize(t *testing.T) {
	g := NewGOSTProvider()
	priv, _, _ := g.GenerateKeyPair()
	if _, err := g.SignGOST3410(priv, []byte("short")); err == nil {
		t.Fatal("expected error for short digest")
	}
}

func TestGOST3410_WrongSignatureSize(t *testing.T) {
	g := NewGOSTProvider()
	_, pub, _ := g.GenerateKeyPair()
	digest := g.Streebog256([]byte("x"))
	if _, err := g.VerifyGOST3410(pub, digest, make([]byte, 10)); err == nil {
		t.Fatal("expected error for wrong signature size")
	}
}

func TestNewPrivateKeyFromRaw_WrongSize(t *testing.T) {
	g := NewGOSTProvider()
	if _, err := g.NewPrivateKeyFromRaw(make([]byte, 16)); err == nil {
		t.Fatal("expected error for wrong private key size")
	}
}

// ---------- MGM ----------

func TestRandomMGMNonce_Valid(t *testing.T) {
	for i := 0; i < 100; i++ {
		nonce, err := RandomMGMNonce()
		if err != nil {
			t.Fatalf("RandomMGMNonce: %v", err)
		}
		if len(nonce) != MGMNonceSize {
			t.Fatalf("nonce size = %d, want %d", len(nonce), MGMNonceSize)
		}
		if nonce[0]&0x80 != 0 {
			t.Fatalf("nonce top bit set: %#x", nonce[0])
		}
	}
}

func TestMGM_SealOpen_Roundtrip(t *testing.T) {
	g := NewGOSTProvider()
	key, _ := RandomBytes(KuznechikKeySize)
	nonce, _ := RandomMGMNonce()
	plaintext := []byte("Перевод 4 850 000 руб. на эскроу-счёт ПИК")
	aad := []byte("dealID=DEAL-001")

	ct, err := g.SealMGM(key, nonce, plaintext, aad)
	if err != nil {
		t.Fatalf("SealMGM: %v", err)
	}
	if bytes.Equal(ct, plaintext) {
		t.Fatal("ciphertext equals plaintext")
	}

	pt, err := g.OpenMGM(key, nonce, ct, aad)
	if err != nil {
		t.Fatalf("OpenMGM: %v", err)
	}
	if !bytes.Equal(pt, plaintext) {
		t.Fatalf("roundtrip mismatch:\n got: %q\nwant: %q", pt, plaintext)
	}
}

func TestMGM_RejectTamperedCiphertext(t *testing.T) {
	g := NewGOSTProvider()
	key, _ := RandomBytes(KuznechikKeySize)
	nonce, _ := RandomMGMNonce()
	pt := []byte("payload")
	aad := []byte("aad")

	ct, err := g.SealMGM(key, nonce, pt, aad)
	if err != nil {
		t.Fatalf("SealMGM: %v", err)
	}
	if len(ct) == 0 {
		t.Fatal("empty ciphertext")
	}
	ct[0] ^= 0x01

	if _, err := g.OpenMGM(key, nonce, ct, aad); err == nil {
		t.Fatal("tampered ciphertext accepted")
	}
}

func TestMGM_RejectWrongAAD(t *testing.T) {
	g := NewGOSTProvider()
	key, _ := RandomBytes(KuznechikKeySize)
	nonce, _ := RandomMGMNonce()
	pt := []byte("payload")

	ct, err := g.SealMGM(key, nonce, pt, []byte("aad-1"))
	if err != nil {
		t.Fatalf("SealMGM: %v", err)
	}
	if _, err := g.OpenMGM(key, nonce, ct, []byte("aad-2")); err == nil {
		t.Fatal("wrong AAD accepted")
	}
}

func TestMGM_RejectWrongNonce(t *testing.T) {
	g := NewGOSTProvider()
	key, _ := RandomBytes(KuznechikKeySize)
	nonce, _ := RandomMGMNonce()
	pt := []byte("payload")

	ct, err := g.SealMGM(key, nonce, pt, nil)
	if err != nil {
		t.Fatalf("SealMGM: %v", err)
	}

	// Другой валидный nonce.
	badNonce, _ := RandomMGMNonce()
	if _, err := g.OpenMGM(key, badNonce, ct, nil); err == nil {
		t.Fatal("wrong nonce accepted")
	}
}

func TestSealMGM_WrongKeySize(t *testing.T) {
	g := NewGOSTProvider()
	nonce, _ := RandomMGMNonce()
	_, err := g.SealMGM(make([]byte, 16), nonce, []byte("x"), nil)
	if err == nil {
		t.Fatal("expected error for wrong key size")
	}
}

func TestSealMGM_WrongNonceSize(t *testing.T) {
	g := NewGOSTProvider()
	key, _ := RandomBytes(KuznechikKeySize)
	_, err := g.SealMGM(key, make([]byte, 4), []byte("x"), nil)
	if err == nil {
		t.Fatal("expected error for wrong nonce size")
	}
}

func TestSealMGM_NonceTopBitSet(t *testing.T) {
	g := NewGOSTProvider()
	key, _ := RandomBytes(KuznechikKeySize)
	nonce, _ := RandomMGMNonce()
	nonce[0] |= 0x80 // Выставляем старший бит.
	_, err := g.SealMGM(key, nonce, []byte("x"), nil)
	if err == nil {
		t.Fatal("expected error for nonce with top bit set")
	}
}