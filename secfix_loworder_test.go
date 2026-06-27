// Copyright (c) 2025 The KarpelesLab developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package edwards25519

import (
	"bytes"
	"crypto/rand"
	"testing"
)

// TestSecFixLowOrderRejectsIdentity verifies that ParsePubKey rejects the
// identity point (0,1), which is a low-order torsion point and must not be
// accepted as an ECDH/aggregation public key.
func TestSecFixLowOrderRejectsIdentity(t *testing.T) {
	// Little-endian encoding of the identity point (0,1): 0x01 then 31 zeros.
	id := make([]byte, 32)
	id[0] = 1

	if _, err := ParsePubKey(id); err == nil {
		t.Fatal("ParsePubKey accepted the identity (low-order) point; expected an error")
	}
}

// TestSecFixLowOrderAcceptsNormalKey verifies that a legitimately generated
// public key still parses successfully after the low-order rejection was added.
func TestSecFixLowOrderAcceptsNormalKey(t *testing.T) {
	pub, _, err := GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}

	if _, err := ParsePubKey(pub[:]); err != nil {
		t.Fatalf("ParsePubKey rejected a normal generated key: %v", err)
	}
}

// TestSecFixLowOrderEncryptDecryptRoundTrip is a sanity check that the
// low-order rejection and the ciphertext-length fix did not break the
// ECDH-based Encrypt/Decrypt round-trip.
func TestSecFixLowOrderEncryptDecryptRoundTrip(t *testing.T) {
	priv, err := GeneratePrivateKey()
	if err != nil {
		t.Fatalf("GeneratePrivateKey failed: %v", err)
	}
	px, py := priv.Public()
	pub := NewPublicKey(px, py)
	if _, err := ParsePubKey(pub.Serialize()); err != nil {
		t.Fatalf("ParsePubKey rejected the generated public key: %v", err)
	}

	for _, msg := range [][]byte{
		[]byte(""),
		[]byte("short"),
		bytes.Repeat([]byte{0xAB}, 16),
		bytes.Repeat([]byte{0xCD}, 100),
	} {
		ct, err := Encrypt(pub, msg)
		if err != nil {
			t.Fatalf("Encrypt failed for len %d: %v", len(msg), err)
		}
		pt, err := Decrypt(priv, ct)
		if err != nil {
			t.Fatalf("Decrypt failed for len %d: %v", len(msg), err)
		}
		if !bytes.Equal(pt, msg) {
			t.Fatalf("round-trip mismatch for len %d: got %x want %x", len(msg), pt, msg)
		}
	}
}
