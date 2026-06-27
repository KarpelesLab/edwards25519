// Copyright (c) 2026 The KarpelesLab developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package edwards25519

import (
	"testing"
)

// secFixSigningScalar returns a valid in-range private scalar (big-endian,
// PrivScalarSize bytes) built from the given small value.
func secFixSigningScalar(v byte) []byte {
	s := make([]byte, PrivScalarSize)
	s[PrivScalarSize-1] = v
	return s
}

// SecFixSigning_NilPriv verifies that SignFromScalar returns an error (and does
// not panic) when given a nil private key (FIX 1).
func TestSecFixSigning_NilPriv(t *testing.T) {
	hash := make([]byte, 32)
	nonce := secFixSigningScalar(7)

	r, s, err := SignFromScalar(nil, nonce, hash)
	if err == nil {
		t.Fatalf("expected error for nil priv, got r=%v s=%v", r, s)
	}
}

// SecFixSigning_ZeroNonce verifies that SignFromScalar rejects an all-zero
// nonce, which would otherwise yield an identity R and leak the private
// scalar (FIX 1).
func TestSecFixSigning_ZeroNonce(t *testing.T) {
	priv, _, err := PrivKeyFromScalar(secFixSigningScalar(5))
	if err != nil {
		t.Fatalf("could not build private key: %v", err)
	}
	hash := make([]byte, 32)
	zeroNonce := make([]byte, PrivScalarSize) // all zero

	_, _, err = SignFromScalar(priv, zeroNonce, hash)
	if err == nil {
		t.Fatalf("expected error for all-zero nonce, got nil")
	}
}

// SecFixSigning_NilGroupPub verifies that SignThreshold returns an error (and
// does not panic) when given a nil group public key (FIX 2).
func TestSecFixSigning_NilGroupPub(t *testing.T) {
	priv, _, err := PrivKeyFromScalar(secFixSigningScalar(5))
	if err != nil {
		t.Fatalf("could not build private key: %v", err)
	}
	privNonce, pubNonce, err := PrivKeyFromScalar(secFixSigningScalar(9))
	if err != nil {
		t.Fatalf("could not build private nonce: %v", err)
	}
	hash := make([]byte, 32)

	r, s, err := SignThreshold(priv, nil, hash, privNonce, pubNonce)
	if err == nil {
		t.Fatalf("expected error for nil groupPub, got r=%v s=%v", r, s)
	}
}

// SecFixSigning_CombinePubkeysHappyPath verifies that the FIX 3b changes to
// combinePubkeys did not break the happy path: combining two valid generated
// pubkeys must still return a non-nil aggregate, and a single valid pubkey must
// still be returned.
func TestSecFixSigning_CombinePubkeysHappyPath(t *testing.T) {
	_, pub1, err := PrivKeyFromScalar(secFixSigningScalar(11))
	if err != nil {
		t.Fatalf("could not build pubkey 1: %v", err)
	}
	_, pub2, err := PrivKeyFromScalar(secFixSigningScalar(13))
	if err != nil {
		t.Fatalf("could not build pubkey 2: %v", err)
	}

	// Single valid key path.
	if got := combinePubkeys([]*PublicKey{pub1}); got == nil {
		t.Fatalf("combinePubkeys with one valid key returned nil")
	}

	// Two valid keys path.
	if got := combinePubkeys([]*PublicKey{pub1, pub2}); got == nil {
		t.Fatalf("combinePubkeys with two valid keys returned nil")
	}

	// Nil element must still be rejected.
	if got := combinePubkeys([]*PublicKey{nil}); got != nil {
		t.Fatalf("combinePubkeys with a nil single key returned non-nil")
	}
}
