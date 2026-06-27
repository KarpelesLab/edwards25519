// Copyright 2026 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package extra25519

import (
	"bytes"
	"crypto/rand"
	"testing"
)

// SecFixExtraHighBitRoundTrip verifies FIX 1: RepresentativeToPublicKey must
// clear both high bits (254 and 255) before decoding. ScalarBaseMult emits a
// representative whose top two bits are always 0; callers randomize those bits
// for wire-indistinguishability. The decode must reconstruct the same public
// key regardless of the high-bit values. Before the fix, the bit-254 cases
// (high == 1 or 3) would fail roughly half the time.
func TestSecFixExtraHighBitRoundTrip(t *testing.T) {
	var publicKey, publicKey2, representative, privateKey [32]byte

	tested := 0
	for i := 0; i < 1000 && tested < 64; i++ {
		if _, err := rand.Read(privateKey[:]); err != nil {
			t.Fatalf("rand.Read failed: %v", err)
		}

		if !ScalarBaseMult(&publicKey, &representative, &privateKey) {
			// ScalarBaseMult fails for ~half of keys; skip those.
			continue
		}
		tested++

		// Genuine representatives never set the top two bits.
		if representative[31]&0xc0 != 0 {
			t.Fatalf("ScalarBaseMult emitted representative with high bits set: %#x", representative[31])
		}

		// Randomize the top two bits to each of the four possible values and
		// ensure the public key is reconstructed identically every time.
		for _, hi := range []byte{0, 1, 2, 3} {
			rep := representative
			rep[31] = (rep[31] & 0x3f) | (hi << 6)

			RepresentativeToPublicKey(&publicKey2, &rep)
			if !bytes.Equal(publicKey[:], publicKey2[:]) {
				t.Fatalf("high-bit randomization %d broke round-trip: want %x, got %x", hi, publicKey[:], publicKey2[:])
			}
		}
	}

	if tested == 0 {
		t.Fatal("no successful ScalarBaseMult keys were tested")
	}
}

// TestSecFixExtraNoInputMutation verifies that RepresentativeToPublicKey does
// not modify its input representative array (FIX 1 operates on a local copy).
func TestSecFixExtraNoInputMutation(t *testing.T) {
	var publicKey, representative, privateKey [32]byte

	for i := 0; i < 1000; i++ {
		if _, err := rand.Read(privateKey[:]); err != nil {
			t.Fatalf("rand.Read failed: %v", err)
		}
		if !ScalarBaseMult(&publicKey, &representative, &privateKey) {
			continue
		}

		// Set high bits to a non-zero value to make any in-place clearing
		// observable.
		representative[31] |= 0xc0

		before := representative

		RepresentativeToPublicKey(&publicKey, &representative)

		if !bytes.Equal(before[:], representative[:]) {
			t.Fatalf("RepresentativeToPublicKey mutated its input: before %x, after %x", before[:], representative[:])
		}
		return
	}

	t.Fatal("no successful ScalarBaseMult key found")
}
