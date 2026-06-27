package edwards25519

import (
	"crypto/rand"
	"math/big"
	"testing"
)

// secFixMalleabilityOrder is the group order L.
var secFixMalleabilityOrder, _ = new(big.Int).SetString(
	"7237005577332262213973186563042994240857116359379907606001950938285454250989", 10)

// secFixMalleabilityReverse reverses a byte slice (LE <-> BE conversion helper).
func secFixMalleabilityReverse(in []byte) []byte {
	out := make([]byte, len(in))
	for i := range in {
		out[len(in)-1-i] = in[i]
	}
	return out
}

// TestSecFixMalleability verifies that adding the group order L to the scalar S
// of a valid signature produces a non-canonical signature that Verify rejects,
// while the original signature still verifies.
func TestSecFixMalleability(t *testing.T) {
	pub, priv, err := GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	msg := []byte("malleability regression message")
	sig := Sign(priv, msg)

	if !Verify(pub, msg, sig) {
		t.Fatal("legitimate signature failed to verify")
	}

	// Interpret S = sig[32:64] as a little-endian integer and compute S+L.
	sBE := secFixMalleabilityReverse(sig[32:64])
	s := new(big.Int).SetBytes(sBE)
	sPlusL := new(big.Int).Add(s, secFixMalleabilityOrder)

	// S+L must still fit in 32 bytes for this test to be meaningful.
	if sPlusL.BitLen() > 256 {
		t.Fatalf("S+L overflows 32 bytes (%d bits); regenerate", sPlusL.BitLen())
	}

	// Re-encode S+L as 32 little-endian bytes.
	be := sPlusL.Bytes() // big-endian, no leading zeros
	if len(be) > 32 {
		t.Fatalf("S+L encodes to %d bytes", len(be))
	}
	padded := make([]byte, 32)
	copy(padded[32-len(be):], be)
	leSPlusL := secFixMalleabilityReverse(padded)

	var malleated [SignatureSize]byte
	copy(malleated[:32], sig[:32])
	copy(malleated[32:], leSPlusL)

	// The malleated signature must differ from the original.
	same := true
	for i := range malleated {
		if malleated[i] != sig[i] {
			same = false
			break
		}
	}
	if same {
		t.Fatal("malleated signature bytes did not change")
	}

	if Verify(pub, msg, &malleated) {
		t.Fatal("malleated signature (S+L) was accepted; malleability not prevented")
	}

	// The original signature must still verify.
	if !Verify(pub, msg, sig) {
		t.Fatal("original signature no longer verifies after fix")
	}
}
