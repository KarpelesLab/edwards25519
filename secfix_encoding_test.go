package edwards25519

import (
	"bytes"
	"math/big"
	"testing"
)

// SecFixEncodingShortInput verifies that a short (sub-32-byte) input is
// right-aligned big-endian for copyBytes, and big-endian then reversed to
// little-endian for bigIntToEncodedBytes, exactly as before the fix, and
// that it round-trips through encodedBytesToBigInt.
func TestSecFixEncodingShortInput(t *testing.T) {
	secFixIn := []byte{0x01, 0x02, 0x03}

	// copyBytes keeps big-endian, right-aligned: trailing 3 bytes set.
	secFixCB := copyBytes(secFixIn)
	var secFixWantCB [32]byte
	secFixWantCB[29] = 0x01
	secFixWantCB[30] = 0x02
	secFixWantCB[31] = 0x03
	if !bytes.Equal(secFixCB[:], secFixWantCB[:]) {
		t.Fatalf("copyBytes short input = %x, want %x", secFixCB[:], secFixWantCB[:])
	}

	// bigIntToEncodedBytes: big-endian right-aligned then reversed to
	// little-endian, so the low-order bytes land at the front.
	secFixBig := new(big.Int).SetBytes(secFixIn) // == 0x010203
	secFixEnc := bigIntToEncodedBytes(secFixBig)
	var secFixWantEnc [32]byte
	secFixWantEnc[0] = 0x03
	secFixWantEnc[1] = 0x02
	secFixWantEnc[2] = 0x01
	if !bytes.Equal(secFixEnc[:], secFixWantEnc[:]) {
		t.Fatalf("bigIntToEncodedBytes short input = %x, want %x", secFixEnc[:], secFixWantEnc[:])
	}

	// Round-trip back to the original value.
	secFixDec := encodedBytesToBigInt(secFixEnc)
	if secFixDec.Cmp(secFixBig) != 0 {
		t.Fatalf("round-trip short input = %s, want %s", secFixDec, secFixBig)
	}
}

// SecFixEncodingOverLength verifies the security fix: an over-length big.Int
// (33 bytes, 2^256 + 5) is now reduced mod 2^256 (low bytes kept) rather than
// silently keeping the high bytes. Decoding must yield 5.
func TestSecFixEncodingOverLength(t *testing.T) {
	secFixVal := new(big.Int).Lsh(big.NewInt(1), 256) // 2^256
	secFixVal.Add(secFixVal, big.NewInt(5))           // 2^256 + 5 (33 bytes)

	if len(secFixVal.Bytes()) != 33 {
		t.Fatalf("expected 33-byte input, got %d bytes", len(secFixVal.Bytes()))
	}

	secFixEnc := bigIntToEncodedBytes(secFixVal)
	secFixDec := encodedBytesToBigInt(secFixEnc)

	if secFixDec.Cmp(big.NewInt(5)) != 0 {
		t.Fatalf("over-length input decoded to %s, want 5 (value mod 2^256)", secFixDec)
	}

	// Sanity: equivalent to explicit mod 2^256.
	secFixMod := new(big.Int).Mod(secFixVal, new(big.Int).Lsh(big.NewInt(1), 256))
	if secFixDec.Cmp(secFixMod) != 0 {
		t.Fatalf("over-length decoded %s != mod 2^256 %s", secFixDec, secFixMod)
	}
}

// SecFixEncodingExact32 verifies a 32-byte exact input round-trips unchanged.
func TestSecFixEncodingExact32(t *testing.T) {
	var secFixRaw [32]byte
	for i := range secFixRaw {
		secFixRaw[i] = byte(i*7 + 1)
	}

	// big-endian value of the 32 bytes.
	secFixBig := new(big.Int).SetBytes(secFixRaw[:])
	secFixEnc := bigIntToEncodedBytes(secFixBig)
	secFixDec := encodedBytesToBigInt(secFixEnc)
	if secFixDec.Cmp(secFixBig) != 0 {
		t.Fatalf("exact-32 round-trip = %s, want %s", secFixDec, secFixBig)
	}

	// copyBytes on an exact-length slice is identity.
	secFixCB := copyBytes(secFixRaw[:])
	if !bytes.Equal(secFixCB[:], secFixRaw[:]) {
		t.Fatalf("copyBytes exact-32 = %x, want %x", secFixCB[:], secFixRaw[:])
	}
}
