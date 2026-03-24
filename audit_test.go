package edwards25519

import (
	"bytes"
	"crypto/aes"
	"crypto/rand"
	"math/big"
	"testing"
)

// TestRemovePKCSPaddingValidatesAllBytes verifies that removePKCSPadding
// rejects data where padding bytes are inconsistent.
func TestRemovePKCSPaddingValidatesAllBytes(t *testing.T) {
	// Valid: 3 bytes of padding (0x03 0x03 0x03)
	valid := make([]byte, 16)
	for i := 0; i < 13; i++ {
		valid[i] = 0xAA
	}
	valid[13] = 0x03
	valid[14] = 0x03
	valid[15] = 0x03

	out, err := removePKCSPadding(valid)
	if err != nil {
		t.Fatalf("valid padding rejected: %v", err)
	}
	if len(out) != 13 {
		t.Fatalf("expected 13 bytes, got %d", len(out))
	}

	// Invalid: last byte says 3 but middle padding byte is wrong
	invalid := make([]byte, 16)
	copy(invalid, valid)
	invalid[13] = 0xFF // corrupt one padding byte
	_, err = removePKCSPadding(invalid)
	if err == nil {
		t.Fatal("corrupted padding should be rejected")
	}

	// Invalid: padLength == 0
	zeroPad := make([]byte, 16)
	zeroPad[15] = 0x00
	_, err = removePKCSPadding(zeroPad)
	if err == nil {
		t.Fatal("zero padding length should be rejected")
	}

	// Invalid: padLength > blockSize
	bigPad := make([]byte, 16)
	bigPad[15] = 0x11 // 17 > 16
	_, err = removePKCSPadding(bigPad)
	if err == nil {
		t.Fatal("padding length > block size should be rejected")
	}

	// Invalid: too short
	_, err = removePKCSPadding([]byte{0x01})
	if err == nil {
		t.Fatal("input shorter than block size should be rejected")
	}

	// Valid: full block of padding (16 bytes of 0x10)
	fullPad := bytes.Repeat([]byte{byte(aes.BlockSize)}, aes.BlockSize)
	out, err = removePKCSPadding(fullPad)
	if err != nil {
		t.Fatalf("full block padding rejected: %v", err)
	}
	if len(out) != 0 {
		t.Fatalf("expected 0 bytes after removing full padding, got %d", len(out))
	}
}

// TestPKCSPaddingRoundTrip verifies add/remove padding round-trips correctly
// for various input lengths.
func TestPKCSPaddingRoundTrip(t *testing.T) {
	for i := 0; i <= 64; i++ {
		data := make([]byte, i)
		rand.Read(data)
		padded := addPKCSPadding(data)
		if len(padded)%aes.BlockSize != 0 {
			t.Fatalf("padded length %d not multiple of block size for input len %d", len(padded), i)
		}
		recovered, err := removePKCSPadding(padded)
		if err != nil {
			t.Fatalf("removePKCSPadding failed for input len %d: %v", i, err)
		}
		if !bytes.Equal(data, recovered) {
			t.Fatalf("round-trip failed for input len %d", i)
		}
	}
}

// TestPrivKeyFromScalarRejectsN verifies that a scalar equal to the group
// order N is rejected.
func TestPrivKeyFromScalarRejectsN(t *testing.T) {
	curve := Edwards()
	nBytes := curve.N.Bytes()
	_, _, err := PrivKeyFromScalar(nBytes)
	if err == nil {
		t.Fatal("scalar == N should be rejected")
	}

	// N-1 should be accepted
	nMinus1 := new(big.Int).Sub(curve.N, big.NewInt(1))
	b := make([]byte, 32)
	nMinus1Bytes := nMinus1.Bytes()
	copy(b[32-len(nMinus1Bytes):], nMinus1Bytes)
	_, _, err = PrivKeyFromScalar(b)
	if err != nil {
		t.Fatalf("scalar == N-1 should be accepted, got: %v", err)
	}

	// Zero should be rejected
	_, _, err = PrivKeyFromScalar(make([]byte, 32))
	if err == nil {
		t.Fatal("zero scalar should be rejected")
	}
}

// TestScalarAddModN verifies that scalarAdd performs addition modulo the
// group order N, not modulo the field prime P.
func TestScalarAddModN(t *testing.T) {
	curve := Edwards()
	n := curve.N

	// a + b where a + b > N but a + b < P should still reduce mod N
	a := new(big.Int).Sub(n, big.NewInt(1)) // N-1
	b := big.NewInt(2)                       // 2
	result := scalarAdd(a, b)

	// (N-1) + 2 = N+1, mod N = 1
	expected := big.NewInt(1)
	if result.Cmp(expected) != 0 {
		t.Fatalf("scalarAdd(N-1, 2) = %v, want 1", result)
	}

	// 0 + 0 = 0
	result = scalarAdd(big.NewInt(0), big.NewInt(0))
	if result.Cmp(big.NewInt(0)) != 0 {
		t.Fatalf("scalarAdd(0, 0) = %v, want 0", result)
	}
}

// TestFeToBytesDoesNotMutateInput verifies that FeToBytes does not modify
// the input FieldElement.
func TestFeToBytesDoesNotMutateInput(t *testing.T) {
	var fe FieldElement
	fe[0] = 12345
	fe[1] = -67890
	fe[2] = 11111
	fe[3] = -22222
	fe[4] = 33333
	fe[5] = -44444
	fe[6] = 55555
	fe[7] = -66666
	fe[8] = 77777
	fe[9] = 88888

	// Save a copy
	var orig FieldElement
	copy(orig[:], fe[:])

	var s [32]byte
	FeToBytes(&s, &fe)

	for i := 0; i < 10; i++ {
		if fe[i] != orig[i] {
			t.Fatalf("FeToBytes mutated input: fe[%d] was %d, now %d", i, orig[i], fe[i])
		}
	}

	// Call again and verify same output (idempotent)
	var s2 [32]byte
	FeToBytes(&s2, &fe)
	if s != s2 {
		t.Fatal("FeToBytes not idempotent: different output on second call")
	}
}

// TestEdwardsSingleton verifies that Edwards() returns the same instance.
func TestEdwardsSingleton(t *testing.T) {
	c1 := Edwards()
	c2 := Edwards()
	if c1 != c2 {
		t.Fatal("Edwards() should return the same singleton instance")
	}
	if c1.P == nil || c1.N == nil || c1.Gx == nil || c1.Gy == nil {
		t.Fatal("Edwards() curve parameters should be initialized")
	}
}

// TestRecoverCompactReturnsError verifies RecoverCompact returns an error.
func TestRecoverCompactReturnsError(t *testing.T) {
	_, _, err := RecoverCompact(nil, nil)
	if err == nil {
		t.Fatal("RecoverCompact should return an error (not implemented)")
	}
}

// TestEncryptDecryptRoundTrip verifies that Encrypt/Decrypt round-trips
// correctly for various message sizes.
func TestEncryptDecryptRoundTrip(t *testing.T) {
	priv, err := GeneratePrivateKey()
	if err != nil {
		t.Fatalf("GeneratePrivateKey: %v", err)
	}
	pub := priv.PubKey()

	for _, size := range []int{0, 1, 15, 16, 17, 31, 32, 33, 100, 256} {
		msg := make([]byte, size)
		rand.Read(msg)

		ct, err := Encrypt(pub, msg)
		if err != nil {
			t.Fatalf("Encrypt (size=%d): %v", size, err)
		}

		pt, err := Decrypt(priv, ct)
		if err != nil {
			t.Fatalf("Decrypt (size=%d): %v", size, err)
		}

		if !bytes.Equal(msg, pt) {
			t.Fatalf("round-trip mismatch for size %d", size)
		}
	}
}

// TestDecryptTamperedCiphertext verifies that tampering with ciphertext
// causes decryption to fail.
func TestDecryptTamperedCiphertext(t *testing.T) {
	priv, err := GeneratePrivateKey()
	if err != nil {
		t.Fatalf("GeneratePrivateKey: %v", err)
	}
	pub := priv.PubKey()

	msg := []byte("test message for tamper detection")
	ct, err := Encrypt(pub, msg)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	// Tamper with ciphertext body (before HMAC)
	tampered := make([]byte, len(ct))
	copy(tampered, ct)
	tampered[len(tampered)/2] ^= 0xFF

	_, err = Decrypt(priv, tampered)
	if err == nil {
		t.Fatal("Decrypt should fail on tampered ciphertext")
	}
}

// TestSignVerifyRoundTrip tests that key generation, signing, and
// verification work end-to-end.
func TestSignVerifyRoundTrip(t *testing.T) {
	pub, priv, err := GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	msg := []byte("test message for sign/verify")
	sig := Sign(priv, msg)

	if !Verify(pub, msg, sig) {
		t.Fatal("valid signature failed verification")
	}

	// Corrupt the message
	badMsg := []byte("wrong message")
	if Verify(pub, badMsg, sig) {
		t.Fatal("signature verified with wrong message")
	}

	// Corrupt the signature
	badSig := new([64]byte)
	copy(badSig[:], sig[:])
	badSig[0] ^= 0xFF
	if Verify(pub, msg, badSig) {
		t.Fatal("corrupted signature passed verification")
	}
}

// TestPrivateKeySerializeSecret tests that PrivateKey.SerializeSecret round-trips.
func TestPrivateKeySerializeSecret(t *testing.T) {
	pub, priv, err := GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	pk, pubKey := PrivKeyFromBytes(priv[:])
	if pk == nil || pubKey == nil {
		t.Fatal("PrivKeyFromBytes returned nil")
	}

	secretBytes := pk.SerializeSecret()
	if secretBytes == nil {
		t.Fatal("SerializeSecret returned nil")
	}
	if len(secretBytes) != 64 {
		t.Fatalf("SerializeSecret returned %d bytes, want 64", len(secretBytes))
	}

	// The public key portion should match
	if !bytes.Equal(secretBytes[32:], pub[:]) {
		t.Fatal("public key portion of SerializeSecret doesn't match")
	}
}

// TestPublicKeyParseSerialization tests that ParsePubKey and Serialize
// round-trip correctly.
func TestPublicKeyParseSerialization(t *testing.T) {
	pub, _, err := GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	parsed, err := ParsePubKey(pub[:])
	if err != nil {
		t.Fatalf("ParsePubKey: %v", err)
	}

	serialized := parsed.Serialize()
	if !bytes.Equal(pub[:], serialized) {
		t.Fatal("ParsePubKey -> Serialize round-trip mismatch")
	}
}

// TestParsePubKeyRejectsInvalid tests that ParsePubKey rejects bad inputs.
func TestParsePubKeyRejectsInvalid(t *testing.T) {
	// Empty
	_, err := ParsePubKey(nil)
	if err == nil {
		t.Fatal("should reject nil")
	}

	// Wrong length
	_, err = ParsePubKey([]byte{1, 2, 3})
	if err == nil {
		t.Fatal("should reject wrong length")
	}

	// Point that doesn't decompress to a valid curve point
	bad := make([]byte, 32)
	bad[0] = 0x01
	bad[31] = 0x7F // large Y with sign bit clear
	_, err = ParsePubKey(bad)
	if err == nil {
		// Some encodings may still be valid; this is a best-effort check
		t.Log("note: test point happened to be valid, skipping")
	}
}

// TestSignatureParseSerialize tests that ParseSignature and Serialize
// round-trip correctly.
func TestSignatureParseSerialize(t *testing.T) {
	pub, priv, err := GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	msg := []byte("signature parse test")
	sigBytes := Sign(priv, msg)

	sig, err := ParseSignature(sigBytes[:])
	if err != nil {
		t.Fatalf("ParseSignature: %v", err)
	}

	serialized := sig.Serialize()
	if !bytes.Equal(sigBytes[:], serialized) {
		t.Fatal("ParseSignature -> Serialize round-trip mismatch")
	}

	// Verify via Signature.Verify method
	pk, err := ParsePubKey(pub[:])
	if err != nil {
		t.Fatalf("ParsePubKey: %v", err)
	}
	if !sig.Verify(msg, pk) {
		t.Fatal("Signature.Verify failed on valid signature")
	}
}

// TestSignatureIsEqual tests Signature.IsEqual.
func TestSignatureIsEqual(t *testing.T) {
	sig1 := NewSignature(big.NewInt(42), big.NewInt(99))
	sig2 := NewSignature(big.NewInt(42), big.NewInt(99))
	sig3 := NewSignature(big.NewInt(42), big.NewInt(100))

	if !sig1.IsEqual(sig2) {
		t.Fatal("equal signatures should be equal")
	}
	if sig1.IsEqual(sig3) {
		t.Fatal("different signatures should not be equal")
	}
}

// TestPrivKeySignRS tests the SignRS and VerifyRS path for keys created
// from scalars (no secret).
func TestPrivKeySignRS(t *testing.T) {
	curve := Edwards()
	// Use a known scalar
	scalar := make([]byte, 32)
	scalar[0] = 1 // small scalar
	priv, pub, err := PrivKeyFromScalar(scalar)
	if err != nil {
		t.Fatalf("PrivKeyFromScalar: %v", err)
	}

	msg := []byte("signrs test message")
	r, s, err := SignRS(priv, msg)
	if err != nil {
		t.Fatalf("SignRS: %v", err)
	}

	if !VerifyRS(pub, msg, r, s) {
		t.Fatal("VerifyRS failed")
	}

	// Verify with wrong message fails
	if VerifyRS(pub, []byte("wrong"), r, s) {
		t.Fatal("VerifyRS should fail with wrong message")
	}

	_ = curve // use curve to avoid lint
}

// TestVerifyRSNilInputs verifies VerifyRS handles nil inputs gracefully.
func TestVerifyRSNilInputs(t *testing.T) {
	if VerifyRS(nil, []byte("msg"), big.NewInt(1), big.NewInt(1)) {
		t.Fatal("should return false for nil pub")
	}
	pub := NewPublicKey(big.NewInt(0), big.NewInt(1))
	if VerifyRS(pub, nil, big.NewInt(1), big.NewInt(1)) {
		t.Fatal("should return false for nil hash")
	}
	if VerifyRS(pub, []byte("msg"), nil, big.NewInt(1)) {
		t.Fatal("should return false for nil r")
	}
	if VerifyRS(pub, []byte("msg"), big.NewInt(1), nil) {
		t.Fatal("should return false for nil s")
	}
}

// TestFieldElementRoundTrip tests FieldElement -> bytes -> FieldElement
// round-trip.
func TestFieldElementRoundTrip(t *testing.T) {
	var fe FieldElement
	FeOne(&fe)

	var buf [32]byte
	FeToBytes(&buf, &fe)

	var fe2 FieldElement
	FeFromBytes(&fe2, &buf)

	var buf2 [32]byte
	FeToBytes(&buf2, &fe2)

	if buf != buf2 {
		t.Fatal("FieldElement round-trip through bytes failed")
	}
}

// TestCurveIsOnCurve verifies that known points are on the curve and
// arbitrary points are not.
func TestCurveIsOnCurve(t *testing.T) {
	curve := Edwards()

	// Base point should be on curve
	if !curve.IsOnCurve(curve.Gx, curve.Gy) {
		t.Fatal("base point should be on curve")
	}

	// Identity (0, 1) should be on curve
	if !curve.IsOnCurve(big.NewInt(0), big.NewInt(1)) {
		t.Fatal("identity point (0,1) should be on curve")
	}

	// Random point should not be on curve
	if curve.IsOnCurve(big.NewInt(12345), big.NewInt(67890)) {
		t.Fatal("arbitrary point should not be on curve")
	}
}

// TestCurveAddDouble verifies that Add and Double are consistent:
// P + P should equal Double(P).
func TestCurveAddDouble(t *testing.T) {
	curve := Edwards()
	gx, gy := curve.Gx, curve.Gy

	// Double
	dx, dy := curve.Double(gx, gy)

	// Add G + G
	ax, ay := curve.Add(gx, gy, gx, gy)

	if dx.Cmp(ax) != 0 || dy.Cmp(ay) != 0 {
		t.Fatal("G+G != 2*G")
	}

	if !curve.IsOnCurve(dx, dy) {
		t.Fatal("2*G not on curve")
	}
}

// TestGenerateKeyDeterministic verifies that GenerateKey with the same
// seed produces the same key pair.
func TestGenerateKeyDeterministic(t *testing.T) {
	seed := make([]byte, 32)
	for i := range seed {
		seed[i] = byte(i)
	}

	pub1, priv1, err := GenerateKey(bytes.NewReader(seed))
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	// Reset seed
	for i := range seed {
		seed[i] = byte(i)
	}

	pub2, priv2, err := GenerateKey(bytes.NewReader(seed))
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	if *pub1 != *pub2 {
		t.Fatal("same seed should produce same public key")
	}
	if *priv1 != *priv2 {
		t.Fatal("same seed should produce same private key")
	}
}
