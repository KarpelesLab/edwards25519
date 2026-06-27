package edwards25519

import (
	"crypto/sha512"
	"crypto/subtle"
)

// order is the group order L in little-endian byte order, where
// L = 2^252 + 27742317777372353535851937790883648493.
var order = [32]byte{
	0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58,
	0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0x10,
}

// scalarIsReduced reports, in constant time, whether the little-endian scalar
// s is fully reduced modulo the group order, i.e. s < L. A scalar equal to L
// (or larger) is not reduced.
func scalarIsReduced(s *[32]byte) bool {
	for i := 31; ; i-- {
		switch {
		case s[i] > order[i]:
			return false
		case s[i] < order[i]:
			return true
		case i == 0:
			return false // s == L is not reduced
		}
	}
}

// Verify returns true iff sig is a valid signature of message by publicKey.
func Verify(publicKey *[PublicKeySize]byte, message []byte, sig *[SignatureSize]byte) bool {
	if sig[63]&224 != 0 {
		return false
	}

	// Reject non-canonical scalars S >= L to prevent signature malleability:
	// without this check, (R, S+L) would also verify for any valid (R, S).
	var s [32]byte
	copy(s[:], sig[32:])
	if !scalarIsReduced(&s) {
		return false
	}

	var A ExtendedGroupElement
	if !A.FromBytes(publicKey) {
		return false
	}
	FeNeg(&A.X, &A.X)
	FeNeg(&A.T, &A.T)

	h := sha512.New()
	h.Write(sig[:32])
	h.Write(publicKey[:])
	h.Write(message)
	var digest [64]byte
	h.Sum(digest[:0])

	var hReduced [32]byte
	ScReduce(&hReduced, &digest)

	var R ProjectiveGroupElement
	var b [32]byte
	copy(b[:], sig[32:])
	GeDoubleScalarMultVartime(&R, &hReduced, &A, &b)

	var checkR [32]byte
	R.ToBytes(&checkR)
	return subtle.ConstantTimeCompare(sig[:32], checkR[:]) == 1
}
