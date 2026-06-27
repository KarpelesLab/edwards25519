package edwards25519

import (
	"bytes"
	"crypto/rand"
	"testing"
)

// randReducedScalar returns a uniformly random scalar reduced mod L, as a
// canonical 32-byte little-endian value.
func randReducedScalar(t *testing.T) [32]byte {
	t.Helper()
	var wide [64]byte
	if _, err := rand.Read(wide[:]); err != nil {
		t.Fatalf("rand: %v", err)
	}
	var s [32]byte
	ScReduce(&s, &wide)
	return s
}

// TestExtendedAddMatchesScalarAdd verifies that point addition agrees with
// scalar addition mod L: (a*B) + (s*B) == (a+s)*B. This is the property that
// makes watch-only (public-path) derivation equivalent to the private path.
func TestExtendedAddMatchesScalarAdd(t *testing.T) {
	one := [32]byte{1}

	for i := 0; i < 1000; i++ {
		a := randReducedScalar(t)
		s := randReducedScalar(t)

		// Public path: A + S where A = a*B, S = s*B.
		var A, S, child ExtendedGroupElement
		GeScalarMultBase(&A, &a)
		GeScalarMultBase(&S, &s)
		child.Add(&A, &S)
		var got [32]byte
		child.ToBytes(&got)

		// Private path: (a + s)*B, with a+s computed via the fused MulAdd
		// (a*1 + s) reduced mod L.
		var sum [32]byte
		ScMulAdd(&sum, &a, &one, &s)
		var direct ExtendedGroupElement
		GeScalarMultBase(&direct, &sum)
		var want [32]byte
		direct.ToBytes(&want)

		if !bytes.Equal(got[:], want[:]) {
			t.Fatalf("iter %d: public path %x != private path %x", i, got, want)
		}
	}
}

// TestExtendedAddDecodeRoundTrip exercises the full Decode->Add->Encode flow on
// compressed points, the way watch-only xpub derivation uses it.
func TestExtendedAddDecodeRoundTrip(t *testing.T) {
	for i := 0; i < 256; i++ {
		a := randReducedScalar(t)
		s := randReducedScalar(t)

		// Encode A = a*B to its compressed form, then decode it back, as a
		// caller holding only a serialized parent public key would.
		var A ExtendedGroupElement
		GeScalarMultBase(&A, &a)
		var aEnc [32]byte
		A.ToBytes(&aEnc)

		var parent ExtendedGroupElement
		if !parent.FromBytes(&aEnc) {
			t.Fatalf("iter %d: FromBytes rejected a valid point", i)
		}

		// contrib = s*B, then child = parent + contrib, encoded.
		var contrib, child ExtendedGroupElement
		GeScalarMultBase(&contrib, &s)
		child.Add(&parent, &contrib)
		var got [32]byte
		child.ToBytes(&got)

		// Reference: (a+s)*B.
		one := [32]byte{1}
		var sum [32]byte
		ScMulAdd(&sum, &a, &one, &s)
		var ref ExtendedGroupElement
		GeScalarMultBase(&ref, &sum)
		var want [32]byte
		ref.ToBytes(&want)

		if !bytes.Equal(got[:], want[:]) {
			t.Fatalf("iter %d: decode->add->encode %x != %x", i, got, want)
		}
	}
}

// TestExtendedAddAliasing checks that r.Add(a, b) is correct when r aliases an
// input, since the doc comment promises in-place use is safe.
func TestExtendedAddAliasing(t *testing.T) {
	a := randReducedScalar(t)
	s := randReducedScalar(t)

	var A, S ExtendedGroupElement
	GeScalarMultBase(&A, &a)
	GeScalarMultBase(&S, &s)

	// Reference sum into a fresh element.
	var ref ExtendedGroupElement
	ref.Add(&A, &S)
	var want [32]byte
	ref.ToBytes(&want)

	// r aliases a.
	var pa, pb ExtendedGroupElement
	GeScalarMultBase(&pa, &a)
	GeScalarMultBase(&pb, &s)
	pa.Add(&pa, &pb)
	var gotA [32]byte
	pa.ToBytes(&gotA)
	if !bytes.Equal(gotA[:], want[:]) {
		t.Fatalf("aliasing a: %x != %x", gotA, want)
	}

	// r aliases b.
	GeScalarMultBase(&pa, &a)
	GeScalarMultBase(&pb, &s)
	pb.Add(&pa, &pb)
	var gotB [32]byte
	pb.ToBytes(&gotB)
	if !bytes.Equal(gotB[:], want[:]) {
		t.Fatalf("aliasing b: %x != %x", gotB, want)
	}
}
