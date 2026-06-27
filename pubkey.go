// Copyright (c) 2013-2014 The btcsuite developers
// Copyright (c) 2015-2016 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package edwards25519

import (
	"crypto/ecdsa"
	"errors"
	"fmt"
	"math/big"
)

// These constants define the lengths of serialized public keys.
const (
	// PubKeyBytesLen is the size, in bytes, of a serialized public key.
	PubKeyBytesLen = 32
)

// PublicKey is an ecdsa.PublicKey with an additional function to
// serialize.
type PublicKey ecdsa.PublicKey

// NewPublicKey instantiates a new public key.
func NewPublicKey(x *big.Int, y *big.Int) *PublicKey {
	return &PublicKey{Edwards(), x, y}
}

// ParsePubKey parses a public key for an edwards curve from a bytestring into a
// ecdsa.Publickey, verifying that it is valid.
func ParsePubKey(pubKeyStr []byte) (key *PublicKey, err error) {
	if len(pubKeyStr) == 0 {
		return nil, errors.New("pubkey string is empty")
	}
	if len(pubKeyStr) != PubKeyBytesLen {
		return nil, fmt.Errorf("malformed public key: invalid length: %d",
			len(pubKeyStr))
	}

	curve := Edwards()
	pubkey := PublicKey{}
	pubkey.Curve = curve
	x, y, err := curve.encodedBytesToBigIntPoint(copyBytes(pubKeyStr))
	if err != nil {
		return nil, err
	}
	pubkey.X = x
	pubkey.Y = y

	if pubkey.X.Cmp(pubkey.Curve.Params().P) >= 0 {
		return nil, fmt.Errorf("pubkey X parameter is >= to P")
	}
	if pubkey.Y.Cmp(pubkey.Curve.Params().P) >= 0 {
		return nil, fmt.Errorf("pubkey Y parameter is >= to P")
	}

	// Subgroup / low-order point check.
	//
	// The Ed25519 group has a cofactor of 8, so the full curve contains a
	// small torsion subgroup of 8 low-order points (including the identity
	// (0,1)). Such points are dangerous for the ECDH key agreement used by
	// Encrypt/Decrypt (where the peer's ephemeral public key is attacker
	// supplied) and for key aggregation: multiplying a low-order point by any
	// scalar yields one of only a handful of possible results, collapsing the
	// shared secret to a tiny, predictable set.
	//
	// A point P has order dividing the cofactor iff [8]P is the identity.
	// Reject any such point here. Note this validation deliberately lives only
	// in ParsePubKey: Ed25519 signature verification (Verify) uses
	// A.FromBytes directly and must keep accepting the low-order public keys
	// present in RFC 8032 test vectors.
	lx, ly := curve.ScalarMult(pubkey.X, pubkey.Y, []byte{8})
	if lx == nil || (lx.Sign() == 0 && ly.Cmp(one) == 0) {
		return nil, fmt.Errorf("public key is a low-order point")
	}

	return &pubkey, nil
}

// ToECDSA returns the public key as a *ecdsa.PublicKey.
func (p PublicKey) ToECDSA() *ecdsa.PublicKey {
	pkecdsa := ecdsa.PublicKey(p)
	return &pkecdsa
}

// Serialize serializes a public key in a 32-byte compressed little endian format.
func (p PublicKey) Serialize() []byte {
	if p.X == nil || p.Y == nil {
		return nil
	}
	return bigIntPointToEncodedBytes(p.X, p.Y)[:]
}

// SerializeUncompressed satisfies the chainec PublicKey interface.
func (p PublicKey) SerializeUncompressed() []byte {
	return p.Serialize()
}

// SerializeCompressed satisfies the chainec PublicKey interface.
func (p PublicKey) SerializeCompressed() []byte {
	return p.Serialize()
}

// GetCurve satisfies the chainec PublicKey interface.
func (p PublicKey) GetCurve() interface{} {
	return p.Curve
}

// GetX satisfies the chainec PublicKey interface.
func (p PublicKey) GetX() *big.Int {
	return p.X
}

// GetY satisfies the chainec PublicKey interface.
func (p PublicKey) GetY() *big.Int {
	return p.Y
}

// GetType satisfies the chainec PublicKey interface.
func (p PublicKey) GetType() int {
	return ecTypeEdwards
}
