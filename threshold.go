// Copyright (c) 2015-2018 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package edwards25519

import (
	"fmt"
	"math/big"
)

// Sha512VersionStringRFC6979 is the RFC6979 nonce version for a Schnorr signature
// over the Curve25519 curve using SHA-512 as the hash function.
var Sha512VersionStringRFC6979 = []byte("Edwards+SHA512  ")

// combinePubkeys combines a slice of public keys into a single public key
// by adding them together with point addition.
//
// WARNING: This naive key-summation scheme is EXPERIMENTAL and INSECURE against
// rogue-key attacks: the group key is a plain sum of member keys with no
// key-aggregation coefficients or proof-of-possession, so a malicious member
// can choose its key to control the aggregate. Production multi-party signing
// should use a key-aggregation scheme such as MuSig2 or FROST instead.
func combinePubkeys(pks []*PublicKey) *PublicKey {
	numPubKeys := len(pks)

	curve := Edwards()

	// Have to have at least one pubkey.
	if numPubKeys < 1 {
		return nil
	}
	if numPubKeys == 1 {
		// Validate the single key the same way the multi-key path does:
		// reject nil or off-curve points.
		if pks[0] == nil || !curve.IsOnCurve(pks[0].GetX(), pks[0].GetY()) {
			return nil
		}
		return pks[0]
	}
	if pks[0] == nil || pks[1] == nil {
		return nil
	}
	var pkSumX *big.Int
	var pkSumY *big.Int

	pkSumX, pkSumY = curve.Add(pks[0].GetX(), pks[0].GetY(),
		pks[1].GetX(), pks[1].GetY())

	if numPubKeys > 2 {
		for i := 2; i < numPubKeys; i++ {
			if pks[i] == nil {
				return nil
			}
			pkSumX, pkSumY = curve.Add(pkSumX, pkSumY,
				pks[i].GetX(), pks[i].GetY())
		}
	}

	if !curve.IsOnCurve(pkSumX, pkSumY) {
		return nil
	}

	return NewPublicKey(pkSumX, pkSumY)
}

// schnorrPartialSign creates a partial Schnorr signature which may be combined
// with other Schnorr signatures to create a valid signature for a group pubkey.
//
// WARNING: This threshold/Schnorr multisig scheme is EXPERIMENTAL and INSECURE
// for production multi-party use. It is vulnerable to nonce-reuse / Wagner-ROS
// forgery (naive single-round aggregate nonces permit key recovery and forgery
// under concurrent signing) and to rogue-key attacks (the group key is a plain
// sum with no key-aggregation coefficients or proof-of-possession). Callers
// MUST ensure per-message nonce uniqueness. Production multi-party signing
// should use MuSig2 or FROST instead.
func schnorrPartialSign(msg []byte, priv []byte,
	groupPublicKey []byte, privNonce []byte, pubNonceSum []byte) (*big.Int,
	*big.Int, error) {

	// Sanity checks.
	if len(msg) != PrivScalarSize {
		str := fmt.Sprintf("wrong size for message (got %v, want %v)",
			len(msg), PrivScalarSize)
		return nil, nil, fmt.Errorf("%v", str)
	}
	if len(priv) != PrivScalarSize {
		str := fmt.Sprintf("wrong size for privkey (got %v, want %v)",
			len(priv), PrivScalarSize)
		return nil, nil, fmt.Errorf("%v", str)
	}
	if len(privNonce) != PrivScalarSize {
		str := fmt.Sprintf("wrong size for privnonce (got %v, want %v)",
			len(privNonce), PrivScalarSize)
		return nil, nil, fmt.Errorf("%v", str)
	}
	if len(groupPublicKey) != PubKeyBytesLen {
		str := fmt.Sprintf("wrong size for group public key (got %v, want %v)",
			len(groupPublicKey), PubKeyBytesLen)
		return nil, nil, fmt.Errorf("%v", str)
	}
	if len(pubNonceSum) != PubKeyBytesLen {
		str := fmt.Sprintf("wrong size for group nonce public key (got %v, "+
			"want %v)",
			len(pubNonceSum), PubKeyBytesLen)
		return nil, nil, fmt.Errorf("%v", str)
	}

	curve := Edwards()
	privBig := new(big.Int).SetBytes(priv)
	if privBig.Cmp(zero) == 0 {
		str := "priv scalar is zero"
		return nil, nil, fmt.Errorf("%v", str)
	}
	if privBig.Cmp(curve.N) >= 0 {
		str := "priv scalar is out of bounds"
		return nil, nil, fmt.Errorf("%v", str)
	}
	zeroBigInt(privBig)

	privNonceBig := new(big.Int).SetBytes(privNonce)
	if privNonceBig.Cmp(zero) == 0 {
		str := "privNonce scalar is zero"
		return nil, nil, fmt.Errorf("%v", str)
	}
	if privNonceBig.Cmp(curve.N) >= 0 {
		str := "privNonce scalar is out of bounds"
		return nil, nil, fmt.Errorf("%v", str)
	}
	zeroBigInt(privNonceBig)

	gpkX, gpkY, err := curve.encodedBytesToBigIntPoint(copyBytes(groupPublicKey))
	if err != nil {
		str := fmt.Sprintf("public key point could not be decoded: %v", err)
		return nil, nil, fmt.Errorf("%v", str)
	}
	if !curve.IsOnCurve(gpkX, gpkY) {
		str := "public key sum is off curve"
		return nil, nil, fmt.Errorf("%v", str)
	}

	gpnX, gpnY, err := curve.encodedBytesToBigIntPoint(copyBytes(pubNonceSum))
	if err != nil {
		str := fmt.Sprintf("public key point could not be decoded: %v", err)
		return nil, nil, fmt.Errorf("%v", str)
	}
	if !curve.IsOnCurve(gpnX, gpnY) {
		str := "public key sum is off curve"
		return nil, nil, fmt.Errorf("%v", str)
	}

	// Capture and check decode errors to prevent a latent nil-deref downstream
	// in SignThreshold.
	privDecoded, _, err := PrivKeyFromScalar(priv)
	if err != nil || privDecoded == nil {
		return nil, nil, fmt.Errorf("could not decode private scalar: %v", err)
	}
	groupPubKeyDecoded, err := ParsePubKey(groupPublicKey)
	if err != nil || groupPubKeyDecoded == nil {
		return nil, nil, fmt.Errorf("could not decode group public key: %v", err)
	}
	privNonceDecoded, _, err := PrivKeyFromScalar(privNonce)
	if err != nil || privNonceDecoded == nil {
		return nil, nil, fmt.Errorf("could not decode private nonce: %v", err)
	}
	pubNonceSumDecoded, err := ParsePubKey(pubNonceSum)
	if err != nil || pubNonceSumDecoded == nil {
		return nil, nil, fmt.Errorf("could not decode public nonce sum: %v", err)
	}

	return SignThreshold(privDecoded, groupPubKeyDecoded, msg,
		privNonceDecoded, pubNonceSumDecoded)
}

// schnorrCombineSigs combines a list of partial Schnorr signatures s values
// into a complete signature s for some group public key. This is achieved
// by simply adding the s values of the partial signatures as scalars.
//
// WARNING: Part of an EXPERIMENTAL and INSECURE threshold/Schnorr multisig
// scheme that is vulnerable to rogue-key and nonce-reuse/ROS attacks. Callers
// MUST ensure per-message nonce uniqueness. Production multi-party signing
// should use MuSig2 or FROST instead.
func schnorrCombineSigs(sigss [][]byte) (*big.Int, error) {
	curve := Edwards()
	combinedSigS := new(big.Int).SetInt64(0)
	for i, sigs := range sigss {
		sigsBI := encodedBytesToBigInt(copyBytes(sigs))
		if sigsBI.Cmp(zero) == 0 {
			str := fmt.Sprintf("sig s %v is zero", i)
			return nil, fmt.Errorf("%v", str)
		}
		if sigsBI.Cmp(curve.N) >= 0 {
			str := fmt.Sprintf("sig s %v is out of bounds", i)
			return nil, fmt.Errorf("%v", str)
		}

		combinedSigS = scalarAdd(combinedSigS, sigsBI)
		combinedSigS.Mod(combinedSigS, curve.N)
	}

	if combinedSigS.Cmp(zero) == 0 {
		str := fmt.Sprintf("combined sig s %v is zero", combinedSigS)
		return nil, fmt.Errorf("%v", str)
	}

	return combinedSigS, nil
}

// schnorrCombinePartialSigs combines partial signatures.
//
// WARNING: Part of an EXPERIMENTAL and INSECURE threshold/Schnorr multisig
// scheme that is vulnerable to rogue-key and nonce-reuse/ROS attacks. Callers
// MUST ensure per-message nonce uniqueness. Production multi-party signing
// should use MuSig2 or FROST instead.
func schnorrCombinePartialSigs(sigs []*Signature) (*Signature, error) {
	sigss := make([][]byte, len(sigs))
	for i, sig := range sigs {
		if sig == nil {
			return nil, fmt.Errorf("nil signature")
		}

		if i > 0 {
			if sigs[i-1].GetR().Cmp(sig.GetR()) != 0 {
				str := fmt.Sprintf("nonmatching r values for idx %v, %v",
					i, i-1)
				return nil, fmt.Errorf("%v", str)
			}
		}

		sigss[i] = bigIntToEncodedBytes(sig.GetS())[:]
	}

	combinedSigS, err := schnorrCombineSigs(sigss)
	if err != nil {
		return nil, err
	}

	return NewSignature(sigs[0].R, combinedSigS), nil
}
