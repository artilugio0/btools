package btools

import (
	"crypto/sha256"
	"math/big"

	"golang.org/x/crypto/ripemd160"
)

func Secp256k1Identifier(k *big.Int) []byte {
	pub := Secp256k1Pub(k)
	pubComp := Secp256k1Compressed(pub)
	hash := sha256.Sum256(pubComp)
	ripe := ripemd160.New()
	ripe.Write(hash[:])

	return ripe.Sum(nil)
}

func Secp256k1Fingerprint(k *big.Int) []byte {
	return Secp256k1Identifier(k)[:4]
}
