package btools

import (
	"crypto/sha256"
	"math/big"
	"strings"
)

func Base58Check(input []byte) string {
	bytes := append([]byte{}, input...)

	checksum := sha256.Sum256(input)
	checksum = sha256.Sum256(checksum[:])

	bytes = append(bytes, checksum[:4]...)

	zero := big.NewInt(0)
	n := big.NewInt(0)
	n = n.SetBytes(bytes)

	base := big.NewInt(58)

	base58Symbols := "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
	reminder := big.NewInt(0)
	builder := strings.Builder{}
	for n.Cmp(zero) > 0 {
		n, reminder = n.DivMod(n, base, reminder)
		builder.WriteByte(base58Symbols[int(reminder.Int64())])
	}

	runes := []rune(builder.String())
	for i, j := 0, len(runes)-1; i < j; i, j = i+1, j-1 {
		runes[i], runes[j] = runes[j], runes[i]
	}

	return string(runes)
}
