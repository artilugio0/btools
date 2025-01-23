package btools

import (
	"crypto/sha256"
	"fmt"
	"math/big"
	"strings"
)

func StringToEntropyHash(s string) ([]byte, error) {
	key := sha256.Sum256([]byte(s))
	return key[:], nil
}

func StringToEntropyRaw(s string, base int, bits int) ([]byte, error) {
	n := big.NewInt(0)
	n, ok := n.SetString(s, base)
	if !ok {
		return nil, fmt.Errorf("invalid input string")
	}

	// left padding to reach the required bits
	requiredLength := bits / 8
	bytes := n.Bytes()
	if len(bytes) < requiredLength {
		missing := requiredLength - len(bytes)
		a := make([]byte, missing)
		bytes = append(a, bytes...)
	}

	return bytes[len(bytes)-requiredLength : len(bytes)], nil
}

func DiceToBase(s string, base int) (string, error) {
	builder := strings.Builder{}
	for _, x := range s {
		if x < '1' || x > '0'+rune(base) {
			return "", fmt.Errorf("invalid symbol found: %c", x)
		}

		if uint(x) == uint('0')+uint(base) {
			x = '0'
		}

		builder.WriteRune(x)
	}

	return builder.String(), nil
}
