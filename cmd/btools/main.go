package main

import (
	"bufio"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"fmt"
	"io"
	"math"
	"math/big"
	"os"
	"strings"

	"github.com/artilugio0/btools"
)

func main() {
	// TODO: only allow raw entropy for base 2, 4 and 8
	rawEntropy := false
	dice := false
	usePassphrase := false
	base := 2   // [2, 10]
	words := 24 // 12 15 18 21 24

	wordsToInputBits := map[int]int{
		12: 128,
		15: 160,
		18: 192,
		21: 224,
		24: 256,
	}

	buf := bufio.NewReader(os.Stdin)
	bits, ok := wordsToInputBits[words]
	if !ok {
		panic("invalid words count")
	}
	bytes := bits / 8

	inputEntropyBuilder := strings.Builder{}
	neededSymbols := int(math.Ceil(float64(bits) / math.Log2(float64(base))))

	for inputEntropyBuilder.Len() < neededSymbols {
		s, err := buf.ReadString('\n')
		if err != nil {
			if err == io.EOF {
				break
			}
			panic(err)
		}
		s = strings.TrimSpace(s)

		inputEntropyBuilder.WriteString(s)
	}
	inputEntropy := inputEntropyBuilder.String()

	if dice {
		var err error
		inputEntropy, err = btools.DiceToBase(inputEntropy, base)
		if err != nil {
			panic(err)
		}
	}

	var entropy []byte
	var err error
	if rawEntropy {
		if len(inputEntropy) != neededSymbols {
			panic("input does not have the required length")
		}
		entropy, err = btools.StringToEntropyRaw(inputEntropy, base, bits)
	} else {
		if len(inputEntropy) < neededSymbols {
			panic("input does not have enough length to produce the required entropy")
		}
		entropy, err = btools.StringToEntropyHash(inputEntropy)
	}
	if err != nil {
		panic(err)
	}

	passphrase := ""
	if usePassphrase {
		fmt.Print("Passphrase: ")
		passphrase, err = buf.ReadString('\n')
		if err != nil {
			panic(err)
		}
		passphrase = strings.TrimSpace(passphrase)
	}

	mnemonic, err := btools.Mnemonic(entropy[:bytes])
	if err != nil {
		panic(err)
	}

	seed, err := btools.NewSeed(mnemonic, passphrase)
	if err != nil {
		panic(err)
	}

	fmt.Print("Seed: ")
	for _, b := range seed.Seed {
		fmt.Printf("%02x", b)
	}
	fmt.Println("")

	masterKey, chainCode, err := masterPrivateKey(seed.Seed)
	if err != nil {
		panic(err)
	}

	fmt.Print("Master private key: ")
	for _, b := range masterKey {
		fmt.Printf("%02x", b)
	}
	fmt.Println("")

	fmt.Print("Chain code: ")
	for _, b := range chainCode {
		fmt.Printf("%02x", b)
	}
	fmt.Println("")

	masterKeyBase58 := serializeMasterKey(masterKey, chainCode, true, true)
	fmt.Printf("Master private key: %s\n", masterKeyBase58)
}

func masterPrivateKey(seed []byte) ([]byte, []byte, error) {
	mac := hmac.New(sha512.New, []byte("Bitcoin seed"))
	mac.Write(seed)
	hash := mac.Sum(nil)
	il := hash[:32]
	ir := hash[32:]

	zero := big.NewInt(0)
	secp256k1Order := big.NewInt(0)
	secp256k1Order, ok := secp256k1Order.SetString("0XFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 0)
	if !ok {
		panic("could not parse secp256k1 order")
	}

	ilInt := big.NewInt(0)
	ilInt = ilInt.SetBytes(il)
	if ilInt.Cmp(zero) == 0 {
		return nil, nil, fmt.Errorf("the derived master private key results in 0")
	}

	if ilInt.Cmp(secp256k1Order) >= 0 {
		return nil, nil, fmt.Errorf(
			"the derived master private key results in a " +
				"value greater or equal than the order of secp256k1")
	}

	return il, ir, nil
}

func serializeMasterKey(key []byte, chaincode []byte, private bool, mainnet bool) string {
	bytes := make([]byte, 82)
	if !private && mainnet {
		bytes[0] = 0x04
		bytes[1] = 0x88
		bytes[2] = 0xB2
		bytes[3] = 0x1E
	} else if private && mainnet {
		bytes[0] = 0x04
		bytes[1] = 0x88
		bytes[2] = 0xAD
		bytes[3] = 0xE4
	} else if !private && !mainnet {
		bytes[0] = 0x04
		bytes[1] = 0x35
		bytes[2] = 0x87
		bytes[3] = 0xCF
	} else if private && !mainnet {
		bytes[0] = 0x04
		bytes[1] = 0x35
		bytes[2] = 0x83
		bytes[3] = 0x94
	}

	bytes[4] = 0x00
	bytes[5] = 0x00
	bytes[6] = 0x00
	bytes[7] = 0x00
	bytes[8] = 0x00
	bytes[9] = 0x00
	bytes[10] = 0x00
	bytes[11] = 0x00
	bytes[12] = 0x00

	for i, c := range chaincode {
		bytes[13+i] = c
	}

	idx := 13 + 32
	if private {
		bytes[idx] = 0x00
		idx++
	}

	for i, c := range key {
		bytes[idx+i] = c
	}

	checksum := sha256.Sum256(bytes[:78])
	checksum = sha256.Sum256(checksum[:])

	bytes[78] = checksum[0]
	bytes[79] = checksum[1]
	bytes[80] = checksum[2]
	bytes[81] = checksum[3]

	zero := big.NewInt(0)
	n := big.NewInt(0)
	n = n.SetBytes(bytes)

	base := big.NewInt(58)

	str := make([]byte, 112)
	base58Symbols := "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
	reminder := big.NewInt(0)
	i := 111
	for n.Cmp(zero) > 0 {
		n, reminder = n.DivMod(n, base, reminder)
		str[i] = base58Symbols[int(reminder.Int64())]
		i--
	}

	return string(str)
}
