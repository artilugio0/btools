package main

import (
	"bufio"
	"fmt"
	"io"
	"math"
	"os"
	"strings"

	"github.com/artilugio0/btools"
)

func main() {
	// TODO: check that the pk is less than the order of the EC
	// TODO: only allow raw entropy for base 2, 4 and 8
	rawEntropy := false
	dice := false
	usePassphrase := false
	base := 2   // [2, 10]
	words := 24 // 12 15 18 21 24
	mainnet := true

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

	fmt.Println("Mnemonic seed phrasee: ")
	for i, m := range mnemonic {
		fmt.Printf("%d) %s\n", i+1, m)
	}
	fmt.Println("")

	seed, err := btools.NewSeed(mnemonic, passphrase)
	if err != nil {
		panic(err)
	}

	fmt.Print("Seed: ")
	for _, b := range seed.Seed {
		fmt.Printf("%02x", b)
	}
	fmt.Println("")

	masterKey, err := btools.MasterPrivateKey(seed)
	if err != nil {
		panic(err)
	}

	fmt.Print("Master private key: ")
	for _, b := range masterKey.PrivateKey.Bytes() {
		fmt.Printf("%02x", b)
	}
	fmt.Println("")

	fmt.Print("Chain code: ")
	for _, b := range masterKey.ChainCode {
		fmt.Printf("%02x", b)
	}
	fmt.Println("")

	masterKey2Base58 := masterKey.SerializeKey(mainnet)
	fmt.Printf("Master private key: %s\n", masterKey2Base58)

	masterPublicKey := masterKey.XPubKey()

	masterKeyPubBase58 := masterPublicKey.SerializeKey(mainnet)
	fmt.Printf("Master public key: %s\n", masterKeyPubBase58)

	index := uint32(42)
	childXPrivKey, err := masterKey.CKDpriv(index)
	if err != nil {
		panic(err)
	}

	cKeyBase58 := childXPrivKey.SerializeKey(mainnet)
	fmt.Printf("Child private key: %s\n", cKeyBase58)

	childPub, err := masterKey.CKDpub(index)
	if err != nil {
		panic(err)
	}
	cPubKeyBase58 := childPub.SerializeKey(mainnet)

	fmt.Printf("Child public key: %s\n", cPubKeyBase58)

	childPub2, err := masterPublicKey.CKDpub(index)
	if err != nil {
		panic(err)
	}
	cPubKey2Base58 := childPub2.SerializeKey(mainnet)
	fmt.Printf("Child public key 2: %s\n", cPubKey2Base58)
}
