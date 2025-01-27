package main

import (
	"bufio"
	"fmt"
	"io"
	"math"
	"math/big"
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

	masterKeyBytes, chainCode, err := btools.MasterPrivateKey(seed.Seed)
	if err != nil {
		panic(err)
	}

	fmt.Print("Master private key: ")
	for _, b := range masterKeyBytes {
		fmt.Printf("%02x", b)
	}
	fmt.Println("")

	fmt.Print("Chain code: ")
	for _, b := range chainCode {
		fmt.Printf("%02x", b)
	}
	fmt.Println("")

	masterKey2Base58 := btools.SerializeKey(masterKeyBytes, chainCode, true, true, 0, nil, 0)
	fmt.Printf("Master private key: %s\n", masterKey2Base58)

	masterKey := big.NewInt(0)
	masterKey.SetBytes(masterKeyBytes)

	mkPub := btools.Secp256k1Pub(masterKey)
	mkPubComp := btools.Secp256k1Compressed(mkPub)

	masterKeyPubBase58 := btools.SerializeKey(mkPubComp, chainCode, false, true, 0, nil, 0)
	fmt.Printf("Master public key: %s\n", masterKeyPubBase58)

	index := uint32(42)
	cPrivateKeyBytes, cChaincode, err := btools.CKDpriv(masterKeyBytes, chainCode, index)
	if err != nil {
		panic(err)
	}

	cKeyBase58 := btools.SerializeKey(cPrivateKeyBytes, cChaincode, true, true, 1, masterKeyBytes, index)
	fmt.Printf("Child private key: %s\n", cKeyBase58)

	childPub, cPubChainCode, err := btools.CKDpubFromPriv(masterKeyBytes, chainCode, index)
	if err != nil {
		panic(err)
	}
	childPubComp := btools.Secp256k1Compressed(childPub)
	cPubKeyBase58 := btools.SerializeKey(childPubComp, cPubChainCode, false, true, 1, masterKeyBytes, index)
	fmt.Printf("Child public key: %s\n", cPubKeyBase58)

	childPub2, cChaincode2, err := btools.CKDpub(mkPub, chainCode, index)
	if err != nil {
		panic(err)
	}
	childPub2Comp := btools.Secp256k1Compressed(childPub2)
	cPubKey2Base58 := btools.SerializeKey(childPub2Comp, cChaincode2, false, true, 1, masterKeyBytes, index)
	fmt.Printf("Child public key 2: %s\n", cPubKey2Base58)
}
