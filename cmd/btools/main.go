package main

import (
	"bufio"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
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

	masterKeyBytes, chainCode, err := masterPrivateKey(seed.Seed)
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

	masterKey2Base58 := serializeKey(masterKeyBytes, chainCode, true, true, 0, nil, 0)
	fmt.Printf("Master private key: %s\n", masterKey2Base58)

	masterKey := big.NewInt(0)
	masterKey.SetBytes(masterKeyBytes)
	mkPubx, mkPuby := btools.Secp256k1Pub(masterKey)
	mkPubComp := btools.Secp256k1Compressed(mkPubx, mkPuby)
	masterKeyPubBase58 := serializeKey(mkPubComp, chainCode, false, true, 0, nil, 0)
	fmt.Printf("Master public key: %s\n", masterKeyPubBase58)

	index := uint32(42)
	cPrivateKeyBytes, cChaincode, err := CKDpriv(masterKeyBytes, chainCode, index)
	if err != nil {
		panic(err)
	}

	cKeyBase58 := serializeKey(cPrivateKeyBytes, cChaincode, true, true, 1, masterKeyBytes, index)
	fmt.Printf("Child private key: %s\n", cKeyBase58)

	childPubx, childPuby, cPubChainCode, err := CKDpubFromPriv(masterKeyBytes, chainCode, index)
	if err != nil {
		panic(err)
	}
	childPubComp := btools.Secp256k1Compressed(childPubx, childPuby)
	cPubKeyBase58 := serializeKey(childPubComp, cPubChainCode, false, true, 1, masterKeyBytes, index)
	fmt.Printf("Child public key: %s\n", cPubKeyBase58)

	childPubx2, childPuby2, cChaincode2, err := CKDpub(mkPubx, mkPuby, chainCode, index)
	if err != nil {
		panic(err)
	}
	childPub2Comp := btools.Secp256k1Compressed(childPubx2, childPuby2)
	cPubKey2Base58 := serializeKey(childPub2Comp, cChaincode2, false, true, 1, masterKeyBytes, index)
	fmt.Printf("Child public key 2: %s\n", cPubKey2Base58)
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

func serializeKey(key []byte, chaincode []byte, private bool, mainnet bool, depth uint8, parkbytes []byte, i uint32) string {
	// TODO: validate that depth, parkbytes, i are consistent
	isMaster := parkbytes == nil

	bytes := []byte{}
	if !private && mainnet {
		bytes = append(bytes, []byte{0x04, 0x88, 0xB2, 0x1E}...)
	} else if private && mainnet {
		bytes = append(bytes, []byte{0x04, 0x88, 0xAD, 0xE4}...)
	} else if !private && !mainnet {
		bytes = append(bytes, []byte{0x04, 0x35, 0x87, 0xCF}...)
	} else if private && !mainnet {
		bytes = append(bytes, []byte{0x04, 0x35, 0x83, 0x94}...)
	}

	bytes = append(bytes, byte(depth))

	if isMaster {
		bytes = append(bytes, []byte{0x00, 0x00, 0x00, 0x00}...)
	} else {
		park := big.NewInt(0)
		park.SetBytes(parkbytes)
		fingerprint := btools.Secp256k1Fingerprint(park)
		bytes = append(bytes, fingerprint...)
	}

	bytes = binary.BigEndian.AppendUint32(bytes, i)

	bytes = append(bytes, chaincode...)

	if private {
		bytes = append(bytes, 0x00)
	}
	bytes = append(bytes, key...)

	return Base58Check(bytes)
}

func CKDpriv(k []byte, c []byte, i uint32) ([]byte, []byte, error) {
	lim := uint32(1) << 31
	var data []byte
	if i >= lim {
		// If so (hardened child): let I = HMAC-SHA512(Key = cpar, Data = 0x00 || ser256(kpar) || ser32(i)). (Note: The 0x00 pads the private key to make it 33 bytes long.)
		data = append([]byte{0x00}, k...)
		data = binary.BigEndian.AppendUint32(data, i)
	} else {
		//If not (normal child): let I = HMAC-SHA512(Key = cpar, Data = serP(point(kpar)) || ser32(i)).
		privk := big.NewInt(0)
		privk.SetBytes(k)
		pubx, puby := btools.Secp256k1Pub(privk)
		data = btools.Secp256k1Compressed(pubx, puby)
		data = binary.BigEndian.AppendUint32(data, i)
	}

	hm := hmac.New(sha512.New, c)
	hm.Write(data)
	I := hm.Sum(nil)

	secp256k1Order := big.NewInt(0)
	secp256k1Order, ok := secp256k1Order.SetString("0XFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 0)
	if !ok {
		panic("could not parse secp256k1 order")
	}

	Il := I[:32]
	Ir := I[32:]

	// In case parse256(IL) ≥ n or ki = 0, the resulting key is invalid, and one should proceed with the next value for i. (Note: this has probability lower than 1 in 2127.)
	kChildNum := big.NewInt(0)
	kChildNum.SetBytes(Il)

	if kChildNum.Cmp(secp256k1Order) >= 0 {
		return nil, nil, fmt.Errorf("resulting key is greater than the order of Secp256K1")
	}

	kParNum := big.NewInt(0)
	kParNum.SetBytes(k)

	kChildNum.Add(kChildNum, kParNum).Mod(kChildNum, secp256k1Order)
	if kChildNum.Cmp(big.NewInt(0)) == 0 {
		return nil, nil, fmt.Errorf("resulting key is 0")
	}

	return kChildNum.Bytes(), Ir, nil
}

func CKDpub(pubx, puby *big.Int, c []byte, i uint32) (*big.Int, *big.Int, []byte, error) {
	lim := uint32(1) << 31
	var data []byte
	if i >= lim {
		return nil, nil, nil, fmt.Errorf("i > %d", lim)
	}

	// If not (normal child): let I = HMAC-SHA512(Key = cpar, Data = serP(Kpar) || ser32(i)).
	data = btools.Secp256k1Compressed(pubx, puby)
	data = binary.BigEndian.AppendUint32(data, i)

	hm := hmac.New(sha512.New, c)
	hm.Write(data)
	I := hm.Sum(nil)

	secp256k1Order := big.NewInt(0)
	secp256k1Order, ok := secp256k1Order.SetString("0XFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 0)
	if !ok {
		panic("could not parse secp256k1 order")
	}

	Il := I[:32]
	Ir := I[32:]

	IlNum := big.NewInt(0)
	IlNum.SetBytes(Il)
	if IlNum.Cmp(secp256k1Order) >= 0 {
		return nil, nil, nil, fmt.Errorf("resulting key is greater than the order of Secp256K1")
	}

	IlPubx, IlPuby := btools.Secp256k1Pub(IlNum)

	childPubx, childPuby := btools.Secp256k1Add(pubx, puby, IlPubx, IlPuby)

	return childPubx, childPuby, Ir, nil
}

func CKDpubFromPriv(key []byte, c []byte, i uint32) (*big.Int, *big.Int, []byte, error) {
	cKeyBytes, cChaincode, err := CKDpriv(key, c, i)
	if err != nil {
		return nil, nil, nil, err
	}

	cKey := big.NewInt(0)
	cKey.SetBytes(cKeyBytes)
	cPubx, cPuby := btools.Secp256k1Pub(cKey)

	return cPubx, cPuby, cChaincode, nil
}

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
