package btools

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"fmt"
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

func MasterPrivateKey(seed []byte) ([]byte, []byte, error) {
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

func SerializeKey(key []byte, chaincode []byte, private bool, mainnet bool, depth uint8, parkbytes []byte, i uint32) string {
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
		fingerprint := Secp256k1Fingerprint(park)
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
		pub := Secp256k1Pub(privk)
		data = Secp256k1Compressed(pub)
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

func CKDpub(pub Point, c []byte, i uint32) (Point, []byte, error) {
	lim := uint32(1) << 31
	var data []byte
	if i >= lim {
		return Infinity(), nil, fmt.Errorf("i > %d", lim)
	}

	// If not (normal child): let I = HMAC-SHA512(Key = cpar, Data = serP(Kpar) || ser32(i)).
	data = Secp256k1Compressed(pub)
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
		return Infinity(), nil, fmt.Errorf("resulting key is greater than the order of Secp256K1")
	}

	IlPub := Secp256k1Pub(IlNum)

	childPub := Secp256k1Add(pub, IlPub)

	return childPub, Ir, nil
}

func CKDpubFromPriv(key []byte, c []byte, i uint32) (Point, []byte, error) {
	cKeyBytes, cChaincode, err := CKDpriv(key, c, i)
	if err != nil {
		return Infinity(), nil, err
	}

	cKey := big.NewInt(0)
	cKey.SetBytes(cKeyBytes)
	cPub := Secp256k1Pub(cKey)

	return cPub, cChaincode, nil
}
