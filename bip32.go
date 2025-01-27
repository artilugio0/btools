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

type XPrivKey struct {
	Parent *XPrivKey
	Depth  uint8
	Index  uint32

	PrivateKey *big.Int
	ChainCode  []byte
}

func (xpriv XPrivKey) XPubKey() XPubKey {
	pub := Secp256k1Pub(xpriv.PrivateKey)

	return XPubKey{
		PrivParent: xpriv.Parent,
		Depth:      xpriv.Depth,
		Index:      xpriv.Index,
		ChainCode:  xpriv.ChainCode,
		PublicKey:  pub,
	}
}

func (xpriv XPrivKey) Identifier() []byte {
	pub := Secp256k1Pub(xpriv.PrivateKey)
	pubComp := Secp256k1Compressed(pub)
	hash := sha256.Sum256(pubComp)
	ripe := ripemd160.New()
	ripe.Write(hash[:])

	return ripe.Sum(nil)
}

func (xpriv XPrivKey) Fingerprint() []byte {
	return xpriv.Identifier()[:4]
}

func (xpriv XPrivKey) SerializeKey(mainnet bool) string {
	// TODO: validate that depth, parkbytes, i are consistent
	bytes := []byte{}
	if mainnet {
		bytes = append(bytes, []byte{0x04, 0x88, 0xAD, 0xE4}...)
	} else {
		bytes = append(bytes, []byte{0x04, 0x35, 0x83, 0x94}...)
	}

	bytes = append(bytes, byte(xpriv.Depth))

	isMaster := xpriv.Parent == nil
	if isMaster {
		bytes = append(bytes, []byte{0x00, 0x00, 0x00, 0x00}...)
	} else {
		fingerprint := xpriv.Parent.Fingerprint()
		bytes = append(bytes, fingerprint...)
	}

	bytes = binary.BigEndian.AppendUint32(bytes, xpriv.Index)

	bytes = append(bytes, xpriv.ChainCode...)

	bytes = append(bytes, 0x00)
	bytes = append(bytes, xpriv.PrivateKey.Bytes()...)

	return Base58Check(bytes)
}

func (xpriv XPrivKey) CKDpriv(i uint32) (XPrivKey, error) {
	lim := uint32(1) << 31
	var data []byte
	if i >= lim {
		// If so (hardened child): let I = HMAC-SHA512(Key = cpar, Data = 0x00 || ser256(kpar) || ser32(i)). (Note: The 0x00 pads the private key to make it 33 bytes long.)
		data = append([]byte{0x00}, xpriv.PrivateKey.Bytes()...)
	} else {
		//If not (normal child): let I = HMAC-SHA512(Key = cpar, Data = serP(point(kpar)) || ser32(i)).
		pub := Secp256k1Pub(xpriv.PrivateKey)
		data = Secp256k1Compressed(pub)
	}

	data = binary.BigEndian.AppendUint32(data, i)

	hm := hmac.New(sha512.New, xpriv.ChainCode)
	hm.Write(data)
	I := hm.Sum(nil)

	Il := I[:32]
	Ir := I[32:]

	// In case parse256(IL) ≥ n or ki = 0, the resulting key is invalid, and one should proceed with the next value for i. (Note: this has probability lower than 1 in 2127.)
	kChildNum := big.NewInt(0)
	kChildNum.SetBytes(Il)

	if kChildNum.Cmp(secp256k1Order) >= 0 {
		return XPrivKey{}, fmt.Errorf("resulting key is greater than the order of Secp256K1")
	}

	kChildNum.Add(kChildNum, xpriv.PrivateKey).Mod(kChildNum, secp256k1Order)
	if kChildNum.Cmp(big.NewInt(0)) == 0 {
		return XPrivKey{}, fmt.Errorf("resulting key is 0")
	}

	return XPrivKey{
		Parent: &xpriv,
		Depth:  xpriv.Depth + 1,
		Index:  i,

		PrivateKey: kChildNum,
		ChainCode:  Ir,
	}, nil
}

func (xpriv XPrivKey) CKDpub(i uint32) (XPubKey, error) {
	ck, err := xpriv.CKDpriv(i)
	if err != nil {
		return XPubKey{}, err
	}

	return ck.XPubKey(), err
}

type XPubKey struct {
	PrivParent *XPrivKey
	PubParent  *XPubKey

	Depth uint8
	Index uint32

	PublicKey Point
	ChainCode []byte
}

func (xpub XPubKey) SerializeKey(mainnet bool) string {
	// TODO: validate that depth, parkbytes, i are consistent

	bytes := []byte{}
	if mainnet {
		bytes = append(bytes, []byte{0x04, 0x88, 0xB2, 0x1E}...)
	} else {
		bytes = append(bytes, []byte{0x04, 0x35, 0x87, 0xCF}...)
	}

	bytes = append(bytes, byte(xpub.Depth))

	isMaster := xpub.PrivParent == nil && xpub.PubParent == nil
	if isMaster {
		bytes = append(bytes, []byte{0x00, 0x00, 0x00, 0x00}...)
	} else {
		var fingerprint []byte
		if xpub.PrivParent != nil {
			fingerprint = xpub.PrivParent.Fingerprint()
		} else {
			fingerprint = xpub.PubParent.Fingerprint()
		}
		bytes = append(bytes, fingerprint...)
	}

	bytes = binary.BigEndian.AppendUint32(bytes, xpub.Index)
	bytes = append(bytes, xpub.ChainCode...)

	comp := Secp256k1Compressed(xpub.PublicKey)
	bytes = append(bytes, comp...)

	return Base58Check(bytes)
}

func (xpub XPubKey) Identifier() []byte {
	pubComp := Secp256k1Compressed(xpub.PublicKey)
	hash := sha256.Sum256(pubComp)
	ripe := ripemd160.New()
	ripe.Write(hash[:])

	return ripe.Sum(nil)
}

func (xpub XPubKey) Fingerprint() []byte {
	return xpub.Identifier()[:4]
}

func (xpub XPubKey) CKDpub(i uint32) (XPubKey, error) {
	lim := uint32(1) << 31
	var data []byte
	if i >= lim {
		return XPubKey{}, fmt.Errorf("i > %d", lim)
	}

	// If not (normal child): let I = HMAC-SHA512(Key = cpar, Data = serP(Kpar) || ser32(i)).
	data = Secp256k1Compressed(xpub.PublicKey)
	data = binary.BigEndian.AppendUint32(data, i)

	hm := hmac.New(sha512.New, xpub.ChainCode)
	hm.Write(data)
	I := hm.Sum(nil)

	Il := I[:32]
	Ir := I[32:]

	IlNum := big.NewInt(0)
	IlNum.SetBytes(Il)
	if IlNum.Cmp(secp256k1Order) >= 0 {
		return XPubKey{}, fmt.Errorf("resulting key is greater than the order of Secp256K1")
	}

	IlPub := Secp256k1Pub(IlNum)

	childPub := Secp256k1Add(xpub.PublicKey, IlPub)

	return XPubKey{
		PubParent: &xpub,

		Depth: xpub.Depth + 1,
		Index: i,

		PublicKey: childPub,
		ChainCode: Ir,
	}, nil
}

func MasterPrivateKey(seed *Seed) (XPrivKey, error) {
	mac := hmac.New(sha512.New, []byte("Bitcoin seed"))
	mac.Write(seed.Seed)
	hash := mac.Sum(nil)
	il := hash[:32]
	ir := hash[32:]

	zero := big.NewInt(0)

	ilInt := big.NewInt(0)
	ilInt = ilInt.SetBytes(il)
	if ilInt.Cmp(zero) == 0 {
		return XPrivKey{}, fmt.Errorf("the derived master private key results in 0")
	}

	if ilInt.Cmp(secp256k1Order) >= 0 {
		return XPrivKey{}, fmt.Errorf(
			"the derived master private key results in a " +
				"value greater or equal than the order of secp256k1")
	}

	pk := big.NewInt(0)
	pk.SetBytes(il)
	return XPrivKey{
		Parent: nil,
		Depth:  0,
		Index:  0,

		PrivateKey: pk,
		ChainCode:  ir,
	}, nil
}
