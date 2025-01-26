package btools

import (
	"crypto/sha256"
	"math/big"

	"golang.org/x/crypto/ripemd160"
)

/*
C:	y^2 = x^3 + 7   (mod p)

p0 = (x0, y0)
p1 = (x1, y1)
p2 = p0 + p1 = (x2, y2)


y = sl(x) = m*x + b
b = y0 - m*x0

(m*x+b)^2 = x^3 + 7

(x-x0)*(x-x1)*(x-x2) = (x^3) - (m^2)*(x^2) - (2*m*b)*x + 7 - (b^2)

(x-x0)*(x-x1)*(x-x2)
(x^2 - x*(x0+x1) + x0*x1)*(x-x2)
x^3 - x2*(x^2) - (x0+x1)*(x^2) + ((x0+x1)*x2+x0*x1)*x - x0*x1*x2


(x^3) - (x0+x1+x2)*(x^2) + ((x0+x1)*x2+x0*x1)*x - x0*x1*x2
==
(x^3) - (m^2)*(x^2)      - (2*m*b)*x            + 7 - (b^2)


==>

m^2 = x0+x1+x2 ==> x2 = m^2-x0-x1
y2 = m*x2 + b

---------------- p0.x != p1.x ----------------
---------------- p0.x != p1.x ----------------
---------------- p0.x != p1.x ----------------
y = sl(x) = m*x + b

m = (y0 - y1)/(x0 - x1)
b = y0 - m*x0

---------------- p0 == p1 ----------------
---------------- p0 == p1 ----------------
---------------- p0 == p1 ----------------
y = tl(x) = m*x + b

(2*y)*m = 3*(x^2)
m = 3*(x^2)/(2*y)

tl(x0) = y0 = m*x0 + b
b = y0 - m*x0

---------------- p0.x == p1.x && p0.y == -p1.y ----------------
---------------- p0.x == p1.x && p0.y == -p1.y ----------------
---------------- p0.x == p1.x && p0.y == -p1.y ----------------
(0, 0)
*/

var secp256k1Order *big.Int
var p *big.Int

func init() {
	secp256k1Order = big.NewInt(0)
	secp256k1Order.SetString("0XFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 0)

	p = big.NewInt(0)
	p.SetString("115792089237316195423570985008687907853269984665640564039457584007908834671663", 10)
}

func Secp256k1Add(x0, y0, x1, y1 *big.Int) (*big.Int, *big.Int) {
	zero := big.NewInt(0)
	if x0.Cmp(zero) == 0 && y0.Cmp(zero) == 0 {
		x2 := big.NewInt(0)
		x2.Add(x2, x1)

		y2 := big.NewInt(0)
		y2.Add(y2, y1)

		return x2, y2
	}

	if x1.Cmp(zero) == 0 && y1.Cmp(zero) == 0 {
		x2 := big.NewInt(0)
		x2.Add(x2, x0)

		y2 := big.NewInt(0)
		y2.Add(y2, y0)

		return x2, y2
	}

	negY1 := big.NewInt(0)
	negY1.Sub(secp256k1Order, y1)
	if x0.Cmp(x1) == 0 && y0.Cmp(negY1) == 0 {
		return big.NewInt(0), big.NewInt(0)
	}

	if x0.Cmp(x1) == 0 && y0.Cmp(y1) == 0 {
		/*
			y = tl(x) = m*x + b

			(2*y)*m = 3*(x^2)
			m = 3*(x^2)/(2*y)

			tl(x0) = y0 = m*x0 + b
			b = y0 - m*x0

			m^2 = x0+x1+x2 ==> x2 = m^2-x0-x1
			y2 = m*x2 + b
		*/

		if y0.Cmp(zero) == 0 {
			return big.NewInt(0), big.NewInt(0)
		}

		denom := big.NewInt(2)
		denom.Mul(denom, y0).Mod(denom, p)
		denom.ModInverse(denom, p)

		m := big.NewInt(3)
		m.Mul(m, x0).Mod(m, p)
		m.Mul(m, x0).Mod(m, p)
		m.Mul(m, denom).Mod(m, p)

		mx0 := big.NewInt(0)
		mx0.Add(mx0, m).Mul(mx0, x0).Mod(mx0, p)

		b := big.NewInt(0)
		b.Add(b, y0).Sub(b, mx0).Mod(b, p)

		x2 := big.NewInt(0)
		x2.Add(x2, m).Mul(x2, m).Sub(x2, x0).Sub(x2, x0).Mod(x2, p)

		y2 := big.NewInt(0)
		y2.Add(y2, m).Mul(y2, x2).Add(y2, b).Mod(y2, p)

		y2.Sub(p, y2)

		return x2, y2
	}

	/*
		y = sl(x) = m*x + b

		m = (y0 - y1)/(x0 - x1)
		b = y0 - m*x0

			m^2 = x0+x1+x2 ==> x2 = m^2-x0-x1
			y2 = m*x2 + b
	*/
	denom := big.NewInt(0)
	denom.Add(denom, x0).Sub(denom, x1).ModInverse(denom, p)
	m := big.NewInt(0)
	m.Add(m, y0).Sub(m, y1).Mul(m, denom).Mod(m, p)

	mx0 := big.NewInt(0)
	mx0.Add(mx0, m).Mul(mx0, x0).Mod(mx0, p)

	b := big.NewInt(0)
	b.Add(b, y0).Mod(b, p)
	b.Sub(b, mx0).Mod(b, p)

	x2 := big.NewInt(0)
	x2.Add(x2, m).Mul(x2, m).Sub(x2, x0).Sub(x2, x1).Mod(x2, p)

	y2 := big.NewInt(0)
	y2.Add(y2, m).Mul(y2, x2).Add(y2, b).Mod(y2, p)

	y2.Sub(p, y2)

	return x2, y2
}

func Secp256k1Mul(n, x0, y0 *big.Int) (*big.Int, *big.Int) {
	xr := big.NewInt(0)
	yr := big.NewInt(0)

	bytes := n.Bytes()
	for _, b := range bytes {
		for range 8 {
			bit := (0b10000000 & b) >> 7
			b = b << 1

			xr, yr = Secp256k1Add(xr, yr, xr, yr)
			if bit == 1 {
				xr, yr = Secp256k1Add(xr, yr, x0, y0)
			}
		}
	}
	return xr, yr
}

func Secp256k1Compressed(x, y *big.Int) []byte {
	result := make([]byte, 33)
	result[0] = 0x03

	xBytes := x.Bytes()
	copy(result[1:], xBytes)

	parity := big.NewInt(0)
	parity.Mod(y, big.NewInt(2))

	if parity.Cmp(big.NewInt(0)) == 0 {
		result[0] = 0x02
	}

	return result
}

func Secp256k1Pub(k *big.Int) (*big.Int, *big.Int) {
	gx := big.NewInt(0)
	gx.SetString("0X79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798", 0)

	gy := big.NewInt(0)
	gy.SetString("0X483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8", 0)

	return Secp256k1Mul(k, gx, gy)
}

func Secp256k1Identifier(k *big.Int) []byte {
	xPub, yPub := Secp256k1Pub(k)
	pubComp := Secp256k1Compressed(xPub, yPub)
	hash := sha256.Sum256(pubComp)
	ripe := ripemd160.New()
	ripe.Write(hash[:])

	return ripe.Sum(nil)
}

func Secp256k1Fingerprint(k *big.Int) []byte {
	return Secp256k1Identifier(k)[:4]
}
