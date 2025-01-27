package btools

import (
	"math/big"
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
var g Point

func init() {
	secp256k1Order = big.NewInt(0)
	secp256k1Order.SetString("0XFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 0)

	p = big.NewInt(0)
	p.SetString("115792089237316195423570985008687907853269984665640564039457584007908834671663", 10)

	gx := big.NewInt(0)
	gx.SetString("0X79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798", 0)

	gy := big.NewInt(0)
	gy.SetString("0X483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8", 0)

	g = Point{X: gx, Y: gy}
}

type Point struct {
	X *big.Int
	Y *big.Int
}

var infinity Point = Point{
	X: big.NewInt(0),
	Y: big.NewInt(0),
}

func (p0 Point) Equal(p1 Point) bool {
	return p0.X != nil && p1.X != nil &&
		p0.X.Cmp(p1.X) == 0 &&
		p0.Y != nil && p1.Y != nil &&
		p0.Y.Cmp(p1.Y) == 0
}

func (p0 Point) Dup() Point {
	x := big.NewInt(0)
	x.Add(x, p0.X)

	y := big.NewInt(0)
	y.Add(y, p0.Y)

	return Point{X: x, Y: y}
}

func (p0 Point) Inverse() Point {
	inv := p0.Dup()
	inv.Y.Sub(p, inv.Y)

	return inv
}

func Secp256k1Add(p0, p1 Point) Point {
	zero := big.NewInt(0)
	if p0.Equal(infinity) {
		return p1.Dup()
	}

	if p1.Equal(infinity) {
		return p0.Dup()
	}

	invP1 := p1.Inverse()
	if p0.Equal(invP1) {
		return infinity.Dup()
	}

	if p0.Equal(p1) {
		/*
			y = tl(x) = m*x + b

			(2*y)*m = 3*(x^2)
			m = 3*(x^2)/(2*y)

			tl(x0) = y0 = m*x0 + b
			b = y0 - m*x0

			m^2 = x0+x1+x2 ==> x2 = m^2-x0-x1
			y2 = m*x2 + b
		*/

		if p0.Y.Cmp(zero) == 0 {
			return infinity.Dup()
		}

		denom := big.NewInt(2)
		denom.Mul(denom, p0.Y).Mod(denom, p)
		denom.ModInverse(denom, p)

		m := big.NewInt(3)
		m.Mul(m, p0.X).Mod(m, p)
		m.Mul(m, p0.X).Mod(m, p)
		m.Mul(m, denom).Mod(m, p)

		mx0 := big.NewInt(0)
		mx0.Add(mx0, m).Mul(mx0, p0.X).Mod(mx0, p)

		b := big.NewInt(0)
		b.Add(b, p0.Y).Sub(b, mx0).Mod(b, p)

		x2 := big.NewInt(0)
		x2.Add(x2, m).Mul(x2, m).Sub(x2, p0.X).Sub(x2, p0.X).Mod(x2, p)

		y2 := big.NewInt(0)
		y2.Add(y2, m).Mul(y2, x2).Add(y2, b).Mod(y2, p)

		y2.Sub(p, y2)

		return Point{X: x2, Y: y2}
	}

	/*
		y = sl(x) = m*x + b

		m = (y0 - y1)/(x0 - x1)
		b = y0 - m*x0

			m^2 = x0+x1+x2 ==> x2 = m^2-x0-x1
			y2 = m*x2 + b
	*/
	denom := big.NewInt(0)
	denom.Add(denom, p0.X).Sub(denom, p1.X).ModInverse(denom, p)
	m := big.NewInt(0)
	m.Add(m, p0.Y).Sub(m, p1.Y).Mul(m, denom).Mod(m, p)

	mx0 := big.NewInt(0)
	mx0.Add(mx0, m).Mul(mx0, p0.X).Mod(mx0, p)

	b := big.NewInt(0)
	b.Add(b, p0.Y).Mod(b, p)
	b.Sub(b, mx0).Mod(b, p)

	x2 := big.NewInt(0)
	x2.Add(x2, m).Mul(x2, m).Sub(x2, p0.X).Sub(x2, p1.X).Mod(x2, p)

	y2 := big.NewInt(0)
	y2.Add(y2, m).Mul(y2, x2).Add(y2, b).Mod(y2, p)

	y2.Sub(p, y2)

	return Point{X: x2, Y: y2}
}

func Secp256k1Mul(n *big.Int, p0 Point) Point {
	result := infinity.Dup()

	bytes := n.Bytes()
	for _, b := range bytes {
		for range 8 {
			bit := (0b10000000 & b) >> 7
			b = b << 1

			result = Secp256k1Add(result, result)
			if bit == 1 {
				result = Secp256k1Add(result, p0)
			}
		}
	}
	return result
}

func Secp256k1Compressed(p0 Point) []byte {
	result := make([]byte, 33)
	result[0] = 0x03

	xBytes := p0.X.Bytes()
	copy(result[1:], xBytes)

	parity := big.NewInt(0)
	parity.Mod(p0.Y, big.NewInt(2))

	if parity.Cmp(big.NewInt(0)) == 0 {
		result[0] = 0x02
	}

	return result
}

func Secp256k1Pub(k *big.Int) Point {
	return Secp256k1Mul(k, g)
}

func Infinity() Point {
	return infinity.Dup()
}
