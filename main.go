package main

import (
	"crypto/rand"
	"fmt"
	"math/big"
)

type RSA struct {
	n *big.Int // Modulus
	p *big.Int // Prime 1
	q *big.Int // Prime 2
	e *big.Int // Public Exponent
	d *big.Int // Private Exponent
}

type CryptoAlgorithm interface {
	KeyGen(bits int)
	Encrypt(plaintext *big.Int)
	Decrypt(ciphertext *big.Int)
	GetKeyInfo()
}

func (rsa *RSA) KeyGen(bits int) error {
	p, q := generatePrimeNumbers(bits)
	n := new(big.Int).Mul(p, q)

	one := big.NewInt(1)
	pMinus1 := new(big.Int).Sub(p, one)
	qMinus1 := new(big.Int).Sub(q, one)
	phi := new(big.Int).Mul(pMinus1, qMinus1)

	e := big.NewInt(65537)
	d := new(big.Int).ModInverse(e, phi)

	rsa.p = p
	rsa.q = q
	rsa.n = n
	rsa.e = e
	rsa.d = d

	return nil
}

func generatePrimeNumbers(bits int) (*big.Int, *big.Int) {
	p, _ := rand.Prime(rand.Reader, bits)
	q, _ := rand.Prime(rand.Reader, bits)
	return p, q
}

func key_bits_count() {

}

func main() {

	var bits int = 512
	p, q := generatePrimeNumbers(bits)

	fmt.Println("These are the prime numbers", p, q)
}
