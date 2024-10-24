package main

import (
	"crypto/rand"
	"fmt"
	"math/big"
)

type CryptoAlgorithm interface {
	KeyGen(bits int)
	Encrypt(plaintext *big.Int)
	Decrypt(ciphertext *big.Int)
	GetKeyInfo()
}

type RSA struct {
	keyPair *KeyPair
}

type KeyPair struct {
	n *big.Int // Modulus
	p *big.Int // Prime 1
	q *big.Int // Prime 2
	e *big.Int // Public Exponent
	d *big.Int // Private Exponent
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

	var keyPair *KeyPair = new(KeyPair)

	keyPair.q = q
	keyPair.p = p
	keyPair.n = n
	keyPair.e = e
	keyPair.d = d

	rsa.keyPair = keyPair

	return nil
}

func (rsa *RSA) GetKeyInfo() {
	fmt.Println("Modulus: ", rsa.keyPair.n)
	fmt.Println("Prime 2: ", rsa.keyPair.q)
	fmt.Println("Prime 1: ", rsa.keyPair.p)
	fmt.Println("Public exponent: ", rsa.keyPair.e)
	fmt.Println("Private exponent: ", rsa.keyPair.d)
}

func generatePrimeNumbers(bits int) (*big.Int, *big.Int) {
	p, _ := rand.Prime(rand.Reader, bits)
	q, _ := rand.Prime(rand.Reader, bits)
	return p, q
}

func main() {

	var bits int = 512

	rsa := new(RSA)
	rsa.KeyGen(bits)
	rsa.GetKeyInfo()
}
