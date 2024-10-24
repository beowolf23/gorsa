package main

import (
	"crypto/rand"
	"fmt"
	"math/big"
)

type CryptoAlgorithm interface {
	KeyGen(bits int)
	Encrypt(plaintext *big.Int) *big.Int
	Decrypt(ciphertext *big.Int) *big.Int
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
	p, q := GeneratePrimeNumbers(bits)
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

func (rsa *RSA) Encrypt(plaintext *big.Int) *big.Int {
	ciphertext := new(big.Int).Exp(plaintext, rsa.keyPair.e, rsa.keyPair.n)
	return ciphertext
}

func (rsa *RSA) Decrypt(ciphertext *big.Int) *big.Int {
	plaintext := new(big.Int).Exp(ciphertext, rsa.keyPair.d, rsa.keyPair.n)
	return plaintext
}

func (rsa *RSA) GetKeyInfo() {
	fmt.Println("Modulus: ", rsa.keyPair.n)
	fmt.Println("Prime 2: ", rsa.keyPair.q)
	fmt.Println("Prime 1: ", rsa.keyPair.p)
	fmt.Println("Public exponent: ", rsa.keyPair.e)
	fmt.Println("Private exponent: ", rsa.keyPair.d)
}

func GeneratePrimeNumbers(bits int) (*big.Int, *big.Int) {
	p, _ := rand.Prime(rand.Reader, bits)
	q, _ := rand.Prime(rand.Reader, bits)
	return p, q
}

func ConvertStringToBigInt(text string) *big.Int {
	bytes := []byte(text)
	n := new(big.Int).SetBytes(bytes)
	return n
}

func ConvertBigIntToString(num *big.Int) string {
	return string(num.Bytes())
}

func main() {

	var bits int = 512
	rsa := new(RSA)
	rsa.KeyGen(bits)
	ciphertext := rsa.Encrypt(ConvertStringToBigInt("something in here"))
	plaintext := ConvertBigIntToString(rsa.Decrypt(ciphertext))
	fmt.Println(plaintext)
}
