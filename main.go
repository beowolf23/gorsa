package main

import (
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"math/big"
)

type CryptoAlgorithm interface {
	KeyGen(bits int)
	Encrypt(plaintext *big.Int) *big.Int
	Decrypt(ciphertext *big.Int) *big.Int
	GetKeyInfo()
	SignMessage(message []byte) []byte
	VerifySignature(message []byte, signature []byte) bool
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

func (rsa *RSA) SignMessage(message []byte) []byte {

	// compute the sha256 hash and convert to big int
	h := ComputeSha256(message)
	H := ByteArrayToBigInt(h)

	// encrypt H with the private key to calculate the signature
	s := new(big.Int).Exp(H, rsa.keyPair.d, rsa.keyPair.n)

	return s.Bytes()
}

func (rsa *RSA) VerifySignature(message []byte, signature []byte) bool {

	// compute the sha256 hash and convert to big int
	h := ComputeSha256(message)
	// H is the original hash of the message which needs
	// to be compared with the hash resulted from decrypting
	// the signature
	hashedMessage := ByteArrayToBigInt(h)

	// decrypt the signature with the public key to find the hash
	hashFromSignature := new(big.Int).Exp(ByteArrayToBigInt(signature), rsa.keyPair.e, rsa.keyPair.n)

	if hashedMessage.Cmp(hashFromSignature) != 0 {
		return false
	}
	return true
}

func ComputeSha256(message []byte) []byte {
	// compute the SHA256 of the message
	sha := sha256.New()
	sha.Write(message)
	return sha.Sum(nil)
}

func ByteArrayToBigInt(message []byte) *big.Int {
	return new(big.Int).SetBytes(message)
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

	// ciphertext := rsa.Encrypt(ConvertStringToBigInt("something in here"))
	// plaintext := ConvertBigIntToString(rsa.Decrypt(ciphertext))
	// fmt.Println(plaintext)
	//

	message := []byte("message")

	signature := rsa.SignMessage(message)
	fmt.Printf("The signature is: %x\n", signature)
	fmt.Println("Is the signature good? ", rsa.VerifySignature(message, signature))
}
