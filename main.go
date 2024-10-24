package main

import (
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"math/big"
)

// CryptoAlgorithm interface defines the methods required for a cryptographic algorithm
type CryptoAlgorithm interface {
	KeyGen(bits int)                                       // Generates a key pair
	Encrypt(plaintext *big.Int) *big.Int                   // Encrypts the plaintext and returns the ciphertext
	Decrypt(ciphertext *big.Int) *big.Int                  // Decrypts the ciphertext and returns the plaintext
	GetKeyInfo()                                           // Prints key information (public and private keys)
	SignMessage(message []byte) []byte                     // Signs a message and returns the signature
	VerifySignature(message []byte, signature []byte) bool // Verifies the signature for the message
}

// RSA struct represents the RSA algorithm, which uses a KeyPair for encryption and signing
type RSA struct {
	keyPair *KeyPair
}

// KeyPair struct stores the RSA key components: primes (p, q), modulus (n), public exponent (e), and private exponent (d)
type KeyPair struct {
	n *big.Int // Modulus (n = p * q)
	p *big.Int // Prime 1 (p)
	q *big.Int // Prime 2 (q)
	e *big.Int // Public exponent
	d *big.Int // Private exponent
}

// KeyGen generates RSA key pair based on the bit size and stores them in the RSA keyPair
func (rsa *RSA) KeyGen(bits int) error {
	// Generate two large prime numbers, p and q
	p, q := GeneratePrimeNumbers(bits)

	// Compute n = p * q
	n := new(big.Int).Mul(p, q)

	// Compute φ(n) = (p-1)(q-1)
	one := big.NewInt(1)
	pMinus1 := new(big.Int).Sub(p, one)
	qMinus1 := new(big.Int).Sub(q, one)
	phi := new(big.Int).Mul(pMinus1, qMinus1)

	// Set public exponent e (commonly 65537)
	e := big.NewInt(65537)

	// Calculate private exponent d (modular inverse of e mod φ(n))
	d := new(big.Int).ModInverse(e, phi)

	// Store the values into the keyPair struct
	var keyPair *KeyPair = new(KeyPair)
	keyPair.q = q
	keyPair.p = p
	keyPair.n = n
	keyPair.e = e
	keyPair.d = d

	// Assign the generated key pair to the RSA struct
	rsa.keyPair = keyPair

	return nil
}

// Encrypt encrypts a plaintext message using the public key (n, e)
func (rsa *RSA) Encrypt(plaintext *big.Int) *big.Int {
	// ciphertext = plaintext^e mod n
	ciphertext := new(big.Int).Exp(plaintext, rsa.keyPair.e, rsa.keyPair.n)
	return ciphertext
}

// Decrypt decrypts a ciphertext using the private key (n, d)
func (rsa *RSA) Decrypt(ciphertext *big.Int) *big.Int {
	// plaintext = ciphertext^d mod n
	plaintext := new(big.Int).Exp(ciphertext, rsa.keyPair.d, rsa.keyPair.n)
	return plaintext
}

// GetKeyInfo prints the RSA key information: modulus, primes, public and private exponents
func (rsa *RSA) GetKeyInfo() {
	fmt.Println("Modulus: ", rsa.keyPair.n)
	fmt.Println("Prime 2: ", rsa.keyPair.q)
	fmt.Println("Prime 1: ", rsa.keyPair.p)
	fmt.Println("Public exponent: ", rsa.keyPair.e)
	fmt.Println("Private exponent: ", rsa.keyPair.d)
}

// SignMessage generates a digital signature by signing the hash of a message using the private key
func (rsa *RSA) SignMessage(message []byte) []byte {
	// Step 1: Hash the message using SHA-256 to get a fixed-length digest
	h := ComputeSha256(message)
	H := ByteArrayToBigInt(h)

	// Step 2: Create the signature by encrypting the hash using the private key (d, n)
	// The signature is computed as: signature = H^d mod n
	// This ensures that only the holder of the private key can generate this signature
	s := new(big.Int).Exp(H, rsa.keyPair.d, rsa.keyPair.n)

	// Step 3: Return the signature as a byte array
	return s.Bytes()
}

// VerifySignature verifies the digital signature of a message using the public key
func (rsa *RSA) VerifySignature(message []byte, signature []byte) bool {
	// Step 1: Hash the original message using SHA-256 to get the expected hash value
	h := ComputeSha256(message)
	hashedMessage := ByteArrayToBigInt(h)

	// Step 2: Decrypt the signature using the public key (e, n)
	// Decrypt the signature by performing: hashFromSignature = signature^e mod n
	// This retrieves the hash that was originally encrypted with the private key during signing
	hashFromSignature := new(big.Int).Exp(ByteArrayToBigInt(signature), rsa.keyPair.e, rsa.keyPair.n)

	// Step 3: Compare the hash from the signature with the hash of the original message
	// If the two hashes match, it means the signature is valid (i.e., it was created using the private key)
	if hashedMessage.Cmp(hashFromSignature) != 0 {
		// The signature is invalid if the hashes do not match
		return false
	}

	// The signature is valid if the hashes match
	return true
}

// ComputeSha256 computes the SHA256 hash of a given message
func ComputeSha256(message []byte) []byte {
	sha := sha256.New()
	sha.Write(message)
	return sha.Sum(nil) // Returns the SHA256 hash as a byte array
}

// ByteArrayToBigInt converts a byte array into a big.Int
func ByteArrayToBigInt(message []byte) *big.Int {
	return new(big.Int).SetBytes(message)
}

// GeneratePrimeNumbers generates two large prime numbers with the specified number of bits
func GeneratePrimeNumbers(bits int) (*big.Int, *big.Int) {
	p, _ := rand.Prime(rand.Reader, bits)
	q, _ := rand.Prime(rand.Reader, bits)
	return p, q
}

// ConvertStringToBigInt converts a string into a big.Int by converting the string to bytes and then to a big.Int
func ConvertStringToBigInt(text string) *big.Int {
	bytes := []byte(text)
	n := new(big.Int).SetBytes(bytes)
	return n
}

// ConvertBigIntToString converts a big.Int back into a string
func ConvertBigIntToString(num *big.Int) string {
	return string(num.Bytes())
}

func main() {
	// Bit size for RSA key generation
	var bits int = 512

	// Initialize RSA and generate the key pair
	rsa := new(RSA)
	rsa.KeyGen(bits)

	// Example message for signing
	message := []byte("message")

	// Sign the message
	signature := rsa.SignMessage(message)
	fmt.Printf("The signature is: %x\n", signature)

	// Verify the signature
	isValid := rsa.VerifySignature(message, signature)
	fmt.Println("Is the signature valid? ", isValid)
}
