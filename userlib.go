package userlib

import (
	"errors"
	"fmt"
	"log"
	"strings"
	"time"

	"io"

	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha512"

	"github.com/google/uuid"
	"golang.org/x/crypto/argon2"
)

type UUID = uuid.UUID

// RSA key size (in bits)
const rsaKeySizeBits = 2048

// AES block size (in bytes)
const AESBlockSizeBytes = aes.BlockSize

// AES key size (in bytes)
const AESKeySizeBytes = 16

// Output size (in bytes) of Hash and MAC
const HashSizeBytes = sha512.Size

// Debug print true/false
var DebugPrint = false

// DebugMsg. Helper function: Does formatted printing to stderr if
// the DebugPrint global is set.  All our testing ignores stderr,
// so feel free to use this for any sort of testing you want.

func SetDebugStatus(status bool) {
	DebugPrint = status
}

func DebugMsg(format string, args ...interface{}) {
	if DebugPrint {
		msg := fmt.Sprintf("%v ", time.Now().Format("15:04:05.00000"))
		log.Printf(msg+strings.Trim(format, "\r\n ")+"\n", args...)
	}
}

// RandomBytes. Helper function: Returns a byte slice of the specified
// size filled with random data
func randomBytes(size int) (data []byte) {
	data = make([]byte, size)
	if _, err := io.ReadFull(rand.Reader, data); err != nil {
		panic(err)
	}
	return
}

// Can replace this function for development/testing
var RandomBytes = randomBytes

type PublicKeyType struct {
	KeyType string
	PubKey  rsa.PublicKey
}

type PrivateKeyType struct {
	KeyType string
	PrivKey rsa.PrivateKey
}

// Bandwidth tracker (for measuring efficient append)
var datastoreBandwidth = 0

// Datastore and Keystore variables
var datastore map[UUID][]byte = make(map[UUID][]byte)
var keystore map[string]PublicKeyType = make(map[string]PublicKeyType)

/*
********************************************
**           Datastore Functions          **
**       DatastoreSet, DatastoreGet,      **
**     DatastoreDelete, DatastoreClear    **
********************************************
 */

// Sets the value in the datastore
func datastoreSet(key UUID, value []byte) {
	// Update bandwidth tracker
	datastoreBandwidth += len(value)

	foo := make([]byte, len(value))
	copy(foo, value)

	datastore[key] = foo
}

var DatastoreSet = datastoreSet

// Returns the value if it exists
func datastoreGet(key UUID) (value []byte, ok bool) {
	value, ok = datastore[key]
	if ok && value != nil {
		// Update bandwidth tracker
		datastoreBandwidth += len(value)

		foo := make([]byte, len(value))
		copy(foo, value)
		return foo, ok
	}
	return
}

var DatastoreGet = datastoreGet

// Deletes a key
func datastoreDelete(key UUID) {
	delete(datastore, key)
}

var DatastoreDelete = datastoreDelete

// Use this in testing to reset the datastore to empty
func datastoreClear() {
	datastore = make(map[UUID][]byte)
}

var DatastoreClear = datastoreClear

func DatastoreResetBandwidth() {
	datastoreBandwidth = 0
}

// Get number of bytes uploaded/downloaded to/from Datastore.
func DatastoreGetBandwidth() int {
	return datastoreBandwidth
}

// Use this in testing to reset the keystore to empty
func keystoreClear() {
	keystore = make(map[string]PublicKeyType)
}

var KeystoreClear = keystoreClear

// Sets the value in the keystore
func keystoreSet(key string, value PublicKeyType) error {
	_, present := keystore[key]
	if present != false {
		return errors.New("That entry in the Keystore has been taken.")
	}

	keystore[key] = value
	return nil
}

var KeystoreSet = keystoreSet

// Returns the value if it exists
func keystoreGet(key string) (value PublicKeyType, ok bool) {
	value, ok = keystore[key]
	return
}

var KeystoreGet = keystoreGet

// Use this in testing to get the underlying map if you want
// to play with the datastore.
func DatastoreGetMap() map[UUID][]byte {
	return datastore
}

// Use this in testing to get the underlying map if you want
// to play with the keystore.
func KeystoreGetMap() map[string]PublicKeyType {
	return keystore
}

/*
********************************************
**               KDF                      **
**            Argon2Key                   **
********************************************
 */

// Argon2:  Automatically chooses a decent combination of iterations and memory
// Use this to generate a key from a password
func argon2Key(password []byte, salt []byte, keyLen uint32) []byte {
	return argon2.IDKey(password, salt, 1, 64*1024, 4, keyLen)
}

var Argon2Key = argon2Key

/*
********************************************
**               Hash                     **
**              SHA512                    **
********************************************
 */

// SHA512: Returns the checksum of data.
func hash(data []byte) []byte {
	hashVal := sha512.Sum512(data)
	return hashVal[:] // Converting from [64]byte array to []byte slice
}

// Hash returns a byte slice containing the SHA512 hash of the given byte slice.
var Hash = hash

/*
********************************************
**         Public Key Encryption          **
**       PKEKeyGen, PKEEnc, PKEDec        **
********************************************
 */

// Four structs to help you manage your different keys
// You should only have 1 of each struct
// keyType should be either:
//     "PKE": encryption
//     "DS": authentication and integrity

type PKEEncKey = PublicKeyType
type PKEDecKey = PrivateKeyType

type DSSignKey = PrivateKeyType
type DSVerifyKey = PublicKeyType

// Generates a key pair for public-key encryption via RSA
func pkeKeyGen() (PKEEncKey, PKEDecKey, error) {
	RSAPrivKey, err := rsa.GenerateKey(rand.Reader, rsaKeySizeBits)
	RSAPubKey := RSAPrivKey.PublicKey

	var PKEEncKeyRes PKEEncKey
	PKEEncKeyRes.KeyType = "PKE"
	PKEEncKeyRes.PubKey = RSAPubKey

	var PKEDecKeyRes PKEDecKey
	PKEDecKeyRes.KeyType = "PKE"
	PKEDecKeyRes.PrivKey = *RSAPrivKey

	return PKEEncKeyRes, PKEDecKeyRes, err
}

var PKEKeyGen = pkeKeyGen

// Encrypts a byte stream via RSA-OAEP with sha512 as hash
func pkeEnc(ek PKEEncKey, plaintext []byte) ([]byte, error) {
	RSAPubKey := &ek.PubKey

	if ek.KeyType != "PKE" {
		return nil, errors.New("Using a non-PKE key for PKE.")
	}

	ciphertext, err := rsa.EncryptOAEP(sha512.New(), rand.Reader, RSAPubKey, plaintext, nil)

	return ciphertext, err
}

var PKEEnc = pkeEnc

// Decrypts a byte stream encrypted with RSA-OAEP/sha512
func pkeDec(dk PKEDecKey, ciphertext []byte) ([]byte, error) {
	RSAPrivKey := &dk.PrivKey

	if dk.KeyType != "PKE" {
		return nil, errors.New("Using a non-PKE key for PKE.")
	}

	decryption, err := rsa.DecryptOAEP(sha512.New(), rand.Reader, RSAPrivKey, ciphertext, nil)

	return decryption, err
}

var PKEDec = pkeDec

/*
********************************************
**           Digital Signature            **
**       DSKeyGen, DSSign, DSVerify       **
********************************************
 */

// Generates a key pair for digital signature via RSA
func dsKeyGen() (DSSignKey, DSVerifyKey, error) {
	RSAPrivKey, err := rsa.GenerateKey(rand.Reader, rsaKeySizeBits)
	RSAPubKey := RSAPrivKey.PublicKey

	var DSSignKeyRes DSSignKey
	DSSignKeyRes.KeyType = "DS"
	DSSignKeyRes.PrivKey = *RSAPrivKey

	var DSVerifyKeyRes DSVerifyKey
	DSVerifyKeyRes.KeyType = "DS"
	DSVerifyKeyRes.PubKey = RSAPubKey

	return DSSignKeyRes, DSVerifyKeyRes, err
}

var DSKeyGen = dsKeyGen

// Signs a byte stream via SHA256 and PKCS1v15
func dsSign(sk DSSignKey, msg []byte) ([]byte, error) {
	RSAPrivKey := &sk.PrivKey

	if sk.KeyType != "DS" {
		return nil, errors.New("Using a non-DS key for DS.")
	}

	hashed := sha512.Sum512(msg)

	sig, err := rsa.SignPKCS1v15(rand.Reader, RSAPrivKey, crypto.SHA512, hashed[:])

	return sig, err
}

var DSSign = dsSign

// Verifies a signature signed with SHA256 and PKCS1v15
func dsVerify(vk DSVerifyKey, msg []byte, sig []byte) error {
	RSAPubKey := &vk.PubKey

	if vk.KeyType != "DS" {
		return errors.New("Using a non-DS key for DS.")
	}

	hashed := sha512.Sum512(msg)

	err := rsa.VerifyPKCS1v15(RSAPubKey, crypto.SHA512, hashed[:], sig)

	return err
}

var DSVerify = dsVerify

/*
********************************************
**                HMAC                    **
**         HMACEval, HMACEqual            **
********************************************
 */

// Evaluate the HMAC using sha512
func hmacEval(key []byte, msg []byte) ([]byte, error) {
	if len(key) != 16 && len(key) != 24 && len(key) != 32 {
		panic(errors.New("The input as key for HMAC should be a 16-byte key."))
	}

	mac := hmac.New(sha512.New, key)
	mac.Write(msg)
	res := mac.Sum(nil)
	return res, nil
}

var HMACEval = hmacEval

// Equals comparison for hashes/MACs
// Does NOT leak timing.
func hmacEqual(a []byte, b []byte) bool {
	return hmac.Equal(a, b)
}

var HMACEqual = hmacEqual

/*
********************************************
**   Hash-Based Key Derivation Function   **
**                 HashKDF                **
********************************************
 */

// HashKDF (uses the same algorithm as hmacEval, wrapped to provide a useful
// error)
func hashKDF(key []byte, msg []byte) ([]byte, error) {
	if len(key) != 16 && len(key) != 24 && len(key) != 32 {
		panic(errors.New("The input as key for HashKDF should be a 16-byte key."))
	}

	mac := hmac.New(sha512.New, key)
	mac.Write(msg)
	res := mac.Sum(nil)
	return res, nil
}

var HashKDF = hashKDF

/*
********************************************
**        Symmetric Encryption            **
**           SymEnc, SymDec               **
********************************************
 */

// Encrypts a byte slice with AES-CBC
// Length of iv should be == AESBlockSizeBytes
// Length of plaintext should be divisible by AESBlockSize
func symEnc(key []byte, iv []byte, plaintext []byte) []byte {
	if len(iv) != AESBlockSizeBytes {
		panic("IV length not equal to AESBlockSizeBytes")
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}

	if len(plaintext)%AESBlockSizeBytes != 0 {
		panic("plaintext is not a multiple of the block size")
	}

	ciphertext := make([]byte, AESBlockSizeBytes+len(plaintext))

	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ciphertext[AESBlockSizeBytes:], plaintext)
	copy(ciphertext[:AESBlockSizeBytes], iv)
	// example taken here https://golang.org/pkg/crypto/cipher/#NewCBCEncrypter

	return ciphertext
}

var SymEnc = symEnc

// Decrypts a ciphertext encrypted with AES-CTR
func symDec(key []byte, ciphertext []byte) []byte {
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}

	iv := ciphertext[:AESBlockSizeBytes]
	plaintext := make([]byte, len(ciphertext)-AESBlockSizeBytes)

	if len(plaintext)%AESBlockSizeBytes != 0 {
		panic("ciphertext is not a multiple of the block size")
	}

	mode := cipher.NewCBCDecrypter(block, iv)

	// usage adapted from this page https://golang.org/pkg/crypto/cipher/#NewCBCEncrypter
	mode.CryptBlocks(plaintext, ciphertext[AESBlockSizeBytes:])

	return plaintext
}

var SymDec = symDec
