package userlib

import (
	"errors"
	"fmt"
	"log"
	"strings"
	"time"

	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha512"

	"golang.org/x/crypto/sha3"

	. "github.com/onsi/ginkgo"

	"github.com/google/uuid"
)

// More info about the UUID type:
// github.com/google/uuid
type UUID = uuid.UUID

// AES block size (in bytes)
// https://pkg.go.dev/crypto/aes
const AESBlockSizeBytes = aes.BlockSize

// AES key size (in bytes)
const AESKeySizeBytes = 16

// Output size (in bytes) of Hash, HMAC, and HashKDF
const HashSizeBytes = sha512.Size

const rsaKeySizeBits = 2048

// UUID size (in bytes)
const UUIDSizeBytes = 16

/*
********************************************
**         Global Definitions            ***
********************************************

Here, we declare a number of global data
structures and types: Keystore/Datastore,
Public/Private Key structures, etc.
*/

type PublicKeyType struct {
	KeyType string
	PubKey  rsa.PublicKey
}

type PrivateKeyType struct {
	KeyType string
	PrivKey rsa.PrivateKey
}

// Bandwidth tracker (for measuring efficient append)
// var datastoreBandwidth = 0
var datastoreBandwidth map[int]int = make(map[int]int)

// Datastore and Keystore variables

var datastore map[int]map[UUID][]byte = make(map[int]map[UUID][]byte)
var keystore map[int]map[string]PublicKeyType = make(map[int]map[string]PublicKeyType)

// var datastore map[UUID][]byte = make(map[UUID][]byte)
// var keystore map[string]PublicKeyType = make(map[string]PublicKeyType)

type DatastoreEntry struct {
	UUID  string
	Value string
}

/*
********************************************
**           Datastore Functions          **
**       DatastoreSet, DatastoreGet,      **
**     DatastoreDelete, DatastoreClear    **
********************************************
 */

func keystorePrologue(pid int) {
	if _, ok := keystore[pid]; !ok {
		keystore[pid] = make(map[string]PublicKeyType)
	}
}

func datastorePrologue(pid int) {
	if _, ok := datastore[pid]; !ok {
		datastore[pid] = make(map[UUID][]byte)
	}
	if _, ok := datastoreBandwidth[pid]; !ok {
		datastoreBandwidth[pid] = 0
	}
}

// Sets the value in the datastore
func datastoreSet(key UUID, value []byte) {
	pid := CurrentSpecReport().LineNumber()
	datastorePrologue(pid)

	// Update bandwidth tracker
	datastoreBandwidth[pid] += len(value)

	foo := make([]byte, len(value))
	copy(foo, value)

	datastore[pid][key] = foo
}

var DatastoreSet = datastoreSet

// Returns the value if it exists
func datastoreGet(key UUID) (value []byte, ok bool) {
	pid := CurrentSpecReport().LineNumber()
	datastorePrologue(pid)

	value, ok = datastore[pid][key]
	if ok && value != nil {
		// Update bandwidth tracker
		datastoreBandwidth[pid] += len(value)

		foo := make([]byte, len(value))
		copy(foo, value)
		return foo, ok
	}
	return
}

var DatastoreGet = datastoreGet

// Deletes a key
func datastoreDelete(key UUID) {
	pid := CurrentSpecReport().LineNumber()
	datastorePrologue(pid)
	delete(datastore[pid], key)
}

var DatastoreDelete = datastoreDelete

// Use this in testing to reset the datastore to empty
func datastoreClear() {
	pid := CurrentSpecReport().LineNumber()
	fmt.Printf("Clearing datastore shard: %d\n", pid)
	datastorePrologue(pid)
	for k := range datastore[pid] {
		delete(datastore[pid], k)
	}
}

var DatastoreClear = datastoreClear

func DatastoreResetBandwidth() {
	pid := CurrentSpecReport().LineNumber()
	datastorePrologue(pid)
	datastoreBandwidth[pid] = 0
}

// Get number of bytes uploaded/downloaded to/from Datastore.
func DatastoreGetBandwidth() int {
	pid := CurrentSpecReport().LineNumber()
	datastorePrologue(pid)
	return datastoreBandwidth[pid]
}

// Use this in testing to reset the keystore to empty
func keystoreClear() {
	pid := CurrentSpecReport().LineNumber()
	keystorePrologue(pid)

	for k := range keystore[pid] {
		delete(keystore[pid], k)
	}
}

var KeystoreClear = keystoreClear

// Sets the value in the keystore
func keystoreSet(key string, value PublicKeyType) error {
	pid := CurrentSpecReport().LineNumber()
	keystorePrologue(pid)

	_, present := keystore[pid][key]
	if present {
		return errors.New("entry in keystore has been taken")
	}

	keystore[pid][key] = value
	return nil
}

var KeystoreSet = keystoreSet

// Returns the value if it exists
func keystoreGet(key string) (value PublicKeyType, ok bool) {
	pid := CurrentSpecReport().LineNumber()
	keystorePrologue(pid)
	value, ok = keystore[pid][key]
	return
}

var KeystoreGet = keystoreGet

// Use this in testing to get the underlying map if you want
// to play with the datastore.
func DatastoreGetMap() map[UUID][]byte {
	pid := CurrentSpecReport().LineNumber()
	datastorePrologue(pid)
	return datastore[pid]
}

// Use this in testing to get the underlying map if you want
// to play with the keystore.
func KeystoreGetMap() map[string]PublicKeyType {
	pid := CurrentSpecReport().LineNumber()
	keystorePrologue(pid)
	return keystore[pid]
}

/*
********************************************
**         Random Byte Generator         ***
********************************************

This method may help with random byte generation.
*/

// RandomBytes. Helper function: Returns a byte slice of the specified
// size filled with random data
func randomBytes(size int) (data []byte) {
	data = make([]byte, size)
	_, err := rand.Read(data)
	if err != nil {
		panic(err)
	}
	return
}

var RandomBytes = randomBytes

/*
********************************************
**               KDF                      **
**            Argon2Key                   **
********************************************
 */

// Argon2:  Automatically chooses a decent combination of iterations and memory
// Use this to generate a key from a password
func argon2Key(password []byte, salt []byte, keyLen uint32) []byte {
	// NOTE: THIS IS MONKEY PATCHED FOR FAST TESTING
	actualLen := keyLen
	if keyLen < 64 {
		actualLen = 64
	}
	h := make([]byte, actualLen)
	hash := []byte(fmt.Sprintf("%v %v", password, salt))
	sha3.ShakeSum256(h, hash)
	return h[:keyLen]
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
	// Converting from [64]byte array to []byte slice
	result := hashVal[:]
	return result
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
		return nil, errors.New("using a non-pke key for pke")
	}

	ciphertext, err := rsa.EncryptOAEP(sha512.New(), rand.Reader, RSAPubKey, plaintext, nil)

	if err != nil {
		return nil, err
	}

	return ciphertext, nil
}

var PKEEnc = pkeEnc

// Decrypts a byte stream encrypted with RSA-OAEP/sha512
func pkeDec(dk PKEDecKey, ciphertext []byte) ([]byte, error) {
	RSAPrivKey := &dk.PrivKey

	if dk.KeyType != "PKE" {
		return nil, errors.New("using a non-pke for pke")
	}

	decryption, err := rsa.DecryptOAEP(sha512.New(), rand.Reader, RSAPrivKey, ciphertext, nil)
	if err != nil {
		return nil, err
	}

	return decryption, nil
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
		return nil, errors.New("using a non-ds key for ds")
	}

	hashed := sha512.Sum512(msg)

	sig, err := rsa.SignPKCS1v15(rand.Reader, RSAPrivKey, crypto.SHA512, hashed[:])
	if err != nil {
		return nil, err
	}

	return sig, nil
}

var DSSign = dsSign

// Verifies a signature signed with SHA256 and PKCS1v15
func dsVerify(vk DSVerifyKey, msg []byte, sig []byte) error {
	RSAPubKey := &vk.PubKey

	if vk.KeyType != "DS" {
		return errors.New("using a non-ds key for ds")
	}

	hashed := sha512.Sum512(msg)

	err := rsa.VerifyPKCS1v15(RSAPubKey, crypto.SHA512, hashed[:], sig)

	if err != nil {
		return err
	} else {
		return nil
	}
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
	if len(key) != 16 { // && len(key) != 24 && len(key) != 32 {
		return nil, errors.New("input as key for hmac should be a 16-byte key")
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
	if len(key) != 16 {
		return nil, errors.New("input as key for HashKDF should be a 16-byte key")
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

// Encrypts a byte slice with AES-CTR
// Length of iv should be == AESBlockSizeBytes
func symEnc(key []byte, iv []byte, plaintext []byte) []byte {
	if len(iv) != AESBlockSizeBytes {
		panic("IV length not equal to AESBlockSizeBytes")
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}

	// The IV needs to be unique, but not secret. Therefore it's common to
	// include it at the beginning of the ciphertext.
	ciphertext := make([]byte, AESBlockSizeBytes+len(plaintext))

	mode := cipher.NewCTR(block, iv)
	mode.XORKeyStream(ciphertext[AESBlockSizeBytes:], plaintext)
	copy(ciphertext[:AESBlockSizeBytes], iv)

	return ciphertext
}

var SymEnc = symEnc

// Decrypts a ciphertext encrypted with AES-CTR
func symDec(key []byte, ciphertext []byte) []byte {
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}

	if len(ciphertext) < AESBlockSizeBytes {
		panic("ciphertext too short")
	}

	iv := ciphertext[:AESBlockSizeBytes]
	ciphertext = ciphertext[AESBlockSizeBytes:]

	plaintext := make([]byte, len(ciphertext))

	mode := cipher.NewCTR(block, iv)
	mode.XORKeyStream(plaintext, ciphertext)

	return plaintext
}

var SymDec = symDec

// If DebugOutput is set to false, then DebugMsg will suppress output.
var DebugOutput = true

// Feel free to use userlib.DebugMsg(...) to print strings to the console.
func DebugMsg(format string, args ...interface{}) {
	if DebugOutput {
		msg := fmt.Sprintf("%v ", time.Now().Format("15:04:05.00000"))
		log.Printf(msg+strings.Trim(format, "\r\n ")+"\n", args...)
	}
}

// Deterministically converts a byte slice to a string of length 128 that is
// suitable to use as the storage key in a map and marshal/unmarshal to/from
// JSON.
func MapKeyFromBytes(data []byte) (truncated string) {
	return fmt.Sprintf("%x", sha512.Sum512(data))
}
