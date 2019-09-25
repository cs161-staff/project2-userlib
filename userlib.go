package userlib

import (
    "fmt"
    "strings"
    "time"
    "errors"
    "log"

    "io"

    "crypto"
    "crypto/rsa"
    "crypto/hmac"
    "crypto/rand"
    "crypto/sha512"
    "crypto/aes"
    "crypto/cipher"

    "golang.org/x/crypto/argon2"
    "github.com/google/uuid"
)

type UUID = uuid.UUID

// RSA key size
var RSAKeySize = 2048

// AES block size and key size
var AESBlockSize = aes.BlockSize
var AESKeySize = 16

// Hash and MAC size
var HashSize = sha512.Size


// Debug print true/false
var DebugPrint = false

// DebugMsg. Helper function: Does formatted printing to stderr if
// the DebugPrint global is set.  All our testing ignores stderr,
// so feel free to use this for any sort of testing you want.

func SetDebugStatus(status bool){
	DebugPrint = status
}

func DebugMsg(format string, args ...interface{}) {
    if DebugPrint {
        msg := fmt.Sprintf("%v ", time.Now().Format("15:04:05.00000"))
        log.Printf(msg+strings.Trim(format, "\r\n ")+"\n", args...)
    }
}

// RandomBytes. Helper function: Returns a byte slice of the specificed
// size filled with random data
func RandomBytes(bytes int) (data []byte) {
    data = make([]byte, bytes)
    if _, err := io.ReadFull(rand.Reader, data); err != nil {
        panic(err)
    }
    return
}

type PublicKeyType struct {
    KeyType string
    PubKey rsa.PublicKey
}

type PrivateKeyType struct {
    KeyType string
    PrivKey rsa.PrivateKey
}

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
func DatastoreSet(key UUID, value []byte) {
    foo := make([]byte, len(value))
    copy(foo, value)

    datastore[key] = foo
}

// Returns the value if it exists
func DatastoreGet(key UUID) (value []byte, ok bool) {
    value, ok = datastore[key]
    if ok && value != nil {
        foo := make([]byte, len(value))
        copy(foo, value)
        return foo, ok
    }
    return
}

// Deletes a key
func DatastoreDelete(key UUID) {
    delete(datastore, key)
}

// Use this in testing to reset the datastore to empty
func DatastoreClear() {
    datastore = make(map[UUID][]byte)
}

// Use this in testing to reset the keystore to empty
func KeystoreClear() {
    keystore = make(map[string]PublicKeyType)
}

// Sets the value in the keystore
func KeystoreSet(key string, value PublicKeyType) error {
    _, present := keystore[key]
    if present != false {
       return errors.New("That entry in the Keystore has been taken.")
    }

    keystore[key] = value
    return nil
}

// Returns the value if it exists
func KeystoreGet(key string) (value PublicKeyType, ok bool) {
    value, ok = keystore[key]
    return
}

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
func PKEKeyGen() (PKEEncKey, PKEDecKey, error) {
    RSAPrivKey, err := rsa.GenerateKey(rand.Reader, RSAKeySize)
    RSAPubKey := RSAPrivKey.PublicKey

    var PKEEncKeyRes PKEEncKey
    PKEEncKeyRes.KeyType = "PKE"
    PKEEncKeyRes.PubKey = RSAPubKey

    var PKEDecKeyRes PKEDecKey
    PKEDecKeyRes.KeyType = "PKE"
    PKEDecKeyRes.PrivKey = *RSAPrivKey

    return PKEEncKeyRes, PKEDecKeyRes, err
}

// Encrypts a byte stream via RSA-OAEP with sha512 as hash
func PKEEnc(ek PKEEncKey, plaintext []byte) ([]byte, error) {
    RSAPubKey := &ek.PubKey

    if ek.KeyType != "PKE" {
        return nil, errors.New("Using a non-PKE key for PKE.")
    }

    ciphertext, err := rsa.EncryptOAEP(sha512.New(), rand.Reader, RSAPubKey, plaintext, nil)

    return ciphertext, err
}

// Decrypts a byte stream encrypted with RSA-OAEP/sha512
func PKEDec(dk PKEDecKey, ciphertext []byte) ([]byte, error) {
    RSAPrivKey := &dk.PrivKey

    if dk.KeyType != "PKE" {
        return nil, errors.New("Using a non-PKE key for PKE.")
    }

    decryption, err := rsa.DecryptOAEP(sha512.New(), rand.Reader, RSAPrivKey, ciphertext, nil)

    return decryption, err
}


/*
********************************************
**           Digital Signature            **
**       DSKeyGen, DSSign, DSVerify       **
********************************************
*/

// Generates a key pair for digital signature via RSA
func DSKeyGen() (DSSignKey, DSVerifyKey, error) {
    RSAPrivKey, err := rsa.GenerateKey(rand.Reader, RSAKeySize)
    RSAPubKey := RSAPrivKey.PublicKey

    var DSSignKeyRes DSSignKey
    DSSignKeyRes.KeyType = "DS"
    DSSignKeyRes.PrivKey = *RSAPrivKey

    var DSVerifyKeyRes DSVerifyKey
    DSVerifyKeyRes.KeyType = "DS"
    DSVerifyKeyRes.PubKey = RSAPubKey

    return DSSignKeyRes, DSVerifyKeyRes, err
}

// Signs a byte stream via SHA256 and PKCS1v15
func DSSign(sk DSSignKey, msg []byte) ([]byte, error) {
    RSAPrivKey := &sk.PrivKey

    if sk.KeyType != "DS" {
        return nil, errors.New("Using a non-DS key for DS.")
    }

    hashed := sha512.Sum512(msg)

    sig, err := rsa.SignPKCS1v15(rand.Reader, RSAPrivKey, crypto.SHA512, hashed[:])

    return sig, err
}

// Verifies a signature signed with SHA256 and PKCS1v15
func DSVerify(vk DSVerifyKey, msg []byte, sig []byte) error {
    RSAPubKey := &vk.PubKey

    if vk.KeyType != "DS" {
        return errors.New("Using a non-DS key for DS.")
    }

    hashed := sha512.Sum512(msg)

    err := rsa.VerifyPKCS1v15(RSAPubKey, crypto.SHA512, hashed[:], sig)

    return err
}


/*
********************************************
**                HMAC                    **
**         HMACEval, HMACEqual            **
********************************************
*/

// Evaluate the HMAC using sha512
func HMACEval(key []byte, msg []byte) ([]byte, error) {
    if len(key) != 16 && len(key) != 24 && len(key) != 32 {
       panic(errors.New("The input as key for HMAC should be a 16-byte key."))
    }

    mac := hmac.New(sha512.New, key)
    mac.Write(msg)
    res := mac.Sum(nil)

    return res, nil
}

// Equals comparison for hashes/MACs
// Does NOT leak timing.
func HMACEqual(a []byte, b []byte) bool {
    return hmac.Equal(a, b)
}


/*
********************************************
**               KDF                      **
**            Argon2Key                   **
********************************************
*/

// Argon2:  Automatically choses a decent combination of iterations and memory
// Use this to generate a key from a password
func Argon2Key(password []byte, salt []byte, keyLen uint32) []byte {
    return argon2.IDKey(password, salt, 1, 64*1024, 4, keyLen)
}


/*
********************************************
**        Symmetric Encryption            **
**           SymEnc, SymDec               **
********************************************
*/

// Encrypts a byte slice with AES-CTR
// Length of iv should be == AESBlockSize
func SymEnc(key []byte, iv []byte, plaintext []byte) []byte {
    if len(iv) != AESBlockSize {
        panic("IV length not equal to AESBlockSize")
    }

    block, err := aes.NewCipher(key)
    if err != nil {
        panic(err)
    }

    stream := cipher.NewCTR(block, iv)
    ciphertext := make([]byte, AESBlockSize + len(plaintext))
    copy(ciphertext[:AESBlockSize], iv)

    stream.XORKeyStream(ciphertext[AESBlockSize:], plaintext)

    return ciphertext
}

// Decrypts a ciphertext encrypted with AES-CTR
func SymDec(key []byte, ciphertext []byte) []byte {
    block, err := aes.NewCipher(key)
    if err != nil {
        panic(err)
    }

    iv := ciphertext[:AESBlockSize]
    plaintext := make([]byte, len(ciphertext) - AESBlockSize)
    stream := cipher.NewCTR(block, iv)

    stream.XORKeyStream(plaintext, ciphertext[aes.BlockSize:])

    return plaintext
}
