package userlib

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"regexp"
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
	"crypto/x509"

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
	for k := range symbols {
		delete(symbols, k)
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
**         JSON Marshal/Unmarshal        ***
********************************************

userlib.Marshal and userlib.Unmarshal are two
wrapper functions around json.Marshal and
json.Unmarshal. We wrap around these methods
to provide symbolic debugger support.

Reference:
https://pkg.go.dev/encoding/json
*/

func marshal(v interface{}) ([]byte, error) {
	data, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	if SymbolicDebug {
		m1 := regexp.MustCompile(`{"KeyType":"PKE","PrivKey":{.*?}}}`)
		replaced := m1.ReplaceAllStringFunc(string(data), resolveString)

		m2 := regexp.MustCompile(`{"KeyType":"DS","PrivKey":{.*?}}}`)
		replaced = m2.ReplaceAllStringFunc(replaced, resolveString)

		m3 := regexp.MustCompile(`".*?"`)
		replaced = m3.ReplaceAllStringFunc(replaced, resolveString)

		record(data, `%s`, replaced)
	}
	return data, nil
}

func unmarshal(data []byte, v interface{}) error {
	return json.Unmarshal(data, v)
}

var Unmarshal = unmarshal
var Marshal = marshal

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

	if SymbolicDebug {
		record(data, `{"userlib.RandomBytes": %s}`, truncateBytes(data))
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
	if SymbolicDebug {
		record(result, `{"userlib.Hash": {"data": %s}}`, resolve(data))
		record(result[:16], `{"userlib.Hash[:16]": {"data": %s}}`, resolve(data))
	}
	return result
}

// Hash returns a byte slice containing the SHA512 hash of the given byte slice.
var Hash = hash

/*
********************************************
**               UUID                     **
**      UUIDNew(), UUIDFromBytes(...)     **
********************************************

These functions are wrappers around:
https://pkg.go.dev/github.com/google/uuid
*/

// UUIDNew creates a new random UUID.
func uuidNew() UUID {
	bytes := make([]byte, UUIDSizeBytes)
	if _, err := io.ReadFull(rand.Reader, bytes); err != nil {
		panic(err)
	}
	result, _ := uuid.FromBytes(bytes)
	if SymbolicDebug {
		record(bytes, `{"userlib.UUIDNew": %s}`, truncateBytes(bytes))
	}
	return result
}

var UUIDNew = uuidNew

// UUIDFromBytes creates a new UUID from a byte slice.
// Returns an error if the slice has a length less than 16.
// The bytes are copied from the slice.
func uuidFromBytes(b []byte) (result UUID, err error) {
	if len(b) < 16 {
		return uuid.New(), errors.New("UUIDFromBytes expects an input greater than or equal to 16 characters")
	}
	result, err = uuid.FromBytes(b[:16])
	if err != nil {
		return uuid.New(), err
	}
	if SymbolicDebug {
		record(result[:], `{"userlib.UUIDFromBytes": %s}`, resolve(b))
	}
	return result, err
}

var UUIDFromBytes = uuidFromBytes

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

func recordKeys(publicKey rsa.PublicKey, privateKey rsa.PrivateKey,
	publicKeyStruct interface{}, privateKeyStruct interface{},
	publicKeyFormat string, privateKeyFormat string) {

	publicKeyBytes := x509.MarshalPKCS1PublicKey(&publicKey)
	publicKeyId := truncateBytes(publicKeyBytes)
	record(publicKeyBytes, publicKeyFormat, publicKeyId)

	privateKeyBytes := x509.MarshalPKCS1PrivateKey(&privateKey)
	privateKeyId := truncateBytes(privateKeyBytes)
	record(privateKeyBytes, privateKeyFormat, privateKeyId)

	// This is for the case where the key is used inside of a struct and we have
	// to regex on the struct's marshalled type
	pubKeyJSON, _ := json.Marshal(publicKeyStruct)
	record(pubKeyJSON, publicKeyFormat, publicKeyId)

	privKeyJSON, _ := json.Marshal(privateKeyStruct)
	record(privKeyJSON, privateKeyFormat, privateKeyId)
}

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

	if SymbolicDebug {
		recordKeys(RSAPubKey, *RSAPrivKey, PKEEncKeyRes, PKEDecKeyRes, `{"PKEEncKey": %s}`, `{"PKEDecKey": %s}`)
	}
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

	if SymbolicDebug {
		record(ciphertext, `{"userlib.PKEEnc": {"ek": %s, "plaintext": %s}}`, resolve(x509.MarshalPKCS1PublicKey(&ek.PubKey)), resolve(plaintext))
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

	if SymbolicDebug {
		record(decryption, `{"userlib.PKEDec": {"dk": %s, "ciphertext": %s}}`, resolve(x509.MarshalPKCS1PrivateKey(&dk.PrivKey)), resolve(ciphertext))
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

	if SymbolicDebug {
		recordKeys(RSAPubKey, *RSAPrivKey, DSSignKeyRes, DSVerifyKeyRes, `{"DSVerifyKey": %s}`, `{"DSSignKey": %s}`)
	}

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

	if SymbolicDebug {
		record(sig, `{"userlib.DSSign": {"sk": %s, "msg": %s}}`, resolve(x509.MarshalPKCS1PrivateKey(&sk.PrivKey)), resolve(msg))
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

	if SymbolicDebug {
		record(res, `{"userlib.HMAC": {"key": %s, "msg": %s}}`, resolve(key), resolve(msg))
		record(res[:16], `{"userlib.HMAC[:16]": {"key": %s, "msg": %s}}`, resolve(key), resolve(msg))
	}

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

	if SymbolicDebug {
		record(res, `{"userlib.HashKDF": {"key": %s, "msg": %s}}`, resolve(key), resolve(msg))
		record(res[:16], `{"userlib.HashKDF[:16]": {"key": %s, "msg": %s}}`, resolve(key), resolve(msg))
	}

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

	if SymbolicDebug {
		record(ciphertext, `{"userlib.SymEnc": {"key": %s, "iv": %s, "plaintext": %s}}`, resolve(key), resolve(iv), resolve(plaintext))
	}

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

	if SymbolicDebug {
		record(plaintext, `{"userlib.SymDec": {"key": %s, "ciphertext": %s}}`, resolve(key), resolve(ciphertext))
	}

	return plaintext
}

var SymDec = symDec

/*
********************************************
**         BETA: Symbolic Debugger        **
********************************************

The Symbolic Debugger is a debugging tool that
we created to assist with debugging Datastore
entries. Read the comments below to see what you
can do with this.
*/

// This flag enables the Symbolic Debugger
// If the Symbolic Debugger is causing excessive slowdown or memory usage,
// you may want to set this to false.
var SymbolicDebug = true

// This flag enables verbose logging through the Symbolic Debugger
// If you set this to true, you may want to pipe your output to a file
// e.g. go test -v > debug.txt
// to see the full, untrunctated debug logging
var SymbolicVerbose = true

// This flag sets the maximum key length in the debugger
// You may want to increase this to a larger number (e.g. 100) if you're using
// identifiers that have meaning, e.g. "username-{}-filename-{}", and want to see
// the entire identifier in the symbolic representation.
var SymbolicMaxLength = 5

// If DebugOutput is set to false, then DebugMsg will suppress output.
var DebugOutput = true

// Feel free to use userlib.DebugMsg(...) to print strings to the console.
func DebugMsg(format string, args ...interface{}) {
	if DebugOutput {
		msg := fmt.Sprintf("%v ", time.Now().Format("15:04:05.00000"))
		log.Printf(msg+strings.Trim(format, "\r\n ")+"\n", args...)
	}
}

// The Symbolic Debugger lets you export a snapshot of the Datastore in a symbolic representation.
// To do this, call DebugExportDatastore("datastore.json"), or any file name of your
// choice.
func DebugExportDatastore(outputFile string) {
	pid := CurrentSpecReport().LineNumber()
	datastorePrologue(pid)
	entries := make([]string, 0)
	for key, element := range datastore[pid] {
		entries = append(entries, fmt.Sprintf(`{"Key": %s, "Value": %s}`, resolve(key[:]), resolve(element)))
	}
	output := fmt.Sprintf(`[%s]`, strings.Join(entries, ","))
	var prettyOutput bytes.Buffer
	json.Indent(&prettyOutput, []byte(output), "", "  ")
	ioutil.WriteFile(outputFile, prettyOutput.Bytes(), 0644)
}

// ----------- SYMBOLIC DEBUGGER: PRIVATE METHODS [BEGIN] ---------------

// Takes in byte slice data (with no text interpretation) and cuts it short
func truncateBytes(data []byte) (truncated string) {
	return truncateStr(fmt.Sprintf("%x", data))
}

// Takes in string data (with text interpretation) and cuts it short
func truncateStr(data string) (truncated string) {
	if len(data) < SymbolicMaxLength+3 {
		truncated = data
	} else {
		truncated = data[:SymbolicMaxLength] + "..."
	}
	data_bytes, err := json.Marshal(truncated)
	if err != nil {
		panic("symbolic debugger failed in truncateStr with error: " + err.Error())
	}
	return fmt.Sprintf("%s", data_bytes)
}

// Deterministically converts a byte slice to a string of length 128 that is
// suitable to use as the storage key in a map and marshal/unmarshal to/from
// JSON.
func MapKeyFromBytes(data []byte) (truncated string) {
	return fmt.Sprintf("%x", sha512.Sum512(data))
}

// The Symbolic Debugger uses a symbols table to map data generated by userlib
// (e.g. hashes, encrypted strings, signatures, etc.) to their string representation.
var symbols map[string]string = make(map[string]string)

// The `resolve` method attempts to look up a symbol corresponing to some particular data
// If it's not found, we treat the data as a byte array, and just slice it appropriatly
func resolve(data []byte) string {
	symbolKey := MapKeyFromBytes(data)
	if result, found := symbols[symbolKey]; found {
		return result
	}
	// For some WACK reason, this is different than
	// truncateBytes(data). So don't do that.
	return truncateStr(string(data))
}

// A special resolution method to help with regex-based string resolution.
// When using regexp's ReplaceAllStringFunc method, we need to pass in a
// function that acts on a found match. That function's signature must be
// string => string, so we define a special resolveString method to allow
// for that. The handling of strings is also slightly different than normal
// byte slices, so we have some special decoding logic as well.
func resolveString(data string) string {

	doubleQuote := "\""

	if strings.HasPrefix(data, doubleQuote) {
		trimmed := strings.TrimPrefix(data, doubleQuote)
		trimmed = strings.TrimSuffix(trimmed, doubleQuote)

		base64Decoded, err := base64.StdEncoding.DecodeString(trimmed)
		symbolKey := MapKeyFromBytes([]byte(base64Decoded))
		symbol, found := symbols[symbolKey]
		if found && err == nil {
			return symbol
		}

		symbolKey = MapKeyFromBytes([]byte(trimmed))
		symbol, found = symbols[symbolKey]
		if found {
			return symbol
		}
	}

	return data
}

func record(key []byte, template string, values ...interface{}) {
	s := fmt.Sprintf(template, values...)
	symbols[MapKeyFromBytes(key)] = s
	if SymbolicVerbose {
		DebugMsg("%s => %s", truncateBytes(key), s)
	}
}

// ----------- SYMBOLIC DEBUGGER: PRIVATE METHODS [END] ---------------
