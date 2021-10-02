package userlib

import (
	"bytes"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/google/uuid"
)

// Golang has a very powerful routine for building tests.

// Run with "go test" to run the tests

// And "go test -v" to run verbosely so you see all the logging and
// what tests pass/fail individually.

// And "go test -cover" to check your code coverage in your tests

// Default test strings
var key1 []byte = []byte("cs161teststring1")
var key2 []byte = []byte("cs161teststring2")
var key3 []byte = []byte("cs161teststring3")
var key4 []byte = []byte("cs161teststring4")
var key5 []byte = []byte("cs161teststring5")

// Creates a UUID from the supplied bytes
// Use for testing only!
func UUIDFromBytes(t *testing.T, b []byte) (u UUID) {
	u, err := uuid.FromBytes(b)
	if err != nil {
		t.Error("Got FromBytes error:", err)
	}

	return
}

func TestUUIDFromBytesDeterministic(t *testing.T) {
	UUID1 := UUIDFromBytes(t, key1)
	t.Log(UUID1)

	UUID2 := UUIDFromBytes(t, key1)
	t.Log(UUID2)

	if UUID1 != UUID2 {
		t.Error("UUID1 != UUID2")
		t.Log("UUID1:", UUID1)
		t.Log("UUID2:", UUID2)
	}
}

func TestDatastore(t *testing.T) {
	UUID1 := UUIDFromBytes(t, key1)
	UUID2 := UUIDFromBytes(t, key2)
	UUID3 := UUIDFromBytes(t, key3)

	DatastoreSet(UUID1, []byte("foo"))

	_, valid := DatastoreGet(UUID3)
	if valid {
		t.Error("Datastore fetched UUID3 when it wasn't supposed to")
	}

	data, valid := DatastoreGet(UUID1)
	if !valid || string(data) != "foo" {
		t.Error("Error with fetching 'foo' from UUID1")
	}

	_, valid = DatastoreGet(UUID3)
	if valid {
		t.Error("Returned when nothing, oops")
	}

	DatastoreSet(UUID2, []byte("bar"))

	data, valid = DatastoreGet(UUID1)
	if !valid || string(data) != "foo" {
		t.Error("Error with fetching 'foo' from UUID1")
	}

	DatastoreDelete(UUID1)

	_, valid = DatastoreGet(UUID1)
	if valid {
		t.Error("DatastoreGet succeeded even after deleting UUID1")
	}

	data, valid = DatastoreGet(UUID2)
	if !valid || string(data) != "bar" {
		t.Error("Error with fetching 'bar' from UUID2")
	}

	DatastoreClear()

	_, valid = DatastoreGet(UUID2)
	if valid {
		t.Error("DatastoreGet succeeded even after DatastoreClear")
	}

	t.Log("Datastore fetch", data)
	t.Log("Datastore map", DatastoreGetMap())
	DatastoreClear()
	t.Log("Datastore map", DatastoreGetMap())

	// Test bandwidth tracker
	DatastoreResetBandwidth()
	fiveBytes := "ABCDE"
	DatastoreSet(UUID1, []byte(fiveBytes))
	bandwidthUsed := DatastoreGetBandwidth()
	if bandwidthUsed != 5 {
		t.Error("Incorrect bandwidth calculation after storing 5 bytes.")
	}
	DatastoreGet(UUID1)
	bandwidthUsed = DatastoreGetBandwidth()
	if bandwidthUsed != 10 {
		t.Error("Incorrect bandwidth calculation after storing and loading 5 bytes")
	}
}

func TestKeystore(t *testing.T) {
	RSAPubKey, _, err1 := PKEKeyGen()
	_, DSVerifyKey, err2 := DSKeyGen()

	if err1 != nil || err2 != nil {
		t.Error("PKEKeyGen() failed")
	}

	KeystoreSet("user1", RSAPubKey)
	KeystoreSet("user2", DSVerifyKey)

	_, valid := KeystoreGet("user3")
	if valid {
		t.Error("Keystore fetched UUID3 when it wasn't supposed to")
	}

	data, valid := KeystoreGet("user1")
	if !valid {
		t.Error("Key stored at UUID1 doesn't match")
	}

	data, valid = KeystoreGet("user2")
	if !valid {
		t.Error("Key stored at UUID2 doesn't match")
	}

	KeystoreClear()

	_, valid = KeystoreGet("user1")
	if valid {
		t.Error("KeystoreGet succeeded even after KeystoreClear")
	}

	t.Log("Keystore fetch", data)
	t.Log("Keystore map", KeystoreGetMap())
	KeystoreClear()
	t.Log("Keystore map", KeystoreGetMap())
}

func TestRSA(t *testing.T) {

	// Test RSA Encrypt and Decrypt
	RSAPubKey, RSAPrivKey, err := PKEKeyGen()
	if err != nil {
		t.Error("PKEKeyGen() failed", err)
	}

	t.Log(RSAPubKey)
	ciphertext, err := PKEEnc(RSAPubKey, []byte("Squeamish Ossifrage"))
	if err != nil {
		t.Error("PKEEnc() error", err)
	}

	decryption, err := PKEDec(RSAPrivKey, ciphertext)
	if err != nil || (string(decryption) != "Squeamish Ossifrage") {
		t.Error("Decryption failed", err)
	}

	// Test RSA Sign and Verify
	DSSignKey, DSVerifyKey, err := DSKeyGen()
	if err != nil {
		t.Error("DSKeyGen() failed", err)
	}

	sign, err := DSSign(DSSignKey, []byte("Squeamish Ossifrage"))
	if err != nil {
		t.Error("RSA sign failure")
	}

	err = DSVerify(DSVerifyKey, []byte("Squeamish Ossifrage"), sign)
	if err != nil {
		t.Error("RSA verification failure")
	}

	err = DSVerify(DSVerifyKey, []byte("foo"), sign)
	if err == nil {
		t.Error("RSA verification worked when it shouldn't")
	}

	t.Log("Error return", err)
}

func TestHMAC(t *testing.T) {
	msga := []byte("foo")
	msgb := []byte("bar")

	hmac1a, _ := HMACEval(key1, msga)
	hmac1b, _ := HMACEval(key1, msgb)
	if HMACEqual(hmac1a, hmac1b) {
		t.Error("HMACs are equal for different data")
	}

	hmac2a, _ := HMACEval(key2, msga)
	if HMACEqual(hmac1a, hmac2a) {
		t.Error("HMACs are equal for different key")
	}

	hmac1a2, _ := HMACEval(key1, msga)
	if !HMACEqual(hmac1a, hmac1a2) {
		t.Error("HMACs are not equal when they should be")
	}
}

func TestArgon2(t *testing.T) {
	val1 := Argon2Key([]byte("Password"), []byte("nosalt"), 32)
	val2 := Argon2Key([]byte("Password"), []byte("nosalt"), 64)
	val3 := Argon2Key([]byte("password"), []byte("nosalt"), 32)

	equal := bytes.Equal

	if equal(val1, val2) || equal(val1, val3) || equal(val2, val3) {
		t.Error("Argon2 problem")
	}
	t.Log(hex.EncodeToString(val1))
	t.Log(hex.EncodeToString(val2))
	t.Log(hex.EncodeToString(val3))
}

func TestStreamCipher(t *testing.T) {
	someMsg := strings.Repeat("A", 123)
	iv := RandomBytes(16)
	t.Log("Random IV:", iv)

	t.Log("Also testing replacing SymDec with wrapper")
	wrapped := false

	// Save the OLD version of SymDec
	decryptInternal := SymDec

	SymDec = func(key []byte, ciphertext []byte) []byte {
		wrapped = true
		t.Log("Wrapped decryption called")
		return decryptInternal(key, ciphertext)
	}

	t.Log("Before SymEnc()")
	ciphertext := SymEnc(key1, iv, []byte(someMsg))
	
	t.Log("Before SymDec()")
	decryption := SymDec(key1, ciphertext)

	t.Log("Decrypted message:", string(decryption))
	if string(decryption) != someMsg {
		t.Error("Symmetric decryption failure")
	}
	if !wrapped {
		t.Error("Failed to properly wrap decryption")
	}
}

func TestHash(t *testing.T) {
	t.Log("Hashing test strings")
	hash1 := Hash(key1)
	hash2 := Hash(key2)
	hash3 := Hash(key3)
	hash4 := Hash(key4)
	hash5 := Hash(key5)

	expected1, err1 := hex.DecodeString("4a56fb0ee081513a4ea0d22a33a6fba8edb95e1cb59dc1b773e77154c239c62e6377fcf26d80e3d7cf5357ebc1a4d0005fc54eb7b7110e1d5b82abc90ee4967b")
	expected2, err2 := hex.DecodeString("2fa5d1e9acaedc743dc7e3a767e58dd8dfba9f61514c474f77f03b4a565808484bf9bdf5a26d40cdef47a93bc18ee88b192359173d8408b3f3c609e60308e998")
	expected3, err3 := hex.DecodeString("0283967f6235d50886fb85d9892fa28642533cdf5aaf58ccfce5dadb2b0c0a6ca76f6ff5e0392d796925a34b57becb81904319e921b97718fb9faab597eea37b")
	expected4, err4 := hex.DecodeString("8a168d2b7b4e28e68d4ed9c8828b60dcc3ad57431837b5d310fa767cb3e0c50a9a237e1ed38150c49e2f04f8a74263a1b830337c5aa93d8c7edda07761a4f851")
	expected5, err5 := hex.DecodeString("03133ff43f9713e65c4a8906fbabd1d6331e47811e4d870c1d515e3471266e0383444aeb5187de640b7fe3e7505107abe91ec63c7df572f6279cb87d41c4ee61")
	if err1 != nil || err2 != nil || err3 != nil || err4 != nil || err5 != nil {
		t.Error("DecodeString failed")
	}
	t.Log("Checking against expected hash from https://sha512.online/")
	if !bytes.Equal(hash1[:], expected1) || !bytes.Equal(hash2[:], expected2) || !bytes.Equal(hash3[:], expected3) || !bytes.Equal(hash4[:], expected4) || !bytes.Equal(hash5[:], expected5) {
		t.Error("Hash does not match up")
	}
}

// Deliberate fail example
// func TestFailure(t *testing.T){
//	t.Log("This test will fail")
//	t.Error("Test of failure")
//}
