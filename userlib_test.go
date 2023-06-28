package userlib

import (
	"encoding/hex"
	"reflect"
	"strings"
	"testing"

	// A "dot" import is used here so that the functions in the ginko and gomega
	// modules can be used without an identifier. For example, Describe() and
	// Expect() instead of ginko.Describe() and gomega.Expect(). You can read more
	// about dot imports here:
	// https://stackoverflow.com/questions/6478962/what-does-the-dot-or-period-in-a-go-import-statement-do
	"github.com/google/uuid"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

func TestSetupAndExecution(t *testing.T) {
	// We are using 2 libraries to help us write readable and maintainable tests:
	//
	// (1) Ginkgo, a Behavior Driven Development (BDD) testing framework that
	//             makes it easy to write expressive specs that describe the
	//             behavior of your code in an organized manner; and
	//
	// (2) Gomega, an assertion/matcher library that allows us to write individual
	//             assertion statements in tests that read more like natural
	//             language. For example "Expect(ACTUAL).To(Equal(EXPECTED))".
	//
	// In the Ginko framework, a test case signals failure by calling Ginkgo’s
	// Fail(description string) function. However, we are using the Gomega library
	// to execute our assertion statements. When a Gomega assertion fails, Gomega
	// calls a GomegaFailHandler, which is a function that must be provided using
	// gomega.RegisterFailHandler(). Here, we pass Ginko's Fail() function to
	// Gomega so that Gomega can report failed assertions to the Ginko test
	// framework, which can take the appropriate action when a test fails.
	//
	// This is the sole connection point between Ginkgo and Gomega.
	RegisterFailHandler(Fail)

	RunSpecs(t, "Userlib Tests")
}

// ================================================
// Global variables
// ================================================

var key1 []byte
var key2 []byte
var key3 []byte
var key4 []byte
var key5 []byte

// ================================================
// The top level Describe() contains all tests in
// this test suite in nested Describe() blocks.
// ================================================

var _ = Describe("Client Tests", func() {
	BeforeEach(func() {
		key1 = []byte("cs161teststring1")
		key2 = []byte("cs161teststring2")
		key3 = []byte("cs161teststring3")
		key4 = []byte("cs161teststring4")
		key5 = []byte("cs161teststring5")
	})

	Describe("Datastore", func() {
		BeforeEach(func() {
			DatastoreClear()
			DatastoreResetBandwidth()
		})

		It("should not return a value for a key that is not set", func() {
			UUID1, _ := uuid.FromBytes(key1)
			_, found := DatastoreGet(UUID1)
			Expect(found).To(BeFalse(),
				"Datastore returned a value for a key that was not set.")
		})

		It("should return the expected value for a key that is set", func() {
			UUID1, _ := uuid.FromBytes(key1)
			UUID2, _ := uuid.FromBytes(key2)

			foo := []byte("foo")
			DatastoreSet(UUID1, foo)

			data, found := DatastoreGet(UUID1)
			Expect(found).To(BeTrue(), "Could not find a value that was set.")
			Expect(data).To(Equal(foo), "Did not retrieve the correct value for UUIID1.")

			bar := []byte("bar")
			DatastoreSet(UUID2, bar)

			data, found = DatastoreGet(UUID2)
			Expect(found).To(BeTrue(), "Could not find a value that was set.")
			Expect(data).To(Equal(bar), "Did not retrieve the correct value for UUIID2.")
		})

		It("should correctly delete values", func() {
			UUID1, _ := uuid.FromBytes(key1)
			DatastoreSet(UUID1, []byte("foo"))
			DatastoreDelete(UUID1)
			_, found := DatastoreGet(UUID1)
			Expect(found).To(BeFalse(), "Was able to load value from a delete key.")
		})

		It("should correctly track the bandwidth usage", func() {
			DatastoreResetBandwidth()
			fiveBytes := "ABCDE"
			UUID1, _ := uuid.FromBytes(key1)
			DatastoreSet(UUID1, []byte(fiveBytes))
			bandwidthUsed := DatastoreGetBandwidth()
			Expect(bandwidthUsed).To(Equal(5),
				"Incorrect bandwidth calculation after storing 5 bytes.")

			DatastoreGet(UUID1)
			bandwidthUsed = DatastoreGetBandwidth()
			Expect(bandwidthUsed).To(Equal(10),
				"Incorrect bandwidth calculation after storing and loading 5 bytes")
		})
	})

	Describe("Keystore", func() {
		const storageKeyA = "A"
		const storageKeyB = "B"
		var encPubKey PublicKeyType
		var sigVerifyKey PublicKeyType

		BeforeEach(func() {
			KeystoreClear()
			encPubKey, _, _ = PKEKeyGen()
			_, sigVerifyKey, _ = DSKeyGen()
		})

		It("should not return a value for a key that is not set", func() {
			_, found := KeystoreGet("something")
			Expect(found).To(BeFalse(),
				"Keystore returned a value for a key that was not set.")
		})

		It("should return the expected value for a key that is set", func() {
			KeystoreSet(storageKeyA, encPubKey)
			KeystoreSet(storageKeyB, sigVerifyKey)

			key, found := KeystoreGet(storageKeyA)
			Expect(found).To(BeTrue(), "Could not find a value that was set.")
			Expect(key).To(Equal(encPubKey),
				"Did not retrieve the correct value for storageKeyA.")

			key, found = KeystoreGet(storageKeyB)
			Expect(found).To(BeTrue(), "Could not find a value that was set.")
			Expect(key).To(Equal(sigVerifyKey),
				"Did not retrieve the correct value for storageKeyB.")
		})

		It("should not allow overwriting keys since the Keystore is immutable", func() {
			keystoreSet(storageKeyA, encPubKey)
			err := keystoreSet(storageKeyA, sigVerifyKey)
			Expect(err).ToNot(BeNil(), "Allowed overwriting an existing key.")
		})

		It("should reset state after calling clear", func() {
			keystoreSet(storageKeyA, encPubKey)
			key, found := KeystoreGet(storageKeyA)
			Expect(found).To(BeTrue(), "Could not find a value that was set.")
			Expect(key).To(Equal(encPubKey),
				"Did not retrieve the correct value for storageKeyA.")
			KeystoreClear()
			_, found = KeystoreGet(storageKeyA)
			Expect(found).To(BeFalse(), "Found the value even after clearing.")
		})

		Describe("KeystoreGetMap()", func() {
			It("should return the underlying map", func() {
				pid := CurrentSpecReport().LineNumber()
				actualPtr := reflect.ValueOf(KeystoreGetMap()).Pointer()
				keystoreShard, _ := keystore.Load(pid)
				expectedPtr := reflect.ValueOf(keystoreShard).Pointer()
				Expect(actualPtr).To(Equal(expectedPtr),
					"The map returned was not the underlying keystore map.")
			})
		})
	})

	Describe("RSA encrypt and decrypt", func() {
		// TODO: break this mega test up into discrete test cases
		It("should work as expected", func() {
			const someString = "Squeamish Ossifrage"

			RSAPubKey, RSAPrivKey, err := PKEKeyGen()
			Expect(err).To(BeNil(), "PKEKeyGen() failed")

			ciphertext, err := PKEEnc(RSAPubKey, []byte(someString))
			Expect(err).To(BeNil(), "PKEEnc() failed")

			decryption, err := PKEDec(RSAPrivKey, ciphertext)
			Expect(err).To(BeNil(), "PKEDec() failed")
			Expect(string(decryption)).To(Equal(someString),
				"PKEDec() failed")

			// Test RSA Sign and Verify
			DSSignKey, DSVerifyKey, err := DSKeyGen()
			Expect(err).To(BeNil(), "DSKeyGen() failed")

			sig, err := DSSign(DSSignKey, []byte(someString))
			Expect(err).To(BeNil(), "DSSignKey() failed")

			err = DSVerify(DSVerifyKey, []byte(someString), sig)
			Expect(err).To(BeNil(), "DSVerifyKey() failed")

			err = DSVerify(DSVerifyKey, []byte("foo"), sig)
			Expect(err).ToNot(BeNil(),
				"DSVerifyKey() succeeded when it should have failed")
		})
	})

	Describe("HMAC", func() {
		// TODO: break this mega test up into discrete test cases
		It("should work as expected", func() {
			msgA := []byte("foo")
			msgB := []byte("bar")

			hmacForMsgAUsingKey1, _ := HMACEval(key1, msgA)
			hmacForMsgB, _ := HMACEval(key1, msgB)
			Expect(hmacForMsgAUsingKey1).ToNot(Equal(hmacForMsgB),
				"HMACs are equal for different data")

			hmacForMsgAUsingKey2, _ := HMACEval(key2, msgA)
			Expect(HMACEqual(hmacForMsgAUsingKey1, hmacForMsgAUsingKey2)).To(BeFalse(),
				"HMACs are equal for different key")

			actual, _ := HMACEval(key1, msgA)
			Expect(HMACEqual(actual, hmacForMsgAUsingKey1)).To(BeTrue(),
				"HMACs are not equal when they should be")
		})
	})

	Describe("Argon2", func() {
		It("should work as expected", func() {
			val1 := Argon2Key([]byte("Password"), []byte("nosalt"), 32)
			val2 := Argon2Key([]byte("Password"), []byte("nosalt"), 64)
			val3 := Argon2Key([]byte("password"), []byte("nosalt"), 32)

			Expect(val1).ToNot(Equal(val2), "val1 equals val2 when it should not.")
			Expect(val1).ToNot(Equal(val3), "val1 equals val3 when it should not.")
			Expect(val2).ToNot(Equal(val3), "val2 equals val3 when it should not.")
		})
	})

	Describe("StreamCipher", func() {
		It("should get back the plaintext when decrypting the ciphertext", func() {
			expectedPlaintext := strings.Repeat("A", 123)
			iv := RandomBytes(16)
			ciphertext := SymEnc(key1, iv, []byte(expectedPlaintext))
			Expect(ciphertext).ToNot(Equal(expectedPlaintext),
				"Symmetric encryption failure.")

			actualPlaintext := SymDec(key1, ciphertext)
			Expect(string(actualPlaintext)).To(Equal(expectedPlaintext),
				"Symmetric decryption failure.")
		})
	})

	Describe("Hash", func() {
		It("should work as expected", func() {
			hash := Hash(key1)
			expected, err := hex.DecodeString("4a56fb0ee081513a4ea0d22a33a6fba8edb95e1cb59dc1b773e77154c239c62e6377fcf26d80e3d7cf5357ebc1a4d0005fc54eb7b7110e1d5b82abc90ee4967b")
			Expect(hash).To(BeEquivalentTo(expected), "Hash of key1 is incorrect.")

			hash = Hash(key2)
			expected, err = hex.DecodeString("2fa5d1e9acaedc743dc7e3a767e58dd8dfba9f61514c474f77f03b4a565808484bf9bdf5a26d40cdef47a93bc18ee88b192359173d8408b3f3c609e60308e998")
			Expect(err).To(BeNil(), "Failed to hash key2.")
			Expect(hash).To(Equal(expected), "Hash of key2 is incorrect.")

			hash = Hash(key3)
			expected, err = hex.DecodeString("0283967f6235d50886fb85d9892fa28642533cdf5aaf58ccfce5dadb2b0c0a6ca76f6ff5e0392d796925a34b57becb81904319e921b97718fb9faab597eea37b")
			Expect(err).To(BeNil(), "Failed to hash key2.")
			Expect(hash).To(Equal(expected), "Hash of key2 is incorrect.")

			hash = Hash(key4)
			expected, err = hex.DecodeString("8a168d2b7b4e28e68d4ed9c8828b60dcc3ad57431837b5d310fa767cb3e0c50a9a237e1ed38150c49e2f04f8a74263a1b830337c5aa93d8c7edda07761a4f851")
			Expect(hash).To(Equal(expected), "Hash of key1 is incorrect.")

			hash = Hash(key5)
			expected, err = hex.DecodeString("03133ff43f9713e65c4a8906fbabd1d6331e47811e4d870c1d515e3471266e0383444aeb5187de640b7fe3e7505107abe91ec63c7df572f6279cb87d41c4ee61")
			Expect(err).To(BeNil(), "Failed to hash key5.")
			Expect(hash).To(Equal(expected), "Hash of key5 is incorrect.")
		})
	})

	Describe("MapKeyFromBytes", func() {
		It("should return a storage key of length 128", func() {
			storageKey := MapKeyFromBytes([]byte("something"))
			Expect(len(storageKey)).To(Equal(128), "storage key is not length 128.")
		})
	})
})
