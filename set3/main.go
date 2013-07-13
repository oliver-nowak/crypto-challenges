package main

import (
	// "bufio"
	"bytes"
	aes "crypto/aes"
	"encoding/base64"
	hex "encoding/hex"
	"errors"
	"fmt"
	ioutil "io/ioutil"
	"log"
	"math/rand"

	// "net/url"
	"os"
	"strings"
	"time"
)

var (
	randomKey []byte
	pad       byte = 0x01
)

func main() {
	fmt.Println("Matasano Crypto Challenges for Set 02")

	rand.Seed(time.Now().UTC().UnixNano())

	// challenge17()
	// challenge18()
	challenge19()
}

func challenge17() {
	// ------------------------------------------------------------

	// 17. The CBC padding oracle

	// Combine your padding code and your CBC code to write two functions.

	// The first function should select at random one of the following 10
	// strings:

	// MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=
	// MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=
	// MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==
	// MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==
	// MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl
	// MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==
	// MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==
	// MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=
	// MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=
	// MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93

	// generate a random AES key (which it should save for all future
	// encryptions), pad the string out to the 16-byte AES block size and
	// CBC-encrypt it under that key, providing the caller the ciphertext and
	// IV.

	// The second function should consume the ciphertext produced by the
	// first function, decrypt it, check its padding, and return true or
	// false depending on whether the padding is valid.

	// This pair of functions approximates AES-CBC encryption as its deployed
	// serverside in web applications; the second function models the
	// server's consumption of an encrypted session token, as if it was a
	// cookie.

	// It turns out that it's possible to decrypt the ciphertexts provided by
	// the first function.

	// The decryption here depends on a side-channel leak by the decryption
	// function.

	// The leak is the error message that the padding is valid or not.

	// You can find 100 web pages on how this attack works, so I won't
	// re-explain it. What I'll say is this:

	// The fundamental insight behind this attack is that the byte 01h is
	// valid padding, and occur in 1/256 trials of "randomized" plaintexts
	// produced by decrypting a tampered ciphertext.

	// 02h in isolation is NOT valid padding.

	// 02h 02h IS valid padding, but is much less likely to occur randomly
	// than 01h.

	// 03h 03h 03h is even less likely.

	// So you can assume that if you corrupt a decryption AND it had valid
	// padding, you know what that padding byte is.

	// It is easy to get tripped up on the fact that CBC plaintexts are
	// "padded". Padding oracles have nothing to do with the actual padding
	// on a CBC plaintext. It's an attack that targets a specific bit of code
	// that handles decryption. You can mount a padding oracle on ANY CBC
	// block, whether it's padded or not.

	// ------------------------------------------------------------
	fmt.Println("Challenge 17")

	// get a message that has been encrypted by a random key & IV
	encryptedMessage, iv := GetEncryptedMessage()

	plainText := BreakCBC(encryptedMessage, iv)
	fmt.Println("Decrypted Text: ", plainText)
}

func challenge18() {
	// ------------------------------------------------------------

	// 18. Implement CTR mode

	// The string:

	//     L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ==

	// decrypts to something approximating English in CTR mode, which is an
	// AES block cipher mode that turns AES into a stream cipher, with the
	// following parameters:

	//           key=YELLOW SUBMARINE
	//           nonce=0
	//           format=64 bit unsigned little endian nonce,
	//                  64 bit little endian block count (byte count / 16)

	// CTR mode is very simple.

	// Instead of encrypting the plaintext, CTR mode encrypts a running
	// counter, producing a 16 byte block of keystream, which is XOR'd
	// against the plaintext.

	// For instance, for the first 16 bytes of a message with these
	// parameters:

	//     keystream = AES("YELLOW SUBMARINE",
	//                     "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00")

	// for the next 16 bytes:

	//     keystream = AES("YELLOW SUBMARINE",
	//                     "\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00")

	// and then:

	//     keystream = AES("YELLOW SUBMARINE",
	//                     "\x00\x00\x00\x00\x00\x00\x00\x00\x02\x00\x00\x00\x00\x00\x00\x00")

	// CTR mode does not require padding; when you run out of plaintext, you
	// just stop XOR'ing keystream and stop generating keystream.

	// Decryption is identical to encryption. Generate the same keystream,
	// XOR, and recover the plaintext.

	// Decrypt the string at the top of this function, then use your CTR
	// function to encrypt and decrypt other things.

	// ------------------------------------------------------------
	fmt.Println("Challenge 18")

	key := []byte("YELLOW SUBMARINE")
	nonce := "\x00\x00\x00\x00\x00\x00\x00\x00"

	encodedCipherBytes := "L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ=="

	cipherText := DecodeBase64String(encodedCipherBytes)
	fmt.Println("Encrypted Decoded Text [0]: ", cipherText)

	plainText := DecryptCTR([]byte(cipherText), key, nonce)
	fmt.Println("Decrypted Plain Text [0]: ", plainText)

	cipherText = EncryptCTR("Waxtrax Records was awesome.", key, nonce)
	fmt.Println("Encrypted Plain Text [1]: ", cipherText)

	plainText = DecryptCTR([]byte(cipherText), key, nonce)
	fmt.Println("Decrypted Plain Text [1]: ", plainText)

	cipherText = EncryptCTR("Frontline Assembly @ Tactical Neural Implant", key, nonce)
	fmt.Println("Encrypted Plain Text [2]: ", cipherText)

	plainText = DecryptCTR([]byte(cipherText), key, nonce)
	fmt.Println("Decrypted Plain Text [2]: ", plainText)
}

func challenge19() {
	// ------------------------------------------------------------

	// 19. Break fixed-nonce CTR mode using substitions

	// Take your CTR encrypt/decrypt function and fix its nonce value to
	// 0. Generate a random AES key.

	// In SUCCESSIVE ENCRYPTIONS (NOT in one big running CTR stream), encrypt
	// each line of the base64 decodes of the following,
	// producing multiple independent ciphertexts:

	//    SSBoYXZlIG1ldCB0aGVtIGF0IGNsb3NlIG9mIGRheQ==
	//    Q29taW5nIHdpdGggdml2aWQgZmFjZXM=
	//    RnJvbSBjb3VudGVyIG9yIGRlc2sgYW1vbmcgZ3JleQ==
	//    RWlnaHRlZW50aC1jZW50dXJ5IGhvdXNlcy4=
	//    SSBoYXZlIHBhc3NlZCB3aXRoIGEgbm9kIG9mIHRoZSBoZWFk
	//    T3IgcG9saXRlIG1lYW5pbmdsZXNzIHdvcmRzLA==
	//    T3IgaGF2ZSBsaW5nZXJlZCBhd2hpbGUgYW5kIHNhaWQ=
	//    UG9saXRlIG1lYW5pbmdsZXNzIHdvcmRzLA==
	//    QW5kIHRob3VnaHQgYmVmb3JlIEkgaGFkIGRvbmU=
	//    T2YgYSBtb2NraW5nIHRhbGUgb3IgYSBnaWJl
	//    VG8gcGxlYXNlIGEgY29tcGFuaW9u
	//    QXJvdW5kIHRoZSBmaXJlIGF0IHRoZSBjbHViLA==
	//    QmVpbmcgY2VydGFpbiB0aGF0IHRoZXkgYW5kIEk=
	//    QnV0IGxpdmVkIHdoZXJlIG1vdGxleSBpcyB3b3JuOg==
	//    QWxsIGNoYW5nZWQsIGNoYW5nZWQgdXR0ZXJseTo=
	//    QSB0ZXJyaWJsZSBiZWF1dHkgaXMgYm9ybi4=
	//    VGhhdCB3b21hbidzIGRheXMgd2VyZSBzcGVudA==
	//    SW4gaWdub3JhbnQgZ29vZCB3aWxsLA==
	//    SGVyIG5pZ2h0cyBpbiBhcmd1bWVudA==
	//    VW50aWwgaGVyIHZvaWNlIGdyZXcgc2hyaWxsLg==
	//    V2hhdCB2b2ljZSBtb3JlIHN3ZWV0IHRoYW4gaGVycw==
	//    V2hlbiB5b3VuZyBhbmQgYmVhdXRpZnVsLA==
	//    U2hlIHJvZGUgdG8gaGFycmllcnM/
	//    VGhpcyBtYW4gaGFkIGtlcHQgYSBzY2hvb2w=
	//    QW5kIHJvZGUgb3VyIHdpbmdlZCBob3JzZS4=
	//    VGhpcyBvdGhlciBoaXMgaGVscGVyIGFuZCBmcmllbmQ=
	//    V2FzIGNvbWluZyBpbnRvIGhpcyBmb3JjZTs=
	//    SGUgbWlnaHQgaGF2ZSB3b24gZmFtZSBpbiB0aGUgZW5kLA==
	//    U28gc2Vuc2l0aXZlIGhpcyBuYXR1cmUgc2VlbWVkLA==
	//    U28gZGFyaW5nIGFuZCBzd2VldCBoaXMgdGhvdWdodC4=
	//    VGhpcyBvdGhlciBtYW4gSSBoYWQgZHJlYW1lZA==
	//    QSBkcnVua2VuLCB2YWluLWdsb3Jpb3VzIGxvdXQu
	//    SGUgaGFkIGRvbmUgbW9zdCBiaXR0ZXIgd3Jvbmc=
	//    VG8gc29tZSB3aG8gYXJlIG5lYXIgbXkgaGVhcnQs
	//    WWV0IEkgbnVtYmVyIGhpbSBpbiB0aGUgc29uZzs=
	//    SGUsIHRvbywgaGFzIHJlc2lnbmVkIGhpcyBwYXJ0
	//    SW4gdGhlIGNhc3VhbCBjb21lZHk7
	//    SGUsIHRvbywgaGFzIGJlZW4gY2hhbmdlZCBpbiBoaXMgdHVybiw=
	//    VHJhbnNmb3JtZWQgdXR0ZXJseTo=
	//    QSB0ZXJyaWJsZSBiZWF1dHkgaXMgYm9ybi4=

	// (This should produce 40 short CTR-encrypted ciphertexts).

	// Because the CTR nonce wasn't randomized for each encryption, each
	// ciphertext has been encrypted against the same keystream. This is very
	// bad.

	// Understanding that, like most stream ciphers (including RC4, and
	// obviously any block cipher run in CTR mode), the actual "encryption"
	// of a byte of data boils down to a single XOR operation, it should be
	// plain that:

	//   CIPHERTEXT-BYTE XOR PLAINTEXT-BYTE = KEYSTREAM-BYTE

	// And since the keystream is the same for every ciphertext:

	//   CIPHERTEXT-BYTE XOR KEYSTREAM-BYTE = PLAINTEXT-BYTE (ie, "you don't
	//   say!")

	// Attack this cryptosystem "Carmen Sandiego" style: guess letters, use
	// expected English language frequence to validate guesses, catch common
	// English trigrams, and so on. Points for automating this, but part of
	// the reason I'm having you do this is that I think this approach is
	// suboptimal.

	// ------------------------------------------------------------
	fmt.Println("Challenge 19")

	key := []byte("YELLOW SUBMARINE")
	nonce := "\x00\x00\x00\x00\x00\x00\x00\x00"

	var firstBlocks []byte

	cipherBook := GetCipherBook(key, nonce)

	// IDEA
	// divide the cipher book into blocks per 'page'
	// take the first blocks of every 'page' and concatenate into one large byte array
	// these blocks have all been XOR'd by the same nonce-ctr keystream.
	// scan for the key to the first block of the keystream
	for _, page := range cipherBook {
		blocks := createBlocks(page, 16)

		// first block of every page
		block := blocks[0]
		// append the bytes of each first block to a large byte array
		firstBlocks = append(firstBlocks, block...)
	}

	// create the transposed blocks for later scanning the XOR key
	// slice out all bytes from a particular key position
	transposedBlocks := createTransposeBlocks(firstBlocks, 16)

	// iterate over t-blocks and look for XOR keys
	// this should give us the key of the first counter block of the keystream
	keystream := scanKeys(transposedBlocks)

	srcString := hex.EncodeToString(firstBlocks)
	hexKeyBytes := hex.EncodeToString(keystream)

	// XOR the bytes from the firstBlocks array to get the plain text
	xorString, err := xorByKey(srcString, hexKeyBytes)
	if err != nil {
		log.Fatal(err)
	}

	xorBytes, _ := hex.DecodeString(xorString)
	xorResult := string(xorBytes)

	fmt.Println(xorResult)

	// IDEA #2
	// automate the iteration of cipher block pages from first block to last block.
	// scan for keys as above, and decrypt the pages

	// IDEA #3
	// break the ECB encryption of the encrypted keystream bytes for the Nth block in a page
}

////////////// -----------------------------------------------------

//////////////------------------------------------------------------

//////////////------------------------------------------------------

//////////////------------------------------------------------------

//////////////------------------------------------------------------

//////////////------------------------------------------------------

//////////////------------------------------------------------------

//////////////------------------------------------------------------

//////////////------------------------------------------------------

//////////////------------------------------------------------------

////////////// -----------------------------------------------------

//////////////------------------------------------------------------

//////////////------------------------------------------------------

//////////////------------------------------------------------------

//////////////------------------------------------------------------

//////////////------------------------------------------------------

//////////////------------------------------------------------------

//////////////------------------------------------------------------

//////////////------------------------------------------------------

//////////////------------------------------------------------------

func GetCipherBook(key []byte, nonce string) (cipherBook [][]byte) {
	resource := "./resources/challenge19.txt"

	content, err := ioutil.ReadFile(resource)
	if err != nil {
		log.Fatal(err)
	}
	lines := strings.Split(string(content), "\n")

	cipherBook = make([][]byte, 40)

	for idx, line := range lines {
		// allocate memory at least as large as source size in bytes
		decodedBytes := make([]byte, len(line))

		// Base64 Decode the bytes
		n, err := base64.StdEncoding.Decode(decodedBytes, []byte(line))
		if err != nil {
			log.Fatal(err)
		}

		// trim slice to actual size of data
		decodedBytes = decodedBytes[:n]

		// cast to string
		decodedString := string(decodedBytes)

		// encrypt with CTR
		cipherText := EncryptCTR(decodedString, key, nonce)

		// persist in book
		cipherBook[idx] = []byte(cipherText)
	}

	return cipherBook
}

func BreakCBC(encryptedMessage []byte, iv []byte) (plainText string) {
	// break up the message into BLOCKSIZE blocks
	blocks := createBlocks(encryptedMessage, 16)

	// count the number of blocks for use later in an iterator
	numBlocks := len(blocks)

	// set up the plain text storage
	plainText = ""

	// iterate through the blocks, last to first.
	// for the first ordinal block (last in the iteration), use the IV as the 'cipher text'
	for x := numBlocks - 1; x >= 0; x-- {
		// initialize the padding value; we start with 0x01
		currentPadValue := 0x01

		// initialize a block of bytes to store this block's plain text bytes
		plainTextBlock := make([]byte, 16)

		// initialize a block of bytes to store this block's XOR bytes.
		// this will be used to calculate the correct XOR value in oreder to get the padding value we want.
		xorBytes := make([]byte, 16)

		// initialize a block of bytes to store the cipher bytes of the previous cipher block (or IV)
		cipherBytes := make([]byte, 16)

		// check if this is the first ordinal block; if it is, copy the IV as the cipher block.
		// otherwise, use the previous cipher block.
		if x > 0 {
			copy(cipherBytes, blocks[x-1])
		} else {
			copy(cipherBytes, iv)
		}

		// append the zero'd XOR bytes to the current cipher block
		// we do this in order to submit the tampered XOR bytes for validation
		encryptedMessage := append(xorBytes, blocks[x]...)

		// iterate through the BLOCKSIZE space
		for q := 15; q >= 0; q-- {

			// iterate through the ASCII byte space
			// we are currently searching for a correct ASCII value that, when XOR'd, will express
			// the correct padding we are currently looking for as expressed by the currentPadValue variable.
			for i := 0; i < 256; i++ {

				// after the first decrypted byte, we have to re-calculate the XOR value according to the currentPadValue
				// we want to express in the encryptedMessage block.
				// this will iterate through those bytes and recalculate the XOR values.
				if q < 15 {
					for zzz := 15; zzz > q; zzz-- {
						// calculate the XOR value that will express the currentPadValue
						tByte := byte(currentPadValue) ^ plainTextBlock[zzz] ^ cipherBytes[zzz]

						// copy the XOR value over to the encryptedMessage block as a tampered byte.
						encryptedMessage[zzz] = tByte
					}

				}

				// we have recalculated the bytes up to the current encrypted byte we are trying to decrypt in order
				// to express the correct currentPadValue.
				// we now copy over the current ASCII byte value into the encryptedMessage at the index position
				// of the byte we are trying to decrypt. since we are iterating over the entire ASCII space,
				// at some point the validation will succeed for the currentPadValue.
				// this will be the byte value we need to calculate the plainText byte value.
				tamperedByte := byte(i)
				encryptedMessage[q] = tamperedByte

				// check if the tampered bytes contains valid padding of the currentByteValue
				isValid := IsPaddingValid(encryptedMessage, randomKey, iv)

				// if the tampered bytes express valid padding, we can then calculate the plainText byte value
				// and save that in the plainTextBlock byte array.
				// we will also re-copy the original cipher bytes back to the encryptedMessage in order to reset
				// the state of the encryptedMessage byte array.
				// this prepares it for the next iteration in the BLOCK space and ASCII space.
				if isValid {
					// calculate the plain text byte according to the following algorithm:
					// plain text = (Current Pad Value) XOR (Valid ASCII Byte Value) XOR (Cipher Byte Value || IV Byte Value)
					plainTextByte := byte(currentPadValue) ^ tamperedByte ^ cipherBytes[q]

					// reset the state of the encrypted message
					encryptedMessage[q] = cipherBytes[q]

					// store the plain text in the byte array
					plainTextBlock[q] = plainTextByte

					// increment the current pad value
					currentPadValue++

					break
				}
			}
		}

		plainText = string(plainTextBlock) + plainText

	}

	return plainText
}

func GetEncryptedMessage() (cipherBytes []byte, iv []byte) {
	randomKey = createRandomKey(16)
	// randomKey = []byte("YELLOW SUBMARINE")

	iv = createRandomIV(16)
	// iv = []byte("CAFEBABEDEADMEAT")

	// randString := "Skinny Puppy is really cool..."
	randString := GetRandomString()
	// fmt.Println("Random String: ", randString)

	cipherBytes = encryptCBCWithPKCS7(randString, randomKey, iv)
	// fmt.Println("+++ ", cipherBytes)

	return cipherBytes, iv
}

func IsPaddingValid(encryptedMessage []byte, key []byte, iv []byte) bool {
	// fmt.Println(">>> ", encryptedMessage)

	decryptedMessage := DecryptCBC(encryptedMessage, key, iv, 16)

	// fmt.Println("+++", decryptedMessage)

	plainText := string(decryptedMessage)
	// fmt.Println("Decrypted Message: ", plainText)

	_, ok := validate(plainText)
	// if !ok {
	// 	fmt.Println("Failed Padding Validation.")
	// } else {
	// 	fmt.Println("Stripped Input: ", strippedInput)
	// }

	return ok
}

func DecodeBase64String(encodedString string) (decodedString string) {
	encodedStringBytes := []byte(encodedString)

	decodedBytes := make([]byte, len(encodedStringBytes))

	n, err := base64.StdEncoding.Decode(decodedBytes, encodedStringBytes)
	if err != nil {
		log.Fatal(err)
	}

	decodedBytes = decodedBytes[:n]

	decodedString = string(decodedBytes)

	return decodedString
}

func GetRandomString() string {
	stringOracle := []string{
		"MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=",
		"MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=",
		"MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==",
		"MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==",
		"MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl",
		"MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==",
		"MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==",
		"MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=",
		"MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=",
		"MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93"}

	// randomly choose a number between 0->10
	randIdx := rand.Intn(10)
	// fmt.Println("Random Idx: ", randIdx)

	// cast string to bytes
	randStringBytes := []byte(stringOracle[randIdx])

	// allocate memory at least as large as source size in bytes
	decodedBytes := make([]byte, len(randStringBytes))

	// Base64 Decode the bytes
	n, err := base64.StdEncoding.Decode(decodedBytes, randStringBytes)
	if err != nil {
		log.Fatal(err)
	}

	// trim slice to actual size of data
	decodedBytes = decodedBytes[:n]
	// fmt.Println("decodedBytes: ", decodedBytes)

	return string(decodedBytes)
}

func randInt(min int, max int) int {
	// max is exclusive NOT inclusive for INTN, so add 1.
	max = max + 1
	return min + rand.Intn(max-min)
}

func createRandomKey(size int) (key []byte) {
	key = make([]byte, size)
	for i := 0; i < size; i++ {
		// random int range is range of printable ASCII characters
		key[i] = byte(randInt(32, 126))
	}
	return key
}

func createRandomIV(size int) []byte {
	return createRandomKey(size)
}

func XORBytes(a []byte, b []byte) (xorBytes []byte, err error) {
	srcLen := len(a)
	trgLen := len(b)

	if srcLen != trgLen {
		err = errors.New("ByteArrays are not equal length.")
		return xorBytes, err
	}

	xorBytes = make([]byte, srcLen)

	for i := 0; i < srcLen; i++ {
		xorBytes[i] = a[i] ^ b[i]
	}

	return xorBytes, err
}

func xorByKey(src string, key string) (xorString string, err error) {
	// convert string-based hex values into byte array
	srcBytes, err := hex.DecodeString(src)

	// convert string-based hex values into byte array
	keyBytes, err := hex.DecodeString(key)

	srcLen := len(srcBytes)
	keyLen := len(keyBytes)

	// allocate target byte array for XOR operation
	xorBytes := make([]byte, srcLen)

	idx := 0

	// the XOR operation
	for i := 0; i < srcLen; i++ {
		xorBytes[i] = srcBytes[i] ^ keyBytes[idx%keyLen]
		idx += 1
	}

	xorString = hex.EncodeToString(xorBytes)

	return xorString, err
}

func encryptCBCWithPKCS7(input string, key []byte, iv []byte) (output []byte) {
	paddedBytes := padWithPKCS7([]byte(input), 16)
	output = EncryptCBC(paddedBytes, key, iv, 16)

	return output
}

func padWithPKCS7(input []byte, blockLength int) []byte {
	output := padBytes(input, blockLength)

	lastByteIdx := len(output)

	if lastByteIdx == 0 {
		log.Fatal("0-length input string.")
	}

	// get value of last byte
	lastByte := output[lastByteIdx-1 : lastByteIdx]

	// pad value will never be 0x0
	padValues := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F}

	if !bytes.Contains(padValues, []byte(lastByte)) {
		extraBytes := make([]byte, blockLength)

		// pad out to 0x16
		for i := 0; i < blockLength; i++ {
			extraBytes[i] = 0x10
		}

		output = append(output, extraBytes...)
	}

	return output
}

func padBytes(input []byte, blockLength int) []byte {
	// does not FULLY IMPLEMENT PKCS7 padding. only pads out the last block.
	inputLen := len(input)

	remainder := inputLen % blockLength

	if remainder > 0 {
		// derive the integer value
		pkcsIntValue := blockLength - remainder

		// allocate storage of the size of pkcsIntValue
		padBytes := make([]byte, pkcsIntValue)

		// initialize the storage with the value pkcsIntValue
		for i := 0; i < pkcsIntValue; i++ {
			padBytes[i] = byte(pkcsIntValue)
		}

		// append pad bytes to end of block and return
		return append(input, padBytes...)
	}

	return input
}

func validate(input string) (strippedInput string, ok bool) {
	// NOTE: this is an improved implementation than the one found in set2

	inputBytes := []byte(input)
	// fmt.Println("Input bytes: ", inputBytes)

	lenBytes := len(inputBytes)

	lastByte := inputBytes[lenBytes-1]
	// fmt.Println("Last Byte: ", lastByte)

	padValue := int(lastByte)

	if padValue > 16 || padValue == 0 {
		ok = false
		return strippedInput, ok
	}

	padBytes := bytes.Repeat([]byte{lastByte}, padValue)
	// fmt.Println("Pad Bytes: ", padBytes)

	startIdx := lenBytes - padValue
	// fmt.Println("Start Idx: ", startIdx)

	slicedPadBytes := inputBytes[startIdx:]
	// fmt.Println("Sliced Pad Bytes: ", slicedPadBytes)

	if bytes.Equal(slicedPadBytes, padBytes) {
		strippedInput = string(inputBytes[:startIdx])
		// fmt.Println("B: ", inputBytes[:startIdx])
		// fmt.Println("SInput: ", strippedInput)
		ok = true
	}

	return strippedInput, ok
}

func createBlocks(decodedBytes []byte, keySize int) [][]byte {
	// NOTE: this contains code that adds an additional block if the input is not a multiple of BLOCKSIZE

	// attach a reader for easier reading / seeking
	bufReader := bytes.NewReader(decodedBytes)

	numBlocks := len(decodedBytes) / keySize

	remainder := len(decodedBytes) % 16

	if remainder > 0 {
		numBlocks++
	}

	// allocate a 2D array for holding KEYSIZE arrays
	blocks := make([][]byte, numBlocks)
	for i := range blocks {
		blocks[i] = make([]byte, keySize)
	}

	// init blocks: each block contains KEYSIZE bytes from the bufReader
	for blockIdx := range blocks {
		bufReader.Read(blocks[blockIdx])
	}

	return blocks
}

func createTransposeBlocks(decodedBytes []byte, keySize int) [][]byte {
	// attach a reader for easier reading / seeking
	bufReader := bytes.NewReader(decodedBytes)

	// size of each transposed key block holding bytes for that particular 'key position' within KEYSIZE
	sizeOfKeyBlock := len(decodedBytes) / keySize

	// this is the number of un-transposed blocks if you were to chop up bytes into KEYSIZE bins
	numBlocks := len(decodedBytes) / keySize

	// allocate storage for the transposed blocks
	transposedBlocks := make([][]byte, keySize)
	for i := range transposedBlocks {
		transposedBlocks[i] = make([]byte, sizeOfKeyBlock)
	}

	// iterate over each key position and grab all of the bytes at that key position
	for currByte := 0; currByte < keySize; currByte++ {
		// move reader to beginning byte position (depends on current byte number)
		bufReader.Seek(int64(currByte), os.SEEK_SET)

		for i := 0; i < numBlocks; i++ {
			aByte, _ := bufReader.ReadByte()

			// store the byte in the appropriate key block (depends on current byte number)
			transposedBlocks[currByte][i] = aByte

			// skip to the next byte in the chain
			bufReader.Seek(int64(keySize-1), os.SEEK_CUR)
		}
	}

	return transposedBlocks
}

func EncryptCBC(input []byte, key []byte, iv []byte, blockSize int) (output []byte) {
	// implement CBC mode endcryption for AES
	// https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation

	numBlocks := len(input) / blockSize

	// allocate storage for encrypted bytes
	output = make([]byte, len(input))

	// initialize new AES ECB cipher
	block, _ := aes.NewCipher(key)

	// iterate over byte arrays and encrypt
	for i := 0; i < numBlocks; i++ {
		begin := i * blockSize
		end := (begin + blockSize)

		var result []byte
		var err error
		// on the very first iteration, XOR the plain-text with the IV
		// then encrypt the result and save in OUTPUT byte-array
		if i == 0 {
			result, err = XORBytes(input[begin:end], iv)
			if err != nil {
				log.Fatal(err)
			}

			block.Encrypt(output[begin:end], result)
		} else {
			// on all remaining iterations, XOR the plain-text with the encrypted
			// result of the previous iteration
			// then encrypt the result and save in OUTPUT byte-array
			prevBegin := begin - blockSize
			prevEnd := (end - blockSize)

			result, err = XORBytes(input[begin:end], output[prevBegin:prevEnd])
			if err != nil {
				log.Fatal(err)
			}

			block.Encrypt(output[begin:end], result)
		}
	}

	return output
}

func DecryptCBC(input []byte, key []byte, iv []byte, blockSize int) (output []byte) {
	// implement CBC mode decryption for AES
	// https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation

	numBlocks := len(input) / blockSize

	// allocate storage for encrypted bytes
	output = make([]byte, len(input))

	// allocate intermediate storage for result of XOR
	xorResult := make([]byte, blockSize)

	// initialize new AES ECB cipher
	block, _ := aes.NewCipher(key)

	// iterate over byte arrays and encrypt
	for i := 0; i < numBlocks; i++ {
		begin := i * blockSize
		end := (begin + blockSize)

		decryptResult := make([]byte, blockSize)
		var err error

		if i == 0 {
			// decrypt: input
			block.Decrypt(decryptResult, input[begin:end])

			// XOR decrypted result with IV
			xorResult, err = XORBytes(decryptResult, iv)
			if err != nil {
				log.Fatal(err)
			}

			copy(output[begin:end], xorResult)
		} else {
			prevBegin := begin - blockSize
			prevEnd := (end - blockSize)

			// decrypt current block
			block.Decrypt(decryptResult, input[begin:end])

			// XOR the previous encrypt bytes with current decrypted result
			xorResult, err = XORBytes(decryptResult, input[prevBegin:prevEnd])
			if err != nil {
				log.Fatal(err)
			}

			// copy XOR'd byte-slice into plain-text output
			copy(output[begin:end], xorResult)
		}
	}

	return output
}

func EncryptCTR(message string, key []byte, nonce string) (cipherText string) {
	messageBytes := []byte(message)

	blocks := createBlocks(messageBytes, 16)

	numBlocks := len(blocks)

	// initialize storage for the encrypted message
	cipherBytes := make([]byte, len(message))

	// initialize the nonce byte array with the passed in nonce prefix values
	// this will need a 'counter' appended to it before encryption
	nonceBytes := []byte(nonce)

	// initialize a new AES cipher with the provided key
	aes, _ := aes.NewCipher(key)

	// initialize the counter 'index'
	counterIdx := []byte{0x0}

	// initialize the index pointer to the cipherBytes array
	cipherByteIdx := 0

	// iterate through the blocks of BLOCKSIZE bytes
	// create the nonce by appending the nonce suffix with the counter
	// create the keystream by encrypting the nonce
	// XOR the keystream bytes with the plain text message bytes to create the encrypted output
	for i := 0; i < numBlocks; i++ {
		block := blocks[i]

		// initialize the counter suffix containing a 'counter' index value
		counterPad := []byte("\x00\x00\x00\x00\x00\x00\x00")
		counter := append(counterIdx, counterPad...)

		// append the nonce prefix with the counter suffix to create the nonce
		nonceBytes := append(nonceBytes, counter...)

		// initialize keystream storage
		keystream := make([]byte, 16)

		// create the keystream with the nonce
		aes.Encrypt(keystream, nonceBytes)

		// iterate through bytes of the current block
		// if the current byte is not 0x0 (NUL) we will XOR with the keystream byte
		// at that index value and save in the cipher bytes array
		for z := 0; z < 16; z++ {
			// the current byte of this block at index 'z'
			bByte := block[z]

			// check if the byte is NULL
			if bByte != 0x0 {
				// get the keystream byte at index 'z'
				kByte := keystream[z]

				// XOR for the cipher text byte
				ctByte := kByte ^ bByte

				// persist the cipher text byte
				cipherBytes[cipherByteIdx] = ctByte

				// increament the cipher byte array pointer
				cipherByteIdx++
			}
		}

		// increment the nonce counter 'index' scalar
		counterIdx[0]++
	}

	cipherText = string(cipherBytes)

	return cipherText
}

func DecryptCTR(cipherBytes []byte, key []byte, nonce string) (plainText string) {
	blocks := createBlocks(cipherBytes, 16)

	numBlocks := len(blocks)

	plainText = ""

	// initialize the nonce byte array with the passed in nonce prefix values
	// this will need a 'counter' appended to it before encryption
	nonceBytes := []byte(nonce)

	// initialize a new AES cipher with the provided key
	aes, _ := aes.NewCipher(key)

	// initialize the counter 'index'
	counterIdx := []byte{0x0}

	// iterate through the blocks of BLOCKSIZE bytes
	// create the nonce by appending the nonce suffix with the counter
	// create the keystream by encrypting the nonce
	// XOR the keystream bytes with the cipher text message bytes to create the plain text output
	for i := 0; i < numBlocks; i++ {
		block := blocks[i]

		// initialize the counter suffix containing a 'counter' index value
		counterPad := []byte("\x00\x00\x00\x00\x00\x00\x00")
		counter := append(counterIdx, counterPad...)

		// append the nonce prefix with the counter suffix to create the nonce
		nonceBytes := append(nonceBytes, counter...)

		// initialize keystream storage
		keystream := make([]byte, 16)

		// create the keystream with the nonce
		aes.Encrypt(keystream, nonceBytes)

		// iterate through bytes of the current block
		// if the current byte is not 0x0 (NUL) we will XOR with the keystream byte
		// at that index value and save in the plain text string
		for z := 0; z < 16; z++ {
			// the current byte of this block at index 'z'
			bByte := block[z]

			// check if the byte is NULL
			if bByte != 0x0 {
				// get the keystream byte at index 'z'
				kByte := keystream[z]

				// XOR for the plain text byte
				ptByte := bByte ^ kByte

				// persist the plain text byte
				plainText += string(ptByte)
			}

		}

		// increment the nonce counter 'index' scalar
		counterIdx[0]++
	}

	return plainText
}

func scanKeys(transposedBlocks [][]byte) []byte {
	// FIX: different from set1; refactor into this implementation
	keyLen := len(transposedBlocks)

	key := make([]byte, keyLen)

	// iterate through list of transposed blocks and find the topscorer of the XOR scan within each t-block
	for blockIdx := range transposedBlocks {
		blockBytes := transposedBlocks[blockIdx]

		hexString := hex.EncodeToString(blockBytes)

		_, _, cypherKey := rotateASCIIChars(hexString)
		fmt.Println("+++ cypherKey: ", cypherKey)

		// cypherByte, _ := hex.DecodeString(cypherKey)
		// fmt.Println(">>> cypherByte: ", cypherByte)
		cypherByte := cypherKey

		// store the first byte in the cypherByte array: **NOTE** it should only have one byte
		// key[blockIdx] = cypherByte[0]
		key[blockIdx] = cypherByte
	}

	return key
}

func rotateASCIIChars(srcString string) (highestScore float32, cypherResult string, cypherKey byte) {
	// FIX: different from set1; refactor into this implementation
	// iterate through visible ASCII char values
	for i := 0; i < 256; i++ {
		// convert the ASCII char int value into a byte array
		cypherTxt := []byte(string(i))

		// convert the byte-array into hex-based string value
		// cypherString := hex.EncodeToString(cypherTxt)

		// XOR the source string via the cypher string
		result, err := xorByChar(srcString, byte(i))
		if err != nil {
			log.Fatal(err)
		}

		// score the result of the XOR operation
		score := score(result)

		// update the score
		if score > highestScore {
			highestScore = score
			cypherResult = result
			cypherKey = byte(i)
			// cypherKey = cypherString
			fmt.Println("iii ", i)
			fmt.Println("src ", srcString)
			fmt.Println("--- ", cypherTxt)
			fmt.Println("________________")
		}
	}

	return highestScore, cypherResult, cypherKey
}

func score(srcString string) (score float32) {
	// iterate through the string and score the chars via an accumulator
	// this method uses 'etaoinshrdlu' character frequencies for scoring
	// SEE: http://en.wikipedia.org/wiki/Letter_frequency
	// SEE: http://www.math.cornell.edu/~mec/2003-2004/cryptography/subs/frequencies.html
	score = 0.0000

	for i := range srcString {

		txt := string(srcString[i])

		switch txt {
		// case "\n":
		// 	score += 7.80
		// case "'", ",":
		// 	score += 8.00
		case " ":
			score += 13.00
		case "e", "E":
			score += 12.702
		case "t", "T":
			score += 9.056
		case "a", "A":
			score += 8.167
		case "o", "O":
			score += 7.507
		case "i", "I":
			score += 6.966
		case "n", "N":
			score += 6.749
		case "s", "S":
			score += 6.327
		case "h", "H":
			score += 6.094
		case "r", "R":
			score += 5.987
		case "d", "D":
			score += 4.253
		case "l", "L":
			score += 4.025
		case "u", "U":
			score += 2.758
		case "c", "C":
			score += 2.782
		case "m", "M":
			score += 2.406
		case "w", "W":
			score += 2.360
		case "f", "F":
			score += 2.228
		case "g", "G":
			score += 2.015
		case "y", "Y":
			score += 1.974
		case "p", "P":
			score += 1.929
		case "b", "B":
			score += 1.492
		case "v", "V":
			score += 0.978
		case "k", "K":
			score += 0.772
		case "j", "J":
			score += 0.153
		case "x", "X":
			score += 0.150
		case "q", "Q":
			score += 0.095
		case "z", "Z":
			score += 0.074
		default:
			score += 0
		}
	}

	return score
}

func xorByChar(src string, cypher byte) (xorString string, err error) {
	// FIX: different from set1; refactor into this implementation
	srcBytes, err := hex.DecodeString(src)
	// cypherBytes, err := hex.DecodeString(cypher)

	srcLen := len(srcBytes)

	xorBytes := make([]byte, srcLen)

	for i := 0; i < srcLen; i++ {
		xorBytes[i] = srcBytes[i] ^ cypher //cypherBytes[0]
	}

	// fmt.Println("xor ", xorBytes)
	xorString = string(xorBytes)

	return xorString, err
}
