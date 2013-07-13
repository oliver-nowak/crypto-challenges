package main

import (
	// "bufio"
	"bytes"
	aes "crypto/aes"
	"encoding/base64"
	// hex "encoding/hex"
	"errors"
	"fmt"
	// ioutil "io/ioutil"
	"log"
	"math/rand"

	// "net/url"
	// "strings"
	"time"
)

var (
	randomKey []byte
	pad       byte = 0x01
)

func main() {
	fmt.Println("Matasano Crypto Challenges for Set 02")

	rand.Seed(time.Now().UTC().UnixNano())

	challenge17()
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

func BreakCBC(encryptedMessage []byte, iv []byte) (plainText string) {
	// break up the message into BLOCKSIZE blocks
	blocks := createBlocks(encryptedMessage, 16)

	// count the number of blocks for use later in an iterator
	numBlocks := len(blocks)

	// set up the plain text storage
	plainText = ""

	// iterate through the blocks, last to first.
	// for the last block, use the IV as the 'cipher text'
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

		// check if this is the last block; if it is, copy the IV as the cipher block.
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

// func validatePadding(input string) (strippedInput string, ok bool) {
// 	// there is something wrong with this validation - use VALIDATE above
// 	inputBytes := []byte(input)

// 	inputBlocks := createBlocks(inputBytes, 16)

// 	numBlocks := len(inputBlocks)
// 	// fmt.Println("Num Blocks: ", numBlocks)

// 	lastBlock := inputBlocks[numBlocks-1]

// 	lastByte := lastBlock[15]
// 	// fmt.Println("Last Byte: ", lastByte)

// 	// pad index lookup table
// 	padIdxTable := []int{16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0}

// 	padValue := int(lastByte)
// 	// fmt.Println("Last Value: ", padValue)

// 	// create padded byte slice for comparison
// 	padBytes := bytes.Repeat([]byte{lastByte}, int(lastByte))
// 	// fmt.Println("pad Bytes: ", padBytes)

// 	// find out the index of the padded byte slice
// 	startPadIdx := bytes.Index(lastBlock, padBytes)
// 	// fmt.Println("Start Pad Idx: ", startPadIdx)

// 	// make sure it found something - otherwise FAIL validation
// 	if startPadIdx == -1 {
// 		// fmt.Println("FAIL.")
// 		ok = false
// 		return strippedInput, ok
// 	}

// 	padIdx := padIdxTable[padValue]

// 	// compare index with lookup table
// 	if padIdx == startPadIdx {
// 		ok = true
// 	}

// 	// strip the padding
// 	if ok {
// 		lastBlock = lastBlock[0:startPadIdx]

// 		inputBlocks[numBlocks-1] = lastBlock

// 		for i := 0; i < numBlocks; i++ {
// 			strippedInput += string(inputBlocks[i])
// 		}

// 		return strippedInput, ok
// 	}

// 	return strippedInput, false
// }

func createBlocks(decodedBytes []byte, keySize int) [][]byte {
	// attach a reader for easier reading / seeking
	bufReader := bytes.NewReader(decodedBytes)

	numBlocks := len(decodedBytes) / keySize

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
