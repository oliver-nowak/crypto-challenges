package main

import (
	"bufio"
	"bytes"
	aes "crypto/aes"
	"encoding/base64"
	hex "encoding/hex"
	"errors"
	"fmt"
	ioutil "io/ioutil"
	"log"
	"math/rand"
	"time"
)

func main() {
	fmt.Println("Matasano Crypto Challenges for Set 02")

	rand.Seed(time.Now().UTC().UnixNano())

	// challenge09()
	// challenge10()
	// challenge11()
	challenge12()
}

func challenge09() {
	// ------------------------------------------------------------

	// 9. Implement PKCS#7 padding

	// Pad any block to a specific block length, by appending the number of
	// bytes of padding to the end of the block. For instance,

	//   "YELLOW SUBMARINE"

	// padded to 20 bytes would be:

	//   "YELLOW SUBMARINE\x04\x04\x04\x04"

	// The particulars of this algorithm are easy to find online.

	// ------------------------------------------------------------
	fmt.Println("Challenge 09")

	input := "YELLOW SUBMARINE"

	// bytes := padBytes([]byte(input), 20)

	// output := string(bytes)
	// fmt.Println(output)

	padded := padWithPKCS7([]byte(input), 16)
	fmt.Println("Padded: ", padded)
}

func challenge10() {
	// ------------------------------------------------------------

	// 10. Implement CBC Mode

	// In CBC mode, each ciphertext block is added to the next plaintext
	// block before the next call to the cipher core.

	// The first plaintext block, which has no associated previous ciphertext
	// block, is added to a "fake 0th ciphertext block" called the IV.

	// Implement CBC mode by hand by taking the ECB function you just wrote,
	// making it encrypt instead of decrypt (verify this by decrypting
	// whatever you encrypt to test), and using your XOR function from
	// previous exercise.

	// DO NOT CHEAT AND USE OPENSSL TO DO CBC MODE, EVEN TO VERIFY YOUR
	// RESULTS. What's the point of even doing this stuff if you aren't going
	// to learn from it?

	// The buffer at:

	//     https://gist.github.com/3132976

	// is intelligible (somewhat) when CBC decrypted against "YELLOW
	// SUBMARINE" with an IV of all ASCII 0 (\x00\x00\x00 &c)

	// ------------------------------------------------------------
	fmt.Println("Challenge 10")

	resource := "./resources/gistfile1.txt"
	key := []byte("YELLOW SUBMARINE")
	blockSize := 16
	iv := make([]byte, blockSize)

	// open file handle and read contents
	decodedBytes := decodeFile(resource)

	result := DecryptCBC(decodedBytes, key, iv, blockSize)
	fmt.Println(string(result))
}

func challenge11() {
	// ------------------------------------------------------------

	// 11. Write an oracle function and use it to detect ECB.

	// Now that you have ECB and CBC working:

	// Write a function to generate a random AES key; that's just 16 random
	// bytes.

	// Write a function that encrypts data under an unknown key --- that is,
	// a function that generates a random key and encrypts under it.

	// The function should look like:

	// encryption_oracle(your-input)
	//  => [MEANINGLESS JIBBER JABBER]

	// Under the hood, have the function APPEND 5-10 bytes (count chosen
	// randomly) BEFORE the plaintext and 5-10 bytes AFTER the plaintext.

	// Now, have the function choose to encrypt under ECB 1/2 the time, and
	// under CBC the other half (just use random IVs each time for CBC). Use
	// rand(2) to decide which to use.

	// Now detect the block cipher mode the function is using each time.

	// ------------------------------------------------------------
	fmt.Println("Challenge 11")

	resource := "./resources/detect_ecb.txt"

	// open file handle and read contents
	fin, err := ioutil.ReadFile(resource)
	if err != nil {
		log.Fatal(err)
	}

	encryptedBytes := randomEncryptionOracle(string(fin))

	isECB := detectECB(encryptedBytes)
	fmt.Println("isECB: ", isECB)
}

func challenge12() {
	// ------------------------------------------------------------

	// 12. Byte-at-a-time ECB decryption, Full control version

	// Copy your oracle function to a new function that encrypts buffers
	// under ECB mode using a consistent but unknown key (for instance,
	// assign a single random key, once, to a global variable).

	// Now take that same function and have it append to the plaintext,
	// BEFORE ENCRYPTING, the following string:

	//   Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg
	//   aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq
	//   dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg
	//   YnkK

	// SPOILER ALERT: DO NOT DECODE THIS STRING NOW. DON'T DO IT.

	// Base64 decode the string before appending it. DO NOT BASE64 DECODE THE
	// STRING BY HAND; MAKE YOUR CODE DO IT. The point is that you don't know
	// its contents.

	// What you have now is a function that produces:

	//   AES-128-ECB(your-string || unknown-string, random-key)

	// You can decrypt "unknown-string" with repeated calls to the oracle
	// function!

	// Here's roughly how:

	// a. Feed identical bytes of your-string to the function 1 at a time ---
	// start with 1 byte ("A"), then "AA", then "AAA" and so on. Discover the
	// block size of the cipher. You know it, but do this step anyway.

	// b. Detect that the function is using ECB. You already know, but do
	// this step anyways.

	// c. Knowing the block size, craft an input block that is exactly 1 byte
	// short (for instance, if the block size is 8 bytes, make
	// "AAAAAAA"). Think about what the oracle function is going to put in
	// that last byte position.

	// d. Make a dictionary of every possible last byte by feeding different
	// strings to the oracle; for instance, "AAAAAAAA", "AAAAAAAB",
	// "AAAAAAAC", remembering the first block of each invocation.

	// e. Match the output of the one-byte-short input to one of the entries
	// in your dictionary. You've now discovered the first byte of
	// unknown-string.

	// f. Repeat for the next byte.

	// ANSWER:
	// Rollin' in my 5.0
	// With my rag-top down so my hair can blow
	// The girlies on standby waving just to say hi
	// Did you stop? No, I just drove by

	// ------------------------------------------------------------
	fmt.Println("Challenge 12")

	// create global random key
	blockSize := 16
	randomKey := createRandomKey(blockSize)

	// load secret message
	secretMessageFile := "./resources/secret_message.txt"
	secretMessageBytes := decodeFile(secretMessageFile)
	secret_message := string(secretMessageBytes)

	// secret_message := "secret message"

	sizeSecretMessage := len(secret_message)

	// declare an uninitialized byte-array to append decrypted bytes
	var decryptedMessageBytes []byte

	// create a plain text injection message of size BLOCK less 1 byte
	plainTextInjectionMessage := "AAAAAAAAAAAAAAA"

	// iterate through bytes of secret message, creating a slice of the secret message byte array for plain text injection
	for q := 0; q < sizeSecretMessage; q++ {
		secretMessageSlice := secret_message[q:sizeSecretMessage]

		// append the secret message to the injected text
		plainText := plainTextInjectionMessage + secretMessageSlice

		// encrypt via AES-ECB
		cypherText := encryptionOracle(plainText, randomKey, true)

		// store the first block of the cypher text
		matchBlock := cypherText[0:16]

		byteMap := map[string][]byte{}

		// iterate through ASCII byte space and inject an ASCII byte into the last position
		// of the first 15 bytes of the first block
		for i := 0; i < 256; i++ {
			injectedByte := string(i)

			testBlock := plainTextInjectionMessage + injectedByte

			check := encryptionOracle(testBlock, randomKey, true)

			firstBlock := check[0:16]

			byteMap[string(firstBlock)] = []byte(injectedByte)
		}

		// match the last byte of the first block - this will be the first byte of the secret message
		decryptedByte := byteMap[string(matchBlock)]

		// append the the decrypted byte
		decryptedMessageBytes = append(decryptedMessageBytes, decryptedByte...)
	}
	fmt.Println(string(decryptedMessageBytes))
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

func encryptionOracle(input string, key []byte, withPKCS bool) (output []byte) {
	if withPKCS {
		paddedBytes := padWithPKCS7([]byte(input), 16)
		output = EncryptECB(paddedBytes, key, 16)
	} else {
		nullBytes := make([]byte, 16)

		inputBytes := []byte(input)
		fmt.Println("Input bytes: ", inputBytes)

		lenInput := len(input)
		fmt.Println("Len Input:", lenInput)

		for i := 0; i < lenInput; i++ {
			nullBytes[i] = inputBytes[i]
		}

		fmt.Println("Null Padded bytes: ", nullBytes)

		output = EncryptECB(nullBytes, key, 16)
		fmt.Println("Encrypted Null Padded bytes:", output)
	}

	return output
}

func randomEncryptionOracle(input string) (output []byte) {
	// prependedBytes := prependRandomBytes([]byte(input))
	// appendedBytes := appendRandomBytes(prependedBytes)

	blockSize := 16

	// paddedBytes := padBytes(appendedBytes, blockSize)
	paddedBytes := padWithPKCS7([]byte(input), blockSize)

	randomKey := createRandomKey(blockSize)
	coinFlip := randInt(1, 2)

	if coinFlip == 1 {
		fmt.Println("Chose CBC")
		iv := createRandomIV(blockSize)
		output = EncryptCBC(paddedBytes, randomKey, iv, blockSize)
	} else {
		fmt.Println("Chose ECB")
		output = EncryptECB(paddedBytes, randomKey, blockSize)
	}

	return output
}

func prependRandomBytes(input []byte) []byte {
	nBeforeBytes := randInt(5, 10)
	prependBytes := make([]byte, nBeforeBytes)

	for i := 0; i < nBeforeBytes; i++ {
		prependBytes[i] = byte(rand.Int())
	}

	prependBytes = append(prependBytes, input...)

	return prependBytes
}

func appendRandomBytes(input []byte) []byte {
	nAfterBytes := randInt(5, 10)

	appendBytes := make([]byte, nAfterBytes)
	for i := 0; i < nAfterBytes; i++ {
		appendBytes[i] = byte(rand.Int())
	}

	appendBytes = append(input, appendBytes...)

	return appendBytes
}

func createRandomIV(size int) []byte {
	return createRandomKey(size)
}

func createRandomKey(size int) (key []byte) {
	key = make([]byte, size)
	for i := 0; i < size; i++ {
		// random int range is range of printable ASCII characters
		key[i] = byte(randInt(32, 126))
	}
	return key
}

func randInt(min int, max int) int {
	// max is exclusive NOT inclusive for INTN, so add 1.
	max = max + 1
	return min + rand.Intn(max-min)
}

func XORStrings(a string, b string) (xorBytes []byte, err error) {
	byteArray01 := []byte(a)
	byteArray02 := []byte(b)

	srcLen := len(byteArray01)
	trgLen := len(byteArray02)

	if srcLen != trgLen {
		return xorBytes, errors.New("Strings are not equal length.")
	}

	xorBytes = make([]byte, srcLen)

	for i := 0; i < srcLen; i++ {
		xorBytes[i] = byteArray01[i] ^ byteArray02[i]
	}

	return xorBytes, err
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

func EncryptECB(input []byte, key []byte, blockSize int) (output []byte) {
	// fmt.Println("input size: ", len(input))
	// fmt.Println("blockSize: ", blockSize)

	numBlocks := len(input) / blockSize
	// fmt.Println("numBlocks to iterate: ", numBlocks)

	// allocate storage for encrypted bytes
	output = make([]byte, len(input))
	// fmt.Println("len of output bytes: ", len(output))

	// initialize new AES ECB cipher
	block, _ := aes.NewCipher(key)

	// iterate over byte arrays and encrypt
	for i := 0; i < numBlocks; i++ {
		begin := i * blockSize
		end := (begin + blockSize) - 1
		block.Encrypt(output[begin:end], input[begin:end])
	}

	return output
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

func DecryptECB(input []byte, key []byte, blockSize int) (output []byte) {
	numBlocks := len(input) / blockSize

	// allocate storage for encrypted bytes
	output = make([]byte, len(input))

	// initialize new AES ECB cipher
	block, _ := aes.NewCipher(key)

	// iterate over byte arrays and encrypt
	for i := 0; i < numBlocks; i++ {
		begin := i * blockSize
		end := (begin + blockSize) - 1
		block.Decrypt(output[begin:end], input[begin:end])
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

func padWithPKCS7(input []byte, blockLength int) []byte {
	// fmt.Println("original bytes: ", input)

	output := padBytes(input, blockLength)
	// fmt.Println("padded bytes: ", output)

	lastByteIdx := len(output)
	// fmt.Println("Last byte idx: ", lastByteIdx)

	if lastByteIdx == 0 {
		log.Fatal("0-length input string.")
	}

	// get value of last byte
	lastByte := output[lastByteIdx-1 : lastByteIdx]
	// fmt.Println("Pad Byte: ", lastByte)

	// pad value will never be 0x0
	padValues := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F}

	// fmt.Println("Contains Pad value: ", bytes.Contains(padValues, []byte(lastByte)))

	if !bytes.Contains(padValues, []byte(lastByte)) {
		extraBytes := make([]byte, blockLength)

		// pad out to 0x16
		for i := 0; i < blockLength; i++ {
			extraBytes[i] = 0x10
		}

		output = append(output, extraBytes...)
	}

	// fmt.Println("Padded PKCS7 bytes: ", output)

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

func decodeFile(resource string) []byte {
	// open file handle and read contents
	fin, err := ioutil.ReadFile(resource)
	if err != nil {
		log.Fatal(err)
	}

	// allocate memory at least as large as source size in bytes
	decodedBytes := make([]byte, len(fin))

	// decode the file
	n, err := base64.StdEncoding.Decode(decodedBytes, fin)
	if err != nil {
		log.Fatal(err)
	}

	// trim slice to actual size of data
	return decodedBytes[:n]
}

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

func detectECB(encryptedBytes []byte) bool {
	// this detects ECB by looking for common lines.
	r := bytes.NewReader(encryptedBytes)

	// create hashmap that will reference ALL lines that are AES-128 ECB encrypted
	// the hash KEY will be the line-number, the hash VALUE will be the number of dupe blocks detected.
	detectedAESData := map[int]int{}

	lineNumber := 1

	scanner := bufio.NewScanner(r)

	// read each line
	for scanner.Scan() {
		txt := scanner.Text()
		// fmt.Println(txt)
		lineBytes := []byte(txt)

		// split blocks according to block size (16 for AES-128)
		blocks := createBlocks(lineBytes, 16)

		// create the hashmap that will track dupe blocks
		dupeBlockDetector := map[string]int{}

		// iterate across blocks, convert to hex-based string, and insert into hash map
		for idx := range blocks {
			hash := hex.EncodeToString(blocks[idx])
			dupeBlockDetector[hash] += 1
		}

		// check hashmap for dupes
		for _, v := range dupeBlockDetector {
			if v > 1 {
				detectedAESData[lineNumber] += v
			}
		}

		lineNumber += 1
	}

	for k, _ := range detectedAESData {
		fmt.Println("Detected AES-encrypted line at #", k)
		return true
	}

	if err := scanner.Err(); err != nil {
		log.Fatal(err)
	}

	return false
}
