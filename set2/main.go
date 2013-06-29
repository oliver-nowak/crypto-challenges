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
	// "os"
	"time"
)

func main() {
	fmt.Println("Matasano Crypto Challenges for Set 02")

	rand.Seed(time.Now().UTC().UnixNano())

	// challenge09()
	// challenge10()
	challenge11()
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

	bytes := padBytes([]byte(input), 20)

	output := string(bytes)
	fmt.Println(output)
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

	test := encryptionOracle(string(fin))

	isECB := detectECB(test)
	fmt.Println("isECB: ", isECB)
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

func encryptionOracle(input string) (output []byte) {
	prependedBytes := prependRandomBytes([]byte(input))
	appendedBytes := appendRandomBytes(prependedBytes)

	blockSize := 16

	randomKey := createRandomKey(blockSize)
	coinFlip := randInt(1, 2)

	if coinFlip == 1 {
		fmt.Println("Chose CBC")
		iv := createRandomIV(blockSize)
		output = EncryptCBC(appendedBytes, randomKey, iv, blockSize)
	} else {
		fmt.Println("Chose ECB")
		output = EncryptECB(appendedBytes, randomKey, blockSize)
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

func padBytes(input []byte, blockLength int) []byte {
	// implements PKCS#7 padding
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
