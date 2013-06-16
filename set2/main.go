package main

import (
	// hex "encoding/hex"
	aes "crypto/aes"
	"errors"
	"fmt"
	"log"
)

func main() {
	fmt.Println("Matasano Crypto Challenges for Set 02")

	challenge09()
	challenge10()
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

	input := []byte("This is a test message for test.") // 32 bytes
	key := []byte("YELLOW SUBMARINE")
	blockSize := 16

	dst, iv := EncryptCBC(input, key, blockSize)
	fmt.Println(dst)
	fmt.Println(iv)

	out := DecryptCBC(dst, key, iv, blockSize)
	fmt.Println(string(out))
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
	numBlocks := len(input) / blockSize

	// allocate storage for encrypted bytes
	output = make([]byte, len(input))

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

func EncryptCBC(input []byte, key []byte, blockSize int) (output []byte, iv []byte) {
	// implement CBC mode endcryption for AES
	// https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation

	iv = make([]byte, blockSize)
	fmt.Println("IV: ", iv)

	numBlocks := len(input) / blockSize
	fmt.Println("numBlocks: ", numBlocks)

	// allocate storage for encrypted bytes
	output = make([]byte, len(input))

	// initialize new AES ECB cipher
	block, _ := aes.NewCipher(key)

	// iterate over byte arrays and encrypt
	for i := 0; i < numBlocks; i++ {
		begin := i * blockSize
		end := (begin + blockSize)

		fmt.Println("begin: ", begin)
		fmt.Println("end: ", end)

		var result []byte
		var err error
		// on the very first iteration, XOR the plain-text with the IV
		// then encrypt the result and save in OUTPUT byte-array
		if i == 0 {
			result, err = XORBytes(input[begin:end], iv)
			if err != nil {
				log.Fatal(err)
			}

			// encrypt: result
			block.Encrypt(output[begin:end], result)
		} else {
			// on all remaining iterations, XOR the plain-text with the encrypted
			// result of the previous iteration
			// then encrypt the result and save in OUTPUT byte-array
			prevBegin := begin - blockSize
			prevEnd := (end - blockSize)
			fmt.Println("prevBegin: ", prevBegin)
			fmt.Println("prevEnd: ", prevEnd)

			result, err = XORBytes(input[begin:end], output[prevBegin:prevEnd])
			if err != nil {
				log.Fatal(err)
			}

			block.Encrypt(output[begin:end], result)
			// TODO: need idx of previous block
			// result, err = XORBytes(// plain-text of current block, // cyphertext of previous block)

			// encrypt: result
		}
		fmt.Println(result)
	}

	return output, iv
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
	fmt.Println("numBlocks: ", numBlocks)

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

		fmt.Println("begin: ", begin)
		fmt.Println("end: ", end)

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
			fmt.Println("prevBegin: ", prevBegin)
			fmt.Println("prevEnd: ", prevEnd)

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
		fmt.Println(output)
	}

	return output
}

func padBytes(block []byte, blockLength int) []byte {
	// implements PKCS#7 padding

	// derive the integer value
	pkcsIntValue := blockLength - len(block)

	// allocate storage of the size of pkcsIntValue
	padBytes := make([]byte, pkcsIntValue)

	// initialize the storage with the value pkcsIntValue
	for i := 0; i < pkcsIntValue; i++ {
		padBytes[i] = byte(pkcsIntValue)
	}

	// append pad bytes to end of block and return
	return append(block, padBytes...)
}
