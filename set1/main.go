package main

import (
	"bufio"
	"bytes"
	aes "crypto/aes"
	"encoding/base64"
	hex "encoding/hex"
	"errors"
	"fmt"
	"io"
	ioutil "io/ioutil"
	"log"
	"os"
)

func main() {
	fmt.Println("Matasano Crypto Challenges for Set 01")
	fmt.Println("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~")

	challenge01()
	fmt.Println("---------------")

	challenge02()
	fmt.Println("---------------")

	challenge03()
	fmt.Println("---------------")

	challenge04()
	fmt.Println("---------------")

	challenge05()
	fmt.Println("---------------")

	challenge06()
	fmt.Println("---------------")

	challenge07()
	fmt.Println("---------------")

	challenge08()
}

func challenge01() {
	// ------------------------------------------------------------

	// 1. Convert hex to base64 and back.

	// The string:
	//   49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d

	// should produce:
	//   SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t

	// Now use this code everywhere for the rest of the exercises. Here's a
	// simple rule of thumb:

	//   Always operate on raw bytes, never on encoded strings. Only use hex
	//   and base64 for pretty-printing.
	// ------------------------------------------------------------
	fmt.Println("Challenge 01")

	stringToDecode := string("49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d")

	convertedData := toBase64(stringToDecode)

	fmt.Println(convertedData)
}

func challenge02() {
	// ------------------------------------------------------------

	// 2. Fixed XOR

	// Write a function that takes two equal-length buffers and produces
	// their XOR sum.

	// The string:

	//  1c0111001f010100061a024b53535009181c

	// ... after hex decoding, when xor'd against:

	//  686974207468652062756c6c277320657965

	// ... should produce:

	//  746865206b696420646f6e277420706c6179

	// ------------------------------------------------------------
	fmt.Println("Challenge 02")

	alphaString := string("1c0111001f010100061a024b53535009181c")
	betaString := string("686974207468652062756c6c277320657965")

	result, err := xor(alphaString, betaString)

	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(result)
}

func challenge03() {
	// ------------------------------------------------------------

	// 3. Single-character XOR Cipher

	// The hex encoded string:

	//       1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736

	// ... has been XOR'd against a single character. Find the key, decrypt
	// the message.

	// Write code to do this for you. How? Devise some method for "scoring" a
	// piece of English plaintext. (Character frequency is a good metric.)
	// Evaluate each output and choose the one with the best score.

	// Tune your algorithm until this works.

	// ANSWER: Cooking MC's like a pound of bacon
	// CYPHERKEY: 0x58

	// // ------------------------------------------------------------
	fmt.Println("Challenge 03")

	srcString := string("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736")

	cypherResult, cypherKey, highestScore := breakSingleCharXOR(srcString)

	fmt.Println("Score:  ", highestScore)
	fmt.Println("Result: ", cypherResult)
	fmt.Println("CypherKey: ", cypherKey)
}

func challenge04() {
	// ------------------------------------------------------------

	// 4. Detect single-character XOR

	// One of the 60-character strings at:

	//   https://gist.github.com/3132713

	// has been encrypted by single-character XOR. Find it. (Your code from
	// #3 should help.)

	// ANSWER: Now that the party is jumping
	// CYPHERKEY: 0x35

	// ------------------------------------------------------------
	fmt.Println("Challenge 04")

	file, err := os.Open("./resources/gistfile1.txt")
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()

	topCypherResult, topKey, topScore := detectSingleCharXOR(file)

	fmt.Println("Top Score:  ", topScore)
	fmt.Println("Top Result: ", topCypherResult)
	fmt.Println("Top Key: ", topKey)
}

func challenge05() {
	// ------------------------------------------------------------

	// 5. Repeating-key XOR Cipher

	// Write the code to encrypt the string:

	//   Burning 'em, if you ain't quick and nimble
	//   I go crazy when I hear a cymbal

	// Under the key "ICE", using repeating-key XOR. It should come out to:

	//   0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f

	// Encrypt a bunch of stuff using your repeating-key XOR function. Get a
	// feel for it.

	// ------------------------------------------------------------
	fmt.Println("Challenge 05")

	srcString := "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal"
	srcStringBytes := hex.EncodeToString([]byte(srcString))
	cypherKey := "ICE"
	cypherKeyBytes := hex.EncodeToString([]byte(cypherKey))

	xorString, err := xorWithKey(srcStringBytes, cypherKeyBytes)

	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(xorString)
}

func challenge06() {
	// ------------------------------------------------------------

	// 6. Break repeating-key XOR

	// The buffer at the following location:

	//  https://gist.github.com/3132752

	// is base64-encoded repeating-key XOR. Break it.

	// ------------------------------------------------------------
	fmt.Println("Challenge 06")

	resource := "./resources/gistfile2.txt"

	// get byte-array holding decoded data from file
	decodedBytes := decodeFile(resource)

	xorResult := breakXORWithKey(decodedBytes)

	fmt.Println(xorResult)
}

func challenge07() {
	// ------------------------------------------------------------

	// 7. AES in ECB Mode

	// The Base64-encoded content at the following location:

	//     https://gist.github.com/3132853

	// Has been encrypted via AES-128 in ECB mode under the key

	//     "YELLOW SUBMARINE".

	// (I like "YELLOW SUBMARINE" because it's exactly 16 bytes long).

	// Decrypt it.

	// Easiest way:

	// Use OpenSSL::Cipher and give it AES-128-ECB as the cipher.

	// ------------------------------------------------------------
	fmt.Println("Challenge 07")

	resource := "./resources/gistfile4.txt"

	// open file handle and read contents
	decodedBytes := decodeFile(resource)

	plainText := decryptAES_ECB(decodedBytes, "YELLOW SUBMARINE")

	fmt.Println(plainText)
}

func challenge08() {
	// ------------------------------------------------------------

	// 8. Detecting ECB

	// At the following URL are a bunch of hex-encoded ciphertexts:

	//    https://gist.github.com/3132928

	// One of them is ECB encrypted. Detect it.

	// Remember that the problem with ECB is that it is stateless and
	// deterministic; the same 16 byte plaintext block will always produce
	// the same 16 byte ciphertext.

	// ------------------------------------------------------------
	fmt.Println("Challenge 08")
	resource := "./resources/gistfile5.txt"

	f, err := os.Open(resource)
	if err != nil {
		log.Fatal(err)
	}

	detectAES_ECB(f)
}

////////////// -----------------------------------------------------

//////////////------------------------------------------------------

//////////////------------------------------------------------------

//////////////------------------------------------------------------

func toBase64(hexString string) (convertedData string) {
	convertedData, err := convertStringHexToBase64(hexString)
	if err != nil {
		log.Fatal(err)
	}

	return convertedData
}

func xor(a string, b string) (result string, err error) {
	result, err = xorHexStrings(a, b)

	return result, err
}

func xorWithKey(src, key string) (cipher string, err error) {
	cipher, err = xorByKey(src, key)
	if err != nil {
		log.Fatal(err)
	}

	return cipher, err
}

func breakSingleCharXOR(src string) (message, key string, score float32) {
	highestScore, cypherResult, cypherKey := rotateASCIIChars(src)

	return cypherResult, cypherKey, highestScore
}

func breakXORWithKey(src []byte) (message string) {
	// get top key sizes, along with their h-distance
	distanceMap := scanKeySizes(src, 2, 40, 20)

	// set a really high threshold - this is an arbritrary value
	keySize := 10000
	var topScore float32 = 100000.0000
	for k, v := range distanceMap {
		if v < topScore {
			topScore = v
			keySize = k
		}
	}

	// slice out all bytes from a particular key position
	transposedBlocks := createTransposeBlocks(src, keySize)

	// iterate over t-blocks and look for XOR keys
	key := scanKeys(transposedBlocks)

	srcString := hex.EncodeToString(src)

	//---------------------------USING SCANNED KEY TO DECRYPT----------------------

	hexKeyBytes := hex.EncodeToString(key)
	xorString, err := xorByKey(srcString, hexKeyBytes)
	if err != nil {
		log.Fatal(err)
	}

	xorBytes, _ := hex.DecodeString(xorString)
	message = string(xorBytes)

	return message
}

func decryptAES_ECB(src []byte, key string) (message string) {
	blockSize := 16

	// calculate number of blocks to decrypt
	numBlocks := len(src) / blockSize

	dst := make([]byte, len(src))

	block, err := aes.NewCipher([]byte(key))

	if err != nil {
		fmt.Println(err)
	}

	for i := 0; i < numBlocks; i++ {
		begin := i * blockSize
		end := (begin + blockSize)
		block.Decrypt(dst[begin:end], src[begin:end])
	}
	message = string(dst)

	return message
}

func detectAES_ECB(f io.Reader) {
	r := bufio.NewReader(f)

	// create hashmap that will reference ALL lines that are AES-128 ECB encrypted
	// the hash KEY will be the line-number, the hash VALUE will be the number of dupe blocks detected.
	detectedAESData := map[int]int{}

	lineNumber := 1

	scanner := bufio.NewScanner(r)

	// read each line
	for scanner.Scan() {
		txt := scanner.Text()
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
	}

	if err := scanner.Err(); err != nil {
		log.Fatal(err)
	}
}

func detectSingleCharXOR(file io.Reader) (topCypherResult, topKey string, topScore float32) {
	r := bufio.NewReader(file)
	s, _, e := r.ReadLine()

	topScore = 0.0000
	topCypherResult = ""
	topKey = ""

	for e == nil {
		line := string(s)

		// topCypherResult, topKey, topScore = detectSingleCharXOR(line)

		// highestScore, cypherResult, cypherKey := rotateASCIIChars(line)
		cypherResult, cypherKey, highestScore := breakSingleCharXOR(line)

		if highestScore > float32(topScore) {
			topScore = highestScore
			topCypherResult = cypherResult
			topKey = cypherKey
		}

		s, _, e = r.ReadLine()
	}

	return topCypherResult, topKey, topScore
}

//////////////------------------------------------------------------

//////////////------------------------------------------------------

//////////////------------------------------------------------------

//////////////------------------------------------------------------

//////////////------------------------------------------------------

//////////////------------------------------------------------------
func convertStringHexToBase64(hexString string) (encodedData string, err error) {
	rawBytes, err := hex.DecodeString(hexString)

	encodedData = base64.StdEncoding.EncodeToString(rawBytes)

	return encodedData, err
}

func xorHexStrings(a string, b string) (xorString string, err error) {
	byteArray01, err := hex.DecodeString(a)
	byteArray02, err := hex.DecodeString(b)

	srcLen := len(byteArray01)
	trgLen := len(byteArray02)

	if srcLen != trgLen {
		return "", errors.New("Strings are not equal length.")
	}

	xorBytes := make([]byte, srcLen)

	for i := 0; i < srcLen; i++ {
		xorBytes[i] = byteArray01[i] ^ byteArray02[i]
	}

	xorString = hex.EncodeToString(xorBytes)

	return xorString, err
}

func xorByChar(src string, cypher string) (xorString string, err error) {
	srcBytes, err := hex.DecodeString(src)
	cypherBytes, err := hex.DecodeString(cypher)

	srcLen := len(srcBytes)

	xorBytes := make([]byte, srcLen)

	for i := 0; i < srcLen; i++ {
		xorBytes[i] = srcBytes[i] ^ cypherBytes[0]
	}

	xorString = string(xorBytes)

	return xorString, err
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

func rotateASCIIChars(srcString string) (highestScore float32, cypherResult string, cypherKey string) {
	// iterate through visible ASCII char values
	for i := 32; i < 128; i++ {
		// convert the ASCII char int value into a byte array
		cypherTxt := []byte(string(i))

		// convert the byte-array into hex-based string value
		cypherString := hex.EncodeToString(cypherTxt)

		// XOR the source string via the cypher string
		result, err := xorByChar(srcString, cypherString)
		if err != nil {
			log.Fatal(err)
		}

		// score the result of the XOR operation
		score := score(result)

		// update the score
		if score > highestScore {
			highestScore = score
			cypherResult = result
			cypherKey = cypherString
		}
	}

	return highestScore, cypherResult, cypherKey
}

func getEncodedByteArray(src string) []byte {
	encodedHexString := hex.EncodeToString([]byte(src))
	hexBytes, err := hex.DecodeString(encodedHexString)

	if err != nil {
		log.Fatal(err)
	}

	return hexBytes
}

func xorBytes(a []byte, b []byte) (xorBytes []byte, err error) {
	aLen := len(a)
	bLen := len(b)

	if aLen != bLen {
		return xorBytes, errors.New("Strings are not equal length.")
	}

	xorBytes = make([]byte, aLen)

	for i := 0; i < aLen; i++ {
		xorBytes[i] = a[i] ^ b[i]
	}

	return xorBytes, err
}

func pop(x uint8) int {
	// Taken from Hacker's Delight p.70
	var sum uint8 = x

	for x != 0 {
		x = x >> 1
		sum = sum - x
	}

	return int(sum)
}

func getHammingDistance(alpha string, beta string) (distance int) {
	alphaBytes := getEncodedByteArray(alpha)
	betaBytes := getEncodedByteArray(beta)

	bytes, err := xorBytes(alphaBytes, betaBytes)
	if err != nil {
		log.Fatal(err)
	}

	byteLen := len(bytes)

	for i := 0; i < byteLen; i++ {
		distance += pop(bytes[i])
	}

	return distance
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

func scanKeySizes(decodedBytes []byte, minKeySize int, maxKeySize int, iterations int) map[int]float32 {
	// attach a reader for easier reading / seeking
	bufReader := bytes.NewReader(decodedBytes)

	// heuristic value
	var smallestDistance float32 = 1000.0000

	// stores KEYSIZES as keys, and normalized hamming distances as values
	topKeySizeMap := map[int]float32{}

	for currentKeySize := minKeySize; currentKeySize <= maxKeySize; currentKeySize++ {
		// allocate byte buffer
		buf := make([]byte, currentKeySize)

		var totalDist float32 = 0.0000
		for i := 0; i < iterations; i++ {
			// read CURRENTKEYSIZE from buffer
			_, err := bufReader.Read(buf)
			if err != nil {
				log.Fatal(err)
			}

			// store buffer contents as string for later processing
			alpha := string(buf)

			// read another CURRENTKEYSIZE from buffer
			_, err = bufReader.Read(buf)
			if err != nil {
				log.Fatal(err)
			}

			beta := string(buf)

			distance := getHammingDistance(alpha, beta)

			totalDist += float32(distance)
		}

		var mean float32 = totalDist / float32(iterations)
		var normDistance float32 = mean / float32(currentKeySize)

		if normDistance <= smallestDistance {
			smallestDistance = normDistance

			topKeySizeMap[currentKeySize] = normDistance
		}

		// reset reader back to 0 for next iteration of CURRENTKEYSIZE
		bufReader.Seek(0, os.SEEK_SET)
	}

	return topKeySizeMap
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

func scanKeys(transposedBlocks [][]byte) []byte {
	keyLen := len(transposedBlocks)

	key := make([]byte, keyLen)

	// iterate through list of transposed blocks and find the topscorer of the XOR scan within each t-block
	for blockIdx := range transposedBlocks {
		blockBytes := transposedBlocks[blockIdx]

		hexString := hex.EncodeToString(blockBytes)
		_, _, cypherKey := rotateASCIIChars(hexString)
		cypherByte, _ := hex.DecodeString(cypherKey)

		// store the first byte in the cypherByte array: **NOTE** it should only have one byte
		key[blockIdx] = cypherByte[0]
	}

	return key
}
