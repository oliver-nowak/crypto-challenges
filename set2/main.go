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
	"net/url"
	"strings"
	"time"
)

func main() {
	fmt.Println("Matasano Crypto Challenges for Set 02")

	rand.Seed(time.Now().UTC().UnixNano())

	challenge09()

	fmt.Println("-------------------------------------------------------------")

	challenge10()

	fmt.Println("-------------------------------------------------------------")

	challenge11()

	fmt.Println("-------------------------------------------------------------")

	challenge12()

	fmt.Println("-------------------------------------------------------------")

	challenge13()

	fmt.Println("-------------------------------------------------------------")

	challenge14()

	fmt.Println("-------------------------------------------------------------")

	challenge15()

	fmt.Println("-------------------------------------------------------------")

	challenge16()

	fmt.Println("-------------------------------------------------------------")
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

	input := "WAXTRAX RECORDS"

	padded := padWithPKCS7([]byte(input), 16)

	fmt.Println("Padded (bytes) : ", padded)
	fmt.Println("Padded (string): ", string(padded))
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

	// create a plain text injection message of size BLOCK less 1 byte
	injection_message := "AAAAAAAAAAAAAAA"

	decryptedText := encryptInjectDecryptECB(injection_message, secret_message, randomKey)
	fmt.Println(decryptedText)
}

func challenge13() {
	// ------------------------------------------------------------

	// 13. ECB cut-and-paste

	// Write a k=v parsing routine, as if for a structured cookie. The
	// routine should take:

	//    foo=bar&baz=qux&zap=zazzle

	// and produce:

	//   {
	//     foo: 'bar',
	//     baz: 'qux',
	//     zap: 'zazzle'
	//   }

	// (you know, the object; I don't care if you convert it to JSON).

	// Now write a function that encodes a user profile in that format, given
	// an email address. You should have something like:

	//   profile_for("foo@bar.com")

	// and it should produce:

	//   {
	//     email: 'foo@bar.com',
	//     uid: 10,
	//     role: 'user'
	//   }

	// encoded as:

	//   email=foo@bar.com&uid=10&role=user

	// Your "profile_for" function should NOT allow encoding metacharacters
	// (& and =). Eat them, quote them, whatever you want to do, but don't
	// let people set their email address to "foo@bar.com&role=admin".

	// Now, two more easy functions. Generate a random AES key, then:

	//  (a) Encrypt the encoded user profile under the key; "provide" that
	//  to the "attacker".

	//  (b) Decrypt the encoded user profile and parse it.

	// Using only the user input to profile_for() (as an oracle to generate
	// "valid" ciphertexts) and the ciphertexts themselves, make a role=admin
	// profile.

	// ANSWER
	// ------------------------------------------------------------------------
	// 	original profile (no null padding at 65bytes)
	// email=onowak1234admin00000000000@olivernowak123.com&uid=10&role=user

	// original profile (with null padding at 80bytes)
	// email=onowak1234admin00000000000@olivernowak123.com&uid=10&role=user000000000000

	// crafted profile (with 16byte boundary)
	// email=onowak1234 admin00000000000 @olivernowak123. com&uid=10&role= user000000000000

	// crafted profile (collapsed)
	// email=onowak1234@olivernowak123.com&uid=10&role=admin00000000000

	// payload (16byte block)
	// admin00000000000

	// ------------------------------------------------------------
	fmt.Println("Challenge 13")

	// create global random key
	blockSize := 16
	randomKey := createRandomKey(blockSize)

	// create user profile param request
	profile := profileFor("onowak1234admin" + "           " + "@olivernowak123.com")
	fmt.Println("Profile: ", profile)

	// (client-side) encrypt via AES-ECB under some random key
	cypherText := EncryptECB([]byte(profile), randomKey, blockSize, true)

	// (server-side) decrypt request and handle
	plainTextBytes := DecryptECB(cypherText, randomKey, blockSize)
	fmt.Println("Decrypted ORIGINAL Profile      : ", string(plainTextBytes))

	// divide cypher text into 16byte blocks so we can rearrange.
	blocks := createBlocks(cypherText, blockSize)

	// declare new storage for rearranged bytes
	var craftedCypherBytes []byte

	// craft the new payload with the 'admin' byte block copied over the 'user' byte block
	craftedCypherBytes = append(craftedCypherBytes, blocks[0]...)
	craftedCypherBytes = append(craftedCypherBytes, blocks[2]...)
	craftedCypherBytes = append(craftedCypherBytes, blocks[3]...)
	craftedCypherBytes = append(craftedCypherBytes, blocks[1]...)

	// (server-side) decrypt malicious bytes
	params := DecryptECB(craftedCypherBytes, randomKey, blockSize)
	fmt.Println("Decrypted HACKED Profile        : ", string(params))

	// parse KV's for mass-assignment
	user, _ := url.ParseQuery(string(params))

	userEmail := user.Get("email")
	fmt.Println("Email: ", userEmail)

	userUID := user.Get("uid")
	fmt.Println("UID: ", userUID)

	userRole := user.Get("role")
	fmt.Println("Role: ", userRole)
}

func challenge14() {
	// ------------------------------------------------------------

	// 14. Byte-at-a-time ECB decryption, Partial control version

	// Take your oracle function from #12. Now generate a random count of
	// random bytes and prepend this string to every plaintext. You are now
	// doing:

	//   AES-128-ECB(random-prefix || attacker-controlled || target-bytes, random-key)

	// Same goal: decrypt the target-bytes.

	// What's harder about doing this?

	// How would you overcome that obstacle? The hint is: you're using
	// all the tools you already have; no crazy math is required.

	// Think about the words "STIMULUS" and "RESPONSE".

	// // ------------------------------------------------------------
	fmt.Println("Challenge 14")

	// create global random key
	blockSize := 16
	randomKey := createRandomKey(blockSize)

	// create random bytes
	randomBytes := getRandomBytes(5, 10)
	fmt.Println("Random Bytes: ", randomBytes)

	// load secret message
	secretMessageFile := "./resources/secret_message.txt"
	secretMessageBytes := decodeFile(secretMessageFile)
	secret_message := string(secretMessageBytes)

	// create a plain text injection message of size BLOCK less size RANDOMBYTES and less 1 byte
	injectionMessage := getInjectionMessage(blockSize, len(randomBytes))
	fmt.Println("Resizable Injection Message: ", injectionMessage)

	// append random bytes
	injectionPayload := string(randomBytes) + injectionMessage

	// decrypt
	decryptedText := encryptInjectDecryptECB(injectionPayload, secret_message, randomKey)
	fmt.Println(decryptedText)
}

func challenge15() {
	// ------------------------------------------------------------

	// 15. PKCS#7 padding validation

	// Write a function that takes a plaintext, determines if it has valid
	// PKCS#7 padding, and strips the padding off.

	// The string:

	//     "ICE ICE BABY\x04\x04\x04\x04"

	// has valid padding, and produces the result "ICE ICE BABY".

	// The string:

	//     "ICE ICE BABY\x05\x05\x05\x05"

	// does not have valid padding, nor does:

	//      "ICE ICE BABY\x01\x02\x03\x04"

	// If you are writing in a language with exceptions, like Python or Ruby,
	// make your function throw an exception on bad padding.

	// ------------------------------------------------------------
	fmt.Println("Challenge 15")

	inputA := "ICE ICE BABY\x04\x04\x04\x04"
	fmt.Println("inputA: ", inputA)

	strippedInput, isValid := validatePadding(inputA)
	fmt.Println("inputA isValid? ", isValid)
	if isValid {
		fmt.Println("inputA Stripped Input: ", strippedInput)
	}

	fmt.Println("---")

	inputB := "ICE ICE BABY\x05\x05\x05\x05"
	fmt.Println("inputB: ", inputB)

	strippedInput, isValid = validatePadding(inputB)
	fmt.Println("inputB isValid? ", isValid)
	if isValid {
		fmt.Println("inputB Stripped Input: ", strippedInput)
	}

	fmt.Println("---")

	inputC := "ICE ICE BABY\x01\x02\x03\x04"
	fmt.Println("inputC: ", inputC)

	strippedInput, isValid = validatePadding(inputC)
	fmt.Println("inputC isValid? ", isValid)
	if isValid {
		fmt.Println("inputC Stripped Input: ", strippedInput)
	}

	fmt.Println("---")

	inputD := "YELLOW SUBMARINE\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10"
	fmt.Println("inputD: ", inputD)

	strippedInput, isValid = validatePadding(inputD)
	fmt.Println("inputD isValid? ", isValid)
	if isValid {
		fmt.Println("inputD Stripped Input: ", strippedInput)
	}

	fmt.Println("---")

	inputE := "YOU\x0D\x0D\x0D\x0D\x0D\x0D\x0D\x0D\x0D\x0D\x0D\x0D\x0D"
	fmt.Println("inputE: ", inputE)

	strippedInput, isValid = validatePadding(inputE)
	fmt.Println("inputE isValid? ", isValid)
	if isValid {
		fmt.Println("inputE Stripped Input: ", strippedInput)
	}

	fmt.Println("---")

	inputF := padWithPKCS7([]byte("YOU"), 16)
	fmt.Println("inputF: ", inputF)

	strippedInput, isValid = validatePadding(string(inputF))
	fmt.Println("inputF isValid? ", isValid)
	if isValid {
		fmt.Println("inputF Stripped Input: ", strippedInput)
	}
}

func challenge16() {
	// ------------------------------------------------------------

	// 16. CBC bit flipping

	// Generate a random AES key.

	// Combine your padding code and CBC code to write two functions.

	// The first function should take an arbitrary input string, prepend the
	// string:
	//         "comment1=cooking%20MCs;userdata="
	// and append the string:
	//     ";comment2=%20like%20a%20pound%20of%20bacon"

	// The function should quote out the ";" and "=" characters.

	// The function should then pad out the input to the 16-byte AES block
	// length and encrypt it under the random AES key.

	// The second function should decrypt the string and look for the
	// characters ";admin=true;" (or, equivalently, decrypt, split the stringb
	// on ;, convert each resulting string into 2-tuples, and look for the
	// "admin" tuple. Return true or false based on whether the string exists.

	// If you've written the first function properly, it should not be
	// possible to provide user input to it that will generate the string the
	// second function is looking for.

	// Instead, modify the ciphertext (without knowledge of the AES key) to
	// accomplish this.

	// You're relying on the fact that in CBC mode, a 1-bit error in a
	// ciphertext block:

	// * Completely scrambles the block the error occurs in

	// * Produces the identical 1-bit error (/edit) in the next ciphertext
	//  block.

	// Before you implement this attack, answer this question: why does CBC
	// mode have this property?

	// ------------------------------------------------------------

	fmt.Println("Challenge 16")

	// create global random key
	blockSize := 16
	randomKey := createRandomKey(blockSize)

	// create CBC IV
	iv := createRandomIV(blockSize)

	// get encrypted bytes which include
	cypherBytes := paddedEncryptionOracle("Skinny Puppy", randomKey, iv)

	// this is the token string we want to audit during our bit-flip operation
	adminToken := ";admin=true;"

	// 0-indexed scalar for first byte in the second block (which is the 'target' block)
	idx := 16

	// set flag for bit-flip operation success
	hasAdminPriv := false

	// store the successful bitflipped string here
	adminString := ""

	// iterate through the tokens of the adminToken string
	// for each token, scan the ASCII byte space to find the bit-flipped equivalent
	// once its found, move on to the next token.
	for i := 0; i < len(adminToken); i++ {
		currentToken := string(adminToken[i])

		// current byte index of the second block
		currIdx := idx + i

		// iterate through the ASCII byte space and flip the corresponding bit
		for q := 0; q < 256; q++ {
			cypherBytes[i] = byte(q)

			// send the request to the server and check results
			strippedInput, isAdmin := checkAdminAccess(cypherBytes, randomKey, iv)
			if isAdmin {
				hasAdminPriv = true
				adminString = strippedInput
				break
			}

			// if the bit-flip operation is successful for a particular token, move on.
			isReady := strings.Contains(strippedInput[currIdx:currIdx+1], currentToken)
			if isReady {
				break
			}
		}

		// exit if we have admin privileges - no need to continue.
		if hasAdminPriv {
			break
		}
	}

	if hasAdminPriv {
		fmt.Println("CBC Plain-text : ", adminString)
		fmt.Println("GOT ADMIN PRIVILEGES. WOULD YOU LIKE TO PLAY A GAME?")
	}
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

func checkAdminAccess(cypherBytes []byte, randomKey []byte, iv []byte) (strippedInput string, isAdmin bool) {
	adminToken := ";admin=true;"

	plainTextBytes := DecryptCBC(cypherBytes, randomKey, iv, 16)

	plainText := string(plainTextBytes)

	strippedInput, ok := validatePadding(plainText)
	if !ok {
		log.Fatal("Invalid Padding.")
	}

	isAdmin = strings.Contains(strippedInput, adminToken)

	return strippedInput, isAdmin
}

func paddedEncryptionOracle(attackString string, randomKey []byte, iv []byte) (cypherBytes []byte) {
	prependString := "comment1=cooking%20MCs;userdata="
	appendString := ";comment2=%20like%20a%20pound%20of%20bacon"

	payload := prependString + attackString + appendString
	fmt.Println("Payload        : ", payload)

	encodedPayload := url.QueryEscape(payload)
	fmt.Println("Encoded Payload: ", encodedPayload)

	cypherBytes = encryptCBCWithPKCS7(encodedPayload, randomKey, iv)

	return cypherBytes
}

func validatePadding(input string) (strippedInput string, ok bool) {
	inputBytes := []byte(input)

	inputBlocks := createBlocks(inputBytes, 16)

	numBlocks := len(inputBlocks)

	lastBlock := inputBlocks[numBlocks-1]

	lastByte := lastBlock[15]

	// pad index lookup table
	padIdxTable := []int{16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0}

	padValue := int(lastByte)

	// create padded byte slice for comparison
	padBytes := bytes.Repeat([]byte{lastByte}, int(lastByte))

	// find out the index of the padded byte slice
	startPadIdx := bytes.Index(lastBlock, padBytes)

	padIdx := padIdxTable[padValue]

	// compare index with lookup table
	if padIdx == startPadIdx {
		ok = true
	}

	// strip the padding
	if ok {
		lastBlock = lastBlock[0:startPadIdx]

		inputBlocks[numBlocks-1] = lastBlock

		for i := 0; i < numBlocks; i++ {
			strippedInput += string(inputBlocks[i])
		}

		return strippedInput, ok
	}

	return strippedInput, false
}

func isPKCSPadByte(token byte) bool {
	pkcsBytes := []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
	isByte := bytes.Contains(pkcsBytes, []byte{token})
	return isByte
}

func getInjectionMessage(blockSize int, sizeOfChunk int) (injectionMessage string) {
	sizeOfInjectionMessage := (blockSize - (sizeOfChunk % blockSize)) - 1

	for i := 0; i < sizeOfInjectionMessage; i++ {
		injectionMessage += "A"
	}

	return injectionMessage
}

func profileFor(email string) (profile string) {
	cleanedEmailString := strings.Replace(email, "&", "", -1)
	cleanedEmailString = strings.Replace(cleanedEmailString, "=", "", -1)

	profile = "email=" + cleanedEmailString + "&" + "uid=10&role=user"

	return profile
}

func encryptInjectDecryptECB(injection_message string, secret_message string, randomKey []byte) (decryptedText string) {
	sizeSecretMessage := len(secret_message)

	// declare an uninitialized byte-array to append decrypted bytes
	var decryptedMessageBytes []byte

	// iterate through bytes of secret message, creating a slice of the secret message byte array for plain text injection
	for q := 0; q < sizeSecretMessage; q++ {
		secretMessageSlice := secret_message[q:sizeSecretMessage]

		// append the secret message to the injected text
		plainText := injection_message + secretMessageSlice

		// encrypt via AES-ECB
		cypherText := EncryptECB([]byte(plainText), randomKey, 16, true)

		// store the first block of the cypher text
		matchBlock := cypherText[0:16]

		byteMap := map[string][]byte{}

		// iterate through ASCII byte space and inject an ASCII byte into the last position
		// of the first 15 bytes of the first block
		for i := 0; i < 256; i++ {
			injectedByte := string(i)

			testBlock := injection_message + injectedByte

			check := EncryptECB([]byte(testBlock), randomKey, 16, true)

			firstBlock := check[0:16]

			byteMap[string(firstBlock)] = []byte(injectedByte)
		}

		// match the last byte of the first block - this will be the first byte of the secret message
		decryptedByte := byteMap[string(matchBlock)]

		// append the the decrypted byte
		decryptedMessageBytes = append(decryptedMessageBytes, decryptedByte...)
	}

	decryptedText = string(decryptedMessageBytes)

	return decryptedText
}

func encryptECBWithPKCS7(input string, key []byte) (output []byte) {
	paddedBytes := padWithPKCS7([]byte(input), 16)
	output = EncryptECB(paddedBytes, key, 16, true)

	return output
}

func encryptCBCWithPKCS7(input string, key []byte, iv []byte) (output []byte) {
	paddedBytes := padWithPKCS7([]byte(input), 16)
	output = EncryptCBC(paddedBytes, key, iv, 16)

	return output
}

func randomEncryptionOracle(input string) (output []byte) {
	prependedBytes := prependRandomBytes([]byte(input))
	appendedBytes := appendRandomBytes(prependedBytes)

	blockSize := 16

	paddedBytes := padWithPKCS7(appendedBytes, blockSize)

	randomKey := createRandomKey(blockSize)
	coinFlip := randInt(1, 2)

	if coinFlip == 1 {
		fmt.Println("Chose CBC")
		iv := createRandomIV(blockSize)
		output = EncryptCBC(paddedBytes, randomKey, iv, blockSize)
	} else {
		fmt.Println("Chose ECB")
		output = EncryptECB(paddedBytes, randomKey, blockSize, true)
	}

	return output
}

func getRandomBytes(min int64, max int64) (randomBytes []byte) {
	nBeforeBytes := randInt(5, 10)
	randomBytes = make([]byte, nBeforeBytes)

	for i := 0; i < nBeforeBytes; i++ {
		randomBytes[i] = byte(rand.Int())
	}
	return randomBytes
}

func prependRandomBytes(input []byte) (prependedBytes []byte) {
	randomBytes := getRandomBytes(5, 10)

	prependedBytes = append(randomBytes, input...)

	return prependedBytes
}

func appendRandomBytes(input []byte) (appendedBytes []byte) {
	randomBytes := getRandomBytes(5, 10)

	appendedBytes = append(input, randomBytes...)

	return appendedBytes
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

func EncryptECB(input []byte, key []byte, blockSize int, withNullPad bool) (output []byte) {
	if withNullPad {
		nullPaddingSizeInBytes := blockSize - (len(input) % blockSize)

		nullPadding := make([]byte, nullPaddingSizeInBytes)

		input = append(input, nullPadding...)
	}

	numBlocks := len(input) / blockSize

	// allocate storage for encrypted bytes
	output = make([]byte, len(input))

	// initialize new AES ECB cipher
	block, err := aes.NewCipher(key)

	if err != nil {
		fmt.Println(err)
	}

	// iterate over byte arrays and encrypt
	for i := 0; i < numBlocks; i++ {
		begin := i * blockSize
		end := (begin + blockSize)
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
		end := (begin + blockSize)
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
