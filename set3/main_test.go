package main

import (
	"bytes"
	hex "encoding/hex"
	"testing"
)

// xorByChar()
func Test_XorHexStrings_4(t *testing.T) {
	// Test for XOR'ing hex string against a single character byte

	alphaString := string("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736")
	// betaString := string("58")

	expectedResult := string("Cooking MC's like a pound of bacon")
	// this is 0x58 as hex value or 'X' as ASCII value or (88) as int value
	result, err := xorByChar(alphaString, 0x58)

	if err != nil {
		t.Error(err)
	}

	if result != expectedResult {
		t.Error("Result is not equal to expected value.", err)
	}
}

// score()
func Test_Score_1(t *testing.T) {
	// Test scoring string via character frequency 'etaoinshrdlu'

	testString := "Cooking MC's like a pound of bacon"
	expectedScore := 216

	result := score(testString)

	if int(result) != expectedScore {
		t.Error("Score was not equal to expected value.", result)
	}
}

// rotateASCIIChars()
func Test_RotatateASCIIChars_1(t *testing.T) {
	// Test iteration through ASCII chars as cypher key results in decryption of source string

	srcString := "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"
	expectedScore := 216
	expectedCypherResult := "Cooking MC's like a pound of bacon"
	expectedCypherKey := byte(0x58) //"58"

	highestScore, cypherResult, cypherKey := rotateASCIIChars(srcString)

	if int(highestScore) != expectedScore {
		t.Error("HighestScore was not equal to expected value.", highestScore)
	}

	if cypherResult != expectedCypherResult {
		t.Error("CypherResult was not equal to expected value.", cypherResult)
	}

	if cypherKey != expectedCypherKey {
		t.Error("CypherKey was not equal to expected value.", cypherKey)
	}
}

// scanKeys()
// DecryptCTR()
// EncryptCTR()
// DecryptCBC()
func Test_DecryptCBC_1(t *testing.T) {
	// test decryption
	input := []byte{89, 245, 143, 60, 140, 62, 115, 150, 176, 229, 133, 179, 184, 50, 45, 56, 147, 121, 79, 122, 30, 173, 189, 143, 201, 130, 154, 2, 158, 128, 0, 63}
	key := []byte("YELLOW SUBMARINE")
	blockSize := 16
	iv := make([]byte, blockSize)
	expectedResult := []byte("This is a test message for test.")

	result := DecryptCBC(input, key, iv, blockSize)

	if !bytes.Equal(result, expectedResult) {
		t.Error("Result is not equal to expected value.")
	}
}

func Test_Encrypt_DecryptCBC_1(t *testing.T) {
	// test that you can encrypt/decrypt in one pass
	input := []byte("This is a test message for test.") // 32 bytes
	key := []byte("YELLOW SUBMARINE")
	blockSize := 16
	iv := make([]byte, blockSize)

	dst := EncryptCBC(input, key, iv, blockSize)
	result := DecryptCBC(dst, key, iv, blockSize)

	if !bytes.Equal(result, input) {
		t.Error("Round-trip CBC Encrypt-Decrypt result is not equal to expected value.")
	}
}

// EncryptCBC()
func Test_EncryptCBC_1(t *testing.T) {
	// encrypt via AES-CBC

	input := []byte("This is a test message for test.") // 32 bytes
	key := []byte("YELLOW SUBMARINE")
	blockSize := 16
	iv := make([]byte, blockSize)
	expectedResult := []byte{89, 245, 143, 60, 140, 62, 115, 150, 176, 229, 133, 179, 184, 50, 45, 56, 147, 121, 79, 122, 30, 173, 189, 143, 201, 130, 154, 2, 158, 128, 0, 63}

	result := EncryptCBC(input, key, iv, blockSize)

	if !bytes.Equal(result, expectedResult) {
		t.Error("Result is not equal to expected value.")
	}
}

// createTransposeBlocks()
// createBlocks()
// validate()
// padBytes()
func Test_Padding_1(t *testing.T) {
	input := []byte("CAFEBABE")
	blockLength := 16
	expectedByteLen := 16
	expectedResult := []byte{67, 65, 70, 69, 66, 65, 66, 69, 8, 8, 8, 8, 8, 8, 8, 8}

	result := padBytes(input, blockLength)

	if len(result) != expectedByteLen {
		t.Error("Result does not equal expected value.")
	}

	if !bytes.Equal(result, expectedResult) {
		t.Error("Result bytes do not equal expected bytes")
	}
}

func Test_Padding_2(t *testing.T) {
	input := []byte("CAFE")
	blockLength := 8
	expectedByteLen := 8
	expectedResult := []byte{67, 65, 70, 69, 4, 4, 4, 4}

	result := padBytes(input, blockLength)

	if len(result) != expectedByteLen {
		t.Error("Result does not equal expected value.")
	}

	if !bytes.Equal(result, expectedResult) {
		t.Error("Result bytes do not equal expected bytes")
	}
}

func Test_Padding_3(t *testing.T) {
	input := []byte("FOO")
	blockLength := 8
	expectedByteLen := 8
	expectedResult := []byte{70, 79, 79, 5, 5, 5, 5, 5}

	result := padBytes(input, blockLength)

	if len(result) != expectedByteLen {
		t.Error("Result does not equal expected value.")
	}

	if !bytes.Equal(result, expectedResult) {
		t.Error("Result bytes do not equal expected bytes.")
	}
}

func Test_Padding_4(t *testing.T) {
	input := []byte("DEADMEATCAF") // 11 bytes
	blockLength := 8
	expectedByteLen := 16
	expectedResult := []byte{68, 69, 65, 68, 77, 69, 65, 84, 67, 65, 70, 5, 5, 5, 5, 5}

	result := padBytes(input, blockLength)

	if len(result) != expectedByteLen {
		t.Error("Result does not equal expected value.")
	}

	if !bytes.Equal(result, expectedResult) {
		t.Error("Result bytes do not equal expected bytes.")
	}
}

func Test_Padding_5(t *testing.T) {
	input := []byte("DEADMEATCAFEBABE") // 16 bytes
	blockLength := 16
	expectedByteLen := 16
	expectedResult := []byte{68, 69, 65, 68, 77, 69, 65, 84, 67, 65, 70, 69, 66, 65, 66, 69}

	result := padBytes(input, blockLength)

	if len(result) != expectedByteLen {
		t.Error("Result does not equal expected value.")
	}

	if !bytes.Equal(result, expectedResult) {
		t.Error("Result bytes do not equal expected bytes.")
	}
}

// padWithPKCS7
func Test_PKCS7Padding_1(t *testing.T) {
	input := []byte("CAFEBABE")
	blockLength := 16
	expectedByteLen := 16
	expectedResult := []byte{67, 65, 70, 69, 66, 65, 66, 69, 8, 8, 8, 8, 8, 8, 8, 8}

	result := padWithPKCS7(input, blockLength)

	if len(result) != expectedByteLen {
		t.Error("Result does not equal expected value.")
	}

	if !bytes.Equal(result, expectedResult) {
		t.Error("Result bytes do not equal expected bytes")
	}
}

func Test_PKCS7Padding_2(t *testing.T) {
	input := []byte("CAFE")
	blockLength := 8
	expectedByteLen := 8
	expectedResult := []byte{67, 65, 70, 69, 4, 4, 4, 4}

	result := padWithPKCS7(input, blockLength)

	if len(result) != expectedByteLen {
		t.Error("Result does not equal expected value.")
	}

	if !bytes.Equal(result, expectedResult) {
		t.Error("Result bytes do not equal expected bytes")
	}
}

func Test_PKCS7Padding_3(t *testing.T) {
	input := []byte("FOO")
	blockLength := 8
	expectedByteLen := 8
	expectedResult := []byte{70, 79, 79, 5, 5, 5, 5, 5}

	result := padWithPKCS7(input, blockLength)

	if len(result) != expectedByteLen {
		t.Error("Result does not equal expected value.")
	}

	if !bytes.Equal(result, expectedResult) {
		t.Error("Result bytes do not equal expected bytes.")
	}
}

func Test_PKCS7Padding_4(t *testing.T) {
	input := []byte("DEADMEATCAF") // 11 bytes
	blockLength := 8
	expectedByteLen := 16
	expectedResult := []byte{68, 69, 65, 68, 77, 69, 65, 84, 67, 65, 70, 5, 5, 5, 5, 5}

	result := padWithPKCS7(input, blockLength)

	if len(result) != expectedByteLen {
		t.Error("Result does not equal expected value.")
	}

	if !bytes.Equal(result, expectedResult) {
		t.Error("Result bytes do not equal expected bytes.")
	}
}

func Test_PKCS7Padding_5(t *testing.T) {
	input := []byte("DEADMEATCAFEBABE") // 16 bytes
	blockLength := 16
	expectedByteLen := 32
	expectedResult := []byte{68, 69, 65, 68, 77, 69, 65, 84, 67, 65, 70, 69, 66, 65, 66, 69, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16}

	result := padWithPKCS7(input, blockLength)

	if len(result) != expectedByteLen {
		t.Error("Result does not equal expected value.")
	}

	if !bytes.Equal(result, expectedResult) {
		t.Error("Result bytes do not equal expected bytes.")
	}
}

// encryptCBCWithPKCS7()
// xorByKey()
func Test_XORByKey_1(t *testing.T) {
	// Test XOR via given repeating key

	srcString := "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal"
	cypherKey := "ICE"
	expectedResult := "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f"

	srcBytes := hex.EncodeToString([]byte(srcString))

	keyBytes := hex.EncodeToString([]byte(cypherKey))

	// XOR by repeating key
	result, err := xorByKey(srcBytes, keyBytes)

	if err != nil {
		t.Error(err)
	}

	if result != expectedResult {
		t.Error("Result was not equal to expected value.")
	}

	// Decrypt result back into source string via the key
	result, err = xorByKey(expectedResult, keyBytes)

	// Decode hex-string into a byte-array
	resultBytes, _ := hex.DecodeString(result)

	// cast byte-array into string
	resultString := string(resultBytes)

	if err != nil {
		t.Error(err)
	}

	if resultString != srcString {
		t.Error("Result was not equal to expected value.")
	}
}

// XORBytes()
func Test_XORBytes_1(t *testing.T) {
	// Test XOR'ing byte-arrays of equal length

	alpha := []byte("CAFEBABE")
	beta := []byte("DEADMEAT")
	expectedResult := []byte{7, 4, 7, 1, 15, 4, 3, 17}

	result, err := XORBytes(alpha, beta)

	if err != nil {
		t.Error(err)
	}

	if !bytes.Equal(result, expectedResult) {
		t.Error("Result is not equal to expected value.", err)
	}
}

func Test_XORBytes_2(t *testing.T) {
	// XOR the encrypted result *back* to the original byte-array

	alpha := []byte{7, 4, 7, 1, 15, 4, 3, 17}
	beta := []byte("DEADMEAT")
	expectedResult := []byte("CAFEBABE")

	result, err := XORBytes(alpha, beta)

	if err != nil {
		t.Error(err)
	}

	if !bytes.Equal(result, expectedResult) {
		t.Error("Result is not equal to expected value.", err)
	}
}
