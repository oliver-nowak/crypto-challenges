package main

import (
	"bytes"
	hex "encoding/hex"
	"testing"
)

func Test_ConvertStringHexToBase64_1(t *testing.T) {
	// Test basic string hex conversion to base64

	hexString := string("49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d")
	expectedEncoding := string("SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t")

	// result, err := convertStringHexToBase64(hexString)

	// if err != nil {
	// 	t.Error(err)
	// }

	result := toBase64(hexString)

	if result != expectedEncoding {
		t.Error("Result is not equal to expected value", result)
	}
}

func Test_XorHexStrings_1(t *testing.T) {
	// Test XOR'ing hex strings of equal length

	alphaString := string("1c0111001f010100061a024b53535009181c")
	betaString := string("686974207468652062756c6c277320657965")
	expectedResult := string("746865206b696420646f6e277420706c6179")

	// result, err := xorHexStrings(alphaString, betaString)

	result, err := xor(alphaString, betaString)

	if err != nil {
		t.Error(err)
	}

	if result != expectedResult {
		t.Error("Result is not equal to expected value.", result)
	}
}

func Test_XorHexStrings_2(t *testing.T) {
	// Test for XOR'ing hex strings of different lengths raises error

	alphaString := string("1c0111001f010100061a024b53535009181c")
	betaString := string("6")

	// result, err := xorHexStrings(alphaString, betaString)

	result, err := xor(alphaString, betaString)

	if err == nil {
		t.Error("Expected error.")
	}

	if result != "" {
		t.Error("Expected result to be empty.")
	}
}

func Test_XorHexStrings_3(t *testing.T) {
	// Test for XOR'ing hex string against a single character

	alphaString := string("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736")
	betaString := string("58") // this is 0x58 as hex value or 'X' as ASCII value or (88) as int value

	expectedResult := string("Cooking MC's like a pound of bacon")

	result, err := xorByChar(alphaString, betaString)

	if err != nil {
		t.Error(err)
	}

	if result != expectedResult {
		t.Error("Result is not equal to expected value.", err)
	}
}

func Test_Score_1(t *testing.T) {
	// Test scoring string via character frequency 'etaoinshrdlu'

	testString := "Cooking MC's like a pound of bacon"
	expectedScore := 216

	result := score(testString)

	if int(result) != expectedScore {
		t.Error("Score was not equal to expected value.", result)
	}
}

func Test_RotatateASCIIChars_1(t *testing.T) {
	// Test iteration through ASCII chars as cypher key results in decryption of source string

	srcString := "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"
	expectedScore := 216
	expectedCypherResult := "Cooking MC's like a pound of bacon"
	expectedCypherKey := "58"

	// highestScore, cypherResult, cypherKey := rotateASCIIChars(srcString)
	cypherResult, cypherKey, highestScore := breakSingleCharXOR(srcString)

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

func Test_XORByKey_1(t *testing.T) {
	// Test XOR via given repeating key

	srcString := "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal"
	cypherKey := "ICE"
	expectedResult := "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f"

	srcBytes := hex.EncodeToString([]byte(srcString))

	keyBytes := hex.EncodeToString([]byte(cypherKey))

	// XOR by repeating key
	// result, err := xorByKey(srcBytes, keyBytes)
	result, err := xorWithKey(srcBytes, keyBytes)

	if err != nil {
		t.Error(err)
	}

	if result != expectedResult {
		t.Error("Result was not equal to expected value.")
	}

	// Decrypt result back into source string via the key
	// result, err = xorByKey(expectedResult, keyBytes)
	result, err = xorWithKey(expectedResult, keyBytes)

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

func Test_GetHammingDistance_1(t *testing.T) {
	// Test that hamming distance func returns expected value

	alpha := "this is a test"
	beta := "wokka wokka!!!"
	expected := 37

	result := getHammingDistance(alpha, beta)

	if result != expected {
		t.Error("Result was not equal to expected value.")
	}
}

func Test_GetHammingDistance_2(t *testing.T) {
	// Test that hamming distance returns expected value with known byte arrays

	alpha := "this is a test"
	beta := "wokka wokka!!!"

	alphaBytes := []byte{116, 104, 105, 115, 32, 105, 115, 32, 97, 32, 116, 101, 115, 116}
	betaBytes := []byte{119, 111, 107, 107, 97, 32, 119, 111, 107, 107, 97, 33, 33, 33}

	expectedScore := 37

	result := getHammingDistance(string(alphaBytes), string(betaBytes))

	if result != expectedScore {
		t.Error("Result was not equal to expected value.")
	}

	if alpha != string(alphaBytes) {
		t.Error("Expected test values are not equal.")
	}

	if beta != string(betaBytes) {
		t.Error("Expected test values are not equal.")
	}
}

func Test_XORBytes_1(t *testing.T) {
	// Test that XOR'ing two byte arrays of equal length produces expected result

	var alpha = []byte{116, 104, 105, 115, 32, 105, 115, 32, 97, 32, 116, 101, 115, 116}
	var beta = []byte{119, 111, 107, 107, 97, 32, 119, 111, 107, 107, 97, 33, 33, 33}
	var expected = []byte{3, 7, 2, 24, 65, 73, 4, 79, 10, 75, 21, 68, 82, 85}

	result, err := xorBytes(alpha, beta)

	if err != nil {
		t.Error(err)
	}

	if !bytes.Equal(result, expected) {
		t.Error("Result was not equal to expected value.")
	}
}

func Test_XORBytes_2(t *testing.T) {
	// Test that XOR'ing two byte arrays of differing lengths produces expected error

	var alpha = []byte{116, 104, 105, 115, 32, 105, 115, 32, 97, 32, 116, 101, 115, 116}
	var beta = []byte{119, 111, 107, 107, 97, 32, 119, 111, 107, 107, 97, 33, 33}

	_, err := xorBytes(alpha, beta)

	if err == nil {
		t.Error("Result did not throw expected error.")
	}
}

func Test_Pop_1(t *testing.T) {
	// Test that summing bits of provided byte results in expected value

	var x uint8 = 3 // expressed as 0011 in binary
	var expected int = 2

	result := pop(x)

	if result != expected {
		t.Error("Result was not equal to expected value.")
	}
}

func Test_DecodeFile_1(t *testing.T) {
	// Test that decoding a base64 encoded file produces the correct output

	resource := "./resources/test_encoded.txt"
	expectedHexString := "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f"
	expectedResult := []byte{11, 54, 55, 39, 42, 43, 46, 99, 98, 44, 46, 105, 105, 42, 35, 105, 58, 42, 60, 99, 36, 32, 45, 98, 61, 99, 52, 60, 42, 38, 34, 99, 36, 39, 39, 101, 39, 42, 40, 43, 47, 32, 67, 10, 101, 46, 44, 101, 42, 49, 36, 51, 58, 101, 62, 43, 32, 39, 99, 12, 105, 43, 32, 40, 49, 101, 40, 99, 38, 48, 46, 39, 40, 47}

	result := decodeFile(resource)

	if !bytes.Equal(result, expectedResult) {
		t.Error("Result was not equal to expected value.")
	}

	resultHexString := hex.EncodeToString(result)

	if resultHexString != expectedHexString {
		t.Error("ResultHexString was not equal to expected value.")
	}
}

func Test_DecodeFileAndXOR_1(t *testing.T) {
	// Test that decoding base64 encoded file and decrypting via known XOR key produces correct output

	resource := "./resources/test_encoded.txt"
	cypherKey := "ICE"
	expectedResult := "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal"

	decodedBytes := decodeFile(resource)

	srcString := hex.EncodeToString(decodedBytes)
	keyBytes := hex.EncodeToString([]byte(cypherKey))

	// result, err := xorByKey(srcString, keyBytes)
	result, err := xorWithKey(srcString, keyBytes)

	if err != nil {
		t.Error(err)
	}

	resultBytes, _ := hex.DecodeString(result)
	resultString := string(resultBytes)

	if resultString != expectedResult {
		t.Error("Result was not equal to expected value.")
	}
}

func Test_ScanKeySizes_1(t *testing.T) {
	// iterations = 3
	// the point of this test is to prove that the key size encode = 3 is the top keysize
	// this has been encode with 'ICE'
	// key := 'ICE'
	// srcString := "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal"
	expectedTopKeySize := 3
	var expectedScore float32 = 2.222222
	encodedString := "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f"

	stringBytes, _ := hex.DecodeString(encodedString)

	distanceMap := scanKeySizes(stringBytes, 2, 12, 3)

	if distanceMap[expectedTopKeySize] > distanceMap[2] {
		t.Error("Key Size result was not not expected result.")
	}

	if distanceMap[3] != expectedScore {
		t.Error("Key Score result was not expected value.")
	}
}

func Test_ScanKeySizes_2(t *testing.T) {
	// iterations = 3
	expectedTopKeySize := 3
	var expectedScore float32 = 2.222222
	resource := "./resources/test_encoded.txt"

	// get byte-array holding decoded data from file
	stringBytes := decodeFile(resource)

	distanceMap := scanKeySizes(stringBytes, 2, 12, 3)

	if distanceMap[expectedTopKeySize] > distanceMap[2] {
		t.Error("Key Size result was not not expected result.")
	}

	if distanceMap[3] != expectedScore {
		t.Error("Key Score result was not expected value.")
	}
}

func Test_ScanKeySizes_3(t *testing.T) {
	resource := "./resources/gistfile2.txt"
	expectedTopKeySize := 29

	// get byte-array holding decoded data from file
	stringBytes := decodeFile(resource)

	distanceMap := scanKeySizes(stringBytes, 2, 40, 32)

	// iterate over result map and check that distanceMap[29] is lowest
	for k, _ := range distanceMap {
		if k != expectedTopKeySize {
			if distanceMap[expectedTopKeySize] > distanceMap[k] {
				t.Error("Key Score result was not expected value.")
			}
		}
	}
}
