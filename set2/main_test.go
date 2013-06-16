package main

import (
	"bytes"
	// hex "encoding/hex"
	"testing"
)

func Test_PKCS7Padding_1(t *testing.T) {
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

func Test_PKCS7Padding_2(t *testing.T) {
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

func Test_PKCS7Padding_3(t *testing.T) {
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

func Test_EncryptECB_1(t *testing.T) {
	testInput := []byte("This is a test message for test.") // 32 bytes
	key := []byte("YELLOW SUBMARINE")
	blockSize := 16
	expectedBytes := []byte{89, 245, 143, 60, 140, 62, 115, 150, 176, 229, 133, 179, 184, 50, 45, 56, 205, 111, 243, 102, 37, 238, 93, 84, 198, 195, 120, 77, 212, 151, 173, 187}
	expectedByteLen := 32

	result := EncryptECB(testInput, key, blockSize)

	if len(result) != expectedByteLen {
		t.Error("Result does not equal expected value.")
	}

	if !bytes.Equal(result, expectedBytes) {
		t.Error("Result bytes do not equal expected bytes.")
	}
}

func Test_DecryptECB_2(t *testing.T) {
	testInput := []byte{89, 245, 143, 60, 140, 62, 115, 150, 176, 229, 133, 179, 184, 50, 45, 56, 205, 111, 243, 102, 37, 238, 93, 84, 198, 195, 120, 77, 212, 151, 173, 187}
	key := []byte("YELLOW SUBMARINE")
	blockSize := 16
	expectedByteLen := 32
	expectedResult := []byte("This is a test message for test.") // 32 bytes

	result := DecryptECB(testInput, key, blockSize)

	if len(result) != expectedByteLen {
		t.Error("Result does not equal expected value.")
	}

	if !bytes.Equal(result, expectedResult) {
		t.Error("Result bytes do not equal expected bytes.")
	}
}

func Test_XORStrings_1(t *testing.T) {
	// Test XOR'ing strings of equal length

	alphaString := string("CAFEBABE")
	betaString := string("DEADMEAT")
	expectedResult := []byte{7, 4, 7, 1, 15, 4, 3, 17}

	result, err := XORStrings(alphaString, betaString)

	if err != nil {
		t.Error(err)
	}

	if !bytes.Equal(result, expectedResult) {
		t.Error("Result is not equal to expected value.", err)
	}
}

func Test_XORStrings_2(t *testing.T) {
	// XOR the encrypted result *back* to the original string

	alphaString := string([]byte{7, 4, 7, 1, 15, 4, 3, 17})
	betaString := string("DEADMEAT")
	expectedResult := []byte("CAFEBABE")

	result, err := XORStrings(alphaString, betaString)

	if err != nil {
		t.Error(err)
	}

	if !bytes.Equal(result, expectedResult) {
		t.Error("Result is not equal to expected value.", err)
	}
}

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
