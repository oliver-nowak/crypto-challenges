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
		t.Error("Result bytes do not equal expected bytes")
	}
}
