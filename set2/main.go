package main

import (
	// hex "encoding/hex"
	"fmt"
	// "log"
)

func main() {
	fmt.Println("Matasano Crypto Challenges for Set 02")

	challenge09()
}

func challenge09() {
	fmt.Println("Challenge 09")

	input := "YELLOW SUBMARINE"

	bytes := padBytes([]byte(input), 20)

	output := string(bytes)
	fmt.Println(output)
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
