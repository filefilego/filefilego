package currency

import (
	"log"
	"math/big"
)

// FFGZero zero
func FFGZero() *big.Int {
	return big.NewInt(0)
}

// FFGZero zero
func FFGOne() *big.Int {
	return big.NewInt(1)
}

// KFFG 1K
func KFFG() *big.Int {
	return big.NewInt(1000)
}

// MFFG 1M
func MFFG() *big.Int {
	return big.NewInt(1000000)
}

// GFFG 1B
func GFFG() *big.Int {
	return big.NewInt(1000000000)
}

// MicroFFG 1T
func MicroFFG() *big.Int {
	return big.NewInt(1000000000000)
}

// MiliFFG 1T * 1000
func MiliFFG() *big.Int {
	return big.NewInt(1000000000000000)
}

// FFG
func FFG() *big.Int {
	return big.NewInt(1000000000000000000)
}

// ZFFG
func ZFFG() *big.Int {
	val, ok := big.NewInt(0).SetString("1000000000000000000000", 10)
	if !ok {
		log.Fatal("failed to set a ZFFG big integer")
	}
	return val
}
