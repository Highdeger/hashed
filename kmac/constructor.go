// Package kmac implements the KMAC hash algorithm.
package kmac

import (
	"golang.org/x/crypto/sha3"
	"hash"
)

// New128 creates a new KMAC-128 hash.Hash.
// Key must have at least 16 bytes, or it will panic.
// Size must be 8 at minimum, or it will panic.
//
// Returned hash.Hash unlike the ones in standard library
// does not implement encoding.BinaryMarshaler or encoding.BinaryUnmarshaler.
func New128(key []byte, size int, customizationString []byte) hash.Hash {
	if len(key) < 16 {
		panic("KMAC-128 key must not be smaller than 16 bytes")
	}

	return newKmac(sha3.NewCShake128([]byte("KMAC"), customizationString), key, size, BlockSize128)
}

// New256 creates a new KMAC-256 hash.Hash.
// Key must have at least 32 bytes, or it will panic.
// Size must be 8 at minimum, or it will panic.
//
// Returned hash.Hash unlike the ones in standard library
// does not implement encoding.BinaryMarshaler or encoding.BinaryUnmarshaler.
func New256(key []byte, size int, customizationString []byte) hash.Hash {
	if len(key) < 32 {
		panic("KMAC-256 key must not be smaller than 32 bytes")
	}

	return newKmac(sha3.NewCShake256([]byte("KMAC"), customizationString), key, size, BlockSize256)
}

// newKmac creates a new KMAC hash.Hash.
// Key must have at least 16 bytes for KMAC-128 and 32 bytes for KMAC-256, or it will panic.
// Size must be 8 at minimum, or it will panic.
//
// Returned hash.Hash unlike the ones in standard library
// does not implement encoding.BinaryMarshaler or encoding.BinaryUnmarshaler.
func newKmac(cShakeHash sha3.ShakeHash, key []byte, size, blockSize int) hash.Hash {
	if size < 8 {
		panic("KMAC size must be at least 8")
	}

	h := &model{ShakeHash: cShakeHash, size: size, blockSize: blockSize}
	h.initBlock = make([]byte, 0, 9+len(key))
	h.initBlock = append(h.initBlock, leftEncode(uint64(len(key)*8))...)
	h.initBlock = append(h.initBlock, key...)

	_, err := h.Write(addPadding(h.initBlock, h.BlockSize()))
	if err != nil {
		panic(err)
	}

	return h
}
