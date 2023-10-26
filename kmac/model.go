package kmac

import (
	"golang.org/x/crypto/sha3"
)

// model represents a structure for the KMAC Hash.
type model struct {
	sha3.ShakeHash
	size      int
	blockSize int
	// initBlock is the KMAC specific initialization byte array.
	// It will be initialized by newKmac function and stores the encoded key.
	// Reset() will use it to reset the hash state.
	initBlock []byte
}

// Reset resets the hash to initial state.
func (k *model) Reset() {
	k.ShakeHash.Reset()

	_, err := k.Write(addPadding(k.initBlock, k.BlockSize()))
	if err != nil {
		panic(err)
	}
}

// Size returns the tag size.
func (k *model) Size() int {
	return k.size
}

// BlockSize returns the hash's underlying block size.
// The Write method must be able to accept any amount of data,
// but it may operate more efficiently if all writes are a multiple of the absorb size.
func (k *model) BlockSize() int {
	return k.blockSize
}

// Sum appends the current KMAC to b and returns the resulting slice.
// It does not change the underlying hash state.
func (k *model) Sum(b []byte) []byte {
	dup := k.ShakeHash.Clone()

	_, err := dup.Write(rightEncode(uint64(k.size * 8)))
	if err != nil {
		panic(err)
	}

	hash := make([]byte, k.size)

	_, err = dup.Read(hash)
	if err != nil {
		panic(err)
	}

	return append(b, hash...)
}
