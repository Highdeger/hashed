// Package keccak implements the KECCAK hash algorithm.
package keccak

import "hash"

// New224 creates a new KECCAK-224 hash.Hash.
func New224() hash.Hash { return newKeccak(Size224, BlockSize224, DomainNone) }

// New256 creates a new KECCAK-256 hash.Hash.
func New256() hash.Hash { return newKeccak(Size256, BlockSize256, DomainNone) }

// New384 creates a new KECCAK-384 hash.Hash.
func New384() hash.Hash { return newKeccak(Size384, BlockSize384, DomainNone) }

// New512 creates a new KECCAK-512 hash.Hash.
func New512() hash.Hash { return newKeccak(Size512, BlockSize512, DomainNone) }

// newKeccak creates a new KECCAK hash.Hash.
func newKeccak(size, blockSize int, domain byte) hash.Hash {
	h := new(model)
	h.size = size
	h.blockSize = blockSize
	h.domain = domain

	return h
}
