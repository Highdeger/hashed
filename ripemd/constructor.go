// Package ripemd implements the RIPEMD hash algorithm.
package ripemd

import "hash"

// New128 creates a new RIPMD-128 hash.Hash.
func New128() hash.Hash {
	r := new(modelRipeMd128)
	r.Reset()

	return r
}

// New160 creates a new RIPMD-160 hash.Hash.
func New160() hash.Hash {
	result := new(modelRipeMd160)
	result.Reset()

	return result
}

// New256 creates a new RIPMD-256 hash.Hash.
func New256() hash.Hash {
	r := new(modelRipeMd256)
	r.Reset()

	return r
}

// New320 creates a new RIPMD-320 hash.Hash.
func New320() hash.Hash {
	r := new(modelRipeMd320)
	r.Reset()

	return r
}
