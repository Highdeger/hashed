// Package md2 implements the MD2 hash algorithm.
package md2

import "hash"

// New creates a new MD2 hash.Hash.
func New() hash.Hash {
	h := new(model)
	h.Reset()

	return h
}
