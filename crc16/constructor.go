// Package crc16 implements the CRC-16 (16-bit cyclic redundancy check) hash algorithm.
package crc16

import "hash"

// Hash represents a crc16.Hash.
type Hash interface {
	hash.Hash
	Sum16() uint16
}

// New creates a new CRC-16 Hash with the given table.
func New(table *Table) Hash {
	h := new(model)
	h.table = table
	h.Reset()

	return h
}
