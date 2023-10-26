package crc16

import (
	"math/bits"
)

// model represents a structure for the CRC-16 Hash.
type model struct {
	sum   uint16
	table *Table
}

// implementation of the hash.Hash

// Reset resets the Hash to its initial state.
func (r *model) Reset() {
	r.sum = r.table.params.Init
}

// Size returns the number of bytes Sum will return.
func (r *model) Size() int { return Size }

// BlockSize returns the hash's underlying block size.
// The Write method must be able to accept any amount of data,
// but it may operate more efficiently if all writes are a multiple of the block size.
func (r *model) BlockSize() int { return BlockSize }

// Write appends the data to the digest.
func (r *model) Write(p []byte) (int, error) {
	r.update(p)

	return len(p), nil
}

// Sum appends the current hash to b and returns the resulting slice.
// It does not change the underlying hash state.
func (r *model) Sum(b []byte) []byte {
	s := r.Sum16()

	return append(b, byte(s>>8), byte(s))
}

// implementation of the crc16.Hash

// Sum16 returns the Hash checksum.
func (r *model) Sum16() uint16 {
	return r.complete()
}

// private

// update refreshes the sum by adding to underlying data.
func (r *model) update(data []byte) {
	for _, d := range data {
		if r.table.params.RefIn {
			d = bits.Reverse8(d)
		}

		r.sum = r.sum<<8 ^ r.table.data[byte(r.sum>>8)^d]
	}
}

// complete returns the result of Hash calculation for the data inserted by update().
func (r *model) complete() uint16 {
	if r.table.params.RefOut {
		return bits.Reverse16(r.sum) ^ r.table.params.XorOut
	}

	return r.sum ^ r.table.params.XorOut
}

// checksum returns the checksum of the given data.
func (r *model) checksum(data []byte) uint16 {
	r.Reset()
	r.update(data)

	return r.complete()
}
