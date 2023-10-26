package ripemd

import (
	"math/bits"
)

// modelRipeMd128 represents a structure for the RIPEMD-128 hash.Hash.
type modelRipeMd128 struct {
	sum            [4]uint32
	buffer         [BlockSize128]byte
	bufferIndex    int
	processedBytes uint64
}

// implementation of the hash.Hash

// Reset resets the hash.Hash to its initial state.
func (r *modelRipeMd128) Reset() {
	r.sum[0], r.sum[1], r.sum[2], r.sum[3] = _s0, _s1, _s2, _s3
	r.bufferIndex = 0
	r.processedBytes = 0
}

// Size returns the number of bytes Sum will return.
func (r *modelRipeMd128) Size() int { return Size128 }

// BlockSize returns the hash's underlying block size.
// The Write method must be able to accept any amount of data,
// but it may operate more efficiently if all writes are a multiple of the update size.
func (r *modelRipeMd128) BlockSize() int { return BlockSize128 }

// Write appends the data to the digest.
func (r *modelRipeMd128) Write(p []byte) (int, error) {
	l := len(p)
	r.processedBytes += uint64(l)

	if r.bufferIndex > 0 {
		n := len(p)
		if n > BlockSize128-r.bufferIndex {
			n = BlockSize128 - r.bufferIndex
		}

		for i := 0; i < n; i++ {
			r.buffer[r.bufferIndex+i] = p[i]
		}

		r.bufferIndex += n
		if r.bufferIndex == BlockSize128 {
			r.update(r.buffer[0:])
			r.bufferIndex = 0
		}

		p = p[n:]
	}

	n := r.update(p)
	p = p[n:]

	if len(p) > 0 {
		r.bufferIndex = copy(r.buffer[:], p)
	}

	return l, nil
}

// Sum appends the current hash to b and returns the resulting slice.
// It does not change the underlying hash state.
func (r *modelRipeMd128) Sum(b []byte) []byte {
	// make a copy to allow other writes to continue and to prevent change of the state
	h := *r

	processedBytes := h.processedBytes
	var tmp [64]byte
	tmp[0] = 0x80

	if processedBytes%64 < 56 {
		_, err := h.Write(tmp[0 : 56-processedBytes%64])
		if err != nil {
			panic(err)
		}
	} else {
		_, err := h.Write(tmp[0 : 64+56-processedBytes%64])
		if err != nil {
			panic(err)
		}
	}

	processedBytes <<= 3
	for i := uint(0); i < 8; i++ {
		tmp[i] = byte(processedBytes >> (8 * i))
	}

	_, err := h.Write(tmp[0:8])
	if err != nil {
		panic(err)
	}

	h.assertEmptyBuffer()
	var digest [Size128]byte

	for i, s := range h.sum {
		digest[i*4] = byte(s)
		digest[i*4+1] = byte(s >> 8)
		digest[i*4+2] = byte(s >> 16)
		digest[i*4+3] = byte(s >> 24)
	}

	return append(b, digest[:]...)
}

// private

// update refresh the sum by adding one block to underlying data.
// It will ignore bytes beyond one block and returns the number of bytes processed.
func (r *modelRipeMd128) update(block []byte) int {
	var (
		n         = 0
		tempArray [16]uint32
		tempN     uint32
	)

	for len(block) >= BlockSize128 {
		n1, n2, n3, n4 := r.sum[0], r.sum[1], r.sum[2], r.sum[3]
		n1a, n2a, n3a, n4a := n1, n2, n3, n4

		j := 0
		for i := 0; i < 16; i++ {
			tempArray[i] = uint32(block[j]) | uint32(block[j+1])<<8 | uint32(block[j+2])<<16 | uint32(block[j+3])<<24
			j += 4
		}

		// round 1
		i := 0
		for i < 16 {
			tempN = n1 + (n2 ^ n3 ^ n4) + tempArray[substituteBufferIndices128n0[i]]
			substitute := int(substituteBufferIndices128r0[i])
			tempN = bits.RotateLeft32(tempN, substitute)
			n1, n2, n3, n4 = n4, tempN, n2, n3

			tempN = n1a + (n3a ^ (n4a & (n2a ^ n3a))) + tempArray[substituteBufferIndices128n1[i]] + 0x50a28be6
			substitute = int(substituteBufferIndices128r1[i])
			tempN = bits.RotateLeft32(tempN, substitute)
			n1a, n2a, n3a, n4a = n4a, tempN, n2a, n3a

			i++
		}

		// round 2
		for i < 32 {
			tempN = n1 + (n4 ^ (n2 & (n3 ^ n4))) + tempArray[substituteBufferIndices128n0[i]] + 0x5a827999
			s := int(substituteBufferIndices128r0[i])
			tempN = bits.RotateLeft32(tempN, s)
			n1, n2, n3, n4 = n4, tempN, n2, n3

			tempN = n1a + (n4a ^ (n2a | ^n3a)) + tempArray[substituteBufferIndices128n1[i]] + 0x5c4dd124
			s = int(substituteBufferIndices128r1[i])
			tempN = bits.RotateLeft32(tempN, s)
			n1a, n2a, n3a, n4a = n4a, tempN, n2a, n3a

			i++
		}

		// round 3
		for i < 48 {
			tempN = n1 + (n4 ^ (n2 | ^n3)) + tempArray[substituteBufferIndices128n0[i]] + 0x6ed9eba1
			s := int(substituteBufferIndices128r0[i])
			tempN = bits.RotateLeft32(tempN, s)
			n1, n2, n3, n4 = n4, tempN, n2, n3

			tempN = n1a + (n4a ^ (n2a & (n3a ^ n4a))) + tempArray[substituteBufferIndices128n1[i]] + 0x6d703ef3
			s = int(substituteBufferIndices128r1[i])
			tempN = bits.RotateLeft32(tempN, s)
			n1a, n2a, n3a, n4a = n4a, tempN, n2a, n3a

			i++
		}

		// round 4
		for i < 64 {
			tempN = n1 + (n3 ^ (n4 & (n2 ^ n3))) + tempArray[substituteBufferIndices128n0[i]] + 0x8f1bbcdc
			s := int(substituteBufferIndices128r0[i])
			tempN = bits.RotateLeft32(tempN, s)
			n1, n2, n3, n4 = n4, tempN, n2, n3

			tempN = n1a + (n2a ^ n3a ^ n4a) + tempArray[substituteBufferIndices128n1[i]]
			s = int(substituteBufferIndices128r1[i])
			tempN = bits.RotateLeft32(tempN, s)
			n1a, n2a, n3a, n4a = n4a, tempN, n2a, n3a

			i++
		}

		// finalize
		n3 = r.sum[1] + n3 + n4a
		r.sum[1] = r.sum[2] + n4 + n1a
		r.sum[2] = r.sum[3] + n1 + n2a
		r.sum[3] = r.sum[0] + n2 + n3a
		r.sum[0] = n3

		block = block[BlockSize128:]
		n += BlockSize128
	}

	return n
}

// assertEmptyBuffer asserts that the buffer is empty and if not, panics.
func (r *modelRipeMd128) assertEmptyBuffer() {
	if r.bufferIndex > 0 {
		panic("buffer should be empty")
	}
}
