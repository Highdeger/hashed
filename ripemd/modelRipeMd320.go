package ripemd

import (
	"math/bits"
)

// modelRipeMd320 represents a structure for the RIPEMD-320 hash.Hash.
type modelRipeMd320 struct {
	sum            [10]uint32
	buffer         [BlockSize320]byte
	bufferIndex    int
	processedBytes uint64
}

// implementation of the hash.Hash

// Reset resets the hash.Hash to its initial state.
func (r *modelRipeMd320) Reset() {
	r.sum[0], r.sum[1], r.sum[2], r.sum[3], r.sum[4] = _s0, _s1, _s2, _s3, _s4
	r.sum[5], r.sum[6], r.sum[7], r.sum[8], r.sum[9] = _s5, _s6, _s7, _s8, _s9
	r.bufferIndex = 0
	r.processedBytes = 0
}

// Size returns the number of bytes Sum will return.
func (r *modelRipeMd320) Size() int { return Size320 }

// BlockSize returns the hash's underlying block size.
// The Write method must be able to accept any amount of data,
// but it may operate more efficiently if all writes are a multiple of the update size.
func (r *modelRipeMd320) BlockSize() int { return BlockSize320 }

// Write appends the data to the digest.
func (r *modelRipeMd320) Write(p []byte) (int, error) {
	l := len(p)
	r.processedBytes += uint64(l)

	if r.bufferIndex > 0 {
		n := len(p)
		if n > BlockSize320-r.bufferIndex {
			n = BlockSize320 - r.bufferIndex
		}

		for i := 0; i < n; i++ {
			r.buffer[r.bufferIndex+i] = p[i]
		}

		r.bufferIndex += n
		if r.bufferIndex == BlockSize320 {
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
func (r *modelRipeMd320) Sum(b []byte) []byte {
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
	var digest [Size320]byte

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
func (r *modelRipeMd320) update(block []byte) int {
	var (
		n         = 0
		tempArray [16]uint32
		tempN1    uint32
		tempN2    uint32
	)

	for len(block) >= BlockSize320 {
		n1, n2, n3, n4, n5 := r.sum[0], r.sum[1], r.sum[2], r.sum[3], r.sum[4]
		n1a, n2a, n3a, n4a, n5a := r.sum[5], r.sum[6], r.sum[7], r.sum[8], r.sum[9]

		j := 0
		for i := 0; i < 16; i++ {
			tempArray[i] = uint32(block[j]) | uint32(block[j+1])<<8 | uint32(block[j+2])<<16 | uint32(block[j+3])<<24
			j += 4
		}

		// round 1
		i := 0
		for i < 16 {
			tempN1 = n1 + (n2 ^ n3 ^ n4) + tempArray[substituteBufferIndices320n0[i]]
			s := int(substituteBufferIndices320r0[i])
			tempN1 = bits.RotateLeft32(tempN1, s) + n5
			tempN2 = bits.RotateLeft32(n3, 10)
			n1, n2, n3, n4, n5 = n5, tempN1, n2, tempN2, n4

			tempN1 = n1a + (n2a ^ (n3a | ^n4a)) + tempArray[substituteBufferIndices320n1[i]] + 0x50a28be6
			s = int(substituteBufferIndices320r1[i])
			tempN1 = bits.RotateLeft32(tempN1, s) + n5a
			tempN2 = bits.RotateLeft32(n3a, 10)
			n1a, n2a, n3a, n4a, n5a = n5a, tempN1, n2a, tempN2, n4a

			i++
		}

		temp := n2
		n2 = n2a
		n2a = temp

		// round 2
		for i < 32 {
			tempN1 = n1 + (n4 ^ (n2 & (n3 ^ n4))) + tempArray[substituteBufferIndices320n0[i]] + 0x5a827999
			s := int(substituteBufferIndices320r0[i])
			tempN1 = bits.RotateLeft32(tempN1, s) + n5
			tempN2 = bits.RotateLeft32(n3, 10)
			n1, n2, n3, n4, n5 = n5, tempN1, n2, tempN2, n4

			tempN1 = n1a + (n3a ^ (n4a & (n2a ^ n3a))) + tempArray[substituteBufferIndices320n1[i]] + 0x5c4dd124
			s = int(substituteBufferIndices320r1[i])
			tempN1 = bits.RotateLeft32(tempN1, s) + n5a
			tempN2 = bits.RotateLeft32(n3a, 10)
			n1a, n2a, n3a, n4a, n5a = n5a, tempN1, n2a, tempN2, n4a

			i++
		}

		temp = n4
		n4 = n4a
		n4a = temp

		// round 3
		for i < 48 {
			tempN1 = n1 + (n4 ^ (n2 | ^n3)) + tempArray[substituteBufferIndices320n0[i]] + 0x6ed9eba1
			s := int(substituteBufferIndices320r0[i])
			tempN1 = bits.RotateLeft32(tempN1, s) + n5
			tempN2 = bits.RotateLeft32(n3, 10)
			n1, n2, n3, n4, n5 = n5, tempN1, n2, tempN2, n4

			tempN1 = n1a + (n4a ^ (n2a | ^n3a)) + tempArray[substituteBufferIndices320n1[i]] + 0x6d703ef3
			s = int(substituteBufferIndices320r1[i])
			tempN1 = bits.RotateLeft32(tempN1, s) + n5a
			tempN2 = bits.RotateLeft32(n3a, 10)
			n1a, n2a, n3a, n4a, n5a = n5a, tempN1, n2a, tempN2, n4a

			i++
		}

		temp = n1
		n1 = n1a
		n1a = temp

		// round 4
		for i < 64 {
			tempN1 = n1 + (n3 ^ (n4 & (n2 ^ n3))) + tempArray[substituteBufferIndices320n0[i]] + 0x8f1bbcdc
			s := int(substituteBufferIndices320r0[i])
			tempN1 = bits.RotateLeft32(tempN1, s) + n5
			tempN2 = bits.RotateLeft32(n3, 10)
			n1, n2, n3, n4, n5 = n5, tempN1, n2, tempN2, n4

			tempN1 = n1a + (n4a ^ (n2a & (n3a ^ n4a))) + tempArray[substituteBufferIndices320n1[i]] + 0x7a6d76e9
			s = int(substituteBufferIndices320r1[i])
			tempN1 = bits.RotateLeft32(tempN1, s) + n5a
			tempN2 = bits.RotateLeft32(n3a, 10)
			n1a, n2a, n3a, n4a, n5a = n5a, tempN1, n2a, tempN2, n4a

			i++
		}

		temp = n3
		n3 = n3a
		n3a = temp

		// round 5
		for i < 80 {
			tempN1 = n1 + (n2 ^ (n3 | ^n4)) + tempArray[substituteBufferIndices320n0[i]] + 0xa953fd4e
			s := int(substituteBufferIndices320r0[i])
			tempN1 = bits.RotateLeft32(tempN1, s) + n5
			tempN2 = bits.RotateLeft32(n3, 10)
			n1, n2, n3, n4, n5 = n5, tempN1, n2, tempN2, n4

			tempN1 = n1a + (n2a ^ n3a ^ n4a) + tempArray[substituteBufferIndices320n1[i]]
			s = int(substituteBufferIndices320r1[i])
			tempN1 = bits.RotateLeft32(tempN1, s) + n5a
			tempN2 = bits.RotateLeft32(n3a, 10)
			n1a, n2a, n3a, n4a, n5a = n5a, tempN1, n2a, tempN2, n4a

			i++
		}

		temp = n5
		n5 = n5a
		n5a = temp

		// finalize
		r.sum[0] += n1
		r.sum[1] += n2
		r.sum[2] += n3
		r.sum[3] += n4
		r.sum[4] += n5
		r.sum[5] += n1a
		r.sum[6] += n2a
		r.sum[7] += n3a
		r.sum[8] += n4a
		r.sum[9] += n5a

		block = block[BlockSize320:]
		n += BlockSize320
	}

	return n
}

// assertEmptyBuffer asserts that the buffer is empty and if not, panics.
func (r *modelRipeMd320) assertEmptyBuffer() {
	if r.bufferIndex > 0 {
		panic("buffer should be empty")
	}
}
