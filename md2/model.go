package md2

import "crypto/md5"

// model represents a structure for the MD2 hash.Hash.
type model struct {
	digest    [Size]byte     // the digest, Size
	state     [Size * 3]byte // state, 48 ints
	buffer    [Size]byte     // temp storage buffer, 16 bytes, Size
	bufferLen uint8          // how many bytes are there in the buffer
}

// implementation of the hash.Hash

// Reset resets the hash.Hash to its initial state.
func (r *model) Reset() {
	for i := range r.digest {
		r.digest[i] = 0
	}

	for i := range r.state {
		r.state[i] = 0
	}

	for i := range r.buffer {
		r.buffer[i] = 0
	}

	r.bufferLen = 0
}

// Size returns the number of bytes Sum will return.
func (r *model) Size() int { return Size }

// BlockSize returns the hash's underlying block size.
// The Write method must be able to accept any amount of data,
// but it may operate more efficiently if all writes are a multiple of the block size.
func (r *model) BlockSize() int { return BlockSize }

// Write appends the data to the digest.
func (r *model) Write(p []byte) (int, error) {
	md5.New().BlockSize()
	if r.bufferLen > 0 {
		n := uint8(len(p))

		if (n + r.bufferLen) > Size {
			n = Size - r.bufferLen
		}

		var i uint8
		for i = 0; i < n; i++ {
			r.buffer[r.bufferLen+i] = p[i]
		}

		r.bufferLen += n

		if r.bufferLen == Size {
			r.update(r.buffer[0:Size])
			r.bufferLen = 0
		}

		p = p[n:]
	}

	imax := len(p) / Size
	for i := 0; i < imax; i++ {
		r.update(p[:Size])
		p = p[Size:]
	}

	if len(p) > 0 {
		r.bufferLen = uint8(copy(r.buffer[:], p))
	}

	return len(p), nil
}

// Sum appends the current hash to b and returns the resulting slice.
// It does not change the underlying hash state.
func (r *model) Sum(b []byte) []byte {
	// make a copy to allow other writes to continue and to prevent change of the state
	h := *r

	padding := make([]byte, 0)
	for i := uint8(0); i < Size-h.bufferLen; i++ {
		padding = append(padding, Size-h.bufferLen)
	}

	_, _ = h.Write(padding)
	h.assertEmptyBuffer()
	_, _ = h.Write(h.digest[0:16])
	h.assertEmptyBuffer()

	return append(b, h.state[0:16]...)
}

// private

// assertEmptyBuffer asserts that the buffer is empty and if not, panics.
func (r *model) assertEmptyBuffer() {
	if r.bufferLen > 0 {
		panic("buffer should be empty")
	}
}

// update refresh the sum (digest and state) by adding one block to underlying data.
func (r *model) update(data []byte) {
	t := uint8(0)

	for i := 0; i < 16; i++ {
		r.state[i+16] = data[i]
		r.state[i+32] = byte(data[i] ^ r.state[i])
	}

	for i := 0; i < 18; i++ {
		for j := 0; j < 48; j++ {
			r.state[j] = byte(r.state[j] ^ substituteTable[t])
			t = r.state[j]
		}

		t = byte(t + uint8(i))
	}

	t = r.digest[15]

	for i := 0; i < 16; i++ {
		r.digest[i] = byte(r.digest[i] ^ substituteTable[data[i]^t])
		t = r.digest[i]
	}
}
