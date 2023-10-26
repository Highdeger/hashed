package keccak

// model represents a structure for the KECCAK Hash.
type model struct {
	sum       [25]uint64
	size      int
	blockSize int
	buf       []byte
	domain    byte
}

// implementation of the hash.Hash

// Reset resets the hash.Hash to its initial state.
func (r *model) Reset() {
	for i := range r.sum {
		r.sum[i] = 0
	}

	r.buf = nil
}

// Size returns the number of bytes Sum will return.
func (r *model) Size() int {
	return r.size
}

// BlockSize returns the hash's underlying block size.
// The Write method must be able to accept any amount of data,
// but it may operate more efficiently if all writes are a multiple of the absorb size.
func (r *model) BlockSize() int {
	return r.blockSize
}

// Write appends the data to the digest.
func (r *model) Write(p []byte) (int, error) {
	n := len(p)

	if len(r.buf) > 0 {
		x := r.blockSize - len(r.buf)
		if x > len(p) {
			x = len(p)
		}

		r.buf = append(r.buf, p[:x]...)
		p = p[x:]

		if len(r.buf) < r.blockSize {
			return n, nil
		}

		r.absorb(r.buf)
		r.buf = nil
	}

	for len(p) >= r.blockSize {
		r.absorb(p[:r.blockSize])
		p = p[r.blockSize:]
	}

	r.buf = p

	return n, nil
}

// Sum appends the current hash to b and returns the resulting slice.
// It does not change the underlying hash state.
func (r *model) Sum(b []byte) []byte {
	// copy the model to allow other writes to continue and to prevent change of the state
	h := *r
	h.finalize()

	return h.squeeze(b)
}

// private

// absorb refreshes the sum by adding to underlying data.
func (r *model) absorb(data []byte) {
	if len(data) != r.blockSize {
		panic("absorb() called with invalid data size")
	}

	for i := 0; i < r.blockSize/8; i++ {
		t := data[i*8:]
		r.sum[i] ^= uint64(t[0]) |
			uint64(t[1])<<8 |
			uint64(t[2])<<16 |
			uint64(t[3])<<24 |
			uint64(t[4])<<32 |
			uint64(t[5])<<40 |
			uint64(t[6])<<48 |
			uint64(t[7])<<56
	}

	r.keccakF()
}

// padded returns the buffer data with padding.
func (r *model) padded() []byte {
	padded := make([]byte, r.blockSize)
	copy(padded, r.buf)
	padded[len(r.buf)] = r.domain
	padded[len(padded)-1] |= 0x80

	return padded
}

// finalize completes the hash by absorbing the padded() buffer.
func (r *model) finalize() {
	r.absorb(r.padded())
}

// squeeze appends the data to buffer and returns the resulting checksum.
func (r *model) squeeze(data []byte) []byte {
	buf := make([]byte, 8*len(r.sum))
	n := r.size

	for {
		for i := range r.sum {
			t := r.sum[i]
			buf[i*8:][0] = byte(t)
			buf[i*8:][1] = byte(t >> 8)
			buf[i*8:][2] = byte(t >> 16)
			buf[i*8:][3] = byte(t >> 24)
			buf[i*8:][4] = byte(t >> 32)
			buf[i*8:][5] = byte(t >> 40)
			buf[i*8:][6] = byte(t >> 48)
			buf[i*8:][7] = byte(t >> 56)
		}

		if n <= r.blockSize {
			data = append(data, buf[:n]...)
			break
		}

		data = append(data, buf[:r.blockSize]...)
		n -= r.blockSize
		r.keccakF()
	}

	return data
}

// keccakF computes the keccak sum
func (r *model) keccakF() {
	var (
		S                       = &r.sum
		bc0, bc1, bc2, bc3, bc4 uint64
		S0, S1, S2, S3, S4      uint64
		S5, S6, S7, S8, S9      uint64
		S10, S11, S12, S13, S14 uint64
		S15, S16, S17, S18, S19 uint64
		S20, S21, S22, S23, S24 uint64
		tmp                     uint64
	)

	S0, S1, S2, S3, S4 = S[0], S[1], S[2], S[3], S[4]
	S5, S6, S7, S8, S9 = S[5], S[6], S[7], S[8], S[9]
	S10, S11, S12, S13, S14 = S[10], S[11], S[12], S[13], S[14]
	S15, S16, S17, S18, S19 = S[15], S[16], S[17], S[18], S[19]
	S20, S21, S22, S23, S24 = S[20], S[21], S[22], S[23], S[24]

	for r := 0; r < rounds; r++ {
		// theta
		bc0 = S0 ^ S5 ^ S10 ^ S15 ^ S20
		bc1 = S1 ^ S6 ^ S11 ^ S16 ^ S21
		bc2 = S2 ^ S7 ^ S12 ^ S17 ^ S22
		bc3 = S3 ^ S8 ^ S13 ^ S18 ^ S23
		bc4 = S4 ^ S9 ^ S14 ^ S19 ^ S24
		tmp = bc4 ^ (bc1<<1 | bc1>>(64-1))
		S0 ^= tmp
		S5 ^= tmp
		S10 ^= tmp
		S15 ^= tmp
		S20 ^= tmp
		tmp = bc0 ^ (bc2<<1 | bc2>>(64-1))
		S1 ^= tmp
		S6 ^= tmp
		S11 ^= tmp
		S16 ^= tmp
		S21 ^= tmp
		tmp = bc1 ^ (bc3<<1 | bc3>>(64-1))
		S2 ^= tmp
		S7 ^= tmp
		S12 ^= tmp
		S17 ^= tmp
		S22 ^= tmp
		tmp = bc2 ^ (bc4<<1 | bc4>>(64-1))
		S3 ^= tmp
		S8 ^= tmp
		S13 ^= tmp
		S18 ^= tmp
		S23 ^= tmp
		tmp = bc3 ^ (bc0<<1 | bc0>>(64-1))
		S4 ^= tmp
		S9 ^= tmp
		S14 ^= tmp
		S19 ^= tmp
		S24 ^= tmp

		// rho phi
		tmp = S1
		tmp, S10 = S10, tmp<<1|tmp>>(64-1)
		tmp, S7 = S7, tmp<<3|tmp>>(64-3)
		tmp, S11 = S11, tmp<<6|tmp>>(64-6)
		tmp, S17 = S17, tmp<<10|tmp>>(64-10)
		tmp, S18 = S18, tmp<<15|tmp>>(64-15)
		tmp, S3 = S3, tmp<<21|tmp>>(64-21)
		tmp, S5 = S5, tmp<<28|tmp>>(64-28)
		tmp, S16 = S16, tmp<<36|tmp>>(64-36)
		tmp, S8 = S8, tmp<<45|tmp>>(64-45)
		tmp, S21 = S21, tmp<<55|tmp>>(64-55)
		tmp, S24 = S24, tmp<<2|tmp>>(64-2)
		tmp, S4 = S4, tmp<<14|tmp>>(64-14)
		tmp, S15 = S15, tmp<<27|tmp>>(64-27)
		tmp, S23 = S23, tmp<<41|tmp>>(64-41)
		tmp, S19 = S19, tmp<<56|tmp>>(64-56)
		tmp, S13 = S13, tmp<<8|tmp>>(64-8)
		tmp, S12 = S12, tmp<<25|tmp>>(64-25)
		tmp, S2 = S2, tmp<<43|tmp>>(64-43)
		tmp, S20 = S20, tmp<<62|tmp>>(64-62)
		tmp, S14 = S14, tmp<<18|tmp>>(64-18)
		tmp, S22 = S22, tmp<<39|tmp>>(64-39)
		tmp, S9 = S9, tmp<<61|tmp>>(64-61)
		tmp, S6 = S6, tmp<<20|tmp>>(64-20)
		S1 = tmp<<44 | tmp>>(64-44)

		// chi
		bc0 = S0
		bc1 = S1
		bc2 = S2
		bc3 = S3
		bc4 = S4
		S0 ^= (^bc1) & bc2
		S1 ^= (^bc2) & bc3
		S2 ^= (^bc3) & bc4
		S3 ^= (^bc4) & bc0
		S4 ^= (^bc0) & bc1
		bc0 = S5
		bc1 = S6
		bc2 = S7
		bc3 = S8
		bc4 = S9
		S5 ^= (^bc1) & bc2
		S6 ^= (^bc2) & bc3
		S7 ^= (^bc3) & bc4
		S8 ^= (^bc4) & bc0
		S9 ^= (^bc0) & bc1
		bc0 = S10
		bc1 = S11
		bc2 = S12
		bc3 = S13
		bc4 = S14
		S10 ^= (^bc1) & bc2
		S11 ^= (^bc2) & bc3
		S12 ^= (^bc3) & bc4
		S13 ^= (^bc4) & bc0
		S14 ^= (^bc0) & bc1
		bc0 = S15
		bc1 = S16
		bc2 = S17
		bc3 = S18
		bc4 = S19
		S15 ^= (^bc1) & bc2
		S16 ^= (^bc2) & bc3
		S17 ^= (^bc3) & bc4
		S18 ^= (^bc4) & bc0
		S19 ^= (^bc0) & bc1
		bc0 = S20
		bc1 = S21
		bc2 = S22
		bc3 = S23
		bc4 = S24
		S20 ^= (^bc1) & bc2
		S21 ^= (^bc2) & bc3
		S22 ^= (^bc3) & bc4
		S23 ^= (^bc4) & bc0
		S24 ^= (^bc0) & bc1

		// iota
		S0 ^= roundConstants[r]
	}

	S[0], S[1], S[2], S[3], S[4] = S0, S1, S2, S3, S4
	S[5], S[6], S[7], S[8], S[9] = S5, S6, S7, S8, S9
	S[10], S[11], S[12], S[13], S[14] = S10, S11, S12, S13, S14
	S[15], S[16], S[17], S[18], S[19] = S15, S16, S17, S18, S19
	S[20], S[21], S[22], S[23], S[24] = S20, S21, S22, S23, S24
}
