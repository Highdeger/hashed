package kmac

import "encoding/binary"

func addPadding(input []byte, w int) []byte {
	buf := make([]byte, 0, 9+len(input)+w)
	buf = append(buf, leftEncode(uint64(w))...)
	buf = append(buf, input...)
	paddingLen := w - (len(buf) % w)

	return append(buf, make([]byte, paddingLen)...)
}

func leftEncode(value uint64) []byte {
	var b [9]byte
	binary.BigEndian.PutUint64(b[1:], value)

	// trim all trailing zero bytes except the last one
	i := byte(1)
	for i < 8 && b[i] == 0 {
		i++
	}

	// prepend number of encoded bytes
	b[i-1] = 9 - i

	return b[i-1:]
}

func rightEncode(value uint64) []byte {
	var b [9]byte
	binary.BigEndian.PutUint64(b[:8], value)

	// trim all leading zero bytes except the last one
	i := byte(0)
	for i < 7 && b[i] == 0 {
		i++
	}

	// append number of encoded bytes
	b[8] = 8 - i

	return b[i:]
}
