package crc16

import params2 "hashed/crc16/algorithm"

// Table is a 256-word table representing algorithm settings for creating CRC-16.
type Table struct {
	params params2.Algorithm
	data   [256]uint16
}

// MakeTable returns the Table constructed from the specified algorithm.
func MakeTable(params params2.Algorithm) *Table {
	table := new(Table)
	table.params = params

	for n := 0; n < 256; n++ {
		crc := uint16(n) << 8
		for i := 0; i < 8; i++ {
			bit := (crc & 0x8000) != 0
			crc <<= 1
			if bit {
				crc ^= params.Poly
			}
		}
		table.data[n] = crc
	}

	return table
}
