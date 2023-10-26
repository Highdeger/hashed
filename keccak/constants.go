package keccak

const (
	// Size224 is the size of an KECCAK-224 checksum in bytes.
	Size224 = 28
	// Size256 is the size of an KECCAK-256 checksum in bytes.
	Size256 = 32
	// Size384 is the size of an KECCAK-384 checksum in bytes.
	Size384 = 48
	// Size512 is the size of an KECCAK-512 checksum in bytes.
	Size512 = 64
	// BlockSize224 the block size of KECCAK-224 in bytes.
	BlockSize224 = 200 - Size224*2
	// BlockSize256 the block size of KECCAK-256 in bytes.
	BlockSize256 = 200 - Size256*2
	// BlockSize384 the block size of KECCAK-384 in bytes.
	BlockSize384 = 200 - Size384*2
	// BlockSize512 the block size of KECCAK-512 in bytes.
	BlockSize512 = 200 - Size512*2

	DomainNone  = 1
	DomainSHA3  = 0x06
	DomainSHAKE = 0x1f

	rounds = 24
)

var (
	roundConstants = []uint64{
		0x0000000000000001, 0x0000000000008082,
		0x800000000000808A, 0x8000000080008000,
		0x000000000000808B, 0x0000000080000001,
		0x8000000080008081, 0x8000000000008009,
		0x000000000000008A, 0x0000000000000088,
		0x0000000080008009, 0x000000008000000A,
		0x000000008000808B, 0x800000000000008B,
		0x8000000000008089, 0x8000000000008003,
		0x8000000000008002, 0x8000000000000080,
		0x000000000000800A, 0x800000008000000A,
		0x8000000080008081, 0x8000000000008080,
		0x0000000080000001, 0x8000000080008008,
	}
)
