package algorithm

// Algorithm represents parameters for creating customized table of a CRC-16 algorithm.
type Algorithm struct {
	Poly   uint16
	Init   uint16
	RefIn  bool
	RefOut bool
	XorOut uint16
	Check  uint16
}
