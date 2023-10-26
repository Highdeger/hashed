package algorithm

var (
	// PredefinedMap stores predefined algorithms by their names.
	PredefinedMap = map[string]Algorithm{
		"arc":         ARC,
		"aug-ccitt":   AUG_CCITT,
		"bypass":      BUYPASS,
		"ccitt_false": CCITT_FALSE,
		"cdma2000":    CDMA2000,
		"dds-110":     DDS_110,
		"dect-r":      DECT_R,
		"dect-x":      DECT_X,
		"dnp":         DNP,
		"en-13757":    EN_13757,
		"genibus":     GENIBUS,
		"maxim":       MAXIM,
		"mcrf4xx":     MCRF4XX,
		"riello":      RIELLO,
		"t10-dif":     T10_DIF,
		"teledisk":    TELEDISK,
		"tms37157":    TMS37157,
		"usb":         USB,
		"crc-a":       CRC_A,
		"kermit":      KERMIT,
		"modbus":      MODBUS,
		"x-25":        X_25,
		"xmodem":      XMODEM,
	}
	// ARC is the ARC algorithm.
	ARC = Algorithm{Poly: 0x8005, Init: 0x0000, RefIn: true, RefOut: true, XorOut: 0x0000, Check: 0xBB3D}
	// AUG_CCITT is the AUG-CCITT algorithm.
	AUG_CCITT = Algorithm{Poly: 0x1021, Init: 0x1D0F, RefIn: false, RefOut: false, XorOut: 0x0000, Check: 0xE5CC}
	// BUYPASS is the BUYPASS algorithm.
	BUYPASS = Algorithm{Poly: 0x8005, Init: 0x0000, RefIn: false, RefOut: false, XorOut: 0x0000, Check: 0xFEE8}
	// CCITT_FALSE is the CCITT-FALSE algorithm.
	CCITT_FALSE = Algorithm{Poly: 0x1021, Init: 0xFFFF, RefIn: false, RefOut: false, XorOut: 0x0000, Check: 0x29B1}
	// CDMA2000 is the CDMA2000 algorithm.
	CDMA2000 = Algorithm{Poly: 0xC867, Init: 0xFFFF, RefIn: false, RefOut: false, XorOut: 0x0000, Check: 0x4C06}
	// DDS_110 is the DDS-110 algorithm.
	DDS_110 = Algorithm{Poly: 0x8005, Init: 0x800D, RefIn: false, RefOut: false, XorOut: 0x0000, Check: 0x9ECF}
	// DECT_R is the DECT-R algorithm.
	DECT_R = Algorithm{Poly: 0x0589, Init: 0x0000, RefIn: false, RefOut: false, XorOut: 0x0001, Check: 0x007E}
	// DECT_X is the DECT-X algorithm.
	DECT_X = Algorithm{Poly: 0x0589, Init: 0x0000, RefIn: false, RefOut: false, XorOut: 0x0000, Check: 0x007F}
	// DNP is the DNP algorithm.
	DNP = Algorithm{Poly: 0x3D65, Init: 0x0000, RefIn: true, RefOut: true, XorOut: 0xFFFF, Check: 0xEA82}
	// EN_13757 is the EN-13757 algorithm.
	EN_13757 = Algorithm{Poly: 0x3D65, Init: 0x0000, RefIn: false, RefOut: false, XorOut: 0xFFFF, Check: 0xC2B7}
	// GENIBUS is the GENIBUS algorithm.
	GENIBUS = Algorithm{Poly: 0x1021, Init: 0xFFFF, RefIn: false, RefOut: false, XorOut: 0xFFFF, Check: 0xD64E}
	// MAXIM is the MAXIM algorithm.
	MAXIM = Algorithm{Poly: 0x8005, Init: 0x0000, RefIn: true, RefOut: true, XorOut: 0xFFFF, Check: 0x44C2}
	// MCRF4XX is the MCRF4XX algorithm.
	MCRF4XX = Algorithm{Poly: 0x1021, Init: 0xFFFF, RefIn: true, RefOut: true, XorOut: 0x0000, Check: 0x6F91}
	// RIELLO is the RIELLO algorithm.
	RIELLO = Algorithm{Poly: 0x1021, Init: 0xB2AA, RefIn: true, RefOut: true, XorOut: 0x0000, Check: 0x63D0}
	// T10_DIF is the T10-DIF algorithm.
	T10_DIF = Algorithm{Poly: 0x8BB7, Init: 0x0000, RefIn: false, RefOut: false, XorOut: 0x0000, Check: 0xD0DB}
	// TELEDISK is the TELEDISK algorithm.
	TELEDISK = Algorithm{Poly: 0xA097, Init: 0x0000, RefIn: false, RefOut: false, XorOut: 0x0000, Check: 0x0FB3}
	// TMS37157 is the TMS37157 algorithm.
	TMS37157 = Algorithm{Poly: 0x1021, Init: 0x89EC, RefIn: true, RefOut: true, XorOut: 0x0000, Check: 0x26B1}
	// USB is the USB algorithm.
	USB = Algorithm{Poly: 0x8005, Init: 0xFFFF, RefIn: true, RefOut: true, XorOut: 0xFFFF, Check: 0xB4C8}
	// CRC_A is the CRC-A algorithm.
	CRC_A = Algorithm{Poly: 0x1021, Init: 0xC6C6, RefIn: true, RefOut: true, XorOut: 0x0000, Check: 0xBF05}
	// KERMIT is the KERMIT algorithm.
	KERMIT = Algorithm{Poly: 0x1021, Init: 0x0000, RefIn: true, RefOut: true, XorOut: 0x0000, Check: 0x2189}
	// MODBUS is the MODBUS algorithm.
	MODBUS = Algorithm{Poly: 0x8005, Init: 0xFFFF, RefIn: true, RefOut: true, XorOut: 0x0000, Check: 0x4B37}
	// X_25 is the X-25 algorithm.
	X_25 = Algorithm{Poly: 0x1021, Init: 0xFFFF, RefIn: true, RefOut: true, XorOut: 0xFFFF, Check: 0x906E}
	// XMODEM is the XMODEM algorithm.
	XMODEM = Algorithm{Poly: 0x1021, Init: 0x0000, RefIn: false, RefOut: false, XorOut: 0x0000, Check: 0x31C3}
)
