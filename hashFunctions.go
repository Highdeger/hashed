package hashed

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"fmt"
	"hash"
	"hash/crc32"
	"hash/crc64"
	"strings"

	"golang.org/x/crypto/blake2b"
	"golang.org/x/crypto/blake2s"
	"golang.org/x/crypto/md4"
	"golang.org/x/crypto/sha3"

	"hashed/crc16"
	crc16Algorithm "hashed/crc16/algorithm"
	"hashed/keccak"
	"hashed/kmac"
	"hashed/md2"
	"hashed/ripemd"
)

func Crc16(subType string) hash.Hash {
	if subType == "" {
		subType = "arc"
	}

	algorithm, found := crc16Algorithm.PredefinedMap[subType]
	if !found {
		fatalError("unknown sub type for crc-16: %s", subType)
	}

	return crc16.New(crc16.MakeTable(algorithm))
}

func Crc32(subType string) hash.Hash {
	if subType == "" {
		subType = "ieee"
	}

	var algorithm uint32
	switch subType {
	case "ieee":
		algorithm = crc32.IEEE
	case "castagnoli":
		algorithm = crc32.Castagnoli
	case "koopman":
		algorithm = crc32.Koopman
	default:
		fatalError("unknown sub type for crc-32: %s", subType)
	}

	return crc32.New(crc32.MakeTable(algorithm))
}

func Crc64(subType string) hash.Hash {
	if subType == "" {
		subType = "iso"
	}

	var algorithm uint64
	switch subType {
	case "iso":
		algorithm = crc64.ISO
	case "ecma":
		algorithm = crc64.ECMA
	default:
		fatalError("unknown sub type for crc-64: %s", subType)
	}

	return crc64.New(crc64.MakeTable(algorithm))
}

func Md2() hash.Hash {
	return md2.New()
}

func Md4() hash.Hash {
	return md4.New()
}

func Md5() hash.Hash {
	return md5.New()
}

func Sha1() hash.Hash {
	return sha1.New()
}

func Sha2Type256() hash.Hash {
	return sha256.New()
}

func Sha2Type256Length224() hash.Hash {
	return sha256.New224()
}

func Sha2Type256Length512() hash.Hash {
	return sha512.New()
}

func Sha2Type512Length224() hash.Hash {
	return sha512.New512_224()
}

func Sha2Type512Length256() hash.Hash {
	return sha512.New512_256()
}

func Sha2Type512Length384() hash.Hash {
	return sha512.New384()
}

func Sha3Type224() hash.Hash {
	return sha3.New224()
}

func Sha3Type256() hash.Hash {
	return sha3.New256()
}

func Sha3Type384() hash.Hash {
	return sha3.New384()
}

func Sha3Type512() hash.Hash {
	return sha3.New512()
}

func KeccakType224() hash.Hash {
	return keccak.New224()
}

func KeccakType256() hash.Hash {
	return sha3.NewLegacyKeccak256()
}

func KeccakType384() hash.Hash {
	return keccak.New384()
}

func KeccakType512() hash.Hash {
	return sha3.NewLegacyKeccak512()
}

func ShakeType128() hash.Hash {
	return sha3.NewShake128()
}

func ShakeType256() hash.Hash {
	return sha3.NewShake256()
}

func CShakeType128(n, s []byte) hash.Hash {
	return sha3.NewCShake128(n, s)
}

func CShakeType256(n, s []byte) hash.Hash {
	return sha3.NewCShake256(n, s)
}

func KMacType128(key, customization []byte, size int) hash.Hash {
	if len(key) < 16 {
		fatalError("kmac-128 key is less than 16 bytes")
	}

	if size < 8 {
		fatalError("kmac size is less than 8 bytes")
	}

	return kmac.New128(key, size, customization)
}

func KMacType256(key, customization []byte, size int) hash.Hash {
	if len(key) < 32 {
		fatalError("kmac-256 key is less than 32 bytes")
	}

	if size < 8 {
		fatalError("kmac size is less than 8 bytes")
	}

	return kmac.New256(key, size, customization)
}

func RipeMdType128() hash.Hash {
	return ripemd.New128()
}

func RipeMdType160() hash.Hash {
	return ripemd.New160()
}

func RipeMdType256() hash.Hash {
	return ripemd.New256()
}

func RipeMdType320() hash.Hash {
	return ripemd.New320()
}

func Blake2SType128(key []byte) hash.Hash {
	if len(key) == 0 {
		fatalError(fmt.Sprintf("blake2s-128 key is empty"))
	}

	if len(key) > blake2s.Size {
		fatalError(fmt.Sprintf("blake2s-128 key is greater than %d bytes", blake2s.Size))
	}

	h, err := blake2s.New128(key)
	if err != nil {
		panic(err)
	}

	return h
}

func Blake2SType256(key []byte) hash.Hash {
	if len(key) > blake2s.Size {
		fatalError(fmt.Sprintf("blake2s-256 key is greater than %d bytes", blake2s.Size))
	}

	h, err := blake2s.New256(key)
	if err != nil {
		panic(err)
	}

	return h
}

func Blake2BType256(key []byte) hash.Hash {
	if len(key) == 0 {
		fatalError(fmt.Sprintf("blake2b-256 key is empty"))
	}

	if len(key) > blake2b.Size256 {
		fatalError(fmt.Sprintf("blake2b-256 key is greater than %d bytes", blake2b.Size256))
	}

	h, err := blake2b.New256(key)
	if err != nil {
		panic(err)
	}

	return h
}

func Blake2BType384(key []byte) hash.Hash {
	if len(key) == 0 {
		fatalError(fmt.Sprintf("blake2b-384 key is empty"))
	}

	if len(key) > blake2b.Size384 {
		fatalError(fmt.Sprintf("blake2b-384 key is greater than %d bytes", blake2b.Size384))
	}

	h, err := blake2b.New384(key)
	if err != nil {
		panic(err)
	}

	return h
}

func Blake2BType512(key []byte) hash.Hash {
	if len(key) == 0 {
		fatalError(fmt.Sprintf("blake2b-512 key is empty"))
	}

	if len(key) > blake2b.Size {
		fatalError(fmt.Sprintf("blake2b-512 key is greater than %d bytes", blake2b.Size))
	}

	h, err := blake2b.New512(key)
	if err != nil {
		panic(err)
	}

	return h
}

func getHashFunc(options *Options) func() hash.Hash {
	switch strings.ToLower(options.HashType) {
	case "crc-16":
		return func() hash.Hash { return Crc16(options.SubType) }
	case "crc-32":
		return func() hash.Hash { return Crc32(options.SubType) }
	case "crc-64":
		return func() hash.Hash { return Crc64(options.SubType) }
	case "md2":
		return Md2
	case "md4":
		return Md4
	case "md5":
		return Md5
	case "sha1":
		return Sha1
	case "sha2-256":
		return Sha2Type256
	case "sha2-256-224":
		return Sha2Type256Length224
	case "sha2-512":
		return Sha2Type256Length512
	case "sha2-512-224":
		return Sha2Type512Length224
	case "sha2-512-256":
		return Sha2Type512Length256
	case "sha2-512-384":
		return Sha2Type512Length384
	case "sha3-224":
		return Sha3Type224
	case "sha3-256":
		return Sha3Type256
	case "sha3-384":
		return Sha3Type384
	case "sha3-512":
		return Sha3Type512
	case "keccak-224":
		return KeccakType224
	case "keccak-256":
		return KeccakType256
	case "keccak-384":
		return KeccakType384
	case "keccak-512":
		return KeccakType512
	case "shake-128":
		return ShakeType128
	case "shake-256":
		return ShakeType256
	case "cshake-128":
		return func() hash.Hash { return CShakeType128(options.FunctionName, options.Customization) }
	case "cshake-256":
		return func() hash.Hash { return CShakeType256(options.FunctionName, options.Customization) }
	case "kmac-128":
		return func() hash.Hash { return KMacType128(options.Key, options.Customization, options.KMac128Size) }
	case "kmac-256":
		return func() hash.Hash { return KMacType256(options.Key, options.Customization, options.KMac256Size) }
	case "ripemd-128":
		return RipeMdType128
	case "ripemd-160":
		return RipeMdType160
	case "ripemd-256":
		return RipeMdType256
	case "ripemd-320":
		return RipeMdType320
	case "blake2s-128":
		return func() hash.Hash { return Blake2SType128(options.Key) }
	case "blake2s-256":
		return func() hash.Hash { return Blake2SType256(options.Key) }
	case "blake2b-256":
		return func() hash.Hash { return Blake2BType256(options.Key) }
	case "blake2b-384":
		return func() hash.Hash { return Blake2BType384(options.Key) }
	case "blake2b-512":
		return func() hash.Hash { return Blake2BType512(options.Key) }
	default:
		return nil
	}
}
