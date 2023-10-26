package hashed

import (
	"strings"
	"testing"
)

func TestSums(t *testing.T) {
	input := "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
	expectedByHash := map[string]string{
		"crc-16":       "5b66",             // ARC
		"crc-32":       "d6213adc",         // IEEE
		"crc-64":       "2fe68fc47360100f", // ISO
		"md2":          "e822ce79446eff3d9afb4ac6d406dac9",
		"md4":          "ecdf9914cbc00bf5d82f1bc002d0058f",
		"md5":          "46cf18a9b447991b450cad3facf5937e",
		"sha1":         "57b5a033a37d0276ea970639cc3b63cab29442fe",
		"sha2-256":     "a58bba2cc561bddbc30505632528c8aec0c367b859555462f52fe4476dc4d4bb",
		"sha2-256-224": "e3dd1cb48541549e27a4ab69142e1c287ddb4560faf715955ea717c7",
		"sha2-512":     "466efae469c6833ea2fd977fa080271bb2f7a562163269eef2222636b50b7d27cde699368905bcfeb44adc9693323943b427548f5ca609a1b100b50e211762ec",
		"sha2-512-224": "bbb18070c91bfd34e4bfe08c3f5b350257d4d50347e1bc0c045d7930",
		"sha2-512-256": "8997c25266c1937435a2a916b89f54c09383820adbcedb1d809e5b878b8b5825",
		"sha2-512-384": "61ec802aa2b6cbc2a4037e5cd15e0141be68bbc2644cbcaa35e62ba6224d1178525fb059d4462aac2c01faa44c79f90a",
		"sha3-224":     "e39bb86280697e16ee67f8c0941305ed168f0c55dec87d12b277515c",
		"sha3-256":     "43722f9b1954d61ff7e937458f12d61a7eb4eabd8b744b6a7ea2983612711084",
		"sha3-384":     "d766b9c9bbf7dce0de23917bf753bbf19132a68c8ab6be606893c6e00538753bb60381d11d6b9a6af9971333c954ee43",
		"sha3-512":     "8a08b4b733f8143c1b676a327b90b3b98efc86c20703ae09159ac4e2cc8f536a6b5489a4402d87fe66dfdcd0d189a4b323acd4ada8961eb2803fabb8befbb70c",
		"keccak-224":   "1975ce9fa3191efcd0cc85cb553d7f28a8632ef955383e48c9d4d0fd",
		"keccak-256":   "33d9df9ae4694da1d3647cf8409438f820f95fc6310c13bbd681e60c98f13e09",
		"keccak-384":   "cd576e7288361c9d8749e2d9abc506b8be45cd83f3abf6e0fb79b597b7aaf28b35bf8c366fe1906f3732ebf628b60e60",
		"keccak-512":   "67ca8046f7b00be66680a22e4f234a4a0822ef0e314ceaad53cb6ec0ec26f5bb6a9ed4ac75814941b2433eee5a9c43a6a234381f8f22a311e4edac36afd95628",
		"shake-128":    "4ab6f22ebe2e71ce53964b4950a39db25681832a754bca66c3f241797e4ad78f",
		"shake-256":    "125b77eb566466caebecf357365c9f0b918d26f4bc00b23e896e6d5c13dc875bcb63b44b63e61c02da175ef7b6f6858005b4da7ffcd7692ccded962312fa3b86",
		"cshake-128":   "79ed336386926373c53cbf97b43ae7498b6cdf93750ad5e4bc3286d0a7b45821",
		"cshake-256":   "bda664b322e0cdd1594ac26bc2c3dcefe9d793fdb6f68bbd8905ee5ef34077cd23e329562eb8ce931c047f30261600c5223a81cfba33d8a44dce5faeadb1d8b5",
		"kmac-128":     "2988caaecedc1cb7c84c520c8ba32b88bd59da3434d5bf87d5817e019580ee4e",
		"kmac-256":     "fe82a26a8dde099e916b9b70e8835abf1c9e67e1e1ae062a0c997f1635dd40e6c32079e0db9592087f3840ba803636b4adeee21ec6f6ff14c130c88038c04bcf",
		"ripemd-128":   "b4328f031ccb7750865e3ee986f5ee9a",
		"ripemd-160":   "d9b27c4dda5b353363352e08a0e112f8c1e0738c",
		"ripemd-256":   "5ad114f0ccf88d0d5a5784f842d0b86884a233c8e8eb6dd3fd23745cc17090fa",
		"ripemd-320":   "265044d981c72af8c31a1c016ab7afced26808e9e34a1b537e054c2ca6c08e71609e6cd4141d85d8",
		"blake2s-128":  "4fd31f3310d8b8c052b764c3167dc1db",
		"blake2s-256":  "8412d52439599e6afd799de2f4a87a5022d1714063763c7f474142ec9d46a972",
		"blake2b-256":  "a679bb73edac2d362c522fa6c631b4aefb76cbf47cdfe2b60d2c95a9365690ca",
		"blake2b-384":  "6307b3240154f70e166f628b397f9061f98e059db425522b2713fde806bed80754c6456bbc528155bb24c6a7414a1c6a",
		"blake2b-512":  "c82412da330c6f8e76d33fe1fd3f8c028673defc1e037f4566c50cf604781425fee4f568f05fc0a8c5304d997d6eabae212a73f2365a64412b5ae14ec10f5534",
	}

	for _, hashType := range sortedKeys(expectedByHash) {
		expected := expectedByHash[hashType]
		h := New(DefaultOptions(hashType).
			SetKey([]byte("46cf18a9b447991b450cad3facf5937e")).
			SetFunctionName([]byte("b61f4c9980370150e1dcf7aa770c58dc")).
			SetCustomization([]byte("8df75ae53e4bdf7b5ae9c09bd0baffb1")))

		output := h.GetSumHex(strings.NewReader(input), false)
		if expected != output {
			t.Errorf("'%s' is wrong:\n\texpected \"%s\"\n\tgot \"%s\"", hashType, expected, output)
		}
	}
}
