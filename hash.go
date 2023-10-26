package hashed

import (
	"crypto/hmac"
	"fmt"
	"hash"
	"io"
	"strings"
)

type Hash struct {
	hash.Hash
	options *Options
	lastSum []byte
	debug   bool
	verbose bool
}

func New(options *Options) *Hash {
	hFunc := getHashFunc(options)
	if hFunc == nil {
		fatalError("invalid hash type: " + options.HashType)
	}

	return &Hash{
		Hash:    hFunc(),
		options: options,
		lastSum: nil,
		debug:   false,
		verbose: false,
	}
}

func (r *Hash) GetSum(reader io.Reader) []byte {
	r.Reset()
	buf := make([]byte, r.BlockSize())

	if reader == nil {
		reader = strings.NewReader("")
	}

	for {
		n, err := reader.Read(buf)
		if err == io.EOF {
			break
		} else if err != nil {
			r.fatalError("cannot read from source: %s\n", err)
		}

		n, err = r.Write(buf[:n])
		if err != nil {
			r.fatalError("cannot write to hash: %s\n", err)
		}
	}

	return r.Sum(nil)
}

func (r *Hash) GetSumHex(reader io.Reader, caps bool) string {
	if caps {
		return fmt.Sprintf("%X", r.GetSum(reader))
	}

	return fmt.Sprintf("%x", r.GetSum(reader))
}

func (r *Hash) HMac(key []byte) {
	r.Hash = hmac.New(getHashFunc(r.options), key)
}

func (r *Hash) KMac128Size(size int) *Hash {
	r.options.KMac128Size = size
	return r
}

func (r *Hash) KMac256Size(size int) *Hash {
	r.options.KMac256Size = size
	return r
}

func (r *Hash) Verbose() *Hash {
	r.verbose = true
	return r
}

func (r *Hash) Debug() *Hash {
	r.debug = true
	return r
}

// private

func (r *Hash) fatalError(format string, a ...any) {
	msg := []string{fmt.Sprintf(format, a...)}

	if r.verbose {
		msg = append(msg, fmt.Sprintf("  > options: %s\n", r.options.Dump()))
	}
	if r.debug {
		file, line, funcName := caller()
		msg = append(msg, fmt.Sprintf("  > caller: %s:%d > %s()\n", file, line, funcName))
	}

	fatalError(msg...)
}
