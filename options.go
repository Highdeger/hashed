package hashed

import (
	"fmt"
	"hashed/kmac"
)

type Options struct {
	HashType      string
	Key           []byte
	FunctionName  []byte
	Customization []byte
	KMac128Size   int
	KMac256Size   int
	SubType       string
}

func DefaultOptions(hashType string) *Options {
	return &Options{
		HashType:      hashType,
		Key:           []byte(""),
		FunctionName:  []byte(""),
		Customization: []byte(""),
		KMac128Size:   kmac.Size128,
		KMac256Size:   kmac.Size256,
		SubType:       "",
	}
}

func (r *Options) Dump() string {
	return fmt.Sprintf("%+v", r)
}

func (r *Options) SetKey(key []byte) *Options {
	r.Key = key
	return r
}

func (r *Options) SetFunctionName(name []byte) *Options {
	r.FunctionName = name
	return r
}

func (r *Options) SetCustomization(customization []byte) *Options {
	r.Customization = customization
	return r
}

func (r *Options) SetSubType(subType string) *Options {
	r.SubType = subType
	return r
}
