package main

import (
	"fmt"
	"github.com/highdeger/vexillum"
	"hashed"
	"strings"
)

var (
	hashType      = vexillum.String('t', "type", "hash type", "md5")
	input         = vexillum.String('i', "input", "input text", "")
	hMacUse       = vexillum.Bool('m', "use-hmac", "use hmac", false)
	hMackey       = vexillum.String('k', "hmac-key", "hmac key", "")
	key           = vexillum.String('K', "key", "key used in kmac and blake", "")
	functionName  = vexillum.String('F', "function-name", "function name used in cshake", "")
	customization = vexillum.String('C', "customization", "customization used in cshake and kmac", "")
	verbose       = vexillum.Bool('v', "verbose", "verbose output", false)
	debug         = vexillum.Bool('d', "debug", "debug output", false)
	subType       = vexillum.String('s', "sub-type", "hash sub type", "")
)

func main() {
	vexillum.OnBareRun(func() {})
	vexillum.Parse()

	h := hashed.New(hashed.DefaultOptions(*hashType).
		SetKey([]byte(*key)).
		SetFunctionName([]byte(*functionName)).
		SetCustomization([]byte(*customization)).
		SetSubType(*subType))

	if *hMacUse {
		h.HMac([]byte(*hMackey))
	}

	if *verbose {
		h.Verbose()
	}

	if *debug {
		h.Debug()
	}

	r := strings.NewReader(*input)

	fmt.Println(h.GetSumHex(r, false))
}
