package hashed

import (
	"fmt"
	"os"
	"runtime"
	"slices"
)

func fatalError(msg ...string) {
	for _, m := range msg {
		fmt.Println(m)
	}

	os.Exit(1)
}

func caller() (file string, line int, funcName string) {
	pc := make([]uintptr, 1)
	runtime.Callers(2, pc)
	f := runtime.FuncForPC(pc[0])
	file, line = f.FileLine(pc[0])
	funcName = f.Name()
	return
}

func sortedKeys[T any](m map[string]T) []string {
	r := make([]string, 0)
	for name := range m {
		r = append(r, name)
	}

	slices.Sort(r)

	return r
}
