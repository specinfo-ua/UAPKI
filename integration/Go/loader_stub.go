//go:build !windows && !(unix && cgo)

package uapki

import "errors"

var errUnsupported = errors.New("uapki: unsupported platform (on POSIX systems build with cgo enabled)")

type nativeLib struct{}

func loadNative(path string) (nativeLib, error) {
	return nativeLib{}, errUnsupported
}

func (nativeLib) unload() error {
	return errUnsupported
}

func (nativeLib) process(request []byte) ([]byte, error) {
	return nil, errUnsupported
}
