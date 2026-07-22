//go:build windows

package uapki

import (
	"errors"
	"os"
	"syscall"
	"unsafe"
)

type nativeLib struct {
	dll          syscall.Handle
	procProcess  uintptr
	procJSONFree uintptr
}

// loadWithAlteredSearchPath makes dependent DLLs (uapkic.dll, uapkif.dll)
// resolvable from the directory of the loaded library, which the default
// LoadLibrary search order does not include.
const loadWithAlteredSearchPath = 0x0000_0008

var procLoadLibraryExW = syscall.NewLazyDLL("kernel32.dll").NewProc("LoadLibraryExW")

func loadLibrary(path string) (syscall.Handle, error) {
	if !containsPathSeparator(path) {
		return syscall.LoadLibrary(path)
	}
	pathW, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return 0, err
	}
	r1, _, callErr := procLoadLibraryExW.Call(
		uintptr(unsafe.Pointer(pathW)), 0, loadWithAlteredSearchPath)
	if r1 == 0 {
		return 0, callErr
	}
	return syscall.Handle(r1), nil
}

func containsPathSeparator(path string) bool {
	for i := 0; i < len(path); i++ {
		if os.IsPathSeparator(path[i]) {
			return true
		}
	}
	return false
}

func loadNative(path string) (nativeLib, error) {
	dll, err := loadLibrary(path)
	if err != nil {
		return nativeLib{}, err
	}
	procProcess, err := syscall.GetProcAddress(dll, "process")
	if err != nil {
		_ = syscall.FreeLibrary(dll)
		return nativeLib{}, err
	}
	procJSONFree, err := syscall.GetProcAddress(dll, "json_free")
	if err != nil {
		_ = syscall.FreeLibrary(dll)
		return nativeLib{}, err
	}
	return nativeLib{dll: dll, procProcess: procProcess, procJSONFree: procJSONFree}, nil
}

func (n nativeLib) unload() error {
	return syscall.FreeLibrary(n.dll)
}

func (n nativeLib) process(request []byte) ([]byte, error) {
	// The native side expects a NUL-terminated C string.
	buf := make([]byte, len(request)+1)
	copy(buf, request)

	r1, _, _ := syscall.SyscallN(n.procProcess, uintptr(unsafe.Pointer(&buf[0])))
	if r1 == 0 {
		return nil, errors.New("uapki: process() returned NULL")
	}
	defer syscall.SyscallN(n.procJSONFree, r1)

	return copyCString(r1), nil
}

// foreignPointer converts an address returned by the native library into an
// unsafe.Pointer. The memory is owned by the C side and never moves, so the
// uintptr round-trip that go vet would normally warn about is safe here.
func foreignPointer(p uintptr) unsafe.Pointer {
	return *(*unsafe.Pointer)(unsafe.Pointer(&p))
}

// copyCString copies a NUL-terminated C string owned by the native library
// into Go-managed memory.
func copyCString(p uintptr) []byte {
	ptr := (*byte)(foreignPointer(p))
	length := 0
	for *(*byte)(unsafe.Add(unsafe.Pointer(ptr), length)) != 0 {
		length++
	}
	out := make([]byte, length)
	copy(out, unsafe.Slice(ptr, length))
	return out
}
