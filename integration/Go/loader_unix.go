//go:build unix && cgo

package uapki

/*
#cgo linux LDFLAGS: -ldl

#include <dlfcn.h>
#include <stdlib.h>

typedef char* (*uapki_process_t)(const char*);
typedef void (*uapki_json_free_t)(char*);

static char* uapki_call_process(void* fn, const char* request) {
	return ((uapki_process_t)fn)(request);
}

static void uapki_call_json_free(void* fn, char* buf) {
	((uapki_json_free_t)fn)(buf);
}
*/
import "C"

import (
	"errors"
	"unsafe"
)

type nativeLib struct {
	handle       unsafe.Pointer
	procProcess  unsafe.Pointer
	procJSONFree unsafe.Pointer
}

func dlError(fallback string) error {
	if msg := C.dlerror(); msg != nil {
		return errors.New(C.GoString(msg))
	}
	return errors.New(fallback)
}

func loadNative(path string) (nativeLib, error) {
	cPath := C.CString(path)
	defer C.free(unsafe.Pointer(cPath))

	handle := C.dlopen(cPath, C.RTLD_NOW|C.RTLD_LOCAL)
	if handle == nil {
		return nativeLib{}, dlError("dlopen failed")
	}
	cProcess := C.CString("process")
	defer C.free(unsafe.Pointer(cProcess))
	procProcess := C.dlsym(handle, cProcess)
	if procProcess == nil {
		err := dlError("symbol process not found")
		C.dlclose(handle)
		return nativeLib{}, err
	}
	cJSONFree := C.CString("json_free")
	defer C.free(unsafe.Pointer(cJSONFree))
	procJSONFree := C.dlsym(handle, cJSONFree)
	if procJSONFree == nil {
		err := dlError("symbol json_free not found")
		C.dlclose(handle)
		return nativeLib{}, err
	}
	return nativeLib{handle: handle, procProcess: procProcess, procJSONFree: procJSONFree}, nil
}

func (n nativeLib) unload() error {
	if C.dlclose(n.handle) != 0 {
		return dlError("dlclose failed")
	}
	return nil
}

func (n nativeLib) process(request []byte) ([]byte, error) {
	cRequest := C.CString(string(request))
	defer C.free(unsafe.Pointer(cRequest))

	cResponse := C.uapki_call_process(n.procProcess, cRequest)
	if cResponse == nil {
		return nil, errors.New("uapki: process() returned NULL")
	}
	defer C.uapki_call_json_free(n.procJSONFree, cResponse)

	return []byte(C.GoString(cResponse)), nil
}
