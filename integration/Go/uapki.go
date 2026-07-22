// Package uapki provides Go bindings for the UAPKI library.
//
// The native library exposes a single JSON-based entry point:
//
//	char* process(const char* request);
//	void  json_free(char* response);
//
// This package loads the shared library at runtime (LoadLibrary on Windows,
// dlopen on POSIX systems), so no C toolchain is required to build Go
// applications on Windows; on Linux/macOS cgo is used only for dlopen.
//
// Typical usage:
//
//	lib, err := uapki.Load("uapki")
//	if err != nil { ... }
//	defer lib.Close()
//
//	version, err := lib.Version()
package uapki

import (
	"encoding/json"
	"fmt"
)

// Request is the JSON envelope accepted by the native process() entry point.
type Request struct {
	Method     string `json:"method"`
	Parameters any    `json:"parameters,omitempty"`
}

// Response is the JSON envelope returned by the native process() entry point.
type Response struct {
	ErrorCode int             `json:"errorCode"`
	Method    string          `json:"method"`
	ErrorText string          `json:"error,omitempty"`
	Result    json.RawMessage `json:"result,omitempty"`
}

// Error is returned by Call when the library reports a non-zero errorCode.
type Error struct {
	Code    int    // UAPKI error code (RET_UAPKI_*)
	Message string // human-readable message reported by the library
	Method  string // method that failed
}

func (e *Error) Error() string {
	return fmt.Sprintf("uapki: method %q failed: %s (errorCode=%d)", e.Method, e.Message, e.Code)
}

// Library is a loaded instance of the native UAPKI shared library.
// All methods are safe for use from multiple goroutines: serialization
// of stateful methods is performed by the native library itself.
type Library struct {
	native nativeLib
}

// Load loads the UAPKI shared library from the given path.
// The path may be a bare name ("uapki") to use the system library search
// order, or an absolute/relative path to the shared library file.
func Load(path string) (*Library, error) {
	native, err := loadNative(path)
	if err != nil {
		return nil, fmt.Errorf("uapki: load %q: %w", path, err)
	}
	return &Library{native: native}, nil
}

// Close unloads the native library. The Library must not be used afterwards.
func (l *Library) Close() error {
	return l.native.unload()
}

// Process sends a raw JSON request to the native library and returns the raw
// JSON response. Most callers should use Call or the typed helpers instead.
func (l *Library) Process(request []byte) ([]byte, error) {
	return l.native.process(request)
}

// Call invokes the given method with parameters marshalled to JSON and, on
// success, unmarshals the "result" object into result (unless result is nil).
// If the library reports a failure, the returned error is of type *Error.
func (l *Library) Call(method string, params any, result any) error {
	request, err := json.Marshal(Request{Method: method, Parameters: params})
	if err != nil {
		return fmt.Errorf("uapki: marshal request for %q: %w", method, err)
	}
	raw, err := l.Process(request)
	if err != nil {
		return err
	}
	var response Response
	if err := json.Unmarshal(raw, &response); err != nil {
		return fmt.Errorf("uapki: unmarshal response of %q: %w", method, err)
	}
	if response.ErrorCode != 0 {
		return &Error{Code: response.ErrorCode, Message: response.ErrorText, Method: method}
	}
	if result != nil && len(response.Result) > 0 {
		if err := json.Unmarshal(response.Result, result); err != nil {
			return fmt.Errorf("uapki: unmarshal result of %q: %w", method, err)
		}
	}
	return nil
}
