package uapki

import (
	"bytes"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// loadTestLibrary loads the UAPKI shared library for testing.
// Set UAPKI_LIBRARY to the path of the shared library; otherwise the
// platform-default name is looked up via the system search path.
func loadTestLibrary(t *testing.T) *Library {
	t.Helper()
	path := os.Getenv("UAPKI_LIBRARY")
	if path == "" {
		switch runtime.GOOS {
		case "windows":
			path = "uapki.dll"
		case "darwin":
			path = "libuapki.dylib"
		default:
			path = "libuapki.so"
		}
	}
	lib, err := Load(path)
	if err != nil {
		t.Skipf("UAPKI shared library not available (set UAPKI_LIBRARY): %v", err)
	}
	t.Cleanup(func() { _ = lib.Close() })
	return lib
}

func TestVersion(t *testing.T) {
	lib := loadTestLibrary(t)
	version, err := lib.Version()
	if err != nil {
		t.Fatalf("VERSION failed: %v", err)
	}
	if version.Name == "" || version.Version == "" {
		t.Errorf("unexpected VERSION result: %+v", version)
	}
	t.Logf("%s %s (uapkic %s, uapkif %s)",
		version.Name, version.Version, version.UapkicVersion, version.UapkifVersion)
}

func TestDigestSha256(t *testing.T) {
	lib := loadTestLibrary(t)
	const oidSha256 = "2.16.840.1.101.3.4.2.1"
	digest, err := lib.Digest(oidSha256, []byte("abc"))
	if err != nil {
		t.Fatalf("DIGEST failed: %v", err)
	}
	want, _ := hex.DecodeString("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
	if !bytes.Equal(digest, want) {
		t.Errorf("SHA-256(\"abc\") = %x, want %x", digest, want)
	}
}

func TestDigestDstu7564(t *testing.T) {
	lib := loadTestLibrary(t)
	const oidKupyna256 = "1.2.804.2.1.1.1.1.2.2.1" // DSTU 7564 ("Kupyna"), 256 bit
	digest, err := lib.Digest(oidKupyna256, []byte("abc"))
	if err != nil {
		t.Fatalf("DIGEST failed: %v", err)
	}
	if len(digest) != 32 {
		t.Errorf("DSTU 7564-256 digest length = %d, want 32", len(digest))
	}
}

func TestRandomBytes(t *testing.T) {
	lib := loadTestLibrary(t)
	random, err := lib.RandomBytes(32)
	if err != nil {
		t.Fatalf("RANDOM_BYTES failed: %v", err)
	}
	if len(random) != 32 {
		t.Fatalf("RANDOM_BYTES length = %d, want 32", len(random))
	}
	if bytes.Equal(random, make([]byte, 32)) {
		t.Error("RANDOM_BYTES returned all zeroes")
	}
}

func TestUnknownMethod(t *testing.T) {
	lib := loadTestLibrary(t)
	err := lib.Call("NO_SUCH_METHOD", nil, nil)
	var uapkiErr *Error
	if err == nil {
		t.Fatal("expected an error for unknown method")
	}
	if !errors.As(err, &uapkiErr) {
		t.Fatalf("expected *uapki.Error, got %T: %v", err, err)
	}
	t.Logf("errorCode=%d message=%q", uapkiErr.Code, uapkiErr.Message)
}

// TestPkcs12CreateKeyAndSign exercises the full flow against the PKCS#12
// provider: INIT with CM providers, create a file storage, generate an EC
// key, issue a CSR and make a RAW signature.
// Set UAPKI_CM_PROVIDERS to the directory containing cm-pkcs12; the test is
// skipped otherwise.
func TestPkcs12CreateKeyAndSign(t *testing.T) {
	providersDir := os.Getenv("UAPKI_CM_PROVIDERS")
	if providersDir == "" {
		t.Skip("UAPKI_CM_PROVIDERS not set")
	}
	lib := loadTestLibrary(t)

	// The library concatenates dir with the platform library name
	// (e.g. "cm-pkcs12.dll"), so dir must end with a path separator.
	if !os.IsPathSeparator(providersDir[len(providersDir)-1]) {
		providersDir += string(os.PathSeparator)
	}
	if _, err := lib.Init(&Config{
		CmProviders: &CmProvidersConfig{
			Dir:              providersDir,
			AllowedProviders: []CmProviderConfig{{Lib: "cm-pkcs12"}},
		},
		Offline: true,
	}); err != nil {
		t.Fatalf("INIT failed: %v", err)
	}
	t.Cleanup(func() { _ = lib.Deinit() })

	providers, err := lib.Providers()
	if err != nil {
		t.Fatalf("PROVIDERS failed: %v", err)
	}
	if len(providers) == 0 {
		t.Fatal("no CM providers loaded")
	}
	t.Logf("providers: %+v", providers)

	storagePath := filepath.Join(t.TempDir(), "test-storage.p12")
	if _, err := lib.Open(OpenParams{
		Provider: providers[0].ID,
		Storage:  storagePath,
		Password: "testpassword",
		Mode:     "CREATE",
	}); err != nil {
		t.Fatalf("OPEN (CREATE) failed: %v", err)
	}
	t.Cleanup(func() { _ = lib.CloseStorage() })

	var created struct {
		ID string `json:"id"`
	}
	if err := lib.Call("CREATE_KEY", map[string]string{
		"mechanismId": "1.2.840.10045.2.1",   // EC
		"parameterId": "1.2.840.10045.3.1.7", // P-256
		"label":       "go-integration-test",
	}, &created); err != nil {
		t.Fatalf("CREATE_KEY failed: %v", err)
	}
	if created.ID == "" {
		t.Fatal("CREATE_KEY returned empty key id")
	}

	if _, err := lib.SelectKey(created.ID); err != nil {
		t.Fatalf("SELECT_KEY failed: %v", err)
	}

	var csr struct {
		Bytes []byte `json:"bytes"`
	}
	if err := lib.Call("GET_CSR", nil, &csr); err != nil {
		t.Fatalf("GET_CSR failed: %v", err)
	}
	if len(csr.Bytes) == 0 {
		t.Fatal("GET_CSR returned empty CSR")
	}
	t.Logf("CSR: %d bytes", len(csr.Bytes))

	signatures, err := lib.Sign(SignParams{
		SignatureFormat: "RAW",
		SignAlgo:        "1.2.840.10045.4.3.2", // ecdsa-with-SHA256
	}, []DataToSign{{ID: "doc-1", Bytes: []byte("Hello, UAPKI from Go!")}})
	if err != nil {
		t.Fatalf("SIGN failed: %v", err)
	}
	if len(signatures) != 1 || len(signatures[0].Bytes) == 0 {
		t.Fatalf("unexpected SIGN result: %+v", signatures)
	}
	t.Logf("RAW signature: %d bytes", len(signatures[0].Bytes))
}
