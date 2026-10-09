package uapki

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"unsafe"
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

// verifyStatus returns statusMessageDigest of every signer, and fails if the
// content was returned.
func verifyStatus(t *testing.T, result VerifyResult) []string {
	t.Helper()
	var parsed struct {
		Content *struct {
			Bytes []byte `json:"bytes"`
		} `json:"content"`
		SignatureInfos []struct {
			StatusMessageDigest string `json:"statusMessageDigest"`
			StatusSignature     string `json:"statusSignature"`
		} `json:"signatureInfos"`
	}
	if err := json.Unmarshal(result, &parsed); err != nil {
		t.Fatalf("VERIFY result: %v", err)
	}
	if parsed.Content != nil && len(parsed.Content.Bytes) > 0 {
		t.Error("VERIFY returned the content")
	}
	if len(parsed.SignatureInfos) == 0 {
		t.Fatal("VERIFY returned no signers")
	}
	statuses := make([]string, len(parsed.SignatureInfos))
	for i, info := range parsed.SignatureInfos {
		statuses[i] = info.StatusMessageDigest
		if info.StatusSignature != "VALID" {
			t.Errorf("statusSignature = %s", info.StatusSignature)
		}
	}
	return statuses
}

// TestSignDetachedAndVerify signs a file and data in memory with the signing
// key of test-diia.p12 and verifies them by a file and by a pointer.
// Set UAPKI_CM_PROVIDERS and UAPKI_TEST_DATA (library/test/data); the test is
// skipped otherwise.
func TestSignDetachedAndVerify(t *testing.T) {
	providersDir := os.Getenv("UAPKI_CM_PROVIDERS")
	testData := os.Getenv("UAPKI_TEST_DATA")
	if providersDir == "" || testData == "" {
		t.Skip("UAPKI_CM_PROVIDERS or UAPKI_TEST_DATA not set")
	}
	lib := loadTestLibrary(t)
	if !os.IsPathSeparator(providersDir[len(providersDir)-1]) {
		providersDir += string(os.PathSeparator)
	}

	work := t.TempDir()
	certDir := filepath.Join(work, "certs") + string(os.PathSeparator)
	crlDir := filepath.Join(work, "crls") + string(os.PathSeparator)
	for _, dir := range []string{certDir, crlDir} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	// The certificate cache renames files, so it gets a copy
	certs, _ := filepath.Glob(filepath.Join(testData, "certs", "*.cer"))
	for _, cert := range certs {
		data, err := os.ReadFile(cert)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(certDir, filepath.Base(cert)), data, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	storage := filepath.Join(work, "storage.p12")
	p12, err := os.ReadFile(filepath.Join(testData, "test-diia.p12"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(storage, p12, 0o644); err != nil {
		t.Fatal(err)
	}

	if _, err := lib.Init(&Config{
		CmProviders: &CmProvidersConfig{Dir: providersDir, AllowedProviders: []CmProviderConfig{{Lib: "cm-pkcs12"}}},
		CertCache:   &CertCacheConfig{Path: certDir},
		CrlCache:    &CrlCacheConfig{Path: crlDir},
		Offline:     true,
	}); err != nil {
		t.Fatalf("INIT failed: %v", err)
	}
	t.Cleanup(func() { _ = lib.Deinit() })
	if _, err := lib.Open(OpenParams{Provider: "PKCS12", Storage: storage, Password: "testpassword", Mode: "RO"}); err != nil {
		t.Fatalf("OPEN failed: %v", err)
	}
	t.Cleanup(func() { _ = lib.CloseStorage() })

	document := filepath.Join(work, "document.txt")
	content := []byte(strings.Repeat("The quick brown fox jumps over the lazy dog", 1000))
	if err := os.WriteFile(document, content, 0o644); err != nil {
		t.Fatal(err)
	}
	other := filepath.Join(work, "other.txt")
	if err := os.WriteFile(other, []byte("Another document"), 0o644); err != nil {
		t.Fatal(err)
	}

	// The memory stays in place for the library: pinned until the end of the test
	var pinner runtime.Pinner
	pinner.Pin(&content[0])
	defer pinner.Unpin()
	memory := MemorySource(unsafe.Pointer(&content[0]), uint64(len(content)))

	// The signing key of the storage: the first one that signs CAdES. The certificates of the test
	// storage have expired, so their status is not checked
	keys, err := lib.Keys()
	if err != nil {
		t.Fatalf("KEYS failed: %v", err)
	}
	params := SignParams{SignatureFormat: "CAdES-BES", SignAlgo: "1.2.804.2.1.1.1.1.3.1.1"} // DSTU 4145 with GOST 34.311
	var signatures [][]byte
	for _, key := range keys {
		if _, err := lib.SelectKey(key.ID); err != nil {
			continue
		}
		if signatures, err = lib.SignDetached(params, []Source{FileSource(document), memory}, &SignOptions{IgnoreCertStatus: true}); err == nil {
			break
		}
	}
	if len(signatures) != 2 {
		t.Fatalf("SIGN with no key of the storage: %v", err)
	}

	for name, check := range map[string]struct {
		signature []byte
		content   Source
		want      string
	}{
		"file by file":     {signatures[0], FileSource(document), "VALID"},
		"memory by memory": {signatures[1], memory, "VALID"},
		"memory by file":   {signatures[1], FileSource(document), "VALID"},
		"file by memory":   {signatures[0], memory, "VALID"},
		"other content":    {signatures[0], FileSource(other), "INVALID"},
	} {
		result, err := lib.VerifyDetached(check.signature, check.content, "STRUCT")
		if err != nil {
			t.Fatalf("%s: VERIFY failed: %v", name, err)
		}
		statuses := verifyStatus(t, result)
		if statuses[0] != check.want {
			t.Errorf("%s: statusMessageDigest = %s, want %s", name, statuses[0], check.want)
		}
	}

	// Nothing is written next to the document
	if _, err := os.Stat(document + ".p7s"); err == nil {
		t.Error("a file was written next to the document")
	}
}
