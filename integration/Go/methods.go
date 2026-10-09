package uapki

import (
	"encoding/json"
	"fmt"
	"strconv"
	"unsafe"
)

// VersionInfo is the result of the VERSION method.
type VersionInfo struct {
	Name          string `json:"name"`
	Version       string `json:"version"`
	UapkicVersion string `json:"uapkicVersion"`
	UapkifVersion string `json:"uapkifVersion"`
}

// Version reports the versions of the loaded native libraries.
func (l *Library) Version() (*VersionInfo, error) {
	var result VersionInfo
	if err := l.Call("VERSION", nil, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// CmProviderConfig describes one allowed key-media (CM) provider.
type CmProviderConfig struct {
	Lib    string `json:"lib"`
	Config any    `json:"config,omitempty"`
}

// CmProvidersConfig configures loading of key-media (CM) providers.
type CmProvidersConfig struct {
	Dir              string             `json:"dir,omitempty"`
	AllowedProviders []CmProviderConfig `json:"allowedProviders,omitempty"`
}

// CertCacheConfig configures the certificate cache.
type CertCacheConfig struct {
	Path         string   `json:"path,omitempty"`
	TrustedCerts [][]byte `json:"trustedCerts,omitempty"` // DER certificates, marshalled as base64
}

// CrlCacheConfig configures the CRL cache.
type CrlCacheConfig struct {
	Path        string `json:"path,omitempty"`
	UseDeltaCrl bool   `json:"useDeltaCrl,omitempty"`
}

// OcspConfig configures OCSP usage.
type OcspConfig struct {
	NonceLen int `json:"nonceLen,omitempty"`
}

// TspConfig configures the time-stamp protocol client.
type TspConfig struct {
	URL      any    `json:"url,omitempty"` // string or []string
	PolicyID string `json:"policyId,omitempty"`
	NonceLen int    `json:"nonceLen,omitempty"`
	CertReq  bool   `json:"certReq,omitempty"`
	Forced   bool   `json:"forced,omitempty"`
}

// Config is the parameter object of the INIT method. All fields are optional.
type Config struct {
	CmProviders  *CmProvidersConfig `json:"cmProviders,omitempty"`
	CertCache    *CertCacheConfig   `json:"certCache,omitempty"`
	CrlCache     *CrlCacheConfig    `json:"crlCache,omitempty"`
	Ocsp         *OcspConfig        `json:"ocsp,omitempty"`
	Tsp          *TspConfig         `json:"tsp,omitempty"`
	Offline      bool               `json:"offline,omitempty"`
	SkipSelfTest bool               `json:"skipSelfTest,omitempty"`
}

// Init initializes the library. cfg may be nil to use defaults.
// It returns the raw "result" object with cache/provider counters.
func (l *Library) Init(cfg *Config) (json.RawMessage, error) {
	var result json.RawMessage
	if err := l.Call("INIT", cfg, &result); err != nil {
		return nil, err
	}
	return result, nil
}

// Deinit releases all resources acquired by Init.
func (l *Library) Deinit() error {
	return l.Call("DEINIT", nil, nil)
}

// Provider describes one loaded key-media (CM) provider.
type Provider struct {
	ID                  string          `json:"id"`
	APIVersion          string          `json:"apiVersion"`
	LibVersion          string          `json:"libVersion"`
	Description         string          `json:"description"`
	Manufacturer        string          `json:"manufacturer"`
	SupportListStorages bool            `json:"supportListStorages"`
	Flags               json.RawMessage `json:"flags,omitempty"`
}

// Providers lists the loaded key-media (CM) providers.
func (l *Library) Providers() ([]Provider, error) {
	var result struct {
		Providers []Provider `json:"providers"`
	}
	if err := l.Call("PROVIDERS", nil, &result); err != nil {
		return nil, err
	}
	return result.Providers, nil
}

// OpenParams is the parameter object of the OPEN method. Provider-specific
// options (e.g. {"bagCipher": ...} for PKCS#12) can be passed via OpenParams.
type OpenParams struct {
	Provider   string `json:"provider"`
	Storage    string `json:"storage"`
	Password   string `json:"password,omitempty"`
	Mode       string `json:"mode,omitempty"` // RO, RW or CREATE
	OpenParams any    `json:"openParams,omitempty"`
}

// Open opens a key storage (session) and returns the raw session info.
func (l *Library) Open(params OpenParams) (json.RawMessage, error) {
	var result json.RawMessage
	if err := l.Call("OPEN", params, &result); err != nil {
		return nil, err
	}
	return result, nil
}

// CloseStorage closes the currently opened key storage.
func (l *Library) CloseStorage() error {
	return l.Call("CLOSE", nil, nil)
}

// KeyInfo describes one key in the opened storage.
type KeyInfo struct {
	ID          string   `json:"id"`
	MechanismID string   `json:"mechanismId"`
	ParameterID string   `json:"parameterId"`
	Label       string   `json:"label"`
	Application string   `json:"application,omitempty"`
	SignAlgo    []string `json:"signAlgo,omitempty"`
}

// Keys lists the keys available in the opened storage.
func (l *Library) Keys() ([]KeyInfo, error) {
	var result struct {
		Keys []KeyInfo `json:"keys"`
	}
	if err := l.Call("KEYS", nil, &result); err != nil {
		return nil, err
	}
	return result.Keys, nil
}

// SelectKeyResult is the result of the SELECT_KEY method.
type SelectKeyResult struct {
	ID          string   `json:"id,omitempty"`
	CertID      string   `json:"certId,omitempty"`
	MechanismID string   `json:"mechanismId,omitempty"`
	ParameterID string   `json:"parameterId,omitempty"`
	SignAlgo    []string `json:"signAlgo,omitempty"`
}

// SelectKey selects the key with the given id in the opened storage.
func (l *Library) SelectKey(id string) (*SelectKeyResult, error) {
	params := map[string]string{"id": id}
	var result SelectKeyResult
	if err := l.Call("SELECT_KEY", params, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// SignParams is the "signParams" object of the SIGN method.
type SignParams struct {
	SignatureFormat  string `json:"signatureFormat,omitempty"` // "CAdES-BES" (default), "CAdES-T", "CMS", "RAW", ...
	SignAlgo         string `json:"signAlgo,omitempty"`
	DigestAlgo       string `json:"digestAlgo,omitempty"`
	DetachedData     *bool  `json:"detachedData,omitempty"` // default: true
	IncludeCert      *bool  `json:"includeCert,omitempty"`
	IncludeTime      *bool  `json:"includeTime,omitempty"`
	IncludeContentTS *bool  `json:"includeContentTS,omitempty"`
}

// DataToSign is one document passed to the SIGN method.
type DataToSign struct {
	ID       string `json:"id"`
	Bytes    []byte `json:"bytes,omitempty"` // marshalled as base64
	IsDigest bool   `json:"isDigest,omitempty"`
	Type     string `json:"type,omitempty"` // content type OID
}

// SignedDoc is one signed document returned by the SIGN method.
type SignedDoc struct {
	ID    string `json:"id"`
	Bytes []byte `json:"bytes"` // signature (or signed content), base64-decoded
}

// Sign signs the given documents with the selected key.
func (l *Library) Sign(signParams SignParams, docs []DataToSign) ([]SignedDoc, error) {
	params := map[string]any{
		"signParams": signParams,
		"dataTbs":    docs,
	}
	var result struct {
		SignatureIds []SignedDoc `json:"signatures"`
	}
	if err := l.Call("SIGN", params, &result); err != nil {
		return nil, err
	}
	return result.SignatureIds, nil
}

// VerifyResult is the raw result of the VERIFY method.
type VerifyResult = json.RawMessage

// Verify verifies a CAdES/CMS signature. content may be nil for an
// attached (enveloped) signature.
func (l *Library) Verify(signature, content []byte) (VerifyResult, error) {
	signatureParams := map[string]any{"bytes": signature}
	if content != nil {
		signatureParams["content"] = content
	}
	params := map[string]any{"signature": signatureParams}
	var result json.RawMessage
	if err := l.Call("VERIFY", params, &result); err != nil {
		return nil, err
	}
	return result, nil
}

// Source is the content of a document for SignDetached and VerifyDetached: a file,
// read by the library in blocks, or data in memory, hashed by the library in
// place. Neither goes through base64, so the size is not limited.
type Source struct {
	File string  // path of the file, or empty for data in memory
	Ptr  uintptr // address of the data in memory
	Size uint64  // size of the data in memory
}

// FileSource is the content of the file at path.
func FileSource(path string) Source {
	return Source{File: path}
}

// MemorySource is size bytes at ptr. The library reads the memory during the
// call only, but the Go garbage collector must not move or free it meanwhile:
// use memory outside the Go heap (a memory-mapped file, C memory) or pin the Go
// memory with runtime.Pinner until the call returns. ptr must not be nil, even
// for empty data.
func MemorySource(ptr unsafe.Pointer, size uint64) Source {
	return Source{Ptr: uintptr(ptr), Size: size}
}

// params returns the fields of the source in a dataTbs or signature object:
// "file", or "ptr" (hex, big-endian, the width of a pointer) and "size".
func (s Source) params() map[string]any {
	if s.File != "" {
		return map[string]any{"file": s.File}
	}
	return map[string]any{
		"ptr":  fmt.Sprintf("%0*X", 2*unsafe.Sizeof(uintptr(0)), uint64(s.Ptr)),
		"size": s.Size,
	}
}

// SignOptions is the "options" object of the SIGN method.
type SignOptions struct {
	IgnoreCertStatus bool `json:"ignoreCertStatus,omitempty"` // do not check the status of the signer certificate
	CheckTrustedRoot bool `json:"checkTrustedRoot,omitempty"` // the chain of the signer must end in a trusted root (with the status check)
}

// SignDetached signs files or data in memory with the selected key in one call
// of the SIGN method. The signatures are detached (signParams.DetachedData is
// ignored) and are returned in the order of sources; nothing is written to disk.
// options may be nil. A signature with encapsulated content can be assembled by
// the caller: the content is not part of the signed attributes, so embedding it
// does not change the signature value.
func (l *Library) SignDetached(signParams SignParams, sources []Source, options *SignOptions) ([][]byte, error) {
	detached := true
	signParams.DetachedData = &detached

	docs := make([]map[string]any, len(sources))
	for i, source := range sources {
		doc := source.params()
		doc["id"] = strconv.Itoa(i)
		docs[i] = doc
	}
	params := map[string]any{
		"signParams": signParams,
		"dataTbs":    docs,
	}
	if options != nil {
		params["options"] = options
	}
	var result struct {
		Signatures []SignedDoc `json:"signatures"`
	}
	if err := l.Call("SIGN", params, &result); err != nil {
		return nil, err
	}

	signatures := make([][]byte, len(sources))
	for _, signature := range result.Signatures {
		i, err := strconv.Atoi(signature.ID)
		if err != nil || i < 0 || i >= len(sources) {
			return nil, fmt.Errorf("uapki: SIGN returned an unknown id %q", signature.ID)
		}
		signatures[i] = signature.Bytes
	}
	for i, signature := range signatures {
		if signature == nil {
			return nil, fmt.Errorf("uapki: SIGN returned no signature for source %d", i)
		}
	}
	return signatures, nil
}

// VerifyDetached verifies a signature without encapsulated content against
// content in a file or in memory, in one call of the VERIFY method; the content
// is not returned. For a signature with encapsulated content the caller can
// pass the signature without the content and point to the content inside the
// memory-mapped signature file. validationType is "FULL", "CHAIN", "STRUCT" or
// empty for the default of the library.
func (l *Library) VerifyDetached(signature []byte, content Source, validationType string) (VerifyResult, error) {
	signatureParams := content.params()
	signatureParams["bytes"] = signature
	params := map[string]any{
		"signature":     signatureParams,
		"returnContent": false,
	}
	if validationType != "" {
		params["options"] = map[string]string{"validationType": validationType}
	}
	var result json.RawMessage
	if err := l.Call("VERIFY", params, &result); err != nil {
		return nil, err
	}
	return result, nil
}

// Digest computes the digest of data with the given hash algorithm
// (an OID string, e.g. "2.16.840.1.101.3.4.2.1" for SHA-256, or
// "1.2.804.2.1.1.1.1.2.1" for DSTU 7564).
func (l *Library) Digest(hashAlgo string, data []byte) ([]byte, error) {
	params := map[string]any{
		"hashAlgo": hashAlgo,
		"bytes":    data,
	}
	var result struct {
		Bytes []byte `json:"bytes"`
	}
	if err := l.Call("DIGEST", params, &result); err != nil {
		return nil, err
	}
	return result.Bytes, nil
}

// RandomBytes generates n random bytes using the library CSPRNG.
func (l *Library) RandomBytes(n int) ([]byte, error) {
	params := map[string]int{"length": n}
	var result struct {
		Bytes []byte `json:"bytes"`
	}
	if err := l.Call("RANDOM_BYTES", params, &result); err != nil {
		return nil, err
	}
	return result.Bytes, nil
}
