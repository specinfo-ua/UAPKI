package uapki

import "encoding/json"

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
