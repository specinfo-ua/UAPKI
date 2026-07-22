// Command example demonstrates basic usage of the UAPKI Go bindings:
// it loads the library, prints its version, computes a digest and, if a
// PKCS#12 file is given, signs a document with CAdES-BES.
//
// Usage:
//
//	example -lib uapki.dll [-providers ./] [-p12 key.p12 -password secret -in document.pdf -out document.pdf.p7s]
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"

	uapki "github.com/specinfo-ua/UAPKI/integration/Go"
)

func main() {
	libPath := flag.String("lib", "uapki", "path to the UAPKI shared library")
	providersDir := flag.String("providers", "", "directory with CM provider libraries (default: same as -lib)")
	p12Path := flag.String("p12", "", "path to a PKCS#12 (*.p12/*.pfx) key storage")
	password := flag.String("password", "", "password of the key storage")
	inPath := flag.String("in", "", "file to sign")
	outPath := flag.String("out", "", "output file for the signature (default: <in>.p7s)")
	flag.Parse()

	lib, err := uapki.Load(*libPath)
	if err != nil {
		log.Fatal(err)
	}
	defer lib.Close()

	version, err := lib.Version()
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("Library: %s %s (uapkic %s, uapkif %s)\n",
		version.Name, version.Version, version.UapkicVersion, version.UapkifVersion)

	if *p12Path == "" {
		fmt.Println("No -p12 given; nothing to sign. Done.")
		return
	}
	if err := signFile(lib, *providersDir, *p12Path, *password, *inPath, *outPath); err != nil {
		log.Fatal(err)
	}
}

// signFile initializes the library with the PKCS#12 provider, opens the key
// storage, selects the first key and writes a CAdES-BES signature of inPath.
func signFile(lib *uapki.Library, providersDir, p12Path, password, inPath, outPath string) error {
	if providersDir == "" {
		providersDir = "./"
	}
	if !os.IsPathSeparator(providersDir[len(providersDir)-1]) {
		providersDir += string(os.PathSeparator)
	}
	if _, err := lib.Init(&uapki.Config{
		Offline: true,
		CmProviders: &uapki.CmProvidersConfig{
			Dir:              providersDir,
			AllowedProviders: []uapki.CmProviderConfig{{Lib: "cm-pkcs12"}},
		},
	}); err != nil {
		return err
	}
	defer lib.Deinit()

	providers, err := lib.Providers()
	if err != nil {
		return err
	}
	if len(providers) == 0 {
		return fmt.Errorf("no CM providers found; pass -providers pointing to cm-pkcs12")
	}

	if _, err := lib.Open(uapki.OpenParams{
		Provider: providers[0].ID,
		Storage:  p12Path,
		Password: password,
	}); err != nil {
		return err
	}
	defer lib.CloseStorage()

	keys, err := lib.Keys()
	if err != nil {
		return err
	}
	if len(keys) == 0 {
		return fmt.Errorf("storage contains no keys")
	}
	selected, err := lib.SelectKey(keys[0].ID)
	if err != nil {
		return err
	}
	info, _ := json.Marshal(selected)
	fmt.Printf("Selected key: %s\n", info)

	data, err := os.ReadFile(inPath)
	if err != nil {
		return err
	}
	includeCert := true
	signatures, err := lib.Sign(uapki.SignParams{
		SignatureFormat: "CAdES-BES",
		IncludeCert:     &includeCert,
	}, []uapki.DataToSign{{ID: "doc-1", Bytes: data}})
	if err != nil {
		return err
	}

	if outPath == "" {
		outPath = inPath + ".p7s"
	}
	if err := os.WriteFile(outPath, signatures[0].Bytes, 0o644); err != nil {
		return err
	}
	fmt.Printf("Signature written to %s (%d bytes)\n", outPath, len(signatures[0].Bytes))
	return nil
}
