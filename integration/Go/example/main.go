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

	dir := *providersDir
	if dir == "" {
		dir = "./"
	}
	if !os.IsPathSeparator(dir[len(dir)-1]) {
		dir += string(os.PathSeparator)
	}
	cfg := &uapki.Config{
		Offline: true,
		CmProviders: &uapki.CmProvidersConfig{
			Dir:              dir,
			AllowedProviders: []uapki.CmProviderConfig{{Lib: "cm-pkcs12"}},
		},
	}
	if _, err := lib.Init(cfg); err != nil {
		log.Fatal(err)
	}
	defer lib.Deinit()

	providers, err := lib.Providers()
	if err != nil {
		log.Fatal(err)
	}
	if len(providers) == 0 {
		log.Fatal("no CM providers found; pass -providers pointing to cm-pkcs12")
	}

	if _, err := lib.Open(uapki.OpenParams{
		Provider: providers[0].ID,
		Storage:  *p12Path,
		Password: *password,
	}); err != nil {
		log.Fatal(err)
	}
	defer lib.CloseStorage()

	keys, err := lib.Keys()
	if err != nil {
		log.Fatal(err)
	}
	if len(keys) == 0 {
		log.Fatal("storage contains no keys")
	}
	selected, err := lib.SelectKey(keys[0].ID)
	if err != nil {
		log.Fatal(err)
	}
	info, _ := json.Marshal(selected)
	fmt.Printf("Selected key: %s\n", info)

	data, err := os.ReadFile(*inPath)
	if err != nil {
		log.Fatal(err)
	}
	includeCert := true
	signatures, err := lib.Sign(uapki.SignParams{
		SignatureFormat: "CAdES-BES",
		IncludeCert:     &includeCert,
	}, []uapki.DataToSign{{ID: "doc-1", Bytes: data}})
	if err != nil {
		log.Fatal(err)
	}

	out := *outPath
	if out == "" {
		out = *inPath + ".p7s"
	}
	if err := os.WriteFile(out, signatures[0].Bytes, 0o644); err != nil {
		log.Fatal(err)
	}
	fmt.Printf("Signature written to %s (%d bytes)\n", out, len(signatures[0].Bytes))
}
