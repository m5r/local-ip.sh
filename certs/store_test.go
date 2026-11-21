package certs

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"io/fs"
	"math/big"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

// testStore returns a store whose state directory does not exist yet, so that the directories it creates can be inspected.
func testStore(t *testing.T) *store {
	t.Helper()
	cfg, err := checkConfig(Config{
		DirectoryURL: "https://ca.test/directory",
		Domain:       "example.com",
		StateDir:     filepath.Join(t.TempDir(), "state"),
		Records:      &memoryRecords{},
	})
	if err != nil {
		t.Fatal(err)
	}
	s, err := newStore(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func keyPEMOf(t *testing.T, key crypto.Signer) []byte {
	t.Helper()
	switch k := key.(type) {
	case *rsa.PrivateKey:
		return pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(k)})
	case *ecdsa.PrivateKey:
		der, err := x509.MarshalECPrivateKey(k)
		if err != nil {
			t.Fatal(err)
		}
		return pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})
	}
	t.Fatalf("unexpected key type %T", key)
	return nil
}

func newECKey(t *testing.T, curve elliptic.Curve) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

// testChain returns a key for names and its chain, leaf first and followed by the self-signed issuer, both PEM-encoded.
func testChain(t *testing.T, names []string, key crypto.Signer) (keyPEM, chainPEM []byte) {
	t.Helper()
	issuerKey := newECKey(t, elliptic.P256())
	now := time.Now()
	issuerTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test issuer"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	issuerDER, err := x509.CreateCertificate(rand.Reader, issuerTemplate, issuerTemplate, issuerKey.Public(), issuerKey)
	if err != nil {
		t.Fatal(err)
	}
	issuer, err := x509.ParseCertificate(issuerDER)
	if err != nil {
		t.Fatal(err)
	}
	serial, err := rand.Int(rand.Reader, big.NewInt(1<<62))
	if err != nil {
		t.Fatal(err)
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, &x509.Certificate{
		SerialNumber: serial,
		DNSNames:     names,
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}, issuer, key.Public(), issuerKey)
	if err != nil {
		t.Fatal(err)
	}
	chainPEM = append(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER}), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: issuerDER})...)
	return keyPEMOf(t, key), chainPEM
}

func testCertificate(t *testing.T, names []string) *Certificate {
	t.Helper()
	keyPEM, chainPEM := testChain(t, names, newECKey(t, elliptic.P256()))
	certificate, err := newCertificate(keyPEM, chainPEM, names)
	if err != nil {
		t.Fatal(err)
	}
	return certificate
}

func writeTestFile(t *testing.T, path string, content []byte) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatal(err)
	}
}

func skipWithoutPermissions(t *testing.T) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("file modes are not enforced on Windows")
	}
	if os.Geteuid() == 0 {
		t.Skip("root ignores file modes")
	}
}

func TestCertificateRoundTrip(t *testing.T) {
	s := testStore(t)
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		id    string
		names []string
		key   crypto.Signer
	}{
		{"site", []string{"example.com"}, rsaKey},
		{"wildcard", []string{"*.example.com"}, newECKey(t, elliptic.P256())},
	} {
		keyPEM, chainPEM := testChain(t, tc.names, tc.key)
		saved, err := newCertificate(keyPEM, chainPEM, tc.names)
		if err != nil {
			t.Fatalf("%s: newCertificate: %v", tc.id, err)
		}
		if err := s.saveCertificate(tc.id, saved); err != nil {
			t.Fatalf("%s: saving: %v", tc.id, err)
		}
		content, err := os.ReadFile(s.certificatePath(tc.id))
		if err != nil {
			t.Fatal(err)
		}
		if want := append(append([]byte{}, keyPEM...), chainPEM...); !bytes.Equal(content, want) {
			t.Errorf("%s: file content is not the key followed by the chain:\n%s", tc.id, content)
		}

		loaded, err := s.loadCertificate(tc.id, tc.names)
		if err != nil {
			t.Fatalf("%s: loading: %v", tc.id, err)
		}
		if !bytes.Equal(loaded.KeyPEM, keyPEM) || !bytes.Equal(loaded.ChainPEM, chainPEM) {
			t.Errorf("%s: loaded PEM differs from what was saved", tc.id)
		}
		if loaded.TLS.Leaf == nil || loaded.TLS.Leaf.SerialNumber.Cmp(saved.TLS.Leaf.SerialNumber) != 0 {
			t.Errorf("%s: loaded leaf = %v, want serial %v", tc.id, loaded.TLS.Leaf, saved.TLS.Leaf.SerialNumber)
		}
		if len(loaded.TLS.Certificate) != 2 {
			t.Errorf("%s: loaded chain has %d certificates, want 2", tc.id, len(loaded.TLS.Certificate))
		}
		if signer, ok := loaded.TLS.PrivateKey.(crypto.Signer); !ok || !signer.Public().(interface{ Equal(crypto.PublicKey) bool }).Equal(tc.key.Public()) {
			t.Errorf("%s: loaded private key is not the saved one", tc.id)
		}
	}
}

func TestExpiredCertificateLoads(t *testing.T) {
	s := testStore(t)
	key := newECKey(t, elliptic.P256())
	der, err := x509.CreateCertificate(rand.Reader, &x509.Certificate{
		SerialNumber: big.NewInt(7),
		DNSNames:     []string{"example.com"},
		NotBefore:    time.Now().Add(-48 * time.Hour),
		NotAfter:     time.Now().Add(-24 * time.Hour),
	}, &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "issuer"}}, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	writeTestFile(t, s.certificatePath("site"), append(keyPEMOf(t, key), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})...))
	if _, err := s.loadCertificate("site", []string{"example.com"}); err != nil {
		t.Errorf("loading an expired certificate: %v", err)
	}
}

func TestAccountKeyRoundTrip(t *testing.T) {
	s := testStore(t)
	key := newECKey(t, elliptic.P256())
	if err := s.saveAccountKey(key); err != nil {
		t.Fatalf("saving: %v", err)
	}
	loaded, err := s.loadAccountKey()
	if err != nil {
		t.Fatalf("loading: %v", err)
	}
	if !loaded.Equal(key) {
		t.Error("loaded account key differs from the saved one")
	}
	content, err := os.ReadFile(s.accountKeyPath())
	if err != nil {
		t.Fatal(err)
	}
	if block, rest := pem.Decode(content); block == nil || block.Type != "EC PRIVATE KEY" || len(rest) != 0 {
		t.Errorf("account.pem is not one EC PRIVATE KEY block:\n%s", content)
	}
}

func assertMode(t *testing.T, path string, want fs.FileMode) {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != want {
		t.Errorf("mode of %s = %v, want %v", path, got, want)
	}
}

func TestFileModes(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("file modes are not enforced on Windows")
	}
	s := testStore(t)
	if err := s.saveAccountKey(newECKey(t, elliptic.P256())); err != nil {
		t.Fatal(err)
	}
	if err := s.saveCertificate("site", testCertificate(t, []string{"example.com"})); err != nil {
		t.Fatal(err)
	}
	assertMode(t, filepath.Dir(s.authorityDir), 0o700)
	assertMode(t, s.authorityDir, 0o700)
	assertMode(t, s.domainDir, 0o700)
	assertMode(t, s.accountKeyPath(), 0o600)
	assertMode(t, s.certificatePath("site"), 0o600)
}

func TestExistingDirectoryModeIsLeftAlone(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("file modes are not enforced on Windows")
	}
	s := testStore(t)
	stateDir := filepath.Dir(s.authorityDir)
	if err := os.Mkdir(stateDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(stateDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := s.saveAccountKey(newECKey(t, elliptic.P256())); err != nil {
		t.Fatal(err)
	}
	assertMode(t, stateDir, 0o755)
	assertMode(t, s.authorityDir, 0o700)
}

func TestLeftoverTemporaryFile(t *testing.T) {
	s := testStore(t)
	names := []string{"example.com"}
	first := testCertificate(t, names)
	if err := s.saveCertificate("site", first); err != nil {
		t.Fatal(err)
	}
	temporary := s.certificatePath("site") + ".tmp"
	writeTestFile(t, temporary, []byte("left over by a crash, longer than nothing at all"))
	if err := os.Chmod(temporary, 0o644); err != nil {
		t.Fatal(err)
	}

	loaded, err := s.loadCertificate("site", names)
	if err != nil {
		t.Fatalf("loading next to a leftover temporary file: %v", err)
	}
	if !bytes.Equal(loaded.ChainPEM, first.ChainPEM) {
		t.Error("loaded certificate is not the saved one")
	}

	second := testCertificate(t, names)
	if err := s.saveCertificate("site", second); err != nil {
		t.Fatalf("saving over a leftover temporary file: %v", err)
	}
	if _, err := os.Stat(temporary); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("temporary file after a write: %v, want it gone", err)
	}
	loaded, err = s.loadCertificate("site", names)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(loaded.ChainPEM, second.ChainPEM) {
		t.Error("the file does not hold the certificate written last")
	}
	if runtime.GOOS != "windows" {
		assertMode(t, s.certificatePath("site"), 0o600)
	}
}

func TestAbsentFiles(t *testing.T) {
	s := testStore(t)
	if _, err := s.loadCertificate("site", []string{"example.com"}); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("absent certificate: err = %v, want fs.ErrNotExist", err)
	}
	if _, err := s.loadAccountKey(); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("absent account key: err = %v, want fs.ErrNotExist", err)
	}
}

func TestUnusableCertificates(t *testing.T) {
	names := []string{"example.com"}
	key := newECKey(t, elliptic.P256())
	keyPEM, chainPEM := testChain(t, names, key)
	otherKeyPEM, _ := testChain(t, names, newECKey(t, elliptic.P256()))
	// The same key, so that the names are the only thing wrong.
	_, otherNamesChain := testChain(t, []string{"other.example"}, key)
	leafBlock, rest := pem.Decode(chainPEM)
	leafPEM := pem.EncodeToMemory(leafBlock)
	issuerBlock, _ := pem.Decode(rest)
	issuerPEM := pem.EncodeToMemory(issuerBlock)
	random := make([]byte, 512)
	if _, err := rand.Read(random); err != nil {
		t.Fatal(err)
	}
	join := func(parts ...[]byte) []byte { return bytes.Join(parts, nil) }

	for _, tc := range []struct {
		name    string
		content []byte
	}{
		{"wrong names", join(keyPEM, otherNamesChain)},
		{"key of another certificate", join(otherKeyPEM, chainPEM)},
		{"no certificate block", keyPEM},
		{"key block not first", join(chainPEM, keyPEM)},
		{"second certificate block damaged", join(keyPEM, leafPEM, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("not DER at all")}))},
		{"block after the key that is not a certificate", join(keyPEM, leafPEM, otherKeyPEM)},
		{"bytes after the chain", join(keyPEM, chainPEM, []byte("trailing garbage\n"))},
		{"middle certificate block with damaged base64", join(keyPEM, leafPEM, damaged(t, issuerPEM), issuerPEM)},
		{"bytes before the key block", join([]byte("explanatory text\n"), keyPEM, chainPEM)},
		{"damaged block before the key block", join(damaged(t, keyPEM), keyPEM, chainPEM)},
		{"text between two certificate blocks", join(keyPEM, leafPEM, []byte("issuer:\n"), issuerPEM)},
		{"last block cut short", join(keyPEM, leafPEM, issuerPEM[:len(issuerPEM)/2])},
		{"random bytes", random},
		{"empty file", nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := testStore(t)
			writeTestFile(t, s.certificatePath("site"), tc.content)
			certificate, err := s.loadCertificate("site", names)
			if err == nil {
				t.Fatalf("loaded %v, want an error", certificate.TLS.Leaf.DNSNames)
			}
			if errors.Is(err, fs.ErrNotExist) {
				t.Errorf("err = %v satisfies fs.ErrNotExist", err)
			}
		})
	}
}

// unusableAccountKeys are the contents of account.pem that the store must refuse with errUnusableAccountKey.
func unusableAccountKeys(t *testing.T) []struct {
	name    string
	content []byte
} {
	t.Helper()
	random := make([]byte, 256)
	if _, err := rand.Read(random); err != nil {
		t.Fatal(err)
	}
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	pkcs8, err := x509.MarshalPKCS8PrivateKey(rsaKey)
	if err != nil {
		t.Fatal(err)
	}
	valid := keyPEMOf(t, newECKey(t, elliptic.P256()))
	_, chainPEM := testChain(t, []string{"example.com"}, newECKey(t, elliptic.P256()))
	certificateBlock, _ := pem.Decode(chainPEM)
	return []struct {
		name    string
		content []byte
	}{
		{"empty file", nil},
		{"random bytes", random},
		{"certificate block", pem.EncodeToMemory(certificateBlock)},
		{"RSA key", keyPEMOf(t, rsaKey)},
		{"RSA key in an EC block", pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: pkcs8})},
		{"P-224 key", keyPEMOf(t, newECKey(t, elliptic.P224()))},
		{"valid block followed by other bytes", append(append([]byte{}, valid...), "more"...)},
		{"bytes before the key block", append([]byte("account key:\n"), valid...)},
		{"damaged block before a valid key block", append(damaged(t, valid), valid...)},
	}
}

// damaged returns block, one PEM block, with a character of its base64 body replaced by one that base64 does not use, which makes pem.Decode step over it.
func damaged(t *testing.T, block []byte) []byte {
	t.Helper()
	body := bytes.IndexByte(block, '\n') + 1
	if body == 0 || body+10 >= len(block) {
		t.Fatalf("not a PEM block:\n%s", block)
	}
	result := bytes.Clone(block)
	result[body+10] = '!'
	if b, _ := pem.Decode(result); b != nil {
		t.Fatalf("the damaged block still decodes:\n%s", result)
	}
	return result
}

// rewrapBase64 rewrites the base64 lines of every block in data to lines of width characters.
func rewrapBase64(t *testing.T, data []byte, width int) []byte {
	t.Helper()
	var out bytes.Buffer
	for rest := data; ; {
		block, next := pem.Decode(rest)
		if block == nil {
			break
		}
		encoded := base64.StdEncoding.EncodeToString(block.Bytes)
		fmt.Fprintf(&out, "-----BEGIN %s-----\n", block.Type)
		for len(encoded) > width {
			out.WriteString(encoded[:width] + "\n")
			encoded = encoded[width:]
		}
		fmt.Fprintf(&out, "%s\n-----END %s-----\n", encoded, block.Type)
		rest = next
	}
	return out.Bytes()
}

func TestAcceptedCertificateRoundTrips(t *testing.T) {
	names := []string{"example.com"}
	for _, tc := range []struct {
		name   string
		change func([]byte) []byte
	}{
		{"key without final newline", func(b []byte) []byte { return bytes.TrimRight(b, "\n") }},
		{"key with CRLF line endings", func(b []byte) []byte { return bytes.ReplaceAll(b, []byte("\n"), []byte("\r\n")) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := testStore(t)
			keyPEM, chainPEM := testChain(t, names, newECKey(t, elliptic.P256()))
			saved, err := newCertificate(tc.change(keyPEM), chainPEM, names)
			if err != nil {
				t.Fatalf("newCertificate: %v", err)
			}
			if err := s.saveCertificate("site", saved); err != nil {
				t.Fatalf("saving: %v", err)
			}
			loaded, err := s.loadCertificate("site", names)
			if err != nil {
				t.Fatalf("an accepted certificate does not load once saved: %v", err)
			}
			if !bytes.Equal(loaded.KeyPEM, saved.KeyPEM) || !bytes.Equal(loaded.ChainPEM, saved.ChainPEM) {
				t.Error("the loaded PEM differs from the saved one")
			}
			if !bytes.Equal(loaded.TLS.Leaf.Raw, saved.TLS.Leaf.Raw) {
				t.Error("the loaded leaf differs from the saved one")
			}
		})
	}
}

func TestKeyPEMIsCanonical(t *testing.T) {
	names := []string{"example.com"}
	keyPEM, chainPEM := testChain(t, names, newECKey(t, elliptic.P256()))
	rewrapped := rewrapBase64(t, keyPEM, 76)
	if bytes.Equal(rewrapped, keyPEM) {
		t.Fatal("rewrapping left the key as it was")
	}
	certificate, err := newCertificate(rewrapped, chainPEM, names)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(certificate.KeyPEM, keyPEM) {
		t.Errorf("KeyPEM =\n%s\nwant the canonical encoding\n%s", certificate.KeyPEM, keyPEM)
	}
	if !bytes.Equal(certificate.ChainPEM, chainPEM) {
		t.Error("ChainPEM is not the chain as given")
	}
}

func TestTolerantPEMLayout(t *testing.T) {
	names := []string{"example.com"}
	keyPEM, chainPEM := testChain(t, names, newECKey(t, elliptic.P256()))
	certificateFile := append(append([]byte{}, keyPEM...), chainPEM...)
	accountKey := keyPEMOf(t, newECKey(t, elliptic.P256()))
	want, err := newCertificate(keyPEM, chainPEM, names)
	if err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		name   string
		change func([]byte) []byte
	}{
		{"CRLF line endings", func(b []byte) []byte { return bytes.ReplaceAll(b, []byte("\n"), []byte("\r\n")) }},
		{"blank line between blocks", func(b []byte) []byte {
			return bytes.ReplaceAll(b, []byte("-----\n-----BEGIN"), []byte("-----\n\n-----BEGIN"))
		}},
		{"no final newline", func(b []byte) []byte { return bytes.TrimRight(b, "\n") }},
		{"base64 lines of 76 characters", func(b []byte) []byte { return rewrapBase64(t, b, 76) }},
		{"white space before and after", func(b []byte) []byte { return append(append([]byte("\n\t \n"), b...), "\n\n"...) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := testStore(t)
			content := tc.change(certificateFile)
			if bytes.Equal(content, certificateFile) {
				t.Fatal("the change left the certificate file as it was")
			}
			writeTestFile(t, s.certificatePath("site"), content)
			loaded, err := s.loadCertificate("site", names)
			if err != nil {
				t.Fatalf("loading the certificate file: %v", err)
			}
			if !bytes.Equal(loaded.TLS.Leaf.Raw, want.TLS.Leaf.Raw) || len(loaded.TLS.Certificate) != len(want.TLS.Certificate) {
				t.Error("the certificate file does not give the same chain")
			}

			writeTestFile(t, s.accountKeyPath(), tc.change(accountKey))
			if _, err := s.loadAccountKey(); err != nil {
				t.Errorf("loading the account key: %v", err)
			}
		})
	}
}

func TestUnusableAccountKeys(t *testing.T) {
	for _, tc := range unusableAccountKeys(t) {
		t.Run(tc.name, func(t *testing.T) {
			s := testStore(t)
			writeTestFile(t, s.accountKeyPath(), tc.content)
			_, err := s.loadAccountKey()
			if !errors.Is(err, errUnusableAccountKey) {
				t.Errorf("err = %v, want errUnusableAccountKey", err)
			}
		})
	}
}

func TestWriteFailureKeepsExistingFile(t *testing.T) {
	skipWithoutPermissions(t)
	s := testStore(t)
	names := []string{"example.com"}
	first := testCertificate(t, names)
	if err := s.saveCertificate("site", first); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(s.domainDir, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(s.domainDir, 0o700) })

	if err := s.saveCertificate("site", testCertificate(t, names)); err == nil {
		t.Fatal("writing into a directory without write permission succeeded")
	}
	loaded, err := s.loadCertificate("site", names)
	if err != nil {
		t.Fatalf("loading after the failed write: %v", err)
	}
	if !bytes.Equal(loaded.KeyPEM, first.KeyPEM) || !bytes.Equal(loaded.ChainPEM, first.ChainPEM) {
		t.Error("the failed write changed the existing file")
	}
}

func TestAuthorityDirName(t *testing.T) {
	for _, tc := range []struct{ url, want string }{
		{LetsEncryptProduction, "acme-v02.api.letsencrypt.org_directory"},
		{LetsEncryptStaging, "acme-staging-v02.api.letsencrypt.org_directory"},
		{"https://127.0.0.1:43017/dir", "127.0.0.1_43017_dir"},
		{"https://CA.Example/Dir~x", "ca.example_dir_x"},
	} {
		got, err := authorityDirName(tc.url)
		if err != nil || got != tc.want {
			t.Errorf("authorityDirName(%q) = %q, %v; want %q", tc.url, got, err, tc.want)
		}
	}
	for _, url := range []string{"", "http://ca.example/dir", "https:///dir", "/dir", "ca.example/dir", "https://..", "https:opaque"} {
		if got, err := authorityDirName(url); err == nil {
			t.Errorf("authorityDirName(%q) = %q, want an error", url, got)
		}
	}
}
