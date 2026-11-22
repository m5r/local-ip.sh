package e2e

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"slices"
	"strings"
	"testing"
	"time"
)

// keyPair is the published wildcard certificate chain (leaf first) and its private key. It only
// ever lives in memory.
type keyPair struct {
	chain  []*x509.Certificate
	signer crypto.Signer
}

func (p keyPair) leaf() *x509.Certificate {
	return p.chain[0]
}

func (p keyPair) intermediates() *x509.CertPool {
	pool := x509.NewCertPool()
	for _, cert := range p.chain[1:] {
		pool.AddCert(cert)
	}
	return pool
}

func (p keyPair) tlsCertificate() tls.Certificate {
	cert := tls.Certificate{PrivateKey: p.signer, Leaf: p.leaf()}
	for _, c := range p.chain {
		cert.Certificate = append(cert.Certificate, c.Raw)
	}
	return cert
}

func (p keyPair) matches() (bool, error) {
	public, ok := p.signer.Public().(interface{ Equal(crypto.PublicKey) bool })
	if !ok {
		return false, fmt.Errorf("public key of type %T cannot be compared", p.signer.Public())
	}
	return public.Equal(p.leaf().PublicKey), nil
}

// pemBlocks is not a general PEM reader: it is deliberately stricter than the PEM grammar, to match
// what the server writes. Only whitespace may surround the blocks, and no block may carry headers
// (the server never writes them; legacy encrypted keys do). A block that does not decode is an
// error rather than skipped: pem.Decode silently skips such a block and returns the next valid one,
// so each decoded block must have consumed exactly one BEGIN line. Errors never include the data,
// which may be a private key.
func pemBlocks(data []byte) ([]*pem.Block, error) {
	begin := []byte("-----BEGIN ")
	var blocks []*pem.Block
	rest := bytes.TrimLeft(data, asciiWhitespace)
	for len(rest) > 0 {
		n := len(blocks) + 1
		if !bytes.HasPrefix(rest, begin) {
			if len(blocks) == 0 {
				return nil, errors.New("unexpected data before the first PEM block")
			}
			return nil, fmt.Errorf("unexpected data after PEM block %d", len(blocks))
		}
		if !bytes.Contains(rest, []byte("-----END ")) {
			return nil, fmt.Errorf("PEM block %d has no END line", n)
		}
		block, next := pem.Decode(rest)
		if block == nil || bytes.Count(rest[:len(rest)-len(next)], begin) != 1 {
			return nil, fmt.Errorf("PEM block %d does not decode", n)
		}
		if len(block.Headers) != 0 {
			return nil, fmt.Errorf("PEM block %d has headers", n)
		}
		blocks = append(blocks, block)
		rest = bytes.TrimLeft(next, asciiWhitespace)
	}
	if len(blocks) == 0 {
		return nil, errors.New("no PEM block found")
	}
	return blocks, nil
}

func parseChain(data []byte) ([]*x509.Certificate, error) {
	blocks, err := pemBlocks(data)
	if err != nil {
		return nil, err
	}
	chain := make([]*x509.Certificate, 0, len(blocks))
	for i, block := range blocks {
		if block.Type != "CERTIFICATE" {
			return nil, fmt.Errorf("PEM block %d has type %q, want CERTIFICATE", i+1, block.Type)
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parsing certificate %d: %w", i+1, err)
		}
		chain = append(chain, cert)
	}
	return chain, nil
}

func parsePrivateKey(data []byte) (crypto.Signer, error) {
	blocks, err := pemBlocks(data)
	if err != nil {
		return nil, err
	}
	if len(blocks) != 1 {
		return nil, fmt.Errorf("found %d PEM blocks, want exactly 1", len(blocks))
	}

	var key any
	switch blockType := blocks[0].Type; blockType {
	case "PRIVATE KEY":
		key, err = x509.ParsePKCS8PrivateKey(blocks[0].Bytes)
	case "RSA PRIVATE KEY":
		key, err = x509.ParsePKCS1PrivateKey(blocks[0].Bytes)
	case "EC PRIVATE KEY":
		key, err = x509.ParseECPrivateKey(blocks[0].Bytes)
	default:
		return nil, fmt.Errorf("unsupported PEM block type %q", blockType)
	}
	if err != nil {
		return nil, fmt.Errorf("parsing %s block: %w", blocks[0].Type, err)
	}
	signer, ok := key.(crypto.Signer)
	if !ok {
		return nil, fmt.Errorf("private key of type %T is not a crypto.Signer", key)
	}
	return signer, nil
}

// matchingKeyPair tolerates one renewal racing the download: each file is served from one consistent pair, but the certificate and the key are two requests, and a renewal between them hands out halves of two pairs. Well-formed files whose keys differ are therefore downloaded once more, and only a second mismatch fails. A download error (such as malformed content) is final and never retried.
func matchingKeyPair(download func() (keyPair, error)) (keyPair, error) {
	for attempt := 1; ; attempt++ {
		pair, err := download()
		if err != nil {
			return keyPair{}, err
		}
		matches, err := pair.matches()
		if err != nil {
			return keyPair{}, fmt.Errorf("comparing published key with published certificate: %w", err)
		}
		if matches {
			return pair, nil
		}
		if attempt == 2 {
			return keyPair{}, errors.New("published key still does not match the published certificate after downloading both again")
		}
	}
}

const testLeafName = "*.example.test"

type testPKI struct {
	root         *x509.Certificate
	intermediate *x509.Certificate
	leaf         *x509.Certificate
	leafKey      *ecdsa.PrivateKey
}

func newECDSAKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating ECDSA key: %v", err)
	}
	return key
}

func newRSAKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generating RSA key: %v", err)
	}
	return key
}

func issueCertificate(t *testing.T, template, parent *x509.Certificate, public crypto.PublicKey, parentKey crypto.Signer) *x509.Certificate {
	t.Helper()
	der, err := x509.CreateCertificate(rand.Reader, template, parent, public, parentKey)
	if err != nil {
		t.Fatalf("creating certificate %q: %v", template.Subject.CommonName, err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parsing certificate %q: %v", template.Subject.CommonName, err)
	}
	return cert
}

func caTemplate(serial int64, name string) *x509.Certificate {
	return &x509.Certificate{
		SerialNumber:          big.NewInt(serial),
		Subject:               pkix.Name{CommonName: name},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
}

func newTestPKI(t *testing.T) testPKI {
	t.Helper()
	rootKey := newECDSAKey(t)
	rootTemplate := caTemplate(1, "e2e test root")
	root := issueCertificate(t, rootTemplate, rootTemplate, rootKey.Public(), rootKey)

	intermediateKey := newECDSAKey(t)
	intermediate := issueCertificate(t, caTemplate(2, "e2e test intermediate"), root, intermediateKey.Public(), rootKey)

	leafKey := newECDSAKey(t)
	leaf := issueCertificate(t, &x509.Certificate{
		SerialNumber: big.NewInt(3),
		Subject:      pkix.Name{CommonName: testLeafName},
		DNSNames:     []string{testLeafName},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}, intermediate, leafKey.Public(), intermediateKey)

	return testPKI{root: root, intermediate: intermediate, leaf: leaf, leafKey: leafKey}
}

func pemEncode(blockType string, der []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: blockType, Bytes: der})
}

func concat(parts ...[]byte) []byte {
	return bytes.Join(parts, nil)
}

func certPool(certs ...*x509.Certificate) *x509.CertPool {
	pool := x509.NewCertPool()
	for _, cert := range certs {
		pool.AddCert(cert)
	}
	return pool
}

func expectErrorContains(t *testing.T, err error, want string) {
	t.Helper()
	if err == nil {
		t.Fatalf("got no error, want one containing %q", want)
	}
	if !strings.Contains(err.Error(), want) {
		t.Fatalf("error %q does not contain %q", err, want)
	}
}

// expectNoKeyMaterial fails if err quotes any base64 line of input or the base64 of any DER
// value, so a rejected key can never be echoed into a test log.
func expectNoKeyMaterial(t *testing.T, err error, input []byte, ders ...[]byte) {
	t.Helper()
	text := err.Error()
	for line := range strings.Lines(string(input)) {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "-----") {
			continue
		}
		if strings.Contains(text, line) {
			t.Errorf("error %q quotes the PEM body", text)
		}
	}
	for _, der := range ders {
		if strings.Contains(text, base64.StdEncoding.EncodeToString(der)) {
			t.Errorf("error %q quotes the DER as base64", text)
		}
	}
}

func TestPEMBlocks(t *testing.T) {
	pki := newTestPKI(t)
	leafPEM := pemEncode("CERTIFICATE", pki.leaf.Raw)
	intermediatePEM := pemEncode("CERTIFICATE", pki.intermediate.Raw)
	corruptPEM := []byte("-----BEGIN CERTIFICATE-----\n!!!! not base64 !!!!\n-----END CERTIFICATE-----\n")

	accepted := []struct {
		name  string
		input []byte
		want  [][]byte
	}{
		{name: "one block", input: leafPEM, want: [][]byte{pki.leaf.Raw}},
		{name: "several blocks", input: concat(leafPEM, intermediatePEM), want: [][]byte{pki.leaf.Raw, pki.intermediate.Raw}},
		{name: "surrounding and in-between whitespace", input: concat([]byte(" \t\r\n\n"), leafPEM, []byte("\r\n \t\n"), intermediatePEM, []byte("\t \r\n")), want: [][]byte{pki.leaf.Raw, pki.intermediate.Raw}},
		{name: "CRLF line endings", input: bytes.ReplaceAll(concat(leafPEM, intermediatePEM), []byte("\n"), []byte("\r\n")), want: [][]byte{pki.leaf.Raw, pki.intermediate.Raw}},
	}
	for _, tt := range accepted {
		t.Run("accepts "+tt.name, func(t *testing.T) {
			blocks, err := pemBlocks(tt.input)
			if err != nil {
				t.Fatal(err)
			}
			if len(blocks) != len(tt.want) {
				t.Fatalf("got %d blocks, want %d", len(blocks), len(tt.want))
			}
			for i, block := range blocks {
				if block.Type != "CERTIFICATE" || !bytes.Equal(block.Bytes, tt.want[i]) {
					t.Errorf("block %d is a %q block with other content than expected", i+1, block.Type)
				}
			}
		})
	}

	rejected := []struct {
		name    string
		input   []byte
		wantErr string
	}{
		{name: "empty input", input: nil, wantErr: "no PEM block found"},
		{name: "whitespace only", input: []byte(" \t\r\n "), wantErr: "no PEM block found"},
		{name: "text before the first block", input: concat([]byte("hello\n"), leafPEM), wantErr: "unexpected data before the first PEM block"},
		{name: "text between two blocks", input: concat(leafPEM, []byte("junk\n"), intermediatePEM), wantErr: "unexpected data after PEM block 1"},
		{name: "text after the last block", input: concat(leafPEM, intermediatePEM, []byte("trailing")), wantErr: "unexpected data after PEM block 2"},
		{name: "block cut off in the middle", input: leafPEM[:len(leafPEM)/2], wantErr: "PEM block 1 has no END line"},
		{name: "second block cut off in the middle", input: concat(leafPEM, intermediatePEM[:len(intermediatePEM)/2]), wantErr: "PEM block 2 has no END line"},
		{name: "corrupt base64 body", input: corruptPEM, wantErr: "PEM block 1 does not decode"},
		{name: "corrupt base64 body followed by a valid block", input: concat(corruptPEM, leafPEM), wantErr: "PEM block 1 does not decode"},
		{name: "block with a header", input: concat(leafPEM, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Headers: map[string]string{"Comment": "e2e"}, Bytes: pki.intermediate.Raw})), wantErr: "PEM block 2 has headers"},
	}
	for _, tt := range rejected {
		t.Run("rejects "+tt.name, func(t *testing.T) {
			blocks, err := pemBlocks(tt.input)
			if err == nil {
				t.Fatalf("got %d blocks, want an error", len(blocks))
			}
			expectErrorContains(t, err, tt.wantErr)
		})
	}
}

func TestParseChain(t *testing.T) {
	pki := newTestPKI(t)
	leafPEM := pemEncode("CERTIFICATE", pki.leaf.Raw)
	intermediatePEM := pemEncode("CERTIFICATE", pki.intermediate.Raw)
	keyDER, err := x509.MarshalPKCS8PrivateKey(pki.leafKey)
	if err != nil {
		t.Fatal(err)
	}

	accepted := []struct {
		name  string
		input []byte
		want  []*x509.Certificate
	}{
		{name: "leaf alone", input: leafPEM, want: []*x509.Certificate{pki.leaf}},
		{name: "leaf then issuer in file order", input: concat(leafPEM, intermediatePEM), want: []*x509.Certificate{pki.leaf, pki.intermediate}},
	}
	for _, tt := range accepted {
		t.Run("accepts "+tt.name, func(t *testing.T) {
			chain, err := parseChain(tt.input)
			if err != nil {
				t.Fatal(err)
			}
			if !slices.EqualFunc(chain, tt.want, (*x509.Certificate).Equal) {
				t.Errorf("got a chain of %d certificates that differs from the expected %d", len(chain), len(tt.want))
			}
		})
	}

	rejected := []struct {
		name    string
		input   []byte
		wantErr string
	}{
		{name: "private key block among certificates", input: concat(leafPEM, pemEncode("PRIVATE KEY", keyDER)), wantErr: `PEM block 2 has type "PRIVATE KEY", want CERTIFICATE`},
		{name: "certificate block whose DER is not a certificate", input: concat(leafPEM, pemEncode("CERTIFICATE", []byte("not a certificate"))), wantErr: "parsing certificate 2"},
	}
	for _, tt := range rejected {
		t.Run("rejects "+tt.name, func(t *testing.T) {
			chain, err := parseChain(tt.input)
			if err == nil {
				t.Fatalf("got a chain of %d certificates, want an error", len(chain))
			}
			expectErrorContains(t, err, tt.wantErr)
		})
	}
}

func TestParsePrivateKey(t *testing.T) {
	ecKey := newECDSAKey(t)
	rsaKey := newRSAKey(t)
	edPublic, edKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	x25519Key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	pkcs8 := func(key any) []byte {
		t.Helper()
		der, err := x509.MarshalPKCS8PrivateKey(key)
		if err != nil {
			t.Fatalf("marshalling %T as PKCS #8: %v", key, err)
		}
		return der
	}
	sec1, err := x509.MarshalECPrivateKey(ecKey)
	if err != nil {
		t.Fatal(err)
	}
	ecPKCS8 := pkcs8(ecKey)

	accepted := []struct {
		name       string
		input      []byte
		wantPublic crypto.PublicKey
	}{
		{name: "PKCS #8 ECDSA P-256", input: pemEncode("PRIVATE KEY", ecPKCS8), wantPublic: ecKey.Public()},
		{name: "PKCS #8 RSA", input: pemEncode("PRIVATE KEY", pkcs8(rsaKey)), wantPublic: rsaKey.Public()},
		{name: "PKCS #8 Ed25519", input: pemEncode("PRIVATE KEY", pkcs8(edKey)), wantPublic: edPublic},
		{name: "PKCS #1 RSA", input: pemEncode("RSA PRIVATE KEY", x509.MarshalPKCS1PrivateKey(rsaKey)), wantPublic: rsaKey.Public()},
		{name: "SEC 1 ECDSA", input: pemEncode("EC PRIVATE KEY", sec1), wantPublic: ecKey.Public()},
	}
	for _, tt := range accepted {
		t.Run("accepts "+tt.name, func(t *testing.T) {
			signer, err := parsePrivateKey(tt.input)
			if err != nil {
				t.Fatal(err)
			}
			public, ok := signer.Public().(interface{ Equal(crypto.PublicKey) bool })
			if !ok || !public.Equal(tt.wantPublic) {
				t.Errorf("parsed %T whose public key differs from the generated one", signer)
			}
		})
	}

	truncatedSEC1 := sec1[:len(sec1)/2]
	x25519PKCS8 := pkcs8(x25519Key)
	rejected := []struct {
		name    string
		input   []byte
		der     [][]byte
		wantErr string
	}{
		{name: "two key blocks", input: concat(pemEncode("PRIVATE KEY", ecPKCS8), pemEncode("PRIVATE KEY", ecPKCS8)), der: [][]byte{ecPKCS8}, wantErr: "found 2 PEM blocks, want exactly 1"},
		{name: "certificate block", input: pemEncode("CERTIFICATE", ecPKCS8), der: [][]byte{ecPKCS8}, wantErr: `unsupported PEM block type "CERTIFICATE"`},
		{name: "unknown block type", input: pemEncode("OPENSSH PRIVATE KEY", ecPKCS8), der: [][]byte{ecPKCS8}, wantErr: `unsupported PEM block type "OPENSSH PRIVATE KEY"`},
		{name: "known block type with corrupt DER", input: pemEncode("EC PRIVATE KEY", truncatedSEC1), der: [][]byte{truncatedSEC1, sec1}, wantErr: "parsing EC PRIVATE KEY block"},
		{name: "PKCS #8 X25519 key that cannot sign", input: pemEncode("PRIVATE KEY", x25519PKCS8), der: [][]byte{x25519PKCS8}, wantErr: "private key of type *ecdh.PrivateKey is not a crypto.Signer"},
	}
	for _, tt := range rejected {
		t.Run("rejects "+tt.name, func(t *testing.T) {
			signer, err := parsePrivateKey(tt.input)
			if err == nil {
				t.Fatalf("parsed a %T, want an error", signer)
			}
			expectErrorContains(t, err, tt.wantErr)
			expectNoKeyMaterial(t, err, tt.input, tt.der...)
		})
	}
}

func TestKeyPairMatches(t *testing.T) {
	pki := newTestPKI(t)

	tests := []struct {
		name string
		key  crypto.Signer
		want bool
	}{
		{name: "certificate and its own key", key: pki.leafKey, want: true},
		{name: "different key of the same type", key: newECDSAKey(t), want: false},
		{name: "RSA key against an ECDSA certificate", key: newRSAKey(t), want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := keyPair{chain: []*x509.Certificate{pki.leaf}, signer: tt.key}.matches()
			if err != nil {
				t.Fatal(err)
			}
			if got != tt.want {
				t.Errorf("matches() = %t, want %t", got, tt.want)
			}
		})
	}
}

func TestKeyPairIntermediates(t *testing.T) {
	pki := newTestPKI(t)

	tests := []struct {
		name  string
		chain []*x509.Certificate
		want  *x509.CertPool
	}{
		{name: "leaf alone", chain: []*x509.Certificate{pki.leaf}, want: certPool()},
		{name: "leaf and intermediate", chain: []*x509.Certificate{pki.leaf, pki.intermediate}, want: certPool(pki.intermediate)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pair := keyPair{chain: tt.chain, signer: pki.leafKey}
			if !pair.intermediates().Equal(tt.want) {
				t.Error("intermediates() does not contain exactly the non-leaf certificates")
			}
		})
	}
}

func TestKeyPairTLSCertificate(t *testing.T) {
	pki := newTestPKI(t)
	pair := keyPair{chain: []*x509.Certificate{pki.leaf, pki.intermediate}, signer: pki.leafKey}

	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()

	serverConn, clientConn := net.Pipe()
	server := tls.Server(serverConn, &tls.Config{Certificates: []tls.Certificate{pair.tlsCertificate()}})
	client := tls.Client(clientConn, &tls.Config{RootCAs: certPool(pki.root), ServerName: "e2e.example.test"})
	// Closing the raw pipe ends rather than the TLS connections avoids a close_notify write that
	// nobody reads, which would block on the unbuffered pipe until tls.Conn's 5 second deadline.
	defer serverConn.Close()
	defer clientConn.Close()

	serverDone := make(chan error, 1)
	go func() { serverDone <- server.HandshakeContext(ctx) }()

	if err := client.HandshakeContext(ctx); err != nil {
		clientConn.Close()
		<-serverDone
		t.Fatalf("client handshake: %v", err)
	}
	if err := <-serverDone; err != nil {
		t.Fatalf("server handshake: %v", err)
	}

	peers := client.ConnectionState().PeerCertificates
	if len(peers) != 2 || !peers[0].Equal(pki.leaf) || !peers[1].Equal(pki.intermediate) {
		t.Errorf("server presented %d certificates, want the leaf and the intermediate", len(peers))
	}
}

func TestMatchingKeyPair(t *testing.T) {
	pki := newTestPKI(t)
	other := newTestPKI(t)
	first := keyPair{chain: []*x509.Certificate{pki.leaf}, signer: pki.leafKey}
	second := keyPair{chain: []*x509.Certificate{other.leaf, other.intermediate}, signer: other.leafKey}
	mismatched := keyPair{chain: []*x509.Certificate{pki.leaf}, signer: other.leafKey}
	malformed := errors.New("server.key: PEM block 1 does not decode")

	type step struct {
		pair keyPair
		err  error
	}
	tests := []struct {
		name          string
		script        []step
		want          keyPair
		wantErr       error
		wantErrText   string
		wantDownloads int
	}{
		{name: "matching pair", script: []step{{pair: first}}, want: first, wantDownloads: 1},
		{name: "mismatched pair then matching pair", script: []step{{pair: mismatched}, {pair: second}}, want: second, wantDownloads: 2},
		{name: "mismatched pair twice", script: []step{{pair: mismatched}, {pair: mismatched}}, wantErrText: "still does not match", wantDownloads: 2},
		{name: "malformed download", script: []step{{err: malformed}}, wantErr: malformed, wantDownloads: 1},
		{name: "mismatched pair then malformed download", script: []step{{pair: mismatched}, {err: malformed}}, wantErr: malformed, wantDownloads: 2},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			downloads := 0
			got, err := matchingKeyPair(func() (keyPair, error) {
				downloads++
				if downloads > len(tt.script) {
					t.Fatalf("download %d was not expected", downloads)
				}
				s := tt.script[downloads-1]
				return s.pair, s.err
			})

			if downloads != tt.wantDownloads {
				t.Errorf("downloaded %d times, want %d", downloads, tt.wantDownloads)
			}
			switch {
			case tt.wantErr != nil:
				if !errors.Is(err, tt.wantErr) {
					t.Errorf("error = %v, want %v", err, tt.wantErr)
				}
			case tt.wantErrText != "":
				expectErrorContains(t, err, tt.wantErrText)
			default:
				if err != nil {
					t.Fatal(err)
				}
				if got.signer != tt.want.signer || !slices.EqualFunc(got.chain, tt.want.chain, (*x509.Certificate).Equal) {
					t.Error("returned a different pair than the expected one")
				}
			}
		})
	}
}
