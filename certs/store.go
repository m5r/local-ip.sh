package certs

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
)

// errUnusableAccountKey marks an account key file that exists and was read but holds no usable key; the error wrapping it gives the reason.
var errUnusableAccountKey = errors.New("unusable ACME account key")

// store keeps the account key and the two certificates in files under the state directory:
//
//	<StateDir>/<authority>/account.pem
//	<StateDir>/<authority>/<domain>/site.pem
//	<StateDir>/<authority>/<domain>/wildcard.pem
//
// After a crash a file holds either its previous or its new content, never a mix, and a key is never next to another certificate's chain. A certificate written just before a power failure can be lost with the directories created for it; it is then ordered again. Files are 0600 and the directories the store creates are 0700; the mode of a directory that already existed is left alone.
//
// Every file must be nothing but complete, well-formed PEM blocks with white space before, between and after them; anything else makes it unusable. Line endings, blank lines between blocks, a missing final newline and the length of base64 lines do not matter.
//
// A store holds nothing but paths, so two stores built from the same configuration are interchangeable. It expects a single writer.
type store struct {
	authorityDir string
	domainDir    string
}

// newStore returns the store for cfg, which must have gone through checkConfig. It touches no file.
func newStore(cfg Config) (*store, error) {
	authority, err := authorityDirName(cfg.DirectoryURL)
	if err != nil {
		return nil, fmt.Errorf("building the store: %w", err)
	}
	authorityDir := filepath.Join(cfg.StateDir, authority)
	return &store{authorityDir: authorityDir, domainDir: filepath.Join(authorityDir, cfg.Domain)}, nil
}

func (s *store) accountKeyPath() string {
	return filepath.Join(s.authorityDir, "account.pem")
}

// certificatePath is the file of the certificate called id ("site" or "wildcard"), for log lines.
func (s *store) certificatePath(id string) string {
	return filepath.Join(s.domainDir, id+".pem")
}

// loadAccountKey returns the account's private key. An absent file gives an error that satisfies errors.Is(err, fs.ErrNotExist); content that is not a single EC PRIVATE KEY block with a P-256 key gives an error that satisfies errors.Is(err, errUnusableAccountKey); any other read error is returned wrapped, and means nothing about the content.
func (s *store) loadAccountKey() (*ecdsa.PrivateKey, error) {
	data, err := os.ReadFile(s.accountKeyPath())
	if err != nil {
		return nil, fmt.Errorf("reading the account key: %w", err)
	}
	blocks, err := decodePEM(data)
	switch {
	case err != nil:
		return nil, fmt.Errorf("%w in %s: %w", errUnusableAccountKey, s.accountKeyPath(), err)
	case len(blocks) == 0:
		return nil, fmt.Errorf("%w in %s: no PEM block", errUnusableAccountKey, s.accountKeyPath())
	case len(blocks) > 1:
		return nil, fmt.Errorf("%w in %s: %d blocks instead of one", errUnusableAccountKey, s.accountKeyPath(), len(blocks))
	case blocks[0].Type != "EC PRIVATE KEY":
		return nil, fmt.Errorf("%w in %s: block of type %q", errUnusableAccountKey, s.accountKeyPath(), blocks[0].Type)
	}
	key, err := x509.ParseECPrivateKey(blocks[0].Bytes)
	if err != nil {
		return nil, fmt.Errorf("%w in %s: %w", errUnusableAccountKey, s.accountKeyPath(), err)
	}
	if key.Curve != elliptic.P256() {
		return nil, fmt.Errorf("%w in %s: curve %s instead of P-256", errUnusableAccountKey, s.accountKeyPath(), key.Curve.Params().Name)
	}
	return key, nil
}

// saveAccountKey replaces the account key file with key, atomically.
func (s *store) saveAccountKey(key *ecdsa.PrivateKey) error {
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return fmt.Errorf("encoding the account key: %w", err)
	}
	return writeFile(s.accountKeyPath(), pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}))
}

// loadCertificate reads the certificate called id ("site" or "wildcard") and checks it with newCertificate against names: the first block is the key and the bytes after it are the chain. An absent file gives an error that satisfies errors.Is(err, fs.ErrNotExist); every other error means the file cannot be used. An expired certificate loads normally.
func (s *store) loadCertificate(id string, names []string) (*Certificate, error) {
	path := s.certificatePath(id)
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading certificate %s: %w", id, err)
	}
	block, chainPEM, err := nextPEMBlock(data)
	if err != nil {
		return nil, fmt.Errorf("loading %s: %w", path, err)
	}
	if block == nil {
		return nil, fmt.Errorf("loading %s: no PEM block", path)
	}
	certificate, err := newCertificate(data[:len(data)-len(chainPEM)], chainPEM, names)
	if err != nil {
		return nil, fmt.Errorf("loading %s: %w", path, err)
	}
	return certificate, nil
}

// saveCertificate replaces the file of the certificate called id ("site" or "wildcard") with c.KeyPEM followed by c.ChainPEM, atomically.
func (s *store) saveCertificate(id string, c *Certificate) error {
	data := make([]byte, 0, len(c.KeyPEM)+len(c.ChainPEM))
	data = append(data, c.KeyPEM...)
	data = append(data, c.ChainPEM...)
	return writeFile(s.certificatePath(id), data)
}

// newCertificate builds a Certificate from one PEM private key block and the chain, and returns an error unless the result can be served for names: keyPEM is exactly one private key block, chainPEM is one or more CERTIFICATE blocks that all parse (a damaged intermediate would be served to every client), both are nothing but complete, well-formed PEM blocks with white space before, between and after them (RFC 8555, section 9.1, allows no explanatory text in a chain), crypto/tls accepts the pair, and the leaf's DNS names are exactly names. Validity dates are not checked. In the returned value KeyPEM is the key block in its canonical encoding, one complete block that ends with a newline whatever layout keyPEM had, so that saveCertificate always writes a file that loads; ChainPEM is chainPEM as given, since it is what the authority delivered and what is published; TLS holds the same key bytes, and TLS.Leaf is set.
func newCertificate(keyPEM, chainPEM []byte, names []string) (*Certificate, error) {
	keyBlocks, err := decodePEM(keyPEM)
	if err != nil {
		return nil, fmt.Errorf("checking the certificate key: %w", err)
	}
	if len(keyBlocks) != 1 || (keyBlocks[0].Type != "PRIVATE KEY" && !strings.HasSuffix(keyBlocks[0].Type, " PRIVATE KEY")) {
		return nil, errors.New("checking the certificate: the first block is not a private key")
	}
	blocks, err := decodePEM(chainPEM)
	if err != nil {
		return nil, fmt.Errorf("checking the certificate chain: %w", err)
	}
	var chain []*x509.Certificate
	for _, block := range blocks {
		if block.Type != "CERTIFICATE" {
			return nil, fmt.Errorf("checking the certificate: block %d of the chain has type %q", len(chain)+1, block.Type)
		}
		parsed, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("checking the certificate: parsing block %d of the chain: %w", len(chain)+1, err)
		}
		chain = append(chain, parsed)
	}
	if len(chain) == 0 {
		return nil, errors.New("checking the certificate: no certificate block")
	}
	canonicalKey := pem.EncodeToMemory(keyBlocks[0])
	pair, err := tls.X509KeyPair(chainPEM, canonicalKey)
	if err != nil {
		return nil, fmt.Errorf("checking the certificate: %w", err)
	}
	pair.Leaf = chain[0]
	if !slices.Equal(chain[0].DNSNames, names) {
		return nil, fmt.Errorf("checking the certificate: names %q, want %q", chain[0].DNSNames, names)
	}
	return &Certificate{TLS: pair, ChainPEM: chainPEM, KeyPEM: canonicalKey}, nil
}

// decodePEM returns the blocks of data, and an error unless data is nothing but complete, well-formed PEM blocks with white space before, between and after them.
func decodePEM(data []byte) ([]*pem.Block, error) {
	var blocks []*pem.Block
	for {
		block, rest, err := nextPEMBlock(data)
		if err != nil {
			return nil, fmt.Errorf("after %d good blocks: %w", len(blocks), err)
		}
		if block == nil {
			return blocks, nil
		}
		blocks = append(blocks, block)
		data = rest
	}
}

// nextPEMBlock returns the first block of data and the bytes after it, or a nil block and no error when data holds nothing but white space. It fails when anything but white space comes before the block or the block is damaged. pem.Decode alone does not tell: it steps over text and blocks it cannot read and returns the next block it can, so the bytes it consumed are compared with the block encoded again, ignoring white space, which leaves line endings and the length of base64 lines free and nothing else.
func nextPEMBlock(data []byte) (*pem.Block, []byte, error) {
	if len(bytes.TrimSpace(data)) == 0 {
		return nil, nil, nil
	}
	block, rest := pem.Decode(data)
	if block == nil {
		return nil, nil, errors.New("bytes that are not a complete PEM block")
	}
	consumed := data[:len(data)-len(rest)]
	if !bytes.Equal(withoutSpace(consumed), withoutSpace(pem.EncodeToMemory(block))) {
		return nil, nil, fmt.Errorf("a damaged block or other bytes before the %s block", block.Type)
	}
	return block, rest, nil
}

func withoutSpace(b []byte) []byte {
	return bytes.Join(bytes.Fields(b), nil)
}

// writeFile replaces path with data through a temporary file and a rename, so that a reader never sees a mix of the two contents.
func writeFile(path string, data []byte) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("creating directory %s: %w", dir, err)
	}
	// The single writer makes a fixed temporary name safe, and a leftover from a crash is simply truncated.
	temporary := path + ".tmp"
	file, err := os.OpenFile(temporary, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return fmt.Errorf("creating %s: %w", temporary, err)
	}
	fail := func(step string, err error) error {
		_ = file.Close()
		_ = os.Remove(temporary)
		return fmt.Errorf("%s %s: %w", step, temporary, err)
	}
	// A leftover temporary file keeps its mode through O_CREATE.
	if err := file.Chmod(0o600); err != nil {
		return fail("setting the mode of", err)
	}
	if _, err := file.Write(data); err != nil {
		return fail("writing", err)
	}
	if err := file.Sync(); err != nil {
		return fail("syncing", err)
	}
	if err := file.Close(); err != nil {
		_ = os.Remove(temporary)
		return fmt.Errorf("closing %s: %w", temporary, err)
	}
	if err := os.Rename(temporary, path); err != nil {
		_ = os.Remove(temporary)
		return fmt.Errorf("renaming %s to %s: %w", temporary, path, err)
	}
	return syncDir(dir)
}

// syncDir makes a rename in dir durable.
func syncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return fmt.Errorf("opening directory %s to sync it: %w", dir, err)
	}
	if err := d.Sync(); err != nil {
		_ = d.Close()
		return fmt.Errorf("syncing directory %s: %w", dir, err)
	}
	if err := d.Close(); err != nil {
		return fmt.Errorf("closing directory %s: %w", dir, err)
	}
	return nil
}
