package heain

// Public statements (heain-core C11 S2): an app publishes a statement for anyone to read and check with no
// client certificate -- only a kind the Policy key public.statements lists for the app, from a capability on
// a listed lane, never lane identity. Core keeps it for ever and commits to it in the node's public Merkle
// tree; the node's public listener (-public-addr) serves the statement, its inclusion proof and the signed
// head. CheckPublicStatement is that check, for an observer with nothing but the deployment CA.

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// Published is what core answers when a statement is published.
type Published struct {
	Seq    uint64 `json:"seq"`
	SHA256 string `json:"sha256"`
	Node   string `json:"node"`
}

// PublishStatement publishes content (any JSON value, at most 64 KB) as a public statement of kind from
// capability. A statement cannot be taken back.
func (a *App) PublishStatement(ctx context.Context, capability, kind string, content any) (Published, error) {
	var out Published
	raw, err := json.Marshal(content)
	if err != nil {
		return out, err
	}
	_, err = a.Core.Do(ctx, http.MethodPost, "/v1/app/public/statements", nil,
		map[string]any{"capability": capability, "kind": kind, "content": json.RawMessage(raw)}, &out)
	return out, err
}

// PublicStatement is a statement as core publishes it.
type PublicStatement struct {
	Seq        uint64          `json:"seq"`
	Node       string          `json:"node"`
	App        string          `json:"app"`
	Instance   string          `json:"instance"`
	Kind       string          `json:"kind"`
	Capability string          `json:"capability"`
	Lane       string          `json:"lane,omitempty"`
	At         time.Time       `json:"at"`
	Content    json.RawMessage `json:"content"`
}

// PublicHead is a signed tree head of a node's public tree.
type PublicHead struct {
	NodeID    string          `json:"node_id"`
	TreeSize  uint64          `json:"tree_size"`
	RootHash  string          `json:"root_hash"`
	Timestamp time.Time       `json:"timestamp"`
	SigAlg    string          `json:"sig_alg"`
	Signature []byte          `json:"signature"`
	CertPEM   string          `json:"cert_pem"`
	ChainPEM  string          `json:"chain_pem,omitempty"`
	Stamp     json.RawMessage `json:"stamp,omitempty"`
}

// PublicInclusion proves a statement is leaf LeafIndex of the tree of TreeSize leaves.
type PublicInclusion struct {
	Seq       uint64   `json:"seq"`
	LeafIndex uint64   `json:"leaf_index"`
	TreeSize  uint64   `json:"tree_size"`
	RootHash  string   `json:"root_hash"`
	Path      []string `json:"path"`
}

// Checked is a statement that verified, with what it verified against.
type Checked struct {
	Statement PublicStatement
	Head      PublicHead
	SHA256    string
	Stamped   bool // the head carries an RFC 3161 stamp (not checked here)
}

func leafHash(seq uint64, h []byte) []byte {
	d := sha256.New()
	d.Write([]byte{0})
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], seq)
	d.Write(b[:])
	d.Write(h)
	return d.Sum(nil)
}

func nodeHash(l, r []byte) []byte {
	d := sha256.New()
	d.Write([]byte{1})
	d.Write(l)
	d.Write(r)
	return d.Sum(nil)
}

// verifyInclusion is RFC 9162 §2.1.3.2.
func verifyInclusion(index, size uint64, leaf []byte, proof [][]byte, root []byte) bool {
	if index >= size {
		return false
	}
	fn, sn := index, size-1
	r := leaf
	for _, p := range proof {
		if sn == 0 {
			return false
		}
		if fn&1 == 1 || fn == sn {
			r = nodeHash(p, r)
			if fn&1 == 0 {
				for fn&1 == 0 && fn != 0 {
					fn >>= 1
					sn >>= 1
				}
			}
		} else {
			r = nodeHash(r, p)
		}
		fn >>= 1
		sn >>= 1
	}
	return sn == 0 && bytes.Equal(r, root)
}

func (h PublicHead) message() []byte {
	return []byte(fmt.Sprintf("heain-sth/v1\nnode=%s\nsize=%d\nroot=%s\ntime=%s\n", h.NodeID, h.TreeSize, h.RootHash, h.Timestamp.UTC().Format(time.RFC3339Nano)))
}

func parsePEMs(s string) []*x509.Certificate {
	var out []*x509.Certificate
	rest := []byte(s)
	for {
		var b *pem.Block
		b, rest = pem.Decode(rest)
		if b == nil {
			return out
		}
		if c, err := x509.ParseCertificate(b.Bytes); err == nil {
			out = append(out, c)
		}
	}
}

// verifyHead checks the head's signature by the node certificate it carries, that the certificate names the
// node and chains to roots.
func verifyHead(h PublicHead, roots *x509.CertPool) error {
	certs := parsePEMs(h.CertPEM)
	if len(certs) == 0 {
		return errors.New("heain-sdk: the head carries no certificate")
	}
	inter := x509.NewCertPool()
	for _, c := range parsePEMs(h.ChainPEM) {
		inter.AddCert(c)
	}
	leaf := certs[0]
	if leaf.Subject.CommonName != h.NodeID {
		return fmt.Errorf("heain-sdk: the head of %s is signed by %s", h.NodeID, leaf.Subject.CommonName)
	}
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: roots, Intermediates: inter, CurrentTime: h.Timestamp, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}}); err != nil {
		return fmt.Errorf("heain-sdk: the node certificate does not chain to the CA: %w", err)
	}
	var alg x509.SignatureAlgorithm
	switch h.SigAlg {
	case "rsa-pkcs1v15-sha256":
		alg = x509.SHA256WithRSA
	case "ecdsa-sha256":
		alg = x509.ECDSAWithSHA256
	case "ed25519":
		alg = x509.PureEd25519
	default:
		return fmt.Errorf("heain-sdk: unknown signature algorithm %q", h.SigAlg)
	}
	if err := leaf.CheckSignature(alg, h.message(), h.Signature); err != nil {
		return fmt.Errorf("heain-sdk: the head's signature does not verify: %w", err)
	}
	return nil
}

// VerifyPublicStatement checks a statement's exact bytes against an inclusion proof and a signed head, and
// the head against the deployment CA (caPEM).
func VerifyPublicStatement(raw []byte, inc PublicInclusion, head PublicHead, caPEM []byte) (Checked, error) {
	var out Checked
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(caPEM) {
		return out, errors.New("heain-sdk: no CA certificate")
	}
	if err := json.Unmarshal(raw, &out.Statement); err != nil {
		return out, fmt.Errorf("heain-sdk: the statement does not parse: %w", err)
	}
	if out.Statement.Seq != inc.Seq || out.Statement.Node != head.NodeID {
		return out, errors.New("heain-sdk: the statement, the proof and the head do not belong together")
	}
	if inc.TreeSize != head.TreeSize || inc.RootHash != head.RootHash {
		return out, errors.New("heain-sdk: the proof is for another head")
	}
	sum := sha256.Sum256(raw)
	var path [][]byte
	for _, p := range inc.Path {
		b, err := hex.DecodeString(p)
		if err != nil {
			return out, errors.New("heain-sdk: bad proof")
		}
		path = append(path, b)
	}
	root, err := hex.DecodeString(head.RootHash)
	if err != nil || !verifyInclusion(inc.LeafIndex, inc.TreeSize, leafHash(inc.Seq, sum[:]), path, root) {
		return out, errors.New("heain-sdk: the statement is not in the signed tree")
	}
	if err := verifyHead(head, roots); err != nil {
		return out, err
	}
	out.Head, out.SHA256, out.Stamped = head, hex.EncodeToString(sum[:]), len(head.Stamp) > 0 && string(head.Stamp) != "null"
	return out, nil
}

// CheckPublicStatement fetches statement seq from a node's public listener (base, e.g. http://host:18090),
// with its proof and the node's signed head, and verifies them against caPEM. No client certificate.
func CheckPublicStatement(ctx context.Context, hc *http.Client, base string, seq uint64, caPEM []byte) (Checked, error) {
	if hc == nil {
		hc = &http.Client{Timeout: 15 * time.Second}
	}
	base = strings.TrimSuffix(base, "/")
	get := func(path string, v any) error {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+path, nil)
		if err != nil {
			return err
		}
		resp, err := hc.Do(req)
		if err != nil {
			return err
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		if resp.StatusCode != http.StatusOK {
			return fmt.Errorf("heain-sdk: %s: %d %s", path, resp.StatusCode, bytes.TrimSpace(b))
		}
		return json.Unmarshal(b, v)
	}
	for try := 0; ; try++ {
		var s struct {
			B64       string           `json:"statement_b64"`
			Inclusion *PublicInclusion `json:"inclusion"`
		}
		var h struct {
			Head PublicHead `json:"head"`
		}
		if err := get(fmt.Sprintf("/v1/public/statements/%d", seq), &s); err != nil {
			return Checked{}, err
		}
		if err := get("/v1/public/statements/head", &h); err != nil {
			return Checked{}, err
		}
		if s.Inclusion != nil && s.Inclusion.TreeSize == h.Head.TreeSize || try >= 3 {
			if s.Inclusion == nil {
				return Checked{}, errors.New("heain-sdk: the statement is not in a signed head yet")
			}
			raw, err := base64.StdEncoding.DecodeString(s.B64)
			if err != nil {
				return Checked{}, err
			}
			return VerifyPublicStatement(raw, *s.Inclusion, h.Head, caPEM)
		}
		time.Sleep(500 * time.Millisecond) // the head moved between the two reads
	}
}
