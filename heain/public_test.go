package heain

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// RFC 9162 root and inclusion proof (test only: the node computes them)
func tRoot(l [][]byte) []byte {
	if len(l) == 1 {
		return l[0]
	}
	k := 1
	for k<<1 < len(l) {
		k <<= 1
	}
	return nodeHash(tRoot(l[:k]), tRoot(l[k:]))
}

func tPath(m int, l [][]byte) [][]byte {
	if len(l) <= 1 {
		return nil
	}
	k := 1
	for k<<1 < len(l) {
		k <<= 1
	}
	if m < k {
		return append(tPath(m, l[:k]), tRoot(l[k:]))
	}
	return append(tPath(m-k, l[k:]), tRoot(l[:k]))
}

func TestPublicStatements(t *testing.T) {
	e := startEnv(t)
	ctx := context.Background()
	if p, err := e.svc.PublishStatement(ctx, "senate.ballot", "senate.result", map[string]any{"unit": "nat"}); err != nil || p.Seq != 7 {
		t.Fatalf("publish: %+v %v", p, err)
	}
	if _, err := e.svc.PublishStatement(ctx, "senate.ballot", "forbidden.kind", map[string]any{}); err == nil || !strings.Contains(err.Error(), "public_statement_refused") {
		t.Fatalf("refusal: %v", err)
	}
	// a node's public listener: a CA, a node certificate, three statements, a signed head
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	caT := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "ca"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	caDER, _ := x509.CreateCertificate(rand.Reader, caT, caT, &caKey.PublicKey, caKey)
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})
	ca, _ := x509.ParseCertificate(caDER)
	nk, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	nT := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "z-nat-1"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	nDER, _ := x509.CreateCertificate(rand.Reader, nT, ca, &nk.PublicKey, caKey)
	var raws [][]byte
	var leaves [][]byte
	for i := 1; i <= 3; i++ {
		raw, _ := json.Marshal(PublicStatement{Seq: uint64(i), Node: "z-nat-1", App: "senapp", Kind: "senate.result", Content: json.RawMessage(`{"n":` + string(rune('0'+i)) + `}`)})
		raws = append(raws, raw)
		h := sha256.Sum256(raw)
		leaves = append(leaves, leafHash(uint64(i), h[:]))
	}
	head := PublicHead{NodeID: "z-nat-1", TreeSize: 3, RootHash: hex.EncodeToString(tRoot(leaves)), Timestamp: time.Now().UTC(), SigAlg: "ecdsa-sha256",
		CertPEM: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: nDER}))}
	d := sha256.Sum256(head.message())
	head.Signature, _ = nk.Sign(rand.Reader, d[:], crypto.SHA256)
	tamper := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/public/statements/head":
			_ = json.NewEncoder(w).Encode(map[string]any{"head": head})
		case "/v1/public/statements/2":
			var path []string
			for _, p := range tPath(1, leaves) {
				path = append(path, hex.EncodeToString(p))
			}
			raw := raws[1]
			if tamper {
				raw = []byte(strings.Replace(string(raw), `"n":2`, `"n":9`, 1))
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"statement_b64": base64.StdEncoding.EncodeToString(raw),
				"inclusion": PublicInclusion{Seq: 2, LeafIndex: 1, TreeSize: 3, RootHash: head.RootHash, Path: path}})
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	c, err := CheckPublicStatement(ctx, srv.Client(), srv.URL, 2, caPEM)
	if err != nil || c.Statement.Seq != 2 || string(c.Statement.Content) != `{"n":2}` {
		t.Fatalf("check: %+v %v", c, err)
	}
	tamper = true
	if _, err := CheckPublicStatement(ctx, srv.Client(), srv.URL, 2, caPEM); err == nil || !strings.Contains(err.Error(), "not in the signed tree") {
		t.Fatalf("a changed statement: %v", err)
	}
	tamper = false
	other, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	oDER, _ := x509.CreateCertificate(rand.Reader, caT, caT, &other.PublicKey, other)
	if _, err := CheckPublicStatement(ctx, srv.Client(), srv.URL, 2, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: oDER})); err == nil || !strings.Contains(err.Error(), "chain") {
		t.Fatalf("another CA: %v", err)
	}
}
