/*
Copyright 2026 PodMotion Authors.
Licensed under the Apache License, Version 2.0.
*/

package tls

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net/url"
	"testing"
	"time"
)

// ADR-SEC-C (GC-B7) M4: unit tests for the operator→agent peer verifier.
//
// The verifier (verifyAgentSPIFFE) is what the operator uses to accept the agent server cert
// when dialing BY IP against a cert that carries ONLY a SPIFFE URI SAN (no IP/DNS SAN). It MUST:
//   - PASS a valid CA-signed agent cert with the correct SPIFFE URI,
//   - REJECT a self-signed cert with the correct URI (no CA chain) — proves the chain build runs,
//   - REJECT a CA-signed cert with the wrong/absent URI — proves the identity pin,
//   - REJECT a CA-signed cert bearing the operator's OWN URI,
//   - REJECT a cert with multiple URI SANs.

const testNS = "podmotion-system"

type testCA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
	der  []byte
}

func newTestCA(t *testing.T) *testCA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ca key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "podmotion-grpc-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("ca cert: %v", err)
	}
	c, _ := x509.ParseCertificate(der)
	return &testCA{cert: c, key: key, der: der}
}

// leaf builds a leaf cert with the given URI SANs. If signer is nil the leaf is self-signed.
func leaf(t *testing.T, ca *testCA, selfSigned bool, uris ...string) [][]byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("leaf key: %v", err)
	}
	parsed := make([]*url.URL, 0, len(uris))
	for _, u := range uris {
		pu, err := url.Parse(u)
		if err != nil {
			t.Fatalf("parse uri %q: %v", u, err)
		}
		parsed = append(parsed, pu)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: "leaf"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		URIs:         parsed,
	}
	var der []byte
	if selfSigned {
		der, err = x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	} else {
		der, err = x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &key.PublicKey, ca.key)
	}
	if err != nil {
		t.Fatalf("leaf cert: %v", err)
	}
	return [][]byte{der}
}

func caPoolOf(ca *testCA) *x509.CertPool {
	p := x509.NewCertPool()
	p.AddCert(ca.cert)
	return p
}

func TestVerifyAgentSPIFFE_ValidAgentCert_Pass(t *testing.T) {
	ca := newTestCA(t)
	verify := verifyAgentSPIFFE(caPoolOf(ca), ExpectedAgentSPIFFEID(testNS))
	raw := leaf(t, ca, false, ExpectedAgentSPIFFEID(testNS))
	if err := verify(raw, nil); err != nil {
		t.Fatalf("expected PASS for valid CA-signed agent cert, got: %v", err)
	}
}

func TestVerifyAgentSPIFFE_SelfSignedCorrectURI_Reject(t *testing.T) {
	ca := newTestCA(t)
	verify := verifyAgentSPIFFE(caPoolOf(ca), ExpectedAgentSPIFFEID(testNS))
	// Correct URI but NOT chained to the CA — chain build must fail closed (C3).
	raw := leaf(t, ca, true, ExpectedAgentSPIFFEID(testNS))
	if err := verify(raw, nil); err == nil {
		t.Fatal("expected REJECT for self-signed cert (no CA chain), got PASS")
	}
}

func TestVerifyAgentSPIFFE_WrongURI_Reject(t *testing.T) {
	ca := newTestCA(t)
	verify := verifyAgentSPIFFE(caPoolOf(ca), ExpectedAgentSPIFFEID(testNS))
	raw := leaf(t, ca, false, "spiffe://podmotion.io/ns/"+testNS+"/sa/some-other-sa")
	if err := verify(raw, nil); err == nil {
		t.Fatal("expected REJECT for CA-signed cert with wrong SPIFFE URI, got PASS")
	}
}

func TestVerifyAgentSPIFFE_AbsentURI_Reject(t *testing.T) {
	ca := newTestCA(t)
	verify := verifyAgentSPIFFE(caPoolOf(ca), ExpectedAgentSPIFFEID(testNS))
	raw := leaf(t, ca, false) // no URI SANs
	if err := verify(raw, nil); err == nil {
		t.Fatal("expected REJECT for CA-signed cert with no SPIFFE URI, got PASS")
	}
}

func TestVerifyAgentSPIFFE_OperatorURI_Reject(t *testing.T) {
	ca := newTestCA(t)
	verify := verifyAgentSPIFFE(caPoolOf(ca), ExpectedAgentSPIFFEID(testNS))
	// A valid CA-signed leaf bearing the OPERATOR's own identity must NOT pass the agent pin.
	raw := leaf(t, ca, false, "spiffe://podmotion.io/ns/"+testNS+"/sa/podmotion-operator")
	if err := verify(raw, nil); err == nil {
		t.Fatal("expected REJECT for CA-signed cert with operator SPIFFE URI, got PASS")
	}
}

func TestVerifyAgentSPIFFE_MultiURI_Reject(t *testing.T) {
	ca := newTestCA(t)
	verify := verifyAgentSPIFFE(caPoolOf(ca), ExpectedAgentSPIFFEID(testNS))
	// Two URI SANs (one of them correct) — a well-formed SVID has exactly one; reject.
	raw := leaf(t, ca, false,
		ExpectedAgentSPIFFEID(testNS),
		"spiffe://podmotion.io/ns/"+testNS+"/sa/podmotion-operator",
	)
	if err := verify(raw, nil); err == nil {
		t.Fatal("expected REJECT for cert with multiple URI SANs, got PASS")
	}
}

func TestVerifyAgentSPIFFE_NamespaceDerivation(t *testing.T) {
	// M2: the expected ID is derived from the namespace; a cert for a DIFFERENT namespace's agent
	// must not satisfy a pin built for testNS.
	ca := newTestCA(t)
	verify := verifyAgentSPIFFE(caPoolOf(ca), ExpectedAgentSPIFFEID(testNS))
	raw := leaf(t, ca, false, ExpectedAgentSPIFFEID("other-ns"))
	if err := verify(raw, nil); err == nil {
		t.Fatal("expected REJECT for agent cert from a different namespace, got PASS")
	}
}

func TestExpectedAgentSPIFFEID_MatchesChartFormat(t *testing.T) {
	got := ExpectedAgentSPIFFEID(testNS)
	want := "spiffe://podmotion.io/ns/podmotion-system/sa/podmotion-agent"
	if got != want {
		t.Fatalf("ExpectedAgentSPIFFEID mismatch with agent-mtls-certs.yaml line 56: got %q, want %q", got, want)
	}
}
