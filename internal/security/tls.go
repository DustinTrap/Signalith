package security

import (
	"crypto/rsa"
	"crypto/x509"
	"net/url"
	"strings"

	"github.com/jrsamsanchez/signalith/internal/config"
	"github.com/jrsamsanchez/signalith/internal/tlsauto"
)

// TLSFactsFrom reads the certificate m serves, or returns nil without
// one. The server adds what it saw at runtime (refusals, names used).
func TLSFactsFrom(m *tlsauto.Manager, c *config.Config) *TLSFacts {
	if m == nil {
		return nil
	}
	t := &TLSFacts{ScopeSetup: c.Server.CAScope()}
	if leaf := m.Leaf(); leaf != nil {
		t.Leaf = leafFacts(leaf)
	}
	if m.LocalCA() {
		t.Mode = config.TLSAuto
		t.Outside = m.Outside()
		t.CA, t.Next, t.Previous = m.CAInfo(), m.Next(), m.Previous()
		t.WouldCover = map[string][]string{
			tlsauto.ScopeStandard: m.WouldCover(tlsauto.ScopeStandard),
			tlsauto.ScopeStrict:   m.WouldCover(tlsauto.ScopeStrict),
		}
		return t
	}
	t.Mode = config.TLSFiles
	t.CertFile, t.KeyFile = c.TLSFiles()
	if u, err := url.Parse(c.Server.PublicURL); err == nil && u.Hostname() != "" {
		t.PublicHost = u.Hostname()
		t.CoversPublicHost = m.Covers(t.PublicHost)
	}
	t.CAMissing = m.CAPEM() == nil && !m.PublicCA()
	return t
}

// leafFacts reads a certificate's end date and how strong it is.
func leafFacts(c *x509.Certificate) *LeafFacts {
	l := &LeafFacts{NotAfter: c.NotAfter}
	if k, ok := c.PublicKey.(*rsa.PublicKey); ok {
		l.RSABits = k.N.BitLen()
	}
	switch c.SignatureAlgorithm {
	case x509.SHA1WithRSA, x509.ECDSAWithSHA1, x509.DSAWithSHA1:
		l.SHA1 = true
	}
	return l
}

// SeenFrom lists the names people used to reach this server, and
// whether a strict certificate authority made now would cover each.
func SeenFrom(m *tlsauto.Manager) []SeenName {
	if m == nil || !m.LocalCA() {
		return nil
	}
	out := []SeenName{}
	for _, s := range m.SeenNames() {
		out = append(out, SeenName{Name: s.Name, LastSeen: s.LastSeen,
			CoveredStrict: m.WouldAllow(tlsauto.ScopeStrict, strings.Trim(s.Name, "[]"))})
	}
	return out
}
