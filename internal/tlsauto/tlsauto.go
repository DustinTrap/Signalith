// Package tlsauto gives Signalith an HTTPS certificate with no setup. In
// auto mode it makes a small certificate authority (CA) of its own on first
// start, and from it a server certificate for every name and address the
// server is known by, renewed well before it expires. Agents and browsers
// trust that one CA. In files mode it serves the admin's certificate and
// key instead, and picks up renewed files without a restart.
package tlsauto

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"math/big"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Lifetimes. The server certificate lasts 397 days, the most Apple
// platforms accept, and is renewed RenewBefore its end; the CA lasts 10
// years, so agents and browsers keep trusting renewed certificates.
const (
	CAYears      = 10
	LeafValidity = 397 * 24 * time.Hour
	RenewBefore  = 30 * 24 * time.Hour
	// CheckEvery is how often Run looks for a certificate due for renewal
	// or certificate files that changed.
	CheckEvery = time.Minute
	// maxAddedNames caps the names EnsureName keeps; the oldest go first.
	maxAddedNames = 32
)

// Files in Options.Dir. The keys are readable by Signalith's user only.
const (
	CAFile    = "ca.pem"
	caKeyFile = "ca.key"
	certFile  = "server.pem"
	keyFile   = "server.key"
	namesFile = "names.txt"
)

// Options configure a Manager.
type Options struct {
	// Dir holds the CA and the server certificate in auto mode.
	Dir string
	// CertFile and KeyFile, when set, are the admin's certificate (with
	// its chain) and key, used instead of the CA (files mode).
	CertFile, KeyFile string
	// Names are host names and IP addresses the auto certificate must
	// cover besides this machine's own: the public_url host and
	// server.tls.names.
	Names []string
	// Log gets renewals and problems; nil discards them.
	Log *slog.Logger
	// Now is the clock; nil uses time.Now.
	Now func() time.Time
}

// Manager serves the current certificate and keeps it fresh.
type Manager struct {
	opts Options
	cert atomic.Pointer[tls.Certificate]

	mu    sync.Mutex
	ca    *x509.Certificate // the CA agents should trust; nil when none is known
	caKey crypto.Signer     // auto mode only
	added []string          // names from EnsureName, oldest first
	// outside are names the certificate should cover but the CA may not
	// sign (see allowed), as of the last wantNames.
	outside []string
	// files mode: what the files looked like when last loaded, and
	// whether the certificate chains to a CA this system trusts.
	stamp    string
	publicCA bool
	failed   string // the files' stamp that last failed to load
}

// localNames lists this machine's names and addresses for the auto
// certificate. Tests replace it.
var localNames = machineNames

// New loads or makes the certificate. In auto mode the first start makes
// the CA, which later starts reuse.
func New(o Options) (*Manager, error) {
	m := &Manager{opts: o}
	if o.CertFile != "" {
		if err := m.loadFiles(true); err != nil {
			return nil, err
		}
		return m, nil
	}
	if o.Dir == "" {
		return nil, errors.New("no folder for the HTTPS certificate")
	}
	if err := os.MkdirAll(o.Dir, 0o700); err != nil {
		return nil, fmt.Errorf("cannot create %s for the HTTPS certificate: %w. Set SIGNALITH_STATE_DIR to a folder Signalith can write, or use your own certificate (server.tls.mode: files)", o.Dir, err)
	}
	// The names first: a new CA is made for them.
	m.added = m.readNames()
	if err := m.loadCA(); err != nil {
		return nil, err
	}
	if err := m.loadOrIssue(); err != nil {
		return nil, err
	}
	return m, nil
}

func (m *Manager) now() time.Time {
	if m.opts.Now != nil {
		return m.opts.Now()
	}
	return time.Now()
}

func (m *Manager) log() *slog.Logger {
	if m.opts.Log != nil {
		return m.opts.Log
	}
	return slog.New(slog.DiscardHandler)
}

// GetCertificate is for tls.Config.GetCertificate.
func (m *Manager) GetCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	return m.cert.Load(), nil
}

// TLSConfig returns a server configuration with this certificate and TLS
// 1.2 or newer. The explicit minimum keeps a GODEBUG setting from
// lowering it.
func (m *Manager) TLSConfig() *tls.Config {
	return &tls.Config{MinVersion: tls.VersionTLS12, GetCertificate: m.GetCertificate}
}

// LocalCA reports whether the certificate comes from Signalith's own CA
// (auto mode).
func (m *Manager) LocalCA() bool { return m != nil && m.opts.CertFile == "" }

// CAPEM returns the CA certificate agents and browsers should trust, in
// PEM: Signalith's own CA, or in files mode the root at the end of the
// certificate file's chain. It is nil when the certificate comes from a CA
// this system already trusts, or when the file does not include its CA.
func (m *Manager) CAPEM() []byte {
	if m == nil {
		return nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.ca == nil || m.publicCA {
		return nil
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: m.ca.Raw})
}

// PublicCA reports whether, in files mode, the certificate chains to a CA
// this system trusts, so agents need no CA file.
func (m *Manager) PublicCA() bool {
	if m == nil {
		return false
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.publicCA
}

// Fingerprint returns the SHA-256 fingerprint of the CA in CAPEM, as
// colon-separated hex (the way openssl x509 -fingerprint -sha256 prints
// it), or "" when there is none.
func (m *Manager) Fingerprint() string {
	if m == nil {
		return ""
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.ca == nil || m.publicCA {
		return ""
	}
	return Fingerprint(m.ca.Raw)
}

// Fingerprint formats the SHA-256 of a DER certificate as AB:CD:...
func Fingerprint(der []byte) string {
	sum := sha256.Sum256(der)
	parts := make([]string, len(sum))
	for i, b := range sum {
		parts[i] = fmt.Sprintf("%02X", b)
	}
	return strings.Join(parts, ":")
}

// CAPath returns the CA file in auto mode, for the log and the docs.
func (m *Manager) CAPath() string {
	if !m.LocalCA() {
		return ""
	}
	return filepath.Join(m.opts.Dir, CAFile)
}

// Leaf returns the certificate being served.
func (m *Manager) Leaf() *x509.Certificate {
	if m == nil {
		return nil
	}
	if c := m.cert.Load(); c != nil {
		return c.Leaf
	}
	return nil
}

// Names lists the host names and IP addresses the certificate covers.
func (m *Manager) Names() []string { return certNames(m.Leaf()) }

// Covers reports whether the certificate is valid for host, a DNS name
// or an IP address.
func (m *Manager) Covers(host string) bool {
	leaf := m.Leaf()
	return leaf != nil && leaf.VerifyHostname(strings.Trim(host, "[]")) == nil
}

// CanCover says whether the certificate covers host or EnsureName can
// make it do so, without changing anything: nil, or an error that says
// why not and what to use instead.
func (m *Manager) CanCover(host string) error {
	_, err := m.canCover(host)
	return err
}

// canCover is CanCover, and also returns host as it goes into the
// certificate, or "" when nothing needs to change.
func (m *Manager) canCover(host string) (string, error) {
	if m == nil {
		return "", nil
	}
	name, ok := normalizeName(host)
	if !ok {
		return "", fmt.Errorf("%q is not a host name or IP address", host)
	}
	if m.Covers(name) {
		return "", nil
	}
	if a, err := netip.ParseAddr(name); err == nil && a.IsUnspecified() {
		return "", nil // 0.0.0.0 is no one's address
	}
	if !m.LocalCA() {
		return "", fmt.Errorf("the certificate in server.tls_cert is not valid for %s (it covers %s). Use one of those, or get a certificate that includes %s",
			name, shortList(certNames(m.Leaf()), 6), name)
	}
	m.mu.Lock()
	allowed := m.allowed(name)
	m.mu.Unlock()
	if !allowed {
		return "", fmt.Errorf("Signalith's certificate can't include %s: its own certificate authority only signs this server's names and private network addresses, "+
			"so trusting it can't expose other websites. Use this computer's IP address or a name the certificate covers (%s), "+
			"or see \"Names the certificate can cover\" in docs/https.md", name, shortList(certNames(m.Leaf()), 4))
	}
	return name, nil
}

// EnsureName makes sure the certificate covers host, the address agents
// are being set up to send to. In auto mode it issues a new certificate
// that adds it, and keeps it in future ones, when the CA may sign it (see
// allowed); in files mode it can only say the certificate does not cover
// it.
func (m *Manager) EnsureName(host string) error {
	name, err := m.canCover(host)
	if err != nil || name == "" {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.Covers(name) {
		return nil
	}
	m.added = slices.DeleteFunc(m.added, func(n string) bool { return n == name })
	m.added = append(m.added, name)
	if len(m.added) > maxAddedNames {
		m.added = m.added[len(m.added)-maxAddedNames:]
	}
	if err := m.writeNames(); err != nil {
		return err
	}
	if err := m.issue(); err != nil {
		return err
	}
	m.log().Info("HTTPS certificate now also covers "+name, "names", strings.Join(certNames(m.Leaf()), ", "))
	return nil
}

// Refresh takes in the names another Manager for the same folder added
// with EnsureName since this one was made (they are kept in names.txt),
// and issues a certificate that covers them when this one does not. A
// restart prepares the new certificate before it stops the one in use,
// which Add data may still give names to meanwhile.
func (m *Manager) Refresh() error {
	if !m.LocalCA() {
		return nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	saved := m.readNames()
	if slices.Equal(saved, m.added) {
		return nil
	}
	m.added = saved
	if m.usable(m.Leaf()) {
		return nil
	}
	if err := m.issue(); err != nil {
		return err
	}
	m.log().Info("HTTPS certificate now also covers the names added on the Add data page", "names", strings.Join(certNames(m.Leaf()), ", "))
	return nil
}

// Run renews the auto certificate before it expires, and in files mode
// loads the files again when they change, until ctx ends.
func (m *Manager) Run(ctx context.Context) {
	t := time.NewTicker(CheckEvery)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		if err := m.Check(); err != nil {
			m.log().Error("HTTPS certificate: "+err.Error(), "err", err)
		}
	}
}

// Check renews the auto certificate when it is due, or loads changed
// certificate files.
func (m *Manager) Check() error {
	if !m.LocalCA() {
		return m.loadFiles(false)
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	leaf := m.Leaf()
	if leaf != nil && m.now().Before(leaf.NotAfter.Add(-RenewBefore)) {
		return nil
	}
	if m.now().After(m.ca.NotAfter.Add(-RenewBefore)) {
		m.log().Warn("Signalith's own certificate authority is about to expire; delete the tls folder and restart to make a new one, "+
			"then give agents the new CA from the Add data page", "ca_file", filepath.Join(m.opts.Dir, CAFile), "expires", m.ca.NotAfter)
	}
	if err := m.issue(); err != nil {
		return fmt.Errorf("could not renew: %w", err)
	}
	m.log().Info("HTTPS certificate renewed", "expires", m.Leaf().NotAfter.Format(time.DateOnly))
	return nil
}

// ---- auto mode ----

func (m *Manager) path(name string) string { return filepath.Join(m.opts.Dir, name) }

// loadCA reads the CA, or makes one on first start.
func (m *Manager) loadCA() error {
	certPEM, err := os.ReadFile(m.path(CAFile))
	if errors.Is(err, fs.ErrNotExist) {
		if _, kerr := os.Stat(m.path(caKeyFile)); kerr == nil {
			return fmt.Errorf("%s is missing but its key %s is there; restore %s, or delete the tls folder to start over (agents then need the new CA)",
				m.path(CAFile), m.path(caKeyFile), CAFile)
		}
		return m.makeCA()
	}
	if err != nil {
		return fmt.Errorf("cannot read Signalith's CA certificate: %w", err)
	}
	ca, err := parseCert(certPEM)
	if err != nil {
		return fmt.Errorf("%s: %w", m.path(CAFile), err)
	}
	key, err := readCAKey(m.path(caKeyFile))
	if err != nil {
		return err
	}
	if !samePublicKey(ca.PublicKey, key.Public()) {
		return fmt.Errorf("%s does not belong to %s; restore the pair, or delete the tls folder to start over (agents then need the new CA)", caKeyFile, CAFile)
	}
	m.ca, m.caKey = ca, key
	return nil
}

// makeCA makes the CA. Its name constraints let it sign only the names
// and addresses this server has now (wantNames) and ones that only mean
// something on a private network (see constraints): computers trust it
// for every site, so this keeps a stolen ca.key from vouching for anyone
// else's.
func (m *Manager) makeCA() error {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	host, _ := os.Hostname()
	if host == "" {
		host = "signalith"
	}
	now := m.now()
	dns, ips := constraints(m.wantNames())
	tmpl := &x509.Certificate{
		SerialNumber:                serial(),
		Subject:                     pkix.Name{CommonName: "Signalith Local CA (" + host + ")", Organization: []string{"Signalith"}},
		NotBefore:                   now.Add(-time.Hour),
		NotAfter:                    now.AddDate(CAYears, 0, 0),
		IsCA:                        true,
		BasicConstraintsValid:       true,
		MaxPathLenZero:              true,
		KeyUsage:                    x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		PermittedDNSDomainsCritical: true,
		PermittedDNSDomains:         dns,
		PermittedIPRanges:           ips,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		return err
	}
	ca, _ := x509.ParseCertificate(der)
	if err := writeCAKey(m.path(caKeyFile), key); err != nil {
		return err
	}
	if err := writeFile(m.path(CAFile), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644); err != nil {
		return err
	}
	m.ca, m.caKey = ca, key
	m.log().Info("made Signalith's own certificate authority for HTTPS", "ca_file", m.path(CAFile), "ca_sha256", Fingerprint(der))
	return nil
}

// readCAKey reads the CA's private key. Every read of it goes through
// here, so a change to how it is stored is made in one place.
func readCAKey(path string) (crypto.Signer, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("cannot read Signalith's CA key: %w", err)
	}
	return parseKey(b, path)
}

// writeCAKey writes the CA's private key, readable by Signalith's user
// only.
func writeCAKey(path string, key crypto.Signer) error {
	return writeKey(path, key)
}

// wantNames lists the names the auto certificate must cover: the ones
// the CA may sign. The others are kept in m.outside, for Outside.
func (m *Manager) wantNames() []string {
	var out, outside []string
	seen := map[string]bool{}
	// The first name (the public_url host when there is one) is also the
	// certificate's common name.
	for _, list := range [][]string{m.opts.Names, localNames(), m.added} {
		for _, n := range list {
			if n, ok := normalizeName(n); ok && !seen[n] {
				seen[n] = true
				if m.allowed(n) {
					out = append(out, n)
				} else {
					outside = append(outside, n)
				}
			}
		}
	}
	m.outside = outside
	return out
}

// Outside lists the names the auto certificate should cover (public_url's
// host, server.tls.names, this machine's names) but leaves out, because
// Signalith's own CA may not sign them: it was made before they were
// known. docs/https.md says how to get them in.
func (m *Manager) Outside() []string {
	if m == nil {
		return nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	return slices.Clone(m.outside)
}

// Names Signalith's own CA may sign besides the ones it was made for:
// names that only mean something on a private network (see RFC 6762,
// appendix G, and RFC 8375), and private, shared (CGNAT), loopback and
// link-local addresses.
var (
	privateDomains = []string{"localhost", "local", "localdomain", "internal", "intranet", "lan", "home", "home.arpa", "corp", "private"}
	privateRanges  = []netip.Prefix{
		netip.MustParsePrefix("10.0.0.0/8"), netip.MustParsePrefix("172.16.0.0/12"), netip.MustParsePrefix("192.168.0.0/16"),
		netip.MustParsePrefix("100.64.0.0/10"), netip.MustParsePrefix("127.0.0.0/8"), netip.MustParsePrefix("169.254.0.0/16"),
		netip.MustParsePrefix("::1/128"), netip.MustParsePrefix("fc00::/7"), netip.MustParsePrefix("fe80::/10"),
	}
)

// constraints returns the name constraints for a new CA: privateDomains
// and privateRanges, plus each of names outside them. A DNS name there
// also allows the names under it.
func constraints(names []string) (dns []string, ips []*net.IPNet) {
	dns = slices.Clone(privateDomains)
	ranges := slices.Clone(privateRanges)
	for _, n := range names {
		if a, err := netip.ParseAddr(n); err == nil {
			if !slices.ContainsFunc(ranges, func(p netip.Prefix) bool { return p.Contains(a) }) {
				ranges = append(ranges, netip.PrefixFrom(a, a.BitLen()))
			}
		} else if !domainAllowed(dns, n) {
			dns = append(dns, n)
		}
	}
	for _, p := range ranges {
		ips = append(ips, &net.IPNet{IP: p.Addr().AsSlice(), Mask: net.CIDRMask(p.Bits(), p.Addr().BitLen())})
	}
	return dns, ips
}

// allowed reports whether the CA's name constraints let it sign name. A
// CA without them (made by an earlier version) may sign anything.
func (m *Manager) allowed(name string) bool {
	if m.ca == nil {
		return true
	}
	if a, err := netip.ParseAddr(name); err == nil {
		if len(m.ca.PermittedIPRanges) == 0 {
			return true
		}
		return slices.ContainsFunc(m.ca.PermittedIPRanges, func(r *net.IPNet) bool { return r.Contains(a.AsSlice()) })
	}
	return len(m.ca.PermittedDNSDomains) == 0 || domainAllowed(m.ca.PermittedDNSDomains, name)
}

// domainAllowed reports whether name is one of domains or under one, the
// way certificate name constraints match DNS names.
func domainAllowed(domains []string, name string) bool {
	for _, d := range domains {
		d = strings.ToLower(strings.TrimPrefix(d, "."))
		if name == d || strings.HasSuffix(name, "."+d) {
			return true
		}
	}
	return false
}

// loadOrIssue uses the saved certificate when it is from the CA, covers
// every name and is not due for renewal; otherwise it issues a new one.
func (m *Manager) loadOrIssue() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	pair, err := tls.LoadX509KeyPair(m.path(certFile), m.path(keyFile))
	if err == nil && m.usable(pair.Leaf) {
		m.cert.Store(&pair)
		return nil
	}
	return m.issue()
}

func (m *Manager) usable(leaf *x509.Certificate) bool {
	if leaf == nil || leaf.CheckSignatureFrom(m.ca) != nil || !m.now().Before(leaf.NotAfter.Add(-RenewBefore)) {
		return false
	}
	want := map[string]bool{}
	for _, n := range m.wantNames() {
		if leaf.VerifyHostname(n) != nil {
			return false
		}
		want[n] = true
	}
	// Nor more: a name taken out of server.tls.names leaves the
	// certificate when Signalith next starts.
	for _, n := range certNames(leaf) {
		if n, ok := normalizeName(n); !ok || !want[n] {
			return false
		}
	}
	return true
}

// issue makes a new server certificate from the CA for wantNames and
// starts serving it. The caller holds m.mu.
func (m *Manager) issue() error {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	names := m.wantNames()
	tmpl := &x509.Certificate{
		SerialNumber: serial(),
		Subject:      pkix.Name{CommonName: names[0], Organization: []string{"Signalith"}},
		NotBefore:    m.now().Add(-time.Hour),
		NotAfter:     m.now().Add(LeafValidity),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	if tmpl.NotAfter.After(m.ca.NotAfter) {
		tmpl.NotAfter = m.ca.NotAfter
	}
	for _, n := range names {
		if a, err := netip.ParseAddr(n); err == nil {
			tmpl.IPAddresses = append(tmpl.IPAddresses, a.AsSlice())
		} else {
			tmpl.DNSNames = append(tmpl.DNSNames, n)
		}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, m.ca, key.Public(), m.caKey)
	if err != nil {
		return err
	}
	leaf, _ := x509.ParseCertificate(der)
	if err := writeKey(m.path(keyFile), key); err != nil {
		return err
	}
	if err := writeFile(m.path(certFile), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644); err != nil {
		return err
	}
	m.cert.Store(&tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf})
	return nil
}

// readNames reads the names EnsureName added, one per line.
func (m *Manager) readNames() []string {
	b, err := os.ReadFile(m.path(namesFile))
	if err != nil {
		return nil
	}
	var out []string
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		if n, ok := normalizeName(line); ok && !strings.HasPrefix(line, "#") && !slices.Contains(out, n) {
			out = append(out, n)
		}
	}
	if len(out) > maxAddedNames {
		out = out[len(out)-maxAddedNames:]
	}
	return out
}

func (m *Manager) writeNames() error {
	text := "# Addresses agents were set up with on the Add data page. Signalith keeps them\n" +
		"# in its HTTPS certificate. For names of your own, use server.tls.names instead.\n" +
		strings.Join(m.added, "\n") + "\n"
	return writeFile(m.path(namesFile), []byte(text), 0o644)
}

// ---- files mode ----

// loadFiles loads the admin's certificate and key when they changed
// since the last load. At startup (first) a problem is an error; later
// the certificate in use stays and the problem is logged once.
func (m *Manager) loadFiles(first bool) error {
	stamp := fileStamp(m.opts.CertFile) + "|" + fileStamp(m.opts.KeyFile)
	m.mu.Lock()
	defer m.mu.Unlock()
	if !first && (stamp == m.stamp || stamp == m.failed) {
		return nil
	}
	pair, err := tls.LoadX509KeyPair(m.opts.CertFile, m.opts.KeyFile)
	if err != nil {
		if first {
			return fmt.Errorf("server.tls_cert and tls_key: %w", err)
		}
		m.failed = stamp
		return fmt.Errorf("the changed files in server.tls_cert and tls_key could not be loaded, so the previous certificate stays in use until they are fixed: %w", err)
	}
	var chain []*x509.Certificate
	for _, der := range pair.Certificate {
		c, err := x509.ParseCertificate(der)
		if err != nil {
			return fmt.Errorf("server.tls_cert: %w", err)
		}
		chain = append(chain, c)
	}
	inter := x509.NewCertPool()
	for _, c := range chain[1:] {
		inter.AddCert(c)
	}
	_, verr := chain[0].Verify(x509.VerifyOptions{Intermediates: inter, CurrentTime: m.now()})
	m.publicCA = verr == nil
	// The CA to hand out: the root at the end of the chain, or the
	// certificate itself when it is self-signed.
	m.ca = nil
	if last := chain[len(chain)-1]; selfSigned(last) {
		m.ca = last
	}
	m.cert.Store(&pair)
	if !first {
		m.log().Info("loaded the changed HTTPS certificate", "file", m.opts.CertFile, "expires", pair.Leaf.NotAfter.Format(time.DateOnly))
	}
	m.stamp, m.failed = stamp, ""
	return nil
}

// fileStamp changes when a file is replaced or rewritten.
func fileStamp(path string) string {
	fi, err := os.Stat(path)
	if err != nil {
		return "missing"
	}
	return fmt.Sprintf("%d/%d", fi.ModTime().UnixNano(), fi.Size())
}

// ---- helpers ----

// machineNames returns this machine's name, its full DNS name when the
// resolver knows one, its network addresses (not loopback or link-local)
// and the loopback names.
func machineNames() []string {
	out := []string{"localhost", "127.0.0.1", "::1"}
	if h, err := os.Hostname(); err == nil && h != "" {
		out = append(out, h)
		if !strings.Contains(h, ".") {
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			if cname, err := net.DefaultResolver.LookupCNAME(ctx, h); err == nil {
				if fqdn := strings.TrimSuffix(cname, "."); strings.Contains(fqdn, ".") {
					out = append(out, fqdn)
				}
			}
			cancel()
		}
	}
	if addrs, err := net.InterfaceAddrs(); err == nil {
		for _, a := range addrs {
			p, err := netip.ParsePrefix(a.String())
			if err != nil {
				continue
			}
			ip := p.Addr().Unmap()
			if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsMulticast() || ip.IsUnspecified() {
				continue
			}
			out = append(out, ip.String())
		}
	}
	return out
}

// normalizeName returns a host name in lower case without a trailing dot,
// or an IP address in its usual form; false when s is neither.
func normalizeName(s string) (string, bool) {
	s = strings.Trim(strings.TrimSpace(s), "[]")
	if a, err := netip.ParseAddr(s); err == nil {
		if a.Zone() != "" {
			return "", false
		}
		return a.Unmap().String(), true
	}
	s = strings.ToLower(strings.TrimSuffix(s, "."))
	if s == "" || len(s) > 253 {
		return "", false
	}
	for _, label := range strings.Split(s, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return "", false
		}
		for _, r := range label {
			if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-' || r == '_') {
				return "", false
			}
		}
	}
	return s, true
}

// certNames lists the names and addresses a certificate covers.
func certNames(c *x509.Certificate) []string {
	if c == nil {
		return nil
	}
	out := slices.Clone(c.DNSNames)
	for _, ip := range c.IPAddresses {
		out = append(out, ip.String())
	}
	return out
}

// shortList lists up to max of names for a message: addresses other
// machines can use first, then names, without the loopback ones.
func shortList(names []string, max int) string {
	var ips, hosts []string
	for _, n := range names {
		if a, err := netip.ParseAddr(n); err == nil {
			if !a.IsLoopback() {
				ips = append(ips, n)
			}
		} else if n != "localhost" && !strings.HasSuffix(n, ".localhost") {
			hosts = append(hosts, n)
		}
	}
	list := append(ips, hosts...)
	switch {
	case len(list) == 0:
		return "only this computer's own names, such as localhost"
	case len(list) > max:
		return strings.Join(list[:max], ", ") + " and others"
	}
	return strings.Join(list, ", ")
}

// selfSigned reports whether c signed itself: a root CA, or a server
// certificate made without a CA.
func selfSigned(c *x509.Certificate) bool {
	return string(c.RawIssuer) == string(c.RawSubject) && c.CheckSignature(c.SignatureAlgorithm, c.RawTBSCertificate, c.Signature) == nil
}

func serial() *big.Int {
	n, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
	if err != nil {
		panic(err)
	}
	return n.Add(n, big.NewInt(1))
}

func parseCert(b []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(b)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, errors.New("no PEM certificate in it")
	}
	return x509.ParseCertificate(block.Bytes)
}

func parseKey(b []byte, path string) (crypto.Signer, error) {
	block, _ := pem.Decode(b)
	if block == nil {
		return nil, fmt.Errorf("%s holds no PEM key", path)
	}
	k, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	s, ok := k.(crypto.Signer)
	if !ok {
		return nil, fmt.Errorf("%s: not a signing key", path)
	}
	return s, nil
}

func writeKey(path string, key crypto.Signer) error {
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return err
	}
	return writeFile(path, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0o600)
}

func samePublicKey(a, b crypto.PublicKey) bool {
	ka, ok := a.(interface{ Equal(crypto.PublicKey) bool })
	return ok && ka.Equal(b)
}

// writeFile replaces path in one step, so a reader never sees half a file.
func writeFile(path string, data []byte, perm os.FileMode) error {
	f, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+"-*")
	if err != nil {
		return fmt.Errorf("cannot write %s: %w", path, err)
	}
	tmp := f.Name()
	defer os.Remove(tmp)
	if err := f.Chmod(perm); err != nil {
		f.Close()
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		return fmt.Errorf("cannot write %s: %w", path, err)
	}
	return nil
}
