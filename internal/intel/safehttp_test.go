package intel

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestCheckAddr(t *testing.T) {
	blocked := []string{"127.0.0.1", "127.8.9.10", "::1", "::ffff:127.0.0.1", "0.0.0.0", "0.1.2.3", "::",
		"169.254.169.254", "169.254.1.1", "fe80::1", "fd00:ec2::254", "100.100.100.200", "224.0.0.251", "ff02::1",
		"255.255.255.255", "64:ff9b::7f00:1", "64:ff9b::a9fe:a9fe"}
	for _, a := range blocked {
		if err := CheckAddr(netip.MustParseAddr(a), false); err == nil {
			t.Errorf("%s is allowed", a)
		}
	}
	// Private LAN ranges are allowed: MISP and OpenCTI servers live there.
	for _, a := range []string{"10.0.0.5", "192.168.1.20", "172.16.4.4", "fd12:3456::1", "203.0.113.9", "2001:db8::1", "100.64.0.1"} {
		if err := CheckAddr(netip.MustParseAddr(a), false); err != nil {
			t.Errorf("%s is blocked: %v", a, err)
		}
	}
	err := CheckAddr(netip.MustParseAddr("127.0.0.1"), false)
	var be *BlockedError
	if !errors.As(err, &be) || !be.Loopback || !strings.Contains(err.Error(), "allow_loopback_feeds") {
		t.Errorf("loopback error = %v", err)
	}
	if err := CheckAddr(netip.MustParseAddr("::1"), true); err != nil {
		t.Errorf("loopback allowed by the setting: %v", err)
	}
	if err := CheckAddr(netip.MustParseAddr("169.254.169.254"), true); err == nil {
		t.Error("the loopback setting must not allow link-local")
	}
}

func feedServer(t *testing.T, h http.HandlerFunc) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	return srv
}

func TestDownloadsRefuseBlockedAddresses(t *testing.T) {
	ctx := context.Background()
	srv := feedServer(t, func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("203.0.113.9\n")) })
	_, port, _ := net.SplitHostPort(strings.TrimPrefix(srv.URL, "http://"))
	f := &Feeds{Store: NewStore(NewMemory())}
	for _, u := range []string{
		srv.URL,                          // 127.0.0.1, refused before connecting
		"http://localhost:" + port + "/", // a name, refused at connect time
		"http://169.254.169.254/latest/meta-data/",
		"http://[fe80::1]/",
		"http://[fd00:ec2::254]/latest/",
		"http://0.0.0.0:" + port + "/",
	} {
		res, err := f.TestFeed(ctx, FeedInput{URL: u}, "")
		if err != nil || res.OK || !strings.Contains(res.Error, "does not download feeds from") {
			t.Errorf("%s: %+v %v", u, res, err)
		}
	}
	// The setting allows a feed server on this machine.
	f = &Feeds{Store: NewStore(NewMemory()), AllowLoopback: true}
	for _, u := range []string{srv.URL, "http://localhost:" + port + "/"} {
		if res, err := f.TestFeed(ctx, FeedInput{URL: u}, ""); err != nil || !res.OK || res.Total != 1 {
			t.Errorf("%s with allow_loopback_feeds: %+v %v", u, res, err)
		}
	}
	// ...but not link-local, even through a redirect.
	redir := feedServer(t, func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://169.254.169.254/latest/meta-data/", http.StatusFound)
	})
	if res, _ := f.TestFeed(ctx, FeedInput{URL: redir.URL}, ""); res == nil || !strings.Contains(res.Error, "169.254.169.254") {
		t.Errorf("redirect to metadata = %+v", res)
	}
	// Other schemes are refused, in a redirect too.
	ftp := feedServer(t, func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "ftp://example.com/x", http.StatusFound)
	})
	if res, _ := f.TestFeed(ctx, FeedInput{URL: ftp.URL}, ""); res == nil || !strings.Contains(res.Error, "http or https") {
		t.Errorf("redirect to ftp = %+v", res)
	}
	// At most five redirects.
	loop := feedServer(t, func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, r.URL.Path+"x", http.StatusFound) })
	if res, _ := f.TestFeed(ctx, FeedInput{URL: loop.URL + "/a"}, ""); res == nil || !strings.Contains(res.Error, "more than 5 times") {
		t.Errorf("redirect loop = %+v", res)
	}
}

func TestRedirectDropsSecretHeaders(t *testing.T) {
	var mu sync.Mutex
	var got http.Header
	other := feedServer(t, func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		got = r.Header.Clone()
		mu.Unlock()
		w.Write([]byte("203.0.113.9\n"))
	})
	_, port, _ := net.SplitHostPort(strings.TrimPrefix(other.URL, "http://"))
	first := feedServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Api-Key") != "k3y-value" {
			http.Error(w, "no key", http.StatusForbidden)
			return
		}
		// "localhost" is another host than "127.0.0.1".
		http.Redirect(w, r, "http://localhost:"+port+"/list.txt", http.StatusFound)
	})
	f := &Feeds{Store: NewStore(NewMemory()), AllowLoopback: true}
	res, err := f.TestFeed(context.Background(), FeedInput{URL: first.URL, Headers: []HeaderInput{{Name: "X-Api-Key", Value: "k3y-value"}},
		Username: "u", Password: "pw-secret"}, "")
	if err != nil || !res.OK {
		t.Fatalf("test = %+v %v", res, err)
	}
	mu.Lock()
	defer mu.Unlock()
	if got.Get("X-Api-Key") != "" || got.Get("Authorization") != "" {
		t.Errorf("secrets followed the redirect to another host: %v", got)
	}
}

func TestSafeDialerProxy(t *testing.T) {
	srv := feedServer(t, func(w http.ResponseWriter, r *http.Request) {})
	addr := strings.TrimPrefix(srv.URL, "http://")
	d := newSafeDialer(false)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if c, err := d.DialContext(ctx, "tcp", addr); err == nil {
		c.Close()
		t.Fatal("dialed loopback")
	} else if !strings.Contains(err.Error(), "loopback") {
		t.Errorf("dial error = %v", err)
	}
	// The configured proxy may be on this machine.
	d.proxies[addr] = true
	c, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		t.Fatalf("proxy dial: %v", err)
	}
	c.Close()

	t.Setenv("HTTPS_PROXY", "proxy.corp.example:3128")
	t.Setenv("HTTP_PROXY", "http://127.0.0.1")
	t.Setenv("https_proxy", "")
	t.Setenv("http_proxy", "socks5://[::1]")
	got := proxyAddrs()
	for _, want := range []string{"proxy.corp.example:3128", "127.0.0.1:80", "[::1]:1080"} {
		if !got[want] {
			t.Errorf("proxy addresses %v lack %s", got, want)
		}
	}
}

func TestDescribeErrors(t *testing.T) {
	plainFeed := Feed{Name: "f", URL: "https://x.example/a?key=abc"}
	keyed := Feed{Name: "f", URL: "https://x.example/a", Headers: map[string]string{"X-Api-Key": "sup3r-secret"}}
	cases := []struct {
		err  error
		fd   Feed
		want string
	}{
		{&HTTPError{Code: 403, Status: "403 Forbidden"}, plainFeed, "The server answered 403 Forbidden. This feed may need an API key."},
		{&HTTPError{Code: 401, Status: "401 Unauthorized", Said: "invalid key sup3r-secret"}, keyed, "Check that the API key"},
		{&HTTPError{Code: 404, Status: "404 Not Found"}, plainFeed, "Check the URL."},
		{&HTTPError{Code: 404, Status: "404 Not Found"}, Feed{Kind: KindTAXII}, "collection ID"},
		{&HTTPError{Code: 429, Status: "429 Too Many Requests"}, plainFeed, "longer interval"},
		{&HTTPError{Code: 503, Status: "503 Service Unavailable"}, plainFeed, "try again later"},
		{&TooBigError{Max: 256 << 20}, plainFeed, "larger than 256 MB"},
		{context.DeadlineExceeded, plainFeed, "did not answer within a minute"},
		{&url.Error{Op: "Get", URL: "https://x.example/a?key=abc", Err: &net.DNSError{Name: "x.example", IsNotFound: true}}, plainFeed, "Could not find the server x.example"},
		{&url.Error{Op: "Get", URL: "https://x.example/a?key=abc", Err: errors.New("boom")}, plainFeed, "Download failed: boom"},
	}
	for _, c := range cases {
		got := describe(c.err, c.fd, time.Minute)
		if !strings.Contains(got, c.want) {
			t.Errorf("describe(%v) = %q, want %q", c.err, got, c.want)
		}
		if strings.Contains(got, "key=abc") || strings.Contains(got, "sup3r-secret") {
			t.Errorf("describe(%v) shows a secret: %q", c.err, got)
		}
	}
	for in, want := range map[string]string{
		"https://u:p@x.example/a/b?key=abc#f": "https://x.example/a/b?…",
		"https://x.example/feed.txt":          "https://x.example/feed.txt",
		"http://x.example/?token=1":           "http://x.example/?…",
	} {
		if got := RedactURL(in); got != want {
			t.Errorf("RedactURL(%q) = %q, want %q", in, got, want)
		}
	}
}
