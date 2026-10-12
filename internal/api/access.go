package api

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"math"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/jrsamsanchez/signalith/internal/users"
)

// route is one API route and the least role that may use it.
type route struct {
	Pattern string
	Role    users.Role
	// Unclassified routes were registered without a role. They are
	// admin-only, and TestEveryRouteHasARole fails until they get one.
	Unclassified bool
	// Anytime routes stay open to a user who must choose a new password
	// before doing anything else.
	Anytime bool
}

// router registers API routes with the role each needs. It is the one
// place access is decided: every route it registers goes through allow.
type router struct {
	s      *Server
	mux    *http.ServeMux
	routes []route
}

// viewer registers a route every signed-in user may use.
func (rt *router) viewer(pattern string, h http.HandlerFunc) {
	rt.add(route{Pattern: pattern, Role: users.Viewer}, h)
}

// analyst registers a route for day-to-day SOC work.
func (rt *router) analyst(pattern string, h http.HandlerFunc) {
	rt.add(route{Pattern: pattern, Role: users.Analyst}, h)
}

// admin registers a route that changes how Signalith works.
func (rt *router) admin(pattern string, h http.HandlerFunc) {
	rt.add(route{Pattern: pattern, Role: users.Admin}, h)
}

// self registers a route about the signed-in user, open to every role
// even before a required password change.
func (rt *router) self(pattern string, h http.HandlerFunc) {
	rt.add(route{Pattern: pattern, Role: users.Viewer, Anytime: true}, h)
}

// HandleFunc registers a route without a role, so it is admin-only. Use
// viewer, analyst or admin instead: TestEveryRouteHasARole fails on
// routes registered this way.
func (rt *router) HandleFunc(pattern string, h http.HandlerFunc) { rt.Handle(pattern, h) }

// Handle is HandleFunc for an http.Handler.
func (rt *router) Handle(pattern string, h http.Handler) {
	rt.add(route{Pattern: pattern, Role: users.Admin, Unclassified: true}, h)
}

func (rt *router) add(r route, h http.Handler) {
	rt.routes = append(rt.routes, r)
	rt.mux.Handle(r.Pattern, rt.s.allow(r, h))
}

// principal is the signed-in user of a request. Its role is looked up
// for every request, so a change applies at once.
type principal struct {
	Username           string
	Name               string
	Email              string
	Role               users.Role
	Source             string // builtin, local or directory
	MustChangePassword bool
	// Method is how the request signed in: session or basic.
	Method string
	token  string // the session's token, to keep it when others end
}

type userKey struct{}

// principalOf returns the signed-in user, or nil.
func principalOf(r *http.Request) *principal {
	p, _ := r.Context().Value(userKey{}).(*principal)
	return p
}

// userOf returns the signed-in user's name.
func userOf(r *http.Request) string {
	if p := principalOf(r); p != nil {
		return p.Username
	}
	return "unknown"
}

// allow refuses a request whose user's role is below the route's, or who
// must change their password first.
func (s *Server) allow(rt route, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := principalOf(r)
		if p == nil {
			s.unauthorized(w, r)
			return
		}
		if p.MustChangePassword && !rt.Anytime {
			if !strings.HasPrefix(r.URL.Path, "/api/") && (r.Method == http.MethodGet || r.Method == http.MethodHead) {
				// The sign-in page asks for the new password.
				http.Redirect(w, r, "/login?change=1", http.StatusSeeOther)
				return
			}
			writeJSON(w, http.StatusForbidden, map[string]any{
				"error": "Choose a new password before you continue.", "code": "password_change_required"})
			return
		}
		if !p.Role.AtLeast(rt.Role) {
			writeJSON(w, http.StatusForbidden, map[string]any{
				"error":    fmt.Sprintf("This needs the %s role, and your role is %s. Ask an admin if you need access.", rt.Role.Label(), p.Role.Label()),
				"code":     "forbidden",
				"role":     p.Role,
				"required": rt.Role,
			})
			return
		}
		next.ServeHTTP(w, r)
	})
}

// requireUser admits requests with a valid sign-in session or HTTP Basic
// credentials and puts the user in the request context. Signed-out
// browsers are sent to the sign-in page; API clients get 401.
func (s *Server) requireUser(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p, err := s.authenticate(r)
		if err != nil {
			writeSignInError(w, err)
			return
		}
		if p == nil {
			s.unauthorized(w, r)
			return
		}
		if !sameOrigin(r) {
			writeError(w, http.StatusForbidden, errors.New("cross-site request refused"))
			return
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), userKey{}, p)))
	})
}

// authenticate checks the session cookie, then Basic credentials. It
// returns nil without an error when the request is not signed in.
func (s *Server) authenticate(r *http.Request) (*principal, error) {
	if c, err := r.Cookie(sessionCookie); err == nil {
		if ss, ok := s.sessions().Lookup(c.Value); ok {
			if p := s.principalFor(ss.User); p != nil {
				p.Method, p.token = "session", c.Value
				return p, nil
			}
			// Deleted or disabled since signing in.
			s.sessions().Delete(c.Value)
		}
	}
	user, pass, ok := r.BasicAuth()
	if !ok {
		return nil, nil
	}
	p, err := s.checkBasic(r, user, pass)
	if errors.Is(err, errWrongCredentials) {
		return nil, nil
	}
	if p != nil {
		p.Method = "basic"
	}
	return p, err
}

// principalFor looks up a signed-in user's current role and state, or
// returns nil if they may no longer sign in.
func (s *Server) principalFor(name string) *principal {
	if strings.EqualFold(name, s.Config.Auth.AdminUser) {
		return s.builtinPrincipal()
	}
	u, ok := s.userStore().Get(name)
	if !ok || u.Disabled {
		return nil
	}
	if u.Source == users.SourceDirectory && !s.dir().Enabled() {
		return nil
	}
	return principalFromUser(u)
}

func (s *Server) builtinPrincipal() *principal {
	return &principal{Username: s.Config.Auth.AdminUser, Role: users.Admin, Source: users.SourceBuiltin}
}

func principalFromUser(u users.User) *principal {
	return &principal{Username: u.Username, Name: u.Name, Email: u.Email, Role: u.Role, Source: u.Source,
		MustChangePassword: u.MustChangePassword}
}

// signInError is a refused sign-in, with the status and words to send.
type signInError struct {
	status     int
	code       string
	msg        string
	retryAfter time.Duration
}

func (e *signInError) Error() string { return e.msg }

var (
	errWrongCredentials = &signInError{status: http.StatusUnauthorized, code: "wrong_credentials",
		msg: "Username and password don't match."}
	errDisabled = &signInError{status: http.StatusForbidden, code: "disabled",
		msg: "This account is disabled. Ask an admin to enable it."}
	errPasswordExpired = &signInError{status: http.StatusForbidden, code: "password_expired",
		msg: "Your directory password has expired or must be changed. Change it (for example by signing in to Windows), then sign in here again."}
	errNoRole = &signInError{status: http.StatusForbidden, code: "not_in_group",
		msg: "Your directory account is not in a group that can use Signalith. Ask an admin to add you to one."}
	errDirectoryDown = &signInError{status: http.StatusServiceUnavailable, code: "directory_unavailable",
		msg: "Signalith could not reach the directory server to check your password. Try again in a minute, or ask an admin."}
)

func writeSignInError(w http.ResponseWriter, err error) {
	var se *signInError
	if !errors.As(err, &se) {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	if se.retryAfter > 0 {
		w.Header().Set("Retry-After", fmt.Sprint(int(math.Ceil(se.retryAfter.Seconds()))))
	}
	writeJSON(w, se.status, map[string]any{"error": se.msg, "code": se.code})
}

func lockedOut(wait time.Duration) error {
	return &signInError{status: http.StatusTooManyRequests, code: "locked_out", retryAfter: wait,
		msg: fmt.Sprintf("Too many failed sign-ins from this address. Try again in %d minutes.", int(math.Ceil(wait.Minutes())))}
}

// signIn checks a username and password for the sign-in page or Basic
// auth: the built-in admin first, then local users, then the directory.
// A local username is never looked up in the directory. Wrong passwords
// count toward the per-address limit, and every attempt is logged
// without the password.
func (s *Server) signIn(r *http.Request, name, password, method string) (*principal, error) {
	client := clientIP(r)
	lim := s.limiter()
	if ok, wait := lim.Allow(client); !ok {
		return nil, lockedOut(wait)
	}
	name = strings.TrimSpace(name)
	p, reason, err := s.checkCredentials(r.Context(), name, password)
	if err != nil {
		locked := false
		if errors.Is(err, errWrongCredentials) {
			locked = lim.Fail(client)
		}
		s.Log.Warn("sign-in failed", "audit", true, "user", name, "client", client, "method", method, "reason", reason, "locked_out", locked)
		return nil, err
	}
	lim.Succeed(client)
	s.Log.Info("signed in", "audit", true, "user", p.Username, "role", p.Role, "source", p.Source, "client", client, "method", method)
	return p, nil
}

// checkCredentials does the checking for signIn and returns why it
// refused, for the log.
func (s *Server) checkCredentials(ctx context.Context, name, password string) (*principal, string, error) {
	if name == "" || password == "" {
		return nil, "empty username or password", errWrongCredentials
	}
	store := s.userStore()
	if strings.EqualFold(name, s.Config.Auth.AdminUser) {
		if !s.Config.CheckPassword(name, password) {
			return nil, "wrong password", errWrongCredentials
		}
		store.RecordBuiltinSignIn()
		return s.builtinPrincipal(), "", nil
	}
	if u, ok := store.Get(name); ok && u.Source == users.SourceLocal {
		if !store.CheckPassword(u.Username, password) {
			return nil, "wrong password", errWrongCredentials
		}
		if u.Disabled {
			return nil, "account disabled", errDisabled
		}
		store.RecordSignIn(u.Username)
		return principalFromUser(u), "", nil
	}
	d := s.dir()
	if !d.Enabled() {
		users.WasteTime(password)
		return nil, "no such user", errWrongCredentials
	}
	// DOMAIN\name is looked up as name, so a local or built-in name with a
	// domain in front is refused without asking the directory.
	if login := users.LoginName(name); !strings.EqualFold(login, name) {
		if u, ok := store.Get(login); strings.EqualFold(login, s.Config.Auth.AdminUser) || (ok && u.Source == users.SourceLocal) {
			users.WasteTime(password)
			return nil, "a domain in front of a local user's or the built-in admin's name", errWrongCredentials
		}
	}
	ctx, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()
	du, err := d.Authenticate(ctx, name, password)
	var sie *users.SignInError
	var de *users.DirectoryError
	switch {
	case errors.As(err, &sie) && errors.Is(err, users.ErrNoRole):
		return nil, "directory: " + sie.Reason, errNoRole
	case errors.As(err, &sie) && errors.Is(err, users.ErrPasswordExpired):
		return nil, "directory: " + sie.Reason, errPasswordExpired
	case errors.As(err, &sie):
		return nil, "directory: " + sie.Reason, errWrongCredentials
	case errors.As(err, &de):
		return nil, fmt.Sprintf("directory unavailable (%s at %s): %s", de.Code, de.Server, de.Detail()), errDirectoryDown
	case err != nil:
		return nil, "directory: " + err.Error(), errDirectoryDown
	}
	u, err := store.SeeDirectoryUser(*du)
	if errors.Is(err, users.ErrExists) || errors.Is(err, users.ErrReserved) {
		return nil, fmt.Sprintf("directory user %s has the name of a local user or the built-in admin", du.Username), errWrongCredentials
	}
	if err != nil {
		return nil, "could not save the directory user: " + err.Error(),
			&signInError{status: http.StatusInternalServerError, code: "store_failed", msg: "Signalith could not save your sign-in. Ask an admin to check the server log."}
	}
	if u.Disabled {
		return nil, "account disabled in Signalith", errDisabled
	}
	return principalFromUser(u), "", nil
}

// How long checked Basic credentials are remembered. Keys include the
// password hash (or the directory settings' revision), so a changed
// password or setting is never served from the cache; the shorter time
// for directory users bounds how long a password changed in the directory
// keeps working here.
const (
	basicCacheLocal     = 10 * time.Minute
	basicCacheDirectory = 2 * time.Minute
)

// credCache remembers recently checked Basic credentials by a hash, so
// API clients do not pay for bcrypt or a directory round trip on every
// request. Only successes are kept.
type credCache struct {
	mu sync.Mutex
	m  map[[32]byte]credEntry
}

type credEntry struct {
	user  string
	until time.Time
}

func (c *credCache) get(key [32]byte) (string, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.m[key]
	if !ok {
		return "", false
	}
	if time.Now().After(e.until) {
		delete(c.m, key)
		return "", false
	}
	return e.user, true
}

func (c *credCache) put(key [32]byte, user string, ttl time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.m == nil {
		c.m = map[[32]byte]credEntry{}
	}
	if len(c.m) >= 10000 {
		now := time.Now()
		for k, e := range c.m {
			if now.After(e.until) {
				delete(c.m, k)
			}
		}
		if len(c.m) >= 10000 {
			clear(c.m)
		}
	}
	c.m[key] = credEntry{user: user, until: time.Now().Add(ttl)}
}

// credentialKey identifies a username and password together with what
// they were checked against.
func (s *Server) credentialKey(user, pass string) ([32]byte, time.Duration) {
	version, ttl := "", basicCacheLocal
	switch {
	case strings.EqualFold(strings.TrimSpace(user), s.Config.Auth.AdminUser):
		version = "builtin:" + s.Config.Auth.AdminPasswordHash
	case s.userStore().PasswordVersion(user) != "":
		version = "local:" + s.userStore().PasswordVersion(user)
	default:
		version, ttl = fmt.Sprintf("directory:%d", s.dir().Revision()), basicCacheDirectory
	}
	return sha256.Sum256([]byte(user + "\x00" + pass + "\x00" + version)), ttl
}

// checkBasic checks HTTP Basic credentials, from the cache when it can.
func (s *Server) checkBasic(r *http.Request, user, pass string) (*principal, error) {
	key, ttl := s.credentialKey(user, pass)
	if name, ok := s.creds.get(key); ok {
		if p := s.principalFor(name); p != nil {
			return p, nil
		}
	}
	p, err := s.signIn(r, user, pass, "basic")
	if err != nil {
		return nil, err
	}
	s.creds.put(key, p.Username, ttl)
	return p, nil
}
