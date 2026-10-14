package api

import (
	"context"
	"net/http"
	"strings"

	"golang.org/x/crypto/bcrypt"

	"github.com/jrsamsanchez/signalith/internal/clusterauth"
	"github.com/jrsamsanchez/signalith/internal/users"
)

// SharedUsers is set on a member of a cluster whose users, directory
// sign-in settings and sessions are kept in the shared settings: Users,
// Directory and SessionStore then work over them, and the built-in admin
// is the cluster's (one password for every server, which its user may
// change on the page). nil on a server that keeps them in its own files,
// where everything works as it always did.
type SharedUsers struct {
	Docs *clusterauth.Docs
	// Seen keeps the last sign-ins, which the Users page lists.
	Seen *clusterauth.LastSeen
	// LocalHash returns the built-in admin's password hash that
	// signalith passwd -local wrote on this server, or "": it works only
	// while the shared settings cannot be written.
	LocalHash func() string
}

var _ SessionStore = (*clusterauth.Sessions)(nil)

// builtinName is the built-in admin's name: the cluster's when users are
// shared (a server whose auth.admin_user differs uses the shared one),
// else auth.admin_user.
func (s *Server) builtinName() string {
	if s.SharedUsers != nil {
		if n := s.SharedUsers.Docs.BuiltinName(); n != "" {
			return n
		}
	}
	return s.conf().Auth.AdminUser
}

// isBuiltin reports whether name is the built-in admin's.
func (s *Server) isBuiltin(name string) bool {
	return strings.EqualFold(strings.TrimSpace(name), s.builtinName())
}

// builtinHash is the built-in admin's password hash in use.
func (s *Server) builtinHash() string {
	if s.SharedUsers != nil {
		if _, h, ok := s.SharedUsers.Docs.Builtin(); ok {
			return h
		}
	}
	return s.conf().Auth.AdminPasswordHash
}

// builtinEpoch is the built-in admin's session epoch: 0 on a server that
// keeps sessions in memory.
func (s *Server) builtinEpoch() int64 {
	if s.SharedUsers == nil {
		return 0
	}
	if v, _, ok := s.SharedUsers.Docs.BuiltinUser(); ok {
		return v.SessionEpoch
	}
	return 0
}

// checkBuiltinPassword reports whether pw is the built-in admin's
// password. With shared users, the one signalith passwd -local wrote on
// this server works too while the shared settings cannot be written, so
// an admin can always sign in to fix that.
func (s *Server) checkBuiltinPassword(pw string, allowLocal bool) bool {
	if s.SharedUsers == nil {
		return s.conf().CheckPassword(s.conf().Auth.AdminUser, pw)
	}
	if bcrypt.CompareHashAndPassword([]byte(s.builtinHash()), []byte(pw)) == nil {
		return true
	}
	if allowLocal && s.sharedPaused() && s.SharedUsers.LocalHash != nil {
		if h := s.SharedUsers.LocalHash(); h != "" {
			return bcrypt.CompareHashAndPassword([]byte(h), []byte(pw)) == nil
		}
	}
	return false
}

// sharedPaused reports whether the shared settings cannot be written on
// this server now.
func (s *Server) sharedPaused() bool {
	return s.Shared != nil && s.Shared.Writable() != nil
}

// usersWritable refuses a change of users or directory settings kept in
// the shared settings while they cannot be written (503). On a server
// that keeps them in its own files it always allows.
func (s *Server) usersWritable(w http.ResponseWriter) bool {
	if s.SharedUsers == nil || s.Shared == nil {
		return true
	}
	return s.sharedWritable(w)
}

// changeContext names the signed-in user as who makes the changes made
// with it, which the shared settings record.
func changeContext(r *http.Request) context.Context {
	return users.WithActor(r.Context(), userOf(r))
}

// setSessionCookie gives the browser a session's cookie; a remembered
// session's lasts as long as the session.
func (s *Server) setSessionCookie(w http.ResponseWriter, r *http.Request, token string, remember bool) {
	c := &http.Cookie{Name: s.cookieName(r), Value: token, Path: "/", HttpOnly: true,
		SameSite: http.SameSiteStrictMode, Secure: s.secureCookie(r)}
	if remember {
		c.MaxAge = int(s.sessions().MaxAge().Seconds())
	}
	http.SetCookie(w, c)
}
