package users

import (
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"net/mail"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode"

	"golang.org/x/crypto/bcrypt"
)

// Where a user's password is checked.
const (
	// SourceLocal users have a password stored by Signalith.
	SourceLocal = "local"
	// SourceDirectory users sign in with their LDAP or Active Directory
	// password; Signalith keeps a record of them from their first sign-in.
	SourceDirectory = "directory"
	// SourceBuiltin is the admin account from signalith.yaml. It is never
	// stored here; the API lists it so people can see it exists.
	SourceBuiltin = "builtin"
)

// User is one person who can sign in. It never holds a password hash.
type User struct {
	// Username is lower case and unique; sign-in ignores case.
	Username string `json:"username"`
	Name     string `json:"name,omitempty"`
	Email    string `json:"email,omitempty"`
	Role     Role   `json:"role"`
	Source   string `json:"source"`
	// Disabled users cannot sign in, and their sessions end.
	Disabled bool `json:"disabled,omitempty"`
	// MustChangePassword sends the user to choose a new password right
	// after signing in, and refuses everything else until they do.
	MustChangePassword bool `json:"must_change_password,omitempty"`
	// DN is a directory user's entry, as found at their last sign-in.
	DN         string     `json:"dn,omitempty"`
	Created    time.Time  `json:"created"`
	Updated    time.Time  `json:"updated"`
	LastSignIn *time.Time `json:"last_sign_in,omitempty"`
}

// NewUser is what an admin enters to add a local user.
type NewUser struct {
	Username           string
	Name               string
	Email              string
	Role               Role
	Password           string
	MustChangePassword bool
}

// Change edits a user; nil fields stay as they are.
type Change struct {
	Name     *string
	Email    *string
	Role     *Role
	Disabled *bool
}

var (
	ErrNotFound = errors.New("there is no user with that name")
	ErrExists   = errors.New("that username is taken; choose another")
	// ErrLastAdmin stops a change that would leave nobody able to manage
	// Signalith.
	ErrLastAdmin = errors.New("Signalith needs at least one enabled admin; make someone else an admin first")
	// ErrManaged refuses edits to what the directory decides.
	ErrManaged = errors.New("the name, email, role and password of directory users come from the directory; here you can only disable or delete them")
	// ErrReserved refuses the built-in admin's name.
	ErrReserved = errors.New("that name belongs to the built-in admin from signalith.yaml; choose another")
)

// FieldError is a value that cannot be used, with the field it belongs
// to (username, name, email, role or password), so a form can mark it.
type FieldError struct {
	Field string
	Err   error
}

func (e *FieldError) Error() string { return e.Err.Error() }
func (e *FieldError) Unwrap() error { return e.Err }

func fieldError(field string, err error) error {
	if err == nil {
		return nil
	}
	return &FieldError{Field: field, Err: err}
}

var usernamePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9._@-]{0,63}$`)

// NormalizeUsername returns the stored form of a username: trimmed and
// lower case.
func NormalizeUsername(name string) string { return strings.ToLower(strings.TrimSpace(name)) }

// ValidUsername checks a new local username.
func ValidUsername(name string) error {
	if !usernamePattern.MatchString(name) {
		return errors.New("usernames are 1-64 letters, digits, dots, dashes, underscores or @, starting with a letter or digit")
	}
	return nil
}

func validName(name string) error {
	if len([]rune(name)) > 100 {
		return errors.New("keep the name under 100 characters")
	}
	for _, r := range name {
		if unicode.IsControl(r) {
			return errors.New("the name cannot contain control characters")
		}
	}
	return nil
}

func validEmail(email string) error {
	if email == "" {
		return nil
	}
	a, err := mail.ParseAddress(email)
	if err != nil || a.Address != email || len(email) > 254 {
		return fmt.Errorf("%q is not an email address like name@example.com", email)
	}
	return nil
}

// MinPasswordLength is the shortest password Signalith accepts.
const MinPasswordLength = 8

// HashPassword returns a bcrypt hash of a new password, after checking its
// length. bcrypt reads at most 72 bytes, so longer passwords are refused
// rather than silently cut.
func HashPassword(pw string) (string, error) {
	if len([]rune(pw)) < MinPasswordLength {
		return "", fmt.Errorf("password must be at least %d characters", MinPasswordLength)
	}
	if len(pw) > 72 {
		return "", errors.New("password must be at most 72 bytes (bcrypt reads no more)")
	}
	h, err := bcrypt.GenerateFromPassword([]byte(pw), bcrypt.DefaultCost)
	return string(h), err
}

// dummyHash is compared against when a user does not exist, so a wrong
// username takes as long to refuse as a wrong password.
var dummyHash = sync.OnceValue(func() []byte {
	h, _ := bcrypt.GenerateFromPassword([]byte("not-a-real-password"), bcrypt.DefaultCost)
	return h
})

// WasteTime does the work of checking a password without a user, so
// sign-in failures take the same time whatever the reason.
func WasteTime(pw string) { _ = bcrypt.CompareHashAndPassword(dummyHash(), []byte(pw)) }

// GeneratePassword returns a random temporary password such as
// "kq7m-3xhp-9tvd-w2fa": 16 characters (about 79 bits) from letters and
// digits that are hard to confuse, in groups of four to read out easily.
func GeneratePassword() string {
	const alphabet = "abcdefghjkmnpqrstuvwxyz23456789"
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	var sb strings.Builder
	for i, v := range b {
		if i > 0 && i%4 == 0 {
			sb.WriteByte('-')
		}
		// 256 is not a multiple of 31; rejection sampling would remove the
		// slight bias, but it costs well under a bit of the 79.
		sb.WriteByte(alphabet[int(v)%len(alphabet)])
	}
	return sb.String()
}

// Store keeps users in a JSON file. Writes go to a temporary file that is
// renamed over the old one, so a crash never leaves half a file.
type Store struct {
	// BuiltinAdmin is the built-in admin's name from signalith.yaml. The
	// name is reserved, and that account always counts as an enabled admin.
	BuiltinAdmin string
	Now          func() time.Time

	path        string
	mu          sync.RWMutex
	users       map[string]*User
	hashes      map[string]string // username -> bcrypt hash, local users only
	builtinLast *time.Time
}

// storedUser is a user as written to the file, with the password hash.
type storedUser struct {
	User
	PasswordHash string `json:"password_hash,omitempty"`
}

type storeFile struct {
	Version           int          `json:"version"`
	Users             []storedUser `json:"users"`
	BuiltinLastSignIn *time.Time   `json:"builtin_last_sign_in,omitempty"`
}

// NewMemory returns a store that keeps users only in memory.
func NewMemory() *Store {
	return &Store{Now: time.Now, users: map[string]*User{}, hashes: map[string]string{}}
}

// Open loads the users file, or starts empty if it does not exist yet.
// A file that cannot be read is an error rather than an empty list, so a
// damaged file is never overwritten.
func Open(path string) (*Store, error) {
	s := NewMemory()
	s.path = path
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return s, nil
	}
	if err != nil {
		return nil, err
	}
	var f storeFile
	if err := json.Unmarshal(data, &f); err != nil {
		return nil, fmt.Errorf("users file %s is damaged (%v); fix it, or move it away to start with only the built-in admin", path, err)
	}
	for _, su := range f.Users {
		u := su.User
		u.Username = NormalizeUsername(u.Username)
		if u.Username == "" || s.users[u.Username] != nil {
			return nil, fmt.Errorf("users file %s lists an empty or repeated username %q", path, su.Username)
		}
		if u.Source != SourceDirectory {
			u.Source = SourceLocal
		}
		if !u.Role.Valid() {
			// An unknown role grants nothing.
			u.Role = Viewer
		}
		s.users[u.Username] = &u
		if su.PasswordHash != "" && u.Source == SourceLocal {
			s.hashes[u.Username] = su.PasswordHash
		}
	}
	s.builtinLast = f.BuiltinLastSignIn
	return s, nil
}

// Path returns the users file, or "" for a memory-only store.
func (s *Store) Path() string { return s.path }

func (s *Store) now() time.Time {
	if s.Now != nil {
		return s.Now().UTC()
	}
	return time.Now().UTC()
}

// saveLocked writes the file; the caller holds the write lock.
func (s *Store) saveLocked() error {
	if s.path == "" {
		return nil
	}
	f := storeFile{Version: 1, Users: make([]storedUser, 0, len(s.users)), BuiltinLastSignIn: s.builtinLast}
	for _, name := range s.sortedNamesLocked() {
		f.Users = append(f.Users, storedUser{User: *s.users[name], PasswordHash: s.hashes[name]})
	}
	data, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		return err
	}
	return WriteFileAtomic(s.path, append(data, '\n'))
}

// WriteFileAtomic writes data readable only by its owner (mode 0600 on
// Linux; on Windows the folder's permissions apply), through a temporary
// file in the same folder that is then renamed into place.
func WriteFileAtomic(name string, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(name), 0o750); err != nil {
		return err
	}
	// CreateTemp makes the file with mode 0600.
	tmp, err := os.CreateTemp(filepath.Dir(name), ".tmp-"+filepath.Base(name)+"-*")
	if err != nil {
		return err
	}
	fail := func(err error) error {
		tmp.Close()
		os.Remove(tmp.Name())
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		return fail(err)
	}
	if err := tmp.Sync(); err != nil {
		return fail(err)
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmp.Name())
		return err
	}
	if err := os.Rename(tmp.Name(), name); err != nil {
		os.Remove(tmp.Name())
		return err
	}
	return nil
}

func (s *Store) sortedNamesLocked() []string {
	names := make([]string, 0, len(s.users))
	for n := range s.users {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}

// Get returns a user by name, ignoring case.
func (s *Store) Get(name string) (User, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	u, ok := s.users[NormalizeUsername(name)]
	if !ok {
		return User{}, false
	}
	return *u, true
}

// List returns every user, sorted by username.
func (s *Store) List() []User {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]User, 0, len(s.users))
	for _, n := range s.sortedNamesLocked() {
		out = append(out, *s.users[n])
	}
	return out
}

func (s *Store) reserved(name string) bool {
	return s.BuiltinAdmin != "" && strings.EqualFold(name, s.BuiltinAdmin)
}

// Create adds a local user.
func (s *Store) Create(in NewUser) (User, error) {
	name := NormalizeUsername(in.Username)
	if err := ValidUsername(name); err != nil {
		return User{}, fieldError("username", err)
	}
	if s.reserved(name) {
		return User{}, fieldError("username", ErrReserved)
	}
	if _, taken := s.Get(name); taken {
		return User{}, fieldError("username", ErrExists)
	}
	in.Name, in.Email = strings.TrimSpace(in.Name), strings.TrimSpace(in.Email)
	if err := validName(in.Name); err != nil {
		return User{}, fieldError("name", err)
	}
	if err := validEmail(in.Email); err != nil {
		return User{}, fieldError("email", err)
	}
	if !in.Role.Valid() {
		return User{}, fieldError("role", fmt.Errorf("role %q must be viewer, analyst or admin", in.Role))
	}
	hash, err := HashPassword(in.Password)
	if err != nil {
		return User{}, fieldError("password", err)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.users[name]; ok {
		return User{}, fieldError("username", ErrExists)
	}
	now := s.now()
	u := &User{Username: name, Name: in.Name, Email: in.Email, Role: in.Role, Source: SourceLocal,
		MustChangePassword: in.MustChangePassword, Created: now, Updated: now}
	s.users[name], s.hashes[name] = u, hash
	if err := s.saveLocked(); err != nil {
		delete(s.users, name)
		delete(s.hashes, name)
		return User{}, err
	}
	return *u, nil
}

// adminsLeftLocked counts the enabled admins if the named user had role
// and disabled instead. The built-in admin always counts.
func (s *Store) adminsLeftLocked(name string, role Role, disabled bool) int {
	n := 0
	if s.BuiltinAdmin != "" {
		n++
	}
	for _, u := range s.users {
		r, off := u.Role, u.Disabled
		if u.Username == name {
			r, off = role, disabled
		}
		// Directory users' roles depend on groups that may have changed
		// since they last signed in, so only local admins count.
		if u.Source == SourceLocal && r == Admin && !off {
			n++
		}
	}
	return n
}

// Update changes a user's details, role or disabled state. Directory
// users can only be disabled or enabled.
func (s *Store) Update(name string, ch Change) (User, error) {
	name = NormalizeUsername(name)
	s.mu.Lock()
	defer s.mu.Unlock()
	cur, ok := s.users[name]
	if !ok {
		return User{}, ErrNotFound
	}
	u := *cur
	if ch.Name != nil {
		u.Name = strings.TrimSpace(*ch.Name)
	}
	if ch.Email != nil {
		u.Email = strings.TrimSpace(*ch.Email)
	}
	if ch.Role != nil {
		u.Role = *ch.Role
	}
	if ch.Disabled != nil {
		u.Disabled = *ch.Disabled
	}
	if cur.Source == SourceDirectory && (u.Name != cur.Name || u.Email != cur.Email || u.Role != cur.Role) {
		return User{}, ErrManaged
	}
	if err := validName(u.Name); err != nil {
		return User{}, fieldError("name", err)
	}
	if err := validEmail(u.Email); err != nil {
		return User{}, fieldError("email", err)
	}
	if !u.Role.Valid() {
		return User{}, fieldError("role", fmt.Errorf("role %q must be viewer, analyst or admin", u.Role))
	}
	wasAdmin := cur.Source == SourceLocal && cur.Role == Admin && !cur.Disabled
	if wasAdmin && (u.Role != Admin || u.Disabled) && s.adminsLeftLocked(name, u.Role, u.Disabled) == 0 {
		return User{}, ErrLastAdmin
	}
	if u == *cur {
		return u, nil
	}
	u.Updated = s.now()
	s.users[name] = &u
	if err := s.saveLocked(); err != nil {
		s.users[name] = cur
		return User{}, err
	}
	return u, nil
}

// Delete removes a user and returns what was removed.
func (s *Store) Delete(name string) (User, error) {
	name = NormalizeUsername(name)
	s.mu.Lock()
	defer s.mu.Unlock()
	cur, ok := s.users[name]
	if !ok {
		return User{}, ErrNotFound
	}
	if cur.Source == SourceLocal && cur.Role == Admin && !cur.Disabled && s.adminsLeftLocked(name, Viewer, true) == 0 {
		return User{}, ErrLastAdmin
	}
	hash := s.hashes[name]
	delete(s.users, name)
	delete(s.hashes, name)
	if err := s.saveLocked(); err != nil {
		s.users[name] = cur
		if hash != "" {
			s.hashes[name] = hash
		}
		return User{}, err
	}
	return *cur, nil
}

// SetPassword gives a local user a new password. mustChange makes it a
// temporary one the user replaces at their next sign-in.
func (s *Store) SetPassword(name, password string, mustChange bool) (User, error) {
	name = NormalizeUsername(name)
	if u, ok := s.Get(name); !ok {
		return User{}, ErrNotFound
	} else if u.Source != SourceLocal {
		return User{}, ErrManaged
	}
	hash, err := HashPassword(password)
	if err != nil {
		return User{}, fieldError("password", err)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	cur, ok := s.users[name]
	if !ok {
		return User{}, ErrNotFound
	}
	if cur.Source != SourceLocal {
		return User{}, ErrManaged
	}
	u, oldHash := *cur, s.hashes[name]
	u.MustChangePassword = mustChange
	u.Updated = s.now()
	s.users[name], s.hashes[name] = &u, hash
	if err := s.saveLocked(); err != nil {
		s.users[name], s.hashes[name] = cur, oldHash
		return User{}, err
	}
	return u, nil
}

// CheckPassword reports whether password is the local user's password. It
// takes as long for a user that does not exist.
func (s *Store) CheckPassword(name, password string) bool {
	s.mu.RLock()
	hash, ok := s.hashes[NormalizeUsername(name)]
	s.mu.RUnlock()
	if !ok {
		WasteTime(password)
		return false
	}
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)) == nil
}

// PasswordVersion changes whenever the user's password does, so a cache
// of checked passwords can include it in its keys.
func (s *Store) PasswordVersion(name string) string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.hashes[NormalizeUsername(name)]
}

// signInWrites limits how often a sign-in time is written, so a script
// signing in on every request does not rewrite the file each time.
const signInWrites = time.Minute

// RecordSignIn notes when a user signed in.
func (s *Store) RecordSignIn(name string) {
	name = NormalizeUsername(name)
	s.mu.Lock()
	defer s.mu.Unlock()
	cur, ok := s.users[name]
	if !ok {
		return
	}
	now := s.now()
	if cur.LastSignIn != nil && now.Sub(*cur.LastSignIn) < signInWrites {
		return
	}
	u := *cur
	u.LastSignIn = &now
	s.users[name] = &u
	if err := s.saveLocked(); err != nil {
		s.users[name] = cur
	}
}

// RecordBuiltinSignIn notes when the built-in admin signed in.
func (s *Store) RecordBuiltinSignIn() {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	if s.builtinLast != nil && now.Sub(*s.builtinLast) < signInWrites {
		return
	}
	prev := s.builtinLast
	s.builtinLast = &now
	if err := s.saveLocked(); err != nil {
		s.builtinLast = prev
	}
}

// BuiltinLastSignIn returns when the built-in admin last signed in.
func (s *Store) BuiltinLastSignIn() *time.Time {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.builtinLast
}

// SeeDirectoryUser records a directory user who just signed in: added on
// their first sign-in, then kept up to date with the name, email and role
// the directory gives. A disabled user is returned unchanged, and a name
// taken by a local user is refused.
func (s *Store) SeeDirectoryUser(d DirectoryUser) (User, error) {
	name := NormalizeUsername(d.Username)
	if name == "" || s.reserved(name) {
		return User{}, ErrReserved
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	cur, ok := s.users[name]
	if ok && cur.Source != SourceDirectory {
		return User{}, ErrExists
	}
	if ok && cur.Disabled {
		return *cur, nil
	}
	u := User{Username: name, Source: SourceDirectory, Created: now}
	if ok {
		u = *cur
	}
	changed := !ok || u.Name != d.Name || u.Email != d.Email || u.Role != d.Role || u.DN != d.DN
	u.Name, u.Email, u.Role, u.DN = d.Name, d.Email, d.Role, d.DN
	if changed {
		u.Updated = now
	}
	if !changed && u.LastSignIn != nil && now.Sub(*u.LastSignIn) < signInWrites {
		return u, nil
	}
	u.LastSignIn = &now
	s.users[name] = &u
	if err := s.saveLocked(); err != nil {
		if ok {
			s.users[name] = cur
		} else {
			delete(s.users, name)
		}
		return User{}, err
	}
	return u, nil
}

// Count returns how many users come from each source.
func (s *Store) Count() map[string]int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := map[string]int{SourceLocal: 0, SourceDirectory: 0}
	for _, u := range s.users {
		out[u.Source]++
	}
	return out
}
