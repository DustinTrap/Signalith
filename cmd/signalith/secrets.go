package main

// "signalith secrets" shows where the master key is and how each stored
// password or key is kept, encrypts those still in plain text, stores one
// without showing it, and changes the master key. See docs/encryption.md.

import (
	"bytes"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"slices"
	"strings"

	"github.com/jrsamsanchez/signalith/internal/config"
	"github.com/jrsamsanchez/signalith/internal/intel"
	"github.com/jrsamsanchez/signalith/internal/secrets"
	"github.com/jrsamsanchez/signalith/internal/securefile"
	"github.com/jrsamsanchez/signalith/internal/users"
)

const secretsUsage = `Usage:
  signalith secrets status         [-c file]   where the master key is, and how each password or key is stored
  signalith secrets encrypt        [-c file]   encrypt the passwords and keys stored as plain text
  signalith secrets set <setting>  [-c file]   store a password or key, encrypted; asks for it without
                                               showing it, or reads one line from a pipe
  signalith secrets rotate-master  [-c file]   make a new master key and encrypt everything again with it
  signalith secrets rotate-master -prune [-c file]   remove the previous master key once nothing uses it

Settings for "set": opensearch.password, assistant.api_key, auth.ldap.bind_password,
and ingest.tokens (adds a token; leave it empty to have one made).
See docs/encryption.md.
`

// secretEnv are the environment variables that replace a setting "set"
// stores. Their values are used as they are and never written to a file.
var secretEnv = map[string]string{
	"opensearch.password":     "SIGNALITH_OPENSEARCH_PASSWORD",
	"assistant.api_key":       "SIGNALITH_ASSISTANT_API_KEY",
	"auth.ldap.bind_password": "SIGNALITH_LDAP_BIND_PASSWORD",
	"ingest.tokens":           "SIGNALITH_INGEST_TOKEN",
}

func cmdSecrets(args []string) error {
	return runSecrets(args, os.Stdin, os.Stdout)
}

// runSecrets runs a secrets subcommand, reading a value from in and
// writing to out.
func runSecrets(args []string, in *os.File, out io.Writer) error {
	if len(args) == 0 {
		fmt.Fprint(out, secretsUsage)
		return errors.New("name a secrets command")
	}
	sub, rest := args[0], args[1:]
	if sub == "help" || sub == "-h" || sub == "--help" {
		fmt.Fprint(out, secretsUsage)
		return nil
	}
	if !slices.Contains([]string{"status", "encrypt", "set", "rotate-master"}, sub) {
		fmt.Fprint(out, secretsUsage)
		return fmt.Errorf("unknown secrets command %q", sub)
	}
	fs := flag.NewFlagSet("secrets "+sub, flag.ContinueOnError)
	fs.SetOutput(out)
	fs.Usage = func() { fmt.Fprint(out, secretsUsage) }
	path := configFlag(fs)
	prune := false
	if sub == "rotate-master" {
		fs.BoolVar(&prune, "prune", false, "remove the previous master key")
	}
	names, err := parseInterspersed(fs, rest)
	if err != nil {
		return err
	}
	if sub != "set" && len(names) > 0 {
		return fmt.Errorf("signalith secrets %s takes no arguments, only -c file", sub)
	}
	if sub == "set" {
		if len(names) != 1 {
			return fmt.Errorf("name the setting to store, one of: %s", strings.Join(config.SettableSecrets, ", "))
		}
		if !slices.Contains(config.SettableSecrets, names[0]) {
			return fmt.Errorf("%s cannot be set this way; the settings are: %s", names[0], strings.Join(config.SettableSecrets, ", "))
		}
	}
	c, err := secretsConfig(*path, out)
	if err != nil {
		return err
	}
	switch sub {
	case "status":
		return secretsStatus(c, out)
	case "encrypt":
		return secretsEncrypt(c, out)
	case "set":
		return secretsSet(c, names[0], in, out)
	}
	if prune {
		return secretsPrune(c, out)
	}
	return secretsRotate(c, out)
}

// parseInterspersed parses flags that may come before or after the
// arguments, as in "set opensearch.password -c file", and returns the
// arguments.
func parseInterspersed(fs *flag.FlagSet, args []string) ([]string, error) {
	var names []string
	for {
		if err := fs.Parse(args); err != nil {
			return nil, err
		}
		if fs.NArg() == 0 {
			return names, nil
		}
		names = append(names, fs.Arg(0))
		args = fs.Args()[1:]
	}
}

// secretsConfig loads the config file without decrypting it, so these
// commands work even when some values cannot be decrypted, and makes its
// master key the one the other files use. On Linux the folders the
// signalith service is given in its unit are used too, so the command
// finds the server's files and key (see serviceEnv).
func secretsConfig(path string, out io.Writer) (*config.Config, error) {
	if set := applyServiceEnv(path); len(set) > 0 {
		fmt.Fprintf(out, "Using the folders the signalith service is given (systemctl show signalith):\n  %s\n\n", strings.Join(set, "\n  "))
	}
	c, err := config.LoadUnchecked(path)
	if err != nil {
		return nil, err
	}
	keys := c.Keyring()
	keys.OnCreate = func(src secrets.Source) {
		fmt.Fprintf(out, "Made a new master key: %s.\nBack it up: without it the stored passwords and keys cannot be read (events are not affected).\n\n", src)
	}
	secrets.SetDefault(keys)
	return c, nil
}

// useKeys makes the config's master key the one the files the server
// writes are encrypted with, and logs where a new one is made.
func useKeys(c *config.Config, log *slog.Logger) {
	keys := c.Keyring()
	keys.OnCreate = func(src secrets.Source) {
		log.Warn("made a new master key for the passwords and keys Signalith stores; back it up, since without it they cannot be read (events are not affected)",
			"key", src.String(), "key_id", src.KeyID)
	}
	secrets.SetDefault(keys)
}

// secretFile is a file that keeps passwords or keys.
type secretFile struct {
	path string
	// reseal passes each stored value through a secrets.Reseal.
	reseal func([]byte, secrets.Reseal) ([]byte, int, error)
	// server is true for the files the server writes. It also encrypts
	// their plain values when it starts.
	server bool
}

// secretFiles lists the files with passwords or keys: signalith.yaml,
// which only these commands and "signalith init" write, then the files
// the server keeps.
func secretFiles(c *config.Config) []secretFile {
	return []secretFile{
		{path: c.Path(), reseal: config.ResealFile},
		{path: c.DirectoryFile(), reseal: users.ResealDirectoryFile, server: true},
		{path: c.IntelFeedsFile(), reseal: intel.ResealFeedsFile, server: true},
	}
}

// listSecrets returns the values stored in a file's text.
func listSecrets(f secretFile, data []byte) ([]secrets.Stored, error) {
	var out []secrets.Stored
	_, _, err := f.reseal(data, func(s secrets.Stored) (string, error) {
		out = append(out, s)
		return s.Value, nil
	})
	return out, err
}

// whyUnreadable says briefly why a value cannot be decrypted.
func whyUnreadable(err error) string {
	var oe *secrets.OpenError
	switch {
	case errors.As(err, &oe) && oe.Reason != "":
		return oe.Reason
	case errors.As(err, &oe) && oe.KeyID != "":
		return "encrypted with master key " + oe.KeyID + ", which is not here"
	case err != nil:
		return err.Error()
	}
	return ""
}

func secretsStatus(c *config.Config, out io.Writer) error {
	keys := c.Keyring()
	src, err := keys.Source()
	switch {
	case errors.Is(err, secrets.ErrNoKey):
		fmt.Fprintf(out, "Master key:    none yet. Signalith makes one in %s\n               the first time it stores a password or key.\n", keys.DefaultPath())
	case err != nil:
		fmt.Fprintf(out, "Master key:    cannot be read: %v\n", err)
	default:
		fmt.Fprintf(out, "Master key:    %s, key id %s\n", src, src.KeyID)
		if src.Weak() {
			fmt.Fprintln(out, "               Warning: other programs can sometimes read environment variables;\n               put the key in a file and set SIGNALITH_MASTER_KEY_FILE instead.")
		}
		switch {
		case src.OldErr != "":
			fmt.Fprintf(out, "Previous key:  %s cannot be read: %s\n", src.OldPath, src.OldErr)
		case src.OldPath != "":
			fmt.Fprintf(out, "Previous key:  %s, key id %s\n               kept after rotate-master; remove it with: signalith secrets rotate-master -prune\n", src.OldPath, src.OldKeyID)
		}
	}
	for _, p := range keys.Unused() {
		fmt.Fprintf(out, "Note:          %s is another master key, not used\n", p)
	}

	counts := map[secrets.State]int{}
	for _, f := range secretFiles(c) {
		data, err := os.ReadFile(f.path)
		if errors.Is(err, os.ErrNotExist) {
			fmt.Fprintf(out, "\n%s\n  not there yet\n", f.path)
			continue
		}
		if err != nil {
			return err
		}
		list, err := listSecrets(f, data)
		if err != nil {
			return fmt.Errorf("%s: %w", f.path, err)
		}
		fmt.Fprintf(out, "\n%s\n", f.path)
		if len(list) == 0 {
			fmt.Fprintln(out, "  no passwords or keys")
		}
		width := 0
		for _, s := range list {
			width = max(width, len(s.Label))
		}
		for _, s := range list {
			st, err := keys.Check(s.Field, s.Value)
			counts[st]++
			line := fmt.Sprintf("  %-*s  %s", width, s.Label, st)
			if st == secrets.Unreadable {
				line = fmt.Sprintf("  %-*s  cannot be decrypted: %s", width, s.Label, whyUnreadable(err))
			}
			fmt.Fprintln(out, line)
		}
	}
	var env []string
	for _, name := range []string{"SIGNALITH_OPENSEARCH_PASSWORD", "SIGNALITH_ADMIN_PASSWORD", "SIGNALITH_INGEST_TOKEN", "SIGNALITH_ASSISTANT_API_KEY", "SIGNALITH_LDAP_BIND_PASSWORD"} {
		if os.Getenv(name) != "" {
			env = append(env, name)
		}
	}
	if len(env) > 0 {
		fmt.Fprintf(out, "\nFrom this shell's environment (used as they are, never written to a file):\n  %s\n", strings.Join(env, ", "))
	}

	fmt.Fprintf(out, "\n%d encrypted", counts[secrets.Current])
	if n := counts[secrets.Previous]; n > 0 {
		fmt.Fprintf(out, ", %d with the previous master key", n)
	}
	fmt.Fprintf(out, ", %d plain text", counts[secrets.Plain])
	if n := counts[secrets.Unreadable]; n > 0 {
		fmt.Fprintf(out, ", %d cannot be decrypted", n)
	}
	fmt.Fprintln(out, ".")
	if counts[secrets.Plain]+counts[secrets.Previous] > 0 {
		fmt.Fprintln(out, "Run: signalith secrets encrypt")
	}
	if n := counts[secrets.Unreadable]; n > 0 {
		return fmt.Errorf("%d stored %s cannot be decrypted with this master key; restore the key they were encrypted with, "+
			"or enter them again (signalith secrets set, or the page where they were added)", n, plural(n, "value", "values"))
	}
	return nil
}

// rewrite is a file whose stored values change.
type rewrite struct {
	path     string
	old, new []byte
	n        int
	pending  *securefile.Pending
}

// Seams for tests that make a write fail.
var (
	prepareFile = securefile.Prepare
	commitFile  = (*securefile.Pending).Commit
)

// writeAll writes every changed file, or none. Each is first written next
// to its place, and checked not to have changed since it was read (the
// server may save one meanwhile); then key runs, if set (it puts a new
// master key in place), and the files are put in place. If one cannot be,
// those already in place get their old text back and undo runs.
func writeAll(list []*rewrite, key, undo func() error) error {
	var todo []*rewrite
	for _, r := range list {
		if r.n > 0 {
			todo = append(todo, r)
		}
	}
	discard := func(rs []*rewrite) {
		for _, r := range rs {
			if r.pending != nil {
				r.pending.Discard()
			}
		}
	}
	for _, r := range todo {
		p, err := prepareFile(r.path, r.new)
		if err != nil {
			discard(todo)
			return fmt.Errorf("could not write %s: %w. Nothing was changed", r.path, err)
		}
		r.pending = p
	}
	for _, r := range todo {
		if now, err := os.ReadFile(r.path); err != nil || !bytes.Equal(now, r.old) {
			discard(todo)
			return fmt.Errorf("%s changed while this ran (the server may have saved it). Nothing was changed; run the command again", r.path)
		}
	}
	if key != nil {
		if err := key(); err != nil {
			discard(todo)
			return fmt.Errorf("%w. Nothing was changed", err)
		}
	}
	for i, r := range todo {
		err := commitFile(r.pending)
		if err == nil {
			continue
		}
		discard(todo[i+1:])
		var stuck []string
		for _, done := range todo[:i] {
			if werr := securefile.WriteFile(done.path, done.old); werr != nil {
				stuck = append(stuck, fmt.Sprintf("%s (%v)", done.path, werr))
			}
		}
		if undo != nil {
			if uerr := undo(); uerr != nil {
				stuck = append(stuck, uerr.Error())
			}
		}
		if len(stuck) > 0 {
			return fmt.Errorf("could not write %s: %w. Putting back what was already changed failed too: %s", r.path, err, strings.Join(stuck, "; "))
		}
		return fmt.Errorf("could not write %s: %w. Nothing was changed", r.path, err)
	}
	return nil
}

func secretsEncrypt(c *config.Config, out io.Writer) error {
	keys := c.Keyring()
	var list []*rewrite
	var unreadable []string
	for _, f := range secretFiles(c) {
		data, err := os.ReadFile(f.path)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return err
		}
		next, n, err := f.reseal(data, func(s secrets.Stored) (string, error) {
			st, _ := keys.Check(s.Field, s.Value)
			switch st {
			case secrets.Plain:
				return keys.Seal(s.Field, s.Value)
			case secrets.Previous:
				plain, err := keys.Open(s.Field, s.Value)
				if err != nil {
					return "", err
				}
				return keys.Seal(s.Field, plain)
			case secrets.Unreadable:
				unreadable = append(unreadable, s.Label+" in "+f.path)
			}
			return s.Value, nil
		})
		if err != nil {
			return fmt.Errorf("%s: %w", f.path, err)
		}
		list = append(list, &rewrite{path: f.path, old: data, new: next, n: n})
	}
	if err := writeAll(list, nil, nil); err != nil {
		return err
	}
	total := 0
	for _, r := range list {
		if r.n > 0 {
			fmt.Fprintf(out, "Encrypted %d %s in %s\n", r.n, plural(r.n, "value", "values"), r.path)
			total += r.n
		}
	}
	if total == 0 {
		fmt.Fprintln(out, "Nothing to encrypt: every stored password and key is already encrypted with the master key in use.")
	} else if src, err := keys.Source(); err == nil {
		fmt.Fprintf(out, "Master key: %s, key id %s\n", src, src.KeyID)
	}
	if len(unreadable) > 0 {
		return leftAsIs(unreadable)
	}
	return nil
}

// leftAsIs reports stored values that could not be decrypted, and so
// were not changed.
func leftAsIs(list []string) error {
	if len(list) == 1 {
		return fmt.Errorf("1 stored value cannot be decrypted and was left as it was: %s. Restore the master key it was encrypted with, or enter it again", list[0])
	}
	return fmt.Errorf("%d stored values cannot be decrypted and were left as they were: %s. Restore the master key they were encrypted with, or enter them again",
		len(list), strings.Join(list, ", "))
}

func plural(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}

func secretsSet(c *config.Config, field string, in *os.File, out io.Writer) error {
	label := "New value for " + field + ": "
	if field == "ingest.tokens" {
		label = "New ingest token (press Enter to have one made): "
	}
	value, err := readSecret(in, out, label, field == "ingest.tokens")
	if err != nil {
		return err
	}
	made := value == ""
	if made {
		value = config.RandomToken(24)
	}
	if err := config.SetSecret(c.Path(), field, value, c.Keyring()); err != nil {
		return err
	}
	if field == "ingest.tokens" {
		if made {
			fmt.Fprintf(out, "Added this ingest token, encrypted, to %s:\n\n  %s\n\nIt is shown only now; give it to the agents that send data.\n", c.Path(), value)
		} else {
			fmt.Fprintf(out, "Added the ingest token, encrypted, to %s.\n", c.Path())
		}
	} else {
		fmt.Fprintf(out, "Saved %s, encrypted, in %s.\n", field, c.Path())
	}
	fmt.Fprintln(out, "Restart the server to use it.")
	if env := secretEnv[field]; env != "" && os.Getenv(env) != "" {
		fmt.Fprintf(out, "Note: %s is set in this environment; wherever it is set for the server, it is used instead of the file.\n", env)
	}
	return nil
}

func secretsRotate(c *config.Config, out io.Writer) error {
	keys := c.Keyring()
	before, err := keys.Source()
	if err != nil && !errors.Is(err, secrets.ErrNoKey) {
		return err
	}
	r, err := keys.BeginRotation()
	if err != nil {
		return err
	}
	committed := false
	defer func() {
		if !committed {
			r.Discard()
		}
	}()
	var list []*rewrite
	var unreadable []string
	for _, f := range secretFiles(c) {
		data, err := os.ReadFile(f.path)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return err
		}
		next, n, err := f.reseal(data, func(s secrets.Stored) (string, error) {
			plain, err := keys.Open(s.Field, s.Value)
			if err != nil {
				unreadable = append(unreadable, s.Label+" in "+f.path)
				return s.Value, nil
			}
			return r.Seal(s.Field, plain)
		})
		if err != nil {
			return fmt.Errorf("%s: %w", f.path, err)
		}
		list = append(list, &rewrite{path: f.path, old: data, new: next, n: n})
	}
	err = writeAll(list, func() error {
		if err := r.Commit(); err != nil {
			return err
		}
		committed = true
		return nil
	}, r.Undo)
	if err != nil {
		return err
	}
	r.Done()
	fmt.Fprintf(out, "New master key %s in %s.\n", r.KeyID(), r.Path())
	for _, w := range list {
		if w.n > 0 {
			fmt.Fprintf(out, "Encrypted %d %s again in %s\n", w.n, plural(w.n, "value", "values"), w.path)
		}
	}
	fmt.Fprintf(out, "The previous key (%s) is kept as %s.old, so files saved before now can still be read.\n", before.KeyID, r.Path())
	if keyIsCredential {
		fmt.Fprintln(out, "The service gets the key as a systemd credential, read when it starts; restart it now: sudo systemctl restart signalith")
	} else {
		fmt.Fprintln(out, "A running server picks up the new key by itself.")
	}
	fmt.Fprintln(out, "Next: back up the new key, then remove the previous one with: signalith secrets rotate-master -prune")
	if len(unreadable) > 0 {
		return leftAsIs(unreadable)
	}
	return nil
}

func secretsPrune(c *config.Config, out io.Writer) error {
	keys := c.Keyring()
	src, err := keys.Source()
	if err != nil {
		return err
	}
	if src.OldPath == "" {
		fmt.Fprintln(out, "There is no previous master key to remove.")
		return nil
	}
	var still []string
	for _, f := range secretFiles(c) {
		data, err := os.ReadFile(f.path)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return err
		}
		list, err := listSecrets(f, data)
		if err != nil {
			return fmt.Errorf("%s: %w", f.path, err)
		}
		for _, s := range list {
			if st, _ := keys.Check(s.Field, s.Value); st == secrets.Previous {
				still = append(still, s.Label+" in "+f.path)
			}
		}
	}
	if len(still) > 0 {
		return fmt.Errorf("%d stored %s still %s the previous master key: %s. Run: signalith secrets encrypt, then this again",
			len(still), plural(len(still), "value", "values"), plural(len(still), "needs", "need"), strings.Join(still, ", "))
	}
	removed, err := keys.RemoveOld()
	if err != nil {
		return err
	}
	fmt.Fprintf(out, "Removed the previous master key %s (key id %s).\n", removed, src.OldKeyID)
	fmt.Fprintln(out, "Backups of files from before the rotation now need a backup of that key to be read.")
	return nil
}

// encryptStores encrypts the plain values (and those still under the
// previous master key) in the files the server writes, once at startup.
// signalith.yaml is never changed by the server; Warnings report its plain
// values instead.
func encryptStores(c *config.Config, log *slog.Logger) {
	keys := c.Keyring()
	for _, f := range secretFiles(c) {
		if !f.server {
			continue
		}
		data, err := os.ReadFile(f.path)
		if err != nil {
			continue
		}
		next, n, err := f.reseal(data, func(s secrets.Stored) (string, error) {
			switch st, _ := keys.Check(s.Field, s.Value); st {
			case secrets.Plain:
				return keys.Seal(s.Field, s.Value)
			case secrets.Previous:
				plain, err := keys.Open(s.Field, s.Value)
				if err != nil {
					return s.Value, nil
				}
				return keys.Seal(s.Field, plain)
			}
			return s.Value, nil
		})
		if err != nil {
			log.Warn("could not encrypt the passwords and keys in a file; they stay as they are", "file", f.path, "err", err)
			continue
		}
		if n == 0 {
			continue
		}
		if err := securefile.WriteFile(f.path, next); err != nil {
			log.Warn("could not encrypt the passwords and keys in a file; they stay as they are until it can be written", "file", f.path, "err", err)
			continue
		}
		log.Info("encrypted the passwords and keys stored in a file", "file", f.path, "values", n)
	}
}
