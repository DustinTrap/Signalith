package security

import (
	"slices"
	"strings"
	"time"

	"github.com/jrsamsanchez/signalith/internal/config"
)

// checkBuiltinPassword: accounts.builtin_password.
func checkBuiltinPassword(f *Facts) *Check {
	a := f.Admin
	cfg := "/etc/signalith/signalith.yaml"
	if f.Config != nil && f.Config.Path() != "" && f.Server.OS != "windows" && !f.InContainer {
		cfg = f.Config.Path()
	}
	fix := &Fix{Steps: []string{"Set a password of its own for the built-in admin, then restart Signalith."},
		Commands: cmds("sudo signalith passwd -c "+sh(cfg)+" && sudo systemctl restart signalith",
			winExe+" passwd; Restart-Service Signalith",
			dockerCompose+" exec signalith signalith passwd\n"+dockerCompose+" restart signalith"),
		Docs: doc(docUsersBuiltin)}
	removeEnv := "Then remove SIGNALITH_ADMIN_PASSWORD from where Signalith is started."
	switch {
	case a.Public:
		fix.Steps = append(fix.Steps, removeEnv)
		return &Check{State: Risk, Line: "The built-in admin's password is change-me-please, an example anyone can look up.", Fix: fix}
	case a.DockerFirst:
		return &Check{State: Attention, Line: "The built-in admin still has the first password the Docker setup made, which is kept as plain text in a Docker volume.", Fix: fix}
	case a.FromEnv:
		fix.Steps = append(fix.Steps, removeEnv)
		return &Check{State: Attention, Line: "The built-in admin's password is set in the SIGNALITH_ADMIN_PASSWORD environment variable.", Fix: fix}
	case a.WeakHash:
		return &Check{State: Attention, Line: "The built-in admin's password is stored with a weaker hash than Signalith uses now. Set it again to store it the stronger way.", Fix: fix}
	}
	name := f.Users.BuiltinName
	if name == "" && f.Config != nil {
		name = f.Config.Auth.AdminUser
	}
	line := "The built-in admin (" + name + ") has a password of its own"
	if a.SetAt != nil {
		line += ", last set " + day(*a.SetAt)
	}
	return &Check{State: Good, Line: line + "."}
}

// checkBuiltinUse: accounts.builtin_use.
func checkBuiltinUse(f *Facts) *Check {
	u := f.Users
	last := u.BuiltinLastSignIn
	if u.OtherAdmins > 0 && last != nil && f.Now.Sub(*last) <= 7*24*time.Hour {
		n := u.OtherAdmins
		return &Check{State: Attention, Line: "The built-in admin signed in " + ago(f.Now, *last) + ", though " + itoa(n) +
			plural(n, " person has an admin account of their own", " people have admin accounts of their own") + ". Keep it for emergencies.",
			Fix: &Fix{Steps: []string{"Sign in with your own admin account day to day, and keep the built-in admin for emergencies."},
				Page: &PageLink{ID: "users", Label: "Open Users"}, Docs: doc(docUsersBuiltin)}}
	}
	if u.Others > 0 || u.OtherAdmins > 0 {
		when := "The built-in admin has never signed in."
		if last != nil {
			when = "The built-in admin last signed in " + ago(f.Now, *last) + "."
		}
		return &Check{State: Good, Line: "People sign in with their own accounts. " + when}
	}
	return &Check{State: Good, Line: "Only the built-in admin signs in so far.",
		Tip: &Fix{Steps: []string{"Give yourself an admin account on the Users page and keep the built-in admin for emergencies. The audit log then shows who did what."},
			Page: &PageLink{ID: "users", Label: "Open Users"}}}
}

// checkTempPasswords: accounts.temp_passwords.
func checkTempPasswords(f *Facts) *Check {
	u := f.Users
	if !u.Local {
		return nil
	}
	if n := len(u.StaleTemporary); n > 0 {
		return &Check{State: Attention, Line: itoa(n) + plural(n, " person hasn't", " people haven't") +
			" changed the temporary password they were given over a week ago: " + shorten(u.StaleTemporary, 5) + ".",
			Fix: &Fix{Steps: []string{"Remind them to sign in and choose a password, or disable their account until they need it."},
				Page: &PageLink{ID: "users", Label: "Open Users"}, Docs: doc(docUsersLocal)}}
	}
	return &Check{State: Good, Line: "Nobody is left on a temporary password."}
}

// checkDirectory: accounts.directory.
func checkDirectory(f *Facts) *Check {
	d := f.Directory
	if d == nil || d.Enabled != nil && !*d.Enabled || strings.TrimSpace(d.URL) == "" {
		return nil
	}
	page := &PageLink{ID: "users", Tab: "directory", Label: "Open Directory sign-in"}
	var hosts []string
	ldaps := true
	for _, raw := range []string{d.URL, d.FailoverURL} {
		if strings.TrimSpace(raw) == "" {
			continue
		}
		scheme, host, _ := urlParts(raw)
		if !slices.Contains(hosts, host) {
			hosts = append(hosts, host)
		}
		if scheme != "ldaps" {
			ldaps = false
			if !d.StartTLS {
				return &Check{State: Risk, Line: "Directory passwords cross the network to " + host + " unencrypted: the address is ldap:// without StartTLS.",
					Fix: &Fix{Steps: []string{"Use an ldaps:// address, or turn on StartTLS."}, Page: page, Docs: doc(docUsersDirectory)}}
			}
		}
	}
	if d.TLSSkipVerify {
		return &Check{State: Risk, Line: "Signalith doesn't check the directory server's certificate, so someone on the network could pose as it and collect passwords.",
			Fix: &Fix{Steps: []string{"Give the directory's CA certificate, then turn off Skip certificate check."}, Page: page, Docs: doc(docUsersDirectory)}}
	}
	how := "LDAPS"
	if !ldaps {
		how = "StartTLS"
	}
	c := &Check{State: Good, Line: "Directory sign-in uses " + how + " to " + joinAnd(hosts) + " and checks its certificate."}
	if strings.EqualFold(d.DefaultRole, "viewer") {
		c.Details = []string{"Anyone in the directory can sign in as a viewer."}
	}
	return c
}

// checkSessions: accounts.sessions.
func checkSessions(f *Facts) *Check {
	idle := f.Config.SessionIdle()
	if idle > 24*time.Hour {
		return &Check{State: Attention, Line: "People stay signed in for up to " + span(idle) + " without using Signalith.",
			Fix: &Fix{Steps: []string{"Set Sign out after to 12h or less."}, Setting: "auth.session_timeout"}}
	}
	return &Check{State: Good, Line: "People are signed out after " + span(idle) + " without use, and after 7 days at most."}
}

// checkAgentTokens: accounts.agent_tokens.
func checkAgentTokens(f *Facts) *Check {
	tokens := f.Config.Ingest.Tokens
	if len(tokens) == 0 {
		return nil
	}
	fix := &Fix{Steps: []string{
		"Add a new token: signalith secrets set ingest.tokens, and press Enter to have one made.",
		"Give each agent a new configuration from Add data.",
		"Then remove the old token.",
	}, Page: &PageLink{ID: "data", Label: "Open Add data"}, Docs: doc(docEncCommands),
		Commands: signalithCommands("secrets set ingest.tokens")}
	details := []string{"All agents share a token, so one taken from any agent works for all of them until it's replaced."}
	shortest := 0
	for _, t := range tokens {
		if config.IsPublicIngestToken(t) {
			return &Check{State: Risk, Line: "Agents can send events with change-this-ingest-token, an example token anyone can look up.", Details: details, Fix: fix}
		}
		if n := len(t); shortest == 0 || n < shortest {
			shortest = n
		}
	}
	if shortest < 24 {
		return &Check{State: Attention, Line: "An agent token is only " + itoa(shortest) + plural(shortest, " character", " characters") +
			" long, so it's easier to guess. Tokens Signalith makes have 48.", Details: details, Fix: fix}
	}
	return &Check{State: Good, Line: "Agents send with tokens of 24 characters or more.", Details: details}
}

// checkOpenSearchRole: accounts.opensearch_role.
func checkOpenSearchRole(f *Facts) *Check {
	o := f.OpenSearch
	if o.Anonymous == "open" || o.AuthNoPlugin || !o.AuthProbed && !o.DemoAdmin {
		return nil
	}
	fix := &Fix{Steps: []string{"Give Signalith its own OpenSearch account with the signalith_server role, ideally signing in with a certificate."}, Docs: doc(docOSRoles)}
	if o.DemoAdmin {
		return &Check{State: Risk, Line: "Signalith signs in to OpenSearch as admin with the password admin, which anyone can look up.", Fix: fix}
	}
	if o.AuthErr != "" {
		return &Check{State: Unknown, Line: "Signalith couldn't ask OpenSearch what its account may do.", Details: []string{"OpenSearch answered: " + short(o.AuthErr) + "."},
			Fix: &Fix{Steps: []string{"Check the roles mapped to Signalith's account in OpenSearch's security settings."}, Docs: doc(docOSRoles)}}
	}
	user := o.AuthUser
	if user == "" {
		user = "its account"
	}
	if slices.ContainsFunc(o.AuthRoles, func(r string) bool { return r == "all_access" || r == "security_manager" }) || slices.Contains(o.AuthBackend, "admin") {
		return &Check{State: Attention, Line: "Signalith signs in to OpenSearch as " + user + ", which can do anything there. If its password or key leaked, so would all of OpenSearch.", Fix: fix}
	}
	return &Check{State: Good, Line: "Signalith signs in to OpenSearch as " + user + ", an account without admin rights."}
}
