// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/chrisreedio/heimdall/internal/auth"
	"github.com/chrisreedio/heimdall/internal/store"
)

// Overridable in tests: where passwords and codes are read from, and how
// TOTP secrets are generated.
var (
	stdin         io.Reader = os.Stdin
	newTOTPSecret           = auth.NewTOTPSecret
)

const totpIssuer = "Heimdall"

// input reads passwords and codes, without echo when stdin is a terminal.
type input struct {
	a        *app
	r        *bufio.Reader
	terminal bool
}

func newInput(a *app, passwordStdin bool) (*input, error) {
	in := &input{a: a, r: bufio.NewReader(stdin)}
	if !passwordStdin {
		f, ok := stdin.(*os.File)
		if !ok || !isTerminal(f) {
			return nil, errors.New("stdin is not a terminal; use --password-stdin to pipe the password (and then the code)")
		}
		in.terminal = true
	}
	return in, nil
}

func (in *input) line(prompt string, hidden bool) (string, error) {
	if in.terminal {
		fmt.Fprint(in.a.stderr, prompt)
		if hidden {
			s, err := readHidden(stdin.(*os.File), in.r)
			fmt.Fprintln(in.a.stderr)
			return s, err
		}
	}
	s, err := in.r.ReadString('\n')
	if err != nil && (err != io.EOF || s == "") {
		return "", errors.New("unexpected end of input")
	}
	return strings.TrimRight(s, "\r\n"), nil
}

// newPassword reads a password (twice on a terminal) and checks the policy.
func (in *input) newPassword() (string, error) {
	pw, err := in.line("Password: ", true)
	if err != nil {
		return "", err
	}
	if err := auth.CheckPasswordPolicy(pw); err != nil {
		return "", err
	}
	if in.terminal {
		again, err := in.line("Confirm password: ", true)
		if err != nil {
			return "", err
		}
		if again != pw {
			return "", errors.New("passwords don't match")
		}
	}
	return pw, nil
}

// enrollTOTP shows a new secret and requires a valid code before returning
// it, so nobody ends up with an account they can't sign in to.
func (in *input) enrollTOTP(email string) (secret []byte, step int64, err error) {
	secret = newTOTPSecret()
	fmt.Fprintf(in.a.stderr, "\nAdd this account to your authenticator app (1Password, Aegis, Google Authenticator, ...):\n"+
		"  Account: %s (%s)\n  Secret:  %s\n  URI:     %s\n\n",
		totpIssuer, email, groupBy4(auth.TOTPSecretBase32(secret)), auth.TOTPURI(totpIssuer, email, secret))
	code, err := in.line("Enter the current 6-digit code to confirm: ", false)
	if err != nil {
		return nil, 0, err
	}
	step, ok := auth.VerifyTOTP(secret, code, time.Now())
	if !ok {
		return nil, 0, errors.New("that code didn't match; nothing was saved (check the device's clock and try again)")
	}
	return secret, step, nil
}

func groupBy4(s string) string {
	var b strings.Builder
	for i, r := range s {
		if i > 0 && i%4 == 0 {
			b.WriteByte(' ')
		}
		b.WriteRune(r)
	}
	return b.String()
}

func cmdUserCreate(a *app, args []string) error {
	fs := a.flags("user create", "[--admin] [--name \"Display Name\"] [--password-stdin] <email>\n"+
		"       heimdall user create --entra --tenant <tenant-id> [--oid <object-id>] [--admin] <email>")
	admin := fs.Bool("admin", false, "grant admin rights (all orgs, user management)")
	name := fs.String("name", "", "display name")
	pwStdin := fs.Bool("password-stdin", false, "read the password, then the TOTP code, from stdin lines")
	entra := fs.Bool("entra", false, "provision a Microsoft Entra ID user (signs in with SSO; no password)")
	tenant := fs.String("tenant", "", "Entra tenant ID (with --entra)")
	oid := fs.String("oid", "", "Entra object ID (with --entra; otherwise bound on first sign-in by email)")
	pos, err := parse(fs, args, 1)
	if err != nil {
		return err
	}
	if *entra {
		return createEntraUser(a, pos[0], *tenant, *oid, *name, *admin)
	}
	email, err := store.NormalizeEmail(pos[0])
	if err != nil {
		return err
	}
	s, err := a.openStore()
	if err != nil {
		return err
	}
	defer s.Close()
	if _, err := s.LocalUserByEmail(a.ctx, email); err == nil {
		return fmt.Errorf("user %s: %w", email, store.ErrExists)
	} else if !errors.Is(err, store.ErrNotFound) {
		return err
	}

	in, err := newInput(a, *pwStdin)
	if err != nil {
		return err
	}
	pw, err := in.newPassword()
	if err != nil {
		return err
	}
	hash, err := auth.HashPassword(pw)
	if err != nil {
		return err
	}
	secret, step, err := in.enrollTOTP(email)
	if err != nil {
		return err
	}
	id, err := s.CreateLocalUser(a.ctx, actor(), email, *name, *admin, hash, secret)
	if err != nil {
		return err
	}
	// The enrollment code can't be reused to sign in.
	if _, err := s.AcceptTOTPStep(a.ctx, id, step); err != nil {
		return err
	}
	role := "user"
	if *admin {
		role = "admin user"
	}
	fmt.Fprintf(a.stderr, "Created %s %s.\n", role, email)
	return nil
}

func cmdUserList(a *app, args []string) error {
	if _, err := parse(a.flags("user list", ""), args, 0); err != nil {
		return err
	}
	s, err := a.openStore()
	if err != nil {
		return err
	}
	defer s.Close()
	users, err := s.ListUsers(a.ctx)
	if err != nil {
		return err
	}
	rows := make([][]string, len(users))
	for i, u := range users {
		admin, status := "no", "active"
		if u.IsAdmin {
			admin = "yes"
		}
		if u.Disabled {
			status = "disabled"
		}
		ms, err := s.Memberships(a.ctx, u.ID)
		if err != nil {
			return err
		}
		roles := make([]string, len(ms))
		for j, m := range ms {
			roles[j] = m.OrgSlug + ":" + string(m.Role)
		}
		rows[i] = []string{u.Email, u.Kind, u.DisplayName, admin, strings.Join(roles, ","), formatTime(u.LastLoginAt), status}
	}
	return table(a, "EMAIL\tKIND\tNAME\tADMIN\tROLES\tLAST LOGIN\tSTATUS", rows)
}

func setDisabled(a *app, args []string, disabled bool) error {
	verb := map[bool]string{true: "disable", false: "enable"}[disabled]
	pos, err := parse(a.flags("user "+verb, "<email>"), args, 1)
	if err != nil {
		return err
	}
	s, err := a.openStore()
	if err != nil {
		return err
	}
	defer s.Close()
	if err := s.SetUserDisabled(a.ctx, actor(), pos[0], disabled); err != nil {
		return err
	}
	if disabled {
		fmt.Fprintf(a.stderr, "Disabled %s and ended their sessions.\n", pos[0])
	} else {
		fmt.Fprintf(a.stderr, "Enabled %s.\n", pos[0])
	}
	return nil
}

func cmdUserDisable(a *app, args []string) error { return setDisabled(a, args, true) }
func cmdUserEnable(a *app, args []string) error  { return setDisabled(a, args, false) }

func cmdUserResetTOTP(a *app, args []string) error {
	fs := a.flags("user reset-totp", "[--password-stdin] <email>")
	pwStdin := fs.Bool("password-stdin", false, "read the confirmation code from stdin")
	pos, err := parse(fs, args, 1)
	if err != nil {
		return err
	}
	s, err := a.openStore()
	if err != nil {
		return err
	}
	defer s.Close()
	u, err := s.LocalUserByEmail(a.ctx, pos[0])
	if err != nil {
		return fmt.Errorf("user %s: %w", pos[0], err)
	}
	in, err := newInput(a, *pwStdin)
	if err != nil {
		return err
	}
	secret, step, err := in.enrollTOTP(u.Email)
	if err != nil {
		return err
	}
	if err := s.SetTOTP(a.ctx, actor(), u.Email, secret); err != nil {
		return err
	}
	if _, err := s.AcceptTOTPStep(a.ctx, u.ID, step); err != nil {
		return err
	}
	fmt.Fprintf(a.stderr, "Reset TOTP for %s; the old authenticator entry no longer works and their sessions were ended.\n", u.Email)
	return nil
}

func cmdUserPasswd(a *app, args []string) error {
	fs := a.flags("user passwd", "[--password-stdin] <email>")
	pwStdin := fs.Bool("password-stdin", false, "read the new password from stdin")
	pos, err := parse(fs, args, 1)
	if err != nil {
		return err
	}
	s, err := a.openStore()
	if err != nil {
		return err
	}
	defer s.Close()
	u, err := s.LocalUserByEmail(a.ctx, pos[0])
	if err != nil {
		return fmt.Errorf("user %s: %w", pos[0], err)
	}
	in, err := newInput(a, *pwStdin)
	if err != nil {
		return err
	}
	pw, err := in.newPassword()
	if err != nil {
		return err
	}
	hash, err := auth.HashPassword(pw)
	if err != nil {
		return err
	}
	if err := s.SetPassword(a.ctx, actor(), u.Email, hash); err != nil {
		return err
	}
	fmt.Fprintf(a.stderr, "Changed the password for %s and ended their sessions.\n", u.Email)
	return nil
}

func createEntraUser(a *app, email, tenant, oid, name string, admin bool) error {
	if tenant == "" {
		return errors.New("--tenant is required with --entra")
	}
	s, err := a.openStore()
	if err != nil {
		return err
	}
	defer s.Close()
	if _, err := s.CreateEntraUser(a.ctx, actor(), tenant, oid, email, name, admin); err != nil {
		return err
	}
	how := "on first sign-in, their email binds to their Entra object ID"
	if oid != "" {
		how = "identified by object ID " + oid
	}
	fmt.Fprintf(a.stderr, "Provisioned Entra user %s (%s).\n", email, how)
	if !admin {
		fmt.Fprintln(a.stderr, "They have no access yet: grant a role with `heimdall user grant --role viewer <email>`.")
	}
	return nil
}

func cmdUserGrant(a *app, args []string) error {
	fs := a.flags("user grant", "[--org <org>] --role viewer|operator|admin <email>")
	org := fs.String("org", "", "organization slug (optional if there is only one)")
	roleFlag := fs.String("role", "", "viewer, operator or admin (required)")
	pos, err := parse(fs, args, 1)
	if err != nil {
		return err
	}
	if err := required(fs, "role"); err != nil {
		return err
	}
	role, err := store.ParseRole(*roleFlag)
	if err != nil {
		return err
	}
	s, err := a.openStore()
	if err != nil {
		return err
	}
	defer s.Close()
	if err := a.defaultOrg(s, org); err != nil {
		return err
	}
	if err := s.Grant(a.ctx, actor(), pos[0], *org, role); err != nil {
		return err
	}
	fmt.Fprintf(a.stderr, "%s is now %s in %s.\n", pos[0], role, *org)
	return nil
}

func cmdUserRevoke(a *app, args []string) error {
	fs := a.flags("user revoke", "[--org <org>] <email>")
	org := fs.String("org", "", "organization slug (optional if there is only one)")
	pos, err := parse(fs, args, 1)
	if err != nil {
		return err
	}
	s, err := a.openStore()
	if err != nil {
		return err
	}
	defer s.Close()
	if err := a.defaultOrg(s, org); err != nil {
		return err
	}
	if err := s.Revoke(a.ctx, actor(), pos[0], *org); err != nil {
		return err
	}
	fmt.Fprintf(a.stderr, "Removed %s's role in %s.\n", pos[0], *org)
	return nil
}
