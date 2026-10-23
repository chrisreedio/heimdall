// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"errors"
	"flag"
	"fmt"
	"os/user"
	"slices"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/chrisreedio/heimdall/internal/config"
	"github.com/chrisreedio/heimdall/internal/store"
)

func (a *app) flags(name, args string) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(a.stderr)
	fs.Usage = func() {
		fmt.Fprintf(a.stderr, "usage: heimdall %s %s\n", name, args)
		fs.PrintDefaults()
	}
	return fs
}

// parse parses flags and returns positional arguments, allowing flags to
// appear before or after them (`host add web-01 --org acme`).
func parse(fs *flag.FlagSet, args []string, want int) ([]string, error) {
	var pos []string
	for {
		if err := fs.Parse(args); err != nil {
			return nil, err
		}
		if fs.NArg() == 0 {
			break
		}
		pos = append(pos, fs.Arg(0))
		args = fs.Args()[1:]
	}
	if len(pos) != want {
		fs.Usage()
		return nil, errUsage
	}
	return pos, nil
}

// parseAtLeast is parse for commands taking a variable number of
// positional arguments.
func parseAtLeast(fs *flag.FlagSet, args []string, min int) ([]string, error) {
	var pos []string
	for {
		if err := fs.Parse(args); err != nil {
			return nil, err
		}
		if fs.NArg() == 0 {
			break
		}
		pos = append(pos, fs.Arg(0))
		args = fs.Args()[1:]
	}
	if len(pos) < min {
		fs.Usage()
		return nil, errUsage
	}
	return pos, nil
}

func required(fs *flag.FlagSet, names ...string) error {
	for _, n := range names {
		if fs.Lookup(n).Value.String() == "" {
			fmt.Fprintf(fs.Output(), "missing required flag --%s\n", n)
			fs.Usage()
			return errUsage
		}
	}
	return nil
}

// openStore loads the config and opens a database at the current schema.
func (a *app) openStore() (*store.Store, error) {
	cfg, err := config.Load(a.configPath)
	if err != nil {
		return nil, err
	}
	s, err := store.Open(a.ctx, cfg.Database)
	if err != nil {
		return nil, err
	}
	if err := s.CheckSchema(a.ctx); err != nil {
		s.Close()
		return nil, err
	}
	return s, nil
}

// actor identifies the CLI caller in the audit log.
func actor() string {
	if u, err := user.Current(); err == nil {
		return "cli:" + u.Username
	}
	return "cli"
}

func table(a *app, header string, rows [][]string) error {
	w := tabwriter.NewWriter(a.stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, header)
	for _, r := range rows {
		fmt.Fprintln(w, strings.Join(r, "\t"))
	}
	return w.Flush()
}

func formatTime(t time.Time) string {
	if t.IsZero() {
		return "never"
	}
	return t.Local().Format("2006-01-02 15:04")
}

func joinKeys[V any](m map[string]V) string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	return strings.Join(keys, "|")
}

// multiFlag collects a repeatable string flag.
type multiFlag []string

func (m *multiFlag) String() string { return strings.Join(*m, ",") }
func (m *multiFlag) Set(v string) error {
	for p := range strings.SplitSeq(v, ",") {
		if p = strings.TrimSpace(p); p != "" {
			*m = append(*m, p)
		}
	}
	return nil
}

// defaultOrg fills in an empty --org when the install has exactly one org,
// the usual setup (one Heimdall per organization).
func (a *app) defaultOrg(s *store.Store, org *string) error {
	if *org != "" {
		return nil
	}
	orgs, err := s.ListOrgs(a.ctx)
	if err != nil {
		return err
	}
	switch len(orgs) {
	case 0:
		return errors.New("no organizations yet; create one with `heimdall org create <slug>`")
	case 1:
		*org = orgs[0].Slug
		return nil
	}
	return fmt.Errorf("this install has %d organizations; pass --org", len(orgs))
}

// defaultEnv fills in an empty --env when the org has exactly one env.
func (a *app) defaultEnv(s *store.Store, org string, env *string) error {
	if *env != "" {
		return nil
	}
	envs, err := s.ListEnvs(a.ctx, org)
	if err != nil {
		return err
	}
	switch len(envs) {
	case 0:
		return fmt.Errorf("org %s has no environments yet; create one with `heimdall env create prod`", org)
	case 1:
		*env = envs[0].Slug
		return nil
	}
	return fmt.Errorf("org %s has %d environments; pass --env", org, len(envs))
}
