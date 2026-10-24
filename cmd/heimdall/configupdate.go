// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/chrisreedio/heimdall/internal/config"
)

// cmdConfigUpdate appends the config sections for features added since the
// file was written, all off.
func cmdConfigUpdate(a *app, args []string) error {
	f := a.flags("config update", "[--dry-run]")
	dry := f.Bool("dry-run", false, "print what would be appended, change nothing")
	if _, err := parse(f, args, 0); err != nil {
		return err
	}
	added, out, err := updateConfigSections(a.configPath, *dry)
	if errors.Is(err, fs.ErrPermission) {
		return fmt.Errorf("%w\nrun: sudo heimdall config update", err)
	}
	if err != nil {
		return err
	}
	switch {
	case len(added) == 0:
		fmt.Fprintln(a.stderr, "config: up to date")
	case *dry:
		fmt.Fprintf(a.stderr, "config: would add %s (off) to %s:\n", sectionList(added), a.configPath)
		fmt.Fprint(a.stdout, out)
	default:
		fmt.Fprintf(a.stderr, "config: added %s (off); previous file kept as %s.pre-upgrade\n", sectionList(added), a.configPath)
	}
	return nil
}

// migrateConfig runs the config update during migrate. It never fails the
// migrate: a config it can't write gets a hint instead.
func migrateConfig(a *app) {
	added, _, err := updateConfigSections(a.configPath, false)
	switch {
	case errors.Is(err, fs.ErrPermission):
		fmt.Fprintln(a.stderr, "config: new feature sections not added (not writable); run: sudo heimdall config update")
	case err != nil:
		fmt.Fprintln(a.stderr, "config: not updated:", err)
	case len(added) > 0:
		fmt.Fprintf(a.stderr, "config: added %s (off)\n", sectionList(added))
	}
}

func sectionList(names []string) string {
	s := make([]string, len(names))
	for i, n := range names {
		s[i] = "[" + n + "]"
	}
	return strings.Join(s, ", ")
}

// updateConfigSections appends the template sections missing from the
// config at path. It returns their names and, with dryRun, the appended
// text without writing anything. Otherwise the old file is copied to
// path.pre-upgrade and replaced atomically, keeping its mode and owner, but
// only if the result loads; on any error the file is left untouched.
func updateConfigSections(path string, dryRun bool) ([]string, string, error) {
	src, err := os.ReadFile(path)
	if err != nil {
		return nil, "", err
	}
	secs, err := config.MissingSections(src)
	if err != nil {
		return nil, "", fmt.Errorf("%s: %w", path, err)
	}
	if len(secs) == 0 {
		return nil, "", nil
	}
	names := make([]string, len(secs))
	for i, s := range secs {
		names[i] = s.Name
	}
	out := config.AppendSections(src, secs, version)
	if dryRun {
		return names, string(out[len(src):]), nil
	}
	fi, err := os.Stat(path)
	if err != nil {
		return nil, "", err
	}
	err = writeLike(path, out, fi, func(tmp string) error {
		if _, err := config.Load(tmp); err != nil {
			return fmt.Errorf("the updated config doesn't load (left unchanged): %w", err)
		}
		return nil
	})
	if err != nil {
		return nil, "", err
	}
	return names, "", nil
}

// writeLike validates data with check, then writes path.pre-upgrade (a copy
// of the current file) and replaces path, both atomically with fi's mode
// and owner.
func writeLike(path string, data []byte, fi os.FileInfo, check func(tmp string) error) error {
	old, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	tmp, err := tempLike(path, data, fi)
	if err != nil {
		return err
	}
	defer os.Remove(tmp)
	if err := check(tmp); err != nil {
		return err
	}
	bak, err := tempLike(path, old, fi)
	if err != nil {
		return err
	}
	defer os.Remove(bak)
	if err := os.Rename(bak, path+".pre-upgrade"); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// tempLike writes data to a new temporary file next to path with fi's mode
// and (as root) owner, and returns its name.
func tempLike(path string, data []byte, fi os.FileInfo) (string, error) {
	f, err := os.CreateTemp(filepath.Dir(path), ".tmp-heimdall-")
	if err != nil {
		return "", err
	}
	name := f.Name()
	_, err = f.Write(data)
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = os.Chmod(name, fi.Mode().Perm())
	}
	if uid, gid, ok := fileOwner(fi); err == nil && ok && os.Geteuid() == 0 {
		err = os.Chown(name, uid, gid)
	}
	if err != nil {
		os.Remove(name)
		return "", err
	}
	return name, nil
}
