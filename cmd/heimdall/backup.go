// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"filippo.io/age"
)

// cmdBackup writes a consistent, age-encrypted copy of the database. Only
// the holder of a matching identity can read it; restore with
// `age -d -i key.txt backup.age > heimdall.db`.
func cmdBackup(a *app, args []string) error {
	fs := a.flags("backup", "--to <file.age> --age-recipient <age1…> [--age-recipient …]")
	to := fs.String("to", "", "output file (must not exist)")
	var recipients multiFlag
	fs.Var(&recipients, "age-recipient", "age public key (age1…), repeatable")
	if _, err := parse(fs, args, 0); err != nil {
		return err
	}
	if err := required(fs, "to", "age-recipient"); err != nil {
		return err
	}
	var rs []age.Recipient
	for _, r := range recipients {
		rec, err := age.ParseX25519Recipient(strings.TrimSpace(r))
		if err != nil {
			return fmt.Errorf("--age-recipient %q: %w", r, err)
		}
		rs = append(rs, rec)
	}
	s, err := a.openStore()
	if err != nil {
		return err
	}
	defer s.Close()

	tmpDir, err := os.MkdirTemp(filepath.Dir(*to), ".heimdall-backup-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(tmpDir) // the plaintext copy never outlives the command
	plain := filepath.Join(tmpDir, "heimdall.db")
	if err := s.Snapshot(a.ctx, plain); err != nil {
		return err
	}

	out, err := os.OpenFile(*to, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if errors.Is(err, os.ErrExist) {
		return fmt.Errorf("%s already exists; refusing to overwrite", *to)
	}
	if err != nil {
		return err
	}
	if err := encryptTo(out, plain, rs); err != nil {
		out.Close()
		os.Remove(*to)
		return err
	}
	if err := out.Close(); err != nil {
		return err
	}
	fmt.Fprintf(a.stderr, "Encrypted backup written to %s for %d recipient(s).\n", *to, len(rs))
	return nil
}

func encryptTo(out io.Writer, plainPath string, rs []age.Recipient) error {
	in, err := os.Open(plainPath)
	if err != nil {
		return err
	}
	defer in.Close()
	w, err := age.Encrypt(out, rs...)
	if err != nil {
		return err
	}
	if _, err := io.Copy(w, in); err != nil {
		return err
	}
	return w.Close()
}
