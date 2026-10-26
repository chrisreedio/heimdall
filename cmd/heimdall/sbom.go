// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"time"

	"github.com/realmwatch/heimdall/internal/sbom"
)

func cmdSBOM(a *app, args []string) error {
	fs := a.flags("sbom", "[--org <org>] <hostname>   (CycloneDX 1.5 JSON on stdout)")
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
	host, err := s.HostByName(a.ctx, *org, pos[0])
	if err != nil {
		return err
	}
	inv, err := s.Inventory(a.ctx, host)
	if err != nil {
		return err
	}
	return sbom.Write(a.stdout, inv, version, time.Now())
}
