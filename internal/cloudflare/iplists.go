// SPDX-License-Identifier: AGPL-3.0-or-later

package cloudflare

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/realmwatch/heimdall/internal/store"
)

// IP labels from Cloudflare IP lists (docs/cloudflare.md#ip-lists): the
// account-level lists ops teams already keep ("offices": 203.0.113.4,
// "Alice Example - Developer") become IP labels, so nobody types them in
// twice. Read with the read-only token (Account > Account Filter Lists >
// Read); every list starts ignored, and an admin maps the ones that matter
// to a kind on the Cloudflare page. Cloudflare is hub-wide, so the labels
// are for every org.

// ListsSource is the list sync's own ip_source_state row; each mapped
// list also gets one under its label source (store.IPListSource).
const ListsSource = "cloudflare:lists"

// ListsPermission is the error when the token can't read IP lists.
const ListsPermission = "the token can't read IP lists (add Account > Account Filter Lists > Read)"

// BanListDescription starts the description of the lists bans write
// (internal/bans). They are never offered for mapping: their items are
// attackers.
const BanListDescription = "Heimdall bans ("

// ListsEvery is how often the lists are read.
const ListsEvery = time.Hour

// ListSyncer keeps the mapped lists' labels current: it records every IP
// list the token can see (new ones ignored), replaces each mapped list's
// labels with its items, and drops the labels of lists that are gone. On
// an API failure the last good labels stay.
type ListSyncer struct {
	Client *Client
	Store  *store.Store
	Now    func() time.Time
	Log    *slog.Logger
	mu     sync.Mutex // serve's schedule and the settings page's "sync now"
}

func (s *ListSyncer) Name() string         { return ListsSource }
func (s *ListSyncer) Every() time.Duration { return ListsEvery }

func (s *ListSyncer) Sync(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	n, err := s.sync(ctx)
	if rerr := s.Store.RecordIPSourceRun(ctx, ListsSource, s.Now(), n, err); err == nil {
		err = rerr
	}
	return err
}

// permission says what's missing when err is a permission error.
func permission(err error) error {
	if IsPermission(err) {
		return errors.New(ListsPermission)
	}
	return err
}

func (s *ListSyncer) sync(ctx context.Context) (int, error) {
	accounts, err := s.Client.Accounts(ctx)
	if err != nil {
		return 0, fmt.Errorf("listing accounts: %w", permission(err))
	}
	if len(accounts) == 0 {
		return 0, errors.New(ListsPermission)
	}
	var errs []error
	var read []string // accounts whose lists were read
	var found []store.CloudflareIPList
	for _, a := range accounts {
		ls, err := s.Client.Lists(ctx, a.ID)
		if err != nil {
			errs = append(errs, fmt.Errorf("account %s: %w", a.Name, permission(err)))
			continue
		}
		read = append(read, a.ID)
		for _, l := range ls {
			if l.Kind != "ip" || !opaqueID(l.ID) {
				continue // ASN, hostname and redirect lists say nothing about an address
			}
			if strings.HasPrefix(l.Description, BanListDescription) {
				continue // Heimdall's own ban lists
			}
			found = append(found, store.CloudflareIPList{ID: l.ID, AccountID: a.ID, Name: clipText(l.Name, 100),
				Description: clipText(l.Description, 500), Items: l.NumItems})
		}
	}
	stored, err := s.Store.ReplaceCloudflareIPLists(ctx, read, found, s.Now())
	if err != nil {
		return 0, err
	}
	total := 0
	for _, l := range stored {
		if l.Kind == store.CFListIgnore || !slices.Contains(read, l.AccountID) {
			continue
		}
		src := store.IPListSource(l.ID)
		items, err := s.Client.ListItems(ctx, l.AccountID, l.ID)
		if err == nil {
			labels := ListLabels(l, items)
			if err = s.Store.ReplaceIPLabels(ctx, 0, src, labels, s.Now()); err == nil {
				total += len(labels)
				err = s.Store.RecordIPSourceRun(ctx, src, s.Now(), len(labels), nil)
				if err != nil {
					return total, err
				}
				continue
			}
		}
		err = fmt.Errorf("list %s: %w", l.Name, permission(err))
		errs = append(errs, err)
		if rerr := s.Store.RecordIPSourceRun(ctx, src, s.Now(), 0, err); rerr != nil {
			return total, rerr
		}
	}
	if s.Log != nil {
		s.Log.Debug("Cloudflare IP lists synced", "lists", len(found), "labels", total)
	}
	return total, errors.Join(errs...)
}

// ListLabels turns a mapped list's items into labels: the item's address
// or range, named after the list. Its comment names the person for staff
// and office, and is the note otherwise. Items that aren't an address or
// range are skipped, and so are repeats.
func ListLabels(l store.CloudflareIPList, items []ListItem) []store.IPLabel {
	var out []store.IPLabel
	seen := map[netip.Prefix]bool{}
	for _, it := range items {
		if it.IP == "" {
			continue // an ASN, hostname or redirect item
		}
		p, err := store.ParseIPPrefix(it.IP)
		if err != nil || seen[p] {
			continue
		}
		seen[p] = true
		lb := store.IPLabel{Prefix: p, Kind: l.Kind, Name: cmp.Or(clipText(l.Name, 100), "Cloudflare list")}
		if c := strings.TrimSpace(it.Comment); l.Kind == store.IPKindStaff || l.Kind == store.IPKindOffice {
			lb.Person = clipText(c, 200)
		} else {
			lb.Note = clipText(c, 500)
		}
		out = append(out, lb)
	}
	return out
}

// clipText trims s and cuts it to at most n bytes on a rune boundary,
// dropping control characters.
func clipText(s string, n int) string {
	s = strings.Map(func(r rune) rune {
		if r < ' ' || r == 0x7f {
			return -1
		}
		return r
	}, strings.TrimSpace(s))
	for len(s) > n {
		_, size := utf8.DecodeLastRuneInString(s)
		s = s[:len(s)-size]
	}
	return s
}

// ListURL is a list's page in the Cloudflare dashboard.
func ListURL(accountID, listID string) string {
	if !zoneIDRe(accountID) || !opaqueID(listID) {
		return ""
	}
	return "https://dash.cloudflare.com/" + accountID + "/configurations/lists/" + listID
}
