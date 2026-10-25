// SPDX-License-Identifier: AGPL-3.0-or-later

package cloudflare

import (
	"context"
	"errors"
	"net"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/chrisreedio/heimdall/internal/store"
)

// thirdParty are hosting services whose names a CNAME commonly points at.
// When such a target stops existing (the app or bucket was deleted),
// anyone can create one with the same name and serve the zone's name: a
// subdomain takeover.
var thirdParty = []struct{ suffix, service string }{
	{".herokuapp.com", "Heroku"}, {".herokudns.com", "Heroku"},
	{".azurewebsites.net", "Azure App Service"}, {".cloudapp.net", "Azure"}, {".cloudapp.azure.com", "Azure"},
	{".trafficmanager.net", "Azure Traffic Manager"}, {".blob.core.windows.net", "Azure Storage"}, {".azureedge.net", "Azure CDN"},
	{".cloudfront.net", "AWS CloudFront"}, {".elasticbeanstalk.com", "AWS Elastic Beanstalk"}, {".s3.amazonaws.com", "AWS S3"},
	{".github.io", "GitHub Pages"}, {".netlify.app", "Netlify"}, {".netlify.com", "Netlify"},
	{".vercel.app", "Vercel"}, {".now.sh", "Vercel"}, {".pages.dev", "Cloudflare Pages"}, {".workers.dev", "Cloudflare Workers"},
	{".fly.dev", "Fly.io"}, {".onrender.com", "Render"}, {".firebaseapp.com", "Firebase"}, {".web.app", "Firebase"},
	{".appspot.com", "Google App Engine"}, {".ghost.io", "Ghost"}, {".myshopify.com", "Shopify"}, {".wpengine.com", "WP Engine"},
	{".readthedocs.io", "Read the Docs"}, {".surge.sh", "Surge"}, {".bitbucket.io", "Bitbucket"}, {".zendesk.com", "Zendesk"},
}

// ThirdParty names the hosting service a CNAME target belongs to, or "".
func ThirdParty(target string) string {
	t := "." + strings.TrimSuffix(strings.ToLower(target), ".")
	// S3 website endpoints: bucket.s3-website-us-east-1.amazonaws.com or
	// bucket.s3-website.eu-west-1.amazonaws.com.
	if strings.Contains(t, ".s3-website") && strings.HasSuffix(t, ".amazonaws.com") {
		return "AWS S3 website"
	}
	for _, p := range thirdParty {
		if strings.HasSuffix(t, p.suffix) {
			return p.service
		}
	}
	return ""
}

// Resolver looks up a name's addresses; *net.Resolver is one.
type Resolver interface {
	LookupHost(ctx context.Context, host string) ([]string, error)
}

// CNAME check bounds: lookups run a few at a time, each with a timeout,
// and a sync checks at most so many targets.
const (
	cnameWorkers = 8
	cnameTimeout = 5 * time.Second
	cnameMax     = 500
)

// CheckCNAMEs resolves each target. A target that doesn't exist
// (NXDOMAIN) is store.CNAMENXDomain; a lookup that fails otherwise is
// store.CNAMEError, which the store doesn't let replace an earlier answer.
func CheckCNAMEs(ctx context.Context, r Resolver, targets []string) []store.CNAMECheck {
	if r == nil {
		r = net.DefaultResolver
	}
	if len(targets) > cnameMax {
		targets = targets[:cnameMax]
	}
	out := make([]store.CNAMECheck, len(targets))
	work := make(chan int)
	var wg sync.WaitGroup
	for range min(cnameWorkers, len(targets)) {
		wg.Go(func() {
			for i := range work {
				out[i] = checkOne(ctx, r, targets[i])
			}
		})
	}
	for i := range targets {
		work <- i
	}
	close(work)
	wg.Wait()
	return out
}

func checkOne(ctx context.Context, r Resolver, target string) store.CNAMECheck {
	ctx, cancel := context.WithTimeout(ctx, cnameTimeout)
	defer cancel()
	c := store.CNAMECheck{Target: target, Status: store.CNAMEOK}
	addrs, err := r.LookupHost(ctx, target)
	var de *net.DNSError
	switch {
	case errors.As(err, &de) && de.IsNotFound:
		c.Status, c.Note = store.CNAMENXDomain, "no such host"
	case err != nil:
		c.Status, c.Note = store.CNAMEError, clip(err.Error())
	case len(addrs) == 0:
		c.Status, c.Note = store.CNAMENXDomain, "no addresses"
	}
	return c
}

// ForeignTargets returns the CNAME targets outside every zone, sorted:
// the ones only DNS can say exist.
func ForeignTargets(zones []store.CloudflareZone, recs []store.CloudflareRecord) []string {
	var out []string
	for _, r := range recs {
		if r.Type != "CNAME" {
			continue
		}
		t := strings.TrimSuffix(strings.ToLower(r.Content), ".")
		if t == "" || zoneFor(zones, t) != "" || slices.Contains(out, t) {
			continue
		}
		out = append(out, t)
	}
	slices.Sort(out)
	return out
}

// InZone reports the zone (of zones) a name is in, or "".
func InZone(zones []store.CloudflareZone, name string) string { return zoneFor(zones, name) }
