package scan

import (
	"context"
	"fmt"
	"strings"

	"github.com/aktezed/assfin/pkg/types"
	"github.com/aktezed/assfin/pkg/waf"
	"github.com/projectdiscovery/goflags"
	httpx "github.com/projectdiscovery/httpx/runner"
)

// ProbeOpts defines options for HTTP probing with httpx.
type ProbeOpts struct {
	Threads int
	Timeout int
	Rate    int
	Follow  bool
}

// Probe runs httpx over hosts; onResult is called for each host that answered HTTP(S).
func Probe(ctx context.Context, hosts []string, o ProbeOpts, onResult func(host string, p types.Probe)) error {
	opts := httpx.Options{
		Methods:                   "GET",
		InputTargetHost:           goflags.StringSlice(hosts),
		Threads:                   o.Threads,
		Timeout:                   o.Timeout,
		RateLimit:                 o.Rate,
		FollowRedirects:           o.Follow,
		MaxRedirects:              10,
		HostMaxErrors:             30,
		MaxResponseBodySizeToRead: 1 << 20,
		TechDetect:                true,
		OutputCDN:                 "true",
		ResponseHeadersInStdout:   true,
		ExtractTitle:              true,
		StatusCode:                true,
		OutputIP:                  true,
		OutputServerHeader:        true,
		Silent:                    true,
		NoColor:                   true,
		DisableStdout:             true,
		DisableUpdateCheck:        true,
		OnResult: func(r httpx.Result) {
			if r.Err != nil || r.Failed {
				return
			}
			cdn := ""
			if r.CDN {
				cdn = r.CDNName
			}
			onResult(Normalize(r.Input), types.Probe{
				URL:    r.URL,
				Status: r.StatusCode,
				Title:  r.Title,
				Server: r.WebServer,
				Tech:   r.Technologies,
				IPs:    strings.Join(r.A, ","),
				CDN:    cdn,
				WAF:    waf.DetectWAF(r.CDNType, r.CDNName, r.ResponseHeaders),
				Length: r.ContentLength,
			})
		},
	}
	if err := opts.ValidateOptions(); err != nil {
		return fmt.Errorf("httpx options: %w", err)
	}
	r, err := httpx.New(&opts)
	if err != nil {
		return fmt.Errorf("httpx: %w", err)
	}
	defer r.Close()
	done := make(chan struct{})
	go func() { r.RunEnumeration(); close(done) }()
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
