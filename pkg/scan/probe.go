package scan

import (
	"context"
	"fmt"
	"net/url"
	"slices"
	"strings"
	"sync/atomic"

	"github.com/aktezed/assfin/pkg/types"
	"github.com/aktezed/assfin/pkg/waf"
	"github.com/projectdiscovery/goflags"
	httpx "github.com/projectdiscovery/httpx/runner"
)

// ProbeOpts defines options for HTTP probing with httpx.
type ProbeOpts struct {
	Threads       int
	Timeout       int
	Rate          int
	Follow        bool
	ExtractRoot   string   // when non-empty, extract in-scope hosts from 2xx/3xx responses
	Exclude       []string // excluded hosts or suffixes for ExtractHosts
	ContentAssets int      // max same-host .js/.json asset URLs collected per host (0 = off)
	TargetAddr    string   // optional loopback host:port override for offline fixture tests
	OnProgress    func(completed, total int)
}

// Probe runs httpx over hosts; onResult is called for each host that answered HTTP(S).
func Probe(ctx context.Context, hosts []string, o ProbeOpts, onResult func(host string, p types.Probe)) error {
	if len(hosts) == 0 {
		return nil
	}
	var completed atomic.Int64
	total := len(hosts)
	extractRoot := Normalize(o.ExtractRoot)

	targets := hosts
	var resolvers goflags.StringSlice
	if o.TargetAddr != "" {
		targets = make([]string, len(hosts))
		for i, h := range hosts {
			targets[i] = h + "," + o.TargetAddr
		}
		// Disable system resolvers and syscall DNS fallback during offline fixture tests.
		resolvers = goflags.StringSlice{"127.0.0.1:1"}
	}

	opts := httpx.Options{
		Methods:                   "GET",
		InputTargetHost:           goflags.StringSlice(targets),
		Resolvers:                 resolvers,
		Threads:                   max(o.Threads, 1),
		Timeout:                   max(o.Timeout, 1),
		RateLimit:                 o.Rate,
		FollowRedirects:           o.Follow,
		MaxRedirects:              10,
		HostMaxErrors:             30,
		MaxResponseBodySizeToRead: maxContentReadBytes,
		TechDetect:                true,
		OutputCDN:                 "true",
		ResponseHeadersInStdout:   true,
		// httpx only populates Result.ResponseBody when ResponseInStdout is true; stdout remains muted by DisableStdout.
		ResponseInStdout:   extractRoot != "",
		ExtractTitle:       true,
		StatusCode:         true,
		OutputIP:           true,
		OutputServerHeader: true,
		Silent:             true,
		NoColor:            true,
		DisableStdout:      true,
		DisableUpdateCheck: true,
		OnResult: func(r httpx.Result) {
			if o.OnProgress != nil {
				done := int(completed.Add(1))
				if done > total {
					done = total
				}
				o.OnProgress(done, total)
			}
			if r.Err != nil || r.Failed {
				return
			}
			cdn := ""
			if r.CDN {
				cdn = r.CDNName
			}

			rawHost := r.Input
			if idx := strings.IndexByte(rawHost, ','); idx >= 0 {
				rawHost = rawHost[:idx]
			}
			inputHost := Normalize(rawHost)
			probeURL := r.URL
			if o.TargetAddr != "" {
				probeURL = rewriteURLHost(r.URL, inputHost)
			}

			var (
				referenced []string
				refSources map[string]string
				assetURLs  []string
			)

			if extractRoot != "" && r.StatusCode >= 200 && r.StatusCode < 400 {
				if isExtractableContentType(r.ContentType) && r.ResponseBody != "" {
					bodyBytes := []byte(r.ResponseBody)
					hostsFound, snippets := ExtractHosts(bodyBytes, extractRoot, o.Exclude)
					for _, h := range hostsFound {
						if h == inputHost {
							continue
						}
						if refSources == nil {
							refSources = make(map[string]string)
						}
						refSources[h] = snippets[h]
						referenced = append(referenced, h)
					}

					if o.ContentAssets > 0 && isLikelyHTML(r.ContentType, r.ResponseBody) {
						assetURLs = ExtractSameHostAssets(bodyBytes, probeURL, o.ContentAssets)
					}
				}

				if r.Location != "" {
					locHosts, _ := ExtractHosts([]byte(r.Location), extractRoot, o.Exclude)
					for _, h := range locHosts {
						if h == inputHost {
							continue
						}
						if refSources == nil {
							refSources = make(map[string]string)
						}
						if _, exists := refSources[h]; !exists {
							refSources[h] = clipRunes("location: "+r.Location, 120)
							referenced = append(referenced, h)
						}
					}
				}
				slices.Sort(referenced)
			}

			onResult(inputHost, types.Probe{
				URL:        probeURL,
				Status:     r.StatusCode,
				Title:      r.Title,
				Server:     r.WebServer,
				Tech:       r.Technologies,
				IPs:        strings.Join(r.A, ","),
				CDN:        cdn,
				WAF:        waf.DetectWAF(r.CDNType, r.CDNName, r.ResponseHeaders),
				Length:     r.ContentLength,
				Referenced: referenced,
				RefSources: refSources,
				AssetURLs:  assetURLs,
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

func rewriteURLHost(rawURL, host string) string {
	u, err := url.Parse(rawURL)
	if err != nil || host == "" {
		return rawURL
	}
	u.Host = host
	return u.String()
}

func isLikelyHTML(contentType, body string) bool {
	ct := strings.ToLower(contentType)
	if strings.Contains(ct, "html") {
		return true
	}
	if strings.TrimSpace(ct) != "" {
		return false
	}
	sample := strings.ToLower(strings.TrimSpace(body[:min(len(body), 256)]))
	return strings.HasPrefix(sample, "<!doctype") || strings.HasPrefix(sample, "<html") || strings.Contains(sample, "<script")
}
