package scan

import (
	"context"
	"fmt"
	"io"
	"slices"

	"github.com/projectdiscovery/goflags"
	subfinder "github.com/projectdiscovery/subfinder/v2/pkg/runner"
)

// subfinderRateLimits mirrors subfinder's CLI defaults plus caps on free OSINT sources to prevent HTTP 429.
var subfinderRateLimits = []string{
	"github=30/m", "fullhunt=60/m", "pugrecon=10/s", "securitytrails=1/s", "shodan=1/s",
	"virustotal=4/m", "hackertarget=2/s", "waybackarchive=15/m", "whoisxmlapi=50/s",
	"sitedossier=8/m", "netlas=1/s", "hudsonrock=5/s", "urlscan=1/s",
	"crtsh=2/s", "anubis=2/s", "subdomaincenter=2/s", "alienvault=2/s", "rapiddns=2/s",
	"certspotter=1/s", "threatcrowd=1/s", "commoncrawl=2/s",
}

// NewSubfinder initializes subfinder enumeration runner.
func NewSubfinder(timeout, maxMinutes int, providerConfig string) (EnumFunc, error) {
	var rls goflags.RateLimitMap
	for _, s := range subfinderRateLimits {
		if err := rls.Set(s); err != nil {
			return nil, fmt.Errorf("rate limit %q: %w", s, err)
		}
	}
	r, err := subfinder.NewRunner(&subfinder.Options{
		Threads:            10,
		Timeout:            timeout,
		MaxEnumerationTime: maxMinutes,
		ProviderConfig:     providerConfig,
		RateLimit:          10, // shortcut: fixed 10 req/s global cap, expose as flag if users add paid API keys
		RateLimits:         rls,
		Silent:             true,
		CaptureSources:     true,
		DisableUpdateCheck: true,
		Output:             io.Discard,
	})
	if err != nil {
		return nil, err
	}
	return func(ctx context.Context, domain string) (map[string][]string, error) {
		m, err := r.EnumerateSingleDomainWithCtx(ctx, domain, []io.Writer{io.Discard})
		if err != nil {
			return nil, err
		}
		out := make(map[string][]string, len(m))
		for h, srcs := range m {
			for s := range srcs {
				out[h] = append(out[h], s)
			}
			slices.Sort(out[h])
		}
		return out, nil
	}, nil
}
