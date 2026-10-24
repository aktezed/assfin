package scan

import (
	"context"
	"fmt"
	"io"
	"slices"

	"github.com/projectdiscovery/goflags"
	subfinder "github.com/projectdiscovery/subfinder/v2/pkg/runner"
)

// subfinderRateLimits mirrors subfinder's CLI defaults for library mode.
var subfinderRateLimits = []string{
	"github=30/m", "fullhunt=60/m", "pugrecon=10/s", "securitytrails=1/s", "shodan=1/s",
	"virustotal=4/m", "hackertarget=2/s", "waybackarchive=15/m", "whoisxmlapi=50/s",
	"sitedossier=8/m", "netlas=1/s", "hudsonrock=5/s", "urlscan=1/s",
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
