package scan

import (
	"bufio"
	"context"
	"os"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/aktezed/assfin/pkg/types"
	"github.com/miekg/dns"
	"github.com/projectdiscovery/dnsx/libs/dnsx"
	"github.com/projectdiscovery/retryabledns"
	"github.com/projectdiscovery/utils/dns/wildcard"
	"golang.org/x/time/rate"
)

// ResolveOpts configures concurrent DNS resolution and wildcard filtering via dnsx.
type ResolveOpts struct {
	Threads        int
	Rate           int
	Timeout        int
	Retries        int
	Resolvers      string // comma-separated resolver addresses or path to a resolvers file
	WildcardFilter bool
}

// ResolveFunc resolves a batch of hosts scoped to root, streaming progress and per-host DNS results.
type ResolveFunc func(
	ctx context.Context,
	root string,
	hosts []string,
	onProgress func(completed, total int),
	onResult func(host string, res types.DNSResult),
) error

type rootWildcard struct {
	a     *wildcard.Resolver
	aaaa  *wildcard.Resolver
	cname *wildcard.Resolver
}

// NewResolver initializes a reusable dnsx resolver with shared per-root wildcard caches.
func NewResolver(o ResolveOpts) (ResolveFunc, error) {
	resolvers, err := parseCustomResolvers(o.Resolvers)
	if err != nil {
		return nil, err
	}
	if len(resolvers) == 0 {
		resolvers = dnsx.DefaultResolvers
	}

	retries := o.Retries
	if retries <= 0 {
		retries = 2
	}
	timeoutSec := o.Timeout
	if timeoutSec <= 0 {
		timeoutSec = 3
	}

	baseOpts := dnsx.Options{
		BaseResolvers:     resolvers,
		MaxRetries:        retries,
		TraceMaxRecursion: 255,
		Hostsfile:         false,
		Timeout:           time.Duration(timeoutSec) * time.Second,
	}

	aOpts := baseOpts
	aOpts.QuestionTypes = []uint16{dns.TypeA}
	aOpts.OutputCDN = true
	aClient, err := dnsx.New(aOpts)
	if err != nil {
		return nil, err
	}

	aaaaOpts := baseOpts
	aaaaOpts.QuestionTypes = []uint16{dns.TypeAAAA}
	aaaaClient, err := dnsx.New(aaaaOpts)
	if err != nil {
		return nil, err
	}

	cnameOpts := baseOpts
	cnameOpts.QuestionTypes = []uint16{dns.TypeCNAME}
	cnameClient, err := dnsx.New(cnameOpts)
	if err != nil {
		return nil, err
	}

	threads := max(o.Threads, 1)
	var limiter *rate.Limiter
	if o.Rate > 0 {
		limiter = rate.NewLimiter(rate.Limit(o.Rate), max(o.Rate, threads))
	}

	// shortcut: wildcard.Resolver callbacks take no context.Context, so concurrent calls on one ResolveFunc share the latest ctx until upstream adds context support.
	var activeCtx atomic.Pointer[context.Context]
	bg := context.Background()
	activeCtx.Store(&bg)

	waitToken := func(ctx context.Context) error {
		if limiter == nil {
			return ctx.Err()
		}
		return limiter.Wait(ctx)
	}

	var (
		wcMu   sync.Mutex
		wcRoot = make(map[string]*rootWildcard)
	)

	getWildcard := func(root string) *rootWildcard {
		wcMu.Lock()
		defer wcMu.Unlock()
		if existing, ok := wcRoot[root]; ok {
			return existing
		}
		ctxFn := func() context.Context {
			if p := activeCtx.Load(); p != nil {
				return *p
			}
			return context.Background()
		}

		wc := &rootWildcard{
			a: wildcard.NewResolver([]string{root}, func(probeHost string) ([]string, error) {
				if err := waitToken(ctxFn()); err != nil {
					return nil, err
				}
				data, qErr := aClient.QueryOne(probeHost)
				if !hasDNSResponse(data) {
					return nil, qErr
				}
				if data.StatusCodeRaw != dns.RcodeSuccess {
					return nil, nil
				}
				return data.A, nil
			}),
			aaaa: wildcard.NewResolver([]string{root}, func(probeHost string) ([]string, error) {
				if err := waitToken(ctxFn()); err != nil {
					return nil, err
				}
				data, qErr := aaaaClient.QueryOne(probeHost)
				if !hasDNSResponse(data) {
					return nil, qErr
				}
				if data.StatusCodeRaw != dns.RcodeSuccess {
					return nil, nil
				}
				return data.AAAA, nil
			}),
			cname: wildcard.NewResolver([]string{root}, func(probeHost string) ([]string, error) {
				if err := waitToken(ctxFn()); err != nil {
					return nil, err
				}
				data, qErr := cnameClient.QueryOne(probeHost)
				if !hasDNSResponse(data) {
					return nil, qErr
				}
				cnames := normalizeCNAMEs(data.CNAME)
				if len(cnames) > 0 {
					return cnames, nil
				}
				if data.StatusCodeRaw != dns.RcodeSuccess {
					return nil, nil
				}
				return nil, nil
			}),
		}
		wcRoot[root] = wc
		return wc
	}

	resolveHost := func(ctx context.Context, root, rootSuffix, host string) (types.DNSResult, error) {
		if err := waitToken(ctx); err != nil {
			return types.DNSResult{}, err
		}
		aData, _ := aClient.QueryOne(host)
		gotA := hasDNSResponse(aData)

		var (
			aRecords    []string
			aaaaRecords []string
			cnames      []string
		)
		if gotA {
			aRecords = aData.A
			cnames = normalizeCNAMEs(aData.CNAME)
		}

		if len(aRecords) == 0 {
			// Definitive NXDOMAIN without an accompanying CNAME means no other record types exist at this label.
			if gotA && aData.StatusCodeRaw == dns.RcodeNameError && len(cnames) == 0 {
				return types.DNSResult{}, nil
			}

			// Query CNAME explicitly on NODATA, SERVFAIL, or timeout to catch dangling CNAMEs pointing to dead nameservers.
			if len(cnames) == 0 {
				if err := waitToken(ctx); err != nil {
					return types.DNSResult{}, err
				}
				if cData, _ := cnameClient.QueryOne(host); hasDNSResponse(cData) && len(cData.CNAME) > 0 {
					cnames = normalizeCNAMEs(cData.CNAME)
				}
			}

			// Check AAAA on NODATA or CNAME-without-A so IPv6-only services are resolved instead of marked dangling.
			if (gotA && aData.StatusCodeRaw == dns.RcodeSuccess) || len(cnames) > 0 {
				if err := waitToken(ctx); err != nil {
					return types.DNSResult{}, err
				}
				if aaaaData, _ := aaaaClient.QueryOne(host); hasDNSResponse(aaaaData) {
					aaaaRecords = aaaaData.AAAA
					if len(cnames) == 0 && len(aaaaData.CNAME) > 0 {
						cnames = normalizeCNAMEs(aaaaData.CNAME)
					}
				}
			}
		}

		if len(aRecords) == 0 && len(aaaaRecords) == 0 && len(cnames) == 0 {
			return types.DNSResult{}, nil
		}

		if o.WildcardFilter && rootSuffix != "" && strings.HasSuffix(host, rootSuffix) {
			wc := getWildcard(root)
			if len(cnames) > 0 {
				if matched, _ := wc.cname.LookupHost(host, cnames); matched {
					return types.DNSResult{Wildcard: true}, nil
				}
			}
			if len(aRecords) > 0 {
				if matched, _ := wc.a.LookupHost(host, aRecords); matched {
					return types.DNSResult{Wildcard: true}, nil
				}
			}
			if len(aaaaRecords) > 0 {
				if matched, _ := wc.aaaa.LookupHost(host, aaaaRecords); matched {
					return types.DNSResult{Wildcard: true}, nil
				}
			}
		}

		ips := aRecords
		if len(ips) == 0 {
			ips = aaaaRecords
		}

		var cdnName, wafName string
		if gotA && (len(aData.A) > 0 || len(aData.AAAA) > 0 || len(aData.CNAME) > 0) {
			if matched, val, itemType, cdnErr := aClient.CdnCheckRespData(aData); cdnErr == nil && matched {
				cdnName = val
				if itemType == "waf" && val != "" {
					wafName = val
				}
			}
		}

		return types.DNSResult{
			IPs:      strings.Join(ips, ","),
			CNAME:    strings.Join(cnames, ","),
			CDN:      cdnName,
			WAF:      wafName,
			Resolved: len(aRecords) > 0 || len(aaaaRecords) > 0,
		}, nil
	}

	return func(
		ctx context.Context,
		root string,
		hosts []string,
		onProgress func(completed, total int),
		onResult func(host string, res types.DNSResult),
	) error {
		if len(hosts) == 0 {
			return nil
		}
		root = Normalize(root)
		rootSuffix := ""
		if root != "" {
			rootSuffix = "." + root
		}
		activeCtx.Store(&ctx)
		defer activeCtx.Store(&bg)

		total := len(hosts)
		workers := min(threads, total)
		jobs := make(chan string, workers)

		var (
			completed atomic.Int64
			resMu     sync.Mutex
			wg        sync.WaitGroup
		)

		for range workers {
			wg.Go(func() {
				for h := range jobs {
					if ctx.Err() != nil {
						return
					}
					norm := Normalize(h)
					res, err := resolveHost(ctx, root, rootSuffix, norm)
					if err != nil && ctx.Err() != nil {
						return
					}
					resMu.Lock()
					if onProgress != nil {
						done := min(int(completed.Add(1)), total)
						onProgress(done, total)
					}
					if onResult != nil {
						onResult(norm, res)
					}
					resMu.Unlock()
				}
			})
		}

	enqueueLoop:
		for _, h := range hosts {
			select {
			case <-ctx.Done():
				break enqueueLoop
			case jobs <- h:
			}
		}
		close(jobs)
		wg.Wait()

		return ctx.Err()
	}, nil
}

func hasDNSResponse(d *retryabledns.DNSData) bool {
	return d != nil && (!d.Timestamp.IsZero() || d.HostsFile)
}

func normalizeCNAMEs(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	if len(in) == 1 {
		if c := Normalize(in[0]); c != "" {
			return []string{c}
		}
		return nil
	}
	out := make([]string, 0, len(in))
	for _, raw := range in {
		if c := Normalize(raw); c != "" && !slices.Contains(out, c) {
			out = append(out, c)
		}
	}
	return out
}

func parseCustomResolvers(spec string) ([]string, error) {
	spec = strings.TrimSpace(spec)
	if spec == "" {
		return nil, nil
	}
	if fi, err := os.Stat(spec); err == nil && !fi.IsDir() {
		f, err := os.Open(spec)
		if err != nil {
			return nil, err
		}
		defer func() { _ = f.Close() }()
		var out []string
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			line := strings.TrimSpace(sc.Text())
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			out = append(out, formatResolverAddr(line))
		}
		return out, sc.Err()
	}

	var out []string
	for part := range strings.SplitSeq(spec, ",") {
		if r := strings.TrimSpace(part); r != "" {
			out = append(out, formatResolverAddr(r))
		}
	}
	return out, nil
}

func formatResolverAddr(r string) string {
	r = strings.TrimSpace(r)
	if !strings.Contains(r, ":") {
		return r + ":53"
	}
	return r
}
