package runner

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"text/tabwriter"
	"time"

	"github.com/aktezed/assfin/pkg/report"
	"github.com/aktezed/assfin/pkg/scan"
	"github.com/aktezed/assfin/pkg/store"
	"github.com/aktezed/assfin/pkg/types"
	"github.com/projectdiscovery/gologger"
)

// Runner manages the lifecycle and execution of assfin tasks.
type Runner struct {
	options    *types.Options
	store      *store.Store
	enumFn     scan.EnumFunc
	resolveFn  scan.ResolveFunc
	targetAddr string
}

// NewRunner creates a new assfin runner instance using manual constructor injection.
func NewRunner(options *types.Options) (*Runner, error) {
	if options == nil {
		return nil, errors.New("options cannot be nil")
	}
	return &Runner{options: options}, nil
}

// Close cleans up any open resources such as database connections.
func (r *Runner) Close() error {
	if r.store != nil {
		return r.store.Close()
	}
	return nil
}

// Run dispatches execution to the corresponding command handler.
func (r *Runner) Run(ctx context.Context) error {
	switch r.options.Command {
	case "scan":
		return r.ExecuteScan(ctx)
	case "query":
		return r.ExecuteQuery(ctx)
	case "report":
		return r.ExecuteReport(ctx)
	case "serve":
		return r.ExecuteServe(ctx)
	default:
		return fmt.Errorf("unknown command %q", r.options.Command)
	}
}

// ExecuteScan executes subdomain discovery and HTTP probing.
func (r *Runner) ExecuteScan(ctx context.Context) error {
	roots, err := readRoots(r.options.Domain, r.options.DomainList)
	if err != nil {
		return err
	}

	dbPath := r.options.DBPath
	if dbPath == "" {
		dbPath = "assfin.db"
		if len(roots) == 1 {
			dbPath = roots[0] + ".db"
		}
	}

	var exclude []string
	for _, e := range r.options.Exclude {
		exclude = append(exclude, scan.Normalize(e))
	}

	optsJSON, _ := json.Marshal(r.options)

	dbStore, err := store.New(dbPath, false)
	if err != nil {
		return fmt.Errorf("open store: %w", err)
	}
	r.store = dbStore

	enum := r.enumFn
	if enum == nil {
		enum, err = scan.NewSubfinder(r.options.SubfinderTimeout, r.options.SubfinderMaxTime, r.options.ProviderConfig)
		if err != nil {
			return fmt.Errorf("subfinder init: %w", err)
		}
	}

	dnsThreads := r.options.DNSThreads
	if dnsThreads <= 0 {
		dnsThreads = 100
	}
	dnsRate := r.options.DNSRate
	if dnsRate <= 0 {
		dnsRate = 500
	}
	dnsTimeout := r.options.DNSTimeout
	if dnsTimeout <= 0 {
		dnsTimeout = 3
	}

	var resolve scan.ResolveFunc
	if !r.options.NoDNS {
		switch {
		case r.resolveFn != nil:
			resolve = r.resolveFn
		case r.targetAddr != "" && r.options.Resolvers == "":
			resolve = func(ctx context.Context, _ string, hosts []string, onProgress func(int, int), onResult func(string, types.DNSResult)) error {
				total := len(hosts)
				for i, h := range hosts {
					if err := ctx.Err(); err != nil {
						return err
					}
					if onProgress != nil {
						onProgress(i+1, total)
					}
					if onResult != nil {
						onResult(scan.Normalize(h), types.DNSResult{IPs: "127.0.0.1", Resolved: true})
					}
				}
				return nil
			}
		default:
			resolve, err = scan.NewResolver(scan.ResolveOpts{
				Threads:        dnsThreads,
				Rate:           dnsRate,
				Timeout:        dnsTimeout,
				Resolvers:      r.options.Resolvers,
				WildcardFilter: !r.options.NoWildcard,
			})
			if err != nil {
				return fmt.Errorf("dnsx init: %w", err)
			}
		}
	}

	totalScanStart := time.Now()

	for _, root := range roots {
		scanStart := time.Now()
		scanID, err := dbStore.StartScan(root, string(optsJSON))
		if err != nil {
			return err
		}

		depthLabel := "auto"
		if r.options.Depth >= 0 {
			depthLabel = strconv.Itoa(r.options.Depth)
		}
		gologger.Info().Msgf("[%s] enumerating subdomains (depth %s, passive only)", root, depthLabel)
		if err := dbStore.UpsertHost(scanID, root, root, 0, nil); err != nil {
			return err
		}

		var (
			dbErr      error
			discovered atomic.Int64
		)
		seen := map[string]bool{root: true}
		queried := map[string]bool{root: true}
		crawlOpts := scan.CrawlOpts{
			Depth:    r.options.Depth,
			MaxHosts: r.options.MaxHosts,
			Conc:     r.options.SubfinderConcurrency,
			Exclude:  exclude,
			Seen:     seen,
			Queried:  queried,
		}

		enumStart := time.Now()
		tickerCtx, cancelTicker := context.WithCancel(ctx)
		go func() {
			t := time.NewTicker(10 * time.Second)
			defer t.Stop()
			for {
				select {
				case <-tickerCtx.Done():
					return
				case <-t.C:
					gologger.Info().Msgf("[%s] enumerating... (%s elapsed, %d subdomains found)",
						root, types.FormatDuration(time.Since(enumStart)), discovered.Load())
				}
			}
		}()

		err = scan.Crawl(ctx, root, crawlOpts, enum, func(h string, sources []string) {
			discovered.Add(1)
			if err := dbStore.UpsertHost(scanID, root, h, scan.LabelDepth(h, root), sources); err != nil && dbErr == nil {
				dbErr = err
			}
		})
		cancelTicker()
		enumDuration := time.Since(enumStart)

		if dbErr != nil {
			return dbErr
		}
		if err != nil {
			return fmt.Errorf("enumeration stopped: %w (partial results saved to %s)", err, dbPath)
		}

		gologger.Info().Msgf("[%s] enumeration completed: %d hosts discovered in %s",
			root, discovered.Load(), types.FormatDuration(enumDuration))

		st := &scanState{
			scanID:      scanID,
			root:        root,
			exclude:     exclude,
			enum:        enum,
			resolve:     resolve,
			dnsThreads:  dnsThreads,
			dnsRate:     dnsRate,
			seen:        seen,
			queried:     queried,
			wildcards:   make(map[string]bool),
			deadContent: make(map[string]bool),
		}

		var (
			dnsDuration   time.Duration
			probeDuration time.Duration
		)

		if r.options.NoProbe {
			if resolve != nil {
				known, qErr := dbStore.QueryHosts(types.Filter{Root: root, Depth: -1})
				if qErr != nil {
					return qErr
				}
				if rErr := dbStore.ResetDNS(root); rErr != nil {
					return rErr
				}
				knownHosts := make([]string, len(known))
				for i, h := range known {
					knownHosts[i] = h.Host
					st.seen[h.Host] = true
				}
				_, dnsDuration, err = r.filterStoredHostsDNS(ctx, dbStore, st, knownHosts)
				if err != nil {
					return fmt.Errorf("dns resolution stopped: %w (partial results saved to %s)", err, dbPath)
				}
			}
		} else {
			dnsDuration, probeDuration, err = r.probeAndDiscover(ctx, dbStore, st)
			if err != nil {
				return fmt.Errorf("probing stopped: %w (partial results saved to %s)", err, dbPath)
			}

			// Classify asset roles across alive endpoints (registerable, login-only, landing)
			if !r.options.NoAuth {
				aliveHosts, qErr := dbStore.QueryHosts(types.Filter{Root: root, Alive: "yes", Depth: -1})
				if qErr == nil && len(aliveHosts) > 0 {
					gologger.Info().Msgf("[%s] classifying asset roles (registerable, login-only, landing) across %d alive hosts", root, len(aliveHosts))
					threads := r.options.AuthThreads
					if threads <= 0 {
						threads = 10
					}
					scan.ClassifyAliveHosts(ctx, aliveHosts, threads, r.options.Timeout, r.options.RateLimit, func(h string, authType, authURL string) {
						_ = dbStore.UpdateAuth(h, authType, authURL)
					})
				}
			}
		}

		if err := dbStore.FinishScan(scanID); err != nil {
			return err
		}

		all, err := dbStore.QueryHosts(types.Filter{Root: root, Depth: -1})
		if err != nil {
			return err
		}

		var alive, resolvedCount, danglingCount, wafCount, fresh int
		for _, h := range all {
			alive += b2i(h.Alive)
			resolvedCount += b2i(h.IPs != "")
			danglingCount += b2i(h.CNAME != "" && h.IPs == "")
			wafCount += b2i(h.WAF != "")
			fresh += b2i(h.New)
		}

		scanDuration := time.Since(scanStart)
		switch {
		case r.options.NoProbe && r.options.NoDNS:
			gologger.Info().Msgf("%s: %d hosts, %d new in %s -> %s",
				root, len(all), fresh, types.FormatDuration(scanDuration), dbPath)
		case r.options.NoProbe:
			gologger.Info().Msgf("%s: %d hosts, %d resolved, %d dangling CNAME, %d new in %s (enum: %s, dns: %s) -> %s",
				root, len(all), resolvedCount, danglingCount, fresh, types.FormatDuration(scanDuration),
				types.FormatDuration(enumDuration), types.FormatDuration(dnsDuration), dbPath)
		case r.options.NoDNS:
			gologger.Info().Msgf("%s: %d hosts, %d alive, %d behind WAF, %d new in %s (enum: %s, probe: %s) -> %s",
				root, len(all), alive, wafCount, fresh, types.FormatDuration(scanDuration),
				types.FormatDuration(enumDuration), types.FormatDuration(probeDuration), dbPath)
		default:
			gologger.Info().Msgf("%s: %d hosts, %d resolved, %d alive, %d dangling CNAME, %d behind WAF, %d new in %s (enum: %s, dns: %s, probe: %s) -> %s",
				root, len(all), resolvedCount, alive, danglingCount, wafCount, fresh, types.FormatDuration(scanDuration),
				types.FormatDuration(enumDuration), types.FormatDuration(dnsDuration), types.FormatDuration(probeDuration), dbPath)
		}

		if !r.options.Silent {
			PrintTargetSummary(os.Stdout, root, all)
		}
	}

	if len(roots) > 1 {
		gologger.Info().Msgf("all %d domains scanned in %s", len(roots), types.FormatDuration(time.Since(totalScanStart)))
	}

	scopeRoot := ""
	if len(roots) == 1 {
		scopeRoot = roots[0]
	}

	if r.options.Report || r.options.ReportOutput != "" {
		out := r.options.ReportOutput
		if out == "" {
			if scopeRoot != "" {
				out = scopeRoot + "-report.html"
			} else {
				out = "assfin-report.html"
			}
		}
		if err := report.WriteScopedReport(dbStore, scopeRoot, out); err != nil {
			return fmt.Errorf("write report: %w", err)
		}
		gologger.Info().Msgf("report written to %s", out)
	}

	if r.options.Serve != "" {
		return runScopedServer(ctx, dbStore, resolveServeAddr(r.options.Serve, r.options.Port), scopeRoot)
	}

	return nil
}

type scanState struct {
	scanID      int64
	root        string
	exclude     []string
	enum        scan.EnumFunc
	resolve     scan.ResolveFunc
	dnsThreads  int
	dnsRate     int
	seen        map[string]bool
	queried     map[string]bool
	wildcards   map[string]bool
	deadContent map[string]bool
}

type pendingRef struct {
	referrer string
	source   string
}

func (r *Runner) probeAndDiscover(ctx context.Context, dbStore *store.Store, st *scanState) (time.Duration, time.Duration, error) {
	known, err := dbStore.QueryHosts(types.Filter{Root: st.root, Depth: -1})
	if err != nil {
		return 0, 0, err
	}
	if err := dbStore.ResetProbe(st.root); err != nil {
		return 0, 0, err
	}
	knownHosts := make([]string, len(known))
	for i, h := range known {
		knownHosts[i] = h.Host
		st.seen[h.Host] = true
	}

	var (
		totalDNSDuration   time.Duration
		totalProbeDuration time.Duration
		toProbe            []string
	)

	if st.resolve != nil {
		var dnsDur time.Duration
		toProbe, dnsDur, err = r.filterStoredHostsDNS(ctx, dbStore, st, knownHosts)
		totalDNSDuration += dnsDur
		if err != nil {
			return totalDNSDuration, 0, err
		}
	} else {
		toProbe = knownHosts
	}

	contentDepth := r.options.ContentDepth
	if contentDepth <= 0 {
		contentDepth = 1
	}

	for round := 0; len(toProbe) > 0; round++ {
		extractActive := !r.options.NoContent && round < contentDepth
		probeOpts := scan.ProbeOpts{
			Threads:       r.options.Threads,
			Timeout:       r.options.Timeout,
			Rate:          r.options.RateLimit,
			Follow:        r.options.FollowRedirects,
			Exclude:       st.exclude,
			ContentAssets: r.options.ContentAssets,
			TargetAddr:    r.targetAddr,
		}
		if extractActive {
			probeOpts.ExtractRoot = st.root
		}

		var (
			refMu        sync.Mutex
			pendingHosts []string
			pendingRefs  = make(map[string][]pendingRef)
			assetURLs    []string
			assetSeen    = make(map[string]bool)
		)

		recordRef := func(referrer, refHost, source string) {
			refMu.Lock()
			if st.wildcards[refHost] || st.deadContent[refHost] {
				refMu.Unlock()
				return
			}
			if existing, isPending := pendingRefs[refHost]; isPending {
				pendingRefs[refHost] = append(existing, pendingRef{referrer: referrer, source: source})
				refMu.Unlock()
				return
			}
			if st.seen[refHost] {
				refMu.Unlock()
				if err := dbStore.SaveHostRef(refHost, referrer, source); err != nil {
					gologger.Warning().Msgf("save ref %s -> %s: %v", referrer, refHost, err)
				}
				depth := scan.LabelDepth(refHost, st.root)
				if err := dbStore.UpsertContentHost(st.scanID, st.root, refHost, depth, referrer); err != nil {
					gologger.Warning().Msgf("upsert content host %s: %v", refHost, err)
				}
				return
			}
			if r.options.MaxHosts > 0 && len(st.seen) >= r.options.MaxHosts {
				refMu.Unlock()
				return
			}
			st.seen[refHost] = true
			pendingHosts = append(pendingHosts, refHost)
			pendingRefs[refHost] = []pendingRef{{referrer: referrer, source: source}}
			refMu.Unlock()
		}

		dur, err := r.probeBatch(ctx, dbStore, toProbe, probeOpts, func(host string, p types.Probe) {
			for _, refHost := range p.Referenced {
				recordRef(host, refHost, p.RefSources[refHost])
			}
			if len(p.AssetURLs) > 0 {
				refMu.Lock()
				for _, u := range p.AssetURLs {
					if !assetSeen[u] {
						assetSeen[u] = true
						assetURLs = append(assetURLs, u)
					}
				}
				refMu.Unlock()
			}
		})
		totalProbeDuration += dur
		if err != nil {
			return totalDNSDuration, totalProbeDuration, err
		}

		if extractActive && r.options.ContentAssets > 0 && len(assetURLs) > 0 {
			assetStart := time.Now()
			assetRefs := scan.FetchAssetHosts(ctx, assetURLs, probeOpts)
			totalProbeDuration += time.Since(assetStart)
			for referrer, discovered := range assetRefs {
				for refHost, src := range discovered {
					recordRef(referrer, refHost, src)
				}
			}
		}

		if len(pendingHosts) == 0 {
			break
		}

		slices.Sort(pendingHosts)

		var (
			verifiedSeeds  []string
			nextProbeBatch []string
		)

		persistContentCandidate := func(h string) {
			refs := pendingRefs[h]
			firstReferrer := ""
			if len(refs) > 0 {
				firstReferrer = refs[0].referrer
			}
			depth := scan.LabelDepth(h, st.root)
			if err := dbStore.UpsertContentHost(st.scanID, st.root, h, depth, firstReferrer); err != nil {
				gologger.Warning().Msgf("upsert content host %s: %v", h, err)
			}
			for _, pr := range refs {
				if err := dbStore.SaveHostRef(h, pr.referrer, pr.source); err != nil {
					gologger.Warning().Msgf("save ref %s -> %s: %v", pr.referrer, h, err)
				}
			}
		}

		if st.resolve != nil {
			resMap, dnsDur, rErr := r.resolveBatch(ctx, st, pendingHosts)
			totalDNSDuration += dnsDur

			var wildcardDropped, deadDropped, danglingFound int
			for _, h := range pendingHosts {
				res, ok := resMap[scan.Normalize(h)]
				if !ok {
					continue
				}
				if res.Wildcard {
					st.wildcards[h] = true
					wildcardDropped++
					continue
				}
				if !res.Resolved && res.CNAME == "" {
					st.deadContent[h] = true
					deadDropped++
					continue
				}
				persistContentCandidate(h)
				if err := dbStore.SaveDNS(h, res); err != nil {
					gologger.Warning().Msgf("save dns %s: %v", h, err)
				}
				verifiedSeeds = append(verifiedSeeds, h)
				if res.Resolved {
					nextProbeBatch = append(nextProbeBatch, h)
				} else {
					danglingFound++
				}
			}
			if rErr != nil {
				return totalDNSDuration, totalProbeDuration, rErr
			}
			gologger.Info().Msgf("[%s] content discovery round %d: %d candidates extracted -> %d verified (%d resolved, %d dangling CNAME, %d wildcard dropped, %d unresolvable dropped)",
				st.root, round+1, len(pendingHosts), len(verifiedSeeds), len(nextProbeBatch), danglingFound, wildcardDropped, deadDropped)
		} else {
			for _, h := range pendingHosts {
				persistContentCandidate(h)
				verifiedSeeds = append(verifiedSeeds, h)
				nextProbeBatch = append(nextProbeBatch, h)
			}
			gologger.Info().Msgf("[%s] content discovery round %d: %d new hosts extracted from HTTP responses",
				st.root, round+1, len(verifiedSeeds))
		}

		if len(verifiedSeeds) == 0 {
			break
		}

		if r.options.Depth != 0 {
			feedbackDepth := r.options.Depth
			if feedbackDepth > 0 {
				feedbackDepth--
			}
			var (
				crawlDBErr error
				crawlFound []string
			)
			crawlErr := scan.Crawl(ctx, st.root, scan.CrawlOpts{
				Depth:    feedbackDepth,
				MaxHosts: r.options.MaxHosts,
				Conc:     r.options.SubfinderConcurrency,
				Exclude:  st.exclude,
				Seeds:    verifiedSeeds,
				Seen:     st.seen,
				Queried:  st.queried,
			}, st.enum, func(h string, sources []string) {
				crawlFound = append(crawlFound, h)
				if err := dbStore.UpsertHost(st.scanID, st.root, h, scan.LabelDepth(h, st.root), sources); err != nil && crawlDBErr == nil {
					crawlDBErr = err
				}
			})
			if crawlDBErr != nil {
				return totalDNSDuration, totalProbeDuration, crawlDBErr
			}
			if crawlErr != nil {
				return totalDNSDuration, totalProbeDuration, crawlErr
			}
			if len(crawlFound) > 0 {
				if st.resolve != nil {
					resolvedChildren, dnsDur, rErr := r.filterStoredHostsDNS(ctx, dbStore, st, crawlFound)
					totalDNSDuration += dnsDur
					if rErr != nil {
						return totalDNSDuration, totalProbeDuration, rErr
					}
					nextProbeBatch = append(nextProbeBatch, resolvedChildren...)
				} else {
					nextProbeBatch = append(nextProbeBatch, crawlFound...)
				}
			}
		}
		toProbe = nextProbeBatch
	}

	return totalDNSDuration, totalProbeDuration, nil
}

func (r *Runner) filterStoredHostsDNS(
	ctx context.Context,
	dbStore *store.Store,
	st *scanState,
	hosts []string,
) ([]string, time.Duration, error) {
	if len(hosts) == 0 {
		return nil, 0, nil
	}

	resMap, dur, err := r.resolveBatch(ctx, st, hosts)

	var (
		resolved      []string
		wildcards     []string
		danglingCount int
		deadCount     int
	)
	for _, h := range hosts {
		res, ok := resMap[scan.Normalize(h)]
		if !ok {
			continue
		}
		if res.Wildcard {
			st.wildcards[h] = true
			wildcards = append(wildcards, h)
			continue
		}
		if res.Resolved || res.CNAME != "" {
			if sErr := dbStore.SaveDNS(h, res); sErr != nil {
				gologger.Warning().Msgf("save dns %s: %v", h, sErr)
			}
		}
		switch {
		case res.Resolved:
			resolved = append(resolved, h)
		case res.CNAME != "":
			danglingCount++
		default:
			deadCount++
		}
	}

	if len(wildcards) > 0 {
		if dErr := dbStore.DeleteHosts(st.root, wildcards); dErr != nil {
			return nil, dur, dErr
		}
	}

	if err != nil {
		return nil, dur, err
	}

	gologger.Info().Msgf("[%s] dns resolution completed: %d/%d resolved, %d dangling CNAME, %d wildcard pruned, %d dead skipped in %s",
		st.root, len(resolved), len(hosts), danglingCount, len(wildcards), deadCount, types.FormatDuration(dur))

	return resolved, dur, nil
}

func newBatchProgress(verb, rateUnit string, start time.Time) (func(completed, total int), func()) {
	var (
		lastUpdate time.Time
		lastLog    time.Time
		updateMu   sync.Mutex
	)
	fi, err := os.Stderr.Stat()
	isTTY := err == nil && (fi.Mode()&os.ModeCharDevice) != 0

	onProgress := func(completed, total int) {
		updateMu.Lock()
		defer updateMu.Unlock()

		now := time.Now()
		elapsed := now.Sub(start)
		pct := float64(completed) / float64(total) * 100
		speed := float64(completed) / elapsed.Seconds()

		eta := "finishing..."
		if speed > 0 && completed < total {
			remSec := float64(total-completed) / speed
			eta = "~" + types.FormatDuration(time.Duration(remSec*float64(time.Second))) + " remaining"
		}

		if isTTY {
			if completed < total && now.Sub(lastUpdate) < 250*time.Millisecond {
				return
			}
			lastUpdate = now
			fmt.Fprintf(os.Stderr, "\r\033[K[INF] %s %d/%d (%.0f%%) | %s elapsed | %s (%d %s)",
				verb, completed, total, pct, types.FormatDuration(elapsed), eta, int(speed), rateUnit)
			return
		}
		if completed < total && now.Sub(lastLog) < 5*time.Second {
			return
		}
		lastLog = now
		gologger.Info().Msgf("%s %d/%d (%.0f%%) | %s elapsed | %s",
			verb, completed, total, pct, types.FormatDuration(elapsed), eta)
	}

	clearTTY := func() {
		if isTTY {
			fmt.Fprint(os.Stderr, "\r\033[K")
		}
	}
	return onProgress, clearTTY
}

func (r *Runner) resolveBatch(
	ctx context.Context,
	st *scanState,
	hosts []string,
) (map[string]types.DNSResult, time.Duration, error) {
	results := make(map[string]types.DNSResult, len(hosts))
	if len(hosts) == 0 || st.resolve == nil {
		return results, 0, nil
	}

	gologger.Info().Msgf("[%s] resolving %d hosts via dnsx (%d qps, %d threads)",
		st.root, len(hosts), st.dnsRate, st.dnsThreads)

	resolveStart := time.Now()
	onProgress, clearTTY := newBatchProgress("resolving", "qps", resolveStart)

	var resMu sync.Mutex
	err := st.resolve(ctx, st.root, hosts, onProgress, func(host string, res types.DNSResult) {
		resMu.Lock()
		results[scan.Normalize(host)] = res
		resMu.Unlock()
	})

	dur := time.Since(resolveStart)
	clearTTY()

	return results, dur, err
}

func (r *Runner) probeBatch(
	ctx context.Context,
	dbStore *store.Store,
	hosts []string,
	o scan.ProbeOpts,
	onExtra func(host string, p types.Probe),
) (time.Duration, error) {
	if len(hosts) == 0 {
		return 0, nil
	}

	gologger.Info().Msgf("probing %d hosts (%d req/s, %d threads)", len(hosts), o.Rate, o.Threads)

	probeStart := time.Now()
	var clearTTY func()
	o.OnProgress, clearTTY = newBatchProgress("probing", "req/s", probeStart)

	err := scan.Probe(ctx, hosts, o, func(host string, p types.Probe) {
		if err := dbStore.SaveProbe(host, p); err != nil {
			gologger.Warning().Msgf("save %s: %v", host, err)
		}
		if onExtra != nil {
			onExtra(host, p)
		}
	})

	probeDuration := time.Since(probeStart)
	clearTTY()

	var speed int
	if probeDuration.Seconds() > 0 {
		speed = int(float64(len(hosts)) / probeDuration.Seconds())
	}
	gologger.Info().Msgf("probing completed: %d hosts probed in %s (%d req/s)",
		len(hosts), types.FormatDuration(probeDuration), speed)

	return probeDuration, err
}

// ExecuteQuery queries the database with filtering and outputs results.
func (r *Runner) ExecuteQuery(ctx context.Context) error {
	if _, err := os.Stat(r.options.DBPath); err != nil {
		return fmt.Errorf("database not found: %w", err)
	}

	dbStore, err := store.New(r.options.DBPath, true)
	if err != nil {
		return fmt.Errorf("open store: %w", err)
	}
	r.store = dbStore

	if r.options.RawSQL != "" {
		cols, rows, err := dbStore.RawQuery(r.options.RawSQL)
		if err != nil {
			return err
		}
		w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		fmt.Fprintln(w, strings.Join(cols, "\t"))
		for _, row := range rows {
			fmt.Fprintln(w, strings.Join(row, "\t"))
		}
		return w.Flush()
	}

	target := r.options.Target
	if target == "" {
		target = r.options.FilterRoot
	}

	f := types.Filter{
		Names:       r.options.Names,
		Tech:        r.options.Tech,
		WAF:         pick(r.options.HasWAF, r.options.NoWAF),
		WAFName:     r.options.WAFName,
		Alive:       pick(r.options.Alive, r.options.Dead),
		Resolved:    pick(r.options.Resolved, false),
		HasCNAME:    r.options.HasCNAME,
		CNAMETarget: r.options.CNAMETarget,
		Dangling:    r.options.Dangling,
		New:         r.options.NewOnly,
		Depth:       r.options.FilterDepth,
		Root:        target,
		AuthType:    r.options.AuthType,
	}

	for s := range strings.SplitSeq(r.options.Status, ",") {
		if s = strings.TrimSpace(s); s == "" {
			continue
		}
		n, err := strconv.Atoi(s)
		if err != nil {
			return fmt.Errorf("bad status %q", s)
		}
		f.Status = append(f.Status, n)
	}

	hosts, err := dbStore.QueryHosts(f)
	if err != nil {
		return err
	}

	// If a specific target was requested and default table output is used without sub-filters, print the dossier
	if r.options.Target != "" && r.options.OutputFormat == "table" && !hasQuerySubFilters(r.options) {
		PrintTargetSummary(os.Stdout, r.options.Target, hosts)
		return nil
	}

	switch r.options.OutputFormat {
	case "list":
		for _, h := range hosts {
			fmt.Println(h.Host)
		}
	case "json":
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if hosts == nil {
			hosts = []types.Host{}
		}
		return enc.Encode(hosts)
	case "table":
		w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		fmt.Fprintln(w, "HOST\tSTATUS\tAUTH\tTITLE\tTECH\tWAF\tIPS\tCNAME")
		for _, h := range hosts {
			st := "-"
			if h.Alive {
				st = strconv.Itoa(h.Status)
			}
			auth := "-"
			if h.AuthType != "" {
				auth = h.AuthType
			}
			cname := "-"
			if h.CNAME != "" {
				cname = types.ClipRunes(h.CNAME, 35)
			}
			fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
				h.Host, st, auth, types.ClipRunes(h.Title, 35), types.ClipRunes(strings.Join(h.Tech, ","), 35), h.WAF, h.IPs, cname)
		}
		if err := w.Flush(); err != nil {
			return err
		}
		fmt.Fprintf(os.Stderr, "%d hosts\n", len(hosts))
	default:
		return fmt.Errorf("unknown output format %q (table, list, json)", r.options.OutputFormat)
	}

	return nil
}

// ExecuteReport generates an HTML report.
func (r *Runner) ExecuteReport(ctx context.Context) error {
	if _, err := os.Stat(r.options.DBPath); err != nil {
		return fmt.Errorf("database not found: %w", err)
	}

	dbStore, err := store.New(r.options.DBPath, true)
	if err != nil {
		return fmt.Errorf("open store: %w", err)
	}
	r.store = dbStore

	scopeRoot := r.requestedScopeRoot()
	out := r.options.ReportOutput
	if out == "" {
		if scopeRoot != "" {
			out = scopeRoot + "-report.html"
		} else {
			out = "report.html"
		}
	}

	if err := report.WriteScopedReport(dbStore, scopeRoot, out); err != nil {
		return err
	}

	gologger.Info().Msgf("report written to %s", out)

	if r.options.Serve != "" {
		return runScopedServer(ctx, dbStore, resolveServeAddr(r.options.Serve, r.options.Port), scopeRoot)
	}

	return nil
}

// ExecuteServe starts the dashboard web server on the specified port.
func (r *Runner) ExecuteServe(ctx context.Context) error {
	if _, err := os.Stat(r.options.DBPath); err != nil {
		return fmt.Errorf("database not found: %w", err)
	}

	dbStore, err := store.New(r.options.DBPath, true)
	if err != nil {
		return fmt.Errorf("open store: %w", err)
	}
	r.store = dbStore

	return runScopedServer(ctx, dbStore, resolveServeAddr(r.options.Serve, r.options.Port), r.requestedScopeRoot())
}

func (r *Runner) requestedScopeRoot() string {
	switch {
	case r.options.Target != "":
		return scan.Normalize(r.options.Target)
	case r.options.FilterRoot != "":
		return scan.Normalize(r.options.FilterRoot)
	case r.options.Domain != "":
		return scan.Normalize(r.options.Domain)
	default:
		return ""
	}
}

func readRoots(domain, list string) ([]string, error) {
	var roots []string
	if domain != "" {
		roots = append(roots, scan.Normalize(domain))
	}
	if list != "" {
		f, err := os.Open(list)
		if err != nil {
			return nil, err
		}
		defer f.Close()
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			if d := scan.Normalize(sc.Text()); d != "" && !strings.HasPrefix(d, "#") {
				roots = append(roots, d)
			}
		}
		if err := sc.Err(); err != nil {
			return nil, err
		}
	}
	if len(roots) == 0 {
		return nil, errors.New("need -d or -dL")
	}
	for _, r := range roots {
		if !strings.Contains(r, ".") || strings.ContainsAny(r, "/: ") {
			return nil, fmt.Errorf("invalid domain %q (use a bare domain like example.com)", r)
		}
	}
	return roots, nil
}

func pick(yes, no bool) string {
	switch {
	case yes:
		return "yes"
	case no:
		return "no"
	}
	return ""
}

func b2i(b bool) int {
	if b {
		return 1
	}
	return 0
}
