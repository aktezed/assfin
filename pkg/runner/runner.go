package runner

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
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
	options *types.Options
	store   *store.Store
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

	enum, err := scan.NewSubfinder(r.options.SubfinderTimeout, r.options.SubfinderMaxTime, r.options.ProviderConfig)
	if err != nil {
		return fmt.Errorf("subfinder init: %w", err)
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
		crawlOpts := scan.CrawlOpts{
			Depth:    r.options.Depth,
			MaxHosts: r.options.MaxHosts,
			Conc:     r.options.SubfinderConcurrency,
			Exclude:  exclude,
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
						root, formatDuration(time.Since(enumStart)), discovered.Load())
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
			root, discovered.Load(), formatDuration(enumDuration))

		var probeDuration time.Duration
		if !r.options.NoProbe {
			probeOpts := scan.ProbeOpts{
				Threads: r.options.Threads,
				Timeout: r.options.Timeout,
				Rate:    r.options.RateLimit,
				Follow:  r.options.FollowRedirects,
			}
			probeDuration, err = r.probeRoot(ctx, dbStore, root, probeOpts)
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
					scan.ClassifyAliveHosts(ctx, aliveHosts, threads, r.options.Timeout, func(h string, authType, authURL string) {
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

		var alive, wafCount, fresh int
		for _, h := range all {
			alive += b2i(h.Alive)
			wafCount += b2i(h.WAF != "")
			fresh += b2i(h.New)
		}

		scanDuration := time.Since(scanStart)
		if r.options.NoProbe {
			gologger.Info().Msgf("%s: %d hosts, %d new in %s -> %s",
				root, len(all), fresh, formatDuration(scanDuration), dbPath)
		} else {
			gologger.Info().Msgf("%s: %d hosts, %d alive, %d behind WAF, %d new in %s (enum: %s, probe: %s) -> %s",
				root, len(all), alive, wafCount, fresh, formatDuration(scanDuration),
				formatDuration(enumDuration), formatDuration(probeDuration), dbPath)
		}

		if !r.options.Silent {
			PrintTargetSummary(os.Stdout, root, all)
		}
	}

	if len(roots) > 1 {
		gologger.Info().Msgf("all %d domains scanned in %s", len(roots), formatDuration(time.Since(totalScanStart)))
	}

	if r.options.Report || r.options.ReportOutput != "" {
		out := r.options.ReportOutput
		if out == "" {
			if len(roots) == 1 {
				out = roots[0] + "-report.html"
			} else {
				out = "assfin-report.html"
			}
		}
		if err := report.WriteReport(dbStore, out); err != nil {
			return fmt.Errorf("write report: %w", err)
		}
		gologger.Info().Msgf("report written to %s", out)
	}

	if r.options.Serve != "" {
		listenAddr := r.options.Serve
		if listenAddr == "true" {
			listenAddr = fmt.Sprintf(":%d", r.options.Port)
		}
		return RunServer(ctx, dbStore, listenAddr)
	}

	return nil
}

func (r *Runner) probeRoot(ctx context.Context, dbStore *store.Store, root string, o scan.ProbeOpts) (time.Duration, error) {
	known, err := dbStore.QueryHosts(types.Filter{Root: root, Depth: -1})
	if err != nil {
		return 0, err
	}
	if err := dbStore.ResetProbe(root); err != nil {
		return 0, err
	}
	hosts := make([]string, len(known))
	for i, h := range known {
		hosts[i] = h.Host
	}

	if len(hosts) == 0 {
		return 0, nil
	}

	gologger.Info().Msgf("probing %d hosts (%d req/s, %d threads)", len(hosts), o.Rate, o.Threads)

	probeStart := time.Now()
	var (
		lastUpdate time.Time
		lastLog    time.Time
		updateMu   sync.Mutex
	)

	fi, err := os.Stderr.Stat()
	isTTY := err == nil && (fi.Mode()&os.ModeCharDevice) != 0

	o.OnProgress = func(completed, total int) {
		updateMu.Lock()
		defer updateMu.Unlock()

		now := time.Now()
		elapsed := now.Sub(probeStart)
		pct := float64(completed) / float64(total) * 100
		speed := float64(completed) / elapsed.Seconds()

		var eta string
		if speed > 0 && completed < total {
			remSec := float64(total-completed) / speed
			eta = "~" + formatDuration(time.Duration(remSec*float64(time.Second))) + " remaining"
		} else {
			eta = "finishing..."
		}

		if isTTY {
			if completed < total && now.Sub(lastUpdate) < 250*time.Millisecond {
				return
			}
			lastUpdate = now
			fmt.Fprintf(os.Stderr, "\r\033[K[INF] probing %d/%d (%.0f%%) | %s elapsed | %s (%d req/s)",
				completed, total, pct, formatDuration(elapsed), eta, int(speed))
		} else {
			if completed < total && now.Sub(lastLog) < 5*time.Second {
				return
			}
			lastLog = now
			gologger.Info().Msgf("probing %d/%d (%.0f%%) | %s elapsed | %s",
				completed, total, pct, formatDuration(elapsed), eta)
		}
	}

	err = scan.Probe(ctx, hosts, o, func(host string, p types.Probe) {
		if err := dbStore.SaveProbe(host, p); err != nil {
			gologger.Warning().Msgf("save %s: %v", host, err)
		}
	})

	probeDuration := time.Since(probeStart)
	if isTTY {
		fmt.Fprint(os.Stderr, "\r\033[K")
	}

	var speed int
	if probeDuration.Seconds() > 0 {
		speed = int(float64(len(hosts)) / probeDuration.Seconds())
	}
	gologger.Info().Msgf("probing completed: %d hosts probed in %s (%d req/s)",
		len(hosts), formatDuration(probeDuration), speed)

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
		Names:    r.options.Names,
		Tech:     r.options.Tech,
		WAF:      pick(r.options.HasWAF, r.options.NoWAF),
		WAFName:  r.options.WAFName,
		Alive:    pick(r.options.Alive, r.options.Dead),
		New:      r.options.NewOnly,
		Depth:    r.options.FilterDepth,
		Root:     target,
		AuthType: r.options.AuthType,
	}

	for _, s := range strings.Split(r.options.Status, ",") {
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
	if r.options.Target != "" && r.options.OutputFormat == "table" && len(r.options.Names) == 0 && len(r.options.Tech) == 0 && r.options.AuthType == "" && r.options.Status == "" {
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
		fmt.Fprintln(w, "HOST\tSTATUS\tAUTH\tTITLE\tTECH\tWAF\tIPS")
		for _, h := range hosts {
			st := "-"
			if h.Alive {
				st = strconv.Itoa(h.Status)
			}
			auth := "-"
			if h.AuthType != "" {
				auth = h.AuthType
			}
			fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\t%s\n", h.Host, st, auth, clip(h.Title, 35), clip(strings.Join(h.Tech, ","), 35), h.WAF, h.IPs)
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

	out := r.options.ReportOutput
	if out == "" {
		if r.options.Domain != "" {
			out = r.options.Domain + "-report.html"
		} else if r.options.Target != "" {
			out = r.options.Target + "-report.html"
		} else if r.options.FilterRoot != "" {
			out = r.options.FilterRoot + "-report.html"
		} else {
			out = "report.html"
		}
	}

	if err := report.WriteReport(dbStore, out); err != nil {
		return err
	}

	gologger.Info().Msgf("report written to %s", out)

	if r.options.Serve != "" {
		listenAddr := r.options.Serve
		if listenAddr == "true" {
			listenAddr = fmt.Sprintf(":%d", r.options.Port)
		}
		return RunServer(ctx, dbStore, listenAddr)
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

	listenAddr := r.options.Serve
	if listenAddr == "" || listenAddr == "true" {
		port := r.options.Port
		if port <= 0 {
			port = 8080
		}
		listenAddr = fmt.Sprintf(":%d", port)
	}

	return RunServer(ctx, dbStore, listenAddr)
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

func clip(s string, n int) string {
	if r := []rune(s); len(r) > n {
		return string(r[:n-1]) + "…"
	}
	return s
}

func formatDuration(d time.Duration) string {
	return types.FormatDuration(d)
}
