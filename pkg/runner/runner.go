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
	"text/tabwriter"

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

	for _, root := range roots {
		scanID, err := dbStore.StartScan(root, string(optsJSON))
		if err != nil {
			return err
		}

		gologger.Info().Msgf("enumerating %s (depth %d, passive only)", root, r.options.Depth)
		if err := dbStore.UpsertHost(scanID, root, root, 0, nil); err != nil {
			return err
		}

		var dbErr error
		crawlOpts := scan.CrawlOpts{
			Depth:    r.options.Depth,
			MaxHosts: r.options.MaxHosts,
			Conc:     r.options.SubfinderConcurrency,
			Exclude:  exclude,
		}

		err = scan.Crawl(ctx, root, crawlOpts, enum, func(h string, sources []string) {
			if err := dbStore.UpsertHost(scanID, root, h, scan.LabelDepth(h, root), sources); err != nil && dbErr == nil {
				dbErr = err
			}
		})
		if dbErr != nil {
			return dbErr
		}
		if err != nil {
			return fmt.Errorf("enumeration stopped: %w (partial results saved to %s)", err, dbPath)
		}

		if !r.options.NoProbe {
			probeOpts := scan.ProbeOpts{
				Threads: r.options.Threads,
				Timeout: r.options.Timeout,
				Rate:    r.options.RateLimit,
				Follow:  r.options.FollowRedirects,
			}
			if err := r.probeRoot(ctx, dbStore, root, probeOpts); err != nil {
				return fmt.Errorf("probing stopped: %w (partial results saved to %s)", err, dbPath)
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
		gologger.Info().Msgf("%s: %d hosts, %d alive, %d behind WAF, %d new -> %s", root, len(all), alive, wafCount, fresh, dbPath)
	}

	return nil
}

func (r *Runner) probeRoot(ctx context.Context, dbStore *store.Store, root string, o scan.ProbeOpts) error {
	known, err := dbStore.QueryHosts(types.Filter{Root: root, Depth: -1})
	if err != nil {
		return err
	}
	if err := dbStore.ResetProbe(root); err != nil {
		return err
	}
	hosts := make([]string, len(known))
	for i, h := range known {
		hosts[i] = h.Host
	}

	gologger.Info().Msgf("probing %d hosts (%d req/s, %d threads)", len(hosts), o.Rate, o.Threads)
	return scan.Probe(ctx, hosts, o, func(host string, p types.Probe) {
		if err := dbStore.SaveProbe(host, p); err != nil {
			gologger.Warning().Msgf("save %s: %v", host, err)
		}
	})
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

	f := types.Filter{
		Names:   r.options.Names,
		Tech:    r.options.Tech,
		WAF:     pick(r.options.HasWAF, r.options.NoWAF),
		WAFName: r.options.WAFName,
		Alive:   pick(r.options.Alive, r.options.Dead),
		New:     r.options.NewOnly,
		Depth:   r.options.FilterDepth,
		Root:    r.options.FilterRoot,
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
		fmt.Fprintln(w, "HOST\tSTATUS\tTITLE\tTECH\tWAF\tIPS")
		for _, h := range hosts {
			st := "-"
			if h.Alive {
				st = strconv.Itoa(h.Status)
			}
			fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\n", h.Host, st, clip(h.Title, 40), clip(strings.Join(h.Tech, ","), 40), h.WAF, h.IPs)
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
		out = "report.html"
	}

	if err := report.WriteReport(dbStore, out); err != nil {
		return err
	}

	gologger.Info().Msgf("report written to %s", out)
	return nil
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
