package runner

import (
	"errors"
	"os"
	"path/filepath"

	"github.com/aktezed/assfin/pkg/types"
	"github.com/projectdiscovery/goflags"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/gologger/levels"
)

// ParseOptions parses command line flags and returns Options.
func ParseOptions() *types.Options {
	opts := &types.Options{}
	flagSet := goflags.NewFlagSet()
	flagSet.SetDescription("assfin - recursive passive subdomain recon & asset intelligence")

	// Ensure config directory is writable (fallback to local workspace file in restricted/sandbox environments)
	configDir, err := os.UserConfigDir()
	configPath := ".assfin-config.yaml"
	if err == nil {
		appDir := filepath.Join(configDir, "assfin")
		if err := os.MkdirAll(appDir, 0o755); err == nil {
			configPath = filepath.Join(appDir, "config.yaml")
		}
	}
	flagSet.SetConfigFilePath(configPath)

	args := os.Args[1:]
	if len(args) > 0 {
		switch args[0] {
		case "scan":
			opts.Command = "scan"
			args = args[1:]
		case "query":
			opts.Command = "query"
			args = args[1:]
		case "report":
			opts.Command = "report"
			args = args[1:]
		}
	}

	// Target Inputs
	flagSet.CreateGroup("input", "INPUT",
		flagSet.StringVarP(&opts.Domain, "domain", "d", "", "root domain to scan"),
		flagSet.StringVarP(&opts.DomainList, "list", "dL", "", "file with root domains, one per line"),
	)

	// Storage
	flagSet.CreateGroup("storage", "STORAGE",
		flagSet.StringVar(&opts.DBPath, "db", "", "SQLite output (default <domain>.db, or assfin.db with -dL)"),
	)

	// Crawling / Recursion
	flagSet.CreateGroup("recursion", "RECURSION",
		flagSet.IntVar(&opts.Depth, "depth", 1, "recursion rounds after the root query (0 = root only)"),
		flagSet.IntVar(&opts.MaxHosts, "max-hosts", 5000, "stop enumerating a root after this many hosts (0 = no cap)"),
		flagSet.StringSliceVar(&opts.Exclude, "exclude", nil, "out-of-scope hosts/suffixes (comma-separated)", goflags.CommaSeparatedStringSliceOptions),
	)

	// Subfinder
	flagSet.CreateGroup("subfinder", "SUBFINDER",
		flagSet.IntVar(&opts.SubfinderTimeout, "sf-timeout", 15, "subfinder per-source timeout in seconds"),
		flagSet.IntVar(&opts.SubfinderMaxTime, "sf-max-time", 2, "subfinder max minutes per domain"),
		flagSet.IntVar(&opts.SubfinderConcurrency, "sf-concurrency", 5, "subdomains enumerated in parallel"),
		flagSet.StringVarP(&opts.ProviderConfig, "provider-config", "pc", "", "subfinder provider-config.yaml"),
	)

	// HTTPX Probing
	flagSet.CreateGroup("httpx", "PROBING",
		flagSet.IntVar(&opts.RateLimit, "rate", 30, "httpx max requests per second"),
		flagSet.IntVar(&opts.Threads, "threads", 25, "httpx threads"),
		flagSet.IntVar(&opts.Timeout, "timeout", 7, "httpx request timeout in seconds"),
		flagSet.BoolVar(&opts.FollowRedirects, "follow", false, "follow redirects when probing"),
		flagSet.BoolVar(&opts.NoProbe, "no-probe", false, "enumerate only, skip httpx"),
	)

	// Query / Filtering
	flagSet.CreateGroup("query", "QUERY / FILTER",
		flagSet.BoolVarP(&opts.Query, "query", "q", false, "run in query mode against existing database"),
		flagSet.StringSliceVar(&opts.Names, "name", nil, "host contains (comma-separated for OR)", goflags.CommaSeparatedStringSliceOptions),
		flagSet.StringSliceVar(&opts.Tech, "tech", nil, "technology, e.g. -tech nginx,php", goflags.CommaSeparatedStringSliceOptions),
		flagSet.BoolVar(&opts.HasWAF, "waf", false, "only hosts behind a WAF"),
		flagSet.BoolVar(&opts.NoWAF, "no-waf", false, "only hosts with no WAF detected"),
		flagSet.StringVar(&opts.WAFName, "waf-name", "", "WAF name contains, e.g. cloudflare"),
		flagSet.BoolVar(&opts.Alive, "alive", false, "only hosts that answered HTTP(S)"),
		flagSet.BoolVar(&opts.Dead, "dead", false, "only hosts that did not answer"),
		flagSet.StringVar(&opts.Status, "status", "", "status codes, e.g. 200,403"),
		flagSet.BoolVar(&opts.NewOnly, "new", false, "only hosts first seen in the latest scan"),
		flagSet.IntVar(&opts.FilterDepth, "filter-depth", -1, "label depth: 1 = x.root, 2 = y.x.root"),
		flagSet.StringVar(&opts.FilterRoot, "root", "", "only this root domain"),
		flagSet.StringVar(&opts.RawSQL, "sql", "", `raw read-only SQL, e.g. "SELECT host, tech FROM hosts WHERE status=401"`),
		flagSet.StringVarP(&opts.OutputFormat, "output-format", "o", "table", "output: table, list, json"),
	)

	// Report
	flagSet.CreateGroup("report", "REPORT",
		flagSet.BoolVar(&opts.Report, "report", false, "generate HTML report from database (or after scan)"),
		flagSet.StringVar(&opts.ReportOutput, "out", "", "HTML report output path (default report.html)"),
	)

	// General
	flagSet.CreateGroup("general", "GENERAL",
		flagSet.BoolVarP(&opts.Silent, "silent", "s", false, "silent mode: output only results"),
		flagSet.BoolVar(&opts.Version, "version", false, "show version"),
	)

	if err := flagSet.Parse(args...); err != nil {
		gologger.Fatal().Msgf("Could not parse flags: %s\n", err)
	}

	if opts.Silent {
		gologger.DefaultLogger.SetMaxLevel(levels.LevelSilent)
	}

	if opts.Version {
		showBanner()
		os.Exit(0)
	}

	if !opts.Silent {
		showBanner()
	}

	if err := validateOptions(opts); err != nil {
		gologger.Fatal().Msgf("Options error: %s\n", err)
	}

	return opts
}

func validateOptions(opts *types.Options) error {
	// Determine effective command if not set explicitly
	if opts.Command == "" {
		switch {
		case opts.Domain != "" || opts.DomainList != "":
			opts.Command = "scan"
		case opts.Report || opts.ReportOutput != "":
			opts.Command = "report"
		case opts.Query || opts.RawSQL != "" || opts.HasWAF || opts.NoWAF || opts.Alive || opts.Dead || len(opts.Names) > 0 || len(opts.Tech) > 0 || opts.Status != "":
			opts.Command = "query"
		default:
			return errors.New("no command or targets specified (use -d, -dL, -q, or -report)")
		}
	}

	if opts.Command == "query" || opts.Command == "report" {
		if opts.DBPath == "" {
			return errors.New("need -db for query or report")
		}
	}

	if opts.HasWAF && opts.NoWAF {
		return errors.New("conflicting flags: -waf and -no-waf cannot be used together")
	}

	if opts.Alive && opts.Dead {
		return errors.New("conflicting flags: -alive and -dead cannot be used together")
	}

	return nil
}
