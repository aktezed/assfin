package types

import "github.com/projectdiscovery/goflags"

// Options contains the configuration options for the assfin runner.
type Options struct {
	// Action subcommand (scan, query, report)
	Command string

	// Target Inputs
	Domain     string
	DomainList string

	// Output & Storage
	DBPath string

	// Recursion / Crawling
	Depth    int
	MaxHosts int
	Exclude  goflags.StringSlice

	// Subfinder Configuration
	SubfinderTimeout     int
	SubfinderMaxTime     int
	SubfinderConcurrency int
	ProviderConfig       string

	// HTTPX Probing Configuration
	RateLimit       int
	Threads         int
	Timeout         int
	FollowRedirects bool
	NoProbe         bool

	// Asset Role / Auth Classification
	NoAuth      bool
	AuthThreads int

	// Query / Filtering
	Query        bool
	Names        goflags.StringSlice
	Tech         goflags.StringSlice
	HasWAF       bool
	NoWAF        bool
	WAFName      string
	Alive        bool
	Dead         bool
	Status       string
	NewOnly      bool
	FilterDepth  int
	FilterRoot   string
	RawSQL       string
	OutputFormat string
	AuthType     string
	Target       string

	// Reporting & Web Dashboard Server
	Report       bool
	ReportOutput string
	Serve        string
	Port         int

	// General
	Silent  bool
	Version bool
}
