<h1 align="center">
  <br>
  <a href="https://github.com/aktezed/assfin"><img src="static/assfin-logo.svg" width="220px" alt="assfin"></a>
  <br>
  assfin
  <br>
</h1>

<h4 align="center">Recursive, passive subdomain reconnaissance and HTTP probing toolkit</h4>

<p align="center">
<a href="https://github.com/aktezed/assfin/releases"><img src="https://img.shields.io/github/release/aktezed/assfin.svg"></a>
<a href="https://goreportcard.com/report/github.com/aktezed/assfin"><img src="https://goreportcard.com/badge/github.com/aktezed/assfin"></a>
<a href="https://pkg.go.dev/github.com/aktezed/assfin"><img src="https://pkg.go.dev/badge/github.com/aktezed/assfin.svg"></a>
<a href="https://github.com/aktezed/assfin/blob/main/LICENSE"><img src="https://img.shields.io/badge/license-MIT-blue.svg"></a>
</p>

<p align="center">
  <a href="#features">Features</a> •
  <a href="#installation">Installation</a> •
  <a href="#usage">Usage</a> •
  <a href="#running-assfin">Running assfin</a> •
  <a href="#querying-results">Querying Results</a> •
  <a href="#html-reports">HTML Reports</a> •
  <a href="#library-usage">Library Usage</a> •
  <a href="#how-it-works">How It Works</a>
</p>

---

**assfin** is a passive reconnaissance and asset intelligence tool that automates recursive subdomain discovery and HTTP service probing in a single Go binary. It queries passive sources for a target root domain using [subfinder](https://github.com/projectdiscovery/subfinder), iteratively recurses across every discovered subdomain layer until no new targets emerge, and immediately verifies live services with [httpx](https://github.com/projectdiscovery/httpx).

All results are deduplicated and tracked in a persistent SQLite database with historical timeline metadata (`first_seen`, `last_seen`, `new`), which can be queried directly via CLI, piped into downstream tools like [nuclei](https://github.com/projectdiscovery/nuclei), or exported into a standalone offline HTML dashboard.

---

## Features

- **Recursive Passive Discovery:** Iteratively enumerates multi-level subdomains by feeding newly uncovered assets back into passive discovery rounds until exhaustion.
- **WAF-Safe Probing:** Pre-configured with conservative request rates (30 req/s, 25 workers) and no DNS brute-forcing to avoid rate limits or disruption.
- **Heuristic WAF Detection:** Detects Cloudflare, Akamai, Imperva, and other WAFs using IP CIDR matching (`cdncheck`) and response headers/cookies without sending attack payloads.
- **Persistent Asset Database:** Tracks target history across runs in SQLite, automatically identifying newly appeared hosts and marking unreachable endpoints.
- **Pipe-Friendly Architecture:** Supports `table`, `list`, and `json` output streams to integrate cleanly with `nuclei`, `katana`, or custom automation pipelines.
- **Self-Contained HTML Reports:** Produces portable, single-file offline dashboards with status filters, technology tags, and WAF categorization.
- **Go Library / SDK:** Clean programmatic API through `pkg/runner` for direct integration into custom Go tools.

---

## Installation

### Using Go

```bash
go install -v github.com/aktezed/assfin/cmd/assfin@latest
```

### From Source

```bash
git clone https://github.com/aktezed/assfin.git
cd assfin
make build
# Binary is compiled to bin/assfin
```

### Pre-built Binaries

Pre-compiled releases for macOS, Linux, and Windows are available on the [Releases](https://github.com/aktezed/assfin/releases) page.

---

## Usage

```bash
assfin -h
```

This displays help for all available flags and command modes:

```text
assfin - recursive passive subdomain recon & asset intelligence

Usage:
  assfin [flags]

Flags:
INPUT:
   -d, -domain string  root domain to scan
   -dL, -list string   file with root domains, one per line

STORAGE:
   -db string  SQLite output (default <domain>.db, or assfin.db with -dL)

RECURSION:
   -depth int         recursion rounds after root (-1 = auto-increase until nothing new is found, 0 = root only) (default -1)
   -max-hosts int     stop enumerating a root after this many hosts (0 = no cap) (default 5000)
   -exclude string[]  out-of-scope hosts/suffixes (comma-separated)

SUBFINDER:
   -sf-timeout int               subfinder per-source timeout in seconds (default 15)
   -sf-max-time int              subfinder max minutes per domain (default 2)
   -sf-concurrency int           subdomains enumerated in parallel (default 5)
   -pc, -provider-config string  subfinder provider-config.yaml

PROBING & CLASSIFICATION:
   -rate int          httpx max requests per second (default 30)
   -threads int       httpx threads (default 25)
   -timeout int       httpx request timeout in seconds (default 7)
   -follow            follow redirects when probing
   -no-probe          enumerate only, skip httpx
   -no-auth           skip asset role (register/login/landing) classification
   -auth-threads int  asset classification concurrency threads (default 10)

QUERY / FILTER:
   -q, -query                 run in query mode against existing database
   -t, -target string         target root domain for scoped query and summary
   -auth-type string          filter by asset role: register, login_only, landing
   -name string[]             host contains (comma-separated for OR)
   -tech string[]             technology, e.g. -tech nginx,php
   -waf                       only hosts behind a WAF
   -no-waf                    only hosts with no WAF detected
   -waf-name string           WAF name contains, e.g. cloudflare
   -alive                     only hosts that answered HTTP(S)
   -dead                      only hosts that did not answer
   -status string             status codes, e.g. 200,403
   -new                       only hosts first seen in the latest scan
   -filter-depth int          label depth: 1 = x.root, 2 = y.x.root (default -1)
   -root string               only this root domain
   -sql string                raw read-only SQL, e.g. "SELECT host, tech FROM hosts WHERE status=401"
   -o, -output-format string  output: table, list, json (default "table")

REPORT & SERVER:
   -report        generate HTML report from database (or after scan)
   -out string    HTML report output path (default <target>-report.html)
   -serve string  start headless dashboard web server on address/port (e.g. :8080 or 8080)
   -p, -port int  port for dashboard web server (default 8080)

GENERAL:
   -s, -silent  silent mode: output only results
   -version     show version
```

---

## Running assfin

### Scan Mode

Scan a single root domain and store output in `example.com.db`:

```bash
assfin scan -d example.com
```

Scan and generate an interactive HTML report in the same run:

```bash
assfin scan -d example.com -report
assfin scan -d example.com -report -out dashboard.html
```

Scan multiple root domains from an input file:

```bash
assfin scan -dL roots.txt -db targets.db
```

Exclude out-of-scope subdomains or domains:

```bash
assfin scan -d example.com -exclude staging.example.com,internal.example.com
```

### WAF-Safe Fast Defaults

| Flag | Default | Description |
|---|---|---|
| `-depth` | `-1` (auto) | Automatically increases depth (`1 -> 2 -> 3...`) until no new hosts are found (`0` = root only) |
| `-max-hosts` | `5000` | Max hosts to discover per root domain before stopping |
| `-sf-concurrency` | `5` | Number of subdomains enumerated concurrently |
| `-sf-timeout` | `15s` | Subfinder per-source timeout |
| `-sf-max-time` | `2m` | Subfinder total timeout per domain |
| `-rate` | `30` | Maximum HTTP requests per second for httpx |
| `-threads` | `25` | Worker thread count for httpx |
| `-timeout` | `7s` | HTTP request timeout |
| `-follow` | `false` | Follow HTTP redirects |
| `-no-probe` | `false` | Passive enumeration only; skips HTTP probing |

> [!NOTE]
> Enumeration uses passive sources only (e.g. crt.sh, VirusTotal, AlienVault) and never queries the target's authoritative DNS servers. The only packets sent to target infrastructure are standard HTTP/HTTPS GET requests from `httpx` governed by `-rate`.

### Passive API Configuration

`assfin` automatically loads subfinder's standard configuration at `~/.config/subfinder/provider-config.yaml`. You can also specify an alternate config path with `-pc`:

```bash
assfin scan -d example.com -pc /path/to/provider-config.yaml
```

---

## Querying Results

Query mode allows fast filtering against an existing SQLite database without making any network requests.

```bash
# Filter alive hosts with no WAF detected
assfin query -db example.com.db -alive -no-waf

# Filter by technology stack and HTTP response code
assfin query -db example.com.db -tech wordpress -status 200

# Filter hosts containing specific keywords
assfin query -db example.com.db -name api,admin,staging

# Filter by specific WAF vendor
assfin query -db example.com.db -waf-name cloudflare

# Filter by asset role: registerable, login_only, or landing
assfin query -db example.com.db -auth-type register

# View formatted terminal dossier for a target (ideal on headless VPS)
assfin query -db example.com.db -target example.com

# Filter newly discovered hosts from the latest scan and pipe to nuclei
assfin query -db example.com.db -new -o list | nuclei -t cves/

# Filter by subdomain label depth (1 = sub.domain.com, 2 = deep.sub.domain.com)
assfin query -db example.com.db -filter-depth 2 -o json

# Run raw read-only SQL queries
assfin query -db example.com.db -sql "SELECT host, title, status, auth_type FROM hosts WHERE status = 200"
```

### Database Schema

The `hosts` table contains the following fields:

```text
host, root, depth, sources, first_seen, last_seen, first_scan, last_scan, alive, url, status, title, server, tech, ips, cdn, waf, length, auth_type, auth_url
```

---

## Reports & Headless VPS Dashboard

### Target-Specific Reports
Generate a self-contained, offline-compatible HTML dashboard from an existing database. Scans automatically name the report after the target (e.g. `example.com-report.html`):

```bash
# Output defaults to example.com-report.html
assfin report -db example.com.db -target example.com

# Custom report output path
assfin report -db example.com.db -out audit.html
```

### Headless VPS Dashboard Server
When running on a headless VPS without a desktop browser, start the built-in lightweight web server:

```bash
# Start server on default port 8080
assfin serve -db example.com.db -port 8080

# Or start server right after scanning
assfin scan -d example.com -serve 8080
```

Access from your local machine using an SSH tunnel:
```bash
ssh -NL 8080:localhost:8080 user@<vps-ip>
# Then open http://localhost:8080 in your laptop browser!
```

The generated report features:
- **Visual Breakdown:** Tri-color distribution bar showing reachable without WAF, behind WAF, and unresponsive hosts.
- **Interactive Filtering:** Instant keyword search, HTTP status code filtering, and technology tag filtering.
- **Host Details:** Expandable drawer for each host containing resolved IPs, response headers, detected technologies, and titles.

---

## Library Usage

`assfin` can be used programmatically in your Go projects using `pkg/runner`:

```go
package main

import (
	"context"
	"log"

	"github.com/aktezed/assfin/pkg/runner"
	"github.com/aktezed/assfin/pkg/types"
)

func main() {
	options := &types.Options{
		Command: "scan",
		Domain:  "example.com",
		DBPath:  "example.db",
		Depth:   2,
	}

	r, err := runner.NewRunner(options)
	if err != nil {
		log.Fatal(err)
	}
	defer r.Close()

	if err := r.Run(context.Background()); err != nil {
		log.Fatal(err)
	}
}
```

---

## How It Works

### Recursive Passive Discovery

```
[Target Domain] ──▶ (Round 0: Subfinder Passive Sources)
                           │
                           ▼
                  [Discovered Subdomains]
                           │
                           ▼
              (Round 1..N: Recursive Re-Feed)
              Repeats until 0 new hosts discovered
                           │
                           ▼
                     [Deduplication]
                           │
                           ▼
               [HTTPX WAF-Safe Probing]
                           │
                           ▼
                   [SQLite Storage]
```

1. **Initial Harvest:** `assfin` enumerates the root domain across dozens of passive sources.
2. **Recursive Expansion:** Any newly identified subdomain is added to the crawl queue and fed back into passive sources. Rounds continue automatically until no new subdomains appear (or `-depth` limit is reached).
3. **Controlled Probing:** Discovered hosts are probed using `httpx` with WAF-safe concurrency (`-rate 30`).
4. **State Persistence:** Hosts are written to SQLite, preserving first-seen and last-seen timestamps to track asset changes over time.

### Heuristic WAF Detection

WAF detection runs entirely without intrusive payloads:
1. **IP Range Matching:** Matches remote IPs against known WAF/CDN CIDR ranges (Cloudflare, Akamai, Imperva, Fastly, CloudFront, etc.) via `cdncheck`.
2. **Passive Header & Cookie Inspection:** If IP checks are inconclusive, checks response headers (e.g. `cf-ray`, `x-sucuri-id`) and cookies (`incap_ses_`, `__cf_bm`) collected during probing.

---

## Limitations

- **Passive Data Dependency:** Discovery relies entirely on passive sources. If an asset has never appeared in certificate transparency logs, DNS datasets, or public indices, passive recursion will not find it.
- **Active DNS Permutations:** `assfin` does not perform active DNS brute-forcing or wordlist permutations.
- **Depth Saturation:** Most passive sources index all known hostnames in the first pass; recursion past depth 2 rarely yields substantial new hosts on standard targets.

---

## License

`assfin` is distributed under the [MIT License](LICENSE).
