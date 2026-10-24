# assfin

Recursive, passive subdomain recon in one Go binary. It runs [subfinder](https://github.com/projectdiscovery/subfinder) on a domain, then on every new subdomain it finds, until nothing new appears. Then it probes each host with [httpx](https://github.com/projectdiscovery/httpx) and stores the results in SQLite, so you can query them or turn them into an HTML report.

## Installation

```bash
# Install binary to $GOPATH/bin
go install -v github.com/aktezed/assfin/cmd/assfin@latest

# Or build locally
git clone https://github.com/aktezed/assfin.git
cd assfin
make build # creates bin/assfin
```

## Programmatic Library Usage (Go SDK)

Like other ProjectDiscovery tools (`subfinder`, `httpx`), `assfin` can be embedded directly in your Go programs via `pkg/runner`:

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

## Scan

```bash
assfin scan -d example.com                       # -> example.com.db
assfin scan -d example.com -report               # -> example.com.db + report.html in one command
assfin scan -d example.com -out example.html     # -> example.com.db + example.html in one command
assfin scan -dL roots.txt -db program.db         # several roots, one DB
assfin scan -d example.com -exclude legacy.example.com,cdn.example.com
```

Re-running a scan updates the same DB. Hosts found for the first time are marked **new**, and every host is probed again so dead ones show up as dead.

### Gentle by default

| Flag | Default | |
|---|---|---|
| `-depth` | `2` | recursion rounds after the root query (`0` = root only) |
| `-max-hosts` | `5000` | stop enumerating a root at this many hosts |
| `-sf-concurrency` | `1` | subdomains enumerated in parallel |
| `-sf-timeout` / `-sf-max-time` | `30`s / `5`min | subfinder source timeout / per-domain cap |
| `-rate` | `10` | httpx requests per second |
| `-threads` / `-timeout` | `10` / `10`s | httpx |
| `-follow` | off | follow redirects |
| `-no-probe` | off | enumerate only, send nothing to the target |

Enumeration is passive only: it queries third-party sources (crt.sh, VirusTotal, …) and never the target's DNS. The only traffic that reaches the target is the httpx probe, one GET per host (https first, then http), sent at `-rate` requests per second.

API keys: assfin reads subfinder's usual `~/.config/subfinder/provider-config.yaml` (or `-pc file`). Adding keys finds far more than raising `-depth`.

Ctrl+C stops cleanly. Everything found so far is already saved.

## Query

```bash
assfin query -db example.com.db -name api,dev              # host contains api OR dev
assfin query -db example.com.db -alive -no-waf             # reachable, no WAF detected
assfin query -db example.com.db -tech wordpress -status 200
assfin query -db example.com.db -waf-name cloudflare
assfin query -db example.com.db -new -o list | nuclei      # new hosts only, pipe-friendly
assfin query -db example.com.db -depth 2 -o json
assfin query -db example.com.db -sql "SELECT host, title FROM hosts WHERE status = 401"
```

Filters combine with AND. Repeating a flag or listing values with commas means OR. `-depth` is the label depth: `1` = `x.example.com`, `2` = `y.x.example.com`. Raw `-sql` runs on a read-only connection.

Columns in `hosts`: `host root depth sources first_seen last_seen first_scan last_scan alive url status title server tech ips cdn waf length`. `tech` is stored as `,Nginx:1.21,PHP,`.

## Report

```bash
assfin report -db example.com.db -out report.html
```

A single HTML file that works offline. It has a bar splitting hosts into reachable without a WAF, behind a WAF, and no response, plus search, status and tech filters, sortable columns, and a details row for each host.

## How WAF detection works

1. httpx's cdncheck matches the host's IP against known WAF ranges (Cloudflare, Akamai, Imperva, …).
2. If that finds nothing, assfin checks the headers and cookies of the response httpx already fetched (e.g. `cf-ray`, `x-sucuri-id`, `incap_ses_`).

No payloads are sent. A WAF that hides behind a generic IP and adds no headers won't be detected.

## Limits

- Passive sources usually return every level in the first round, so recursion past depth 2 rarely finds more.
- There's no DNS bruteforce or permutation (e.g. `dev-api`), so names no source has seen won't be found.
