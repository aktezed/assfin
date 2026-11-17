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
  <a href="#why-use-assfin">Why assfin</a> •
  <a href="#install">Install</a> •
  <a href="#quick-start">Quick start</a> •
  <a href="#common-queries">Queries</a> •
  <a href="#reports-and-dashboard">Reports</a> •
  <a href="#key-flags">Flags</a>
</p>

`assfin` is a passive subdomain recon and HTTP probing CLI backed by SQLite. Run it when you want a repeatable inventory of what a domain exposes online without noisy DNS brute-forcing or fragile shell pipelines.

## Why use assfin

Standard recon usually means chaining `subfinder`, `dnsx`, `httpx`, and flat text files by hand. When a run gets cut off or you come back a week later, you end up re-scanning everything and diffing text files yourself.

`assfin` puts that workflow in one binary and one SQLite file:

- Finds multi-level subdomains passively and drops wildcards and dead DNS entries before any HTTP request goes out.
- Keeps `CNAME` chains and unresolved dangling `CNAME` records so potential takeover targets stand out.
- Tracks `first_seen`, `last_seen`, and `new` per host so repeat scans show what changed since last time.
- Detects WAFs passively and tags live sites as `register`, `login_only`, or `landing` at a conservative default rate (30 req/s).
- Survives interruptions on large root lists: `-resume` skips roots already finished, and `-probe-only` finishes resolving and probing hosts already in the database.
- Lets you query results offline (`table`, `list`, `json`, or raw SQL) and exits with code `2` if you filter `-alive` on hosts that have never been probed.

## Install

```bash
go install -v github.com/aktezed/assfin/cmd/assfin@latest
```

Or build from source (`bin/assfin`):

```bash
git clone https://github.com/aktezed/assfin.git
cd assfin
make build
```

Pre-built binaries for macOS, Linux, and Windows are on the [Releases](https://github.com/aktezed/assfin/releases) page.

## Quick start

Scan one domain (writes `example.com.db`) and view its summary:

```bash
assfin scan -d example.com
assfin query -db example.com.db -target example.com
```

Scan a list of root domains, and resume if a `timeout` or `Ctrl+C` stops the run early:

```bash
assfin scan -dL roots.txt -db targets.db
assfin scan -dL roots.txt -db targets.db -resume
```

Enumerate first without HTTP probing, then resolve and probe the stored hosts later:

```bash
assfin scan -d example.com -db targets.db -no-probe
assfin scan -db targets.db -probe-only
```

Use your existing subfinder API keys (`~/.config/subfinder/provider-config.yaml` is loaded automatically, or pass `-pc`):

```bash
assfin scan -d example.com -pc /path/to/provider-config.yaml
```

## Common queries

All queries run offline against the SQLite file:

```bash
# Live hosts without a WAF, piped to nuclei
assfin query -db example.com.db -alive -no-waf -o list -s | nuclei -t cves/

# Newly discovered hosts from the latest scan
assfin query -db example.com.db -new -o list

# Open sign-up / registration pages
assfin query -db example.com.db -auth-type register

# Dangling CNAMEs (unresolved CNAME targets)
assfin query -db example.com.db -dangling -o json

# Tech stack, status codes, or host substring
assfin query -db example.com.db -tech wordpress -status 200
assfin query -db example.com.db -name api,admin,staging

# Raw read-only SQL
assfin query -db example.com.db -sql "SELECT host, status, auth_type FROM hosts WHERE alive = 1"
```

If `-alive`, `-dead`, `-status`, `-tech`, or `-auth-type` matches zero rows because the target has never been probed, `assfin` prints a notice to `stderr` and exits `2` instead of `0`.

## Reports and dashboard

Export a self-contained HTML report (use `-target` to isolate one domain from a multi-root DB):

```bash
assfin report -db targets.db -target example.com
```

On a headless VPS, start the local web dashboard (`127.0.0.1:8080` by default) and tunnel it over SSH:

```bash
assfin serve -db example.com.db -port 8080
ssh -NL 8080:localhost:8080 user@<vps-ip>
```

## Key flags

Run `assfin -h` for the full flag list. The main ones you will tune day to day:

| Flag | Default | Purpose |
|---|---|---|
| `-d`, `-dL` | | Target domain or file of root domains |
| `-db` | `<domain>.db` / `assfin.db` | SQLite database path |
| `-resume` | `false` | Skip roots already completed in the DB (`-skip-completed` alias) |
| `-depth` | `-1` (auto) | Passive recursion rounds (`0` = root-only enum, still probes stored hosts) |
| `-max-hosts` | `5000` | Host cap per root (`0` = no cap) |
| `-exclude` | | Out-of-scope hosts or suffixes (comma-separated) |
| `-no-probe` | `false` | Enumerate and resolve DNS only, skip HTTP probing |
| `-probe-only` | `false` | Resolve and probe stored DB hosts without passive enumeration |
| `-rate` | `30` | Max HTTP requests/s across probing and role checks |
| `-content-assets` | `0` (off) | Same-host `.js`/`.json` files inspected per page for extra subdomains |
| `-report`, `-serve` | | Write HTML report or start local dashboard |

## Go library

You can also run scans from Go code via `pkg/runner`:

```go
r, err := runner.NewRunner(&types.Options{
	Command: "scan",
	Domain:  "example.com",
	DBPath:  "example.db",
	Depth:   2,
})
if err != nil {
	log.Fatal(err)
}
defer r.Close()
if err := r.Run(context.Background()); err != nil {
	log.Fatal(err)
}
```

## Scope and limits

`assfin` relies on passive OSINT sources and links found inside reachable HTTP responses. It does not brute-force DNS names, so hosts behind wildcard certs that never show up in public feeds or page content will not appear.

## License

[MIT](LICENSE)
