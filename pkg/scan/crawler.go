package scan

import (
	"context"
	"log"
	"slices"
	"strings"
	"sync"
)

// EnumFunc returns subdomains of domain mapped to the sources that reported them.
type EnumFunc func(ctx context.Context, domain string) (map[string][]string, error)

// CrawlOpts defines options for recursive enumeration crawling.
type CrawlOpts struct {
	Depth       int                                 // recursion rounds after the root query (-1 = auto/unlimited until no new hosts, 0 = root only)
	MaxHosts    int                                 // stop once this many hosts are known
	Conc        int                                 // domains enumerated in parallel
	Exclude     []string                            // hosts or suffixes to drop
	Seeds       []string                            // optional starting seeds instead of root for feedback rounds
	Seen        map[string]bool                     // optional shared seen-hosts set across rounds
	Queried     map[string]bool                     // optional shared queried-domains set across rounds
	Malformed   map[string]bool                     // optional shared malformed-hosts set across rounds
	OnMalformed func(host string, sources []string) // optional callback invoked once per malformed in-scope host
}

// Crawl queries root (or o.Seeds), then newly found subdomains level by level until nothing new
// appears or a cap is hit. onFound is called once per new host (never for root or initial seeds) and is serialized.
func Crawl(ctx context.Context, root string, o CrawlOpts, enum EnumFunc, onFound func(host string, sources []string)) error {
	seen := o.Seen
	if seen == nil {
		seen = make(map[string]bool)
	}
	seen[root] = true

	queried := o.Queried
	if queried == nil {
		queried = make(map[string]bool)
	}

	malformed := o.Malformed
	if malformed == nil {
		malformed = make(map[string]bool)
	}

	var level []string
	if len(o.Seeds) > 0 {
		for _, raw := range o.Seeds {
			s := Normalize(raw)
			if s == "" || !InScope(s, root, o.Exclude) {
				continue
			}
			seen[s] = true
			if !queried[s] {
				queried[s] = true
				level = append(level, s)
			}
			for _, p := range parentBranches(s, root) {
				if !queried[p] && InScope(p, root, o.Exclude) {
					queried[p] = true
					level = append(level, p)
				}
			}
		}
	} else {
		queried[root] = true
		level = []string{root}
	}
	var mu sync.Mutex
	var notifyMu sync.Mutex
	full := func() bool { return o.MaxHosts > 0 && len(seen) >= o.MaxHosts }

	// Reuse a single semaphore channel across all rounds to avoid per-round allocations.
	sem := make(chan struct{}, max(o.Conc, 1))

	for round := 0; (o.Depth < 0 || round <= o.Depth) && len(level) > 0 && !full(); round++ {
		var next []string
		var wg sync.WaitGroup
		for i, d := range level {
			if ctx.Err() != nil {
				break
			}
			select {
			case sem <- struct{}{}:
			case <-ctx.Done():
				break
			}
			wg.Add(1)
			go func(domain string, idx, total int) {
				defer func() { <-sem; wg.Done() }()
				if o.Conc > 1 || total > 10 {
					log.Printf("round %d [%d/%d]: enumerating %s", round, idx+1, total, domain)
				}
				res, err := enum(ctx, domain)
				if err != nil {
					log.Printf("enumerate %s: %v", domain, err)
					return
				}

				hosts := make([]string, 0, len(res))
				for h := range res {
					hosts = append(hosts, h)
				}
				slices.Sort(hosts)

				type item struct {
					host    string
					sources []string
				}
				var (
					toNotify []item
					toReject []item
				)

				mu.Lock()
				for _, raw := range hosts {
					h := Normalize(raw)
					if seen[h] || !inScopeSuffix(h, root, o.Exclude) || full() {
						continue
					}
					if IsMalformedHost(h, root) {
						if !malformed[h] {
							malformed[h] = true
							toReject = append(toReject, item{host: h, sources: res[raw]})
						}
						continue
					}
					seen[h] = true
					if !queried[h] {
						queried[h] = true
						next = append(next, h)
					}
					// Extract intermediate parent zones (e.g. x.dev.a.com -> dev.a.com) as branch candidates
					for _, p := range parentBranches(h, domain) {
						if !queried[p] && InScope(p, root, o.Exclude) {
							queried[p] = true
							next = append(next, p)
						}
					}
					toNotify = append(toNotify, item{host: h, sources: res[raw]})
				}
				mu.Unlock()

				if o.OnMalformed != nil {
					for _, it := range toReject {
						notifyMu.Lock()
						o.OnMalformed(it.host, it.sources)
						notifyMu.Unlock()
					}
				}
				for _, it := range toNotify {
					notifyMu.Lock()
					onFound(it.host, it.sources)
					notifyMu.Unlock()
				}
			}(d, i, len(level))
		}
		wg.Wait()
		if err := ctx.Err(); err != nil {
			return err
		}
		log.Printf("round %d: %d newqueued, %d total hosts", round, len(next), len(seen))
		level = next
	}
	return nil
}

// parentBranches extracts intermediate parent domains between host and base (e.g. a.b.base -> b.base).
func parentBranches(host, base string) []string {
	suffix := "." + base
	if !strings.HasSuffix(host, suffix) {
		return nil
	}
	sub := strings.TrimSuffix(host, suffix)
	parts := strings.Split(sub, ".")
	if len(parts) <= 1 {
		return nil
	}
	out := make([]string, 0, len(parts)-1)
	for i := 1; i < len(parts); i++ {
		out = append(out, strings.Join(parts[i:], ".")+suffix)
	}
	return out
}

// Normalize sanitizes and standardizes a domain name.
func Normalize(h string) string {
	return strings.TrimPrefix(strings.TrimSuffix(strings.ToLower(strings.TrimSpace(h)), "."), "*.")
}

// InScope checks whether a host belongs to the target domain, is not excluded, and is not malformed.
func InScope(h, root string, exclude []string) bool {
	return inScopeSuffix(h, root, exclude) && !IsMalformedHost(h, root)
}

func inScopeSuffix(h, root string, exclude []string) bool {
	if !strings.HasSuffix(h, "."+root) {
		return false
	}
	for _, e := range exclude {
		if h == e || strings.HasSuffix(h, "."+e) {
			return false
		}
	}
	return true
}

// IsMalformedHost reports whether h has invalid DNS syntax or concatenation artifacts under root.
func IsMalformedHost(h, root string) bool {
	suffix := "." + root
	if root == "" || !strings.HasSuffix(h, suffix) || len(h) > 253 {
		return true
	}
	sub := strings.TrimSuffix(h, suffix)
	if sub == "" || strings.Contains("."+sub, "."+root) {
		return true
	}
	labels := strings.Split(h, ".")
	subCount := len(labels) - strings.Count(root, ".") - 1
	for i, l := range labels {
		if !isValidDNSLabel(l) {
			return true
		}
		if i < subCount && (labels[i] == labels[i+1] || isDoubledAlphaLabel(l)) {
			return true
		}
	}
	return false
}

func isValidDNSLabel(l string) bool {
	if len(l) == 0 || len(l) > 63 || l[0] == '-' || l[len(l)-1] == '-' {
		return false
	}
	for i := range len(l) {
		c := l[i]
		if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '-' {
			return false
		}
	}
	return true
}

func isDoubledAlphaLabel(l string) bool {
	if len(l) < 4 || len(l)%2 != 0 {
		return false
	}
	for i := range len(l) {
		if l[i] < 'a' || l[i] > 'z' {
			return false
		}
	}
	half := len(l) / 2
	return l[:half] == l[half:]
}

// LabelDepth returns how many labels a host has beyond root: a.com=0, x.a.com=1, y.x.a.com=2.
func LabelDepth(h, root string) int {
	if h == root {
		return 0
	}
	return strings.Count(strings.TrimSuffix(h, "."+root), ".") + 1
}
