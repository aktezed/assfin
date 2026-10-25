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
	Depth    int      // recursion rounds after the root query (-1 = auto/unlimited until no new hosts, 0 = root only)
	MaxHosts int      // stop once this many hosts are known
	Conc     int      // domains enumerated in parallel
	Exclude  []string // hosts or suffixes to drop
}

// Crawl queries root, then newly found subdomains level by level until nothing new
// appears or a cap is hit. onFound is called once per new host (never for root) and is serialized.
func Crawl(ctx context.Context, root string, o CrawlOpts, enum EnumFunc, onFound func(host string, sources []string)) error {
	seen := map[string]bool{root: true}
	queried := map[string]bool{root: true}
	level := []string{root}
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
				var toNotify []item

				mu.Lock()
				for _, raw := range hosts {
					h := Normalize(raw)
					if seen[h] || !InScope(h, root, o.Exclude) || full() {
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

// InScope checks whether a host belongs to the target domain and is not excluded.
func InScope(h, root string, exclude []string) bool {
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

// LabelDepth returns how many labels a host has beyond root: a.com=0, x.a.com=1, y.x.a.com=2.
func LabelDepth(h, root string) int {
	if h == root {
		return 0
	}
	return strings.Count(strings.TrimSuffix(h, "."+root), ".") + 1
}
