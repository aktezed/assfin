package scan

import (
	"context"
	"errors"
	"slices"
	"sync"
	"testing"
)

// fakeEnum serves a fixed tree and counts queries per domain.
func fakeEnum(tree map[string][]string, calls map[string]int) EnumFunc {
	var mu sync.Mutex
	return func(_ context.Context, d string) (map[string][]string, error) {
		mu.Lock()
		calls[d]++
		mu.Unlock()
		if d == "broken.a.com" {
			return nil, errors.New("source down")
		}
		out := map[string][]string{}
		for _, h := range tree[d] {
			out[h] = []string{"fake"}
		}
		return out, nil
	}
}

var tree = map[string][]string{
	"a.com":        {"x.a.com", "API.a.com.", "evil.com", "nota.com", "broken.a.com", "skip.a.com"},
	"x.a.com":      {"y.x.a.com", "a.com", "x.a.com", "in.skip.a.com"}, // loops back + excluded child
	"y.x.a.com":    {"z.y.x.a.com"},
	"z.y.x.a.com":  {"deep.z.y.x.a.com"},
	"api.a.com":    {"v1.api.a.com"},
	"broken.a.com": {"never.a.com"},
}

func run(t *testing.T, o CrawlOpts) ([]string, map[string]int) {
	t.Helper()
	calls := map[string]int{}
	var found []string
	if err := Crawl(context.Background(), "a.com", o, fakeEnum(tree, calls), func(h string, _ []string) {
		found = append(found, h)
	}); err != nil {
		t.Fatal(err)
	}
	slices.Sort(found)
	return found, calls
}

func TestCrawlDepthScopeDedup(t *testing.T) {
	found, calls := run(t, CrawlOpts{Depth: 2, Conc: 3, Exclude: []string{"skip.a.com"}})
	want := []string{"api.a.com", "broken.a.com", "v1.api.a.com", "x.a.com", "y.x.a.com", "z.y.x.a.com"}
	if !slices.Equal(found, want) {
		t.Fatalf("found %v, want %v", found, want)
	}
	for d, n := range calls {
		if n != 1 {
			t.Errorf("%s queried %d times", d, n)
		}
	}
	if calls["z.y.x.a.com"] != 0 {
		t.Error("depth cap ignored: queried round-3 host")
	}
}

func TestCrawlRootOnly(t *testing.T) {
	found, calls := run(t, CrawlOpts{Depth: 0, Conc: 1})
	if len(calls) != 1 || calls["a.com"] != 1 {
		t.Fatalf("depth 0 should only query root, got %v", calls)
	}
	if len(found) != 4 {
		t.Fatalf("found %v", found)
	}
}

func TestCrawlMaxHosts(t *testing.T) {
	found, _ := run(t, CrawlOpts{Depth: 5, Conc: 1, MaxHosts: 3})
	if len(found) != 2 {
		t.Fatalf("want 2 hosts under cap 3, got %v", found)
	}
}

func TestCrawlCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err := Crawl(ctx, "a.com", CrawlOpts{Depth: 2}, fakeEnum(tree, map[string]int{}), func(string, []string) {})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("want context.Canceled, got %v", err)
	}
}

func TestLabelDepth(t *testing.T) {
	for h, want := range map[string]int{"a.com": 0, "x.a.com": 1, "y.x.a.com": 2} {
		if got := LabelDepth(h, "a.com"); got != want {
			t.Errorf("%s: got %d want %d", h, got, want)
		}
	}
}
