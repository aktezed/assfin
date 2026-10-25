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

func TestCrawlAutoDepth(t *testing.T) {
	found, calls := run(t, CrawlOpts{Depth: -1, Conc: 3, Exclude: []string{"skip.a.com"}})
	// With Depth: -1 (auto), it climbs x.a.com -> y.x.a.com -> z.y.x.a.com -> deep.z.y.x.a.com and stops when deep.z.y.x.a.com returns nothing new.
	if !slices.Contains(found, "deep.z.y.x.a.com") {
		t.Fatalf("expected auto depth to reach deep.z.y.x.a.com, got %v", found)
	}
	if calls["deep.z.y.x.a.com"] != 1 {
		t.Errorf("expected deep.z.y.x.a.com to be queried once before auto-stopping, got %d", calls["deep.z.y.x.a.com"])
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

func TestCrawlAllBranches(t *testing.T) {
	round0 := make([]string, 0, 22)
	for i := 1; i <= 20; i++ {
		round0 = append(round0, "host"+string(rune('a'+i-1))+".a.com")
	}
	round0 = append(round0, "dev.a.com", "leaf.branch.a.com")

	largeTree := map[string][]string{
		"a.com":        round0,
		"hosta.a.com":  {"sub.hosta.a.com"},
		"dev.a.com":    {"sub.dev.a.com"},
		"branch.a.com": {"other.branch.a.com"},
	}
	calls := map[string]int{}
	found := []string{}
	err := Crawl(
		context.Background(),
		"a.com",
		CrawlOpts{Depth: 1, Conc: 5},
		fakeEnum(largeTree, calls),
		func(h string, _ []string) { found = append(found, h) },
	)
	if err != nil {
		t.Fatal(err)
	}
	if calls["hosta.a.com"] != 1 || calls["dev.a.com"] != 1 || calls["branch.a.com"] != 1 {
		t.Errorf("expected all branches including leaf hosts to be queried, got calls=%v", calls)
	}
	if !slices.Contains(found, "sub.hosta.a.com") || !slices.Contains(found, "sub.dev.a.com") || !slices.Contains(found, "other.branch.a.com") {
		t.Errorf("expected deep children to be discovered across all branches, got %v", found)
	}
}
