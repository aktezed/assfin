package scan

import (
	"context"
	"net/http"
	"net/http/httptest"
	"slices"
	"sync"
	"testing"

	"github.com/aktezed/assfin/pkg/types"
)

func TestProbeEmpty(t *testing.T) {
	called := false
	err := Probe(context.Background(), []string{}, ProbeOpts{
		OnProgress: func(c, tot int) {
			called = true
		},
	}, func(host string, p types.Probe) {})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if called {
		t.Errorf("expected OnProgress not to be called for empty hosts")
	}
}

func TestProbeExtractsContentHostsAndRedirects(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Host {
		case "v2.example.test":
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			_, _ = w.Write([]byte(`<!doctype html><html><head><title>V2</title><script src="/app.js"></script></head><body><a href="https://v3.example.test/login">New Portal</a></body></html>`))
		case "old.example.test":
			w.Header().Set("Location", "https://migrated.example.test/welcome")
			w.WriteHeader(http.StatusFound)
		default:
			http.NotFound(w, r)
		}
	}))
	defer ts.Close()

	var mu sync.Mutex
	results := make(map[string]types.Probe)

	err := Probe(
		context.Background(),
		[]string{"v2.example.test", "old.example.test"},
		ProbeOpts{
			Threads:       2,
			Timeout:       3,
			Rate:          50,
			ExtractRoot:   "example.test",
			ContentAssets: 2,
			TargetAddr:    ts.Listener.Addr().String(),
		},
		func(host string, p types.Probe) {
			mu.Lock()
			results[host] = p
			mu.Unlock()
		},
	)
	if err != nil {
		t.Fatalf("Probe failed: %v", err)
	}

	v2, ok := results["v2.example.test"]
	if !ok {
		t.Fatalf("missing probe result for v2.example.test: %v", results)
	}
	if !slices.Equal(v2.Referenced, []string{"v3.example.test"}) {
		t.Errorf("v2.Referenced = %v, want [v3.example.test]", v2.Referenced)
	}
	if !slices.Equal(v2.AssetURLs, []string{"http://v2.example.test/app.js"}) {
		t.Errorf("v2.AssetURLs = %v, want [http://v2.example.test/app.js]", v2.AssetURLs)
	}

	old, ok := results["old.example.test"]
	if !ok {
		t.Fatalf("missing probe result for old.example.test: %v", results)
	}
	if !slices.Equal(old.Referenced, []string{"migrated.example.test"}) {
		t.Errorf("old.Referenced = %v, want [migrated.example.test]", old.Referenced)
	}
}
