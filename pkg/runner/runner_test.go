package runner

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aktezed/assfin/pkg/store"
	"github.com/aktezed/assfin/pkg/types"
)

func TestRunnerQueryAndReport(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "test_runner.db")
	s, err := store.New(dbPath, false)
	if err != nil {
		t.Fatalf("create store: %v", err)
	}
	defer s.Close()

	scanID, err := s.StartScan("example.com", "{}")
	if err != nil {
		t.Fatalf("start scan: %v", err)
	}
	if err := s.UpsertHost(scanID, "example.com", "admin.example.com", 1, []string{"subfinder"}); err != nil {
		t.Fatalf("upsert host: %v", err)
	}

	// Test Query mode
	queryOpts := &types.Options{
		Command:      "query",
		DBPath:       dbPath,
		OutputFormat: "json",
	}
	r, err := NewRunner(queryOpts)
	if err != nil {
		t.Fatalf("new runner: %v", err)
	}
	if err := r.Run(context.Background()); err != nil {
		t.Fatalf("run query: %v", err)
	}
	r.Close()

	// Test Report mode
	reportOut := filepath.Join(t.TempDir(), "report.html")
	reportOpts := &types.Options{
		Command:      "report",
		DBPath:       dbPath,
		ReportOutput: reportOut,
	}
	rReport, err := NewRunner(reportOpts)
	if err != nil {
		t.Fatalf("new report runner: %v", err)
	}
	if err := rReport.Run(context.Background()); err != nil {
		t.Fatalf("run report: %v", err)
	}
	rReport.Close()

	// Test validateOptions with scan + report in one command
	oneLineOpts := &types.Options{
		Domain: "example.com",
		Report: true,
	}
	if err := validateOptions(oneLineOpts); err != nil {
		t.Fatalf("validateOptions scan+report: %v", err)
	}
	if oneLineOpts.Command != "scan" {
		t.Fatalf("expected Command 'scan', got %q", oneLineOpts.Command)
	}
}

func TestFormatDuration(t *testing.T) {
	tests := []struct {
		d    time.Duration
		want string
	}{
		{d: 400 * time.Millisecond, want: "0.4s"},
		{d: 5 * time.Second, want: "5s"},
		{d: 65 * time.Second, want: "1m 5s"},
		{d: 3665 * time.Second, want: "1h 1m 5s"},
	}

	for _, tt := range tests {
		got := types.FormatDuration(tt.d)
		if got != tt.want {
			t.Errorf("FormatDuration(%v) = %q, want %q", tt.d, got, tt.want)
		}
	}
}

func TestNormalizeListenAddr(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"", "127.0.0.1:8080"},
		{"8080", "127.0.0.1:8080"},
		{":9000", ":9000"},
		{"127.0.0.1:3000", "127.0.0.1:3000"},
		{"0.0.0.0:8080", "0.0.0.0:8080"},
	}

	for _, tt := range tests {
		got := normalizeListenAddr(tt.input)
		if got != tt.want {
			t.Errorf("normalizeListenAddr(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}

	if got := resolveServeAddr("true", 9090); got != "127.0.0.1:9090" {
		t.Errorf("resolveServeAddr(true, 9090) = %q, want 127.0.0.1:9090", got)
	}
	if got := resolveServeAddr("", 0); got != "127.0.0.1:8080" {
		t.Errorf("resolveServeAddr(\"\", 0) = %q, want 127.0.0.1:8080", got)
	}
}

func TestRunServerEndpointsAndShutdown(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "serve.db")
	s, err := store.New(dbPath, false)
	if err != nil {
		t.Fatalf("create store: %v", err)
	}
	defer func() { _ = s.Close() }()

	scanA, err := s.StartScan("alpha.test", "{}")
	if err != nil {
		t.Fatalf("start scan alpha: %v", err)
	}
	if err := s.UpsertHost(scanA, "alpha.test", "app.alpha.test", 1, []string{"subfinder"}); err != nil {
		t.Fatalf("upsert alpha: %v", err)
	}
	if err := s.FinishScan(scanA); err != nil {
		t.Fatalf("finish alpha: %v", err)
	}

	scanB, err := s.StartScan("beta.test", "{}")
	if err != nil {
		t.Fatalf("start scan beta: %v", err)
	}
	if err := s.UpsertHost(scanB, "beta.test", "secret.beta.test", 1, []string{"subfinder"}); err != nil {
		t.Fatalf("upsert beta: %v", err)
	}
	if err := s.FinishScan(scanB); err != nil {
		t.Fatalf("finish beta: %v", err)
	}

	probeLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("allocate ephemeral port: %v", err)
	}
	addr := probeLn.Addr().String()
	_ = probeLn.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	errCh := make(chan error, 1)
	go func() {
		errCh <- runScopedServer(ctx, s, addr, "alpha.test")
	}()

	client := &http.Client{Timeout: 2 * time.Second}
	baseURL := "http://" + addr

	var ready bool
	for range 50 {
		resp, reqErr := client.Get(baseURL + "/api/summary")
		if reqErr == nil {
			_ = resp.Body.Close()
			ready = true
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if !ready {
		t.Fatalf("dashboard server did not become ready at %s", baseURL)
	}

	// 1. / renders scoped HTML report containing alpha.test and excluding beta.test
	resp, err := client.Get(baseURL + "/")
	if err != nil {
		t.Fatalf("GET /: %v", err)
	}
	bodyBytes, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	html := string(bodyBytes)
	if resp.StatusCode != http.StatusOK || !strings.Contains(html, "app.alpha.test") {
		t.Fatalf("expected 200 HTML containing app.alpha.test, got status=%d", resp.StatusCode)
	}
	if strings.Contains(html, "secret.beta.test") {
		t.Errorf("scoped dashboard leaked out-of-scope host secret.beta.test")
	}

	// 2. /api/hosts returns only alpha.test hosts
	hostsResp, err := client.Get(baseURL + "/api/hosts")
	if err != nil {
		t.Fatalf("GET /api/hosts: %v", err)
	}
	var gotHosts []types.Host
	if err := json.NewDecoder(hostsResp.Body).Decode(&gotHosts); err != nil {
		_ = hostsResp.Body.Close()
		t.Fatalf("decode /api/hosts: %v", err)
	}
	_ = hostsResp.Body.Close()
	if len(gotHosts) != 1 || gotHosts[0].Host != "app.alpha.test" {
		t.Errorf("unexpected /api/hosts response: %+v", gotHosts)
	}

	// 3. /api/summary returns only alpha.test root summary
	sumResp, err := client.Get(baseURL + "/api/summary")
	if err != nil {
		t.Fatalf("GET /api/summary: %v", err)
	}
	var gotRoots []types.RootInfo
	if err := json.NewDecoder(sumResp.Body).Decode(&gotRoots); err != nil {
		_ = sumResp.Body.Close()
		t.Fatalf("decode /api/summary: %v", err)
	}
	_ = sumResp.Body.Close()
	if len(gotRoots) != 1 || gotRoots[0].Root != "alpha.test" {
		t.Errorf("unexpected /api/summary response: %+v", gotRoots)
	}

	// 4. Unknown route returns 404
	notFoundResp, err := client.Get(baseURL + "/not-a-route")
	if err != nil {
		t.Fatalf("GET /not-a-route: %v", err)
	}
	_ = notFoundResp.Body.Close()
	if notFoundResp.StatusCode != http.StatusNotFound {
		t.Errorf("expected 404 for unknown route, got %d", notFoundResp.StatusCode)
	}

	// 5. Context cancellation shuts down cleanly
	cancel()
	select {
	case srvErr := <-errCh:
		if srvErr != nil {
			t.Fatalf("runScopedServer returned error on shutdown: %v", srvErr)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for dashboard server shutdown")
	}
}

func TestPrintTargetSummary(t *testing.T) {
	hosts := []types.Host{
		{Host: "app.example.com", Alive: true, AuthType: "register", AuthURL: "https://app.example.com/signup"},
		{Host: "admin.example.com", Alive: true, AuthType: "login_only", AuthURL: "https://admin.example.com/login", WAF: "Cloudflare"},
		{Host: "blog.example.com", Alive: true, AuthType: "landing", URL: "https://blog.example.com"},
		{Host: "v3.example.com", Alive: true, Status: 200, AuthType: "landing", URL: "https://v3.example.com", Sources: "content:app.example.com"},
		{Host: "dead.example.com", Alive: false},
	}

	var buf bytes.Buffer
	PrintTargetSummary(&buf, "example.com", hosts)
	out := buf.String()

	if !strings.Contains(out, "TARGET DOSSIER : EXAMPLE.COM") {
		t.Errorf("missing target header: %s", out)
	}
	if !strings.Contains(out, "[REGISTERABLE] : 1") {
		t.Errorf("missing registerable count: %s", out)
	}
	if !strings.Contains(out, "https://app.example.com/signup") {
		t.Errorf("missing register auth url: %s", out)
	}
	if !strings.Contains(out, "[LOGIN-ONLY]   : 1") {
		t.Errorf("missing login-only count: %s", out)
	}
	if !strings.Contains(out, "[Cloudflare]") {
		t.Errorf("missing WAF label: %s", out)
	}
	if !strings.Contains(out, "Discovered via Content      : 1") {
		t.Errorf("missing content discovery count: %s", out)
	}
	if !strings.Contains(out, "DISCOVERED VIA CONTENT") || !strings.Contains(out, "via app.example.com [200]") {
		t.Errorf("missing content discovery section details: %s", out)
	}
}

func TestValidateOptionsContentFlags(t *testing.T) {
	badDepth := &types.Options{Domain: "example.com", ContentDepth: -1}
	if err := validateOptions(badDepth); err == nil {
		t.Fatal("expected error for negative -content-depth")
	}
	badAssets := &types.Options{Domain: "example.com", ContentAssets: -2}
	if err := validateOptions(badAssets); err == nil {
		t.Fatal("expected error for negative -content-assets")
	}
}

func newWildcardFixtureServer(t *testing.T) *httptest.Server {
	t.Helper()
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host := r.Host
		if idx := strings.IndexByte(host, ':'); idx >= 0 {
			host = host[:idx]
		}
		switch host {
		case "example.test":
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			_, _ = fmt.Fprint(w, `<!doctype html><html><head><title>Root</title></head><body>Welcome</body></html>`)
		case "v2.example.test":
			if r.URL.Path == "/static/app.js" {
				w.Header().Set("Content-Type", "application/javascript")
				_, _ = fmt.Fprint(w, `const HIDDEN_API = "http://hidden-api.example.test/v1/status";`)
				return
			}
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			_, _ = fmt.Fprint(w, `<!doctype html><html><head><title>Portal V2</title><script src="/static/app.js"></script></head><body><a href="http://v3.example.test/portal">Switch to V3</a><a href="https://v4.example.test.evil.com">External</a></body></html>`)
		case "v3.example.test":
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			_, _ = fmt.Fprint(w, `<!doctype html><html><head><title>Portal V3</title></head><body>Wildcard V3</body></html>`)
		case "api.v3.example.test":
			w.Header().Set("Content-Type", "application/json")
			_, _ = fmt.Fprint(w, `{"service":"v3-api"}`)
		case "hidden-api.example.test":
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			_, _ = fmt.Fprint(w, `<!doctype html><html><head><title>Hidden API</title></head><body>OK</body></html>`)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(ts.Close)
	return ts
}

func TestExecuteScanContentDiscovery(t *testing.T) {
	ts := newWildcardFixtureServer(t)
	dbPath := filepath.Join(t.TempDir(), "wildcard.db")

	opts := &types.Options{
		Command:      "scan",
		Domain:       "example.test",
		DBPath:       dbPath,
		Depth:        -1,
		ContentDepth: 1,
		Threads:      2,
		RateLimit:    100,
		Timeout:      3,
		NoAuth:       true,
		Silent:       true,
	}
	r, err := NewRunner(opts)
	if err != nil {
		t.Fatalf("NewRunner: %v", err)
	}
	defer func() { _ = r.Close() }()

	r.targetAddr = ts.Listener.Addr().String()
	r.enumFn = func(_ context.Context, domain string) (map[string][]string, error) {
		switch domain {
		case "example.test":
			return map[string][]string{"v2.example.test": {"subfinder"}}, nil
		case "v3.example.test":
			return map[string][]string{"api.v3.example.test": {"crtsh"}}, nil
		default:
			return nil, nil
		}
	}

	if err := r.Run(context.Background()); err != nil {
		t.Fatalf("ExecuteScan: %v", err)
	}

	ro, err := store.New(dbPath, true)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer func() { _ = ro.Close() }()

	hosts, err := ro.QueryHosts(types.Filter{Root: "example.test", Depth: -1})
	if err != nil {
		t.Fatalf("QueryHosts: %v", err)
	}
	byHost := make(map[string]types.Host, len(hosts))
	for _, h := range hosts {
		byHost[h.Host] = h
	}

	v3, ok := byHost["v3.example.test"]
	if !ok {
		t.Fatalf("expected wildcard host v3.example.test to be discovered, got hosts: %v", byHost)
	}
	if v3.Sources != "content:v2.example.test" {
		t.Errorf("v3.Sources = %q, want %q", v3.Sources, "content:v2.example.test")
	}
	if v3.Depth != 1 {
		t.Errorf("v3.Depth = %d, want 1", v3.Depth)
	}
	if !v3.Alive || v3.Status != 200 || v3.Title != "Portal V3" {
		t.Errorf("expected v3.example.test to be probed alive (200 Portal V3), got alive=%v status=%d title=%q", v3.Alive, v3.Status, v3.Title)
	}

	apiV3, ok := byHost["api.v3.example.test"]
	if !ok {
		t.Fatalf("expected passive feedback child api.v3.example.test to be discovered")
	}
	if apiV3.Sources != "crtsh" || !apiV3.Alive || apiV3.Status != 200 {
		t.Errorf("unexpected api.v3.example.test state: %+v", apiV3)
	}

	if _, bad := byHost["v4.example.test.evil.com"]; bad {
		t.Errorf("out-of-scope host v4.example.test.evil.com leaked into hosts table")
	}
	if _, assetLeak := byHost["hidden-api.example.test"]; assetLeak {
		t.Errorf("hidden-api.example.test should not be fetched when ContentAssets=0")
	}

	refs, err := ro.QueryHostRefs("example.test")
	if err != nil {
		t.Fatalf("QueryHostRefs: %v", err)
	}
	if len(refs) != 1 || refs[0].Host != "v3.example.test" || refs[0].Referrer != "v2.example.test" || refs[0].Source == "" {
		t.Errorf("unexpected host_refs: %+v", refs)
	}
}

func TestExecuteScanNoContentFlag(t *testing.T) {
	ts := newWildcardFixtureServer(t)
	dbPath := filepath.Join(t.TempDir(), "nocontent.db")

	opts := &types.Options{
		Command:   "scan",
		Domain:    "example.test",
		DBPath:    dbPath,
		Depth:     -1,
		NoContent: true,
		Threads:   2,
		RateLimit: 100,
		Timeout:   3,
		NoAuth:    true,
		Silent:    true,
	}
	r, err := NewRunner(opts)
	if err != nil {
		t.Fatalf("NewRunner: %v", err)
	}
	defer func() { _ = r.Close() }()

	r.targetAddr = ts.Listener.Addr().String()
	r.enumFn = func(_ context.Context, domain string) (map[string][]string, error) {
		if domain == "example.test" {
			return map[string][]string{"v2.example.test": {"subfinder"}}, nil
		}
		return nil, nil
	}

	if err := r.Run(context.Background()); err != nil {
		t.Fatalf("ExecuteScan: %v", err)
	}

	ro, err := store.New(dbPath, true)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer func() { _ = ro.Close() }()

	hosts, err := ro.QueryHosts(types.Filter{Root: "example.test", Depth: -1})
	if err != nil {
		t.Fatalf("QueryHosts: %v", err)
	}
	for _, h := range hosts {
		if h.Host == "v3.example.test" {
			t.Fatalf("v3.example.test should not be discovered when -no-content is set")
		}
	}
	refs, err := ro.QueryHostRefs("example.test")
	if err != nil {
		t.Fatalf("QueryHostRefs: %v", err)
	}
	if len(refs) != 0 {
		t.Fatalf("expected 0 host_refs when -no-content is set, got %+v", refs)
	}
}

func TestExecuteScanContentAssets(t *testing.T) {
	ts := newWildcardFixtureServer(t)
	dbPath := filepath.Join(t.TempDir(), "assets.db")

	opts := &types.Options{
		Command:       "scan",
		Domain:        "example.test",
		DBPath:        dbPath,
		Depth:         0,
		ContentDepth:  1,
		ContentAssets: 2,
		Threads:       2,
		RateLimit:     100,
		Timeout:       3,
		NoAuth:        true,
		Silent:        true,
	}
	r, err := NewRunner(opts)
	if err != nil {
		t.Fatalf("NewRunner: %v", err)
	}
	defer func() { _ = r.Close() }()

	r.targetAddr = ts.Listener.Addr().String()
	r.enumFn = func(_ context.Context, domain string) (map[string][]string, error) {
		if domain == "example.test" {
			return map[string][]string{"v2.example.test": {"subfinder"}}, nil
		}
		return nil, nil
	}

	if err := r.Run(context.Background()); err != nil {
		t.Fatalf("ExecuteScan: %v", err)
	}

	ro, err := store.New(dbPath, true)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer func() { _ = ro.Close() }()

	hosts, err := ro.QueryHosts(types.Filter{Root: "example.test", Depth: -1})
	if err != nil {
		t.Fatalf("QueryHosts: %v", err)
	}
	byHost := make(map[string]types.Host, len(hosts))
	for _, h := range hosts {
		byHost[h.Host] = h
	}

	hidden, ok := byHost["hidden-api.example.test"]
	if !ok {
		t.Fatalf("expected hidden-api.example.test from /static/app.js, got %v", byHost)
	}
	if hidden.Sources != "content:v2.example.test" || !hidden.Alive || hidden.Title != "Hidden API" {
		t.Errorf("unexpected hidden-api.example.test state: %+v", hidden)
	}

	refs, err := ro.QueryHostRefs("example.test")
	if err != nil {
		t.Fatalf("QueryHostRefs: %v", err)
	}
	foundAssetRef := false
	for _, ref := range refs {
		if ref.Host == "hidden-api.example.test" && ref.Referrer == "v2.example.test" && strings.HasPrefix(ref.Source, "asset:/static/app.js:") {
			foundAssetRef = true
		}
	}
	if !foundAssetRef {
		t.Errorf("expected asset provenance in host_refs, got %+v", refs)
	}
}

func TestValidateOptionsDNSFlags(t *testing.T) {
	for _, tc := range []struct {
		name string
		opts types.Options
	}{
		{name: "negative dns-threads", opts: types.Options{Domain: "example.com", DNSThreads: -1}},
		{name: "negative dns-rate", opts: types.Options{Domain: "example.com", DNSRate: -5}},
		{name: "negative dns-timeout", opts: types.Options{Domain: "example.com", DNSTimeout: -2}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			o := tc.opts
			if err := validateOptions(&o); err == nil {
				t.Fatal("expected error from validateOptions")
			}
		})
	}

	for _, tc := range []struct {
		name string
		opts types.Options
	}{
		{name: "dangling", opts: types.Options{Dangling: true}},
		{name: "has-cname", opts: types.Options{HasCNAME: true}},
		{name: "cname-target", opts: types.Options{CNAMETarget: []string{"s3.amazonaws.com"}}},
		{name: "resolved", opts: types.Options{Resolved: true}},
		{name: "waf-name", opts: types.Options{WAFName: "cloudflare"}},
		{name: "new-only", opts: types.Options{NewOnly: true}},
		{name: "filter-root", opts: types.Options{FilterRoot: "example.com"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			o := tc.opts
			if err := validateOptions(&o); err != nil {
				t.Fatalf("validateOptions failed: %v", err)
			}
			if o.Command != "query" {
				t.Errorf("Command = %q, want %q", o.Command, "query")
			}
		})
	}
}

func TestPrintTargetSummaryDanglingCNAME(t *testing.T) {
	hosts := []types.Host{
		{Host: "example.com", Alive: true, IPs: "203.0.113.1", AuthType: "landing", URL: "https://example.com"},
		{Host: "cdn.example.com", Alive: true, IPs: "203.0.113.2", CNAME: "edge.cloudfront.net", AuthType: "landing", URL: "https://cdn.example.com"},
		{Host: "shop.example.com", Alive: false, CNAME: "old-shop.myshopify.com"},
	}

	var buf bytes.Buffer
	PrintTargetSummary(&buf, "example.com", hosts)
	out := buf.String()

	if !strings.Contains(out, "DNS Resolved Hosts          : 2") {
		t.Errorf("expected DNS Resolved Hosts count of 2, got:\n%s", out)
	}
	if !strings.Contains(out, "Dangling CNAMEs     : 1") {
		t.Errorf("expected Dangling CNAMEs count of 1, got:\n%s", out)
	}
	if !strings.Contains(out, "DANGLING CNAME RECORDS") || !strings.Contains(out, "old-shop.myshopify.com [unresolved]") {
		t.Errorf("expected dangling CNAME section in summary, got:\n%s", out)
	}
}

func TestExecuteScanDNSResolutionWildcardDanglingAndGhostPruning(t *testing.T) {
	var (
		httpMu     sync.Mutex
		probedHTTP = make(map[string]int)
		enumMu     sync.Mutex
		enumCalls  = make(map[string]int)
	)

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host := r.Host
		if idx := strings.IndexByte(host, ':'); idx >= 0 {
			host = host[:idx]
		}
		httpMu.Lock()
		probedHTTP[host]++
		httpMu.Unlock()

		switch host {
		case "example.test":
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			_, _ = fmt.Fprint(w, `<!doctype html><html><head><title>Apex</title></head><body>Root</body></html>`)
		case "app.example.test":
			if r.URL.Path == "/app.js" {
				w.Header().Set("Content-Type", "application/javascript")
				_, _ = fmt.Fprint(w, `const REAL = "http://js-real.example.test/api"; const GHOST = "http://js-ghost.example.test/internal";`)
				return
			}
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			_, _ = fmt.Fprint(w, `<!doctype html><html><head><title>App</title><script src="/app.js"></script></head><body>`+
				`<a href="http://v3.example.test/portal">V3</a>`+
				`<a href="http://ghost-internal.example.test/admin">Ghost</a>`+
				`<a href="http://wild-link.example.test/">Wild</a>`+
				`<a href="http://cdn-dangling.example.test/asset">Dangling</a>`+
				`</body></html>`)
		case "v3.example.test":
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			_, _ = fmt.Fprint(w, `<!doctype html><html><head><title>V3</title></head><body>OK</body></html>`)
		case "js-real.example.test":
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			_, _ = fmt.Fprint(w, `<!doctype html><html><head><title>JS Real</title></head><body>OK</body></html>`)
		case "api.v3.example.test":
			w.Header().Set("Content-Type", "application/json")
			_, _ = fmt.Fprint(w, `{"ok":true}`)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(ts.Close)

	dnsRecords := map[string]types.DNSResult{
		"example.test":             {IPs: "127.0.0.1", Resolved: true},
		"app.example.test":         {IPs: "127.0.0.1", Resolved: true},
		"dead-ct.example.test":     {},
		"wild-1.example.test":      {Wildcard: true},
		"wild-2.example.test":      {Wildcard: true},
		"legacy-docs.example.test": {CNAME: "old-docs.github.io", Resolved: false},

		"v3.example.test":             {IPs: "127.0.0.1", CNAME: "v3-edge.cloudfront.net", CDN: "cloudfront", Resolved: true},
		"js-real.example.test":        {IPs: "127.0.0.1", Resolved: true},
		"cdn-dangling.example.test":   {CNAME: "deleted-bucket.s3.amazonaws.com", Resolved: false},
		"ghost-internal.example.test": {},
		"js-ghost.example.test":       {},
		"wild-link.example.test":      {Wildcard: true},

		"api.v3.example.test":        {IPs: "127.0.0.1", Resolved: true},
		"wild-child.v3.example.test": {Wildcard: true},
		"dead-child.v3.example.test": {},
	}

	resolveStub := func(_ context.Context, _ string, hosts []string, onProgress func(int, int), onResult func(string, types.DNSResult)) error {
		for i, h := range hosts {
			if onProgress != nil {
				onProgress(i+1, len(hosts))
			}
			if onResult != nil {
				onResult(h, dnsRecords[h])
			}
		}
		return nil
	}

	dbPath := filepath.Join(t.TempDir(), "dnsx_pipeline.db")
	opts := &types.Options{
		Command:       "scan",
		Domain:        "example.test",
		DBPath:        dbPath,
		Depth:         -1,
		ContentDepth:  1,
		ContentAssets: 2,
		Threads:       2,
		RateLimit:     100,
		Timeout:       3,
		NoAuth:        true,
		Silent:        true,
	}
	r, err := NewRunner(opts)
	if err != nil {
		t.Fatalf("NewRunner: %v", err)
	}
	defer func() { _ = r.Close() }()

	r.targetAddr = ts.Listener.Addr().String()
	r.resolveFn = resolveStub
	r.enumFn = func(_ context.Context, domain string) (map[string][]string, error) {
		enumMu.Lock()
		enumCalls[domain]++
		enumMu.Unlock()

		switch domain {
		case "example.test":
			return map[string][]string{
				"app.example.test":         {"subfinder"},
				"dead-ct.example.test":     {"crtsh"},
				"wild-1.example.test":      {"subfinder"},
				"wild-2.example.test":      {"subfinder"},
				"legacy-docs.example.test": {"crtsh"},
			}, nil
		case "v3.example.test":
			return map[string][]string{
				"api.v3.example.test":        {"crtsh"},
				"wild-child.v3.example.test": {"crtsh"},
				"dead-child.v3.example.test": {"crtsh"},
			}, nil
		default:
			return nil, nil
		}
	}

	if err := r.Run(context.Background()); err != nil {
		t.Fatalf("ExecuteScan: %v", err)
	}

	// 1. Dead, wildcard, and dangling-CNAME hosts must never reach httpx TCP probing.
	for _, mustSkipHTTP := range []string{
		"dead-ct.example.test",
		"wild-1.example.test",
		"wild-2.example.test",
		"legacy-docs.example.test",
		"ghost-internal.example.test",
		"js-ghost.example.test",
		"wild-link.example.test",
		"cdn-dangling.example.test",
		"wild-child.v3.example.test",
		"dead-child.v3.example.test",
	} {
		if probedHTTP[mustSkipHTTP] > 0 {
			t.Errorf("host %s should have been skipped before httpx, got %d HTTP requests", mustSkipHTTP, probedHTTP[mustSkipHTTP])
		}
	}

	// 2. Unresolvable or wildcard content candidates must never trigger recursive subfinder queries.
	for _, ghost := range []string{"ghost-internal.example.test", "js-ghost.example.test", "wild-link.example.test"} {
		if enumCalls[ghost] > 0 {
			t.Errorf("unverified content candidate %s must not enter recursive subfinder crawl", ghost)
		}
	}

	ro, err := store.New(dbPath, true)
	if err != nil {
		t.Fatalf("open read-only store: %v", err)
	}
	defer func() { _ = ro.Close() }()

	all, err := ro.QueryHosts(types.Filter{Root: "example.test", Depth: -1})
	if err != nil {
		t.Fatalf("QueryHosts: %v", err)
	}
	byHost := make(map[string]types.Host, len(all))
	for _, h := range all {
		byHost[h.Host] = h
	}

	// 3. Wildcard hosts and unresolvable content ghosts must be absent from SQLite.
	for _, absent := range []string{
		"wild-1.example.test",
		"wild-2.example.test",
		"wild-link.example.test",
		"wild-child.v3.example.test",
		"ghost-internal.example.test",
		"js-ghost.example.test",
	} {
		if _, exists := byHost[absent]; exists {
			t.Errorf("expected %s to be pruned from SQLite hosts table", absent)
		}
	}

	// 4. Passive non-wildcard NXDOMAIN hosts stay in SQLite with alive=0.
	for _, deadPassive := range []string{"dead-ct.example.test", "dead-child.v3.example.test"} {
		h, ok := byHost[deadPassive]
		if !ok {
			t.Fatalf("expected passive NXDOMAIN host %s to remain in SQLite as alive=0", deadPassive)
		}
		if h.Alive || h.IPs != "" {
			t.Errorf("expected %s alive=false and empty IPs, got %+v", deadPassive, h)
		}
	}

	// 5. Active CNAME and dangling CNAME records (passive + content-derived) are stored accurately.
	v3, ok := byHost["v3.example.test"]
	if !ok || !v3.Alive || v3.CNAME != "v3-edge.cloudfront.net" {
		t.Errorf("expected v3.example.test alive with CNAME v3-edge.cloudfront.net, got %+v", v3)
	}
	if _, ok := byHost["js-real.example.test"]; !ok || !byHost["js-real.example.test"].Alive {
		t.Errorf("expected js-real.example.test to be verified via DNS and probed alive")
	}
	if _, ok := byHost["api.v3.example.test"]; !ok || !byHost["api.v3.example.test"].Alive {
		t.Errorf("expected feedback passive child api.v3.example.test to be probed alive")
	}

	dangling, err := ro.QueryHosts(types.Filter{Root: "example.test", Dangling: true, Depth: -1})
	if err != nil {
		t.Fatalf("QueryHosts dangling: %v", err)
	}
	if len(dangling) != 2 {
		t.Fatalf("expected 2 dangling CNAME hosts, got %+v", dangling)
	}
	danglingMap := map[string]string{
		dangling[0].Host: dangling[0].CNAME,
		dangling[1].Host: dangling[1].CNAME,
	}
	if danglingMap["legacy-docs.example.test"] != "old-docs.github.io" ||
		danglingMap["cdn-dangling.example.test"] != "deleted-bucket.s3.amazonaws.com" {
		t.Errorf("unexpected dangling CNAME hosts: %+v", danglingMap)
	}

	// 6. Verify -no-probe still runs dnsx (resolving IPs, saving CNAMEs, pruning wildcards) with zero HTTP requests.
	httpMu.Lock()
	probedHTTP = make(map[string]int)
	httpMu.Unlock()

	noProbeDB := filepath.Join(t.TempDir(), "noprobe_dnsx.db")
	rNoProbe, err := NewRunner(&types.Options{
		Command: "scan",
		Domain:  "example.test",
		DBPath:  noProbeDB,
		Depth:   0,
		NoProbe: true,
		Silent:  true,
	})
	if err != nil {
		t.Fatalf("NewRunner no-probe: %v", err)
	}
	defer func() { _ = rNoProbe.Close() }()
	rNoProbe.targetAddr = ts.Listener.Addr().String()
	rNoProbe.resolveFn = resolveStub
	rNoProbe.enumFn = func(_ context.Context, _ string) (map[string][]string, error) {
		return map[string][]string{
			"app.example.test":         {"subfinder"},
			"wild-1.example.test":      {"subfinder"},
			"legacy-docs.example.test": {"crtsh"},
		}, nil
	}
	if err := rNoProbe.Run(context.Background()); err != nil {
		t.Fatalf("ExecuteScan -no-probe: %v", err)
	}
	if len(probedHTTP) != 0 {
		t.Errorf("expected 0 HTTP requests with -no-probe, got %v", probedHTTP)
	}
	roNP, err := store.New(noProbeDB, true)
	if err != nil {
		t.Fatalf("open noprobe store: %v", err)
	}
	defer func() { _ = roNP.Close() }()

	npHosts, err := roNP.QueryHosts(types.Filter{Root: "example.test", Depth: -1})
	if err != nil {
		t.Fatalf("QueryHosts noprobe: %v", err)
	}
	if len(npHosts) != 3 { // example.test, app.example.test, legacy-docs.example.test (wild-1 pruned)
		t.Fatalf("expected 3 hosts in -no-probe DB after wildcard pruning, got %+v", npHosts)
	}
}
