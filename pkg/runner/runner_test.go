package runner

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
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
		got := formatDuration(tt.d)
		if got != tt.want {
			t.Errorf("formatDuration(%v) = %q, want %q", tt.d, got, tt.want)
		}
	}
}

func TestNormalizeListenAddr(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"", ":8080"},
		{"8080", ":8080"},
		{":9000", ":9000"},
		{"127.0.0.1:3000", "127.0.0.1:3000"},
	}

	for _, tt := range tests {
		got := normalizeListenAddr(tt.input)
		if got != tt.want {
			t.Errorf("normalizeListenAddr(%q) = %q, want %q", tt.input, got, tt.want)
		}
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
