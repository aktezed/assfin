package runner

import (
	"bytes"
	"context"
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
}
