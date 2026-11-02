package report

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aktezed/assfin/pkg/store"
	"github.com/aktezed/assfin/pkg/types"
)

func TestWriteReport(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "test.db")
	s, err := store.New(dbPath, false)
	if err != nil {
		t.Fatalf("create store: %v", err)
	}
	defer s.Close()

	scanID, err := s.StartScan("example.com", "{}")
	if err != nil {
		t.Fatalf("start scan: %v", err)
	}

	if err := s.UpsertHost(scanID, "example.com", "api.example.com", 1, []string{"subfinder"}); err != nil {
		t.Fatalf("upsert host: %v", err)
	}
	if err := s.SaveDNS("api.example.com", types.DNSResult{
		IPs:      "203.0.113.10",
		CNAME:    "api-edge.cloudfront.net",
		CDN:      "cloudfront",
		Resolved: true,
	}); err != nil {
		t.Fatalf("save dns: %v", err)
	}

	if err := s.SaveProbe("api.example.com", types.Probe{
		URL:    "https://api.example.com",
		Status: 200,
		Title:  "API Gateway",
		Server: "nginx",
		Tech:   []string{"Nginx", "Node.js"},
		WAF:    "Cloudflare",
	}); err != nil {
		t.Fatalf("save probe: %v", err)
	}

	if err := s.UpsertHost(scanID, "example.com", "docs.example.com", 1, []string{"crtsh"}); err != nil {
		t.Fatalf("upsert dangling host: %v", err)
	}
	if err := s.SaveDNS("docs.example.com", types.DNSResult{
		CNAME:    "retired-docs.github.io",
		Resolved: false,
	}); err != nil {
		t.Fatalf("save dangling dns: %v", err)
	}

	if err := s.UpsertContentHost(scanID, "example.com", "v3.example.com", 1, "api.example.com"); err != nil {
		t.Fatalf("upsert content host: %v", err)
	}
	if err := s.SaveHostRef("v3.example.com", "api.example.com", `</script><img src=x onerror=alert(1)> https://v3.example.com/portal`); err != nil {
		t.Fatalf("save host ref: %v", err)
	}

	if err := s.FinishScan(scanID); err != nil {
		t.Fatalf("finish scan: %v", err)
	}

	outPath := filepath.Join(t.TempDir(), "report.html")
	if err := WriteReport(s, outPath); err != nil {
		t.Fatalf("write report: %v", err)
	}

	content, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("read report: %v", err)
	}
	html := string(content)

	if !strings.Contains(html, "api.example.com") {
		t.Errorf("expected report to contain host api.example.com")
	}
	if !strings.Contains(html, "Cloudflare") {
		t.Errorf("expected report to contain WAF Cloudflare")
	}
	if !strings.Contains(html, "content:api.example.com") {
		t.Errorf("expected report to contain content-derived source provenance")
	}
	if !strings.Contains(html, `"refs":[`) {
		t.Errorf("expected report payload to include refs array")
	}
	if !strings.Contains(html, `"cname":"retired-docs.github.io"`) {
		t.Errorf("expected report payload to serialize dangling CNAME record")
	}
	if !strings.Contains(html, "Dangling CNAME") {
		t.Errorf("expected report template to include Dangling CNAME facet and badge controls")
	}
	if strings.Contains(html, "</script><img") {
		t.Errorf("expected untrusted snippet in DATA JSON to escape </script> tags")
	}
}

func TestWriteScopedReportIsolatesTarget(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "multi.db")
	s, err := store.New(dbPath, false)
	if err != nil {
		t.Fatalf("create store: %v", err)
	}
	defer func() { _ = s.Close() }()

	scanA, err := s.StartScan("client-a.com", "{}")
	if err != nil {
		t.Fatalf("start scan A: %v", err)
	}
	if err := s.UpsertHost(scanA, "client-a.com", "portal.client-a.com", 1, []string{"subfinder"}); err != nil {
		t.Fatalf("upsert A: %v", err)
	}
	if err := s.SaveHostRef("portal.client-a.com", "www.client-a.com", "href=/portal"); err != nil {
		t.Fatalf("save ref A: %v", err)
	}
	if err := s.FinishScan(scanA); err != nil {
		t.Fatalf("finish scan A: %v", err)
	}

	scanB, err := s.StartScan("client-b.com", "{}")
	if err != nil {
		t.Fatalf("start scan B: %v", err)
	}
	if err := s.UpsertHost(scanB, "client-b.com", "internal.client-b.com", 1, []string{"subfinder"}); err != nil {
		t.Fatalf("upsert B: %v", err)
	}
	if err := s.SaveHostRef("internal.client-b.com", "app.client-b.com", "href=/internal"); err != nil {
		t.Fatalf("save ref B: %v", err)
	}
	if err := s.FinishScan(scanB); err != nil {
		t.Fatalf("finish scan B: %v", err)
	}

	scopedPath := filepath.Join(t.TempDir(), "client-a-report.html")
	if err := WriteScopedReport(s, "client-a.com", scopedPath); err != nil {
		t.Fatalf("WriteScopedReport: %v", err)
	}
	scopedBytes, err := os.ReadFile(scopedPath)
	if err != nil {
		t.Fatalf("read scoped report: %v", err)
	}
	scopedHTML := string(scopedBytes)

	if !strings.Contains(scopedHTML, "portal.client-a.com") || !strings.Contains(scopedHTML, "www.client-a.com") {
		t.Errorf("expected scoped report to include client-a.com hosts and refs")
	}
	for _, leaked := range []string{"client-b.com", "internal.client-b.com", "app.client-b.com"} {
		if strings.Contains(scopedHTML, leaked) {
			t.Errorf("scoped report for client-a.com leaked %q", leaked)
		}
	}
}
