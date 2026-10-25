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

	if !strings.Contains(string(content), "api.example.com") {
		t.Errorf("expected report to contain host api.example.com")
	}
	if !strings.Contains(string(content), "Cloudflare") {
		t.Errorf("expected report to contain WAF Cloudflare")
	}
}
