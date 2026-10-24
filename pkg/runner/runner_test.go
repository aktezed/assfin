package runner

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/dzaki/assfin/pkg/store"
	"github.com/dzaki/assfin/pkg/types"
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
}
