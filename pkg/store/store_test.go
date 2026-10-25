package store

import (
	"path/filepath"
	"slices"
	"testing"

	"github.com/aktezed/assfin/pkg/types"
)

func seedDB(t *testing.T) (string, func(types.Filter) []string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "t.db")
	s, err := New(path, false)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}

	s1, err := s.StartScan("a.com", "{}")
	must(err)
	must(s.UpsertHost(s1, "a.com", "a.com", 0, nil))
	must(s.UpsertHost(s1, "a.com", "api.a.com", 1, []string{"crtsh"}))
	must(s.UpsertHost(s1, "a.com", "dev.a.com", 1, nil))
	must(s.SaveProbe("api.a.com", types.Probe{Status: 200, Tech: []string{"Nginx:1.21", "PHP"}, WAF: "Cloudflare"}))
	must(s.SaveProbe("dev.a.com", types.Probe{Status: 403, Tech: []string{"Apache"}}))

	s2, err := s.StartScan("a.com", "{}")
	must(err)
	must(s.UpsertHost(s2, "a.com", "api.a.com", 1, nil)) // seen again: not new
	must(s.UpsertHost(s2, "a.com", "v1.api.a.com", 2, nil))
	must(s.UpsertHost(s2, "a.com", "100%_x.a.com", 1, nil))

	return path, func(f types.Filter) []string {
		t.Helper()
		ro, err := New(path, true)
		must(err)
		defer ro.Close()
		hs, err := ro.QueryHosts(f)
		must(err)
		var out []string
		for _, h := range hs {
			out = append(out, h.Host)
		}
		slices.Sort(out)
		return out
	}
}

func TestQueryFilters(t *testing.T) {
	_, q := seedDB(t)
	tests := []struct {
		name string
		f    types.Filter
		want []string
	}{
		{"name OR", types.Filter{Depth: -1, Names: []string{"api", "dev"}}, []string{"api.a.com", "dev.a.com", "v1.api.a.com"}},
		{"name is literal not wildcard", types.Filter{Depth: -1, Names: []string{"%_"}}, []string{"100%_x.a.com"}},
		{"injection is literal", types.Filter{Depth: -1, Names: []string{"'; DROP TABLE hosts; --"}}, nil},
		{"tech prefix matches version", types.Filter{Depth: -1, Tech: []string{"nginx"}}, []string{"api.a.com"}},
		{"no waf + alive", types.Filter{Depth: -1, WAF: "no", Alive: "yes"}, []string{"dev.a.com"}},
		{"waf name", types.Filter{Depth: -1, WAFName: "cloud"}, []string{"api.a.com"}},
		{"status", types.Filter{Depth: -1, Status: []int{403, 500}}, []string{"dev.a.com"}},
		{"dead", types.Filter{Depth: -1, Alive: "no"}, []string{"100%_x.a.com", "a.com", "v1.api.a.com"}},
		{"new", types.Filter{Depth: -1, New: true}, []string{"100%_x.a.com", "v1.api.a.com"}},
		{"depth", types.Filter{Depth: 2}, []string{"v1.api.a.com"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := q(tt.f); !slices.Equal(got, tt.want) {
				t.Errorf("got %v, want %v", got, tt.want)
			}
		})
	}
	if got := q(types.Filter{Depth: -1}); len(got) != 5 {
		t.Errorf("table should still have 5 rows, got %v", got)
	}
}

func TestReadOnlyRejectsWrites(t *testing.T) {
	path, _ := seedDB(t)
	ro, err := New(path, true)
	if err != nil {
		t.Fatal(err)
	}
	defer ro.Close()
	if _, _, err := ro.RawQuery("DELETE FROM hosts"); err == nil {
		t.Fatal("raw write on read-only DB should fail")
	}
	cols, rows, err := ro.RawQuery("SELECT count(*) AS n FROM hosts")
	if err != nil || cols[0] != "n" || rows[0][0] != "5" {
		t.Fatalf("got %v %v %v", cols, rows, err)
	}
}

func TestGetScansSummary(t *testing.T) {
	path := filepath.Join(t.TempDir(), "summary.db")
	s, err := New(path, false)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	scanID, err := s.StartScan("example.com", "{}")
	if err != nil {
		t.Fatal(err)
	}

	if err := s.FinishScan(scanID); err != nil {
		t.Fatal(err)
	}

	summaries, err := s.GetScansSummary()
	if err != nil {
		t.Fatalf("GetScansSummary: %v", err)
	}
	if len(summaries) != 1 {
		t.Fatalf("expected 1 summary, got %d", len(summaries))
	}
	if summaries[0].Root != "example.com" {
		t.Errorf("expected root 'example.com', got %q", summaries[0].Root)
	}
	if summaries[0].Scans != 1 {
		t.Errorf("expected 1 scan, got %d", summaries[0].Scans)
	}
	if summaries[0].Last == "" {
		t.Errorf("expected non-empty Last")
	}
}
