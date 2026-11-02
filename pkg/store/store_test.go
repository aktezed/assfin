package store

import (
	"database/sql"
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
	must(s.SaveProbe("api.a.com", types.Probe{Status: 200, Tech: []string{"Nginx:1.21", "PHP"}, WAF: "Cloudflare", AuthType: "register", AuthURL: "https://api.a.com/signup"}))
	must(s.SaveProbe("dev.a.com", types.Probe{Status: 403, Tech: []string{"Apache"}, AuthType: "login_only", AuthURL: "https://dev.a.com/login"}))

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
		{"auth_type register", types.Filter{Depth: -1, AuthType: "register"}, []string{"api.a.com"}},
		{"auth_type login_only", types.Filter{Depth: -1, AuthType: "login_only"}, []string{"dev.a.com"}},
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

func TestContentHostsAndRefs(t *testing.T) {
	path := filepath.Join(t.TempDir(), "content.db")
	s, err := New(path, false)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	scanID, err := s.StartScan("example.gov", "{}")
	if err != nil {
		t.Fatal(err)
	}

	if err := s.UpsertHost(scanID, "example.gov", "v2.example.gov", 1, []string{"crtsh"}); err != nil {
		t.Fatal(err)
	}
	// Content reference to an already-known CT host must preserve its passive source.
	if err := s.UpsertContentHost(scanID, "example.gov", "v2.example.gov", 1, "www.example.gov"); err != nil {
		t.Fatal(err)
	}
	// Brand-new content-derived host gets content:<referrer>.
	if err := s.UpsertContentHost(scanID, "example.gov", "v3.example.gov", 1, "v2.example.gov"); err != nil {
		t.Fatal(err)
	}
	if err := s.SaveHostRef("v3.example.gov", "v2.example.gov", `<a href="https://v3.example.gov">`); err != nil {
		t.Fatal(err)
	}
	if err := s.SaveHostRef("v2.example.gov", "www.example.gov", `<a href="https://v2.example.gov">`); err != nil {
		t.Fatal(err)
	}

	hosts, err := s.QueryHosts(types.Filter{Root: "example.gov", Depth: -1})
	if err != nil {
		t.Fatal(err)
	}
	byHost := make(map[string]types.Host, len(hosts))
	for _, h := range hosts {
		byHost[h.Host] = h
	}
	if byHost["v2.example.gov"].Sources != "crtsh" {
		t.Errorf("v2.example.gov sources = %q, want crtsh", byHost["v2.example.gov"].Sources)
	}
	if byHost["v3.example.gov"].Sources != "content:v2.example.gov" {
		t.Errorf("v3.example.gov sources = %q, want content:v2.example.gov", byHost["v3.example.gov"].Sources)
	}

	refs, err := s.QueryHostRefs("example.gov")
	if err != nil {
		t.Fatal(err)
	}
	if len(refs) != 2 {
		t.Fatalf("expected 2 host_refs, got %d: %+v", len(refs), refs)
	}
	if refs[1].Host != "v3.example.gov" || refs[1].Referrer != "v2.example.gov" {
		t.Errorf("unexpected ref[1]: %+v", refs[1])
	}
}

func TestDNSStorageFiltersAndWildcardDelete(t *testing.T) {
	path := filepath.Join(t.TempDir(), "dns.db")
	s, err := New(path, false)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = s.Close() }()

	scanID, err := s.StartScan("example.com", "{}")
	if err != nil {
		t.Fatal(err)
	}
	for _, h := range []string{"example.com", "app.example.com", "vpn.example.com", "promo.example.com", "wc1.example.com"} {
		depth := 1
		if h == "example.com" {
			depth = 0
		}
		if err := s.UpsertHost(scanID, "example.com", h, depth, []string{"subfinder"}); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.SaveHostRef("wc1.example.com", "app.example.com", "https://wc1.example.com"); err != nil {
		t.Fatal(err)
	}

	// Active CNAME + HTTP response: probe keeps CNAME and updates HTTP fields while preserving DNS IPs if probe leaves IPs empty.
	if err := s.SaveDNS("app.example.com", types.DNSResult{
		IPs:      "104.21.1.10",
		CNAME:    "app.cdn.cloudflare.net",
		CDN:      "cloudflare",
		WAF:      "Cloudflare",
		Resolved: true,
	}); err != nil {
		t.Fatal(err)
	}
	if err := s.SaveProbe("app.example.com", types.Probe{
		URL:    "https://app.example.com",
		Status: 200,
		Title:  "App",
	}); err != nil {
		t.Fatal(err)
	}

	// Non-HTTP service (e.g. VPN): resolved in DNS, no HTTP SaveProbe call.
	if err := s.SaveDNS("vpn.example.com", types.DNSResult{
		IPs:      "203.0.113.44",
		Resolved: true,
	}); err != nil {
		t.Fatal(err)
	}

	// Dangling CNAME: CNAME present, no A/AAAA IPs.
	if err := s.SaveDNS("promo.example.com", types.DNSResult{
		CNAME:    "old-promo.s3.amazonaws.com",
		Resolved: false,
	}); err != nil {
		t.Fatal(err)
	}

	// DeleteHosts must remove wc1.example.com (and its host_refs) without deleting root apex example.com.
	if err := s.DeleteHosts("example.com", []string{"example.com", "wc1.example.com"}); err != nil {
		t.Fatal(err)
	}

	all, err := s.QueryHosts(types.Filter{Depth: -1})
	if err != nil {
		t.Fatal(err)
	}
	byHost := make(map[string]types.Host, len(all))
	for _, h := range all {
		byHost[h.Host] = h
	}
	if _, exists := byHost["wc1.example.com"]; exists {
		t.Fatal("expected wildcard host wc1.example.com to be deleted")
	}
	if _, exists := byHost["example.com"]; !exists {
		t.Fatal("root apex example.com must never be deleted by DeleteHosts")
	}
	if got := byHost["app.example.com"]; got.CNAME != "app.cdn.cloudflare.net" || got.IPs != "104.21.1.10" || got.WAF != "Cloudflare" || !got.Alive {
		t.Errorf("app.example.com DNS + probe merge unexpected: %+v", got)
	}
	if got := byHost["vpn.example.com"]; got.IPs != "203.0.113.44" || got.Alive {
		t.Errorf("vpn.example.com non-HTTP DNS state unexpected: %+v", got)
	}

	refs, err := s.QueryHostRefs("example.com")
	if err != nil {
		t.Fatal(err)
	}
	if len(refs) != 0 {
		t.Errorf("expected host_refs for deleted wildcard host to be removed, got %+v", refs)
	}

	// Verify DNS query filters.
	dangling, err := s.QueryHosts(types.Filter{Depth: -1, Dangling: true})
	if err != nil || len(dangling) != 1 || dangling[0].Host != "promo.example.com" {
		t.Fatalf("dangling filter got %+v (err=%v)", dangling, err)
	}
	cnames, err := s.QueryHosts(types.Filter{Depth: -1, HasCNAME: true})
	if err != nil || len(cnames) != 2 {
		t.Fatalf("HasCNAME filter got %+v (err=%v)", cnames, err)
	}
	s3Hosts, err := s.QueryHosts(types.Filter{Depth: -1, CNAMETarget: []string{"s3.amazonaws.com"}})
	if err != nil || len(s3Hosts) != 1 || s3Hosts[0].Host != "promo.example.com" {
		t.Fatalf("CNAMETarget filter got %+v (err=%v)", s3Hosts, err)
	}
	resolved, err := s.QueryHosts(types.Filter{Depth: -1, Resolved: "yes"})
	if err != nil || len(resolved) != 2 {
		t.Fatalf("Resolved=yes filter got %+v (err=%v)", resolved, err)
	}
}

func TestLegacyReadOnlyDBWithoutCNAMEColumn(t *testing.T) {
	path := filepath.Join(t.TempDir(), "legacy.db")
	rawDB, err := sql.Open("sqlite", "file:"+path)
	if err != nil {
		t.Fatal(err)
	}
	_, err = rawDB.Exec(`
CREATE TABLE scans (id INTEGER PRIMARY KEY, root TEXT, started TEXT, finished TEXT, opts TEXT);
CREATE TABLE hosts (
  host TEXT PRIMARY KEY, root TEXT, depth INT, sources TEXT,
  first_seen TEXT, last_seen TEXT, first_scan INT, last_scan INT,
  alive INT DEFAULT 0, url TEXT DEFAULT '', status INT DEFAULT 0, title TEXT DEFAULT '',
  server TEXT DEFAULT '', tech TEXT DEFAULT '', ips TEXT DEFAULT '', cdn TEXT DEFAULT '',
  waf TEXT DEFAULT '', length INT DEFAULT 0, auth_type TEXT DEFAULT '', auth_url TEXT DEFAULT '');
INSERT INTO scans(id, root, started, finished, opts) VALUES (1, 'old.com', '2026-01-01T00:00:00Z', '2026-01-01T00:01:00Z', '{}');
INSERT INTO hosts(host, root, depth, sources, first_seen, last_seen, first_scan, last_scan, alive, status, ips)
VALUES ('api.old.com', 'old.com', 1, 'crtsh', '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z', 1, 1, 1, 200, '198.51.100.1');`)
	if err != nil {
		_ = rawDB.Close()
		t.Fatal(err)
	}
	_ = rawDB.Close()

	ro, err := New(path, true)
	if err != nil {
		t.Fatalf("open legacy read-only DB: %v", err)
	}
	defer func() { _ = ro.Close() }()

	hosts, err := ro.QueryHosts(types.Filter{Depth: -1})
	if err != nil {
		t.Fatalf("QueryHosts on legacy DB: %v", err)
	}
	if len(hosts) != 1 || hosts[0].Host != "api.old.com" || hosts[0].CNAME != "" {
		t.Fatalf("unexpected legacy hosts: %+v", hosts)
	}
	dangling, err := ro.QueryHosts(types.Filter{Depth: -1, Dangling: true})
	if err != nil || len(dangling) != 0 {
		t.Fatalf("expected 0 dangling rows on legacy DB, got %+v (err=%v)", dangling, err)
	}
}
