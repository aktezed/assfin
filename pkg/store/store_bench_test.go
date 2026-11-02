package store

import (
	"fmt"
	"path/filepath"
	"testing"

	"github.com/aktezed/assfin/pkg/types"
)

func seedBenchStore(b *testing.B, count int) *Store {
	b.Helper()
	dbPath := filepath.Join(b.TempDir(), "bench.db")
	st, err := New(dbPath, false)
	if err != nil {
		b.Fatalf("New store: %v", err)
	}
	b.Cleanup(func() { _ = st.Close() })

	scanID, err := st.StartScan("example.com", "{}")
	if err != nil {
		b.Fatalf("StartScan: %v", err)
	}

	for i := range count {
		host := fmt.Sprintf("sub-%d.example.com", i)
		if err := st.UpsertHost(scanID, "example.com", host, 1, []string{"subfinder"}); err != nil {
			b.Fatalf("UpsertHost: %v", err)
		}
		switch {
		case i%10 == 0:
			// Dangling CNAME (10%)
			if err := st.SaveDNS(host, types.DNSResult{
				CNAME: fmt.Sprintf("deleted-%d.s3.amazonaws.com", i),
			}); err != nil {
				b.Fatalf("SaveDNS dangling: %v", err)
			}
		case i%3 == 0:
			// Resolved with CNAME (30%)
			if err := st.SaveDNS(host, types.DNSResult{
				IPs:      "203.0.113.10",
				CNAME:    "edge.cloudfront.net",
				CDN:      "cloudfront",
				Resolved: true,
			}); err != nil {
				b.Fatalf("SaveDNS cname: %v", err)
			}
		case i%2 == 0:
			// Resolved direct A record
			if err := st.SaveDNS(host, types.DNSResult{
				IPs:      "203.0.113.20",
				Resolved: true,
			}); err != nil {
				b.Fatalf("SaveDNS direct: %v", err)
			}
		}
	}
	return st
}

func BenchmarkStore_SaveDNS(b *testing.B) {
	st := seedBenchStore(b, 64)
	hosts := make([]string, 64)
	for i := range hosts {
		hosts[i] = fmt.Sprintf("sub-%d.example.com", i)
	}
	res := types.DNSResult{
		IPs:      "203.0.113.10,203.0.113.11",
		CNAME:    "edge.cloudfront.net",
		CDN:      "cloudfront",
		WAF:      "cloudfront",
		Resolved: true,
	}

	b.ReportAllocs()
	var idx int
	for b.Loop() {
		host := hosts[idx&63]
		idx++
		if err := st.SaveDNS(host, res); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkStore_DeleteHosts(b *testing.B) {
	st := seedBenchStore(b, 16)
	batch := make([]string, 200)
	for i := range batch {
		batch[i] = fmt.Sprintf("wc-%d.example.com", i)
	}

	b.ReportAllocs()
	for b.Loop() {
		b.StopTimer()
		tx, err := st.db.Begin()
		if err != nil {
			b.Fatal(err)
		}
		stmt := tx.Stmt(st.upsertSt)
		for _, h := range batch {
			if _, err := stmt.Exec(h, "example.com", 1, "subfinder", "2026-01-01T00:00:00Z", "2026-01-01T00:00:00Z", 1, 1); err != nil {
				_ = stmt.Close()
				_ = tx.Rollback()
				b.Fatal(err)
			}
		}
		_ = stmt.Close()
		if err := tx.Commit(); err != nil {
			b.Fatal(err)
		}
		b.StartTimer()

		if err := st.DeleteHosts("example.com", batch); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkStore_QueryHosts(b *testing.B) {
	st := seedBenchStore(b, 500)

	cases := []struct {
		name   string
		filter types.Filter
	}{
		{
			name:   "resolved",
			filter: types.Filter{Root: "example.com", Depth: -1, Resolved: "yes"},
		},
		{
			name:   "has_cname",
			filter: types.Filter{Root: "example.com", Depth: -1, HasCNAME: true},
		},
		{
			name:   "cname_target",
			filter: types.Filter{Root: "example.com", Depth: -1, CNAMETarget: []string{"s3.amazonaws.com"}},
		},
		{
			name:   "dangling",
			filter: types.Filter{Root: "example.com", Depth: -1, Dangling: true},
		},
	}

	for _, tc := range cases {
		b.Run(tc.name, func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				if _, err := st.QueryHosts(tc.filter); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func BenchmarkBuildWhere(b *testing.B) {
	filter := types.Filter{
		Root:        "example.com",
		Depth:       -1,
		Resolved:    "no",
		HasCNAME:    true,
		CNAMETarget: []string{"s3.amazonaws.com", "github.io"},
		Dangling:    true,
	}

	b.ReportAllocs()
	for b.Loop() {
		_, _ = buildWhere(filter, true)
	}
}
