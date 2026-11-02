package scan

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aktezed/assfin/pkg/types"
	"github.com/miekg/dns"
)

func startBenchDNSServer(b *testing.B, handler dns.HandlerFunc) string {
	b.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		b.Fatalf("listen udp: %v", err)
	}
	srv := &dns.Server{
		PacketConn: pc,
		Handler:    handler,
	}
	ready := make(chan struct{})
	srv.NotifyStartedFunc = func() { close(ready) }
	go func() { _ = srv.ActivateAndServe() }()
	<-ready
	b.Cleanup(func() { _ = srv.Shutdown() })
	return pc.LocalAddr().String()
}

func mustRR(b *testing.B, s string) dns.RR {
	b.Helper()
	r, err := dns.NewRR(s)
	if err != nil {
		b.Fatalf("parse RR %q: %v", s, err)
	}
	return r
}

func BenchmarkNewResolver(b *testing.B) {
	aRR := mustRR(b, "api.bench.test. 60 IN A 203.0.113.10")
	cnameRR := mustRR(b, "cdn.bench.test. 60 IN CNAME edge.provider.test.")
	cnameTargetARR := mustRR(b, "edge.provider.test. 60 IN A 203.0.113.20")

	addr := startBenchDNSServer(b, func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		if len(r.Question) == 0 {
			_ = w.WriteMsg(m)
			return
		}
		q := r.Question[0]
		name := strings.ToLower(q.Name)

		switch {
		case name == "api.bench.test.":
			if q.Qtype == dns.TypeA {
				m.Answer = append(m.Answer, aRR)
			}
		case name == "cdn.bench.test.":
			switch q.Qtype {
			case dns.TypeA:
				m.Answer = append(m.Answer, cnameRR, cnameTargetARR)
			case dns.TypeCNAME:
				m.Answer = append(m.Answer, cnameRR)
			}
		case strings.HasSuffix(name, ".wc.test."):
			if q.Qtype == dns.TypeA {
				m.Answer = append(m.Answer, &dns.A{
					Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
					A:   net.IPv4(198, 51, 100, 99),
				})
			}
		default:
			m.Rcode = dns.RcodeNameError
		}
		_ = w.WriteMsg(m)
	})

	resolve, err := NewResolver(ResolveOpts{
		Threads:        8,
		Rate:           0,
		Timeout:        2,
		Retries:        1,
		Resolvers:      addr,
		WildcardFilter: true,
	})
	if err != nil {
		b.Fatalf("NewResolver: %v", err)
	}

	ctx := context.Background()
	// Warm per-root wildcard caches once outside measured loops.
	if err := resolve(ctx, "bench.test", []string{"api.bench.test"}, nil, nil); err != nil {
		b.Fatalf("warm bench.test: %v", err)
	}
	if err := resolve(ctx, "wc.test", []string{"warm.wc.test"}, nil, nil); err != nil {
		b.Fatalf("warm wc.test: %v", err)
	}

	cases := []struct {
		name  string
		root  string
		hosts []string
	}{
		{name: "A_record", root: "bench.test", hosts: []string{"api.bench.test"}},
		{name: "CNAME_chain", root: "bench.test", hosts: []string{"cdn.bench.test"}},
		{name: "NXDOMAIN_fast_exit", root: "bench.test", hosts: []string{"dead.bench.test"}},
		{name: "Wildcard_cached", root: "wc.test", hosts: []string{"junk.wc.test"}},
	}

	for _, tc := range cases {
		b.Run(tc.name, func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				if err := resolve(ctx, tc.root, tc.hosts, nil, func(_ string, _ types.DNSResult) {}); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func BenchmarkNormalizeCNAMEs(b *testing.B) {
	b.Run("single_hop", func(b *testing.B) {
		in := []string{"Edge.CloudFront.NET."}
		b.ReportAllocs()
		for b.Loop() {
			_ = normalizeCNAMEs(in)
		}
	})

	b.Run("multi_hop_dedup", func(b *testing.B) {
		in := []string{
			"Alias-1.Target.COM.",
			"alias-2.cdn.net.",
			"ALIAS-1.target.com",
			"origin-bucket.s3.amazonaws.com.",
		}
		b.ReportAllocs()
		for b.Loop() {
			_ = normalizeCNAMEs(in)
		}
	})
}

func BenchmarkParseCustomResolvers(b *testing.B) {
	b.Run("inline_csv", func(b *testing.B) {
		const spec = "1.1.1.1, 8.8.8.8:53, 9.9.9.9, 1.0.0.1:5353"
		b.ReportAllocs()
		for b.Loop() {
			if _, err := parseCustomResolvers(spec); err != nil {
				b.Fatal(err)
			}
		}
	})

	b.Run("file", func(b *testing.B) {
		path := filepath.Join(b.TempDir(), "resolvers.txt")
		var sb strings.Builder
		sb.WriteString("# resolver list\n")
		for i := range 32 {
			fmt.Fprintf(&sb, "198.51.100.%d\n", i+1)
		}
		if err := os.WriteFile(path, []byte(sb.String()), 0o644); err != nil {
			b.Fatal(err)
		}
		b.ReportAllocs()
		for b.Loop() {
			if _, err := parseCustomResolvers(path); err != nil {
				b.Fatal(err)
			}
		}
	})
}
