package scan

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/aktezed/assfin/pkg/types"
	"github.com/miekg/dns"
)

func startLocalDNSServer(t *testing.T, handler dns.HandlerFunc) string {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen udp: %v", err)
	}
	srv := &dns.Server{
		PacketConn: pc,
		Handler:    handler,
	}
	ready := make(chan struct{})
	srv.NotifyStartedFunc = func() { close(ready) }
	go func() { _ = srv.ActivateAndServe() }()
	<-ready
	t.Cleanup(func() { _ = srv.Shutdown() })
	return pc.LocalAddr().String()
}

func rr(t *testing.T, s string) dns.RR {
	t.Helper()
	r, err := dns.NewRR(s)
	if err != nil {
		t.Fatalf("parse RR %q: %v", s, err)
	}
	return r
}

func TestResolverRecordsAndDanglingCNAMEs(t *testing.T) {
	addr := startLocalDNSServer(t, func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		if len(r.Question) == 0 {
			_ = w.WriteMsg(m)
			return
		}
		q := r.Question[0]
		name := strings.ToLower(q.Name)

		switch name {
		case "example.test.":
			if q.Qtype == dns.TypeA {
				m.Answer = append(m.Answer, rr(t, "example.test. 60 IN A 203.0.113.1"))
			}
		case "api.example.test.":
			if q.Qtype == dns.TypeA {
				m.Answer = append(m.Answer, rr(t, "api.example.test. 60 IN A 203.0.113.10"))
			}
		case "v6.example.test.":
			// IPv6-only: NOERROR empty answer on A (NODATA), AAAA record on AAAA.
			if q.Qtype == dns.TypeAAAA {
				m.Answer = append(m.Answer, rr(t, "v6.example.test. 60 IN AAAA 2001:db8::1"))
			}
		case "cdn.example.test.":
			if q.Qtype == dns.TypeA {
				m.Answer = append(m.Answer,
					rr(t, "cdn.example.test. 60 IN CNAME edge.provider.test."),
					rr(t, "edge.provider.test. 60 IN A 203.0.113.20"),
				)
			} else if q.Qtype == dns.TypeCNAME {
				m.Answer = append(m.Answer, rr(t, "cdn.example.test. 60 IN CNAME edge.provider.test."))
			}
		case "s3.example.test.":
			// Dangling CNAME where target bucket does not exist (NXDOMAIN on A/AAAA, CNAME included).
			m.Answer = append(m.Answer, rr(t, "s3.example.test. 60 IN CNAME deleted-bucket.s3.amazonaws.com."))
			if q.Qtype != dns.TypeCNAME {
				m.Rcode = dns.RcodeNameError
			}
		case "broken.example.test.":
			// Dangling CNAME pointing to an expired external domain whose NS fails (SERVFAIL on A, NOERROR on CNAME).
			switch q.Qtype {
			case dns.TypeA, dns.TypeAAAA:
				m.Rcode = dns.RcodeServerFailure
			case dns.TypeCNAME:
				m.Answer = append(m.Answer, rr(t, "broken.example.test. 60 IN CNAME expired-ns.external.test."))
			}
		default:
			m.Rcode = dns.RcodeNameError
		}
		_ = w.WriteMsg(m)
	})

	resolve, err := NewResolver(ResolveOpts{
		Threads:        4,
		Rate:           500,
		Timeout:        2,
		Retries:        1,
		Resolvers:      addr,
		WildcardFilter: true,
	})
	if err != nil {
		t.Fatalf("NewResolver: %v", err)
	}

	inputs := []string{
		"example.test",
		"api.example.test",
		"v6.example.test",
		"cdn.example.test",
		"s3.example.test",
		"broken.example.test",
		"dead.example.test",
	}

	got := make(map[string]types.DNSResult)
	var progressCalls int
	err = resolve(t.Context(), "example.test", inputs, func(_, _ int) {
		progressCalls++
	}, func(host string, res types.DNSResult) {
		got[host] = res
	})
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if progressCalls != len(inputs) {
		t.Errorf("progressCalls = %d, want %d", progressCalls, len(inputs))
	}

	if r := got["api.example.test"]; !r.Resolved || r.IPs != "203.0.113.10" || r.Wildcard {
		t.Errorf("api.example.test = %+v", r)
	}
	if r := got["v6.example.test"]; !r.Resolved || r.IPs != "2001:db8::1" || r.Wildcard {
		t.Errorf("v6.example.test = %+v", r)
	}
	if r := got["cdn.example.test"]; !r.Resolved || r.IPs != "203.0.113.20" || r.CNAME != "edge.provider.test" {
		t.Errorf("cdn.example.test = %+v", r)
	}
	if r := got["s3.example.test"]; r.Resolved || r.IPs != "" || r.CNAME != "deleted-bucket.s3.amazonaws.com" || r.Wildcard {
		t.Errorf("s3.example.test expected dangling CNAME, got %+v", r)
	}
	if r := got["broken.example.test"]; r.Resolved || r.IPs != "" || r.CNAME != "expired-ns.external.test" || r.Wildcard {
		t.Errorf("broken.example.test expected SERVFAIL fallback dangling CNAME, got %+v", r)
	}
	if r := got["dead.example.test"]; r.Resolved || r.IPs != "" || r.CNAME != "" || r.Wildcard {
		t.Errorf("dead.example.test expected empty NXDOMAIN result, got %+v", r)
	}
}

func TestResolverWildcardIPAndCNAMEPruning(t *testing.T) {
	var roundRobin atomic.Uint32
	addr := startLocalDNSServer(t, func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		q := r.Question[0]
		name := strings.ToLower(q.Name)

		switch {
		case name == "wc.test.":
			if q.Qtype == dns.TypeA {
				m.Answer = append(m.Answer, rr(t, "wc.test. 60 IN A 198.51.100.99"))
			}
		case name == "real-api.wc.test.":
			if q.Qtype == dns.TypeA {
				m.Answer = append(m.Answer, rr(t, "real-api.wc.test. 60 IN A 203.0.113.55"))
			}
		case strings.HasSuffix(name, ".wc.test."):
			// Wildcard A zone *.wc.test -> 198.51.100.99
			if q.Qtype == dns.TypeA {
				m.Answer = append(m.Answer, rr(t, name+" 60 IN A 198.51.100.99"))
			}

		case name == "mail.parked.test.":
			switch q.Qtype {
			case dns.TypeA:
				m.Answer = append(m.Answer,
					rr(t, "mail.parked.test. 60 IN CNAME ghs.googlehosted.test."),
					rr(t, "ghs.googlehosted.test. 60 IN A 203.0.113.77"),
				)
			case dns.TypeCNAME:
				m.Answer = append(m.Answer, rr(t, "mail.parked.test. 60 IN CNAME ghs.googlehosted.test."))
			}
		case strings.HasSuffix(name, ".parked.test."):
			// Wildcard CNAME zone *.parked.test -> parking.bodis.test with rotating IPs
			switch q.Qtype {
			case dns.TypeA:
				ip := "198.51.100.1"
				if roundRobin.Add(1)%2 == 0 {
					ip = "198.51.100.2"
				}
				m.Answer = append(m.Answer,
					rr(t, name+" 60 IN CNAME parking.bodis.test."),
					rr(t, "parking.bodis.test. 60 IN A "+ip),
				)
			case dns.TypeCNAME:
				m.Answer = append(m.Answer, rr(t, name+" 60 IN CNAME parking.bodis.test."))
			}
		default:
			m.Rcode = dns.RcodeNameError
		}
		_ = w.WriteMsg(m)
	})

	resolve, err := NewResolver(ResolveOpts{
		Threads:        4,
		Rate:           500,
		Timeout:        2,
		Retries:        1,
		Resolvers:      addr,
		WildcardFilter: true,
	})
	if err != nil {
		t.Fatalf("NewResolver: %v", err)
	}

	wcResults := make(map[string]types.DNSResult)
	err = resolve(t.Context(), "wc.test", []string{"wc.test", "real-api.wc.test", "fake1.wc.test", "fake2.wc.test"}, nil, func(h string, res types.DNSResult) {
		wcResults[h] = res
	})
	if err != nil {
		t.Fatalf("resolve wc.test: %v", err)
	}
	if r := wcResults["wc.test"]; r.Wildcard || !r.Resolved {
		t.Errorf("apex wc.test must not be flagged wildcard: %+v", r)
	}
	if r := wcResults["real-api.wc.test"]; r.Wildcard || !r.Resolved || r.IPs != "203.0.113.55" {
		t.Errorf("real-api.wc.test must bypass wildcard filter: %+v", r)
	}
	if !wcResults["fake1.wc.test"].Wildcard || !wcResults["fake2.wc.test"].Wildcard {
		t.Errorf("expected fake1/fake2 to be flagged wildcard: %+v", wcResults)
	}

	parkedResults := make(map[string]types.DNSResult)
	err = resolve(t.Context(), "parked.test", []string{"mail.parked.test", "junk.parked.test"}, nil, func(h string, res types.DNSResult) {
		parkedResults[h] = res
	})
	if err != nil {
		t.Fatalf("resolve parked.test: %v", err)
	}
	if r := parkedResults["mail.parked.test"]; r.Wildcard || !r.Resolved || r.CNAME != "ghs.googlehosted.test" {
		t.Errorf("mail.parked.test must bypass wildcard CNAME filter: %+v", r)
	}
	if !parkedResults["junk.parked.test"].Wildcard {
		t.Errorf("expected junk.parked.test wildcard CNAME to be pruned: %+v", parkedResults["junk.parked.test"])
	}
}

func TestParseCustomResolversFileAndCancel(t *testing.T) {
	rf := filepath.Join(t.TempDir(), "resolvers.txt")
	if err := os.WriteFile(rf, []byte("# comment\n1.1.1.1\n8.8.8.8:53\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	list, err := parseCustomResolvers(rf)
	if err != nil {
		t.Fatalf("parseCustomResolvers: %v", err)
	}
	if len(list) != 2 || list[0] != "1.1.1.1:53" || list[1] != "8.8.8.8:53" {
		t.Fatalf("unexpected resolvers: %v", list)
	}

	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	resolve, err := NewResolver(ResolveOpts{Resolvers: "127.0.0.1:53", Retries: 1, Timeout: 1})
	if err != nil {
		t.Fatal(err)
	}
	if err := resolve(ctx, "example.test", []string{"a.example.test"}, nil, nil); err == nil {
		t.Fatal("expected context canceled error")
	}
}
