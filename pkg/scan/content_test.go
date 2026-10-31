package scan

import (
	"context"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
)

func TestExtractHosts(t *testing.T) {
	tests := []struct {
		name    string
		body    string
		root    string
		exclude []string
		want    []string
	}{
		{
			name: "html links and bare subdomains",
			body: `<html><body>
				<a href="https://v3.example.gov/portal">Portal v3</a>
				<script src="//STATIC.example.gov/app.js"></script>
				<p>Contact maps.internal.example.gov. Visit example.gov for info.</p>
			</body></html>`,
			root: "example.gov",
			want: []string{"maps.internal.example.gov", "static.example.gov", "v3.example.gov"},
		},
		{
			name: "escaped json, url-encoded, unicode, and newline escapes",
			body: `{
				"api": "https:\/\/api-v3.example.gov:8443\/v1",
				"sso": "https:\u002f\u002fsso.example.gov\u002flogin",
				"redirect": "/auth?next=https%3A%2F%2Fportal.example.gov%2Fhome",
				"doubleEnc": "/go?u=https%253A%252F%252Fdeep.example.gov",
				"list": "one.example.gov\ntwo.example.gov\tthree.example.gov"
			}`,
			root: "example.gov",
			want: []string{
				"api-v3.example.gov",
				"deep.example.gov",
				"one.example.gov",
				"portal.example.gov",
				"sso.example.gov",
				"three.example.gov",
				"two.example.gov",
			},
		},
		{
			name: "rejects out-of-scope suffixes, excluded subdomains, and identifier underscores",
			body: `
				https://sub.example.gov.akamaized.net/bundle.js
				https://v3.example.gov.evil.com/phish
				https://dev.skip.example.gov/test
				const my_var_v9.example.gov = 1;
				https://valid.example.gov/ok
			`,
			root:    "example.gov",
			exclude: []string{"skip.example.gov"},
			want:    []string{"valid.example.gov"},
		},
		{
			name: "fast negative exit when root absent",
			body: `<html><body><a href="https://other.org">No match</a></body></html>`,
			root: "example.gov",
			want: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, snippets := ExtractHosts([]byte(tt.body), tt.root, tt.exclude)
			if !slices.Equal(got, tt.want) {
				t.Fatalf("ExtractHosts() = %v, want %v", got, tt.want)
			}
			for _, h := range got {
				if strings.TrimSpace(snippets[h]) == "" {
					t.Errorf("expected non-empty provenance snippet for %s", h)
				}
			}
		})
	}
}

func TestExtractSameHostAssets(t *testing.T) {
	html := `<html><head>
		<script src="/static/js/main.1a2b.js"></script>
		<script src="assets/config.json?v=4#ignore"></script>
		<script src="https://v2.example.gov/runtime.js"></script>
		<script src="https://cdn.thirdparty.com/vendor.js"></script>
		<script src="https://other.example.gov/cross-sub.js"></script>
		<link rel="stylesheet" href="/static/app.css">
		<script src="/static/js/extra.js"></script>
	</head></html>`

	got := ExtractSameHostAssets([]byte(html), "https://v2.example.gov/app/index.html", 3)
	want := []string{
		"https://v2.example.gov/static/js/main.1a2b.js",
		"https://v2.example.gov/app/assets/config.json?v=4",
		"https://v2.example.gov/runtime.js",
	}
	if !slices.Equal(got, want) {
		t.Fatalf("ExtractSameHostAssets() = %v, want %v", got, want)
	}
}

func TestFetchAssetHosts(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Host == "v2.example.test" && r.URL.Path == "/static/config.json" {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"apiBase":"https://hidden-api.example.test/v2","self":"https://v2.example.test"}`))
			return
		}
		http.NotFound(w, r)
	}))
	defer ts.Close()

	addr := ts.Listener.Addr().String()
	refs := FetchAssetHosts(
		context.Background(),
		[]string{"http://v2.example.test/static/config.json"},
		ProbeOpts{
			Threads:     2,
			Rate:        50,
			Timeout:     3,
			ExtractRoot: "example.test",
			TargetAddr:  addr,
		},
	)

	got := refs["v2.example.test"]["hidden-api.example.test"]
	if got == "" {
		t.Fatalf("expected hidden-api.example.test to be extracted from asset, got %v", refs)
	}
	if !strings.HasPrefix(got, "asset:/static/config.json:") {
		t.Errorf("unexpected provenance format: %q", got)
	}
	if _, selfFound := refs["v2.example.test"]["v2.example.test"]; selfFound {
		t.Errorf("self-reference should be excluded from asset refs")
	}
}
