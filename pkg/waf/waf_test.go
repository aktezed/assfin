package waf

import "testing"

func TestDetectWAF(t *testing.T) {
	tests := []struct {
		name, cdnType, cdnName string
		headers                map[string]any
		want                   string
	}{
		{"cdncheck wins", "waf", "cloudflare", map[string]any{"x_sucuri_id": "1"}, "cloudflare"},
		{"cdn type not waf ignored", "cdn", "fastly", nil, ""},
		{"cf-ray header", "", "", map[string]any{"cf-ray": "abc"}, "Cloudflare"},
		{"imperva cookie", "", "", map[string]any{"set_cookie": "incap_ses_123=x"}, "Imperva"},
		{"case insensitive", "", "", map[string]any{"Server": "AkamaiGHost"}, "Akamai"},
		{"nothing", "", "", map[string]any{"server": "nginx"}, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := DetectWAF(tt.cdnType, tt.cdnName, tt.headers); got != tt.want {
				t.Errorf("got %q, want %q", got, tt.want)
			}
		})
	}
}
