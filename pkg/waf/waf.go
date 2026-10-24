package waf

import (
	"fmt"
	"strings"
)

// wafSigs are matched against the response httpx already fetched, so detection sends no extra traffic.
var wafSigs = []struct{ needle, name string }{
	{"cf-ray", "Cloudflare"},
	{"__cf_bm", "Cloudflare"},
	{"x-sucuri-id", "Sucuri"},
	{"incap_ses_", "Imperva"},
	{"visid_incap_", "Imperva"},
	{"x-iinfo", "Imperva"},
	{"akamaighost", "Akamai"},
	{"x-akamai", "Akamai"},
	{"x-amz-cf-id", "AWS CloudFront"},
	{"awsalb", "AWS ELB"},
	{"x-azure-ref", "Azure Front Door"},
	{"barra_counter", "Barracuda"},
	{"bigipserver", "F5 BIG-IP"},
	{"ts01", "F5 BIG-IP"},
	{"fortiwafsid", "FortiWeb"},
	{"x-datadome", "DataDome"},
}

// DetectWAF trusts cdncheck's IP-range verdict first, then falls back to header/cookie signatures.
func DetectWAF(cdnType, cdnName string, headers map[string]any) string {
	if cdnType == "waf" && cdnName != "" {
		return cdnName
	}
	var b strings.Builder
	for k, v := range headers {
		fmt.Fprintf(&b, "%s: %v\n", k, v)
	}
	blob := strings.ToLower(b.String())
	for _, s := range wafSigs {
		if strings.Contains(blob, s.needle) {
			return s.name
		}
	}
	return ""
}
