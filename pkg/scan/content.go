package scan

import (
	"bytes"
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/aktezed/assfin/pkg/types"
)

const maxContentReadBytes = 1 << 20

var (
	hostTokenRe = regexp.MustCompile(`(?i)[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+`)
	assetRefRe  = regexp.MustCompile(`(?i)(?:src|href)\s*=\s*["']([^"'\s<>]+)["']|["']([^"'\s<>]+\.(?:js|json)(?:[?#][^"'\s<>]*)?)["']`)

	// Same-length replacements preserve exact byte offsets into the raw body for snippet slicing.
	escapeBlanker = strings.NewReplacer(
		`\u002f`, "      ", `\u002F`, "      ",
		`\u003a`, "      ", `\u003A`, "      ",
		`\u0022`, "      ", `\u0027`, "      ",
		`\u003c`, "      ", `\u003C`, "      ",
		`\u003e`, "      ", `\u003E`, "      ",
		`%252f`, "     ", `%252F`, "     ",
		`%253a`, "     ", `%253A`, "     ",
		`\x2f`, "    ", `\x2F`, "    ",
		`\x3a`, "    ", `\x3A`, "    ",
		`\x22`, "    ", `\x27`, "    ",
		`%2f`, "   ", `%2F`, "   ",
		`%3a`, "   ", `%3A`, "   ",
		`%20`, "   ", `%22`, "   ", `%27`, "   ",
		`%3c`, "   ", `%3C`, "   ", `%3e`, "   ", `%3E`, "   ",
		`%0a`, "   ", `%0A`, "   ", `%0d`, "   ", `%0D`, "   ", `%09`, "   ",
		`\n`, "  ", `\r`, "  ", `\t`, "  ", `\/`, "  ",
	)
)

// ExtractHosts returns deduplicated, sorted in-scope hostnames referenced in body,
// along with a short single-line context snippet per host for provenance.
func ExtractHosts(body []byte, root string, exclude []string) ([]string, map[string]string) {
	root = Normalize(root)
	if root == "" || len(body) == 0 || !hasDotRootFold(body, root) {
		return nil, nil
	}

	cleaned := escapeBlanker.Replace(string(body))
	matches := hostTokenRe.FindAllStringIndex(cleaned, -1)
	if len(matches) == 0 {
		return nil, nil
	}

	var hosts []string
	var snippets map[string]string

	for _, idx := range matches {
		start, end := idx[0], idx[1]
		if end-start > 253 {
			continue
		}
		if start > 0 && isInvalidHostBoundary(cleaned[start-1]) {
			continue
		}
		if end < len(cleaned) && isInvalidHostBoundary(cleaned[end]) {
			continue
		}

		h := Normalize(cleaned[start:end])
		if _, dup := snippets[h]; dup {
			continue
		}
		if !InScope(h, root, exclude) {
			continue
		}

		if snippets == nil {
			snippets = make(map[string]string)
		}
		snippets[h] = extractSnippet(body, start, end)
		hosts = append(hosts, h)
	}

	slices.Sort(hosts)
	return hosts, snippets
}

// ExtractSameHostAssets returns up to limit deduplicated HTTP(S) URLs of same-host
// .js and .json assets referenced in an HTML body relative to pageURL.
func ExtractSameHostAssets(body []byte, pageURL string, limit int) []string {
	if limit <= 0 || len(body) == 0 || pageURL == "" {
		return nil
	}
	base, err := url.Parse(pageURL)
	if err != nil || base.Host == "" {
		return nil
	}
	baseHost := Normalize(base.Hostname())
	if baseHost == "" {
		return nil
	}

	matches := assetRefRe.FindAllSubmatch(body, -1)
	if len(matches) == 0 {
		return nil
	}

	seen := make(map[string]bool)
	var out []string
	for _, m := range matches {
		raw := string(m[1])
		if raw == "" {
			raw = string(m[2])
		}
		raw = strings.TrimSpace(raw)
		if raw == "" || strings.HasPrefix(raw, "data:") || strings.HasPrefix(raw, "javascript:") {
			continue
		}

		u, err := base.Parse(raw)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") {
			continue
		}
		if Normalize(u.Hostname()) != baseHost {
			continue
		}
		lowerPath := strings.ToLower(u.Path)
		if !strings.HasSuffix(lowerPath, ".js") && !strings.HasSuffix(lowerPath, ".json") {
			continue
		}

		u.Fragment = ""
		resolved := u.String()
		if seen[resolved] {
			continue
		}
		seen[resolved] = true
		out = append(out, resolved)
		if len(out) >= limit {
			break
		}
	}
	return out
}

// FetchAssetHosts fetches same-host .js/.json asset URLs within the configured rate/thread budget
// and extracts in-scope hostnames mapped by referrerHost -> (discoveredHost -> provenance).
func FetchAssetHosts(ctx context.Context, urls []string, o ProbeOpts) map[string]map[string]string {
	root := Normalize(o.ExtractRoot)
	if len(urls) == 0 || root == "" {
		return nil
	}

	timeout := time.Duration(max(o.Timeout, 5)) * time.Second
	transport := &http.Transport{
		TLSClientConfig:     &tls.Config{InsecureSkipVerify: true}, // nolint:gosec // recon probes self-signed targets
		MaxIdleConns:        64,
		MaxIdleConnsPerHost: 8,
		IdleConnTimeout:     15 * time.Second,
	}
	if o.TargetAddr != "" {
		var dialer net.Dialer
		transport.DialContext = func(dialCtx context.Context, network, _ string) (net.Conn, error) {
			return dialer.DialContext(dialCtx, network, o.TargetAddr)
		}
	}
	client := &http.Client{
		Transport: transport,
		Timeout:   timeout,
	}
	defer transport.CloseIdleConnections()

	workers := min(max(o.Threads, 1), len(urls))
	sem := make(chan struct{}, workers)

	var tick <-chan time.Time
	if o.Rate > 0 {
		interval := max(time.Second/time.Duration(o.Rate), time.Millisecond)
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		tick = ticker.C
	}

	var (
		mu  sync.Mutex
		wg  sync.WaitGroup
		out = make(map[string]map[string]string)
	)

	for _, rawURL := range urls {
		if ctx.Err() != nil {
			break
		}
		if tick != nil {
			select {
			case <-tick:
			case <-ctx.Done():
				break
			}
		}
		select {
		case sem <- struct{}{}:
		case <-ctx.Done():
			break
		}

		wg.Add(1)
		go func(assetURL string) {
			defer func() { <-sem; wg.Done() }()

			parsed, err := url.Parse(assetURL)
			if err != nil {
				return
			}
			referrer := Normalize(parsed.Hostname())
			if referrer == "" {
				return
			}

			req, err := http.NewRequestWithContext(ctx, http.MethodGet, assetURL, nil)
			if err != nil {
				return
			}
			resp, err := client.Do(req)
			if err != nil {
				return
			}
			defer func() { _ = resp.Body.Close() }()

			if resp.StatusCode < 200 || resp.StatusCode >= 400 {
				return
			}
			if !isExtractableContentType(resp.Header.Get("Content-Type")) {
				return
			}

			data, err := io.ReadAll(io.LimitReader(resp.Body, maxContentReadBytes))
			if err != nil || len(data) == 0 {
				return
			}

			hosts, snippets := ExtractHosts(data, root, o.Exclude)
			if len(hosts) == 0 {
				return
			}

			assetPath := parsed.RequestURI()
			mu.Lock()
			defer mu.Unlock()
			for _, h := range hosts {
				if h == referrer {
					continue
				}
				if out[referrer] == nil {
					out[referrer] = make(map[string]string)
				}
				if _, exists := out[referrer][h]; !exists {
					out[referrer][h] = types.ClipRunes("asset:"+assetPath+": "+snippets[h], 140)
				}
			}
		}(rawURL)
	}

	wg.Wait()
	return out
}

func hasDotRootFold(body []byte, root string) bool {
	rootBytes := []byte(root)
	n := len(rootBytes)
	for {
		idx := bytes.IndexByte(body, '.')
		if idx < 0 || idx+1+n > len(body) {
			return false
		}
		if bytes.EqualFold(body[idx+1:idx+1+n], rootBytes) {
			return true
		}
		body = body[idx+1:]
	}
}

func isInvalidHostBoundary(b byte) bool {
	return b == '-' || b == '_'
}

func isExtractableContentType(ct string) bool {
	ct = strings.ToLower(strings.TrimSpace(ct))
	if ct == "" {
		return true
	}
	nonTextPrefixes := []string{
		"image/",
		"video/",
		"audio/",
		"font/",
		"application/octet-stream",
		"application/pdf",
		"application/zip",
		"application/gzip",
		"application/x-gzip",
		"application/x-tar",
		"application/wasm",
	}
	for _, p := range nonTextPrefixes {
		if strings.HasPrefix(ct, p) {
			return false
		}
	}
	return true
}

func extractSnippet(body []byte, start, end int) string {
	lo := max(start-32, 0)
	hi := min(end+32, len(body))
	for lo < start && !utf8.RuneStart(body[lo]) {
		lo++
	}
	for hi > end && hi < len(body) && !utf8.RuneStart(body[hi]) {
		hi++
	}

	var b strings.Builder
	b.Grow(hi - lo)
	prevSpace := false
	for _, r := range string(body[lo:hi]) {
		if r == utf8.RuneError {
			continue
		}
		if r <= ' ' || r == '\u007f' {
			if !prevSpace && b.Len() > 0 {
				b.WriteByte(' ')
				prevSpace = true
			}
			continue
		}
		b.WriteRune(r)
		prevSpace = false
	}
	return types.ClipRunes(strings.TrimSpace(b.String()), 120)
}
