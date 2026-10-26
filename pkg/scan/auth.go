package scan

import (
	"context"
	"crypto/tls"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/aktezed/assfin/pkg/types"
)

var (
	registerPaths = []string{
		"/register",
		"/signup",
		"/sign-up",
		"/join",
		"/register.php",
		"/signup.php",
		"/create-account",
	}

	loginPaths = []string{
		"/login",
		"/signin",
		"/sign-in",
		"/login.php",
		"/signin.php",
		"/auth/login",
		"/admin",
	}

	registerRegex = regexp.MustCompile(`(?i)\b(register|sign\s*up|create\s+account|join\s+now|registration)\b`)
	loginRegex    = regexp.MustCompile(`(?i)\b(login|sign\s*in|log\s*in|authenticate|portal)\b`)
	passwordRegex = regexp.MustCompile(`(?i)<input[^>]+type=["']?password["']?`)
	formRegex     = regexp.MustCompile(`(?i)<form[^>]*>`)
	linkRegex     = regexp.MustCompile(`(?i)<a[^>]+href=["']([^"']+)["'][^>]*>`)
	actionRegex   = regexp.MustCompile(`(?i)action=["']([^"']+)["']`)
)

// AuthClassifier handles asset classification into register, login_only, or landing.
type AuthClassifier struct {
	client *http.Client
}

// NewAuthClassifier creates a configured AuthClassifier.
func NewAuthClassifier(timeout time.Duration) *AuthClassifier {
	transport := &http.Transport{
		TLSClientConfig:     &tls.Config{InsecureSkipVerify: true}, // nolint:gosec // asset recon requires testing self-signed hosts
		DisableKeepAlives:   false,
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 10,
		IdleConnTimeout:     30 * time.Second,
	}

	return &AuthClassifier{
		client: &http.Client{
			Transport: transport,
			Timeout:   timeout,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				if len(via) >= 5 {
					return http.ErrUseLastResponse
				}
				return nil
			},
		},
	}
}

// NewAuthClassifierWithClient creates an AuthClassifier with a custom http.Client (e.g. for testing).
func NewAuthClassifierWithClient(client *http.Client) *AuthClassifier {
	if client == nil {
		return NewAuthClassifier(5 * time.Second)
	}
	return &AuthClassifier{client: client}
}

// Classify determines whether a target asset allows registration, is login-only, or is a landing page.
func (c *AuthClassifier) Classify(ctx context.Context, rawURL string) (authType string, authURL string) {
	if rawURL == "" {
		return "", ""
	}

	parsed, err := url.Parse(rawURL)
	if err != nil {
		return "landing", rawURL
	}
	baseURL := parsed.Scheme + "://" + parsed.Host

	// Step 1: Base page inspection
	baseResp, baseBody, err := c.fetch(ctx, rawURL)
	if err != nil {
		// fallback to unknown if connection failed
		return "unknown", rawURL
	}

	hasRegLink, regLink := extractLink(baseBody, baseURL, registerRegex)
	hasLoginLink, loginLink := extractLink(baseBody, baseURL, loginRegex)
	hasPassword := passwordRegex.MatchString(baseBody)
	hasForm := formRegex.MatchString(baseBody)

	if hasRegLink {
		return "register", regLink
	}

	// Base page is an open registration page itself
	if hasPassword && registerRegex.MatchString(baseBody) {
		return "register", rawURL
	}

	// Base page is a login-only page
	if hasPassword && (loginRegex.MatchString(baseBody) || hasForm) {
		return "login_only", rawURL
	}

	// Step 2: Wildcard / Soft-404 baseline check
	// Send a request to an absurd path to detect catch-all 200 SPAs
	isWildcard, wildcardLen := c.checkWildcard(ctx, baseURL)

	// Step 3: Check candidate registration endpoints
	for _, path := range registerPaths {
		candidateURL := baseURL + path
		resp, body, err := c.fetch(ctx, candidateURL)
		if err != nil || resp.StatusCode < 200 || resp.StatusCode >= 400 {
			continue
		}

		// Avoid wildcard SPA false positives
		if isWildcard && abs(len(body)-wildcardLen) < 64 && !passwordRegex.MatchString(body) {
			continue
		}

		if resp.StatusCode == 200 || (resp.StatusCode >= 300 && resp.StatusCode < 400) {
			if passwordRegex.MatchString(body) || registerRegex.MatchString(body) || strings.Contains(resp.Request.URL.Path, "register") || strings.Contains(resp.Request.URL.Path, "signup") {
				targetURL := candidateURL
				if resp.Request != nil && resp.Request.URL != nil {
					targetURL = resp.Request.URL.String()
				}
				return "register", targetURL
			}
		}
	}

	// If root linked to a login page
	if hasLoginLink {
		return "login_only", loginLink
	}

	// Step 4: Check candidate login endpoints
	for _, path := range loginPaths {
		candidateURL := baseURL + path
		resp, body, err := c.fetch(ctx, candidateURL)
		if err != nil || resp.StatusCode < 200 || resp.StatusCode >= 400 {
			continue
		}

		if isWildcard && abs(len(body)-wildcardLen) < 64 && !passwordRegex.MatchString(body) {
			continue
		}

		if passwordRegex.MatchString(body) || loginRegex.MatchString(body) || strings.Contains(resp.Request.URL.Path, "login") {
			targetURL := candidateURL
			if resp.Request != nil && resp.Request.URL != nil {
				targetURL = resp.Request.URL.String()
			}
			return "login_only", targetURL
		}
	}

	// If base response was valid 200/30x with HTML/content, it's a public landing page
	if baseResp != nil && baseResp.StatusCode < 400 {
		return "landing", rawURL
	}

	return "unknown", rawURL
}

func (c *AuthClassifier) fetch(ctx context.Context, target string) (*http.Response, string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return nil, "", err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; assfin/1.0)")
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, "", err
	}
	defer resp.Body.Close()

	bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 128*1024))
	return resp, string(bodyBytes), nil
}

func (c *AuthClassifier) checkWildcard(ctx context.Context, baseURL string) (bool, int) {
	randomPath := "/assfin_chk_404_rand_" + time.Now().Format("150405")
	resp, body, err := c.fetch(ctx, baseURL+randomPath)
	if err != nil || resp == nil {
		return false, 0
	}
	if resp.StatusCode == http.StatusOK {
		return true, len(body)
	}
	return false, 0
}

func extractLink(html, baseURL string, targetPattern *regexp.Regexp) (bool, string) {
	matches := linkRegex.FindAllStringSubmatch(html, -1)
	for _, m := range matches {
		if len(m) > 1 {
			href := strings.TrimSpace(m[1])
			if targetPattern.MatchString(href) {
				return true, resolveURL(baseURL, href)
			}
		}
	}

	formMatches := actionRegex.FindAllStringSubmatch(html, -1)
	for _, m := range formMatches {
		if len(m) > 1 {
			action := strings.TrimSpace(m[1])
			if targetPattern.MatchString(action) {
				return true, resolveURL(baseURL, action)
			}
		}
	}

	return false, ""
}

func resolveURL(baseURL, href string) string {
	if strings.HasPrefix(href, "http://") || strings.HasPrefix(href, "https://") {
		return href
	}
	if strings.HasPrefix(href, "//") {
		return "https:" + href
	}
	base, err := url.Parse(baseURL)
	if err != nil {
		return href
	}
	rel, err := url.Parse(href)
	if err != nil {
		return href
	}
	return base.ResolveReference(rel).String()
}

func abs(x int) int {
	if x < 0 {
		return -x
	}
	return x
}

// ClassifyAliveHosts runs concurrent classification on a slice of alive hosts.
func ClassifyAliveHosts(ctx context.Context, hosts []types.Host, threads int, timeoutSec int, onResult func(host string, authType, authURL string)) {
	if len(hosts) == 0 {
		return
	}
	if threads <= 0 {
		threads = 10
	}
	if timeoutSec <= 0 {
		timeoutSec = 4
	}

	classifier := NewAuthClassifier(time.Duration(timeoutSec) * time.Second)

	jobs := make(chan types.Host, len(hosts))
	for _, h := range hosts {
		if h.Alive && h.URL != "" {
			jobs <- h
		}
	}
	close(jobs)

	var wg sync.WaitGroup
	for i := 0; i < threads; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for h := range jobs {
				select {
				case <-ctx.Done():
					return
				default:
					aType, aURL := classifier.Classify(ctx, h.URL)
					if onResult != nil {
						onResult(h.Host, aType, aURL)
					}
				}
			}
		}()
	}
	wg.Wait()
}
