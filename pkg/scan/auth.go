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
		// Common modern & standard
		"/register",
		"/register/",
		"/signup",
		"/signup/",
		"/sign-up",
		"/sign-up/",
		"/join",
		"/join/",
		"/create-account",
		"/get-started",

		// Sub-path /auth/, /account/, /users/
		"/auth/register",
		"/auth/signup",
		"/auth/sign-up",
		"/auth/create-account",
		"/account/register",
		"/account/signup",
		"/account/create",
		"/user/register",
		"/users/sign_up",
		"/accounts/signup",
		"/accounts/signup/",
		"/accounts/register",
		"/accounts/register/",

		// Classic / PHP / ASP / HTML
		"/register.php",
		"/signup.php",
		"/register.html",
		"/signup.html",
		"/register.aspx",
		"/signup.aspx",
		"/Register.aspx",
		"/Signup.aspx",
		"/Account/Register",
		"/Identity/Account/Register",

		// CMS & Frameworks & LMS & Forums (WordPress, Joomla, Drupal, phpBB, vBulletin, Moodle)
		"/wp-login.php?action=register",
		"/wp-signup.php",
		"/index.php?option=com_users&view=registration",
		"/ucp.php?mode=register",
		"/member.php?action=register",
		"/login/signup.php",

		// Multilingual (Indonesian / Southeast Asian)
		"/daftar",
		"/daftar/",
		"/pendaftaran",
		"/pendaftaran/",
		"/registrasi",
		"/registrasi/",
		"/daftar-akun",
		"/buat-akun",
		"/daftar-online",
		"/pendaftaran-online",
		"/daftar.php",
		"/pendaftaran.php",
		"/registrasi.php",
		"/auth/daftar",
		"/auth/registrasi",
		"/user/daftar",
	}

	loginPaths = []string{
		"/login",
		"/login/",
		"/signin",
		"/signin/",
		"/sign-in",
		"/sign-in/",
		"/login.php",
		"/signin.php",
		"/login.html",
		"/signin.html",
		"/login.aspx",
		"/Login.aspx",
		"/Account/Login",
		"/Identity/Account/Login",
		"/auth/login",
		"/auth/signin",
		"/auth/sign-in",
		"/account/login",
		"/user/login",
		"/users/sign_in",
		"/admin",
		"/admin/login",
		"/wp-login.php",
		"/masuk",
		"/masuk/",
		"/masuk.php",
		"/auth/masuk",
	}

	registerRegex = regexp.MustCompile(`(?i)(register|sign[\s_-]*up|create[\s_-]*account|join[\s_-]*now|registration|daftar[\s_-]*(?:akun|baru|online|member|pengguna|user|sekarang)?|buat[\s_-]*akun|bikin[\s_-]*akun|registrasi|pendaftaran)`)
	loginRegex    = regexp.MustCompile(`(?i)(login|sign[\s_-]*in|log[\s_-]*in|authenticate|portal|masuk)`)
	passwordRegex = regexp.MustCompile(`(?i)<input[^>]+type=["']?password["']?`)
	formRegex     = regexp.MustCompile(`(?i)<form[^>]*>`)
	anchorRegex   = regexp.MustCompile(`(?i)<a[^>]+href=["']([^"']+)["'][^>]*>(.*?)</a>`)
	linkRegex     = regexp.MustCompile(`(?i)<a[^>]+href=["']([^"']+)["'][^>]*>`)
	actionRegex   = regexp.MustCompile(`(?i)action=["']([^"']+)["']`)
	jsonLinkRegex = regexp.MustCompile(`(?i)["'](/[a-zA-Z0-9_\-\/]*(?:register|sign[\s_-]*up|daftar|registrasi|login|sign[\s_-]*in|masuk)[a-zA-Z0-9_\-\/]*)["']`)

	// Negative filter for Indonesian words where 'daftar' means catalog/list, not account registration.
	nonAuthDaftarRegex = regexp.MustCompile(`(?i)daftar[-_\s]*(artikel|berita|buku|harga|menu|isi|produk|layanan|kegiatan|pengumuman|alumni|pegawai|dosen|mahasiswa|siswa|kontak|pustaka|arsip|wisata|fasilitas|unduhan|download|transaksi|peserta|nilai|tabel|kategori|file|post|item|faq|tanya|outlet|cabang|mitra|inventaris|pemilih|prestasi|guru|sekolah|jadwal|informasi|galeri|video|dokumen|publikasi|lowongan|agenda)`)
	soft404Regex       = regexp.MustCompile(`(?i)(<title>[^<]*(?:404|not found|page not found|halaman tidak ditemukan|tidak ditemukan)[^<]*</title>|<h1>[^<]*(?:404|not found|page not found|halaman tidak ditemukan)[^<]*</h1>)`)
	regDisabledRegex   = regexp.MustCompile(`(?i)(registration\s+is\s+(?:closed|disabled|not\s+allowed)|user\s+registration\s+is\s+currently\s+not\s+allowed|pendaftaran\s+(?:ditutup|tidak\s+diizinkan|dinonaktifkan))`)
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

	// Detect wildcard SPA once
	isWildcard, wildcardLen := c.checkWildcard(ctx, baseURL)

	// Step 1: Base page inspection
	baseResp, baseBody, err := c.fetch(ctx, rawURL)
	if err != nil {
		// fallback to unknown if connection failed
		return "unknown", rawURL
	}

	hasRegLink, regLinkCandidate := extractLink(baseBody, baseURL, registerRegex)
	hasLoginLink, loginLinkCandidate := extractLink(baseBody, baseURL, loginRegex)
	hasPassword := passwordRegex.MatchString(baseBody)
	hasForm := formRegex.MatchString(baseBody)

	// If root directly has a registration link, verify it is alive (not a 404 or dead link)
	if hasRegLink {
		if ok, verifiedReg := c.verifyRegisterEndpoint(ctx, regLinkCandidate, isWildcard, wildcardLen); ok {
			return "register", verifiedReg
		}
	}

	// Base page is an open registration page itself
	if hasPassword && registerRegex.MatchString(baseBody) && !isNonAuthHref(rawURL) {
		return "register", rawURL
	}

	// Step 2: If root links to a login page, inspect the login page itself!
	// Real-world flow: Most sites put "Don't have an account? Register / Daftar" INSIDE the login page.
	var loginLink string
	if hasLoginLink {
		if ok, verifiedLogin, loginBody := c.verifyLoginEndpoint(ctx, loginLinkCandidate, isWildcard, wildcardLen); ok {
			loginLink = verifiedLogin
			if hasReg, regFromLogin := extractLink(loginBody, baseURL, registerRegex); hasReg {
				if regOk, verifiedReg := c.verifyRegisterEndpoint(ctx, regFromLogin, isWildcard, wildcardLen); regOk {
					return "register", verifiedReg
				}
			}
			if passwordRegex.MatchString(loginBody) && registerRegex.MatchString(loginBody) && !regDisabledRegex.MatchString(loginBody) {
				return "register", loginLink
			}
		}
	}

	// Base page is a login page with password field
	if hasPassword && (loginRegex.MatchString(baseBody) || hasForm) {
		if hasReg, regFromLogin := extractLink(baseBody, baseURL, registerRegex); hasReg {
			if regOk, verifiedReg := c.verifyRegisterEndpoint(ctx, regFromLogin, isWildcard, wildcardLen); regOk {
				return "register", verifiedReg
			}
		}
		if loginLink == "" {
			loginLink = rawURL
		}
	}

	// Step 3: Check candidate registration endpoints directly
	// (CMS, frameworks, Indonesian, international)
	for _, path := range registerPaths {
		candidateURL := baseURL + path
		if ok, verifiedReg := c.verifyRegisterEndpoint(ctx, candidateURL, isWildcard, wildcardLen); ok {
			return "register", verifiedReg
		}
	}

	// Step 4: Check candidate login endpoints directly
	// (And inspect if the login page itself contains a live registration link!)
	for _, path := range loginPaths {
		candidateURL := baseURL + path
		if ok, verifiedLogin, loginBody := c.verifyLoginEndpoint(ctx, candidateURL, isWildcard, wildcardLen); ok {
			if hasReg, regFromLogin := extractLink(loginBody, baseURL, registerRegex); hasReg {
				if regOk, verifiedReg := c.verifyRegisterEndpoint(ctx, regFromLogin, isWildcard, wildcardLen); regOk {
					return "register", verifiedReg
				}
			}
			if loginLink == "" {
				loginLink = verifiedLogin
			}
		}
	}

	// If any login portal was detected but no registration link exists anywhere
	if loginLink != "" {
		return "login_only", loginLink
	}

	// If base response was valid 200/30x with HTML/content, it's a public landing page
	if baseResp != nil && baseResp.StatusCode < 400 {
		return "landing", rawURL
	}

	return "unknown", rawURL
}

func (c *AuthClassifier) verifyRegisterEndpoint(ctx context.Context, targetURL string, isWildcard bool, wildcardLen int) (bool, string) {
	if isNonAuthHref(targetURL) {
		return false, ""
	}

	resp, body, err := c.fetch(ctx, targetURL)
	if err != nil || resp == nil {
		return false, ""
	}

	// Must be HTTP 200 OK or 30x redirect
	if resp.StatusCode < 200 || resp.StatusCode >= 400 {
		return false, ""
	}

	// Reject soft-404 pages
	if soft404Regex.MatchString(body) {
		return false, ""
	}

	// Reject if registration is explicitly closed/disabled (e.g. WordPress, Joomla, forums)
	if regDisabledRegex.MatchString(body) {
		return false, ""
	}

	// Reject wildcard SPA match unless there's a password field
	if isWildcard && abs(len(body)-wildcardLen) < 64 && !passwordRegex.MatchString(body) {
		return false, ""
	}

	finalURL := targetURL
	if resp.Request != nil && resp.Request.URL != nil {
		finalURL = resp.Request.URL.String()
	}

	if isNonAuthHref(finalURL) || soft404Regex.MatchString(finalURL) {
		return false, ""
	}

	lowerPath := ""
	if resp.Request != nil && resp.Request.URL != nil {
		lowerPath = strings.ToLower(resp.Request.URL.Path)
	}

	hasPassword := passwordRegex.MatchString(body)
	hasForm := formRegex.MatchString(body)
	hasRegContent := registerRegex.MatchString(body)

	pathHasReg := strings.Contains(lowerPath, "register") ||
		strings.Contains(lowerPath, "signup") ||
		strings.Contains(lowerPath, "sign-up") ||
		strings.Contains(lowerPath, "registrasi") ||
		(strings.Contains(lowerPath, "daftar") && !isNonAuthHref(lowerPath))

	targetLower := strings.ToLower(targetURL)
	targetHasReg := strings.Contains(targetLower, "register") ||
		strings.Contains(targetLower, "signup") ||
		strings.Contains(targetLower, "sign-up") ||
		strings.Contains(targetLower, "registrasi") ||
		(strings.Contains(targetLower, "daftar") && !isNonAuthHref(targetLower))

	if hasPassword || (hasForm && hasRegContent) || pathHasReg || targetHasReg {
		return true, finalURL
	}

	return false, ""
}

func (c *AuthClassifier) verifyLoginEndpoint(ctx context.Context, targetURL string, isWildcard bool, wildcardLen int) (bool, string, string) {
	if isNonAuthHref(targetURL) {
		return false, "", ""
	}

	resp, body, err := c.fetch(ctx, targetURL)
	if err != nil || resp == nil {
		return false, "", ""
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 400 {
		return false, "", ""
	}

	if soft404Regex.MatchString(body) {
		return false, "", ""
	}

	if isWildcard && abs(len(body)-wildcardLen) < 64 && !passwordRegex.MatchString(body) {
		return false, "", ""
	}

	finalURL := targetURL
	if resp.Request != nil && resp.Request.URL != nil {
		finalURL = resp.Request.URL.String()
	}

	hasPassword := passwordRegex.MatchString(body)
	hasLoginContent := loginRegex.MatchString(body)

	lowerPath := ""
	if resp.Request != nil && resp.Request.URL != nil {
		lowerPath = strings.ToLower(resp.Request.URL.Path)
	}
	pathHasLogin := strings.Contains(lowerPath, "login") ||
		strings.Contains(lowerPath, "signin") ||
		strings.Contains(lowerPath, "sign-in") ||
		strings.Contains(lowerPath, "masuk")

	targetLower := strings.ToLower(targetURL)
	targetHasLogin := strings.Contains(targetLower, "login") ||
		strings.Contains(targetLower, "signin") ||
		strings.Contains(targetLower, "sign-in") ||
		strings.Contains(targetLower, "masuk")

	if hasPassword || (formRegex.MatchString(body) && hasLoginContent) || pathHasLogin || targetHasLogin {
		return true, finalURL, body
	}

	return false, "", ""
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

	bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 512*1024))
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
	// 1. Check anchor tags with inner text (e.g. <a href="...">Daftar</button></a>)
	anchorMatches := anchorRegex.FindAllStringSubmatch(html, -1)
	for _, m := range anchorMatches {
		if len(m) > 2 {
			href := strings.TrimSpace(m[1])
			innerText := strings.TrimSpace(m[2])
			if isNonAuthHref(href) || nonAuthDaftarRegex.MatchString(innerText) {
				continue
			}
			if (targetPattern.MatchString(href) || targetPattern.MatchString(innerText)) && isValidAuthLink(href) {
				return true, resolveURL(baseURL, href)
			}
		}
	}

	// 2. Check standalone <a href="..."> tags
	matches := linkRegex.FindAllStringSubmatch(html, -1)
	for _, m := range matches {
		if len(m) > 1 {
			href := strings.TrimSpace(m[1])
			if isNonAuthHref(href) {
				continue
			}
			if targetPattern.MatchString(href) && isValidAuthLink(href) {
				return true, resolveURL(baseURL, href)
			}
		}
	}

	// 3. Check form actions
	formMatches := actionRegex.FindAllStringSubmatch(html, -1)
	for _, m := range formMatches {
		if len(m) > 1 {
			action := strings.TrimSpace(m[1])
			if isNonAuthHref(action) {
				continue
			}
			if targetPattern.MatchString(action) && isValidAuthLink(action) {
				return true, resolveURL(baseURL, action)
			}
		}
	}

	// 4. Check JSON / script router paths (e.g. Next.js router strings, client bundle configs)
	jsonMatches := jsonLinkRegex.FindAllStringSubmatch(html, -1)
	for _, m := range jsonMatches {
		if len(m) > 1 {
			path := strings.TrimSpace(m[1])
			if isNonAuthHref(path) {
				continue
			}
			if targetPattern.MatchString(path) && isValidAuthLink(path) {
				return true, resolveURL(baseURL, path)
			}
		}
	}

	return false, ""
}

func isNonAuthHref(href string) bool {
	if href == "" {
		return false
	}
	lower := strings.ToLower(href)
	if nonAuthDaftarRegex.MatchString(lower) {
		return true
	}
	// If path or query segment has daftar-xxx, check if it's not a known auth suffix
	if strings.Contains(lower, "daftar-") || strings.Contains(lower, "daftar_") {
		validAuthSuffix := regexp.MustCompile(`(?i)daftar[-_](akun|baru|online|member|pengguna|user|sekarang|registrasi)`)
		if !validAuthSuffix.MatchString(lower) {
			return true
		}
	}
	return false
}

func isValidAuthLink(href string) bool {
	if href == "" || href == "#" || strings.HasPrefix(href, "javascript:") || strings.HasPrefix(href, "mailto:") {
		return false
	}
	lower := strings.ToLower(href)
	for _, ext := range []string{".js", ".css", ".png", ".jpg", ".jpeg", ".svg", ".ico", ".woff", ".woff2"} {
		if strings.HasSuffix(lower, ext) {
			return false
		}
	}
	return true
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
