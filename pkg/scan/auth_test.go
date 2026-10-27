package scan

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

func mockResponse(status int, body string, req *http.Request) *http.Response {
	return &http.Response{
		StatusCode: status,
		Status:     http.StatusText(status),
		Body:       io.NopCloser(bytes.NewBufferString(body)),
		Header:     make(http.Header),
		Request:    req,
	}
}

func TestAuthClassifier_RegisterPage(t *testing.T) {
	client := &http.Client{
		Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			switch req.URL.Path {
			case "":
				return mockResponse(http.StatusOK, `<html><body><h1>Welcome</h1><a href="/register">Sign Up Here</a></body></html>`, req), nil
			case "/register":
				return mockResponse(http.StatusOK, `<html><body><form action="/register"><input type="password"><button>Create Account</button></form></body></html>`, req), nil
			default:
				return mockResponse(http.StatusNotFound, "not found", req), nil
			}
		}),
	}

	classifier := NewAuthClassifierWithClient(client)
	authType, authURL := classifier.Classify(context.Background(), "https://app.example.com")

	if authType != "register" {
		t.Errorf("expected authType 'register', got %q", authType)
	}
	expectedURL := "https://app.example.com/register"
	if authURL != expectedURL {
		t.Errorf("expected authURL %q, got %q", expectedURL, authURL)
	}
}

func TestAuthClassifier_LoginOnlyPage(t *testing.T) {
	client := &http.Client{
		Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			switch req.URL.Path {
			case "":
				return mockResponse(http.StatusOK, `<html><body><h1>Corporate Portal</h1><a href="/login">Employee Sign In</a></body></html>`, req), nil
			case "/login":
				return mockResponse(http.StatusOK, `<html><body><form action="/login"><input type="password"><button>Log In</button></form></body></html>`, req), nil
			default:
				return mockResponse(http.StatusNotFound, "not found", req), nil
			}
		}),
	}

	classifier := NewAuthClassifierWithClient(client)
	authType, authURL := classifier.Classify(context.Background(), "https://sso.example.com")

	if authType != "login_only" {
		t.Errorf("expected authType 'login_only', got %q", authType)
	}
	expectedURL := "https://sso.example.com/login"
	if authURL != expectedURL {
		t.Errorf("expected authURL %q, got %q", expectedURL, authURL)
	}
}

func TestAuthClassifier_LandingPage(t *testing.T) {
	client := &http.Client{
		Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			if req.URL.Path == "" {
				return mockResponse(http.StatusOK, `<html><body><h1>Welcome to Blog</h1><p>Articles.</p></body></html>`, req), nil
			}
			return mockResponse(http.StatusNotFound, "not found", req), nil
		}),
	}

	classifier := NewAuthClassifierWithClient(client)
	authType, _ := classifier.Classify(context.Background(), "https://blog.example.com")

	if authType != "landing" {
		t.Errorf("expected authType 'landing', got %q", authType)
	}
}

func TestAuthClassifier_WildcardSPA(t *testing.T) {
	client := &http.Client{
		Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			// Catch-all SPA returning identical shell
			return mockResponse(http.StatusOK, `<!doctype html><html><head><title>App</title></head><body><div id="root"></div></body></html>`, req), nil
		}),
	}

	classifier := NewAuthClassifierWithClient(client)
	authType, _ := classifier.Classify(context.Background(), "https://spa.example.com")

	if authType != "landing" {
		t.Errorf("expected authType 'landing' for wildcard SPA without auth, got %q", authType)
	}
}

func TestAuthClassifier_DirectRegisterEndpoint(t *testing.T) {
	// Base page does NOT link to register, but /signup endpoint exists and has a registration form
	client := &http.Client{
		Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			switch req.URL.Path {
			case "":
				return mockResponse(http.StatusOK, `<html><body><h1>Company</h1></body></html>`, req), nil
			case "/signup":
				return mockResponse(http.StatusOK, `<html><body><form><input type="email"><input type="password"><button>Register</button></form></body></html>`, req), nil
			default:
				if strings.Contains(req.URL.Path, "assfin_chk_404") {
					return mockResponse(http.StatusNotFound, "not found", req), nil
				}
				return mockResponse(http.StatusNotFound, "not found", req), nil
			}
		}),
	}

	classifier := NewAuthClassifierWithClient(client)
	authType, authURL := classifier.Classify(context.Background(), "https://hidden.example.com")

	if authType != "register" {
		t.Errorf("expected 'register', got %q", authType)
	}
	expectedURL := "https://hidden.example.com/signup"
	if authURL != expectedURL {
		t.Errorf("expected %q, got %q", expectedURL, authURL)
	}
}

func TestAuthClassifier_NextJSDaftarLink(t *testing.T) {
	// Simulating Next.js React Server Component layout with Indonesian Daftar button and /auth/sign-up
	client := &http.Client{
		Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			switch req.URL.Path {
			case "":
				return mockResponse(http.StatusOK, `<!DOCTYPE html><html lang="id"><head><title>Portal</title></head><body><header><a href="/auth/login"><button>Masuk</button></a><a class="hidden md:block" href="/auth/sign-up"><button>Daftar</button></a></header></body></html>`, req), nil
			case "/auth/sign-up":
				return mockResponse(http.StatusOK, `<!DOCTYPE html><html><body><form><input type="password"><button>Daftar Akun</button></form></body></html>`, req), nil
			default:
				return mockResponse(http.StatusNotFound, "not found", req), nil
			}
		}),
	}

	classifier := NewAuthClassifierWithClient(client)
	authType, authURL := classifier.Classify(context.Background(), "https://balaiyanpus.jogjaprov.go.id")

	if authType != "register" {
		t.Errorf("expected 'register', got %q", authType)
	}
	expectedURL := "https://balaiyanpus.jogjaprov.go.id/auth/sign-up"
	if authURL != expectedURL {
		t.Errorf("expected %q, got %q", expectedURL, authURL)
	}
}

func TestAuthClassifier_DaftarArtikel_NotRegister(t *testing.T) {
	// Base page has Indonesian catalog/listing links ("Daftar Artikel", "Daftar Harga").
	// Must NOT be classified as register!
	client := &http.Client{
		Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			switch req.URL.Path {
			case "":
				return mockResponse(http.StatusOK, `<html><body><nav><a href="/daftar-artikel">Daftar Artikel</a><a href="/daftar-harga">Daftar Harga</a></nav><main><p>Selamat datang di portal informasi</p></main></body></html>`, req), nil
			case "/daftar-artikel":
				return mockResponse(http.StatusOK, `<html><body><h1>Daftar Artikel</h1><ul><li>Artikel 1</li></ul></body></html>`, req), nil
			case "/daftar-harga":
				return mockResponse(http.StatusOK, `<html><body><h1>Daftar Harga</h1><p>Rp 100.000</p></body></html>`, req), nil
			default:
				return mockResponse(http.StatusNotFound, "not found", req), nil
			}
		}),
	}

	classifier := NewAuthClassifierWithClient(client)
	authType, _ := classifier.Classify(context.Background(), "https://news.example.com")

	if authType != "landing" {
		t.Errorf("expected 'landing' for site with daftar-artikel, got %q", authType)
	}
}

func TestAuthClassifier_DaftarPhp_404_NotRegister(t *testing.T) {
	// Base page contains dead link <a href="/daftar.php">Daftar</a>, but /daftar.php returns 404!
	// Must NOT be classified as register!
	client := &http.Client{
		Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			switch req.URL.Path {
			case "":
				return mockResponse(http.StatusOK, `<html><body><h1>Old Company</h1><a href="/daftar.php">Daftar</a></body></html>`, req), nil
			default:
				// /daftar.php returns 404 Not Found!
				return mockResponse(http.StatusNotFound, "404 page not found", req), nil
			}
		}),
	}

	classifier := NewAuthClassifierWithClient(client)
	authType, _ := classifier.Classify(context.Background(), "https://deadlink.example.com")

	if authType != "landing" {
		t.Errorf("expected 'landing' when register link returns 404, got %q", authType)
	}
}

func TestAuthClassifier_DaftarPhp_200_IsRegister(t *testing.T) {
	// Base page contains link <a href="/daftar.php">Daftar</a>, and /daftar.php is alive and returns 200 with form!
	client := &http.Client{
		Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			switch req.URL.Path {
			case "":
				return mockResponse(http.StatusOK, `<html><body><h1>Gov Portal</h1><a href="/daftar.php">Daftar</a></body></html>`, req), nil
			case "/daftar.php":
				return mockResponse(http.StatusOK, `<html><body><h1>Pendaftaran Akun Baru</h1><form><input type="password"><button>Submit</button></form></body></html>`, req), nil
			default:
				return mockResponse(http.StatusNotFound, "not found", req), nil
			}
		}),
	}

	classifier := NewAuthClassifierWithClient(client)
	authType, authURL := classifier.Classify(context.Background(), "https://gov.example.com")

	if authType != "register" {
		t.Errorf("expected 'register', got %q", authType)
	}
	expectedURL := "https://gov.example.com/daftar.php"
	if authURL != expectedURL {
		t.Errorf("expected %q, got %q", expectedURL, authURL)
	}
}

func TestAuthClassifier_WordPress_RegisterDisabled(t *testing.T) {
	// WordPress site where registration is disabled (/wp-login.php?action=register returns registration disabled message).
	client := &http.Client{
		Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			if req.URL.Path == "" {
				return mockResponse(http.StatusOK, `<html><body><h1>Blog</h1><a href="/wp-login.php">Log In</a></body></html>`, req), nil
			}
			if req.URL.Path == "/wp-login.php" {
				if strings.Contains(req.URL.RawQuery, "action=register") {
					return mockResponse(http.StatusOK, `<html><body><div id="login_error">User registration is currently not allowed.</div></body></html>`, req), nil
				}
				return mockResponse(http.StatusOK, `<html><body><form id="loginform"><input type="password"></form></body></html>`, req), nil
			}
			return mockResponse(http.StatusNotFound, "not found", req), nil
		}),
	}

	classifier := NewAuthClassifierWithClient(client)
	authType, authURL := classifier.Classify(context.Background(), "https://wp.example.com")

	if authType != "login_only" {
		t.Errorf("expected 'login_only' when WordPress registration is disabled, got %q", authType)
	}
	expectedURL := "https://wp.example.com/wp-login.php"
	if authURL != expectedURL {
		t.Errorf("expected %q, got %q", expectedURL, authURL)
	}
}

func TestAuthClassifier_RegisterInsideLoginPage(t *testing.T) {
	// Root has ONLY a login link (/login.php).
	// But INSIDE /login.php, there is a link to /register.php!
	client := &http.Client{
		Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			switch req.URL.Path {
			case "":
				return mockResponse(http.StatusOK, `<html><body><h1>Welcome</h1><a href="/login.php">Log In</a></body></html>`, req), nil
			case "/login.php":
				return mockResponse(http.StatusOK, `<html><body><form><input type="password"></form><p>No account? <a href="/register.php">Sign Up</a></p></body></html>`, req), nil
			case "/register.php":
				return mockResponse(http.StatusOK, `<html><body><h1>Registration Form</h1><form><input type="password"></form></body></html>`, req), nil
			default:
				return mockResponse(http.StatusNotFound, "not found", req), nil
			}
		}),
	}

	classifier := NewAuthClassifierWithClient(client)
	authType, authURL := classifier.Classify(context.Background(), "https://classic.example.com")

	if authType != "register" {
		t.Errorf("expected 'register', got %q", authType)
	}
	expectedURL := "https://classic.example.com/register.php"
	if authURL != expectedURL {
		t.Errorf("expected %q, got %q", expectedURL, authURL)
	}
}

func TestAuthClassifier_DirectRegisterPhp(t *testing.T) {
	// Root has no link at all. But /register.php is directly reachable.
	client := &http.Client{
		Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			switch req.URL.Path {
			case "":
				return mockResponse(http.StatusOK, `<html><body><h1>Landing Page Only</h1></body></html>`, req), nil
			case "/register.php":
				return mockResponse(http.StatusOK, `<html><body><h1>Daftar Akun Baru</h1><form><input type="password"><button>Daftar</button></form></body></html>`, req), nil
			default:
				return mockResponse(http.StatusNotFound, "not found", req), nil
			}
		}),
	}

	classifier := NewAuthClassifierWithClient(client)
	authType, authURL := classifier.Classify(context.Background(), "https://phpapp.example.com")

	if authType != "register" {
		t.Errorf("expected 'register', got %q", authType)
	}
	expectedURL := "https://phpapp.example.com/register.php"
	if authURL != expectedURL {
		t.Errorf("expected %q, got %q", expectedURL, authURL)
	}
}
