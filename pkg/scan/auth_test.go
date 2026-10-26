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
