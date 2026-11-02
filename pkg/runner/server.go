package runner

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/aktezed/assfin/pkg/report"
	"github.com/aktezed/assfin/pkg/scan"
	"github.com/aktezed/assfin/pkg/store"
	"github.com/aktezed/assfin/pkg/types"
	"github.com/projectdiscovery/gologger"
)

// RunServer starts an HTTP dashboard server serving the HTML report and API on a headless VPS.
func RunServer(ctx context.Context, dbStore *store.Store, listenAddr string) error {
	return runScopedServer(ctx, dbStore, listenAddr, "")
}

func runScopedServer(ctx context.Context, dbStore *store.Store, listenAddr, scopeRoot string) error {
	if dbStore == nil {
		return errors.New("database store cannot be nil")
	}

	addr := normalizeListenAddr(listenAddr)
	scopeRoot = scan.Normalize(scopeRoot)

	mux := http.NewServeMux()

	// Dashboard HTML report
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		if err := report.RenderScopedReport(dbStore, scopeRoot, w); err != nil {
			http.Error(w, fmt.Sprintf("Failed to render report: %v", err), http.StatusInternalServerError)
		}
	})

	// JSON APIs
	mux.HandleFunc("/api/hosts", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		hosts, err := dbStore.QueryHosts(types.Filter{Root: scopeRoot, Depth: -1})
		if err != nil {
			http.Error(w, `{"error":"query failed"}`, http.StatusInternalServerError)
			return
		}
		if hosts == nil {
			hosts = []types.Host{}
		}
		_ = json.NewEncoder(w).Encode(hosts)
	})

	mux.HandleFunc("/api/summary", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		allRoots, err := dbStore.GetScansSummary()
		if err != nil {
			http.Error(w, `{"error":"summary failed"}`, http.StatusInternalServerError)
			return
		}
		roots := allRoots
		if scopeRoot != "" {
			roots = make([]types.RootInfo, 0, 1)
			for _, ri := range allRoots {
				if ri.Root == scopeRoot {
					roots = append(roots, ri)
				}
			}
		}
		_ = json.NewEncoder(w).Encode(roots)
	})

	server := &http.Server{
		Addr:              addr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}

	serverErr := make(chan error, 1)
	go func() {
		ln, err := net.Listen("tcp", addr)
		if err != nil {
			serverErr <- err
			return
		}
		defer ln.Close()

		tcpAddr := ln.Addr().(*net.TCPAddr)
		port := tcpAddr.Port

		gologger.Info().Msgf("assfin headless dashboard listening at http://%s", tcpAddr.String())
		gologger.Info().Msgf("local VPS browser access : http://localhost:%d", port)
		gologger.Info().Msgf("remote SSH port forwarding: ssh -NL %d:localhost:%d user@<vps-ip>", port, port)
		gologger.Info().Msg("press Ctrl+C to stop server")

		if err := server.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			serverErr <- err
		}
	}()

	select {
	case err := <-serverErr:
		return fmt.Errorf("dashboard server failed: %w", err)
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_ = server.Shutdown(shutdownCtx)
		gologger.Info().Msg("dashboard server stopped")
		return nil
	}
}

func resolveServeAddr(serve string, port int) string {
	serve = strings.TrimSpace(serve)
	if serve == "" || serve == "true" {
		if port <= 0 {
			port = 8080
		}
		return fmt.Sprintf("127.0.0.1:%d", port)
	}
	return normalizeListenAddr(serve)
}

func normalizeListenAddr(in string) string {
	in = strings.TrimSpace(in)
	if in == "" {
		return "127.0.0.1:8080"
	}
	if !strings.Contains(in, ":") {
		if _, err := strconv.Atoi(in); err == nil {
			return "127.0.0.1:" + in
		}
	}
	return in
}
