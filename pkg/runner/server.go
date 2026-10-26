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
	"github.com/aktezed/assfin/pkg/store"
	"github.com/aktezed/assfin/pkg/types"
	"github.com/projectdiscovery/gologger"
)

// RunServer starts an HTTP dashboard server serving the HTML report and API on a headless VPS.
func RunServer(ctx context.Context, dbStore *store.Store, listenAddr string) error {
	if dbStore == nil {
		return errors.New("database store cannot be nil")
	}

	addr := normalizeListenAddr(listenAddr)

	mux := http.NewServeMux()

	// Dashboard HTML report
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		if err := report.RenderReport(dbStore, w); err != nil {
			http.Error(w, fmt.Sprintf("Failed to render report: %v", err), http.StatusInternalServerError)
		}
	})

	// JSON APIs
	mux.HandleFunc("/api/hosts", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		hosts, err := dbStore.QueryHosts(types.Filter{Depth: -1})
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
		roots, err := dbStore.GetScansSummary()
		if err != nil {
			http.Error(w, `{"error":"summary failed"}`, http.StatusInternalServerError)
			return
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

		gologger.Info().Msgf("assfin headless dashboard listening at http://0.0.0.0:%d", port)
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

func normalizeListenAddr(in string) string {
	in = strings.TrimSpace(in)
	if in == "" {
		return ":8080"
	}
	if !strings.Contains(in, ":") {
		if _, err := strconv.Atoi(in); err == nil {
			return ":" + in
		}
	}
	return in
}
