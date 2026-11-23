package scan

import (
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/aktezed/assfin/pkg/types"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/gologger/levels"
)

func TestPreserveDefaultLoggerLevel(t *testing.T) {
	ctx := context.Background()
	t.Cleanup(func() {
		gologger.DefaultLogger.SetMaxLevel(levels.LevelInfo)
	})

	cases := []struct {
		name         string
		level        levels.Level
		wantInfo     bool
		wantDebug    bool
		wantWarning  bool
		wantVerbose  bool
		wantSilentOn bool
	}{
		{"verbose", levels.LevelVerbose, true, true, true, true, true},
		{"debug", levels.LevelDebug, true, true, true, false, true},
		{"warning", levels.LevelWarning, true, false, true, false, true},
		{"info", levels.LevelInfo, true, false, false, false, true},
		{"error", levels.LevelError, false, false, false, false, true},
		{"silent", levels.LevelSilent, false, false, false, false, true},
		{"fatal", levels.LevelFatal, false, false, false, false, false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			gologger.DefaultLogger.SetMaxLevel(tc.level)
			restore := preserveDefaultLoggerLevel()
			gologger.DefaultLogger.SetMaxLevel(levels.LevelSilent)
			restore()

			if got := gologger.DefaultLogger.Enabled(ctx, slog.LevelInfo); got != tc.wantInfo {
				t.Errorf("Enabled(Info) = %v, want %v", got, tc.wantInfo)
			}
			if got := gologger.DefaultLogger.Enabled(ctx, slog.LevelDebug); got != tc.wantDebug {
				t.Errorf("Enabled(Debug) = %v, want %v", got, tc.wantDebug)
			}
			if got := gologger.DefaultLogger.Enabled(ctx, slog.LevelWarn); got != tc.wantWarning {
				t.Errorf("Enabled(Warn) = %v, want %v", got, tc.wantWarning)
			}
			if got := gologger.DefaultLogger.Enabled(ctx, gologger.LevelVerbose); got != tc.wantVerbose {
				t.Errorf("Enabled(Verbose) = %v, want %v", got, tc.wantVerbose)
			}
			if got := gologger.DefaultLogger.Enabled(ctx, gologger.LevelSilent); got != tc.wantSilentOn {
				t.Errorf("Enabled(Silent) = %v, want %v", got, tc.wantSilentOn)
			}
		})
	}
}

func TestNewSubfinderPreservesLoggerLevel(t *testing.T) {
	ctx := context.Background()
	t.Cleanup(func() {
		gologger.DefaultLogger.SetMaxLevel(levels.LevelInfo)
	})

	gologger.DefaultLogger.SetMaxLevel(levels.LevelInfo)
	if _, err := NewSubfinder(5, 1, ""); err != nil {
		t.Fatalf("NewSubfinder failed: %v", err)
	}
	if !gologger.DefaultLogger.Enabled(ctx, slog.LevelInfo) {
		t.Fatal("NewSubfinder muted LevelInfo on gologger.DefaultLogger")
	}

	gologger.DefaultLogger.SetMaxLevel(levels.LevelSilent)
	if _, err := NewSubfinder(5, 1, ""); err != nil {
		t.Fatalf("NewSubfinder (silent) failed: %v", err)
	}
	if gologger.DefaultLogger.Enabled(ctx, slog.LevelError) {
		t.Fatal("NewSubfinder elevated gologger.DefaultLogger above LevelSilent")
	}
}

func TestProbePreservesLoggerLevel(t *testing.T) {
	ctx := context.Background()
	t.Cleanup(func() {
		gologger.DefaultLogger.SetMaxLevel(levels.LevelInfo)
	})

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	gologger.DefaultLogger.SetMaxLevel(levels.LevelInfo)
	err := Probe(ctx, []string{"app.example.test"}, ProbeOpts{
		Threads:    1,
		Timeout:    2,
		Rate:       20,
		TargetAddr: ts.Listener.Addr().String(),
	}, func(string, types.Probe) {})
	if err != nil {
		t.Fatalf("Probe failed: %v", err)
	}
	if !gologger.DefaultLogger.Enabled(ctx, slog.LevelInfo) {
		t.Fatal("Probe muted LevelInfo on gologger.DefaultLogger")
	}
}
