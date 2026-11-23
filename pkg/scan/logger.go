package scan

import (
	"context"
	"log/slog"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/gologger/levels"
)

// preserveDefaultLoggerLevel snapshots gologger.DefaultLogger's max level so
// initializing third-party runners (subfinder, httpx) with Silent: true does
// not mute assfin's own progress and summary logs.
func preserveDefaultLoggerLevel() func() {
	ctx := context.Background()
	table := []struct {
		slogLevel slog.Level
		goLevel   levels.Level
	}{
		{gologger.LevelVerbose, levels.LevelVerbose},
		{slog.LevelDebug, levels.LevelDebug},
		{slog.LevelWarn, levels.LevelWarning},
		{slog.LevelInfo, levels.LevelInfo},
		{slog.LevelError, levels.LevelError},
		{gologger.LevelSilent, levels.LevelSilent},
	}

	prev := levels.LevelFatal
	for _, entry := range table {
		if gologger.DefaultLogger.Enabled(ctx, entry.slogLevel) {
			prev = entry.goLevel
			break
		}
	}

	return func() {
		gologger.DefaultLogger.SetMaxLevel(prev)
	}
}
