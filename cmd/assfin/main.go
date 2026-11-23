package main

import (
	"context"
	"errors"
	"os"
	"os/signal"
	"syscall"

	"github.com/aktezed/assfin/pkg/runner"
	"github.com/projectdiscovery/gologger"
)

func main() {
	options := runner.ParseOptions()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	go func() {
		<-ctx.Done()
		stop() // Allow a second signal to terminate immediately.
	}()

	r, err := runner.NewRunner(options)
	if err != nil {
		gologger.Fatal().Msgf("Could not create runner: %s\n", err)
	}
	defer r.Close()

	if err := r.Run(ctx); err != nil {
		_ = r.Close()
		var exitErr *runner.ExitError
		if errors.As(err, &exitErr) {
			os.Exit(exitErr.Code)
		}
		gologger.Fatal().Msgf("Execution failed: %s\n", err)
	}
}
