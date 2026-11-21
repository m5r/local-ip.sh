//go:build unix

package cmd

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"github.com/rs/zerolog"
)

// onRenewSignal calls renew each time the process receives SIGUSR1, until ctx is cancelled.
func onRenewSignal(ctx context.Context, logger zerolog.Logger, renew func()) {
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGUSR1)
	go func() {
		defer signal.Stop(signals)
		for {
			select {
			case <-ctx.Done():
				return
			case <-signals:
				// A select whose two cases are ready picks either, so cancellation is looked at again to make it win over a late signal.
				if ctx.Err() != nil {
					return
				}
				logger.Info().Msg("Certificate renewal requested by SIGUSR1")
				renew()
			}
		}
	}()
}
