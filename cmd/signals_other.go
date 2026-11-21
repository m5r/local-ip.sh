//go:build !unix

package cmd

import (
	"context"

	"github.com/rs/zerolog"
)

// onRenewSignal does nothing on systems without SIGUSR1.
func onRenewSignal(ctx context.Context, logger zerolog.Logger, renew func()) {}
