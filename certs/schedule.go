package certs

import (
	"crypto/x509"
	"time"
)

// shortLifetime is the lifetime under which half of it, rather than a third, is kept as the margin, following Let's Encrypt's guidance for short-lived certificates.
const shortLifetime = 10 * 24 * time.Hour

// renewalDeadline is the latest moment to start renewing: when one third of the lifetime remains, or half of it for a certificate valid less than 10 days.
func renewalDeadline(leaf *x509.Certificate) time.Time {
	lifetime := leaf.NotAfter.Sub(leaf.NotBefore)
	if lifetime < shortLifetime {
		return leaf.NotBefore.Add(lifetime / 2)
	}
	return leaf.NotAfter.Add(-lifetime / 3)
}

const (
	firstPause   = 5 * time.Minute
	longestPause = 6 * time.Hour
	// doublings is how many times the first pause doubles before the longest pause takes over: 5 minutes becomes 160 minutes.
	doublings = 5
)

// pauseAfter is how long to wait after the nth consecutive failed order (n >= 1): 5, 10, 20, 40, 80, 160 minutes, then 6 hours.
func pauseAfter(failures int) time.Duration {
	switch {
	case failures < 1:
		return firstPause
	case failures-1 > doublings:
		return longestPause
	default:
		return firstPause << (failures - 1)
	}
}
