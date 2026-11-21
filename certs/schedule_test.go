package certs

import (
	"crypto/x509"
	"testing"
	"time"
)

func TestRenewalDeadline(t *testing.T) {
	const day = 24 * time.Hour
	start := time.Date(2026, 11, 21, 12, 0, 0, 0, time.UTC)
	for _, tc := range []struct {
		name     string
		lifetime time.Duration
		want     time.Duration
	}{
		{"90 days", 90 * day, 60 * day},
		{"64 days", 64 * day, 64 * day * 2 / 3},
		{"exactly 10 days follows the one-third rule", 10 * day, 10*day - 10*day/3},
		{"160 hours", 160 * time.Hour, 80 * time.Hour},
		{"15 seconds", 15 * time.Second, 7500 * time.Millisecond},
	} {
		leaf := &x509.Certificate{NotBefore: start, NotAfter: start.Add(tc.lifetime)}
		if got := renewalDeadline(leaf); !got.Equal(start.Add(tc.want)) {
			t.Errorf("%s: renewalDeadline = %v after the start, want %v", tc.name, got.Sub(start), tc.want)
		}
	}
}

func TestPauseAfter(t *testing.T) {
	want := []time.Duration{
		5 * time.Minute,
		10 * time.Minute,
		20 * time.Minute,
		40 * time.Minute,
		80 * time.Minute,
		160 * time.Minute,
		6 * time.Hour,
		6 * time.Hour,
		6 * time.Hour,
		6 * time.Hour,
	}
	for i, w := range want {
		if got := pauseAfter(i + 1); got != w {
			t.Errorf("pauseAfter(%d) = %v, want %v", i+1, got, w)
		}
	}
	for _, failures := range []int{11, 64, 65, 1000, int(^uint(0) >> 1)} {
		if got := pauseAfter(failures); got <= 0 || got > 6*time.Hour {
			t.Errorf("pauseAfter(%d) = %v, want at most 6 hours", failures, got)
		}
	}
}
