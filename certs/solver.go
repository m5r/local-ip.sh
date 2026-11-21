package certs

import (
	"context"
	"time"

	"github.com/mholt/acmez/v3"
	"github.com/mholt/acmez/v3/acme"
)

// solver answers DNS-01 challenges by publishing their values in the zone this program serves.
type solver struct {
	records ChallengeRecords
	delay   time.Duration
}

var (
	_ acmez.Solver = (*solver)(nil)
	_ acmez.Waiter = (*solver)(nil)
)

func (s *solver) Present(_ context.Context, chal acme.Challenge) error {
	return s.records.AddChallenge(chal.DNS01TXTRecordName(), chal.DNS01KeyAuthorization())
}

// Wait holds the validation request back until the value has been published for the validation delay. When the authority is then asked to validate, the value has been in the record set without interruption for longer than a validating resolver keeps anything, so whatever such a resolver still holds was fetched while the value was published and contains it, whatever the name answered before: another order's value, an empty answer, or the activity of a process before a restart.
//
// A cancelled order does not mean the authority has stopped: validations already requested can still arrive, find the value gone and fail that authorization. That costs a failed validation at the authority, and if the authority hands the same authorization to the next order, that order fails with it and the ordinary retry applies.
func (s *solver) Wait(ctx context.Context, _ acme.Challenge) error {
	timer := time.NewTimer(s.delay)
	defer timer.Stop()
	select {
	case <-timer.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// CleanUp ignores its context because the library hands it the order's context, which may already be cancelled, and the value must be withdrawn all the same.
func (s *solver) CleanUp(_ context.Context, chal acme.Challenge) error {
	return s.records.RemoveChallenge(chal.DNS01TXTRecordName(), chal.DNS01KeyAuthorization())
}
