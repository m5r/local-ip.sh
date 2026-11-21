package xip

import (
	"fmt"
	"maps"
	"slices"

	"github.com/miekg/dns"
)

const challengeLabel = "_acme-challenge."

// challengeTTL is 0 because both certificates are validated at this one name with different values minutes or seconds apart, and a validating resolver that caches the first answer rejects the second order (observed with TTL 300 on 2026-11-21).
const challengeTTL = 0

// AddChallenge publishes value in the TXT record set of name, next to the values already there.
// name must be the zone's challenge name, _acme-challenge.<domain>, with or without a trailing dot, in any case.
// It refuses a value that would make the TXT answer larger than a response may be, and leaves the published values as they were.
func (xip *Xip) AddChallenge(name, value string) error {
	if err := xip.checkChallengeName(name); err != nil {
		return err
	}
	// The size is measured under the write lock, so two calls cannot both pass the check and overflow the answer together.
	xip.challengeMu.Lock()
	defer xip.challengeMu.Unlock()
	if _, published := xip.challengeValues[value]; published {
		return nil
	}
	values := append(slices.Collect(maps.Keys(xip.challengeValues)), value)
	slices.Sort(values)
	size, err := answerSize(xip.challengeName, challengeRecords(xip.challengeName, values))
	if err != nil {
		return fmt.Errorf("xip: building the TXT answer at %s: %w", xip.challengeName, err)
	}
	if size > maxResponseSize {
		return fmt.Errorf("xip: publishing this value at %s would make the TXT answer %d octets, more than the limit of %d octets for a UDP response", xip.challengeName, size, maxResponseSize)
	}
	xip.challengeValues[value] = struct{}{}
	return nil
}

// RemoveChallenge withdraws value from the TXT record set of name. Removing a value that is not published is not an error.
func (xip *Xip) RemoveChallenge(name, value string) error {
	if err := xip.checkChallengeName(name); err != nil {
		return err
	}
	xip.challengeMu.Lock()
	defer xip.challengeMu.Unlock()
	delete(xip.challengeValues, value)
	return nil
}

func (xip *Xip) checkChallengeName(name string) error {
	if dns.CanonicalName(name) != xip.challengeName {
		return fmt.Errorf("xip: %q is not the challenge name of this zone (%s)", name, xip.challengeName)
	}
	return nil
}

// handleChallenge answers every query type at the challenge name. The name always exists, so it never gets NXDOMAIN, which a resolver could hold against the name whatever the type.
// Every record of the reply has TTL 0, the SOA record of a negative answer included.
func (xip *Xip) handleChallenge(question dns.Question, message *dns.Msg) {
	xip.challengeMu.RLock()
	var values []string
	if question.Qtype == dns.TypeTXT {
		values = slices.Sorted(maps.Keys(xip.challengeValues))
	}
	published := len(xip.challengeValues) > 0
	xip.challengeMu.RUnlock()

	switch {
	case len(values) > 0:
		message.Answer = challengeRecords(question.Name, values)
	case question.Qtype == dns.TypeANY && published:
		message.Answer = []dns.RR{anyAnswer(question.Name, challengeTTL)}
	default:
		// A resolver may keep an empty answer for the smaller of the SOA's TTL and its minimum field, and Let's Encrypt's resolvers turn an empty answer without SOA into SERVFAIL.
		message.Ns = xip.zone.negativeAuthority(challengeTTL)
	}
}

// challengeRecords builds the TXT record set of the published values, owned by owner.
func challengeRecords(owner string, values []string) []dns.RR {
	records := make([]dns.RR, len(values))
	for i, value := range values {
		records[i] = &dns.TXT{Hdr: header(owner, dns.TypeTXT, challengeTTL), Txt: chunkBy(value, 255)}
	}
	return records
}
