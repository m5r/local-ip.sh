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
func (xip *Xip) AddChallenge(name, value string) error {
	if err := xip.checkChallengeName(name); err != nil {
		return err
	}
	xip.challengeMu.Lock()
	defer xip.challengeMu.Unlock()
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
func (xip *Xip) handleChallenge(question dns.Question, message *dns.Msg) {
	var values []string
	if question.Qtype == dns.TypeTXT {
		xip.challengeMu.RLock()
		values = slices.Sorted(maps.Keys(xip.challengeValues))
		xip.challengeMu.RUnlock()
	}

	if len(values) == 0 {
		// A resolver may keep an empty answer for the smaller of the SOA's TTL and its minimum field, and Let's Encrypt's resolvers turn an empty answer without SOA into SERVFAIL.
		message.Ns = append(message.Ns, xip.soaRecord(xip.domain+".", challengeTTL))
		return
	}

	for _, value := range values {
		message.Answer = append(message.Answer, &dns.TXT{
			Hdr: dns.RR_Header{
				Name:   question.Name,
				Rrtype: dns.TypeTXT,
				Class:  dns.ClassINET,
				Ttl:    challengeTTL,
			},
			Txt: chunkBy(value, 255),
		})
	}
}
