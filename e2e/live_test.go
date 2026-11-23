package e2e

import (
	"os"
	"strings"
	"testing"
)

const flyConfigEnv = "E2E_FLY_CONFIG"

func TestLive(t *testing.T) {
	configPath, set := os.LookupEnv(flyConfigEnv)
	if !set {
		t.Skipf("%s is not set; set it to the path of a Fly config file to run the live suite", flyConfigEnv)
	}
	configPath = strings.TrimSpace(configPath)
	if configPath == "" {
		t.Fatalf("%s is set but empty; set it to the path of a Fly config file, or unset it to skip the live suite", flyConfigEnv)
	}

	tg, err := loadFlyTarget(configPath)
	if err != nil {
		t.Fatal(err)
	}
	liveSections(t, tg)
}

// liveSections only reads from the target, so that they can run against production.
func liveSections(t *testing.T, tg *target) {
	cuts := make([]string, len(tg.delegations))
	for i, d := range tg.delegations {
		cuts[i] = d.cut
	}
	t.Logf("target: %s, domain %s, name servers at %v, website at %v, publicly delegated %t, delegations %v", tg.name, tg.domain, tg.dnsServers, tg.webAddresses, tg.publiclyDelegated, cuts)

	t.Run("AuthoritativeAnswers", func(t *testing.T) { authoritativeAnswers(t, tg) })
	t.Run("Delegations", func(t *testing.T) { delegationChecks(t, tg) })
	t.Run("PublicResolvers", func(t *testing.T) {
		if reason, skip := publicResolverSkip(tg); skip {
			t.Skip(reason)
		}
		publicResolverAnswers(t, tg)
	})
	t.Run("Website", func(t *testing.T) { website(t, tg) })
	t.Run("WildcardCertificate", func(t *testing.T) { wildcardCertificate(t, tg) })
}

// publicResolverSkip gives the reason to skip the public resolvers for a target they cannot reach: they find a name server only through a delegation on the public internet.
func publicResolverSkip(tg *target) (reason string, skip bool) {
	if tg.publiclyDelegated {
		return "", false
	}
	return tg.name + " is not delegated on the public internet, so public resolvers cannot answer for " + tg.domain, true
}
