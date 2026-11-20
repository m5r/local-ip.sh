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

	tg, err := loadTarget(configPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("target: app %s, domain %s, nameservers %v, staging CA %t", tg.app, tg.domain, tg.nameServers, tg.stagingCA)

	t.Run("AuthoritativeAnswers", func(t *testing.T) { authoritativeAnswers(t, tg) })
	t.Run("PublicResolvers", func(t *testing.T) { publicResolverAnswers(t, tg) })
	t.Run("Website", func(t *testing.T) { website(t, tg) })
	t.Run("WildcardCertificate", func(t *testing.T) { wildcardCertificate(t, tg) })
}
