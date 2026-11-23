package cmd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"local-ip.sh/app"
	"local-ip.sh/certs"
)

// optionVariables are cleared for every test, so that what the shell running the tests exports cannot change their outcome.
var optionVariables = []string{"XIP_ACME_DIRECTORY", "XIP_DOMAIN", "XIP_EMAIL", "XIP_STATE_DIR", "XIP_ZONE_FILE", "XIP_DNS_PORT", "XIP_HTTP_PORT", "XIP_HTTPS_PORT", "FLY_APP_NAME", "FLY_REGION"}

// setUp gives the test a fresh viper with the flags bound and the environment loaded, as Run does, and the command whose flags the test may set.
func setUp(t *testing.T, environment map[string]string) *cobra.Command {
	t.Helper()
	viper.Reset()
	t.Cleanup(viper.Reset)
	for _, name := range optionVariables {
		// viper treats an empty variable as unset.
		t.Setenv(name, "")
	}
	for name, value := range environment {
		t.Setenv(name, value)
	}
	command := &cobra.Command{}
	if err := defineFlags(command); err != nil {
		t.Fatalf("defineFlags: %v", err)
	}
	loadEnvironment()
	return command
}

// writeZoneFile writes a zone file for example.com with the records every zone needs and returns its path.
func writeZoneFile(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "example.com.zone")
	content := "@ 3600 SOA ns1 admin 1 900 900 1800 3600\n@ 3600 NS ns1\nns1 3600 A 192.0.2.1\n"
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func mustConfig(t *testing.T) app.Config {
	t.Helper()
	cfg, err := config()
	if err != nil {
		t.Fatalf("config: %v", err)
	}
	return cfg
}

func TestConfigACMEDirectory(t *testing.T) {
	const other = "https://ca.example:14000/dir"

	t.Run("default", func(t *testing.T) {
		setUp(t, nil)
		if got := mustConfig(t).DirectoryURL; got != certs.LetsEncryptProduction {
			t.Errorf("DirectoryURL is %q, want %q", got, certs.LetsEncryptProduction)
		}
	})

	t.Run("environment", func(t *testing.T) {
		setUp(t, map[string]string{"XIP_ACME_DIRECTORY": other})
		if got := mustConfig(t).DirectoryURL; got != other {
			t.Errorf("DirectoryURL is %q, want %q", got, other)
		}
	})

	t.Run("flag", func(t *testing.T) {
		command := setUp(t, nil)
		if err := command.Flags().Set("acme-directory", other); err != nil {
			t.Fatal(err)
		}
		if got := mustConfig(t).DirectoryURL; got != other {
			t.Errorf("DirectoryURL is %q, want %q", got, other)
		}
	})

	// The option is passed on unparsed, so the refusal of a URL that is not HTTPS is the certificate manager's, which app.New reports before it binds any socket.
	t.Run("not https", func(t *testing.T) {
		setUp(t, map[string]string{
			"XIP_ACME_DIRECTORY": "http://ca.example/dir",
			"XIP_DOMAIN":         "example.com",
			"XIP_EMAIL":          "admin@example.com",
			"XIP_ZONE_FILE":      writeZoneFile(t),
			"XIP_STATE_DIR":      t.TempDir(),
			"XIP_DNS_PORT":       "0",
			"XIP_HTTP_PORT":      "0",
			"XIP_HTTPS_PORT":     "0",
		})
		if _, err := app.New(mustConfig(t)); err == nil {
			t.Fatal("app.New accepted an http directory URL")
		} else if !strings.Contains(err.Error(), `directory URL "http://ca.example/dir" is not an absolute https URL`) {
			t.Errorf("the error %q is not the refusal of a directory URL that is not https", err)
		}
	})
}

func TestConfigZoneFile(t *testing.T) {
	t.Run("environment", func(t *testing.T) {
		path := writeZoneFile(t)
		setUp(t, map[string]string{"XIP_ZONE_FILE": path})
		if got := mustConfig(t).ZoneFile; got != path {
			t.Errorf("ZoneFile is %q, want %q", got, path)
		}
	})

	t.Run("flag", func(t *testing.T) {
		path := writeZoneFile(t)
		command := setUp(t, nil)
		if err := command.Flags().Set("zone-file", path); err != nil {
			t.Fatal(err)
		}
		if got := mustConfig(t).ZoneFile; got != path {
			t.Errorf("ZoneFile is %q, want %q", got, path)
		}
	})

	// The option is passed on as it is, so the refusal of a start without a zone file is the DNS server's, which app.New reports before it binds any socket.
	t.Run("missing", func(t *testing.T) {
		setUp(t, map[string]string{
			"XIP_DOMAIN":     "example.com",
			"XIP_STATE_DIR":  t.TempDir(),
			"XIP_DNS_PORT":   "0",
			"XIP_HTTP_PORT":  "0",
			"XIP_HTTPS_PORT": "0",
		})
		if _, err := app.New(mustConfig(t)); err == nil {
			t.Fatal("app.New started without a zone file")
		} else if !strings.Contains(err.Error(), "a zone file is required") {
			t.Errorf("the error %q is not the refusal of a start without a zone file", err)
		}
	})
}

func TestConfigDefaultAddresses(t *testing.T) {
	for _, test := range []struct {
		flyAppName string
		dnsUDP     string
	}{
		{flyAppName: "", dnsUDP: ":53"},
		{flyAppName: "local-ip-staging", dnsUDP: "fly-global-services:53"},
	} {
		t.Run("FLY_APP_NAME="+test.flyAppName, func(t *testing.T) {
			setUp(t, map[string]string{"FLY_APP_NAME": test.flyAppName})
			cfg := mustConfig(t)
			if cfg.DNSUDPAddress != test.dnsUDP || cfg.DNSTCPAddress != ":53" || cfg.HTTPAddress != ":80" || cfg.HTTPSAddress != ":443" {
				t.Errorf("addresses are %q, %q, %q and %q, want %q, \":53\", \":80\" and \":443\"", cfg.DNSUDPAddress, cfg.DNSTCPAddress, cfg.HTTPAddress, cfg.HTTPSAddress, test.dnsUDP)
			}
		})
	}
}

func TestConfigPorts(t *testing.T) {
	t.Run("environment", func(t *testing.T) {
		setUp(t, map[string]string{"XIP_HTTP_PORT": "8080"})
		if got := mustConfig(t).HTTPAddress; got != ":8080" {
			t.Errorf("HTTPAddress is %q, want \":8080\"", got)
		}
	})

	t.Run("flag", func(t *testing.T) {
		command := setUp(t, nil)
		if err := command.Flags().Set("https-port", "8443"); err != nil {
			t.Fatal(err)
		}
		if got := mustConfig(t).HTTPSAddress; got != ":8443" {
			t.Errorf("HTTPSAddress is %q, want \":8443\"", got)
		}
	})

	t.Run("zero", func(t *testing.T) {
		setUp(t, map[string]string{"XIP_DNS_PORT": "0"})
		cfg := mustConfig(t)
		if cfg.DNSUDPAddress != ":0" || cfg.DNSTCPAddress != ":0" {
			t.Errorf("DNS addresses are %q and %q, want \":0\" for both", cfg.DNSUDPAddress, cfg.DNSTCPAddress)
		}
	})

	// A leading zero is decimal and nothing but decimal digits is a port, whether the text comes from the flag or from the environment.
	t.Run("leading zero/environment", func(t *testing.T) {
		setUp(t, map[string]string{"XIP_HTTP_PORT": "010"})
		if got := mustConfig(t).HTTPAddress; got != ":10" {
			t.Errorf("HTTPAddress is %q, want \":10\"", got)
		}
	})
	t.Run("leading zero/flag", func(t *testing.T) {
		command := setUp(t, nil)
		if err := command.Flags().Set("http-port", "010"); err != nil {
			t.Fatal(err)
		}
		if got := mustConfig(t).HTTPAddress; got != ":10" {
			t.Errorf("HTTPAddress is %q, want \":10\"", got)
		}
	})
	for _, value := range []string{"0x50", "0o10", "1e3"} {
		t.Run("XIP_HTTP_PORT="+value, func(t *testing.T) {
			setUp(t, map[string]string{"XIP_HTTP_PORT": value})
			checkPortRefused(t, "XIP_HTTP_PORT", "--http-port", value)
		})
		t.Run("--http-port="+value, func(t *testing.T) {
			command := setUp(t, nil)
			if err := command.Flags().Set("http-port", value); err != nil {
				t.Fatalf("the flag refused %q by itself, so the option has two parsers: %v", value, err)
			}
			checkPortRefused(t, "XIP_HTTP_PORT", "--http-port", value)
		})
	}

	for _, variable := range []struct{ env, flag string }{
		{env: "XIP_DNS_PORT", flag: "--dns-port"},
		{env: "XIP_HTTP_PORT", flag: "--http-port"},
		{env: "XIP_HTTPS_PORT", flag: "--https-port"},
	} {
		for _, value := range []string{"ssh", "abc", "-1", "65536", "80.0"} {
			t.Run(variable.env+"="+value, func(t *testing.T) {
				setUp(t, map[string]string{variable.env: value})
				checkPortRefused(t, variable.env, variable.flag, value)
			})
		}
	}
}

func checkPortRefused(t *testing.T, env, flag, value string) {
	t.Helper()
	cfg, err := config()
	if err == nil {
		t.Fatalf("config accepted %q for %s / %s: addresses %q, %q, %q and %q", value, flag, env, cfg.DNSUDPAddress, cfg.DNSTCPAddress, cfg.HTTPAddress, cfg.HTTPSAddress)
	}
	if !strings.Contains(err.Error(), env) || !strings.Contains(err.Error(), flag) || !strings.Contains(err.Error(), `"`+value+`"`) {
		t.Errorf("the error %q does not name %s / %s and quote the value", err, flag, env)
	}
}

func TestConfigRegion(t *testing.T) {
	for _, region := range []string{"ams", ""} {
		t.Run("FLY_REGION="+region, func(t *testing.T) {
			setUp(t, map[string]string{"FLY_REGION": region})
			if got := mustConfig(t).Region; got != region {
				t.Errorf("Region is %q, want %q", got, region)
			}
		})
	}
}
