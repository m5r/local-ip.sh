package cmd

import (
	"strings"
	"testing"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"local-ip.sh/app"
	"local-ip.sh/certs"
)

// optionVariables are cleared for every test, so that what the shell running the tests exports cannot change their outcome.
var optionVariables = []string{"XIP_STAGING", "XIP_DNS_PORT", "XIP_HTTP_PORT", "XIP_HTTPS_PORT", "FLY_APP_NAME", "FLY_REGION"}

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

func mustConfig(t *testing.T) app.Config {
	t.Helper()
	cfg, err := config()
	if err != nil {
		t.Fatalf("config: %v", err)
	}
	return cfg
}

func TestConfigStaging(t *testing.T) {
	for _, test := range []struct {
		value string
		want  string
	}{
		{value: "", want: certs.LetsEncryptProduction},
		{value: "false", want: certs.LetsEncryptProduction},
		{value: "true", want: certs.LetsEncryptStaging},
		{value: "1", want: certs.LetsEncryptStaging},
	} {
		t.Run("XIP_STAGING="+test.value, func(t *testing.T) {
			setUp(t, map[string]string{"XIP_STAGING": test.value})
			if got := mustConfig(t).DirectoryURL; got != test.want {
				t.Errorf("DirectoryURL is %q, want %q", got, test.want)
			}
		})
	}

	for _, value := range []string{"tru", "yes"} {
		t.Run("XIP_STAGING="+value, func(t *testing.T) {
			setUp(t, map[string]string{"XIP_STAGING": value})
			cfg, err := config()
			if err == nil {
				t.Fatalf("config accepted XIP_STAGING=%s and chose %s", value, cfg.DirectoryURL)
			}
			if !strings.Contains(err.Error(), "XIP_STAGING") || !strings.Contains(err.Error(), "--staging") || !strings.Contains(err.Error(), `"`+value+`"`) {
				t.Errorf("the error %q does not name --staging / XIP_STAGING and quote the value", err)
			}
		})
	}

	t.Run("flag", func(t *testing.T) {
		command := setUp(t, nil)
		if err := command.Flags().Set("staging", "true"); err != nil {
			t.Fatal(err)
		}
		if got := mustConfig(t).DirectoryURL; got != certs.LetsEncryptStaging {
			t.Errorf("DirectoryURL is %q, want %q", got, certs.LetsEncryptStaging)
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
