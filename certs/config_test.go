package certs

import (
	"strings"
	"testing"
	"time"
)

func TestCheckConfig(t *testing.T) {
	valid := func() Config {
		return Config{DirectoryURL: LetsEncryptStaging, Domain: "Example.COM.", StateDir: t.TempDir(), Records: &memoryRecords{}}
	}

	checked, err := checkConfig(valid())
	if err != nil {
		t.Fatalf("checkConfig of a valid configuration: %v", err)
	}
	if checked.Domain != "example.com" {
		t.Errorf("Domain = %q, want the canonical example.com", checked.Domain)
	}
	if checked.ValidationDelay != DefaultValidationDelay {
		t.Errorf("ValidationDelay = %v, want DefaultValidationDelay", checked.ValidationDelay)
	}
	again, err := checkConfig(checked)
	if err != nil || again.Domain != checked.Domain || again.ValidationDelay != checked.ValidationDelay {
		t.Errorf("checkConfig of its own result = %+v, %v", again, err)
	}
	for _, email := range []string{"", "admin@example.com"} {
		withEmail := valid()
		withEmail.Email = email
		if checked, err := checkConfig(withEmail); err != nil || checked.Email != email {
			t.Errorf("the email %q became %q, %v", email, checked.Email, err)
		}
	}
	custom := valid()
	custom.ValidationDelay = time.Millisecond
	if checked, err := checkConfig(custom); err != nil || checked.ValidationDelay != time.Millisecond {
		t.Errorf("a positive delay became %v, %v", checked.ValidationDelay, err)
	}

	for _, tc := range []struct {
		name   string
		change func(*Config)
		want   string
	}{
		{"invalid domain", func(c *Config) { c.Domain = "a..b" }, "invalid domain"},
		{"empty domain", func(c *Config) { c.Domain = "" }, "invalid domain"},
		{"http directory", func(c *Config) { c.DirectoryURL = "http://ca.example/dir" }, "not an absolute https URL"},
		{"relative directory", func(c *Config) { c.DirectoryURL = "/dir" }, "not an absolute https URL"},
		{"no state directory", func(c *Config) { c.StateDir = "" }, "no state directory"},
		{"no records", func(c *Config) { c.Records = nil }, "no challenge records"},
		{"negative delay", func(c *Config) { c.ValidationDelay = -time.Second }, "negative"},
		{"email that is not an address", func(c *Config) { c.Email = "admin" }, `email "admin" is not a bare address`},
		{"email with a display name", func(c *Config) { c.Email = "Admin <admin@example.com>" }, `email "Admin <admin@example.com>" is not a bare address`},
		{"email in angle brackets", func(c *Config) { c.Email = "<admin@example.com>" }, `email "<admin@example.com>" is not a bare address`},
	} {
		cfg := valid()
		tc.change(&cfg)
		if _, err := checkConfig(cfg); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: err = %v, want one that contains %q", tc.name, err, tc.want)
		}
	}
}
