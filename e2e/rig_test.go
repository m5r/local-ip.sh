package e2e

import (
	"bytes"
	"context"
	"crypto/x509"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"net/http"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

const (
	composeFileEnv = "E2E_COMPOSE_FILE"

	// rigProject is the only compose project TestRig runs, because it removes the project with its volumes.
	rigProject = "local-ip-e2e"
	rigServer  = "server"
	rigPebble  = "pebble"

	dockerCommandTimeout = 2 * time.Minute
	// dockerUpTimeout leaves room for pulling Pebble's image and building the server's.
	dockerUpTimeout = 15 * time.Minute

	pebbleWaitLimit    = 30 * time.Second
	pebblePollInterval = time.Second
	// issuanceWaitLimit covers the two orders of a first start, each of which publishes its challenge for 75 seconds before it is validated.
	issuanceWaitLimit    = 5 * time.Minute
	issuancePollInterval = 5 * time.Second
)

// pebbleAPIRootPEM is the root of the certificate Pebble's API serves for the names localhost and pebble. The issuer root Pebble generates at each start is fetched over this API, with this root as its only trust anchor.
//
//go:embed rig/pebble.minica.pem
var pebbleAPIRootPEM []byte

// rig runs docker compose on one compose file.
type rig struct {
	file string
}

// compose runs docker compose with args and returns what it printed on standard output; its standard error goes into the error.
func (r rig) compose(ctx context.Context, timeout time.Duration, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	return runDocker(ctx, append([]string{"compose", "--file", r.file}, args...)...)
}

func runDocker(ctx context.Context, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, "docker", args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("docker %s: %w: %s", strings.Join(args, " "), err, strings.TrimSpace(stderr.String()))
	}
	return stdout.Bytes(), nil
}

// containerState is what tells one run of a container's process from another.
type containerState struct {
	id        string
	startedAt time.Time
	running   bool
}

// serverState inspects the server's container.
func (r rig) serverState(ctx context.Context) (containerState, error) {
	ids, err := r.compose(ctx, dockerCommandTimeout, "ps", "--all", "--quiet", rigServer)
	if err != nil {
		return containerState{}, err
	}
	fields := strings.Fields(string(ids))
	if len(fields) != 1 {
		return containerState{}, fmt.Errorf("compose lists the containers %q for the service %s, want exactly one", fields, rigServer)
	}
	inspectCtx, cancel := context.WithTimeout(ctx, dockerCommandTimeout)
	defer cancel()
	inspected, err := runDocker(inspectCtx, "inspect", fields[0])
	if err != nil {
		return containerState{}, err
	}
	return parseContainerState(inspected)
}

// parseContainerState reads the output of docker inspect for one container.
func parseContainerState(inspected []byte) (containerState, error) {
	var containers []struct {
		ID    string `json:"Id"`
		State struct {
			Running   bool   `json:"Running"`
			StartedAt string `json:"StartedAt"`
		} `json:"State"`
	}
	if err := json.Unmarshal(inspected, &containers); err != nil {
		return containerState{}, fmt.Errorf("parsing docker inspect: %w", err)
	}
	if len(containers) != 1 {
		return containerState{}, fmt.Errorf("docker inspect describes %d containers, want 1", len(containers))
	}
	c := containers[0]
	if c.ID == "" {
		return containerState{}, errors.New("docker inspect gives the container no Id")
	}
	startedAt, err := time.Parse(time.RFC3339Nano, c.State.StartedAt)
	if err != nil {
		return containerState{}, fmt.Errorf("container %s: parsing State.StartedAt: %w", c.ID, err)
	}
	return containerState{id: c.ID, startedAt: startedAt, running: c.State.Running}, nil
}

// checkNotRestarted fails unless after is the same run of the same container as before.
func checkNotRestarted(before, after containerState) error {
	switch {
	case after.id != before.id:
		return fmt.Errorf("the server's container is %s, not %s: it was replaced", after.id, before.id)
	case !after.running:
		return fmt.Errorf("the server's container %s is not running", after.id)
	case !after.startedAt.Equal(before.startedAt):
		return fmt.Errorf("the server's container %s started at %s, not at %s: the process that renewed is not the one that was running", after.id, after.startedAt.Format(time.RFC3339Nano), before.startedAt.Format(time.RFC3339Nano))
	}
	return nil
}

// checkRestartedInPlace fails unless after is a later run of the same container as before.
func checkRestartedInPlace(before, after containerState) error {
	switch {
	case after.id != before.id:
		return fmt.Errorf("the server's container is %s, not %s: it was replaced instead of restarted", after.id, before.id)
	case !after.running:
		return fmt.Errorf("the server's container %s is not running", after.id)
	case !after.startedAt.After(before.startedAt):
		return fmt.Errorf("the server's container %s started at %s, not after %s: it was not restarted", after.id, after.startedAt.Format(time.RFC3339Nano), before.startedAt.Format(time.RFC3339Nano))
	}
	return nil
}

// rigConfig is what the suite reads from the resolved compose configuration.
type rigConfig struct {
	project   string
	serverEnv map[string]any
	// serverFiles maps the target of each bind mount of the server to its source on this machine.
	serverFiles map[string]string
	pebble      netip.Addr
}

// parseRigConfig reads the output of docker compose config --format json, in which compose has resolved the environment, the project name and the paths of bind mounts.
func parseRigConfig(data []byte) (rigConfig, error) {
	type volume struct {
		Type   string `json:"type"`
		Source string `json:"source"`
		Target string `json:"target"`
	}
	type network struct {
		IPv4Address string `json:"ipv4_address"`
	}
	var raw struct {
		Name     string `json:"name"`
		Services map[string]struct {
			Environment map[string]any      `json:"environment"`
			Volumes     []volume            `json:"volumes"`
			Networks    map[string]*network `json:"networks"`
		} `json:"services"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return rigConfig{}, fmt.Errorf("parsing the compose configuration: %w", err)
	}
	server, ok := raw.Services[rigServer]
	if !ok {
		return rigConfig{}, fmt.Errorf("the compose configuration has no service %s", rigServer)
	}
	pebble, ok := raw.Services[rigPebble]
	if !ok {
		return rigConfig{}, fmt.Errorf("the compose configuration has no service %s", rigPebble)
	}

	files := make(map[string]string)
	for i, v := range server.Volumes {
		if v.Type != "bind" {
			continue
		}
		if _, twice := files[v.Target]; twice {
			return rigConfig{}, fmt.Errorf("services.%s.volumes[%d]: %q is the target of an earlier bind mount too", rigServer, i, v.Target)
		}
		files[v.Target] = v.Source
	}

	var addresses []string
	for _, n := range pebble.Networks {
		if n != nil && n.IPv4Address != "" {
			addresses = append(addresses, n.IPv4Address)
		}
	}
	if len(addresses) != 1 {
		return rigConfig{}, fmt.Errorf("services.%s has the fixed IPv4 addresses %q, want exactly one, where the test reaches it", rigPebble, addresses)
	}
	address, err := netip.ParseAddr(addresses[0])
	if err != nil {
		return rigConfig{}, fmt.Errorf("services.%s: %w", rigPebble, err)
	}

	return rigConfig{project: raw.Name, serverEnv: server.Environment, serverFiles: files, pebble: address}, nil
}

// checkRigProject refuses any project but rigProject, so that pointing the test at another compose file cannot remove that project's containers and volumes.
func checkRigProject(project string) error {
	if project != rigProject {
		return fmt.Errorf("refusing to run compose project %q: the test removes the project it runs, with its volumes, and only runs %q", project, rigProject)
	}
	return nil
}

// target is the rig's server as the suite expects to find it: nothing delegates its domain on the public internet, and its certificates verify against Pebble's issuer root.
func (c rigConfig) target(composeFile string, issuerRoots *x509.CertPool) (*target, error) {
	return newTarget(targetSource{
		path:    composeFile,
		envKeys: "services." + rigServer + ".environment.",
		name:    "compose project " + c.project,
		env:     c.serverEnv,
		files:   c.serverFiles,
		roots:   issuerRoots,
	})
}

// waitPebble waits until Pebble answers on its ACME directory and its management API, and returns the root it issues under.
func waitPebble(ctx context.Context, address netip.Addr) (*x509.CertPool, error) {
	apiRoots := x509.NewCertPool()
	if !apiRoots.AppendCertsFromPEM(pebbleAPIRootPEM) {
		return nil, errors.New("rig/pebble.minica.pem holds no PEM certificate")
	}
	client := newPinnedClient(address, apiRoots)
	defer client.CloseIdleConnections()

	deadline := time.Now().Add(pebbleWaitLimit)
	for {
		// Pebble starts its management listener in a goroutine of its own, so the directory can answer before the root can be fetched: either failing to answer means not ready yet.
		_, err := fetch(ctx, client, "https://"+rigPebble+":14000/dir")
		var rootPEM []byte
		if err == nil {
			rootPEM, err = fetch(ctx, client, "https://"+rigPebble+":15000/roots/0")
		}
		if err != nil {
			if time.Now().After(deadline) {
				return nil, fmt.Errorf("Pebble did not answer at %s within %s; the rig needs a Docker Engine running natively on the Linux host, which reaches the containers' addresses directly (not Docker Desktop, not a remote context); last error: %w", address, pebbleWaitLimit, err)
			}
			if !pause(ctx, pebblePollInterval) {
				return nil, ctx.Err()
			}
			continue
		}
		chain, err := parseChain(rootPEM)
		if err != nil {
			return nil, fmt.Errorf("parsing Pebble's issuer root: %w", err)
		}
		if len(chain) != 1 {
			return nil, fmt.Errorf("Pebble's issuer root is %d certificates, want 1", len(chain))
		}
		return certPool(chain[0]), nil
	}
}

func fetch(ctx context.Context, client *http.Client, url string) ([]byte, error) {
	resp, body, err := observeGet(ctx, client, url)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GET %s: status %d, want 200", url, resp.StatusCode)
	}
	return body, nil
}

// waitIssued waits until the server serves both certificates of its first start.
func waitIssued(t *testing.T, tg *target) {
	t.Helper()
	endpoint := netip.AddrPortFrom(tg.nameServers[0], 443)
	deadline := time.Now().Add(issuanceWaitLimit)
	var logged string
	for {
		_, err := observe(t.Context(), tg, endpoint)
		if err == nil {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("the server did not serve both certificates within %s of its start; last error: %v", issuanceWaitLimit, err)
		}
		// The same error comes back for the minute or more an order takes, so only a change is worth a line.
		if err.Error() != logged {
			logged = err.Error()
			logStep(t, "waiting for the first issuance: %v", err)
		}
		if !pause(t.Context(), issuancePollInterval) {
			t.Fatal("test context ended while waiting for the first issuance")
		}
	}
}

// tearDown removes the project with its volumes, after printing the logs of both services when the test failed. It runs as a cleanup, after the test's context has ended.
func (r rig) tearDown(t *testing.T) {
	ctx := context.Background()
	if t.Failed() {
		logs, err := r.compose(ctx, dockerCommandTimeout, "logs", "--no-color", "--timestamps", rigServer, rigPebble)
		if err != nil {
			t.Logf("reading the logs of the rig: %v", err)
		} else {
			t.Logf("logs of the rig:\n%s", logs)
		}
	}
	if _, err := r.compose(ctx, dockerCommandTimeout, "down", "--volumes", "--remove-orphans"); err != nil {
		t.Errorf("removing the rig: %v", err)
	}
}

// TestRig starts the rig, runs the live sections and the lifecycle test against its server, and removes it whatever the outcome. It is the only test that runs Docker.
func TestRig(t *testing.T) {
	composeFile, set := os.LookupEnv(composeFileEnv)
	if !set {
		t.Skipf("%s is not set; set it to the path of the rig's compose file to run the suite against a container", composeFileEnv)
	}
	composeFile = strings.TrimSpace(composeFile)
	if composeFile == "" {
		t.Fatalf("%s is set but empty; set it to the path of the rig's compose file, or unset it to skip the rig", composeFileEnv)
	}
	ctx := t.Context()
	r := rig{file: composeFile}

	resolved, err := r.compose(ctx, dockerCommandTimeout, "config", "--format", "json")
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := parseRigConfig(resolved)
	if err != nil {
		t.Fatalf("%s: %v", composeFile, err)
	}
	if err := checkRigProject(cfg.project); err != nil {
		t.Fatalf("%s: %v", composeFile, err)
	}

	logStep(t, "removing whatever an earlier run left of project %s", cfg.project)
	if _, err := r.compose(ctx, dockerCommandTimeout, "down", "--volumes", "--remove-orphans"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { r.tearDown(t) })

	logStep(t, "starting Pebble at %s", cfg.pebble)
	if _, err := r.compose(ctx, dockerUpTimeout, "up", "--detach", rigPebble); err != nil {
		t.Fatal(err)
	}
	issuerRoots, err := waitPebble(ctx, cfg.pebble)
	if err != nil {
		t.Fatal(err)
	}
	tg, err := cfg.target(composeFile, issuerRoots)
	if err != nil {
		t.Fatal(err)
	}

	// The server starts only once Pebble answers: an order that fails at the start would put off the next attempt by five minutes.
	logStep(t, "building and starting the server at %v", tg.nameServers)
	if _, err := r.compose(ctx, dockerUpTimeout, "up", "--detach", "--build", rigServer); err != nil {
		t.Fatal(err)
	}
	waitIssued(t, tg)
	logStep(t, "the server serves both certificates")

	t.Run("Live", func(t *testing.T) { liveSections(t, tg) })
	t.Run("Lifecycle", func(t *testing.T) { lifecycle(t, r, tg) })
}

// capturedRigConfig is the output of docker compose config --format json for rig/compose.yml, with the directory of the compose file written as RIG_DIR.
const capturedRigConfig = `{
  "name": "local-ip-e2e",
  "networks": {
    "rig": {
      "name": "local-ip-e2e_rig",
      "ipam": {"config": [{"subnet": "10.253.53.0/24"}]}
    }
  },
  "services": {
    "pebble": {
      "command": ["-config", "test/config/pebble-config.json", "-strict", "-dnsserver", "10.253.53.53:53"],
      "entrypoint": null,
      "environment": {"PEBBLE_AUTHZREUSE": "0", "PEBBLE_VA_NOSLEEP": "1"},
      "image": "ghcr.io/letsencrypt/pebble:2.10.3@sha256:0c81f05db371f436c97fb894bd6d2ab8fc9c8e2ce40f8bef8a8e15941bcd75ef",
      "networks": {"rig": {"ipv4_address": "10.253.53.10"}}
    },
    "server": {
      "command": null,
      "entrypoint": null,
      "environment": {
        "SSL_CERT_FILE": "/etc/pebble.minica.pem",
        "XIP_ACME_DIRECTORY": "https://pebble:14000/dir",
        "XIP_ACME_PROFILE": "default",
        "XIP_DOMAIN": "local-ip.test",
        "XIP_EMAIL": "admin@local-ip.test",
        "XIP_NAMESERVERS": "10.253.53.53",
        "XIP_ZONE_FILE": "/etc/local-ip.zone"
      },
      "networks": {"rig": {"ipv4_address": "10.253.53.53"}},
      "volumes": [
        {"type": "bind", "source": "RIG_DIR/zone", "target": "/etc/local-ip.zone", "read_only": true, "bind": {}},
        {"type": "bind", "source": "RIG_DIR/pebble.minica.pem", "target": "/etc/pebble.minica.pem", "read_only": true, "bind": {}},
        {"type": "volume", "source": "state", "target": "/local-ip/state", "volume": {}}
      ],
      "build": {"context": "RIG_DIR/../..", "dockerfile": "Dockerfile"}
    }
  },
  "volumes": {"state": {"name": "local-ip-e2e_state"}}
}`

// rigDir is the absolute path of the rig's directory, spelled for a JSON string.
func rigDir(t *testing.T) string {
	t.Helper()
	dir, err := filepath.Abs("rig")
	if err != nil {
		t.Fatal(err)
	}
	quoted, err := json.Marshal(dir)
	if err != nil {
		t.Fatal(err)
	}
	return string(quoted[1 : len(quoted)-1])
}

// capturedRigTarget is the target that capturedRigConfig describes, with the rig's own zone file.
func capturedRigTarget(t *testing.T) *target {
	t.Helper()
	cfg, err := parseRigConfig([]byte(strings.ReplaceAll(capturedRigConfig, "RIG_DIR", rigDir(t))))
	if err != nil {
		t.Fatal(err)
	}
	tg, err := cfg.target("compose.yml", x509.NewCertPool())
	if err != nil {
		t.Fatal(err)
	}
	return tg
}

func TestParseRigConfig(t *testing.T) {
	dir := rigDir(t)
	cfg, err := parseRigConfig([]byte(strings.ReplaceAll(capturedRigConfig, "RIG_DIR", dir)))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.project != rigProject {
		t.Errorf("project = %q, want %q", cfg.project, rigProject)
	}
	if want := netip.MustParseAddr("10.253.53.10"); cfg.pebble != want {
		t.Errorf("pebble = %s, want %s", cfg.pebble, want)
	}
	wantFiles := map[string]string{"/etc/local-ip.zone": dir + "/zone", "/etc/pebble.minica.pem": dir + "/pebble.minica.pem"}
	if !maps.Equal(cfg.serverFiles, wantFiles) {
		t.Errorf("serverFiles = %v, want only the bind mounts %v", cfg.serverFiles, wantFiles)
	}
	if got := cfg.serverEnv["XIP_ACME_DIRECTORY"]; got != "https://pebble:14000/dir" {
		t.Errorf("XIP_ACME_DIRECTORY = %v, want https://pebble:14000/dir", got)
	}

	tg := capturedRigTarget(t)
	if tg.name != "compose project "+rigProject {
		t.Errorf("name = %q, want %q", tg.name, "compose project "+rigProject)
	}
	if tg.domain != "local-ip.test" {
		t.Errorf("domain = %q, want local-ip.test", tg.domain)
	}
	if want := []netip.Addr{netip.MustParseAddr("10.253.53.53")}; !slices.Equal(tg.nameServers, want) {
		t.Errorf("nameServers = %v, want %v", tg.nameServers, want)
	}
	if tg.publiclyDelegated {
		t.Error("publiclyDelegated = true, want false")
	}
	if got, want := tg.soaRname(), "admin.local-ip.test."; got != want {
		t.Errorf("soaRname = %q, want %q", got, want)
	}
	if len(tg.delegations) != 1 || len(tg.recordSets) != 10 {
		t.Errorf("%d delegations and %d record sets, want the 1 and 10 of rig/zone", len(tg.delegations), len(tg.recordSets))
	}
}

func TestParseRigConfigRefuses(t *testing.T) {
	tests := []struct {
		name    string
		config  string
		wantErr string
	}{
		{name: "not JSON", config: `name: local-ip-e2e`, wantErr: "parsing the compose configuration"},
		{name: "an environment written as a list", config: `{"services": {"server": {"environment": ["XIP_DOMAIN=local-ip.test"]}, "pebble": {}}}`, wantErr: "parsing the compose configuration"},
		{name: "no server", config: `{"services": {"pebble": {"networks": {"rig": {"ipv4_address": "10.0.0.2"}}}}}`, wantErr: "no service server"},
		{name: "no pebble", config: `{"services": {"server": {}}}`, wantErr: "no service pebble"},
		{name: "pebble without a fixed address", config: `{"services": {"server": {}, "pebble": {"networks": {"rig": null}}}}`, wantErr: "want exactly one"},
		{name: "pebble with two fixed addresses", config: `{"services": {"server": {}, "pebble": {"networks": {"a": {"ipv4_address": "10.0.0.2"}, "b": {"ipv4_address": "10.0.1.2"}}}}}`, wantErr: "want exactly one"},
		{name: "two bind mounts at one target", config: `{"services": {"server": {"volumes": [{"type": "bind", "source": "/a", "target": "/etc/z"}, {"type": "bind", "source": "/b", "target": "/etc/z"}]}, "pebble": {"networks": {"rig": {"ipv4_address": "10.0.0.2"}}}}}`, wantErr: `services.server.volumes[1]: "/etc/z" is the target of an earlier bind mount too`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := parseRigConfig([]byte(tt.config))
			expectErrorContains(t, err, tt.wantErr)
		})
	}

	t.Run("an environment variable without a value", func(t *testing.T) {
		cfg, err := parseRigConfig([]byte(`{"name": "local-ip-e2e", "services": {"server": {"environment": {"XIP_DOMAIN": null}}, "pebble": {"networks": {"rig": {"ipv4_address": "10.0.0.2"}}}}}`))
		if err != nil {
			t.Fatal(err)
		}
		_, err = cfg.target("compose.yml", nil)
		expectErrorContains(t, err, "compose.yml: services.server.environment.XIP_DOMAIN: must be a string")
	})
}

func TestCheckRigProject(t *testing.T) {
	if err := checkRigProject("local-ip-e2e"); err != nil {
		t.Errorf("the rig's project refused: %v", err)
	}
	for _, project := range []string{"", "local-ip", "local-ip-e2e-2", "build10"} {
		t.Run(project, func(t *testing.T) {
			expectErrorContains(t, checkRigProject(project), fmt.Sprintf("refusing to run compose project %q", project))
		})
	}
}

func TestPublicResolverSkip(t *testing.T) {
	production, err := loadFlyTarget(filepath.Join("..", "fly.toml"))
	if err != nil {
		t.Fatal(err)
	}
	if reason, skip := publicResolverSkip(production); skip {
		t.Errorf("the public resolvers are skipped for production: %s", reason)
	}
	reason, skip := publicResolverSkip(capturedRigTarget(t))
	if !skip {
		t.Fatal("the public resolvers are not skipped for the rig")
	}
	if want := "compose project local-ip-e2e is not delegated on the public internet"; !strings.Contains(reason, want) {
		t.Errorf("reason %q does not contain %q", reason, want)
	}
}

func TestParseContainerState(t *testing.T) {
	const inspected = `[{"Id": "4f1c2b", "Created": "2026-11-22T10:00:00.1Z", "State": {"Status": "running", "Running": true, "Pid": 4242, "StartedAt": "2026-11-22T10:00:01.123456789Z", "FinishedAt": "0001-01-01T00:00:00Z"}, "Name": "/local-ip-e2e-server-1"}]`
	got, err := parseContainerState([]byte(inspected))
	if err != nil {
		t.Fatal(err)
	}
	want := containerState{id: "4f1c2b", startedAt: time.Date(2026, 11, 22, 10, 0, 1, 123456789, time.UTC), running: true}
	if got.id != want.id || !got.startedAt.Equal(want.startedAt) || got.running != want.running {
		t.Errorf("parseContainerState = %+v, want %+v", got, want)
	}

	for _, tt := range []struct {
		name      string
		inspected string
		wantErr   string
	}{
		{name: "no container", inspected: `[]`, wantErr: "describes 0 containers"},
		{name: "two containers", inspected: `[{"Id": "a", "State": {"StartedAt": "2026-11-22T10:00:01Z"}}, {"Id": "b", "State": {"StartedAt": "2026-11-22T10:00:01Z"}}]`, wantErr: "describes 2 containers"},
		{name: "no Id", inspected: `[{"State": {"StartedAt": "2026-11-22T10:00:01Z"}}]`, wantErr: "no Id"},
		{name: "no start time", inspected: `[{"Id": "a", "State": {}}]`, wantErr: "State.StartedAt"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			_, err := parseContainerState([]byte(tt.inspected))
			expectErrorContains(t, err, tt.wantErr)
		})
	}
}

func TestContainerJudgments(t *testing.T) {
	start := time.Date(2026, 11, 22, 10, 0, 1, 0, time.UTC)
	before := containerState{id: "4f1c2b", startedAt: start, running: true}
	same := before
	later := containerState{id: "4f1c2b", startedAt: start.Add(time.Minute), running: true}
	replaced := containerState{id: "9a8b7c", startedAt: start.Add(time.Minute), running: true}
	stopped := containerState{id: "4f1c2b", startedAt: start, running: false}

	if err := checkNotRestarted(before, same); err != nil {
		t.Errorf("the same run is judged restarted: %v", err)
	}
	expectErrorContains(t, checkNotRestarted(before, later), "is not the one that was running")
	expectErrorContains(t, checkNotRestarted(before, replaced), "it was replaced")
	expectErrorContains(t, checkNotRestarted(before, stopped), "is not running")

	if err := checkRestartedInPlace(before, later); err != nil {
		t.Errorf("a later run of the same container is not judged restarted: %v", err)
	}
	expectErrorContains(t, checkRestartedInPlace(before, same), "it was not restarted")
	expectErrorContains(t, checkRestartedInPlace(before, replaced), "replaced instead of restarted")
	expectErrorContains(t, checkRestartedInPlace(later, before), "it was not restarted")
}
