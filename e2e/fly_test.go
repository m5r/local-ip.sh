package e2e

import (
	"bufio"
	"bytes"
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
	"unicode/utf8"
)

const (
	flyMachinesURL    = "https://api.machines.dev"
	flyRequestTimeout = 30 * time.Second
	flyErrorLimit     = 200
	flyRedacted       = "[redacted]"
)

// flyMachines talks to the Fly Machines API for one app. The token only ever travels in the Authorization header: no error, log line or test output may contain it.
type flyMachines struct {
	baseURL string // https://api.machines.dev, replaced in unit tests
	app     string
	auth    string       // the complete Authorization header value
	client  *http.Client // 30-second timeout, redirects refused
}

type flyMachine struct {
	ID     string            `json:"id"`
	State  string            `json:"state"`
	Config flyMachineConfig  `json:"config"`
	Events []flyMachineEvent `json:"events"` // newest first; the API returns only the last five
}

// flyMachineConfig is the configuration the machine really runs with, which is what the guard of the lifecycle test looks at.
type flyMachineConfig struct {
	Env map[string]string `json:"env"`
}

type flyMachineEvent struct {
	ID        string `json:"id"`
	Type      string `json:"type"`      // "start", "exit", "stop", ...
	Status    string `json:"status"`    // "started", "stopped", "stopping", ...
	Timestamp int64  `json:"timestamp"` // milliseconds since the epoch
}

func (e flyMachineEvent) time() time.Time {
	return time.UnixMilli(e.Timestamp).UTC()
}

func newFlyMachines(app, token string) (*flyMachines, error) {
	auth, err := flyAuthorization(token)
	if err != nil {
		return nil, err
	}
	return &flyMachines{
		baseURL: flyMachinesURL,
		app:     app,
		auth:    auth,
		client: &http.Client{
			Timeout: flyRequestTimeout,
			// The Authorization header must never travel to a URL other than the one asked for.
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}, nil
}

// flyAuthorization accepts the token in the forms flyctl prints: macaroons (fm…) need the FlyV1 scheme, other tokens are bearer tokens, and a value that already names its scheme is used as it is.
func flyAuthorization(token string) (string, error) {
	token = strings.TrimSpace(token)
	switch {
	case token == "":
		return "", errors.New("building the Fly API authorization: the token is empty")
	case strings.HasPrefix(token, "FlyV1 "), strings.HasPrefix(token, "Bearer "):
		return token, nil
	case strings.HasPrefix(token, "fm"):
		return "FlyV1 " + token, nil
	default:
		return "Bearer " + token, nil
	}
}

// secrets lists what must never appear in an error: the header value, the credential after its scheme and each comma-separated token of the credential (deploy tokens hold several macaroons). Longest first, so that a longer secret is replaced as a whole before a part of it is. The token as given is always the header value or the credential once trimmed, and white space around it is no secret.
func (f *flyMachines) secrets() []string {
	credential := f.auth
	for _, scheme := range []string{"FlyV1 ", "Bearer "} {
		credential = strings.TrimPrefix(credential, scheme)
	}
	secrets := []string{f.auth, credential}
	for part := range strings.SplitSeq(credential, ",") {
		secrets = append(secrets, strings.TrimSpace(part))
	}
	secrets = slices.DeleteFunc(secrets, func(s string) bool { return s == "" })
	slices.SortFunc(secrets, func(a, b string) int { return cmp.Compare(len(b), len(a)) })
	return slices.Compact(secrets)
}

func (f *flyMachines) redact(s string) string {
	for _, secret := range f.secrets() {
		s = strings.ReplaceAll(s, secret, flyRedacted)
	}
	return s
}

func (f *flyMachines) machinesPath(parts ...string) string {
	p := "/v1/apps/" + url.PathEscape(f.app) + "/machines"
	for _, part := range parts {
		p += "/" + url.PathEscape(part)
	}
	return p
}

// redactedError is how every error leaves the client: its text has every secret replaced, and Unwrap still gives the original so that errors.Is and errors.As see context errors and network errors. Go's HTTP client quotes what it could not parse (a malformed status or header line), so even a transport error can carry the token when a server or proxy reflects the header.
type redactedError struct {
	text string
	err  error
}

func (e *redactedError) Error() string {
	return e.text
}

func (e *redactedError) Unwrap() error {
	return e.err
}

// do is the only way the client talks to the API, and so the one place its errors are redacted: it marshals payload when it is not nil, sends one request, and decodes the body of a 2xx response into into when it is not nil. Any other status is an error that quotes nothing of the body but the API's own error string.
func (f *flyMachines) do(ctx context.Context, method, escapedPath string, payload, into any) (err error) {
	defer func() {
		if err != nil {
			err = &redactedError{text: f.redact(err.Error()), err: err}
		}
	}()

	var reader io.Reader
	if payload != nil {
		body, err := json.Marshal(payload)
		if err != nil {
			return fmt.Errorf("encoding the body of %s %s: %w", method, escapedPath, err)
		}
		reader = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, f.baseURL+escapedPath, reader)
	if err != nil {
		return fmt.Errorf("building request %s %s: %w", method, escapedPath, err)
	}
	req.Header.Set("Authorization", f.auth)
	req.Header.Set("Accept", "application/json")
	if payload != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := f.client.Do(req)
	if err != nil {
		return fmt.Errorf("sending %s %s: %w", method, escapedPath, err)
	}
	defer resp.Body.Close()

	content, err := io.ReadAll(io.LimitReader(resp.Body, maxBodyBytes))
	if err != nil {
		return fmt.Errorf("reading response of %s %s: %w", method, escapedPath, err)
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		message := fmt.Sprintf("%s %s: status %d %s", method, escapedPath, resp.StatusCode, http.StatusText(resp.StatusCode))
		if apiError, ok := flyAPIError(content); ok {
			message += ": " + truncateUTF8(f.redact(apiError), flyErrorLimit)
		}
		return errors.New(message)
	}
	if into == nil {
		return nil
	}
	return decodeFlyJSON(content, into, method, escapedPath)
}

func flyAPIError(body []byte) (string, bool) {
	var object map[string]json.RawMessage
	if err := json.Unmarshal(body, &object); err != nil {
		return "", false
	}
	var message string
	if err := json.Unmarshal(object["error"], &message); err != nil {
		return "", false
	}
	return message, true
}

func truncateUTF8(s string, limit int) string {
	if len(s) <= limit {
		return s
	}
	cut := limit
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut]
}

// decodeFlyJSON keeps the decoder's message out of the error: a syntax or type error can quote part of the body, and nothing of a response body may reach an error.
func decodeFlyJSON(content []byte, v any, method, escapedPath string) error {
	err := json.Unmarshal(content, v)
	if err == nil {
		return nil
	}
	var syntaxErr *json.SyntaxError
	var typeErr *json.UnmarshalTypeError
	switch {
	case errors.As(err, &syntaxErr):
		return fmt.Errorf("decoding response of %s %s: invalid JSON at byte %d", method, escapedPath, syntaxErr.Offset)
	case errors.As(err, &typeErr):
		return fmt.Errorf("decoding response of %s %s: field %q does not hold a %s", method, escapedPath, typeErr.Field, typeErr.Type)
	default:
		return fmt.Errorf("decoding response of %s %s: not the expected JSON", method, escapedPath)
	}
}

func (f *flyMachines) list(ctx context.Context) ([]flyMachine, error) {
	var machines []flyMachine
	if err := f.do(ctx, http.MethodGet, f.machinesPath(), nil, &machines); err != nil {
		return nil, err
	}
	return machines, nil
}

func (f *flyMachines) get(ctx context.Context, id string) (flyMachine, error) {
	var machine flyMachine
	if err := f.do(ctx, http.MethodGet, f.machinesPath(id), nil, &machine); err != nil {
		return flyMachine{}, err
	}
	return machine, nil
}

func (f *flyMachines) signal(ctx context.Context, id, signal string) error {
	payload := struct {
		Signal string `json:"signal"`
	}{Signal: signal}
	return f.do(ctx, http.MethodPost, f.machinesPath(id, "signal"), payload, nil)
}

func (f *flyMachines) restart(ctx context.Context, id string) error {
	return f.do(ctx, http.MethodPost, f.machinesPath(id, "restart"), nil, nil)
}

type recordedRequest struct {
	method      string
	path        string
	auth        string
	contentType string
	body        string
}

// flyTestServer records every request and answers each with what respond returns.
func flyTestServer(t *testing.T, respond func(w http.ResponseWriter, r *http.Request)) (*httptest.Server, func() []recordedRequest) {
	t.Helper()
	var mu sync.Mutex
	var requests []recordedRequest
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		mu.Lock()
		requests = append(requests, recordedRequest{
			method:      r.Method,
			path:        r.URL.EscapedPath(),
			auth:        r.Header.Get("Authorization"),
			contentType: r.Header.Get("Content-Type"),
			body:        string(body),
		})
		mu.Unlock()
		respond(w, r)
	}))
	t.Cleanup(server.Close)
	return server, func() []recordedRequest {
		mu.Lock()
		defer mu.Unlock()
		return append([]recordedRequest(nil), requests...)
	}
}

// reflectingServer answers every request on a loopback listener with the raw bytes response builds from the Authorization header it received, which is how a broken server or proxy puts the credential into a line the HTTP client cannot parse and therefore quotes.
func reflectingServer(t *testing.T, response func(auth string) string) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listening on loopback: %v", err)
	}
	t.Cleanup(func() { listener.Close() })
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				req, err := http.ReadRequest(bufio.NewReader(conn))
				if err != nil {
					return
				}
				io.WriteString(conn, response(req.Header.Get("Authorization")))
			}()
		}
	}()
	return "http://" + listener.Addr().String()
}

func testFlyMachines(t *testing.T, baseURL, token string) *flyMachines {
	t.Helper()
	f, err := newFlyMachines("local-ip-staging", token)
	if err != nil {
		t.Fatal(err)
	}
	f.baseURL = baseURL
	return f
}

func writeJSON(w http.ResponseWriter, status int, body string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	io.WriteString(w, body)
}

func expectNoSecret(t *testing.T, err error, secrets ...string) {
	t.Helper()
	for _, secret := range secrets {
		if strings.Contains(err.Error(), secret) {
			t.Errorf("error %q contains a secret", err)
		}
	}
}

const testMachineJSON = `{"id":"d8901","state":"started","config":{"env":{"XIP_STAGING":"true","XIP_DOMAIN":"xip-staging.local-ip.sh","FLY_REGION":"ams"},"image":"x"},"events":[{"id":"e2","type":"start","status":"started","request":{"x":1},"source":"flyd","timestamp":1763700000500},{"id":"e1","type":"launch","status":"created","timestamp":1763700000000}]}`

func TestFlyMachinesClient(t *testing.T) {
	const token = "fm2_abc"
	ctx := t.Context()

	t.Run("calls", func(t *testing.T) {
		server, requests := flyTestServer(t, func(w http.ResponseWriter, r *http.Request) {
			switch {
			case r.Method == http.MethodGet && r.URL.Path == "/v1/apps/local-ip-staging/machines":
				writeJSON(w, http.StatusOK, "["+testMachineJSON+"]")
			case r.Method == http.MethodGet:
				writeJSON(w, http.StatusOK, testMachineJSON)
			default:
				writeJSON(w, http.StatusOK, `{"ok":true}`)
			}
		})
		f := testFlyMachines(t, server.URL, token)

		machines, err := f.list(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if len(machines) != 1 {
			t.Fatalf("list returned %d machines, want 1", len(machines))
		}
		m := machines[0]
		if m.ID != "d8901" || m.State != "started" {
			t.Errorf("machine = %s %s, want d8901 started", m.ID, m.State)
		}
		if m.Config.Env["XIP_STAGING"] != "true" || m.Config.Env["XIP_DOMAIN"] != "xip-staging.local-ip.sh" || m.Config.Env["FLY_REGION"] != "ams" {
			t.Errorf("config.env = %v", m.Config.Env)
		}
		wantEvents := []flyMachineEvent{
			{ID: "e2", Type: "start", Status: "started", Timestamp: 1763700000500},
			{ID: "e1", Type: "launch", Status: "created", Timestamp: 1763700000000},
		}
		if len(m.Events) != len(wantEvents) {
			t.Fatalf("events = %+v, want %+v", m.Events, wantEvents)
		}
		for i := range wantEvents {
			if m.Events[i] != wantEvents[i] {
				t.Errorf("event %d = %+v, want %+v", i, m.Events[i], wantEvents[i])
			}
		}

		got, err := f.get(ctx, "a/b")
		if err != nil {
			t.Fatal(err)
		}
		if got.ID != "d8901" {
			t.Errorf("get returned machine %q, want d8901", got.ID)
		}
		if err := f.signal(ctx, "d8901", "SIGUSR1"); err != nil {
			t.Fatal(err)
		}
		if err := f.restart(ctx, "d8901"); err != nil {
			t.Fatal(err)
		}

		want := []recordedRequest{
			{method: http.MethodGet, path: "/v1/apps/local-ip-staging/machines"},
			{method: http.MethodGet, path: "/v1/apps/local-ip-staging/machines/a%2Fb"},
			{method: http.MethodPost, path: "/v1/apps/local-ip-staging/machines/d8901/signal", contentType: "application/json", body: `{"signal":"SIGUSR1"}`},
			{method: http.MethodPost, path: "/v1/apps/local-ip-staging/machines/d8901/restart"},
		}
		recorded := requests()
		if len(recorded) != len(want) {
			t.Fatalf("server received %d requests, want %d", len(recorded), len(want))
		}
		for i, w := range want {
			r := recorded[i]
			if r.method != w.method || r.path != w.path {
				t.Errorf("request %d = %s %s, want %s %s", i+1, r.method, r.path, w.method, w.path)
			}
			if w.body != "" && (r.body != w.body || r.contentType != w.contentType) {
				t.Errorf("request %d body %q with Content-Type %q, want %q with %q", i+1, r.body, r.contentType, w.body, w.contentType)
			}
			if r.auth != "FlyV1 "+token {
				t.Errorf("request %d Authorization does not carry the token in the FlyV1 scheme", i+1)
			}
		}
	})

	t.Run("authorization", func(t *testing.T) {
		tests := []struct {
			token string
			want  string
		}{
			{token: "fm2_abc", want: "FlyV1 fm2_abc"},
			{token: "FlyV1 fm2_abc", want: "FlyV1 fm2_abc"},
			{token: "fo1_abc", want: "Bearer fo1_abc"},
			{token: "Bearer abc", want: "Bearer abc"},
			{token: " \tfm2_abc\n", want: "FlyV1 fm2_abc"},
		}
		for _, tt := range tests {
			t.Run(strings.TrimSpace(tt.token), func(t *testing.T) {
				server, requests := flyTestServer(t, func(w http.ResponseWriter, _ *http.Request) {
					writeJSON(w, http.StatusOK, testMachineJSON)
				})
				if _, err := testFlyMachines(t, server.URL, tt.token).get(ctx, "d8901"); err != nil {
					t.Fatal(err)
				}
				recorded := requests()
				if len(recorded) != 1 || recorded[0].auth != tt.want {
					t.Errorf("Authorization header differs from %q", tt.want)
				}
			})
		}
	})

	t.Run("empty token", func(t *testing.T) {
		for _, token := range []string{"", " \t\n"} {
			if f, err := newFlyMachines("local-ip-staging", token); err == nil {
				t.Errorf("newFlyMachines(%q) = %v, want an error", token, f != nil)
			}
		}
	})

	t.Run("API error", func(t *testing.T) {
		server, _ := flyTestServer(t, func(w http.ResponseWriter, _ *http.Request) {
			writeJSON(w, http.StatusNotFound, `{"error":"machine not found"}`)
		})
		_, err := testFlyMachines(t, server.URL, token).get(ctx, "d8901")
		expectErrorContains(t, err, "404")
		expectErrorContains(t, err, "machine not found")
		expectErrorContains(t, err, "GET /v1/apps/local-ip-staging/machines/d8901")
	})

	t.Run("API error repeating the header", func(t *testing.T) {
		server, _ := flyTestServer(t, func(w http.ResponseWriter, r *http.Request) {
			body, _ := json.Marshal(map[string]string{"error": "bad token " + r.Header.Get("Authorization") + " for app"})
			writeJSON(w, http.StatusInternalServerError, string(body))
		})
		_, err := testFlyMachines(t, server.URL, token).get(ctx, "d8901")
		expectErrorContains(t, err, "500")
		expectErrorContains(t, err, flyRedacted)
		expectNoSecret(t, err, token, "FlyV1 "+token)
	})

	t.Run("API error repeating the credential", func(t *testing.T) {
		tests := []struct {
			token      string
			credential string
		}{
			{token: "FlyV1 fm2_abc", credential: "fm2_abc"},
			{token: "Bearer abc", credential: "abc"},
		}
		for _, tt := range tests {
			t.Run(tt.token, func(t *testing.T) {
				server, _ := flyTestServer(t, func(w http.ResponseWriter, _ *http.Request) {
					writeJSON(w, http.StatusInternalServerError, `{"error":"`+tt.credential+`"}`)
				})
				_, err := testFlyMachines(t, server.URL, tt.token).get(ctx, "d8901")
				expectErrorContains(t, err, "500")
				expectNoSecret(t, err, tt.credential)
			})
		}
	})

	t.Run("API error repeating one token of a deploy credential", func(t *testing.T) {
		const deployToken = "FlyV1 fm2_aaa,fm2_bbb"
		tests := []struct {
			name     string
			apiError string
		}{
			{name: "second token alone", apiError: "fm2_bbb"},
			{name: "whole header value", apiError: "rejected " + deployToken + " for app"},
		}
		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				server, _ := flyTestServer(t, func(w http.ResponseWriter, _ *http.Request) {
					body, _ := json.Marshal(map[string]string{"error": tt.apiError})
					writeJSON(w, http.StatusInternalServerError, string(body))
				})
				_, err := testFlyMachines(t, server.URL, deployToken).get(ctx, "d8901")
				expectErrorContains(t, err, "500")
				expectErrorContains(t, err, flyRedacted)
				expectNoSecret(t, err, deployToken, "fm2_aaa,fm2_bbb", "fm2_aaa", "fm2_bbb")
			})
		}
	})

	t.Run("long API error is cut", func(t *testing.T) {
		long := strings.Repeat("é", 300)
		server, _ := flyTestServer(t, func(w http.ResponseWriter, _ *http.Request) {
			writeJSON(w, http.StatusInternalServerError, `{"error":"`+long+`"}`)
		})
		_, err := testFlyMachines(t, server.URL, token).get(ctx, "d8901")
		expectErrorContains(t, err, strings.Repeat("é", flyErrorLimit/2))
		if strings.Contains(err.Error(), strings.Repeat("é", flyErrorLimit/2+1)) {
			t.Errorf("error holds more than %d bytes of the API's message", flyErrorLimit)
		}
		if !utf8.ValidString(err.Error()) {
			t.Error("error is not valid UTF-8 after the cut")
		}
	})

	t.Run("body that is not JSON", func(t *testing.T) {
		const body = "<html>internal failure fm2_abc</html>"
		server, _ := flyTestServer(t, func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
			io.WriteString(w, body)
		})
		_, err := testFlyMachines(t, server.URL, token).get(ctx, "d8901")
		expectErrorContains(t, err, "500")
		for _, part := range []string{"html", "internal failure", token} {
			if strings.Contains(err.Error(), part) {
				t.Errorf("error %q quotes the body", err)
			}
		}
	})

	t.Run("2xx body that is not the expected JSON", func(t *testing.T) {
		for _, body := range []string{`{"id": nope fm2_abc}`, `{"id": 12345678}`, `{"id": "x"`} {
			server, _ := flyTestServer(t, func(w http.ResponseWriter, _ *http.Request) {
				writeJSON(w, http.StatusOK, body)
			})
			_, err := testFlyMachines(t, server.URL, token).get(ctx, "d8901")
			expectErrorContains(t, err, "decoding response")
			for _, part := range []string{"nope", "12345678", token} {
				if strings.Contains(err.Error(), part) {
					t.Errorf("error %q quotes the body %q", err, body)
				}
			}
		}
	})

	t.Run("malformed response reflecting the credential", func(t *testing.T) {
		const deployToken = "FlyV1 fm2_aaa,fm2_bbb"
		tests := []struct {
			name     string
			response func(auth string) string
		}{
			{name: "status line with the credential", response: func(auth string) string {
				return "HTTP/1.1 " + strings.TrimPrefix(auth, "FlyV1 ") + "\r\n\r\n"
			}},
			{name: "status line with one token", response: func(auth string) string {
				_, second, _ := strings.Cut(auth, ",")
				return "HTTP/1.1 " + second + "\r\n\r\n"
			}},
			{name: "header line", response: func(auth string) string { return "HTTP/1.1 200 OK\r\n" + auth + "\r\n\r\n" }},
		}
		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				baseURL := reflectingServer(t, tt.response)
				_, err := testFlyMachines(t, baseURL, deployToken).get(ctx, "d8901")
				expectErrorContains(t, err, "sending GET /v1/apps/local-ip-staging/machines/d8901")
				expectErrorContains(t, err, flyRedacted)
				expectNoSecret(t, err, deployToken, "fm2_aaa,fm2_bbb", "fm2_aaa", "fm2_bbb")
			})
		}
	})

	t.Run("cancelled context", func(t *testing.T) {
		server, requests := flyTestServer(t, func(w http.ResponseWriter, _ *http.Request) {
			writeJSON(w, http.StatusOK, testMachineJSON)
		})
		cancelled, cancel := context.WithCancel(ctx)
		cancel()
		_, err := testFlyMachines(t, server.URL, token).get(cancelled, "d8901")
		if !errors.Is(err, context.Canceled) {
			t.Errorf("get with a cancelled context returned %v, want an error that is context.Canceled", err)
		}
		if n := len(requests()); n != 0 {
			t.Errorf("server received %d requests, want 0", n)
		}
	})

	t.Run("redirect", func(t *testing.T) {
		var redirected atomic.Int32
		elsewhere := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			redirected.Add(1)
			writeJSON(w, http.StatusOK, testMachineJSON)
		}))
		t.Cleanup(elsewhere.Close)
		server, _ := flyTestServer(t, func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, elsewhere.URL+r.URL.Path, http.StatusFound)
		})
		_, err := testFlyMachines(t, server.URL, token).get(ctx, "d8901")
		expectErrorContains(t, err, "302")
		if n := redirected.Load(); n != 0 {
			t.Errorf("redirect target received %d requests, want 0", n)
		}
	})
}
