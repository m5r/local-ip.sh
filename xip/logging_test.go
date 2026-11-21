package xip

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net"
	"strings"
	"testing"

	"github.com/miekg/dns"
	"github.com/rs/zerolog"
)

type recordingWriter struct {
	written *dns.Msg
	writes  int
	err     error
	onWrite func()
}

func (w *recordingWriter) LocalAddr() net.Addr {
	return &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 53}
}
func (w *recordingWriter) RemoteAddr() net.Addr {
	return &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 5353}
}
func (w *recordingWriter) Write([]byte) (int, error) {
	return 0, errors.New("raw writes are not expected")
}
func (w *recordingWriter) Close() error        { return nil }
func (w *recordingWriter) TsigStatus() error   { return nil }
func (w *recordingWriter) TsigTimersOnly(bool) {}
func (w *recordingWriter) Hijack()             {}

func (w *recordingWriter) WriteMsg(message *dns.Msg) error {
	if w.onWrite != nil {
		w.onWrite()
	}
	w.writes++
	w.written = message
	return w.err
}

func assertOneWrite(t *testing.T, w *recordingWriter) {
	t.Helper()
	if w.writes != 1 {
		t.Errorf("WriteMsg was called %d times, want 1", w.writes)
	}
}

type discardWriter struct{ recordingWriter }

func (discardWriter) WriteMsg(*dns.Msg) error { return nil }

func newLoggingXip(tb testing.TB, domain string, level zerolog.Level, out io.Writer) *Xip {
	tb.Helper()
	xip, err := NewXip(
		WithDomain(domain),
		WithEmail("admin@"+domain),
		WithNameServers([]string{"192.0.2.10"}),
		WithLogger(zerolog.New(out).Level(level).With().Timestamp().Logger()),
	)
	if err != nil {
		tb.Fatalf("NewXip: %v", err)
	}
	return xip
}

func newQuery(name string, qtype uint16) *dns.Msg {
	query := new(dns.Msg)
	query.SetQuestion(name, qtype)
	return query
}

func logLinesAfter(t *testing.T, buf *bytes.Buffer, offset int) []map[string]any {
	t.Helper()
	text := strings.TrimRight(buf.String()[offset:], "\n")
	if text == "" {
		return nil
	}
	var lines []map[string]any
	for _, line := range strings.Split(text, "\n") {
		var fields map[string]any
		if err := json.Unmarshal([]byte(line), &fields); err != nil {
			t.Fatalf("log line is not JSON: %v\n%s", err, line)
		}
		lines = append(lines, fields)
	}
	return lines
}

func TestHandleDnsRequestLogsNothingAtInfo(t *testing.T) {
	notify := newQuery("10-11-12-13.logging-info.test.", dns.TypeA)
	notify.Opcode = dns.OpcodeNotify

	cases := []struct {
		name  string
		query *dns.Msg
		rcode int
	}{
		{"matching A", newQuery("10-11-12-13.logging-info.test.", dns.TypeA), dns.RcodeSuccess},
		{"non-matching A", newQuery("nope.logging-info.test.", dns.TypeA), dns.RcodeNameError},
		{"opcode other than QUERY", notify, dns.RcodeRefused},
	}
	var buf bytes.Buffer
	xip := newLoggingXip(t, "logging-info.test", zerolog.InfoLevel, &buf)

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			offset := buf.Len()
			writer := &recordingWriter{}
			xip.handleDnsRequest(writer, tc.query)

			assertOneWrite(t, writer)
			if writer.written == nil {
				t.Fatal("no response was written")
			}
			if writer.written.Rcode != tc.rcode {
				t.Errorf("rcode = %s, want %s", dns.RcodeToString[writer.written.Rcode], dns.RcodeToString[tc.rcode])
			}
			if logged := buf.String()[offset:]; logged != "" {
				t.Errorf("level info logged %q, want nothing", logged)
			}
		})
	}
}

func TestHandleDnsRequestLogsResolvedAtDebug(t *testing.T) {
	cases := []struct {
		name        string
		query       *dns.Msg
		wantType    string
		wantRcode   string
		wantAnswers []string
	}{
		{
			name:        "matching A in mixed case",
			query:       newQuery("10-11-12-13.LoGgInG-Debug.TEST.", dns.TypeA),
			wantType:    "A",
			wantRcode:   "NOERROR",
			wantAnswers: []string{"10.11.12.13"},
		},
		{
			name:        "non-matching A",
			query:       newQuery("nope.logging-debug.test.", dns.TypeA),
			wantType:    "A",
			wantRcode:   "NXDOMAIN",
			wantAnswers: []string{},
		},
		{
			name:     "unassigned type at the apex",
			query:    newQuery("logging-debug.test.", 65280),
			wantType: "TYPE65280",
		},
	}
	var buf bytes.Buffer
	xip := newLoggingXip(t, "logging-debug.test", zerolog.DebugLevel, &buf)

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			offset := buf.Len()
			writer := &recordingWriter{}
			xip.handleDnsRequest(writer, tc.query)
			assertOneWrite(t, writer)

			lines := logLinesAfter(t, &buf, offset)
			if len(lines) != 1 {
				t.Fatalf("got %d log lines, want 1: %q", len(lines), buf.String()[offset:])
			}
			line := lines[0]
			if line["message"] != "resolved" {
				t.Errorf("message = %v, want resolved", line["message"])
			}
			if want := tc.query.Question[0].Name; line["name"] != want {
				t.Errorf("name = %v, want %s", line["name"], want)
			}
			if line["type"] != tc.wantType {
				t.Errorf("type = %v, want %s", line["type"], tc.wantType)
			}
			if tc.wantRcode != "" && line["rcode"] != tc.wantRcode {
				t.Errorf("rcode = %v, want %s", line["rcode"], tc.wantRcode)
			}

			answers, ok := line["answers"].([]any)
			if !ok {
				t.Fatalf("answers = %#v, want an array", line["answers"])
			}
			if tc.wantAnswers != nil && len(answers) != len(tc.wantAnswers) {
				t.Fatalf("answers = %v, want %d of them", answers, len(tc.wantAnswers))
			}
			for i, want := range tc.wantAnswers {
				answer, _ := answers[i].(string)
				if !strings.Contains(answer, want) {
					t.Errorf("answer %d = %q, want it to contain %s", i, answer, want)
				}
				if strings.Contains(answer, "\t") {
					t.Errorf("answer %d = %q contains a tab", i, answer)
				}
			}

			region, present := line["FLY_REGION"]
			switch {
			case flyRegion == "" && present:
				t.Errorf("FLY_REGION = %v, want it absent", region)
			case flyRegion != "" && region != flyRegion:
				t.Errorf("FLY_REGION = %v, want %s", region, flyRegion)
			}
		})
	}
}

func TestLogResolvedWithoutQuestion(t *testing.T) {
	var buf bytes.Buffer
	xip := newLoggingXip(t, "logging-no-question.test", zerolog.DebugLevel, &buf)
	offset := buf.Len()

	xip.logResolved(new(dns.Msg))

	lines := logLinesAfter(t, &buf, offset)
	if len(lines) != 1 {
		t.Fatalf("got %d log lines, want 1: %q", len(lines), buf.String()[offset:])
	}
	if lines[0]["message"] != "resolved" {
		t.Errorf("message = %v, want resolved", lines[0]["message"])
	}
	for _, field := range []string{"name", "type"} {
		if value, present := lines[0][field]; present {
			t.Errorf("%s = %v, want it absent", field, value)
		}
	}
}

func TestHandleDnsRequestLogsWriteFailure(t *testing.T) {
	cases := []struct {
		name   string
		domain string
		level  zerolog.Level
	}{
		{"level info", "logging-write-info.test", zerolog.InfoLevel},
		{"level debug", "logging-write-debug.test", zerolog.DebugLevel},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			xip := newLoggingXip(t, tc.domain, tc.level, &buf)
			offset := buf.Len()
			name := "10-11-12-13." + tc.domain + "."

			writer := &recordingWriter{err: errors.New("socket is gone")}
			xip.handleDnsRequest(writer, newQuery(name, dns.TypeA))
			assertOneWrite(t, writer)

			lines := logLinesAfter(t, &buf, offset)
			if len(lines) != 1 {
				t.Fatalf("got %d log lines, want 1: %q", len(lines), buf.String()[offset:])
			}
			want := map[string]string{
				"level":   "error",
				"message": "Error responding to query",
				"error":   "socket is gone",
				"name":    name,
				"type":    "A",
			}
			for field, value := range want {
				if lines[0][field] != value {
					t.Errorf("%s = %v, want %s", field, lines[0][field], value)
				}
			}
			for field := range lines[0] {
				if _, expected := want[field]; !expected && field != "time" {
					t.Errorf("unexpected field %s = %v", field, lines[0][field])
				}
			}
		})
	}
}

func TestLogResolvedComputesNothingAtInfo(t *testing.T) {
	var buf bytes.Buffer
	xip := newLoggingXip(t, "logging-guard.test", zerolog.InfoLevel, &buf)
	offset := buf.Len()

	// Formatting a nil record panics, so this fails if any answer is formatted before the debug guard.
	message := &dns.Msg{Answer: []dns.RR{nil}}
	xip.logResolved(message)

	if logged := buf.String()[offset:]; logged != "" {
		t.Errorf("level info logged %q, want nothing", logged)
	}
}

func TestLogResolvedUnknownRcode(t *testing.T) {
	var buf bytes.Buffer
	xip := newLoggingXip(t, "logging-rcode.test", zerolog.DebugLevel, &buf)
	offset := buf.Len()

	const rcode = 3841
	if _, known := dns.RcodeToString[rcode]; known {
		t.Fatalf("rcode %d has a name, pick one that does not", rcode)
	}
	message := new(dns.Msg)
	message.Rcode = rcode
	xip.logResolved(message)

	lines := logLinesAfter(t, &buf, offset)
	if len(lines) != 1 {
		t.Fatalf("got %d log lines, want 1: %q", len(lines), buf.String()[offset:])
	}
	if want := "RCODE3841"; lines[0]["rcode"] != want {
		t.Errorf("rcode = %v, want %s", lines[0]["rcode"], want)
	}
}

func TestHandleDnsRequestLogsWriteFailureWithoutQuestion(t *testing.T) {
	var buf bytes.Buffer
	xip := newLoggingXip(t, "logging-write-no-question.test", zerolog.DebugLevel, &buf)
	offset := buf.Len()

	request := new(dns.Msg)
	request.Opcode = dns.OpcodeNotify
	writer := &recordingWriter{err: errors.New("socket is gone")}
	xip.handleDnsRequest(writer, request)
	assertOneWrite(t, writer)

	lines := logLinesAfter(t, &buf, offset)
	if len(lines) != 1 {
		t.Fatalf("got %d log lines, want 1: %q", len(lines), buf.String()[offset:])
	}
	want := map[string]string{
		"level":   "error",
		"message": "Error responding to query",
		"error":   "socket is gone",
	}
	for field, value := range want {
		if lines[0][field] != value {
			t.Errorf("%s = %v, want %s", field, lines[0][field], value)
		}
	}
	for _, field := range []string{"name", "type"} {
		if value, present := lines[0][field]; present {
			t.Errorf("%s = %v, want it absent", field, value)
		}
	}
}

func TestHandleDnsRequestWritesBeforeLogging(t *testing.T) {
	var buf bytes.Buffer
	xip := newLoggingXip(t, "logging-order.test", zerolog.DebugLevel, &buf)
	offset := buf.Len()

	lengthAtWrite := -1
	writer := &recordingWriter{onWrite: func() { lengthAtWrite = buf.Len() }}
	xip.handleDnsRequest(writer, newQuery("10-11-12-13.logging-order.test.", dns.TypeA))
	assertOneWrite(t, writer)

	if lengthAtWrite != offset {
		t.Errorf("log held %d bytes when the response was written, want %d", lengthAtWrite, offset)
	}
	lines := logLinesAfter(t, &buf, offset)
	if len(lines) != 1 || lines[0]["message"] != "resolved" {
		t.Errorf("after the handler returned the log holds %v, want one resolved line", lines)
	}
}

func BenchmarkHandleDnsRequest(b *testing.B) {
	queries := []struct {
		name  string
		label string
		qtype uint16
	}{
		{"matching dashed A", "app.10-11-12-13", dns.TypeA},
		{"matching dotted A with prefix", "foo.bar.10.11.12.13", dns.TypeA},
		{"unknown name A", "nope", dns.TypeA},
		{"AAAA of a dashed name", "app.10-11-12-13", dns.TypeAAAA},
	}
	levels := []zerolog.Level{zerolog.InfoLevel, zerolog.DebugLevel}

	for _, query := range queries {
		for _, level := range levels {
			b.Run(query.name+"/"+level.String(), func(b *testing.B) {
				domain := "logging-bench.test"
				xip := newLoggingXip(b, domain, level, io.Discard)
				request := newQuery(query.label+"."+domain+".", query.qtype)
				writer := &discardWriter{}
				b.ReportAllocs()
				for b.Loop() {
					xip.handleDnsRequest(writer, request)
				}
			})
		}
	}
}
