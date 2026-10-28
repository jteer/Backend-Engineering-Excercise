package ndjson

import (
	"bufio"
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"log-exercise/internal/model"
)

var fixedNow = time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)

func newJSONParser() *Parser {
	return &Parser{Now: func() time.Time { return fixedNow }}
}

func deref(s *string) string {
	if s == nil {
		return "<nil>"
	}
	return *s
}

// loadSample returns a samples/json file minified to a single line.
func loadSample(t *testing.T, name string) []byte {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "..", "samples", "json", name))
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	if err := json.Compact(&buf, raw); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// The provided expected/sample-output.ndjson covers samples 1 and 2.
func TestNDJSON_GoldenAgainstExpected(t *testing.T) {
	f, err := os.Open(filepath.Join("..", "..", "..", "expected", "sample-output.ndjson"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	var want []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if l := strings.TrimSpace(sc.Text()); l != "" {
			want = append(want, l)
		}
	}

	for i, name := range []string{"sample-1.json", "sample-2.json"} {
		ev, err := newJSONParser().Parse(loadSample(t, name))
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		got, err := json.Marshal(ev)
		if err != nil {
			t.Fatal(err)
		}
		if string(got) != want[i] {
			t.Errorf("%s\n got: %s\nwant: %s", name, got, want[i])
		}
	}
}

func TestNDJSON_Sample3_ProcessCreation(t *testing.T) {
	ev, err := newJSONParser().Parse(loadSample(t, "sample-3.json"))
	if err != nil {
		t.Fatal(err)
	}
	got, _ := json.Marshal(ev)
	// source.ip comes from the OpenWEC fallback (EventData has no IpAddress);
	// user.name is the Subject because TargetUserName is "-".
	want := `{"@timestamp":"2026-02-14T16:06:51.064Z","event.type":"start","event.category":"process","event.outcome":"success","source.ip":"192.168.1.10","user.name":"DC01$","host.name":"dc01.contoso.local","log.level":"info","message":"A new process has been created."}`
	if string(got) != want {
		t.Errorf("\n got: %s\nwant: %s", got, want)
	}
}

func TestNDJSON_Mapping(t *testing.T) {
	type want struct {
		ts       string
		typ      model.EventType
		cat      model.EventCategory
		outcome  model.EventOutcome
		ip, user string
		host     string
		level    string
		msg      string
	}
	tests := []struct {
		name string
		in   string
		want want
	}{
		{
			name: "logon success, all fields",
			in: `{"System":{"EventID":4624,"TimeCreated":"2026-02-14T14:22:10.8831200Z","Computer":"dc01"},
			"EventData":{"TargetUserName":"jsmith","SubjectUserName":"-","IpAddress":"10.0.50.42"},
			"RenderingInfo":{"Message":"hi","Level":"Information","Keywords":["Audit Success"]},
			"OpenWEC":{"IpAddress":"192.168.1.10"}}`,
			want: want{"2026-02-14T14:22:10.883Z", "start", "authentication", "success", "10.0.50.42", "jsmith", "dc01", "info", "hi"},
		},
		{
			name: "4625 failed logon is start/authentication/failure",
			in: `{"System":{"EventID":4625,"TimeCreated":"2026-02-14T15:45:33Z","Computer":"h"},
			"EventData":{"TargetUserName":"admin","SubjectUserName":"-"},
			"RenderingInfo":{"Message":"m","Level":"Information","Keywords":["Audit Failure"]}}`,
			want: want{"2026-02-14T15:45:33.000Z", "start", "authentication", "failure", "<nil>", "admin", "h", "info", "m"},
		},
		{
			name: "4634 logoff",
			in:   `{"System":{"EventID":4634,"TimeCreated":"2026-02-14T15:45:33Z"},"RenderingInfo":{"Message":"m","Keywords":["Audit Success"]}}`,
			want: want{"2026-02-14T15:45:33.000Z", "end", "authentication", "success", "<nil>", "<nil>", "<nil>", "<nil>", "m"},
		},
		{
			name: "4647 logoff",
			in:   `{"System":{"EventID":4647,"TimeCreated":"2026-02-14T15:45:33Z"}}`,
			want: want{"2026-02-14T15:45:33.000Z", "end", "authentication", "unknown", "<nil>", "<nil>", "<nil>", "<nil>", "Windows Event 4647"},
		},
		{
			name: "4648 explicit credentials logon",
			in:   `{"System":{"EventID":4648,"TimeCreated":"2026-02-14T15:45:33Z"}}`,
			want: want{"2026-02-14T15:45:33.000Z", "start", "authentication", "unknown", "<nil>", "<nil>", "<nil>", "<nil>", "Windows Event 4648"},
		},
		{
			name: "4689 process end",
			in:   `{"System":{"EventID":4689,"TimeCreated":"2026-02-14T15:45:33Z"}}`,
			want: want{"2026-02-14T15:45:33.000Z", "end", "process", "unknown", "<nil>", "<nil>", "<nil>", "<nil>", "Windows Event 4689"},
		},
		{
			name: "4720 user created is info/host (range start)",
			in:   `{"System":{"EventID":4720,"TimeCreated":"2026-02-14T15:45:33Z"}}`,
			want: want{"2026-02-14T15:45:33.000Z", "info", "host", "unknown", "<nil>", "<nil>", "<nil>", "<nil>", "Windows Event 4720"},
		},
		{
			name: "4767 is info/host (range end)",
			in:   `{"System":{"EventID":4767,"TimeCreated":"2026-02-14T15:45:33Z"}}`,
			want: want{"2026-02-14T15:45:33.000Z", "info", "host", "unknown", "<nil>", "<nil>", "<nil>", "<nil>", "Windows Event 4767"},
		},
		{
			name: "unknown event id defaults to info/host",
			in:   `{"System":{"EventID":9999,"TimeCreated":"2026-02-14T15:45:33Z"}}`,
			want: want{"2026-02-14T15:45:33.000Z", "info", "host", "unknown", "<nil>", "<nil>", "<nil>", "<nil>", "Windows Event 9999"},
		},
		{
			name: "event id as string",
			in:   `{"System":{"EventID":"4688","TimeCreated":"2026-02-14T15:45:33Z"}}`,
			want: want{"2026-02-14T15:45:33.000Z", "start", "process", "unknown", "<nil>", "<nil>", "<nil>", "<nil>", "Windows Event 4688"},
		},
		{
			name: "event id as object with #text",
			in:   `{"System":{"EventID":{"#text":"4688","Qualifiers":"0"},"TimeCreated":"2026-02-14T15:45:33Z"}}`,
			want: want{"2026-02-14T15:45:33.000Z", "start", "process", "unknown", "<nil>", "<nil>", "<nil>", "<nil>", "Windows Event 4688"},
		},
		{
			name: "missing event id falls through to defaults",
			in:   `{"System":{"TimeCreated":"2026-02-14T15:45:33Z"}}`,
			want: want{"2026-02-14T15:45:33.000Z", "info", "host", "unknown", "<nil>", "<nil>", "<nil>", "<nil>", "Windows Event 0"},
		},
		{
			name: "keywords as plain string",
			in:   `{"System":{"EventID":4624,"TimeCreated":"2026-02-14T15:45:33Z"},"RenderingInfo":{"Message":"m","Keywords":"Audit Failure"}}`,
			want: want{"2026-02-14T15:45:33.000Z", "start", "authentication", "failure", "<nil>", "<nil>", "<nil>", "<nil>", "m"},
		},
		{
			name: "keywords with both markers: failure wins",
			in:   `{"System":{"EventID":4624,"TimeCreated":"2026-02-14T15:45:33Z"},"RenderingInfo":{"Message":"m","Keywords":["Audit Success","Audit Failure"]}}`,
			want: want{"2026-02-14T15:45:33.000Z", "start", "authentication", "failure", "<nil>", "<nil>", "<nil>", "<nil>", "m"},
		},
		{
			name: "unrecognized keywords -> unknown",
			in:   `{"System":{"EventID":4624,"TimeCreated":"2026-02-14T15:45:33Z"},"RenderingInfo":{"Message":"m","Keywords":["Classic"]}}`,
			want: want{"2026-02-14T15:45:33.000Z", "start", "authentication", "unknown", "<nil>", "<nil>", "<nil>", "<nil>", "m"},
		},
		{
			name: "EventData IpAddress '-' omits ip and does NOT fall back to OpenWEC",
			in: `{"System":{"EventID":4624,"TimeCreated":"2026-02-14T15:45:33Z"},
			"EventData":{"IpAddress":"-"},"OpenWEC":{"IpAddress":"192.168.1.10"}}`,
			want: want{"2026-02-14T15:45:33.000Z", "start", "authentication", "unknown", "<nil>", "<nil>", "<nil>", "<nil>", "Windows Event 4624"},
		},
		{
			name: "EventData IpAddress empty omits ip",
			in:   `{"System":{"EventID":4624,"TimeCreated":"2026-02-14T15:45:33Z"},"EventData":{"IpAddress":""}}`,
			want: want{"2026-02-14T15:45:33.000Z", "start", "authentication", "unknown", "<nil>", "<nil>", "<nil>", "<nil>", "Windows Event 4624"},
		},
		{
			name: "no EventData IpAddress key falls back to OpenWEC",
			in:   `{"System":{"EventID":4688,"TimeCreated":"2026-02-14T15:45:33Z"},"EventData":{},"OpenWEC":{"IpAddress":"192.168.1.10"}}`,
			want: want{"2026-02-14T15:45:33.000Z", "start", "process", "unknown", "192.168.1.10", "<nil>", "<nil>", "<nil>", "Windows Event 4688"},
		},
		{
			name: "IPv6 source",
			in:   `{"System":{"EventID":4624,"TimeCreated":"2026-02-14T15:45:33Z"},"EventData":{"IpAddress":"::1"}}`,
			want: want{"2026-02-14T15:45:33.000Z", "start", "authentication", "unknown", "::1", "<nil>", "<nil>", "<nil>", "Windows Event 4624"},
		},
		{
			name: "invalid IP omitted",
			in:   `{"System":{"EventID":4624,"TimeCreated":"2026-02-14T15:45:33Z"},"EventData":{"IpAddress":"not-an-ip"}}`,
			want: want{"2026-02-14T15:45:33.000Z", "start", "authentication", "unknown", "<nil>", "<nil>", "<nil>", "<nil>", "Windows Event 4624"},
		},
		{
			name: "target user preferred; subject used when target is '-'",
			in:   `{"System":{"EventID":4688,"TimeCreated":"2026-02-14T15:45:33Z"},"EventData":{"TargetUserName":"-","SubjectUserName":"SYSTEM"}}`,
			want: want{"2026-02-14T15:45:33.000Z", "start", "process", "unknown", "<nil>", "SYSTEM", "<nil>", "<nil>", "Windows Event 4688"},
		},
		{
			name: "both users sentinel/empty -> omitted",
			in:   `{"System":{"EventID":4688,"TimeCreated":"2026-02-14T15:45:33Z"},"EventData":{"TargetUserName":" - ","SubjectUserName":""}}`,
			want: want{"2026-02-14T15:45:33.000Z", "start", "process", "unknown", "<nil>", "<nil>", "<nil>", "<nil>", "Windows Event 4688"},
		},
		{
			name: "level mapping: Warning, Error, Verbose, unknown passthrough",
			in:   `{"System":{"EventID":1,"TimeCreated":"2026-02-14T15:45:33Z"},"RenderingInfo":{"Level":"Warning"}}`,
			want: want{"2026-02-14T15:45:33.000Z", "info", "host", "unknown", "<nil>", "<nil>", "<nil>", "warning", "Windows Event 1"},
		},
		{
			name: "TimeCreated as object",
			in:   `{"System":{"EventID":1,"TimeCreated":{"SystemTime":"2026-02-14T15:45:33.5Z"}}}`,
			want: want{"2026-02-14T15:45:33.500Z", "info", "host", "unknown", "<nil>", "<nil>", "<nil>", "<nil>", "Windows Event 1"},
		},
		{
			name: "TimeCreated as #attributes object",
			in:   `{"System":{"EventID":1,"TimeCreated":{"#attributes":{"SystemTime":"2026-02-14T15:45:33Z"}}}}`,
			want: want{"2026-02-14T15:45:33.000Z", "info", "host", "unknown", "<nil>", "<nil>", "<nil>", "<nil>", "Windows Event 1"},
		},
		{
			name: "non-UTC offset converted to UTC",
			in:   `{"System":{"EventID":1,"TimeCreated":"2026-02-14T10:45:33-05:00"}}`,
			want: want{"2026-02-14T15:45:33.000Z", "info", "host", "unknown", "<nil>", "<nil>", "<nil>", "<nil>", "Windows Event 1"},
		},
		{
			name: "zone-less timestamp treated as UTC",
			in:   `{"System":{"EventID":1,"TimeCreated":"2026-02-14T15:45:33.25"}}`,
			want: want{"2026-02-14T15:45:33.250Z", "info", "host", "unknown", "<nil>", "<nil>", "<nil>", "<nil>", "Windows Event 1"},
		},
		{
			name: "bad TimeCreated falls back to OpenWEC.TimeReceived",
			in:   `{"System":{"EventID":1,"TimeCreated":"garbage"},"OpenWEC":{"TimeReceived":"2026-02-14T14:23:01.112+00:00"}}`,
			want: want{"2026-02-14T14:23:01.112Z", "info", "host", "unknown", "<nil>", "<nil>", "<nil>", "<nil>", "Windows Event 1"},
		},
		{
			name: "no usable timestamp falls back to Now",
			in:   `{"System":{"EventID":1}}`,
			want: want{"2026-01-02T03:04:05.000Z", "info", "host", "unknown", "<nil>", "<nil>", "<nil>", "<nil>", "Windows Event 1"},
		},
		{
			name: "case-insensitive keys",
			in:   `{"system":{"eventid":4624,"timecreated":"2026-02-14T15:45:33Z","computer":"h"}}`,
			want: want{"2026-02-14T15:45:33.000Z", "start", "authentication", "unknown", "<nil>", "<nil>", "h", "<nil>", "Windows Event 4624"},
		},
		{
			name: "non-string EventData values are tolerated",
			in:   `{"System":{"EventID":4624,"TimeCreated":"2026-02-14T15:45:33Z"},"EventData":{"TargetUserName":42,"IpAddress":{"x":1}}}`,
			want: want{"2026-02-14T15:45:33.000Z", "start", "authentication", "unknown", "<nil>", "42", "<nil>", "<nil>", "Windows Event 4624"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ev, err := newJSONParser().Parse([]byte(tt.in))
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			got := want{
				ts:      ev.Timestamp.UTC().Format("2006-01-02T15:04:05.000Z"),
				typ:     ev.EventType,
				cat:     ev.EventCategory,
				outcome: ev.EventOutcome,
				ip:      deref(ev.SourceIP),
				user:    deref(ev.UserName),
				host:    deref(ev.HostName),
				level:   deref(ev.LogLevel),
				msg:     ev.Message,
			}
			if got != tt.want {
				t.Errorf("\n got: %+v\nwant: %+v", got, tt.want)
			}
		})
	}
}

func TestNDJSON_Malformed(t *testing.T) {
	tests := []struct{ name, in string }{
		{"not json", `{not json`},
		{"truncated", `{"System":{"EventID":4624,"TimeCreated":"2026-02`},
		{"empty object has no System", `{}`},
		{"System is not an object", `{"System":"nope"}`},
		{"json null", `null`},
		{"json array", `[{"System":{}}]`},
		{"json scalar", `42`},
		{"trailing data", `{"System":{}} {"System":{}}`},
		{"trailing garbage", `{"System":{}} xyz`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ev, err := newJSONParser().Parse([]byte(tt.in))
			if err == nil {
				t.Fatalf("expected error, got event %+v", ev)
			}
			if ev != nil {
				t.Errorf("expected nil event on error, got %+v", ev)
			}
		})
	}
}

func TestNDJSON_NilNowDefaultsToWallClock(t *testing.T) {
	p := &Parser{} // as constructed in cmd/main.go
	ev, err := p.Parse([]byte(`{"System":{"EventID":1}}`))
	if err != nil {
		t.Fatal(err)
	}
	if d := time.Since(ev.Timestamp); d < 0 || d > time.Minute {
		t.Errorf("timestamp not ~now: %v", ev.Timestamp)
	}
}

func BenchmarkNDJSONParse(b *testing.B) {
	line, err := os.ReadFile(filepath.Join("..", "..", "..", "samples", "json", "sample-1.json"))
	if err != nil {
		b.Fatal(err)
	}
	var buf bytes.Buffer
	_ = json.Compact(&buf, line)
	p := newJSONParser()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := p.Parse(buf.Bytes()); err != nil {
			b.Fatal(err)
		}
	}
}
