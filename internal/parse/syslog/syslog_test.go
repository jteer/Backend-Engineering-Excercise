package syslog

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"log-exercise/internal/model"
)

// Dec 6 2026, so the samples' "Dec 05" resolves to 2026.
var syslogNow = time.Date(2026, 12, 6, 12, 0, 0, 0, time.UTC)

func deref(s *string) string {
	if s == nil {
		return "<nil>"
	}
	return *s
}

func newSyslogParser(now time.Time) *Parser {
	return &Parser{Now: func() time.Time { return now }}
}

func loadSyslogSample(t *testing.T, name string) []byte {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "..", "samples", "syslog", name))
	if err != nil {
		t.Fatal(err)
	}
	return []byte(strings.TrimSpace(string(raw)))
}

func TestSyslog_Samples(t *testing.T) {
	tests := []struct{ file, want string }{
		{"sample-1.log", `{"@timestamp":"2026-12-05T10:30:45.000Z","event.type":"allowed","event.category":"authentication","event.outcome":"success","source.ip":"10.0.50.42","user.name":"jsmith","host.name":"192.168.1.1","log.level":"info","message":"An account was successfully logged on"}`},
		{"sample-2.log", `{"@timestamp":"2026-12-05T10:35:22.000Z","event.type":"denied","event.category":"authentication","event.outcome":"failure","source.ip":"10.99.0.55","user.name":"admin","host.name":"192.168.1.1","log.level":"notice","message":"An account failed to log on"}`},
		{"sample-3.log", `{"@timestamp":"2026-12-05T10:40:15.000Z","event.type":"allowed","event.category":"network","event.outcome":"success","source.ip":"192.168.1.100","user.name":"jdoe","host.name":"192.168.1.1","log.level":"info","message":"Connection allowed"}`},
	}
	for _, tt := range tests {
		t.Run(tt.file, func(t *testing.T) {
			ev, err := newSyslogParser(syslogNow).Parse(loadSyslogSample(t, tt.file))
			if err != nil {
				t.Fatal(err)
			}
			got, _ := json.Marshal(ev)
			if string(got) != tt.want {
				t.Errorf("\n got: %s\nwant: %s", got, tt.want)
			}
		})
	}
}

func TestSyslog_Mapping(t *testing.T) {
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
	const n = "<134>Dec 05 10:30:45 h1 " // prefix used by most cases
	nilp := "<nil>"
	tests := []struct {
		name string
		now  time.Time // zero => syslogNow
		in   string
		want want
	}{
		// --- timestamps
		{name: "space-padded single-digit day",
			in:   "<134>Dec  5 10:30:45 h1 hello",
			want: want{"2026-12-05T10:30:45.000Z", "info", "host", "unknown", nilp, nilp, "h1", "info", "hello"}},
		{name: "year rolls back across new year",
			now:  time.Date(2027, 1, 2, 0, 0, 0, 0, time.UTC),
			in:   "<134>Dec 31 23:59:59 h1 hello",
			want: want{"2026-12-31T23:59:59.000Z", "info", "host", "unknown", nilp, nilp, "h1", "info", "hello"}},
		{name: "small clock skew into the future is kept in current year",
			now:  time.Date(2026, 12, 5, 10, 0, 0, 0, time.UTC),
			in:   "<134>Dec 05 10:30:45 h1 hello",
			want: want{"2026-12-05T10:30:45.000Z", "info", "host", "unknown", nilp, nilp, "h1", "info", "hello"}},
		{name: "feb 29 resolves to the most recent leap year",
			now:  time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC),
			in:   "<134>Feb 29 01:02:03 h1 hello",
			want: want{"2024-02-29T01:02:03.000Z", "info", "host", "unknown", nilp, nilp, "h1", "info", "hello"}},
		{name: "rfc3339 timestamp converted to UTC",
			in:   "<134>2026-12-05T05:30:45.5-05:00 h1 hello",
			want: want{"2026-12-05T10:30:45.500Z", "info", "host", "unknown", nilp, nilp, "h1", "info", "hello"}},
		{name: "unreadable timestamp uses Now and keeps the line as message",
			in:   "<134>Xyz 99 10:30:45 h1 hello",
			want: want{"2026-12-06T12:00:00.000Z", "info", "host", "unknown", nilp, nilp, nilp, "info", "Xyz 99 10:30:45 h1 hello"}},
		{name: "truncated timestamp uses Now",
			in:   "<134>Dec 05 10:3",
			want: want{"2026-12-06T12:00:00.000Z", "info", "host", "unknown", nilp, nilp, nilp, "info", "Dec 05 10:3"}},
		{name: "CRLF terminated",
			in:   n + "hello\r\n",
			want: want{"2026-12-05T10:30:45.000Z", "info", "host", "unknown", nilp, nilp, "h1", "info", "hello"}},

		// --- priority -> log.level
		{name: "pri 0 emergency", in: "<0>Dec 05 10:30:45 h1 x",
			want: want{"2026-12-05T10:30:45.000Z", "info", "host", "unknown", nilp, nilp, "h1", "emergency", "x"}},
		{name: "pri 27 error", in: "<27>Dec 05 10:30:45 h1 x",
			want: want{"2026-12-05T10:30:45.000Z", "info", "host", "unknown", nilp, nilp, "h1", "error", "x"}},
		{name: "pri 12 warning", in: "<12>Dec 05 10:30:45 h1 x",
			want: want{"2026-12-05T10:30:45.000Z", "info", "host", "unknown", nilp, nilp, "h1", "warning", "x"}},
		{name: "pri 191 debug", in: "<191>Dec 05 10:30:45 h1 x",
			want: want{"2026-12-05T10:30:45.000Z", "info", "host", "unknown", nilp, nilp, "h1", "debug", "x"}},

		// --- CEF header/extension handling
		{name: "CEF with no hostname field",
			in:   "<134>Dec 05 10:30:45 CEF:0|V|P|1|100|The Name|3|msg=hello world src=1.2.3.4",
			want: want{"2026-12-05T10:30:45.000Z", "info", "host", "unknown", "1.2.3.4", nilp, nilp, "info", "hello world"}},
		{name: "CEF behind a tag prefix",
			in:   n + "app[123]: CEF:0|V|P|1|100|The Name|3|suser=bob msg=x",
			want: want{"2026-12-05T10:30:45.000Z", "info", "host", "unknown", nilp, "bob", "h1", "info", "x"}},
		{name: "escaped pipe in header name; message falls back to name",
			in:   n + `CEF:0|V|P|1|100|a\|b|3|src=1.2.3.4`,
			want: want{"2026-12-05T10:30:45.000Z", "info", "host", "unknown", "1.2.3.4", nilp, "h1", "info", "a|b"}},
		{name: "escaped equals and multi-word values",
			in:   n + `CEF:0|V|P|1|100|N|3|msg=a\=b c d suser=bob`,
			want: want{"2026-12-05T10:30:45.000Z", "info", "host", "unknown", nilp, "bob", "h1", "info", "a=b c d"}},
		{name: "header with fewer than 7 fields is treated as plain text",
			in:   n + "CEF:0|V|P|1|100",
			want: want{"2026-12-05T10:30:45.000Z", "info", "host", "unknown", nilp, nilp, "h1", "info", "CEF:0|V|P|1|100"}},
		{name: "invalid src ip omitted; '-' user omitted",
			in:   n + "CEF:0|V|P|1|100|N|3|src=notanip suser=-",
			want: want{"2026-12-05T10:30:45.000Z", "info", "host", "unknown", nilp, nilp, "h1", "info", "N"}},
		{name: "duser used when suser absent",
			in:   n + "CEF:0|V|P|1|100|N|3|duser=carol",
			want: want{"2026-12-05T10:30:45.000Z", "info", "host", "unknown", nilp, "carol", "h1", "info", "N"}},
		{name: "IPv6 src",
			in:   n + "CEF:0|V|P|1|100|N|3|src=2001:db8::1",
			want: want{"2026-12-05T10:30:45.000Z", "info", "host", "unknown", "2001:db8::1", nilp, "h1", "info", "N"}},

		// --- category
		{name: "microsoft 4624 is authentication even though text says 'logged on'",
			in:   n + "CEF:0|Microsoft|Windows|10|4624|x|1|msg=An account was successfully logged on",
			want: want{"2026-12-05T10:30:45.000Z", "start", "authentication", "success", nilp, nilp, "h1", "info", "An account was successfully logged on"}},
		{name: "microsoft 4688 is process",
			in:   n + "CEF:0|Microsoft|Windows|10|4688|x|1|msg=proc",
			want: want{"2026-12-05T10:30:45.000Z", "start", "process", "unknown", nilp, nilp, "h1", "info", "proc"}},
		{name: "non-microsoft numeric class is NOT treated as a windows id",
			in:   n + "CEF:0|Acme|Box|1|4624|x|1|msg=proc",
			want: want{"2026-12-05T10:30:45.000Z", "info", "host", "unknown", nilp, nilp, "h1", "info", "proc"}},
		{name: "traffic class is network",
			in:   n + "CEF:0|PAN|OS|1|TRAFFIC|x|1|msg=m",
			want: want{"2026-12-05T10:30:45.000Z", "info", "network", "unknown", nilp, nilp, "h1", "info", "m"}},
		{name: "plain message with 'connection' is network",
			in:   n + "connection from 1.2.3.4 established",
			want: want{"2026-12-05T10:30:45.000Z", "info", "network", "unknown", nilp, nilp, "h1", "info", "connection from 1.2.3.4 established"}},
		{name: "plain login message is authentication/start",
			in:   n + "user login ok",
			want: want{"2026-12-05T10:30:45.000Z", "start", "authentication", "unknown", nilp, nilp, "h1", "info", "user login ok"}},
		{name: "plain logout message is authentication/end",
			in:   n + "user bob logout",
			want: want{"2026-12-05T10:30:45.000Z", "end", "authentication", "unknown", nilp, nilp, "h1", "info", "user bob logout"}},
		{name: "plain message with key=value pairs",
			in:   n + "login failed src=10.1.1.1 suser=eve",
			want: want{"2026-12-05T10:30:45.000Z", "start", "authentication", "failure", "10.1.1.1", "eve", "h1", "info", "login failed src=10.1.1.1 suser=eve"}},

		// --- event.type from act
		{name: "act=blocked -> denied",
			in:   n + "CEF:0|V|P|1|TRAFFIC|N|3|act=blocked",
			want: want{"2026-12-05T10:30:45.000Z", "denied", "network", "failure", nilp, nilp, "h1", "info", "N"}},
		{name: "act=deny -> denied",
			in:   n + "CEF:0|V|P|1|X|N|3|act=deny",
			want: want{"2026-12-05T10:30:45.000Z", "denied", "host", "failure", nilp, nilp, "h1", "info", "N"}},
		{name: "act=ALLOW case-insensitive",
			in:   n + "CEF:0|V|P|1|X|N|3|act=ALLOW",
			want: want{"2026-12-05T10:30:45.000Z", "allowed", "host", "success", nilp, nilp, "h1", "info", "N"}},
		{name: "unknown act ignored",
			in:   n + "CEF:0|V|P|1|X|N|3|act=wibble",
			want: want{"2026-12-05T10:30:45.000Z", "info", "host", "unknown", nilp, nilp, "h1", "info", "N"}},

		// --- event.outcome
		{name: "explicit outcome=failure beats success words in text",
			in:   n + "CEF:0|V|P|1|X|N|3|msg=success outcome=failure",
			want: want{"2026-12-05T10:30:45.000Z", "info", "host", "failure", nilp, nilp, "h1", "info", "success"}},
		{name: "unsuccessful is failure not success",
			in:   n + "operation unsuccessful",
			want: want{"2026-12-05T10:30:45.000Z", "info", "host", "failure", nilp, nilp, "h1", "info", "operation unsuccessful"}},
		{name: "'denied' word is failure",
			in:   n + "access denied",
			want: want{"2026-12-05T10:30:45.000Z", "info", "host", "failure", nilp, nilp, "h1", "info", "access denied"}},
		{name: "'succeeded' is success",
			in:   n + "backup succeeded",
			want: want{"2026-12-05T10:30:45.000Z", "info", "host", "success", nilp, nilp, "h1", "info", "backup succeeded"}},
		{name: "'failover' is not a failure",
			in:   n + "failover complete",
			want: want{"2026-12-05T10:30:45.000Z", "info", "host", "unknown", nilp, nilp, "h1", "info", "failover complete"}},
		{name: "'Audit Success' text",
			in:   n + "Audit Success for object",
			want: want{"2026-12-05T10:30:45.000Z", "info", "host", "success", nilp, nilp, "h1", "info", "Audit Success for object"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			now := tt.now
			if now.IsZero() {
				now = syslogNow
			}
			ev, err := newSyslogParser(now).Parse([]byte(tt.in))
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

func TestSyslog_Malformed(t *testing.T) {
	tests := []struct{ name, in string }{
		{"empty", ``},
		{"whitespace", `   `},
		{"no priority", `Dec 05 10:30:45 h1 hello`},
		{"just a word", `hello`},
		{"truncated priority", `<13`},
		{"empty priority", `<>Dec 05 10:30:45 h1 hello`},
		{"non-numeric priority", `<abc>Dec 05 10:30:45 h1 hello`},
		{"signed priority", `<+5>Dec 05 10:30:45 h1 hello`},
		{"priority too large", `<192>Dec 05 10:30:45 h1 hello`},
		{"priority too long", `<00134>Dec 05 10:30:45 h1 hello`},
		{"priority only", `<134>`},
		{"header with no message", `<134>Dec 05 10:30:45`},
		{"host with no message", `<134>Dec 05 10:30:45 h1`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ev, err := newSyslogParser(syslogNow).Parse([]byte(tt.in))
			if err == nil {
				t.Fatalf("expected error, got %+v", ev)
			}
			if ev != nil {
				t.Errorf("expected nil event on error")
			}
		})
	}
}

func TestSyslog_NilNowDefaultsToWallClock(t *testing.T) {
	ev, err := (&Parser{}).Parse([]byte("<134>garbage-timestamp h1 hello"))
	if err != nil {
		t.Fatal(err)
	}
	if d := time.Since(ev.Timestamp); d < 0 || d > time.Minute {
		t.Errorf("timestamp not ~now: %v", ev.Timestamp)
	}
}

func TestSyslog_NeverPanicsOnJunk(t *testing.T) {
	inputs := []string{
		"<", "<1", "<1>", "<1>D", "<1>Dec", "<1>Dec 05 10:30:4", "<1>Dec 05 10:30:45 ", "<1>Dec 05 10:30:45 h CEF:",
		"<1>Dec 05 10:30:45 h CEF:0|", "<1>Dec 05 10:30:45 h CEF:0|a|b|c|d|e|f|", "<1>Dec 05 10:30:45 h CEF:0|a|b|c|d|e|f|=",
		"<1>Dec 05 10:30:45 h x=\\", "<1>Dec 05 10:30:45 h =x", "<1>Dec 05 10:30:45 h \xff\xfe", "\x00", "<1>\x00\x00",
		"<1>Dec 05 10:30:45 h CEF:0|a|b|c|d|e|f|k=v\\",
	}
	p := newSyslogParser(syslogNow)
	for _, in := range inputs {
		_, _ = p.Parse([]byte(in)) // must not panic
	}
}

func TestParseExtension(t *testing.T) {
	tests := []struct {
		name, in string
		want     map[string]string
	}{
		{"empty", "", map[string]string{}},
		{"simple", "a=1 b=2", map[string]string{"a": "1", "b": "2"}},
		{"spaces in value", "msg=hello big world act=allow", map[string]string{"msg": "hello big world", "act": "allow"}},
		{"value containing equals", "msg=a=b c", map[string]string{"msg": "a=b c"}},
		{"escaped equals", `msg=a\=b c=d`, map[string]string{"msg": "a=b", "c": "d"}},
		{"escaped backslash and newline", `msg=a\\b\nc`, map[string]string{"msg": "a\\b\nc"}},
		{"empty value", "a= b=2", map[string]string{"a": "", "b": "2"}},
		{"leading junk before first key is ignored", "junk words k=v", map[string]string{"k": "v"}},
		{"trailing spaces trimmed", "a=1   ", map[string]string{"a": "1"}},
		{"dotted and underscored keys", "x.y_z=1", map[string]string{"x.y_z": "1"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseExtension(tt.in)
			if len(got) != len(tt.want) {
				t.Fatalf("got %v want %v", got, tt.want)
			}
			for k, v := range tt.want {
				if got[k] != v {
					t.Errorf("key %q: got %q want %q (all: %v)", k, got[k], v, got)
				}
			}
		})
	}
}

func BenchmarkSyslogParse(b *testing.B) {
	line := []byte("<134>Dec 05 10:30:45 192.168.1.1 CEF:0|Microsoft|Windows|10.0|4624|An account was successfully logged on|1|src=10.0.50.42 suser=jsmith msg=An account was successfully logged on act=allow outcome=success")
	p := newSyslogParser(syslogNow)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := p.Parse(line); err != nil {
			b.Fatal(err)
		}
	}
}
