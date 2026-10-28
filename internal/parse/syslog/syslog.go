// Package syslog parses RFC 3164 syslog lines, including CEF payloads, into
// normalized events.
package syslog

import (
	"errors"
	"fmt"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"log-exercise/internal/model"
)

// Parser parses RFC 3164 syslog lines, including a CEF payload if one
// is present, into a normalized Event.
// Decisions/Assumptions based on SCHEMA.md:
//   - RFC 3164 timestamps have no year or zone: the year is inferred from Now
//     and the zone is assumed UTC. If no timestamp can be read, Now is used, per the spec, and
//     the remainder of the line becomes the message.
//   - log.level comes from the syslog severity in PRI, not the CEF severity.
//     The spec's examples (6 info, 4 warning, 3 error) are syslog severities;
//     CEF's scale is 0-10 and its "1" would read as syslog "alert" for a
//     routine logon.
//   - message prefers the CEF msg extension, then the CEF name, then the raw
//     message text.
//   - Per the spec's ordering, CEF act=allow/deny decides event.type before
//     any auth context. So a successful logon with act=allow is "allowed",
//     whereas the same event as Windows JSON is "start".
type Parser struct {
	Now func() time.Time // defaults to time.Now; injectable for tests
}

func (p *Parser) now() time.Time {
	if p.Now != nil {
		return p.Now()
	}
	return time.Now()
}

func (p *Parser) Parse(line []byte) (*model.Event, error) {
	s := strings.TrimSpace(string(line))
	pri, rest, err := parsePRI(s)
	if err != nil {
		return nil, err
	}

	now := p.now().UTC()
	ts, host, msg := splitHeader(rest, now)
	if msg == "" {
		return nil, errors.New("syslog message is empty")
	}

	var (
		f       facts
		ext     map[string]string
		message = msg
	)
	if rec, ok := parseCEF(msg); ok {
		ext = rec.Ext
		f = facts{
			class:      strings.ToLower(rec.Class),
			name:       strings.ToLower(rec.Name),
			msg:        strings.ToLower(ext["msg"]),
			act:        strings.ToLower(ext["act"]),
			outcomeExt: strings.ToLower(ext["outcome"]),
		}
		if isMicrosoft(rec) {
			if id, err := strconv.Atoi(strings.TrimSpace(rec.Class)); err == nil {
				f.winID = id
			}
		}
		message = model.FirstNonEmpty(model.Clean(ext["msg"]), model.Clean(rec.Name), msg)
	} else {
		f = facts{msg: strings.ToLower(msg)}
		ext = parseExtension(msg)
	}

	cat := categoryOf(f)
	return &model.Event{
		Timestamp:     ts,
		EventType:     typeOf(f, cat),
		EventCategory: cat,
		EventOutcome:  outcomeOf(f),
		SourceIP:      model.Str(validIP(ext["src"])),
		UserName:      model.Str(model.FirstNonEmpty(model.Clean(ext["suser"]), model.Clean(ext["duser"]))),
		HostName:      model.Str(model.Clean(host)),
		LogLevel:      model.Str(syslogLevel(pri)),
		Message:       message,
	}, nil
}

func isMicrosoft(rec *cefRecord) bool {
	vp := strings.ToLower(rec.Vendor + " " + rec.Product)
	return strings.Contains(vp, "microsoft") || strings.Contains(vp, "windows")
}

func validIP(s string) string {
	s = model.Clean(s)
	if _, err := netip.ParseAddr(s); err != nil {
		return ""
	}
	return s
}

// parsePRI reads the leading "<N>" (0-191) and returns N and the remainder.
func parsePRI(s string) (int, string, error) {
	if len(s) == 0 || s[0] != '<' {
		return 0, "", errors.New("not syslog: missing <PRI> prefix")
	}
	end := strings.IndexByte(s, '>')
	if end < 2 || end > 4 {
		return 0, "", errors.New("invalid syslog priority")
	}
	digits := s[1:end]
	for i := range len(digits) {
		if digits[i] < '0' || digits[i] > '9' {
			return 0, "", errors.New("invalid syslog priority")
		}
	}
	n, _ := strconv.Atoi(digits)
	if n > 191 {
		return 0, "", fmt.Errorf("invalid syslog priority %d (max 191)", n)
	}
	return n, s[end+1:], nil
}

// splitHeader reads TIMESTAMP and HOSTNAME from rest and returns what is left
// as the message.
func splitHeader(rest string, now time.Time) (ts time.Time, host, msg string) {
	if t, n, ok := parseBSDTime(rest, now); ok {
		ts, rest = t, strings.TrimLeft(rest[n:], " ")
	} else if tok, after := cutToken(rest); tok != "" {
		t, err := time.Parse(time.RFC3339Nano, tok)
		if err != nil {
			// No readable timestamp: use Now and keep everything as message.
			return now, "", strings.TrimSpace(rest)
		}
		ts, rest = t.UTC(), after
	} else {
		return now, "", ""
	}

	tok, after := cutToken(rest)
	if strings.HasPrefix(tok, "CEF:") { // no hostname field
		return ts, "", strings.TrimSpace(rest)
	}
	return ts, tok, strings.TrimSpace(after)
}

// parseBSDTime parses "Mmm dd hh:mm:ss" (day zero- or space-padded) at the
// start of s, returning the time and the number of bytes consumed.
func parseBSDTime(s string, now time.Time) (time.Time, int, bool) {
	const n = len("Dec 05 10:30:45")
	if len(s) < n || (len(s) > n && s[n] != ' ') {
		return time.Time{}, 0, false
	}
	// Try this year, then earlier ones: handles the Dec->Jan rollover and
	// Feb 29 (which only parses in a leap year).
	for y := now.Year(); y > now.Year()-5; y-- {
		t, err := time.Parse("2006 Jan _2 15:04:05", strconv.Itoa(y)+" "+s[:n])
		if err != nil {
			continue
		}
		if t.After(now.Add(24 * time.Hour)) { // allow modest clock skew
			continue
		}
		return t, n, true
	}
	return time.Time{}, 0, false
}

// cutToken splits off the first space-delimited token.
func cutToken(s string) (tok, rest string) {
	s = strings.TrimLeft(s, " ")
	i := strings.IndexByte(s, ' ')
	if i < 0 {
		return s, ""
	}
	return s[:i], s[i+1:]
}
