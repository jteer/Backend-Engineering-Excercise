package syslog

import (
	"strings"
)

// CEF:Version|Device Vendor|Device Product|Device Version|Device Event Class ID|Name|Severity|Extension
type cefRecord struct {
	Version    string
	Vendor     string
	Product    string
	DevVersion string
	Class      string
	Name       string
	Severity   string
	Ext        map[string]string
}

// parseCEF looks for a CEF header anywhere in msg and parses it.
// ok is false when msg has no complete 7-field header, e.g. when it is truncated.
func parseCEF(msg string) (rec *cefRecord, ok bool) {
	i := strings.Index(msg, "CEF:")
	if i < 0 {
		return nil, false
	}
	body := msg[i+len("CEF:"):]

	// The header is 7 fields, each terminated by an unescaped '|'. Inside a
	// header field, "\|" is a literal pipe and "\\" a literal backslash.
	fields := make([]string, 0, 7)
	var cur strings.Builder
	k := 0
	for ; k < len(body) && len(fields) < 7; k++ {
		c := body[k]
		switch {
		case c == '\\' && k+1 < len(body) && (body[k+1] == '|' || body[k+1] == '\\'):
			cur.WriteByte(body[k+1])
			k++
		case c == '|':
			fields = append(fields, cur.String())
			cur.Reset()
		default:
			cur.WriteByte(c)
		}
	}
	if len(fields) < 7 {
		return nil, false
	}
	return &cefRecord{
		Version:    fields[0],
		Vendor:     fields[1],
		Product:    fields[2],
		DevVersion: fields[3],
		Class:      fields[4],
		Name:       fields[5],
		Severity:   fields[6],
		Ext:        parseExtension(body[k:]),
	}, true
}

// parseExtension splits a CEF extension string into key/value pairs.
//
// Values may contain spaces ("msg=An account was logged on act=allow"), so a
// plain split on whitespace is wrong. Instead a new pair starts wherever a
// key-shaped token followed by '=' appears at the start of the string or
// after a space; a value runs until the next such token. Inside values,
// "\=", "\\", "\n" and "\r" are unescaped. Text before the first key is
// ignored, which also lets this be used on non-CEF "free text key=value" lines.
//
// This is inherently ambiguous when a value itself contains " word=" (the CEF
// spec requires senders to escape '=' in values, and we honor that).
func parseExtension(s string) map[string]string {
	type mark struct{ keyStart, keyEnd int }
	var marks []mark
	for i := 0; i < len(s); {
		if i == 0 || s[i-1] == ' ' {
			j := i
			for j < len(s) && isKeyChar(s[j]) {
				j++
			}
			if j > i && j < len(s) && s[j] == '=' {
				marks = append(marks, mark{i, j})
				i = j + 1
				continue
			}
		}
		if s[i] == '\\' && i+1 < len(s) { // skip escaped char, e.g. "\="
			i += 2
			continue
		}
		i++
	}

	out := make(map[string]string, len(marks))
	for n, m := range marks {
		end := len(s)
		if n+1 < len(marks) {
			end = marks[n+1].keyStart
		}
		out[s[m.keyStart:m.keyEnd]] = unescapeExt(strings.TrimSpace(s[m.keyEnd+1 : end]))
	}
	return out
}

func isKeyChar(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '.'
}

func unescapeExt(v string) string {
	if !strings.Contains(v, `\`) {
		return v
	}
	var b strings.Builder
	for i := 0; i < len(v); i++ {
		if v[i] == '\\' && i+1 < len(v) {
			switch v[i+1] {
			case '=', '\\':
				b.WriteByte(v[i+1])
				i++
				continue
			case 'n':
				b.WriteByte('\n')
				i++
				continue
			case 'r':
				b.WriteByte('\r')
				i++
				continue
			}
		}
		b.WriteByte(v[i])
	}
	return b.String()
}
