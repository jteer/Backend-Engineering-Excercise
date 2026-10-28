// Package ndjson parses Windows-Event-Log-style JSON events (one object per
// line) into normalized events.
package ndjson

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"log-exercise/internal/model"
	"log-exercise/internal/parse/winevent"
)

// Parser maps one Windows-Event-Log-style JSON object (one line of
// NDJSON) to a normalized Event.
// Decisions/Assumptions based on SCHEMA.md:
//   - The input is decoded into map[string]any rather than a struct. This
//     is a defensive choice for varying exporter output.
//   - @timestamp: set to System.TimeCreated, then OpenWEC.TimeReceived, then Now() when
//     a fallback is required.
//   - source.ip: if EventData has an IpAddress key, it alone decides (a "-"
//     there means "not applicable" and the field is omitted). Only when the key
//     is absent do we fall back to OpenWEC.IpAddress. Note that OpenWEC is the
//     collector, not the originating host.
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
	doc, err := decodeObject(line)
	if err != nil {
		return nil, err
	}
	sys := object(doc, "System")
	if sys == nil {
		return nil, errors.New("missing System object")
	}
	eventData := object(doc, "EventData")
	render := object(doc, "RenderingInfo")
	wec := object(doc, "OpenWEC")

	id := eventID(sys)

	ev := &model.Event{
		Timestamp:     p.timestamp(sys, wec),
		EventType:     winevent.EventType(id),
		EventCategory: winevent.Category(id),
		EventOutcome:  outcome(render),
		SourceIP:      model.Str(sourceIP(eventData, wec)),
		UserName:      model.Str(model.FirstNonEmpty(str(eventData, "TargetUserName"), str(eventData, "SubjectUserName"))),
		HostName:      model.Str(str(sys, "Computer")),
		LogLevel:      model.Str(logLevel(str(render, "Level"))),
		Message:       str(render, "Message"),
	}
	if ev.Message == "" {
		ev.Message = fmt.Sprintf("Windows Event %d", id)
	}
	return ev, nil
}

// decodeObject decodes exactly one JSON object from line.
func decodeObject(line []byte) (map[string]any, error) {
	dec := json.NewDecoder(bytes.NewReader(line))
	dec.UseNumber() // keep EventID,..., exact instead of float64
	var doc map[string]any
	if err := dec.Decode(&doc); err != nil {
		return nil, fmt.Errorf("invalid json: %w", err)
	}
	if doc == nil {
		return nil, errors.New("json value is null, want object")
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, errors.New("invalid json: trailing data after object")
	}
	return doc, nil
}

// get looks up key in m, exact match first, then case-insensitively.
func get(m map[string]any, key string) (any, bool) {
	if v, ok := m[key]; ok {
		return v, true
	}
	for k, v := range m {
		if strings.EqualFold(k, key) {
			return v, true
		}
	}
	return nil, false
}

// object returns m[key] as an object, or nil if absent or not an object.
func object(m map[string]any, key string) map[string]any {
	v, _ := get(m, key)
	o, _ := v.(map[string]any)
	return o
}

// str returns m[key] as a cleaned string ("" for absent, sentinel, or non-scalar).
func str(m map[string]any, key string) string {
	v, _ := get(m, key)
	return model.Clean(scalar(v))
}

func scalar(v any) string {
	switch x := v.(type) {
	case string:
		return x
	case json.Number:
		return x.String()
	case bool:
		return strconv.FormatBool(x)
	}
	return ""
}

// eventID reads System.EventID, tolerating number, numeric string, and the
// {"#text": "4624", "Qualifiers": ...} form. Returns 0 if unusable.
func eventID(sys map[string]any) int {
	v, _ := get(sys, "EventID")
	if o, ok := v.(map[string]any); ok {
		v, _ = get(o, "#text")
	}
	n, err := strconv.Atoi(strings.TrimSpace(scalar(v)))
	if err != nil {
		return 0
	}
	return n
}

func (p *Parser) timestamp(sys, wec map[string]any) time.Time {
	for _, src := range []struct {
		m   map[string]any
		key string
	}{{sys, "TimeCreated"}, {wec, "TimeReceived"}} {
		v, _ := get(src.m, src.key)
		if t, ok := parseTime(v); ok {
			return t.UTC()
		}
	}
	return p.now().UTC()
}

// parseTime accepts an RFC 3339 string (any fractional precision, e.g. the
// 7-digit Windows form), a zone-less ISO string (treated as UTC), or an object
// holding one under SystemTime / @SystemTime / #text / #attributes.
func parseTime(v any) (time.Time, bool) {
	switch x := v.(type) {
	case string:
		s := strings.TrimSpace(x)
		if t, err := time.Parse(time.RFC3339Nano, s); err == nil {
			return t, true
		}
		if t, err := time.Parse("2006-01-02T15:04:05.999999999", s); err == nil {
			return t, true // no zone given: assume UTC
		}
	case map[string]any:
		for _, k := range []string{"SystemTime", "@SystemTime", "#text", "#attributes"} {
			if inner, ok := get(x, k); ok {
				if t, ok := parseTime(inner); ok {
					return t, true
				}
			}
		}
	}
	return time.Time{}, false
}

// outcome maps RenderingInfo.Keywords, array or string, to event.outcome.
func outcome(render map[string]any) model.EventOutcome {
	v, _ := get(render, "Keywords")
	var kw string
	switch x := v.(type) {
	case string:
		kw = x
	case []any:
		parts := make([]string, 0, len(x))
		for _, e := range x {
			parts = append(parts, scalar(e))
		}
		kw = strings.Join(parts, " ")
	}
	kw = strings.ToLower(kw)
	switch {
	case strings.Contains(kw, "audit failure"):
		return model.OutcomeFailure
	case strings.Contains(kw, "audit success"):
		return model.OutcomeSuccess
	}
	return model.OutcomeUnknown
}

// sourceIP implements the EventData-then-OpenWEC rule described on the type.
// Values that are not valid IP addresses are omitted.
func sourceIP(eventData, wec map[string]any) string {
	var raw string
	if v, ok := get(eventData, "IpAddress"); ok {
		raw = model.Clean(scalar(v))
	} else {
		raw = str(wec, "IpAddress")
	}
	if raw == "" {
		return ""
	}
	if _, err := netip.ParseAddr(raw); err != nil {
		return ""
	}
	return raw
}

// logLevel maps Windows level names to the schema's lowercase severities.
func logLevel(s string) string {
	switch strings.ToLower(s) {
	case "":
		return ""
	case "information", "informational", "logalways":
		return "info"
	case "warning":
		return "warning"
	case "error":
		return "error"
	case "critical":
		return "critical"
	case "verbose":
		return "debug"
	}
	return strings.ToLower(s)
}
