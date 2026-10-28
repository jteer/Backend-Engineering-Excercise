package model

import (
	"encoding/json"
	"strings"
	"time"
)

type (
	// EventType is the value of "event.type".
	EventType string
	// EventCategory is the value of "event.category".
	EventCategory string
	// EventOutcome is the value of "event.outcome".
	EventOutcome string

	// Event is the single output schema for the Log Normalizer Service.
	// Keys are flat, dotted names (e.g. "event.type"), matching the spec.
	// Optional fields are pointers so they serialize as omitted/null when the
	// source does not provide them.
	Event struct {
		Timestamp     time.Time     `json:"@timestamp"`     // required, always UTC
		EventType     EventType     `json:"event.type"`     // required
		EventCategory EventCategory `json:"event.category"` // required
		EventOutcome  EventOutcome  `json:"event.outcome"`  // required
		SourceIP      *string       `json:"source.ip,omitempty"`
		UserName      *string       `json:"user.name,omitempty"`
		HostName      *string       `json:"host.name,omitempty"`
		LogLevel      *string       `json:"log.level,omitempty"`
		Message       string        `json:"message"` // required
	}
)

const (
	EventTypeStart   EventType = "start"
	EventTypeEnd     EventType = "end"
	EventTypeInfo    EventType = "info"
	EventTypeDenied  EventType = "denied"
	EventTypeAllowed EventType = "allowed"

	CategoryAuthentication EventCategory = "authentication"
	CategoryNetwork        EventCategory = "network"
	CategoryProcess        EventCategory = "process"
	CategoryHost           EventCategory = "host"

	OutcomeSuccess EventOutcome = "success"
	OutcomeFailure EventOutcome = "failure"
	OutcomeUnknown EventOutcome = "unknown"
)

// MarshalJSON forces @timestamp to UTC with millisecond precision,
// e.g. 2026-02-14T15:45:33.221Z.
func (r Event) MarshalJSON() ([]byte, error) {
	type alias Event
	return json.Marshal(struct {
		Timestamp string `json:"@timestamp"`
		alias
	}{
		Timestamp: r.Timestamp.UTC().Format("2006-01-02T15:04:05.000Z"),
		alias:     alias(r),
	})
}

// Clean trims whitespace and maps the Windows "not applicable" sentinel "-"
// to "".
func Clean(s string) string {
	s = strings.TrimSpace(s)
	if s == "-" {
		return ""
	}
	return s
}

// FirstNonEmpty returns the first argument that is not "".
func FirstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

// Str returns a pointer to the cleaned s, or nil if it is empty or the
// Windows "-" sentinel.
func Str(s string) *string {
	s = Clean(s)
	if s == "" {
		return nil
	}
	return &s
}
