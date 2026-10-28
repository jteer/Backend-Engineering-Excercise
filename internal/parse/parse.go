package parse

import (
	"bytes"
	"log-exercise/internal/model"
)

const (
	FormatUnknown Format = iota
	FormatRFC3164
	FormatNDJSON
)

type (
	Format int
	Parser interface {
		Parse(line []byte) (*model.Event, error)
	}
)

func Detect(line []byte) Format {
	trimmed := bytes.TrimSpace(line)
	if len(trimmed) == 0 {
		return FormatUnknown
	}
	if trimmed[0] == '{' {
		return FormatNDJSON
	}
	return FormatRFC3164
}

func (f Format) String() string {
	switch f {
	case FormatRFC3164:
		return "rfc3164"
	case FormatNDJSON:
		return "ndjson"
	}
	return "unknown"
}
