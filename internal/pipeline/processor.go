package pipeline

import (
	"bytes"
	"context"
	"errors"
	"log"
	"sync/atomic"

	"log-exercise/internal/model"
	"log-exercise/internal/parse"
)

type (
	Writer interface {
		Write(ctx context.Context, ev *model.Event) error
	}

	Processor struct {
		syslog  parse.Parser
		json    parse.Parser
		sink    Writer
		verbose bool

		parsed  atomic.Int64
		dropped atomic.Int64
	}
)

func New(syslog, json parse.Parser, sk Writer, verbose bool) *Processor {
	return &Processor{syslog: syslog, json: json, sink: sk, verbose: verbose}
}

func (p *Processor) Parsed() int64  { return p.parsed.Load() }
func (p *Processor) Dropped() int64 { return p.dropped.Load() }

func (p *Processor) Handle(line []byte) {
	line = bytes.TrimSpace(line)
	if len(line) == 0 {
		return
	}

	format := parse.Detect(line)
	var (
		ev  *model.Event
		err error
	)
	switch format {
	case parse.FormatNDJSON:
		ev, err = p.json.Parse(line)
	case parse.FormatRFC3164:
		ev, err = p.syslog.Parse(line)
	default:
		err = errors.New("invalid or unsupported log format")
	}
	if err == nil && ev == nil {
		err = errors.New("parser returned no event")
	}
	if err != nil {
		p.dropped.Add(1)
		if p.verbose {
			log.Printf("parse (%s): %v: %.200q", format, err, line)
		}
		return
	}

	// Background ctx on purpose: shutdown must not discard queued events.
	if err := p.sink.Write(context.Background(), ev); err != nil {
		p.dropped.Add(1)
		log.Printf("sink: %v", err)
		return
	}
	p.parsed.Add(1)
}
