package sink

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"log"
	"log-exercise/internal/model"
	"sync"
	"time"
)

// flushInterval bounds how long a written event can sit in the buffer when
// traffic is too light to fill it.
const flushInterval = 100 * time.Millisecond

type NDJSON struct {
	ch   chan *model.Event
	done chan struct{}
	once sync.Once
	bw   *bufio.Writer
	enc  *json.Encoder
}

func New(w io.Writer, queueSize int) *NDJSON {
	if queueSize <= 0 {
		queueSize = 1024
	}
	bw := bufio.NewWriterSize(w, 64*1024)
	enc := json.NewEncoder(bw)
	enc.SetEscapeHTML(false)
	s := &NDJSON{
		ch:   make(chan *model.Event, queueSize),
		done: make(chan struct{}),
		enc:  enc,
		bw:   bw,
	}
	go s.run()
	return s
}

func (s *NDJSON) run() {
	defer close(s.done)
	tick := time.NewTicker(flushInterval)
	defer tick.Stop()
	for {
		select {
		case ev, ok := <-s.ch:
			if !ok {
				if err := s.bw.Flush(); err != nil {
					log.Printf("sink: final flush: %v", err)
				}
				return
			}
			if err := s.enc.Encode(ev); err != nil {
				log.Printf("sink: encode: %v", err)
				continue
			}
			if s.bw.Buffered() > 32*1024 {
				_ = s.bw.Flush()
			}
		case <-tick.C:
			if s.bw.Buffered() > 0 {
				_ = s.bw.Flush()
			}
		}
	}
}

func (s *NDJSON) Write(ctx context.Context, evnt *model.Event) error {
	select {
	case s.ch <- evnt:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (s *NDJSON) Close() error {
	s.once.Do(func() { close(s.ch) })
	<-s.done
	return nil
}
