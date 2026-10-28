package source

import (
	"bufio"
	"context"
	"fmt"
	"log"
	"net"
	"sync"
	"time"
)

type (
	Handler interface {
		Handle(line []byte)
	}
	Server struct {
		ln net.Listener
		h  Handler

		MaxLine     int
		IdleTimeout time.Duration
	}
)

func NewServer(ln net.Listener, h Handler) *Server {
	return &Server{ln: ln, h: h, MaxLine: 1 << 20, IdleTimeout: 5 * time.Minute}
}

func (s *Server) Serve(ctx context.Context) error {
	ctx, cancel := context.WithCancel(ctx)
	context.AfterFunc(ctx, func() { s.ln.Close() }) // unblocks Accept

	var wg sync.WaitGroup
	defer wg.Wait() // runs last: wait for handlers
	defer cancel()  // runs first: closes listener and all conns

	for {
		conn, err := s.ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return fmt.Errorf("accept: %w", err)
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			s.handle(ctx, conn)
		}()
	}
}

func (s *Server) handle(ctx context.Context, conn net.Conn) {
	defer conn.Close()
	stop := context.AfterFunc(ctx, func() { conn.Close() })
	defer stop()

	sc := bufio.NewScanner(conn)
	sc.Buffer(make([]byte, 0, 64*1024), s.MaxLine)
	for {
		if s.IdleTimeout > 0 {
			conn.SetReadDeadline(time.Now().Add(s.IdleTimeout))
		}
		if !sc.Scan() {
			break
		}
		s.h.Handle(sc.Bytes())
	}
	if err := sc.Err(); err != nil && ctx.Err() == nil {
		log.Printf("conn %s: %v", conn.RemoteAddr(), err)
	}
}
