package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"

	"log-exercise/internal/parse/ndjson"
	"log-exercise/internal/parse/syslog"
	"log-exercise/internal/pipeline"
	"log-exercise/internal/sink"
	"log-exercise/internal/source"
)

type config struct {
	addr    string
	out     string
	maxLine int
	verbose bool
	queue   int
}

func loadConfig() config {
	var c config
	flag.StringVar(&c.addr, "addr", ":5044", "TCP listen address")
	flag.StringVar(&c.out, "out", "-", "output path '-' for stdout")
	flag.IntVar(&c.maxLine, "max-line", 1<<20, "max bytes per input line")
	flag.BoolVar(&c.verbose, "verbose", true, "log parse errors")
	flag.IntVar(&c.queue, "queue", 10_000, "sink queue size")
	flag.Parse()
	return c
}

func main() {
	if err := run(loadConfig()); err != nil {
		log.Fatal(err)
	}
}

func run(cfg config) error {
	out := os.Stdout
	if cfg.out != "-" {
		f, err := os.Create(cfg.out)
		if err != nil {
			return fmt.Errorf("open output: %w", err)
		}
		defer f.Close()
		out = f
	}

	ln, err := net.Listen("tcp", cfg.addr)
	if err != nil {
		return fmt.Errorf("listen: %w", err)
	}
	log.Printf("listening on %s", ln.Addr())

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	sk := sink.New(out, cfg.queue)
	proc := pipeline.New(&syslog.Parser{}, &ndjson.Parser{}, sk, cfg.verbose)
	srv := source.NewServer(ln, proc)
	srv.MaxLine = cfg.maxLine

	// Serve blocks until ctx is cancelled or accept fails, and does
	// not return until every connection handler has finished, so closing the
	// sink afterwards cannot race with a writer.
	serveErr := srv.Serve(ctx)
	log.Println("shutting down")
	// flush
	closeErr := sk.Close()

	log.Printf("stats: parsed=%d dropped=%d", proc.Parsed(), proc.Dropped())
	return errors.Join(serveErr, closeErr)
}
