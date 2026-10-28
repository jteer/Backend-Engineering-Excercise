## Running the service

Requires Go 1.27 (see `go.mod`).

```sh
# Start the server (default :5044, output to stdout)
go run ./cmd

# Or build a binary first
go build -o lognorm ./cmd && ./lognorm
```

Flags:

| Flag | Default | Description |
|------|---------|-------------|
| `-addr` | `:5044` | TCP listen address |
| `-out` | `-` | Output file path (`-` for stdout). The file is created or truncated at startup |
| `-max-line` | `1048576` | Max bytes per input line. A longer line closes that connection |
| `-queue` | `10000` | Sink queue size. When it is full, senders are slowed by TCP backpressure |
| `-verbose` | `true` | Log lines that fail to parse (`-verbose=false` to silence) |

Stop with Ctrl-C. The server drains in-flight events, flushes, and prints
`parsed`/`dropped` counts.

## Sending input

Send one message per line over TCP. In a second terminal:

```sh
# Syslog (each sample is already a single line)
nc -w1 localhost 5044 < samples/syslog/sample-1.log

# JSON: the samples are pretty-printed, so minify them to one line with jq
jq -c . samples/json/sample-1.json | nc -w1 localhost 5044

# All samples at once
{ for f in samples/json/*.json; do jq -c . "$f"; done; cat samples/syslog/*.log; } | nc -w1 localhost 5044
```

Records appear on stdout (or in the `-out` file) within about 100ms. Lines that
fail to parse are logged to stderr and counted as dropped. The server keeps running.

### Writing output to a file

```sh
go run ./cmd -addr :5044 -out normalized.ndjson
# in another terminal, send input as above, then:
cat normalized.ndjson | jq .
```

## Error handling

Lines that can't be parsed are dropped. Each one is logged to stderr and counted in the `dropped` stat. The connection and the
server stay up. Try it:

```sh
# Truncated JSON: first 100 bytes of a real sample
jq -c . samples/json/sample-1.json | head -c 100 | nc -w1 localhost 5044

# Valid JSON, but not a Windows event (no System object)
jq -nc '{EventData:{TargetUserName:"bob"}}' | nc -w1 localhost 5044

# Syslog with an out-of-range priority
sed 's/^<134>/<999>/' samples/syslog/sample-1.log | nc -w1 localhost 5044

# Neither JSON nor syslog
echo 'total garbage' | nc -w1 localhost 5044
```

Server log (stderr):

```
parse (ndjson): invalid json: unexpected EOF: "{\"System\":{\"Provider\":{\"Name\":\"Microsoft-Windows-Security-Auditing\",\"Guid\":\"{54849625-5478-4994-a5ba"
parse (ndjson): missing System object: "{\"EventData\":{\"TargetUserName\":\"bob\"}}"
parse (rfc3164): invalid syslog priority 999 (max 191): "<999>Dec 05 10:30:45 192.168.1.1 CEF:0|Microsoft|Windows|10.0|4624|...
parse (rfc3164): not syslog: missing <PRI> prefix: "total garbage"
stats: parsed=0 dropped=4
```

## Tests

```sh
go test ./...            # all packages
go test -race ./...      # with the race detector (recommended)
go vet ./...
go test -bench=. -run='^$' ./internal/parse/...   # parser benchmarks
```