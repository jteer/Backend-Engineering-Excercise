The following outlines my usage of AI with this coding exercise and the prompts I used.

- Tool: Claude Code CLI
- Model: Sonnet 5.5 (Medium)
- What I wrote myself vs. what was generated:
  - Myself: Parsing logic for each parser (first pass), processor logic for orchestrating the pipeline of normalization, and the initial tests and cases for the syslog and ndjson parsers (reviewed in #3, #6 below), Entrypoint and other server setup.
  - Generated: Event structs based on Schema.md (#1), verification and additional cases for the initial parser tests (#3), and tests for the remaining packages (#2).

### Prompts and Tasks (no specific order)
1. Generate go structs from the provided SCHEMA.md into internal/model/event.go

```
Generate Go types for the normalized event schema described in `SCHEMA.md`, in
`internal/model/event.go` (package `model`, module `log-exercise`). Read `SCHEMA.md` first.
Write only that file and don't change anything else.

## Don't
- Don't add parsing, validation or mapping logic. Those belong in the parser packages.
- Don't add fields that aren't in the schema (no `ReceivedAt`, no `user.id`).
```

2. Generate table based test cases for testing each package

```
Write Go tests for this repo. It's a coding exercise, so keep it
lean: cover the main paths and a few edge cases per package, not every permutation.

## Conventions
- Standard library `testing` only. No testify or other dependencies.
- Table-driven tests with `t.Run` subtests wherever there are several input/output cases.
  Use a struct with `name`, inputs, and `want` (and `wantErr` where relevant).
- Mark independent tests and subtests with `t.Parallel()`. Call `t.Helper()` in helpers.
- Test files sit next to the code, in the same package unless testing only the public API.
- Compare with `reflect.DeepEqual` or field by field. Print got/want in failure messages.
- No `time.Sleep` for synchronization. Use channels, `sync.WaitGroup`, or poll with a deadline.
- Inject dependencies: fake `io.Writer`s, fake `Writer`/`Handler` interfaces, and the parsers'
  `Now func() time.Time`. Never depend on the wall clock or a fixed port. Listen on
  `127.0.0.1:0`.
- Tests must pass under `go test -race ./...` and `go vet ./...`.
- Don't modify non-test code. If you find a bug, report it instead of fixing it.

## Packages
Existing tests are already comprehensive for `parse/ndjson`, `parse/syslog` and
`parse/winevent`. Leave them alone.

1. `internal/model`: table tests for `Clean`, `FirstNonEmpty` and `Str` (empty, whitespace,
   `-`, normal value). Test `Event` marshalling: UTC millisecond timestamp, field order,
   and optional fields omitted when nil.
2. `internal/parse` (`parse.go`): table test for `Detect` (JSON object, leading whitespace,
   syslog, empty, whitespace only) and `Format.String`.
3. `internal/pipeline`: use fake parsers and a fake sink that records events. Cases: JSON
   line goes to the JSON parser and syslog goes to the syslog parser. A parse error is
   counted as dropped and not written. A nil event with a nil error is counted as dropped.
   A blank line is ignored. A sink error is counted as dropped. Check `Parsed()` and
   `Dropped()`.
4. `internal/sink`: write to a goroutine-safe buffer. Cases: events appear before `Close`
   (within the flush interval, polling with a deadline), all events are flushed and in
   order after `Close`, and `Close` is idempotent. Run concurrent writers under `-race` and
   check the line count. Every output line must be valid JSON.
5. `internal/source`: start a `Server` on `127.0.0.1:0` with a recording `Handler`. Use
   `net.Dial`. Cases: lines from one connection arrive in order, multiple concurrent
   connections work, a final line without a trailing newline is delivered, and a line over
   `MaxLine` ends that connection without crashing the server. Cancelling the context makes
   `Serve` return and closes open connections.
6. `cmd`: skip it. There's nothing worth unit testing in `main`.


When done, run `go vet ./... && go test -race ./...` and report the results.
```

3. Review the written parser logic for NDJSON and syslog to verify my logic matched the specified mapping logic within SCHEMA.md

```
Review the NDJSON and syslog/CEF parsers against the mapping rules in `SCHEMA.md`.
This is a read-only review: do not modify any files. Report findings only.

## Read first
- `SCHEMA.md` (the source of truth), and the "Acceptance Criteria" in `README.md`
- `internal/model/event.go`
- `internal/parse/ndjson/`, `internal/parse/syslog/`, `internal/parse/winevent/`
- `samples/json/`, `samples/syslog/`, and `expected/sample-output.ndjson`

## Method
1. Build a traceability table, one row per rule in SCHEMA.md. For each of the two formats
   (Windows JSON and syslog/CEF), list every rule for `@timestamp`, `event.type`,
   `event.category`, `event.outcome`, `source.ip`, `user.name`, `host.name`, `log.level`,
   `message`, and the "Handling Missing or Sentinel Values" section. Columns: the rule
   (quoted), the code that implements it (file:line), and a verdict of
   **Matches**, **Deviates**, **Missing**, or **Ambiguous in spec**.
2. For every Deviates or Missing row, give a concrete input that shows the wrong output
   and what the spec says it should be. Reproduce it by running the parser (a throwaway
   test or `go run` is fine). Don't leave a test file in the repo.
3. Run all six samples through the parsers. Compare the JSON samples with
   `expected/sample-output.ndjson`. For the rest, derive the expected output by hand from
   SCHEMA.md and compare.
4. Check the traps that keyword rules usually miss:
   - spec keywords vs real phrasing ("logon" vs "logged on" / "log on"; "deny" vs "denied")
   - substring false positives ("unsuccessful" contains "success"; "failover" contains
     "fail")
   - precedence when several rules match (act vs auth text; success vs failure)
   - sentinels (`-`, empty, whitespace) for IP and user fields
   - range rules (4720–4767 boundaries), timestamp precision and UTC conversion, and the
     missing year/zone in RFC 3164
5. Check that malformed input never panics: truncated lines, empty fields, wrong JSON
   types, huge values.

## Output
- A one-paragraph verdict: does the code implement the spec, yes or no, and how confident
  you are.
- The traceability table.
- Findings, ordered by severity. Severity levels:
  - **Bug**: contradicts an explicit spec rule
  - **Gap**: a rule isn't implemented
  - **Ambiguity**: the spec allows more than one reading. State the reading the code took
    and the alternative.
  - **Nit**
- For each finding: the location, the failing input, the actual vs expected output, and
  a suggested fix. Don't apply the fix.
- Don't invent requirements. If something isn't in SCHEMA.md or the README, call it a
  suggestion, not a defect.
```
3.1 Generate CEF Parsing

```
Given the parseCEF function write a function to parse a CEF extension string into key/value pairs.
```
