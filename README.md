# Log Normalizer Service — Coding Exercise

A backend coding exercise for Data Integration Engineers. Build a small TCP server that accepts logs in two formats, parses them, and outputs normalized records. This exercise assesses data source wiring, schema mapping, and systems thinking relevant to log ingestion pipelines.

**Time estimate:** 2–3 hours

---

## Overview

Build a **Log Normalizer Service** that:

1. Listens on a TCP port for incoming log messages
2. Accepts two input formats: **RFC 3164 syslog** and **NDJSON** (structured events, similar to Windows Event Log)
3. Detects the format of each incoming message
4. Parses and maps the data to a **normalized schema** (see [SCHEMA.md](SCHEMA.md))
5. Outputs one NDJSON record per input to stdout or a configurable sink

### Architecture

```
┌─────────────────┐     ┌─────────────────┐
│ RFC 3164 Syslog │     │  NDJSON (JSON)  │
└────────┬────────┘     └────────┬────────┘
         │                       │
         └───────────┬───────────┘
                     ▼
            ┌────────────────┐
            │  TCP Server    │  (e.g., port 5044)
            │  Listen + Read  │
            └────────┬───────┘
                     ▼
            ┌────────────────┐
            │ Format Detector│  (per line or per connection)
            │ + Parser       │
            └────────┬───────┘
                     ▼
            ┌────────────────┐
            │ Schema Mapper   │  (map to normalized fields)
            └────────┬───────┘
                     ▼
            ┌────────────────┐
            │ NDJSON Output   │  (stdout or configurable)
            └────────────────┘
```

---

## Requirements

| Requirement | Description |
|-------------|-------------|
| **TCP listener** | Listen on a configurable TCP port (default: 5044) |
| **Two input formats** | Accept RFC 3164 syslog and NDJSON (one JSON object per line) |
| **Format detection** | Detect format per connection or per line. Document your choice and rationale. |
| **Schema mapping** | Map all parsed fields to the normalized schema in `SCHEMA.md` |
| **Output** | Emit one NDJSON record per input to stdout or a configurable sink (e.g., file) |
| **Error handling** | Handle malformed input without crashing. Log or emit errors appropriately. |

---

## Sample Data

Sample input files are provided for testing. **Each file contains one message.** When sending over TCP, send one message per line. For syslog, each sample is a single line. For JSON, minify to one line per event (e.g., `jq -c . samples/json/sample-1.json`) so each TCP line carries one complete JSON object.

### `samples/syslog/`

| File | Description |
|------|-------------|
| `sample-1.log` | Auth success — RFC 3164 syslog with CEF message (successful logon) |
| `sample-2.log` | Auth failure — RFC 3164 syslog with CEF message (failed logon) |
| `sample-3.log` | Network event — RFC 3164 syslog with CEF message (traffic allowed) |

### `samples/json/`

| File | Description |
|------|-------------|
| `sample-1.json` | Windows Event 4624 — logon success (nested `System`, `EventData`, `RenderingInfo`) |
| `sample-2.json` | Windows Event 4625 — logon failure |
| `sample-3.json` | Windows Event 4688 — process creation |

Each JSON sample uses a Windows Event Log–like structure with nested objects. Your mapper must extract fields from these nested paths.

---

## Acceptance Criteria

Your solution should:

- [ ] Parse RFC 3164 syslog: priority, timestamp, hostname, and message
- [ ] Parse CEF extensions when present (e.g., `src=`, `suser=`, `act=`) in syslog
- [ ] Parse NDJSON: one JSON object per line
- [ ] Extract `@timestamp` from both formats (syslog timestamp or `System.TimeCreated` / equivalent)
- [ ] Extract `user.name` from both formats (e.g., CEF `suser`, JSON `EventData.TargetUserName`)
- [ ] Extract `source.ip` when available
- [ ] Map `event.category` and `event.outcome` using the rules in `SCHEMA.md`
- [ ] Handle malformed input without crashing (e.g., invalid JSON, truncated syslog)
- [ ] Output valid NDJSON (one record per line)

---

## What We're Evaluating

| Criterion | What we look for |
|-----------|------------------|
| **Data mapping logic** | Correct nested field extraction; conditional categorization (event type, outcome); handling of `-` or empty values |
| **Format detection** | Clear strategy (e.g., first character `{` → JSON); rationale for per-line vs per-connection detection |
| **Systems awareness** | TCP handling; graceful degradation on bad input; consideration of batching, backpressure, or connection limits |
| **Code organization** | Readable, organized, testable structure |
| **AI usage disclosure** | `AI_USAGE.md` present and honest (see below) |

---

## Language & Scope

- **Language:** Any (Go, Python, Node, Rust, etc.)
- **Time:** 2–3 hours. Prioritize: (1) parsing both formats, (2) schema mapping, (3) systems considerations.
- **Tradeoffs:** If time is short, focus on mapping accuracy over batching or advanced TCP behavior. Document what you would do with more time.

---

## AI Usage

Use of AI tools (e.g., ChatGPT, Copilot, Cursor) is **allowed**. We want to see how you work with these tools.

Please document your usage in `AI_USAGE.md`:

- What tools you used
- What you used them for (e.g., boilerplate, parsing logic, debugging)
- What you wrote yourself vs. generated

Honest disclosure is required. We evaluate your integration and mapping choices, not whether you used AI.

---

## Expected Output

See `expected/sample-output.ndjson` for example normalized records. Use these to validate your mapper output format and field values.

---

## Getting Started

1. Read [SCHEMA.md](SCHEMA.md) for the target schema and mapping rules
2. Review the sample files in `samples/syslog/` and `samples/json/`
3. Implement the service
4. Test with the sample data (e.g., `nc` or a small script to send samples over TCP). Syslog samples are single-line; for JSON, send one minified object per line
5. Create `AI_USAGE.md` before submitting

---

## Submission

When complete, ensure your repository includes:

- Implementation code
- Brief README or instructions on how to run and test
- `AI_USAGE.md` with your AI usage disclosure
