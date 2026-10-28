# Normalized Schema Specification

The Log Normalizer Service maps heterogeneous input (syslog and JSON) to a single normalized schema. All output records must conform to this schema. Fields may be `null` when the source does not provide the data.

---

## Target Fields

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `@timestamp` | ISO 8601 string | Yes | Event time. Must be UTC (e.g., `2026-02-14T15:45:33.221Z`) |
| `event.type` | string | Yes | One of: `start`, `end`, `info`, `denied`, `allowed` |
| `event.category` | string | Yes | One of: `authentication`, `network`, `process`, `host` |
| `event.outcome` | string | Yes | One of: `success`, `failure`, `unknown` |
| `source.ip` | string | No | Source IP address when available |
| `user.name` | string | No | User account name when available |
| `host.name` | string | No | Host or computer name |
| `log.level` | string | No | Severity: `info`, `warning`, `error`, etc. |
| `message` | string | Yes | Original or normalized message text |

---

## Mapping Rules

### From Windows Event Log (JSON) Input

- **`@timestamp`**: Use `System.TimeCreated`. Convert to ISO 8601 UTC if needed.
- **`event.type`** (from EventID):
  - `4624`, `4648` → `start` (logon)
  - `4625` → `start` (failed logon attempt)
  - `4634`, `4647` → `end` (logoff)
  - `4688` → `start` (process creation)
  - `4689` → `end` (process termination)
  - `4720`–`4767` → `info` (IAM events such as user creation, group changes)
  - Otherwise → `info`
- **`event.category`** (from EventID):
  - `4624`, `4625`, `4634`, `4647`, `4648` → `authentication`
  - `4688`, `4689` → `process`
  - `4720`–`4767` → `host`
  - Otherwise → `host`
- **`event.outcome`**: From `RenderingInfo.Keywords`:
  - Contains `"Audit Success"` → `success`
  - Contains `"Audit Failure"` → `failure`
  - Otherwise → `unknown`
- **`source.ip`**: `EventData.IpAddress` or `OpenWEC.IpAddress` (prefer EventData when present). Omit if value is `-` or empty.
- **`user.name`**: `EventData.TargetUserName` or `EventData.SubjectUserName`. Omit if `-` or empty.
- **`host.name`**: `System.Computer`
- **`log.level`**: From `RenderingInfo.Level` (e.g., `Information` → `info`)
- **`message`**: `RenderingInfo.Message` or a fallback description

### From Syslog (RFC 3164 / CEF) Input

- **`@timestamp`**: Parse from syslog timestamp (e.g., `Dec 05 10:30:45`). Use current UTC if parsing fails.
- **`event.type`**:
  - CEF `act=allow` or similar → `allowed`
  - CEF `act=deny` or `act=denied` or blocked → `denied`
  - Auth-related message text → `start` or `end` based on context
  - Otherwise → `info`
- **`event.category`**:
  - CEF class `authentication` or message contains "logon", "login", "auth" → `authentication`
  - CEF class `traffic` or message contains "connection", "traffic" → `network`
  - Otherwise → `host`
- **`event.outcome`**:
  - Message or extensions contain "success", "allow", "Audit Success" → `success`
  - Message or extensions contain "failure", "deny", "Audit Failure", "failed" → `failure`
  - Otherwise → `unknown`
- **`source.ip`**: CEF extension `src=` or equivalent
- **`user.name`**: CEF extension `suser=` or equivalent
- **`host.name`**: Syslog hostname field
- **`log.level`**: From syslog priority (PRI) or CEF severity. Map numeric severity to string (e.g., 6 → `info`, 4 → `warning`, 3 → `error`)
- **`message`**: Full syslog message or CEF extension content

---

## Handling Missing or Sentinel Values

- In Windows Event Log, `-` often denotes "not applicable". Treat as null/omit.
- `S-1-0-0` for SIDs is a null-type SID; omit `user.id`-like fields when this is the value.
- Empty strings should be treated as null for optional fields.

---

## Example Output Record

```json
{
  "@timestamp": "2026-02-14T15:45:33.221Z",
  "event.type": "start",
  "event.category": "authentication",
  "event.outcome": "failure",
  "source.ip": "10.99.0.55",
  "user.name": "admin",
  "host.name": "dc01.contoso.local",
  "log.level": "info",
  "message": "An account failed to log on."
}
```
