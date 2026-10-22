# burp2json

Convert Burp Suite project data into structured, AI-readable JSON.

`burp2json` is a Go command-line tool for turning a Burp Suite engagement into
something an LLM or a script can reason about: ordered headers, decoded bodies,
comments, highlights, timestamps, Site Map entries, Repeater tabs, and Collaborator
HTTP interactions. It is read-only and uses the Go standard library plus a small
Brotli decoder for `Content-Encoding: br`.

> Only use this on targets you are authorised to test. The output can contain
> credentials, session tokens, personal data, and full response bodies. Review it
> before sharing, and prefer `--redact` when sending it to a third party.

## Features

- Reads Burp project files (`.burp`) structurally, without requiring Burp itself.
- Also reads Burp "Save items" XML exports and HAR files.
- Preserves header order and duplicate headers as `[name, value]` pairs.
- Decodes `gzip`, `deflate`, Brotli (`br`), and chunked bodies.
- Emits binary bodies as base64 instead of corrupting them.
- Recovers Proxy history, Repeater tabs, Target Site Map entries, and Collaborator
  HTTP interactions where the project stores them.
- Supports comments, highlight colours, capture timestamps, listener ports, Burp
  MIME types, and response titles where available.
- Deduplicates the same exchange across tools and records `also_seen_in`.
- Builds an application summary (hosts, endpoints, parameters, cookies, statuses,
  technologies, missing security headers, redirects, errors).
- Can split output into numbered parts for context-window limits.
- Shows a progress bar on stderr for large inputs on interactive terminals.
- Best-effort `--redact` mode for auth headers, cookies, JWTs, and secret-looking
  fields.

## Install

Requires Go 1.22 or newer.

```bash
go install github.com/cold-lapwing/burp2json@latest
```

The binary is installed into `$(go env GOPATH)/bin` (usually `~/go/bin`). Add that
directory to your `PATH` if it is not already there. You can also build from a clone:

```bash
git clone https://github.com/cold-lapwing/burp2json
cd burp2json
go build -o burp2json .
```

## Quick start

```bash
# Burp project -> JSON
burp2json engagement.burp -o engagement.json

# Redact common secrets before sharing
burp2json engagement.burp -o engagement.redacted.json --redact

# Keep one host only
burp2json engagement.burp -o api.json --host api.example.com

# Split a large export into 200-item parts
burp2json engagement.burp -o engagement.json --chunk-items 200

# XML or HAR exports
burp2json saved-items.xml -o saved.json
burp2json capture.har -o capture.json
```

The input file is opened read-only and is never modified. If `-o` is omitted the
output is written next to the input as `<input>.json`.

For inputs of 1 MiB or more, an interactive terminal also shows a progress bar on
stderr while the file is read, parsed, and written. Progress is disabled
automatically when stderr is redirected, and can be forced off with
`--no-progress`.

## CLI options

| Option | Meaning |
| --- | --- |
| `-o, --output PATH` | Output JSON path. Default: `<input>.json`. |
| `--format {burp,xml,har}` | Force the input format instead of auto-detecting. |
| `--max-body BYTES` | Maximum body bytes kept per message. Default: `200000`. |
| `--host TEXT` | Keep only items whose host contains `TEXT`. Repeatable. |
| `--redact` | Redact sensitive headers, cookies, JWTs, and secret-looking fields. |
| `--chunk-items N` | Write `*_part001.json`, `*_part002.json`, ... with `N` items each. |
| `--no-summary` | Omit the top-level `summary` object. |
| `--no-progress` | Disable the progress bar even on an interactive terminal. |

## Output shape

```jsonc
{
  "ai_instructions": "Guidance for an LLM reading this file...",
  "meta": {
    "tool": "burp2json",
    "tool_version": "2.0.0",
    "source_file": "engagement.burp",
    "source_sha256": "...",
    "source_size": 16777216,
    "input_format": "burp",
    "extraction_method": "burp-heap",
    "generated_at": "2026-10-22T09:47:40+00:00",
    "read_only": true,
    "item_count": 95,
    "source_tool_counts": {"proxy": 11, "site-map": 84},
    "redacted": true,
    "burp": {
      "magic": "0x66858280",
      "outer_version": 1,
      "schema_current": 217,
      "project_name": "engagement"
    },
    "warnings": []
  },
  "summary": {
    "total_items": 95,
    "hosts": {"chatgpt.com": 95},
    "host_details": [
      {"host": "chatgpt.com", "count": 95, "ports": [443], "protocols": ["https"]}
    ],
    "endpoints": [
      {"host": "chatgpt.com", "method": "GET", "path": "/", "count": 1,
       "statuses": {"200": 1}, "params": []}
    ],
    "parameter_names": ["..."],
    "methods": {"GET": 66, "POST": 29},
    "status_codes": {"200": 81, "202": 9, "302": 3, "403": 2},
    "content_types": {"application/json": 59},
    "technology_headers": {},
    "cookie_names_seen": ["..."],
    "auth_header_names_seen": ["Authorization"],
    "responses_missing_security_headers": {},
    "redirects": [],
    "client_errors": [],
    "server_errors": [],
    "highlights": {"none": 11}
  },
  "collaborator": {
    "domains_seen": ["...oastify.com"],
    "interaction_types_seen": ["HTTP"],
    "interactions": [
      {
        "type": "HTTP",
        "host": "...oastify.com",
        "method": "GET",
        "path": "/.git/HEAD",
        "response_status": 200,
        "response_server": "Burp Collaborator https://burpcollaborator.net/",
        "request": {"headers": [["Host", "..."]], "body": "", "...": "..."},
        "response": {"headers": [["Server", "Burp Collaborator ..."]], "...": "..."}
      }
    ]
  },
  "repeater": {
    "tabs": [{"address": 14524816, "caption": "1", "uuid": null,
              "group": null, "pair_count": 0}],
    "groups": []
  },
  "intruder": {"recovered": false, "note": "..."},
  "scanner": {"recovered": false, "note": "..."},
  "coverage": {
    "proxy_items": 11,
    "repeater_pairs": 0,
    "site_map_messages": 95,
    "framed_http_records": 442,
    "unattributed_frames": 242,
    "collaborator_http_interactions": 5
  },
  "items": [
    {
      "id": 1,
      "source_tool": "proxy",
      "also_seen_in": ["site-map"],
      "time": 1792661035929,
      "time_iso": "2026-10-22T09:23:55.929000+00:00",
      "url": "https://chatgpt.com/",
      "host": "chatgpt.com",
      "port": 443,
      "protocol": "https",
      "method": "GET",
      "path": "/",
      "status": 200,
      "comment": "js",
      "highlight": "none",
      "metadata": {
        "entry_id": 2867,
        "ip": "172.64.155.209",
        "status": 200,
        "burp_mime_code": 256,
        "burp_mime": "HTML",
        "response_length": 651480,
        "title": "ChatGPT",
        "time_epoch_ms": 1792661035929,
        "listener_port": 8080,
        "service": {"host": "chatgpt.com", "port": 443, "tls": true},
        "row_address": 14542034
      },
      "request_file_offset": 13320902,
      "response_file_offset": 122436,
      "request": {
        "method": "GET",
        "target": "/",
        "path": "/",
        "http_version": "HTTP/2",
        "request_line": "GET / HTTP/2",
        "headers": [["Host", "chatgpt.com"], ["Cookie", "[REDACTED]"]],
        "cookies": {"session": "[REDACTED]"},
        "query_params": [],
        "body_params": [],
        "body": "",
        "body_encoding": "utf-8",
        "body_length": 0,
        "body_truncated": false
      },
      "response": {
        "status": 200,
        "reason": "OK",
        "http_version": "2",
        "status_line": "HTTP/2 200 OK",
        "headers": [["Content-Type", "text/html"]],
        "body": "<!DOCTYPE html>...",
        "body_encoding": "utf-8",
        "body_length": 638888,
        "body_truncated": true
      }
    }
  ]
}
```

Headers are lists rather than objects so duplicate and ordered headers survive.
`body_encoding` is `utf-8`, `latin-1`, or `base64`. When `body_truncated` is true,
`body_length` still reports the original decoded length.

## How extraction works

### 1. Burp project heap (`.burp`)

Current Burp projects are not a container of standalone HTTP messages. They are an
append-only object heap:

- a 72-byte big-endian header with magic `0x66858280`, compatibility value
  `0x80527974`, schema numbers, allocation cursor, and project root address;
- compact self-describing objects with a flags byte, type/subtype, a field table, and
  field values at relative offsets;
- length-framed byte records (`total`, `logical`, payload) for raw HTTP messages,
  strings, and arrays;
- chunked collections used for history rows and identity indexes.

`burp2json` walks the object graph from the header's project root. It does not scan
for strings and guess. For a schema-217 project it reads:

- **Proxy history** rows: method, service (host/port/TLS), comment, highlight,
  listener port, status, Burp MIME code, response length, title, cookie header,
  timestamp, client IP, and request/response frame addresses.
- **Repeater** tabs and pairs: caption, UUID, group, and each request/response pair.
- **Target Site Map** identity index: buckets of 24-byte `(hash, node, value)` tuples;
  each node points at an HTTP message object with request, response, and timestamp.
- **Collaborator** HTTP interactions: framed requests containing a Collaborator
  payload domain, paired with the nearest Collaborator response frame.

Exchanges are deduplicated by SHA-256 of the exact request and response bytes. When
the same exchange exists in several tools, the item keeps the higher-priority source
(`proxy` > `repeater` > `site-map` > `unknown`) and lists the others in
`also_seen_in`.

If the header or schema is not recognised, the structural parser is skipped and a
byte-level HTTP carver is used. The carver also inspects zlib/gzip blobs, but it
cannot recover tool names, comments, highlights, Repeater metadata, or Collaborator
pairing.

### 2. Burp XML export

Proxy / Repeater / Logger / Site Map items exported with Burp's "Save items" are
parsed from `<items><item>...` elements, including base64-encoded request and
response elements. The item `type` is normalised to `proxy`, `repeater`, `site-map`,
`logger`, and so on.

### 3. HAR

HAR entries are mapped directly. Request URLs supply host, port, and scheme, and
HAR `postData` / `content` bodies are decoded. HAR files do not contain Collaborator
metadata.

## What is recovered, and what is not

| Area | Status |
| --- | --- |
| Proxy HTTP history | Recovered structurally (schema-217). |
| Repeater tabs and pairs | Recovered structurally. |
| Target Site Map HTTP messages | Recovered structurally. |
| Collaborator HTTP interactions | Recovered from framed request/response records. |
| Comments, highlights, timestamps | Recovered where the heap stores them. |
| Duplicate/ordered headers | Preserved. |
| Compressed and chunked bodies | Decoded. |
| Binary bodies | Base64. |
| Intruder configuration/results | Not recovered. |
| Scanner issue/task ownership | Not mapped. |
| Collaborator DNS/SMTP interactions | Not recovered (only HTTP frames are present). |
| Exact Burp release | Not stored in the project format; only the schema is reported. |

The heap is append-only, so deleted or superseded objects and old HTTP frames remain
in the file. The parser only promotes frames that are referenced by Proxy, Repeater,
Site Map, or Collaborator metadata. Other reachable frames (for example WebSocket
handshake requests and old history entries) are counted in
`coverage.unattributed_frames` and reported in `meta.warnings` instead of being
silently presented as Proxy traffic.

## Real sample results

The development sample was a 16 MiB schema-217 project captured against
`chatgpt.com`. The structural parser produced:

| Metric | Value |
| --- | --- |
| Unique HTTP items | 95 |
| Proxy items | 11 |
| Site Map messages | 95 (84 not already in Proxy) |
| Repeater pairs | 0 (one empty tab) |
| Collaborator HTTP interactions | 5 |
| Unique Collaborator payload domains | 2 |
| Comments | 4 (`"js"`) |
| Framed HTTP records found | 442 |
| Unattributed records | 242 (other heap branches / WebSocket handshakes) |
| Protocols / ports | all `https`, port `443` |
| Statuses | 200: 81, 202: 9, 302: 3, 403: 2 |

The sample itself is intentionally not committed because it contains live session
material.

## Redaction

`--redact` is a safety aid, not a guarantee. It currently:

- replaces values of `Authorization`, `Proxy-Authorization`, `Cookie`, `Set-Cookie`,
  `X-Api-Key`, CSRF/auth token headers, and similar headers;
- replaces cookie values in the request's parsed `cookies` object and Burp's stored
  history cookie column;
- replaces JWT-shaped strings;
- redacts body/query/form keys whose names look like passwords, secrets, tokens,
  keys, auth, or sessions;
- redacts Collaborator request/response messages too.

It does **not** reliably redact secrets embedded in free-form response bodies, HTML,
JavaScript, or unusual header names. Always review the output before sharing it.

## Reverse-engineering notes

The `.burp` layout was derived by inspecting the shipped artifact rather than by
relying on Burp's UI: header fields, object descriptors, field widths, framed
records, chunked-collection layout, and the schema-217 field meanings were verified
against the sample. The REA methodology and CLI were used for artifact triage; the
generic `rea inspect-artifact` command does not recognise `.burp` as a supported
binary container, so the heap parser is purpose-built. RTK was used to keep probe
and test output compact during development.

Key format facts worth preserving:

- header: 72 bytes, big-endian; magic `0x66858280`, outer version `1`,
  compatibility `0x80527974`;
- object: `flags` (1), `type` (1), `subtype` (1), `count` (1), then `count`
  three-byte `(field_id, relative_offset)` entries;
- framed record: `total` and `logical` int32 values followed by `logical` bytes;
- address arrays use 8-byte addresses; Site Map tuples use 24 bytes;
- schema 217 Proxy row field 3 is the comment; newer schemas may use field 27;
- service host is an immutable string wrapper; port is an int32 and TLS is the
  following byte (do not read port and TLS as one int64).

## Repository layout

```text
main.go       CLI, input reading, format detection, output and chunk writing
progress.go   terminal progress bar
model.go      shared JSON types
httpmsg.go    HTTP parsing, body decoding, URL inference
burp.go       structural schema-217 heap parser
carver.go     fallback byte-level HTTP carver
xmlhar.go     Burp XML and HAR readers
transform.go  deduplication, finalisation, redaction, summary
*_test.go     Go test suite and synthetic heap fixture
go.mod        module and Brotli dependency
README.md     this document
.gitignore    ignores .burp files, generated JSON, and build artifacts
```

## License

Add the license your engagement or organisation requires. No license is implied by
this repository.
