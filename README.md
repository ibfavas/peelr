# 🧅 Peelr

**Peel back every secret.**

Peelr is a fast JavaScript security scanner for bug bounty hunters and security researchers. Point it at a `.js` file and it highlights the lines worth opening first: exposed secrets, dangerous sinks, prototype pollution gadgets, GraphQL clues, and source-to-sink taint flows.

[![Go](https://img.shields.io/badge/Go-1.21+-00ADD8?style=flat&logo=go)](https://go.dev/)
[![Dependencies](https://img.shields.io/badge/dependencies-stdlib%20only-brightgreen?style=flat)](#installation)
[![License](https://img.shields.io/badge/license-MIT-blue?style=flat)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20macOS%20%7C%20Windows-lightgrey?style=flat)](#installation)

> JavaScript recon, but with triage.  
> Peelr helps you move from "there are 84 JS files here" to "these 3 deserve manual review right now."

---

## Why Peelr

Modern targets ship huge bundles, vendor blobs, and frontend code paths nobody wants to read line by line. Peelr cuts that down by combining regex-based detection with lightweight token-level flow correlation, confidence scoring, and per-file risk scoring.

It is designed for:

- Bug bounty recon
- Web app security reviews
- Triage during content discovery
- Repeat scans against changing targets
- Fast CLI pipelines with minimal setup

It is not trying to be a full static analysis framework. It is trying to be fast, useful, and easy to drop into real recon.

---

## What It Finds

- Hardcoded API keys, tokens, passwords, private keys, and connection strings
- XSS sinks such as `innerHTML`, `eval`, `document.write`, `Function()`, and `dangerouslySetInnerHTML`
- Source-to-sink taint flows like `location.hash -> innerHTML`
- Prototype pollution gadgets like `__proto__`, `constructor.prototype`, and unsafe merge patterns
- GraphQL endpoints, operations, Apollo usage, and introspection fields
- Endpoints, API paths, emails, filesystem paths, S3 references, and developer comments
- A `0-100` risk score for each scanned file
- Diffs against previous scans so target changes stand out immediately

---

## Quick Example

```text
 ____           _
|  _ \ ___  ___| |_ __
| |_) / _ \/ _ \ | '__|
|  __/  __/  __/ | |
|_|   \___|\___|_|_|
Peel back every secret. v1.1.0

  scanning https://target.com/app.js

https://target.com/app.js
1842 lines · 7 findings · 2 flows · risk HIGH [68/100]
──────────────────────────────────────────────────────────────────────────────
⚡ SOURCE → SINK FLOWS
  location.hash → innerHTML  via var 'userInput'  (L12→L47)
    # Direct HTML injection. Tainted variable reaches innerHTML.
──────────────────────────────────────────────────────────────────────────────
SEV       CONF    CATEGORY               TYPE                            VALUE
──────────────────────────────────────────────────────────────────────────────
CRITICAL  high    api_keys               AWS Access Key                  AKIAIOSFODNN7EXAMPLE
HIGH      high    api_keys               GitHub Token (PAT)             ghp_aBcDeFgHiJkLmN...
HIGH      medium  xss                    innerHTML assignment           .innerHTML =
HIGH      high    prototype_pollution    __proto__ bracket write        .__proto__[
MEDIUM    high    graphql                GraphQL introspection field    __schema
```

![CLI](assets/peelr-cli.png)

---

## What Peelr Is And Isn't

| Peelr does | Peelr does not |
|---|---|
| Fast pattern matching over real-world JS | Full SSA or inter-procedural dataflow |
| Lightweight source-to-sink flow correlation | Prove exploitability |
| Confidence scoring to reduce noise | Replace manual validation |
| Historical diffing for repeat scans | Act like a browser crawler |
| Clean CLI and web UI workflows | Require a heavy dependency stack |

---

## Installation

Requirement: `Go 1.21+`

```bash
# Arch
sudo pacman -S go

# Kali / Debian / Ubuntu
sudo apt install golang-go

# macOS
brew install go
```

Build from source:

```bash
git clone https://github.com/ibfavas/peelr.git
cd peelr
go build -o peelr ./cmd/peelr/
```

Peelr uses the Go standard library only. No external runtime dependencies and no extra build tooling.

---

## Usage

### Web UI

```bash
./peelr
./peelr --port 9000
```

Then open `http://localhost:8080` or your chosen port.

<div align="center">
  <img src="assets/peelr-web-01.png" alt="Dashboard" width="45%">
  <img src="assets/peelr-web-2.png" alt="Scan Results" width="45%">
</div>

The web UI includes:

- Risk score per file
- Taint flow viewer
- Diff mode
- Severity and category filtering
- JSON export
- Batch analysis for up to 50 URLs

### CLI: single URL

```bash
./peelr --url https://target.com/app.js
```

### CLI: pipe from recon tools

```bash
gau target.com | grep '\.js$' | ./peelr
waybackurls target.com | grep '\.js$' | ./peelr
katana -u target.com -f endpoint | grep '\.js$' | ./peelr
```

### CLI: file input

```bash
./peelr --file js_urls.txt --workers 10
```

### Output formats

```bash
# Default table output
./peelr --url https://target.com/app.js

# JSON
./peelr --url https://target.com/app.js --format json

# Plain tab-separated output
./peelr --url https://target.com/app.js --format plain
```

### Filtering

```bash
./peelr --url https://target.com/app.js --only-high-conf
./peelr --url https://target.com/app.js --min-severity high
./peelr --url https://target.com/app.js --min-confidence high --min-severity medium
./peelr --file urls.txt --no-flows
```

### Diff and history

```bash
# First run creates history
./peelr --url https://target.com/app.js

# Compare against the previous scan
./peelr --url https://target.com/app.js --diff

# Show scan history
./peelr --history

# Clear stored history
./peelr --clear-history
```

### Exit codes for automation

Peelr exits with code `1` when filtered results contain any `high` or `critical` finding.

```bash
./peelr --url https://deploy.example.com/app.js --only-high-conf
echo $?
```

### Silent mode

```bash
./peelr --url https://target.com/app.js --silent --format plain
```

---

## Detection Coverage

| Category | Examples |
|---|---|
| API keys and tokens | AWS, Google, GitHub, Stripe, Slack, Firebase, JWT, Twilio, SendGrid, Shopify, PayPal, Square, Mapbox |
| Credentials | Hardcoded passwords, Basic auth headers, bearer tokens, DB connection strings, private key blocks |
| XSS sinks | `innerHTML`, `outerHTML`, `eval()`, `document.write()`, `Function()`, `dangerouslySetInnerHTML`, jQuery `.html()`, `insertAdjacentHTML` |
| DOM sinks | `postMessage`, `srcdoc`, `document.domain`, dynamic `script.src`, `window.location` |
| Prototype pollution | `__proto__`, `constructor.prototype`, unsafe merges, lodash merge patterns |
| GraphQL | Endpoints, operations, Apollo client usage, `gql` tags, introspection fields |
| Endpoints and URLs | `fetch()`, `axios`, XHR, jQuery AJAX, API literals, full URLs |
| Misc | Emails, Unix and Windows paths, S3 bucket references, TODO/FIXME/security comments |

### Tracked taint sources

`location.hash`, `location.search`, `location.href`, `document.URL`, `document.referrer`, `document.cookie`, `URLSearchParams`, `postMessage event.data`, `window.name`, `localStorage.getItem`, `req.body`, `req.params`, `req.query`, `JSON.parse(input)`

### Tracked taint sinks

`innerHTML`, `outerHTML`, `document.write`, `eval`, `Function()`, `insertAdjacentHTML`, `jQuery .html()`, `setTimeout(string)`, `script.src`, `window.location`, `postMessage`

---

## Confidence Model

Each finding gets a confidence level:

| Confidence | Meaning |
|---|---|
| `high` | Strong structural match with low expected false positives |
| `medium` | Plausible finding that needs manual confirmation |
| `low` | Broad heuristic; expect more noise |

Confidence is automatically downgraded when the value looks like a placeholder such as `example`, `dummy`, or `REPLACE`, or when the match appears on a comment line.

---

## Risk Scoring

Each file gets a `0-100` score based on severity, confidence, and confirmed taint flows.

| Score | Label |
|---|---|
| `80-100` | `critical` |
| `55-79` | `high` |
| `30-54` | `medium` |
| `10-29` | `low` |
| `0-9` | `minimal` |

CLI output is sorted by risk so the worst files rise to the top first.

---

## HTTP API

### Analyze one JS file

```bash
curl -X POST http://localhost:8080/api/analyze \
  -H 'Content-Type: application/json' \
  -d '{"url":"https://target.com/app.js"}' | jq .
```

### Analyze a batch

```bash
curl -X POST http://localhost:8080/api/analyze/batch \
  -H 'Content-Type: application/json' \
  -d '{"urls":["https://target.com/app.js","https://target.com/vendor.js"]}' | jq .
```

### Retrieve history

```bash
curl http://localhost:8080/api/history | jq .
```

Batch API limits: `1-50` URLs per request.

---

## CLI Flags

| Flag | Default | Description |
|---|---|---|
| `--port` | `8080` | Web UI port |
| `--url` | - | Single URL to analyze |
| `--file` | - | File with one URL per line |
| `--format` | `table` | Output: `table`, `json`, `plain` |
| `--min-severity` | - | `critical`, `high`, `medium`, `low`, `info` |
| `--min-confidence` | - | `high`, `medium`, `low` |
| `--only-high-conf` | `false` | Keep only high-confidence findings |
| `--diff` | `false` | Show only new findings vs. previous scan |
| `--history` | `false` | List previously scanned URLs |
| `--clear-history` | `false` | Delete stored scan history |
| `--workers` | `5` | Concurrent workers in batch mode |
| `--no-flows` | `false` | Skip taint flow analysis |
| `--silent` | `false` | Suppress banner and progress output |
| `--no-color` | `false` | Disable ANSI colors |
| `--version` | `false` | Print version and exit |

---

## Project Layout

```text
peelr/
├── cmd/peelr/main.go
├── internal/analyzer/analyzer.go
├── internal/ast/ast.go
├── internal/history/history.go
├── internal/scorer/scorer.go
├── internal/server/server.go
├── web/templates/index.html
├── web/static/app.css
└── web/static/app.js
```

---

## Limits

| Limit | Value |
|---|---|
| Maximum JS file size | `15 MB` |
| Batch size in web/API mode | `50 URLs` |
| CLI batch size | Unlimited |
| Default worker count | `5` |
| HTTP timeout | `20s` per file |
| History storage | `~/.peelr/history/` |

---

## Disclaimer

Peelr is for authorized security testing and education. Only scan JavaScript from systems you own or have explicit written permission to assess.
