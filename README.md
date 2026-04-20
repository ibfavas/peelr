<div align="center">

# 🧅 Peelr

**Peel back every secret.**

A fast JavaScript security scanner for bug bounty hunters and security researchers.  
Finds API keys, credentials, XSS sinks, prototype pollution gadgets, taint flows, and more.

[![Go](https://img.shields.io/badge/Go-1.21+-00ADD8?style=flat&logo=go)](https://go.dev/)
[![Zero deps](https://img.shields.io/badge/dependencies-zero-brightgreen?style=flat)](#installation)
[![License](https://img.shields.io/badge/license-MIT-blue?style=flat)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20macOS%20%7C%20Windows-lightgrey?style=flat)](#installation)

</div>

---

## What it does

Point Peelr at any `.js` URL and it will:

- Extract **API keys, tokens, and credentials** hardcoded in the source
- Detect **XSS sinks** (`innerHTML`, `eval`, `document.write`, `dangerouslySetInnerHTML`, …)
- Trace **taint flows** — when user-controlled input (e.g. `location.hash`) flows into a dangerous function
- Flag **prototype pollution** gadgets (`__proto__`, deep merge with user data, …)
- Enumerate **GraphQL endpoints**, operations, and introspection usage
- Collect **endpoints, API paths, emails, file paths**, and dev comments
- Score each file with a **0–100 risk score** based on severity, confidence, and taint flow count
- **Diff** findings against the previous scan to track target changes over time

Works as a **web dashboard** or a **CLI tool** that pipes directly into your recon workflow.

---

## What it isn't

| ✅ Does | ❌ Doesn't |
|---|---|
| Regex + token-level flow correlation | Full SSA dataflow / taint engine |
| Confidence scoring (reduces noise) | Context-aware inter-procedural analysis |
| Scan history + diff | Proof-of-exploit generation |
| Pipe-friendly CLI | Replace manual review |

> Solid recon amplifier. Moves you from "JS exists" to "these specific lines need manual review."

---

## Demo

```
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
HIGH      high    api_keys               GitHub Token (PAT)              ghp_aBcDeFgHiJkLmN...
HIGH      medium  xss                    innerHTML assignment             .innerHTML =
HIGH      high    prototype_pollution    __proto__ bracket write         .__proto__[
MEDIUM    high    graphql                GraphQL introspection field     __schema
```
![CLI](assets/peelr-cli.png)
---

## Installation

**Requirement: Go 1.21+**

```bash
# Arch Linux / Kali
sudo pacman -S go          # Arch
sudo apt install golang-go # Kali / Debian / Ubuntu

# macOS
brew install go
```

**Build from source:**

```bash
git clone https://github.com/ibfavas/peelr.git
cd peelr
go build -o peelr ./cmd/peelr/
```

No `go get`, no internet needed for the build. Zero external dependencies — stdlib only.

---

## Usage

### Web dashboard

```bash
./peelr                 # http://localhost:8080
./peelr --port 9000     # custom port
```
<div align="center">
  <img src="assets/peelr-web-01.png" alt="Dashboard" width="45%">
  <img src="assets/peelr-web-2.png" alt="Scan Results" width="45%">
</div>

Features: dark/light mode · risk score per file · taint flow viewer · diff mode · severity/category filters · JSON export

### CLI — single URL

```bash
./peelr --url https://target.com/app.js
```

### CLI — pipe from recon tools

```bash
# gau
gau target.com | grep '\.js$' | ./peelr

# waybackurls
waybackurls target.com | grep '\.js$' | ./peelr

# katana
katana -u target.com -f endpoint | grep '\.js$' | ./peelr
```

### CLI — file of URLs

```bash
./peelr --file js_urls.txt --workers 10
```

### Output formats

```bash
# Colored table, sorted by risk score (default)
./peelr --url https://target.com/app.js

# JSON (pipe to jq)
./peelr --url https://target.com/app.js --format json | jq '.findings[] | select(.severity=="critical")'

# Plain TSV — url · severity · confidence · category · type · value · line
./peelr --url https://target.com/app.js --format plain

# Pull only confirmed taint flows
./peelr --file urls.txt --format json | jq '.[] | select(.flows | length > 0) | {url:.url, flows:.flows}'
```

### Filtering

```bash
# High-confidence findings only (low noise)
./peelr --url https://target.com/app.js --only-high-conf

# Minimum severity
./peelr --url https://target.com/app.js --min-severity high

# Combined
./peelr --url https://target.com/app.js --min-confidence high --min-severity medium

# Skip taint flow analysis (faster for large batches)
./peelr --file urls.txt --no-flows
```

### Diff — track target changes over time

```bash
# First scan saves a baseline automatically
./peelr --url https://target.com/app.js

# Next scan — show only what's new or gone
./peelr --url https://target.com/app.js --diff

# List all previously scanned URLs
./peelr --history
```

### CI / pipeline integration

```bash
# Exits with code 1 on any critical or high finding
./peelr --url https://deploy.example.com/app.js --only-high-conf
echo $?  # 0 = clean, 1 = findings present
```

### Silent / scriptable

```bash
./peelr --url https://target.com/app.js --silent --format plain
```

---

## Detection coverage

| Category | Examples |
|---|---|
| **API Keys & Tokens** | AWS, Google, GitHub, Stripe, Slack, Firebase, JWT, Twilio, SendGrid, Shopify, PayPal, Square, Mapbox |
| **Credentials** | Hardcoded passwords, Basic Auth headers, Bearer tokens, DB connection strings, private key blocks |
| **XSS Sinks** | `innerHTML`, `outerHTML`, `eval()`, `document.write()`, `dangerouslySetInnerHTML`, jQuery `.html()`, `insertAdjacentHTML`, `Function()` |
| **DOM Sinks** | `postMessage`, `srcdoc`, `document.domain`, dynamic `script.src`, `location.hash`, `URLSearchParams(location)` |
| **Prototype Pollution** | `__proto__` writes, `constructor.prototype`, `Object.assign` with req body, lodash/deepmerge taints |
| **GraphQL** | Endpoints, queries/mutations, introspection fields, Apollo client, gql tags |
| **Endpoints & APIs** | `fetch()`, `axios`, XHR, jQuery AJAX, versioned API paths, full URLs |
| **Misc** | Emails, Unix/Windows paths, S3 buckets, TODO/FIXME/security comments |

### Taint flow sources tracked

`location.hash` · `location.search` · `location.href` · `document.URL` · `document.referrer` · `document.cookie` · `URLSearchParams` · `postMessage event.data` · `window.name` · `localStorage.getItem` · `req.body/params/query` · `JSON.parse(input)`

### Taint flow sinks tracked

`innerHTML` · `outerHTML` · `document.write` · `eval` · `Function()` · `insertAdjacentHTML` · `jQuery .html()` · `setTimeout(string)` · `script.src` · `window.location` · `postMessage`

---

## Confidence scoring

Every finding carries a confidence level to cut noise:

| Confidence | Meaning |
|---|---|
| `high` | Strong structural pattern — low false positive rate |
| `medium` | Plausible, verify manually |
| `low` | Generic heuristic — expect noise |

Automatically downgraded when the matched value looks like a placeholder (`example`, `test`, `REPLACE`, `dummy`, …) or when the match is on a comment line.

---

## Risk scoring

Each scanned file gets a **0–100 risk score** based on severity weights × confidence multipliers + confirmed taint flow bonus. Files are sorted by score in CLI output.

| Score | Label |
|---|---|
| 80–100 | critical |
| 55–79 | high |
| 30–54 | medium |
| 10–29 | low |
| 0–9 | minimal |

---

## HTTP API

```bash
# Single file
curl -X POST http://localhost:8080/api/analyze \
  -H 'Content-Type: application/json' \
  -d '{"url":"https://target.com/app.js"}' | jq .

# Batch (up to 50 URLs)
curl -X POST http://localhost:8080/api/analyze/batch \
  -H 'Content-Type: application/json' \
  -d '{"urls":["https://target.com/app.js","https://target.com/vendor.js"]}' | jq .

# Scan history
curl http://localhost:8080/api/history | jq .
```

---

## Flags

| Flag | Default | Description |
|---|---|---|
| `--port` | `8080` | Web UI port |
| `--url` | — | Single URL to analyze |
| `--file` | — | File with one URL per line |
| `--format` | `table` | Output: `table` · `json` · `plain` |
| `--min-severity` | — | `critical` · `high` · `medium` · `low` · `info` |
| `--min-confidence` | — | `high` · `medium` · `low` |
| `--only-high-conf` | `false` | High-confidence findings only |
| `--diff` | `false` | Show only new findings vs last scan |
| `--history` | `false` | List all previously scanned URLs |
| `--clear-history` | `false` | Delete all scan history |
| `--no-flows` | `false` | Skip taint flow analysis |
| `--workers` | `5` | Concurrent workers |
| `--silent` | `false` | No banner or progress output |
| `--no-color` | `false` | Disable ANSI colors |
| `--version` | `false` | Print version and exit |

---

## Project structure

```
peelr/
├── cmd/peelr/main.go          # CLI entry point — flags, output formatters, diff display
├── internal/
│   ├── analyzer/analyzer.go   # Regex patterns, confidence scoring, risk scoring
│   ├── ast/ast.go             # Token-level source → sink taint flow tracker
│   ├── history/history.go     # Scan persistence + diff engine (~/.peelr/history/)
│   └── server/server.go       # HTTP server + API routes
├── web/templates/index.html   # Web dashboard (single file, no build step)
└── go.mod
```

---

## Limits

| | |
|---|---|
| Max JS file size | 15 MB |
| Max batch (web/API) | 50 URLs |
| CLI batch | Unlimited (`--workers` controls concurrency) |
| HTTP timeout | 20s per file |
| History | `~/.peelr/history/` — one JSON per URL |

---

## Disclaimer

For **authorized security testing and educational purposes only**.  
Only scan JavaScript files from targets you own or have explicit written permission to test.

---
