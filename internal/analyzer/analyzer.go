package analyzer

import (
	"bufio"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"
	"unicode"
)

type Severity string

const (
	SevCritical Severity = "critical"
	SevHigh     Severity = "high"
	SevMedium   Severity = "medium"
	SevLow      Severity = "low"
	SevInfo     Severity = "info"
)

// Confidence describes how likely a finding is to be real.
type Confidence string

const (
	ConfHigh   Confidence = "high"
	ConfMedium Confidence = "medium"
	ConfLow    Confidence = "low"
)

type Finding struct {
	Category   string     `json:"category"`
	Type       string     `json:"type"`
	Value      string     `json:"value"`
	Line       int        `json:"line"`
	Context    string     `json:"context"`
	Severity   Severity   `json:"severity"`
	Confidence Confidence `json:"confidence"`
	Note       string     `json:"note,omitempty"`
}

type AnalysisResult struct {
	URL         string         `json:"url"`
	Timestamp   string         `json:"timestamp"`
	FileSize    int            `json:"file_size"`
	LineCount   int            `json:"line_count"`
	RiskScore   int            `json:"risk_score"`
	RiskLabel   string         `json:"risk_label"`
	Findings    []Finding      `json:"findings"`
	Summary     map[string]int `json:"summary"`
	SevSummary  map[string]int `json:"sev_summary"`
	ConfSummary map[string]int `json:"conf_summary"`
	Error       string         `json:"error,omitempty"`
}

type pattern struct {
	name       string
	category   string
	severity   Severity
	confidence Confidence
	note       string
	re         *regexp.Regexp
}

var patterns []pattern

var placeholderHints = []string{
	"example", "sample", "test", "placeholder", "your_", "your-", "<your",
	"EXAMPLE", "REPLACE", "INSERT", "CHANGEME", "xxxxxxxx", "00000000",
	"1234567890", "abcdefgh", "dummy", "fake", "demo",
}

var commentPrefixes = []string{"//", "/*", "*", "#", "<!--"}

func init() {
	raw := []struct {
		name, category, re string
		sev                Severity
		conf               Confidence
		note               string
	}{
		{"AWS Access Key", "api_keys", `AKIA[0-9A-Z]{16}`, SevCritical, ConfHigh,
			"AWS access key ID. Verify it's not revoked before reporting."},
		{"AWS Secret Key", "api_keys", `(?i)aws.{0,20}secret.{0,20}['\"][0-9a-zA-Z/+]{40}['\"]`, SevCritical, ConfMedium,
			"Likely AWS secret key. Validate the 40-char base64 value is real."},
		{"Google API Key", "api_keys", `AIza[0-9A-Za-z\-_]{35}`, SevHigh, ConfHigh,
			"Google API key. Check which APIs are enabled via key restriction."},
		{"GitHub Token (PAT)", "api_keys", `ghp_[0-9a-zA-Z]{36}|github_pat_[0-9a-zA-Z_]{82}`, SevCritical, ConfHigh,
			"GitHub personal access token. Scope determines blast radius."},
		{"GitHub OAuth Token", "api_keys", `gho_[0-9a-zA-Z]{36}`, SevHigh, ConfHigh, ""},
		{"Stripe Secret Key", "api_keys", `sk_live_[0-9a-zA-Z]{24,}`, SevCritical, ConfHigh,
			"Live Stripe secret key. Full payment access."},
		{"Stripe Publishable Key", "api_keys", `pk_live_[0-9a-zA-Z]{24,}`, SevMedium, ConfHigh,
			"Stripe publishable key. Low risk alone but confirms Stripe usage."},
		{"Slack Bot/App Token", "api_keys", `xox[baprs]-[0-9a-zA-Z\-]{10,}`, SevHigh, ConfHigh, ""},
		{"Slack Webhook", "api_keys", `https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[a-zA-Z0-9]+`, SevHigh, ConfHigh,
			"Can post messages to channel without auth."},
		{"Firebase Realtime DB", "api_keys", `[a-z0-9-]+\.firebaseio\.com`, SevMedium, ConfMedium,
			"Check if DB has open read/write rules."},
		{"Firebase Cloud Msg Key", "api_keys", `AAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140}`, SevHigh, ConfHigh, ""},
		{"JWT Token", "api_keys", `eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}`, SevHigh, ConfHigh,
			"Decode at jwt.io. Check alg, exp, and claims."},
		{"Twilio API Key", "api_keys", `SK[0-9a-fA-F]{32}`, SevHigh, ConfMedium,
			"Could also be a Stripe idempotency key. Check context."},
		{"SendGrid API Key", "api_keys", `SG\.[a-zA-Z0-9_-]{22,}\.[a-zA-Z0-9_-]{43,}`, SevHigh, ConfHigh, ""},
		{"Mailchimp API Key", "api_keys", `[0-9a-f]{32}-us[0-9]{1,2}`, SevMedium, ConfMedium, ""},
		{"Shopify Token", "api_keys", `shpat_[a-fA-F0-9]{32}|shpss_[a-fA-F0-9]{32}`, SevCritical, ConfHigh,
			"Admin API access token. Full store access."},
		{"PayPal Live Token", "api_keys", `access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}`, SevCritical, ConfHigh, ""},
		{"Square Token", "api_keys", `sq0atp-[0-9A-Za-z\-_]{22}|sq0csp-[0-9A-Za-z\-_]{43}`, SevHigh, ConfHigh, ""},
		{"Mapbox Token", "api_keys", `pk\.eyJ1IjoiW[A-Za-z0-9_-]{50,}`, SevMedium, ConfHigh, ""},
		{"Generic API Key", "api_keys", `(?i)(?:api[_-]?key|apikey|api[_-]?secret)\s*[:=]\s*['\"][a-zA-Z0-9_\-]{16,}['\"]`, SevMedium, ConfLow,
			"Generic pattern. High false positive rate — verify manually."},
		{"Generic Secret", "api_keys", `(?i)(?:secret|token|password|passwd|pwd)\s*[:=]\s*['\"][^'"]{8,}['\"]`, SevMedium, ConfLow,
			"Generic pattern. Could be a config placeholder."},

		{"Hardcoded Password", "credentials", `(?i)(?:password|passwd|pwd)\s*[=:]\s*['"][^'"]{6,}['"]`, SevHigh, ConfLow,
			"Check if this value is actually used vs just a label."},
		{"Basic Auth Header", "credentials", `Authorization:\s*Basic\s+[A-Za-z0-9+/=]{20,}`, SevHigh, ConfHigh,
			"Base64-decode to recover credentials."},
		{"Bearer Token", "credentials", `Authorization:\s*Bearer\s+[A-Za-z0-9\-._~+/]+=*`, SevMedium, ConfMedium, ""},
		{"DB Connection String", "credentials", `(?i)(?:mongodb|mysql|postgres|redis|mssql):\/\/[^'">\s]{10,}`, SevCritical, ConfHigh,
			"Full DB connection string. May contain credentials."},
		{"Private Key Block", "credentials", `-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----`, SevCritical, ConfHigh,
			"Private key material in JS source."},

		{"Email Address", "emails", `[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}`, SevInfo, ConfMedium, ""},

		{"innerHTML assignment", "xss", `\.innerHTML\s*[+]?=\s*(?!['"]<)`, SevHigh, ConfMedium,
			"Sink exists. Check flow analysis tab for confirmed taint paths."},
		{"outerHTML assignment", "xss", `\.outerHTML\s*[+]?=`, SevHigh, ConfMedium, ""},
		{"document.write()", "xss", `document\.write\s*\(`, SevHigh, ConfMedium, ""},
		{"document.writeln()", "xss", `document\.writeln\s*\(`, SevHigh, ConfMedium, ""},
		{"eval() call", "xss", `\beval\s*\(`, SevHigh, ConfMedium,
			"eval exists. Check flow analysis for confirmed taint."},
		{"setTimeout string arg", "xss", `setTimeout\s*\(\s*['"]`, SevMedium, ConfHigh,
			"String literal passed to setTimeout — eval equivalent."},
		{"setInterval string arg", "xss", `setInterval\s*\(\s*['"]`, SevMedium, ConfHigh, ""},
		{"dangerouslySetInnerHTML", "xss", `dangerouslySetInnerHTML\s*=\s*\{`, SevHigh, ConfMedium,
			"React explicit bypass. Check what __html receives."},
		{"jQuery .html() sink", "xss", `\$\([^)]+\)\.html\s*\(`, SevHigh, ConfMedium, ""},
		{"insertAdjacentHTML", "xss", `\.insertAdjacentHTML\s*\(`, SevHigh, ConfMedium, ""},
		{"location.href assignment", "xss", `location\.href\s*=`, SevMedium, ConfLow,
			"Open redirect or XSS depending on scheme. Check source."},
		{"window.location assign", "xss", `window\.location\s*=`, SevMedium, ConfLow, ""},
		{"Function() constructor", "xss", `new\s+Function\s*\(`, SevHigh, ConfMedium,
			"Equivalent to eval. Check argument source."},

		{"document.domain write", "dom_sinks", `document\.domain\s*=`, SevHigh, ConfHigh,
			"document.domain relaxation. Same-origin policy weakening."},
		{"postMessage sink", "dom_sinks", `\.postMessage\s*\(`, SevMedium, ConfLow,
			"Check if origin validation exists on the receiver side."},
		{"srcdoc attribute", "dom_sinks", `\.srcdoc\s*=`, SevHigh, ConfMedium, ""},
		{"WebSocket dynamic URL", "dom_sinks", `new\s+WebSocket\s*\(\s*[^'"]*\+`, SevMedium, ConfMedium,
			"Dynamic WebSocket URL. Check if attacker-controlled."},
		{"script.src assignment", "dom_sinks", `\.src\s*=\s*(?!['"])`, SevHigh, ConfMedium,
			"Dynamic script load. If user-controlled this is script injection."},
		{"open() with concat", "dom_sinks", `window\.open\s*\([^)]*\+`, SevMedium, ConfMedium, ""},
		{"location.hash read", "dom_sinks", `location\.hash`, SevLow, ConfLow,
			"Hash-based source. Only interesting if passed to a sink."},
		{"URLSearchParams(location)", "dom_sinks", `new URLSearchParams\(location`, SevLow, ConfMedium, ""},

		{"__proto__ bracket write", "prototype_pollution", `\.__proto__\s*\[`, SevHigh, ConfHigh,
			"Direct prototype write. If user-controlled this is confirmed pollution."},
		{"constructor.prototype write", "prototype_pollution", `\.constructor\.prototype`, SevHigh, ConfMedium, ""},
		{"Object.assign with req body", "prototype_pollution", `Object\.assign\s*\([^,]+,\s*(?:req\.|body\.|params\.)`, SevHigh, ConfHigh,
			"User-controlled object merged at top level. Classic pollution vector."},
		{"merge/extend with taint", "prototype_pollution", `(?i)(?:merge|extend|deepmerge|deepextend)\s*\([^,]+,\s*(?:req\.|body\.|params\.|JSON\.parse)`, SevHigh, ConfHigh,
			"Deep merge with user-supplied data. High confidence pollution gadget."},
		{"lodash _.merge taint", "prototype_pollution", `_\.merge\s*\([^,]+,\s*(?:req\.|body\.|params\.)`, SevHigh, ConfHigh,
			"Lodash merge with req data. Lodash <4.17.5 is directly exploitable."},
		{"bracket notation taint", "prototype_pollution", `\w+\[(?:req|body|params|query)[\.\[]\w+\]\s*=`, SevMedium, ConfMedium, ""},

		{"fetch() call", "endpoints", `fetch\s*\(\s*['"]([^'"]+)['"]`, SevInfo, ConfHigh, ""},
		{"axios call", "endpoints", `axios\.[a-z]+\s*\(\s*['"]([^'"]+)['"]`, SevInfo, ConfHigh, ""},
		{"XMLHttpRequest open", "endpoints", `\.open\s*\(\s*['"][A-Z]+['"]\s*,\s*['"]([^'"]+)['"]`, SevInfo, ConfHigh, ""},
		{"jQuery AJAX call", "endpoints", `\$\.(?:ajax|get|post)\s*\(\s*['"]([^'"]+)['"]`, SevInfo, ConfHigh, ""},
		{"API path literal", "endpoints", `/api/v?[0-9]*/[a-zA-Z0-9/_\-?=&.]{3,}`, SevInfo, ConfMedium, ""},
		{"Full URL literal", "endpoints", `https?://[a-zA-Z0-9.\-_/?=&#%@+:]{10,}`, SevInfo, ConfMedium, ""},

		{"GraphQL endpoint", "graphql", `/graphql(?:[/?#]|$)`, SevInfo, ConfHigh, ""},
		{"GraphQL operation", "graphql", `(?i)(?:query|mutation|subscription)\s+\w+\s*\{`, SevInfo, ConfHigh,
			"Reveals operation names and structure."},
		{"GraphQL introspection field", "graphql", `__schema|__type|__typename`, SevMedium, ConfMedium,
			"If introspection is enabled on prod this is a full schema leak."},
		{"Apollo client init", "graphql", `(?i)apolloclient|ApolloClient|createApolloClient`, SevInfo, ConfHigh, ""},
		{"gql template tag", "graphql", `gql\s*` + "`", SevInfo, ConfHigh, ""},

		{"Unix file path", "paths", `(?:^|['"])((?:/[a-zA-Z0-9._\-]+){2,})`, SevInfo, ConfLow,
			"May reveal server-side directory structure."},
		{"Windows file path", "paths", `[A-Za-z]:\\(?:[^<>:"/\\|?*\r\n]+\\)*[^<>:"/\\|?*\r\n]*`, SevInfo, ConfMedium, ""},
		{"S3 bucket reference", "paths", `s3://[a-zA-Z0-9.\-_/]+|[a-zA-Z0-9\-]+\.s3(?:\.[a-z0-9\-]+)?\.amazonaws\.com`, SevMedium, ConfHigh,
			"Check bucket ACL. May be publicly readable or writable."},

		{"TODO comment", "comments", `//\s*TODO[:\s]`, SevInfo, ConfLow, ""},
		{"FIXME comment", "comments", `//\s*FIXME[:\s]`, SevInfo, ConfLow, ""},
		{"HACK comment", "comments", `//\s*HACK[:\s]`, SevLow, ConfLow, ""},
		{"Security-related comment", "comments", `(?i)//.*(?:security|vuln|hack|bypass|workaround|insecure)`, SevLow, ConfLow, ""},
		{"Danger comment", "comments", `(?i)//.*(?:broken|don.t use|dangerous|legacy|deprecated)`, SevLow, ConfLow, ""},
		{"Credential comment", "comments", `(?i)//.*(?:password|secret|key|token|credential)`, SevMedium, ConfLow,
			"Comment references creds — check surrounding code."},
	}

	for _, r := range raw {
		re, err := regexp.Compile(r.re)
		if err != nil {
			continue
		}
		patterns = append(patterns, pattern{r.name, r.category, r.sev, r.conf, r.note, re})
	}
}

type dedup struct{ seen map[string]bool }

func newDedup() *dedup { return &dedup{seen: map[string]bool{}} }
func (d *dedup) add(key string) bool {
	if d.seen[key] {
		return false
	}
	d.seen[key] = true
	return true
}

func isPlaceholder(val string) bool {
	lower := strings.ToLower(val)
	for _, hint := range placeholderHints {
		if strings.Contains(lower, strings.ToLower(hint)) {
			return true
		}
	}
	return false
}

func isCommentLine(line string) bool {
	t := strings.TrimSpace(line)
	for _, p := range commentPrefixes {
		if strings.HasPrefix(t, p) {
			return true
		}
	}
	return false
}

func downgradeConf(c Confidence) Confidence {
	switch c {
	case ConfHigh:
		return ConfMedium
	case ConfMedium:
		return ConfLow
	default:
		return ConfLow
	}
}

func scoreConfidence(base Confidence, val, line string) (Confidence, string) {
	conf := base
	note := ""
	if isPlaceholder(val) {
		conf = ConfLow
		note = "Value looks like a placeholder/example — verify manually."
	} else if isCommentLine(line) && conf > ConfLow {
		conf = downgradeConf(conf)
		note = "Found in a comment — lower confidence."
	}
	return conf, note
}

var sevWeight = map[Severity]float64{
	SevCritical: 40, SevHigh: 15, SevMedium: 5, SevLow: 1, SevInfo: 0,
}
var confMult = map[Confidence]float64{
	ConfHigh: 1.0, ConfMedium: 0.6, ConfLow: 0.3,
}

func computeRisk(findings []Finding, flowCount int) (int, string) {
	raw := 0.0
	for _, f := range findings {
		raw += sevWeight[f.Severity] * confMult[f.Confidence]
	}
	// Flows add extra weight because they confirm a real path to a sink.
	bonus := float64(flowCount) * 20.0
	if bonus > 40 {
		bonus = 40
	}
	raw += bonus
	score := int(100.0 * (1.0 - expApprox(-raw/120.0)))
	label := riskLabel(score)
	return score, label
}

// expApprox keeps the scorer self-contained.
func expApprox(x float64) float64 {
	return mathExp(x)
}

var mathExpFn func(float64) float64

func mathExp(x float64) float64 {
	// A short series is accurate enough for this score curve.
	if x < -10 {
		return 0.0
	}
	result := 1.0
	term := 1.0
	for i := 1; i <= 20; i++ {
		term *= x / float64(i)
		result += term
	}
	return result
}

func riskLabel(score int) string {
	switch {
	case score >= 80:
		return "critical"
	case score >= 55:
		return "high"
	case score >= 30:
		return "medium"
	case score >= 10:
		return "low"
	default:
		return "minimal"
	}
}

func fetchContent(url string) (string, error) {
	client := &http.Client{Timeout: 20 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return "", fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	lr := io.LimitReader(resp.Body, 15<<20)
	b, err := io.ReadAll(lr)
	return string(b), err
}

// AnalyzeContent scans already-loaded JavaScript.
func AnalyzeContent(source, content string, flowCount int) AnalysisResult {
	result := AnalysisResult{
		URL:         source,
		Timestamp:   time.Now().UTC().Format(time.RFC3339),
		Summary:     map[string]int{},
		SevSummary:  map[string]int{},
		ConfSummary: map[string]int{},
		FileSize:    len(content),
	}

	dd := newDedup()
	scanner := bufio.NewScanner(strings.NewReader(content))
	scanner.Buffer(make([]byte, 1024*1024), 4*1024*1024)
	lineNum := 0

	for scanner.Scan() {
		lineNum++
		line := scanner.Text()

		for _, p := range patterns {
			matches := p.re.FindAllString(line, -1)
			for _, m := range matches {
				m = strings.TrimSpace(m)
				if m == "" || len(m) < 4 || !isPrintable(m) {
					continue
				}
				key := p.category + ":" + p.name + ":" + m
				if !dd.add(key) {
					continue
				}
				ctx := strings.TrimSpace(line)
				if len(ctx) > 200 {
					ctx = ctx[:200] + "…"
				}
				conf, autoNote := scoreConfidence(p.confidence, m, line)
				note := p.note
				if autoNote != "" {
					if note != "" {
						note = autoNote + " " + note
					} else {
						note = autoNote
					}
				}
				result.Findings = append(result.Findings, Finding{
					Category:   p.category,
					Type:       p.name,
					Value:      m,
					Line:       lineNum,
					Context:    ctx,
					Severity:   p.severity,
					Confidence: conf,
					Note:       note,
				})
				result.Summary[p.category]++
				result.SevSummary[string(p.severity)]++
				result.ConfSummary[string(conf)]++
			}
		}
	}
	result.LineCount = lineNum
	result.RiskScore, result.RiskLabel = computeRisk(result.Findings, flowCount)
	return result
}

// Analyze fetches a URL and runs the content scanner.
func Analyze(url string) (AnalysisResult, string) {
	content, err := fetchContent(url)
	if err != nil {
		return AnalysisResult{
			URL:         url,
			Timestamp:   time.Now().UTC().Format(time.RFC3339),
			Summary:     map[string]int{},
			SevSummary:  map[string]int{},
			ConfSummary: map[string]int{},
			Error:       err.Error(),
		}, ""
	}
	return AnalyzeContent(url, content, 0), content
}

func isPrintable(s string) bool {
	for _, r := range s {
		if r > unicode.MaxASCII && !unicode.IsPrint(r) {
			return false
		}
	}
	return true
}
