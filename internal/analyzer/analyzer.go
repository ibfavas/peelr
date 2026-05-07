package analyzer

import (
	"bufio"
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

const MaxSourceBytes = 20 << 20

type Severity string

const (
	SevCritical Severity = "critical"
	SevHigh     Severity = "high"
	SevMedium   Severity = "medium"
	SevLow      Severity = "low"
	SevInfo     Severity = "info"
)

type Confidence string

const (
	ConfHigh   Confidence = "high"
	ConfMedium Confidence = "medium"
	ConfLow    Confidence = "low"
)

type SourceKind string

const (
	SourceURL  SourceKind = "url"
	SourceJS   SourceKind = "js"
	SourceFile SourceKind = "file"
)

type SourceInput struct {
	ID      string     `json:"id"`
	Name    string     `json:"name"`
	Kind    SourceKind `json:"kind"`
	Origin  string     `json:"origin"`
	Content string     `json:"content"`
}

type Finding struct {
	ID         string     `json:"id"`
	Category   string     `json:"category"`
	Type       string     `json:"type"`
	Title      string     `json:"title"`
	Value      string     `json:"value"`
	Line       int        `json:"line"`
	Column     int        `json:"column"`
	Context    string     `json:"context"`
	Snippet    string     `json:"snippet"`
	Severity   Severity   `json:"severity"`
	Confidence Confidence `json:"confidence"`
	Note       string     `json:"note,omitempty"`
}

type Summary struct {
	TotalFindings      int            `json:"total_findings"`
	ByCategory         map[string]int `json:"by_category"`
	BySeverity         map[string]int `json:"by_severity"`
	ByConfidence       map[string]int `json:"by_confidence"`
	NetworkRequests    int            `json:"network_requests"`
	SensitiveParams    int            `json:"sensitive_params"`
	InterestingComment int            `json:"interesting_comments"`
	RiskScore          int            `json:"risk_score"`
	RiskLabel          string         `json:"risk_label"`
}

type Result struct {
	ID          string     `json:"id"`
	Name        string     `json:"name"`
	Kind        SourceKind `json:"kind"`
	Origin      string     `json:"origin"`
	Status      string     `json:"status"`
	StartedAt   string     `json:"started_at"`
	CompletedAt string     `json:"completed_at,omitempty"`
	FileSize    int        `json:"file_size"`
	LineCount   int        `json:"line_count"`
	Summary     Summary    `json:"summary"`
	Findings    []Finding  `json:"findings"`
	Error       string     `json:"error,omitempty"`
}

type detector struct {
	category   string
	name       string
	title      string
	severity   Severity
	confidence Confidence
	note       string
	re         *regexp.Regexp
}

type requestDetector struct {
	name       string
	title      string
	re         *regexp.Regexp
	confidence Confidence
}

var placeholderHints = []string{
	"example", "sample", "test", "placeholder", "your_", "your-", "<your",
	"replace", "changeme", "dummy", "demo", "fake", "localhost", "000000",
}

var sensitiveParamNames = []string{
	"token", "secret", "key", "password", "passwd", "pwd", "auth", "email", "session",
}

var lineDetectors = mustDetectors([]detector{
	{category: "api_keys", name: "aws_access_key", title: "AWS Access Key", severity: SevCritical, confidence: ConfHigh, re: regexp.MustCompile(`AKIA[0-9A-Z]{16}`)},
	{category: "api_keys", name: "aws_secret_key", title: "AWS Secret Key", severity: SevCritical, confidence: ConfMedium, note: "Verify the 40-character value before treating as valid.", re: regexp.MustCompile(`(?i)aws.{0,20}secret.{0,20}['"][0-9a-zA-Z/+]{40}['"]`)},
	{category: "api_keys", name: "google_api_key", title: "Google API Key", severity: SevHigh, confidence: ConfHigh, re: regexp.MustCompile(`AIza[0-9A-Za-z\-_]{35}`)},
	{category: "api_keys", name: "github_pat", title: "GitHub Token", severity: SevCritical, confidence: ConfHigh, re: regexp.MustCompile(`ghp_[0-9a-zA-Z]{36}|github_pat_[0-9a-zA-Z_]{82}`)},
	{category: "api_keys", name: "stripe_secret", title: "Stripe Secret Key", severity: SevCritical, confidence: ConfHigh, re: regexp.MustCompile(`sk_live_[0-9a-zA-Z]{16,}`)},
	{category: "api_keys", name: "stripe_public", title: "Stripe Publishable Key", severity: SevMedium, confidence: ConfHigh, re: regexp.MustCompile(`pk_live_[0-9a-zA-Z]{16,}`)},
	{category: "api_keys", name: "paypal_token", title: "PayPal Production Token", severity: SevCritical, confidence: ConfHigh, re: regexp.MustCompile(`access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}`)},
	{category: "api_keys", name: "slack_token", title: "Slack Token", severity: SevHigh, confidence: ConfHigh, re: regexp.MustCompile(`xox[baprs]-[0-9a-zA-Z\-]{10,}`)},
	{category: "api_keys", name: "slack_webhook", title: "Slack Webhook", severity: SevHigh, confidence: ConfHigh, re: regexp.MustCompile(`https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[a-zA-Z0-9]+`)},
	{category: "api_keys", name: "firebase", title: "Firebase Reference", severity: SevMedium, confidence: ConfMedium, re: regexp.MustCompile(`[a-z0-9-]+\.firebaseio\.com`)},
	{category: "api_keys", name: "firebase_msg", title: "Firebase Messaging Key", severity: SevHigh, confidence: ConfHigh, re: regexp.MustCompile(`AAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{80,}`)},
	{category: "api_keys", name: "jwt", title: "JWT Token", severity: SevHigh, confidence: ConfHigh, note: "Decode to inspect algorithm, expiry, and claims.", re: regexp.MustCompile(`eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}`)},
	{category: "api_keys", name: "sendgrid", title: "SendGrid API Key", severity: SevHigh, confidence: ConfHigh, re: regexp.MustCompile(`SG\.[a-zA-Z0-9_-]{22,}\.[a-zA-Z0-9_-]{43,}`)},
	{category: "api_keys", name: "generic_key", title: "Generic API Key", severity: SevMedium, confidence: ConfLow, note: "Generic key pattern. Validate manually.", re: regexp.MustCompile(`(?i)(?:api[_-]?key|apikey|client[_-]?secret|access[_-]?token)\s*[:=]\s*['"][^'"]{12,}['"]`)},

	{category: "credentials", name: "password", title: "Hardcoded Password", severity: SevHigh, confidence: ConfLow, re: regexp.MustCompile(`(?i)(?:password|passwd|pwd)\s*[:=]\s*['"][^'"]{6,}['"]`)},
	{category: "credentials", name: "username", title: "Hardcoded Username", severity: SevLow, confidence: ConfLow, re: regexp.MustCompile(`(?i)(?:username|user|login)\s*[:=]\s*['"][^'"]{3,}['"]`)},
	{category: "credentials", name: "basic_auth", title: "Basic Auth Header", severity: SevHigh, confidence: ConfHigh, re: regexp.MustCompile(`Authorization:\s*Basic\s+[A-Za-z0-9+/=]{12,}`)},
	{category: "credentials", name: "bearer", title: "Bearer Token", severity: SevMedium, confidence: ConfMedium, re: regexp.MustCompile(`Authorization:\s*Bearer\s+[A-Za-z0-9\-._~+/]+=*`)},
	{category: "credentials", name: "db_conn", title: "Database Connection String", severity: SevCritical, confidence: ConfHigh, re: regexp.MustCompile(`(?i)(?:mongodb|mysql|postgres|postgresql|redis|amqp|mssql):\/\/[^'">\s]{10,}`)},
	{category: "credentials", name: "private_key", title: "Private Key Block", severity: SevCritical, confidence: ConfHigh, re: regexp.MustCompile(`-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----`)},

	{category: "emails", name: "email", title: "Email Address", severity: SevInfo, confidence: ConfMedium, re: regexp.MustCompile(`\b[a-zA-Z0-9._%+\-]{1,64}@[a-zA-Z0-9.\-]{1,253}\.[a-zA-Z]{2,24}\b`)},

	{category: "xss", name: "innerhtml", title: "innerHTML Assignment", severity: SevHigh, confidence: ConfMedium, note: "Check whether user-controlled input reaches the sink.", re: regexp.MustCompile(`\.innerHTML\s*[+]?=`)},
	{category: "xss", name: "outerhtml", title: "outerHTML Assignment", severity: SevHigh, confidence: ConfMedium, re: regexp.MustCompile(`\.outerHTML\s*[+]?=`)},
	{category: "xss", name: "document_write", title: "document.write Usage", severity: SevHigh, confidence: ConfMedium, re: regexp.MustCompile(`document\.write(?:ln)?\s*\(`)},
	{category: "xss", name: "eval", title: "eval() Usage", severity: SevHigh, confidence: ConfMedium, re: regexp.MustCompile(`\beval\s*\(`)},
	{category: "xss", name: "function_ctor", title: "Function Constructor", severity: SevHigh, confidence: ConfMedium, re: regexp.MustCompile(`new\s+Function\s*\(`)},
	{category: "xss", name: "dangerously_set_inner_html", title: "React dangerouslySetInnerHTML", severity: SevHigh, confidence: ConfMedium, re: regexp.MustCompile(`dangerouslySetInnerHTML\s*=\s*\{`)},
	{category: "xss", name: "jquery_html", title: "jQuery html() Injection Point", severity: SevHigh, confidence: ConfMedium, re: regexp.MustCompile(`\$\([^)]+\)\.(?:html|append|prepend|before|after)\s*\(`)},
	{category: "xss", name: "insert_adjacent_html", title: "insertAdjacentHTML Usage", severity: SevHigh, confidence: ConfMedium, re: regexp.MustCompile(`\.insertAdjacentHTML\s*\(`)},
	{category: "xss", name: "srcdoc", title: "srcdoc Assignment", severity: SevHigh, confidence: ConfMedium, re: regexp.MustCompile(`\.srcdoc\s*=`)},

	{category: "paths", name: "unix_path", title: "Unix Path", severity: SevInfo, confidence: ConfLow, re: regexp.MustCompile(`(?:^|['"\s])((?:/[\w.\-]+){2,})`)},
	{category: "paths", name: "relative_path", title: "Relative Path", severity: SevInfo, confidence: ConfLow, re: regexp.MustCompile(`(?:\.{1,2}/[\w./\-]+\.(?:js|json|map|html|txt|env|graphql))`)},
	{category: "paths", name: "windows_path", title: "Windows Path", severity: SevInfo, confidence: ConfMedium, re: regexp.MustCompile(`[A-Za-z]:\\(?:[^<>:"/\\|?*\r\n]+\\)*[^<>:"/\\|?*\r\n]*`)},
	{category: "paths", name: "s3", title: "S3 Reference", severity: SevMedium, confidence: ConfHigh, re: regexp.MustCompile(`s3://[a-zA-Z0-9.\-_/]+|[a-zA-Z0-9\-]+\.s3(?:\.[a-z0-9\-]+)?\.amazonaws\.com`)},
})

var commentDetectors = mustDetectors([]detector{
	{category: "comments", name: "todo", title: "TODO Comment", severity: SevInfo, confidence: ConfLow, re: regexp.MustCompile(`(?i)\bTODO\b`)},
	{category: "comments", name: "fixme", title: "FIXME Comment", severity: SevInfo, confidence: ConfLow, re: regexp.MustCompile(`(?i)\bFIXME\b`)},
	{category: "comments", name: "hack", title: "HACK Comment", severity: SevLow, confidence: ConfLow, re: regexp.MustCompile(`(?i)\bHACK\b`)},
	{category: "comments", name: "security", title: "Security Comment", severity: SevMedium, confidence: ConfLow, note: "Comment references a sensitive topic. Review surrounding code.", re: regexp.MustCompile(`(?i)\b(security|vuln|bypass|insecure|workaround|token|secret|password|credential)\b`)},
})

var requestDetectors = []requestDetector{
	{name: "fetch", title: "fetch() Request", re: regexp.MustCompile(`fetch\s*\(\s*['"]([^'"]+)['"]`), confidence: ConfHigh},
	{name: "axios", title: "axios Request", re: regexp.MustCompile(`axios(?:\.[a-z]+)?\s*\(\s*['"]([^'"]+)['"]`), confidence: ConfHigh},
	{name: "xhr", title: "XMLHttpRequest open()", re: regexp.MustCompile(`\.open\s*\(\s*['"][A-Z]+['"]\s*,\s*['"]([^'"]+)['"]`), confidence: ConfHigh},
	{name: "jquery_ajax", title: "jQuery AJAX Call", re: regexp.MustCompile(`\$\.(?:ajax|get|post)\s*\(\s*['"]([^'"]+)['"]`), confidence: ConfHigh},
}

var genericEndpointRe = regexp.MustCompile(`https?://[a-zA-Z0-9.\-_/?=&#%@+:]{8,}|/[a-zA-Z0-9._\-/]+(?:\?[a-zA-Z0-9=&_%\-@.:]+)?`)
var queryParamRe = regexp.MustCompile(`[?&]([a-zA-Z0-9_.\-]{1,64})=`)
var functionDeclRe = regexp.MustCompile(`function(?:\s+[A-Za-z0-9_$]+)?\s*\(([^)]{1,200})\)`)
var arrowDeclRe = regexp.MustCompile(`(?:const|let|var)?\s*[A-Za-z0-9_$]*\s*=\s*\(([^)]{1,200})\)\s*=>`)
var userInputRe = regexp.MustCompile(`location\.(?:hash|search|href)|document\.(?:URL|cookie|referrer)|window\.name|URLSearchParams|event\.data|req\.(?:body|query|params)`)

func mustDetectors(items []detector) []detector {
	return items
}

func LoadURL(raw string) (SourceInput, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return SourceInput{}, fmt.Errorf("empty URL")
	}
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return SourceInput{}, fmt.Errorf("invalid URL: %s", raw)
	}
	client := &http.Client{Timeout: 20 * time.Second}
	resp, err := client.Get(raw)
	if err != nil {
		return SourceInput{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return SourceInput{}, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	if resp.ContentLength > MaxSourceBytes {
		return SourceInput{}, fmt.Errorf("file exceeds %d MB limit", MaxSourceBytes>>20)
	}
	limited := io.LimitReader(resp.Body, MaxSourceBytes+1)
	body, err := io.ReadAll(limited)
	if err != nil {
		return SourceInput{}, err
	}
	if len(body) > MaxSourceBytes {
		return SourceInput{}, fmt.Errorf("file exceeds %d MB limit", MaxSourceBytes>>20)
	}
	return SourceInput{
		ID:      SourceKey(SourceURL, raw),
		Name:    filepath.Base(parsed.Path),
		Kind:    SourceURL,
		Origin:  raw,
		Content: string(body),
	}, nil
}

func Analyze(input SourceInput) Result {
	startedAt := time.Now().UTC().Format(time.RFC3339)
	result := Result{
		ID:        sourceID(input),
		Name:      fallbackName(input),
		Kind:      input.Kind,
		Origin:    input.Origin,
		Status:    "completed",
		StartedAt: startedAt,
		FileSize:  len(input.Content),
		Summary: Summary{
			ByCategory:   map[string]int{},
			BySeverity:   map[string]int{},
			ByConfidence: map[string]int{},
		},
	}

	content := strings.ReplaceAll(input.Content, "\r\n", "\n")
	lines := strings.Split(content, "\n")
	result.LineCount = len(lines)
	dedup := map[string]bool{}

	for i, line := range lines {
		lineNo := i + 1
		trimmed := strings.TrimSpace(line)
		context := trimContext(trimmed)

		for _, d := range lineDetectors {
			matches := d.re.FindAllStringIndex(line, -1)
			for _, loc := range matches {
				value := strings.TrimSpace(line[loc[0]:loc[1]])
				if d.category == "emails" && !isStrictEmailMatch(line, loc[0], loc[1], value) {
					continue
				}
				conf, note := adjustConfidence(d.confidence, value, trimmed)
				sev := d.severity
				if d.category == "xss" && userInputRe.MatchString(line) {
					conf = ConfHigh
					if sev == SevMedium {
						sev = SevHigh
					}
					note = appendNote(note, "User-controlled input appears on the same line.")
				}
				addFinding(&result, dedup, Finding{
					Category:   d.category,
					Type:       d.name,
					Title:      d.title,
					Value:      normalizeValue(value),
					Line:       lineNo,
					Column:     loc[0] + 1,
					Context:    context,
					Snippet:    makeSnippet(lines, lineNo),
					Severity:   sev,
					Confidence: conf,
					Note:       appendNote(note, d.note),
				})
			}
		}

		if isCommentLine(trimmed) {
			for _, d := range commentDetectors {
				if d.re.MatchString(trimmed) {
					addFinding(&result, dedup, Finding{
						Category:   d.category,
						Type:       d.name,
						Title:      d.title,
						Value:      context,
						Line:       lineNo,
						Column:     1,
						Context:    context,
						Snippet:    makeSnippet(lines, lineNo),
						Severity:   d.severity,
						Confidence: d.confidence,
						Note:       d.note,
					})
				}
			}
		}

		for _, req := range requestDetectors {
			matches := req.re.FindAllStringSubmatchIndex(line, -1)
			for _, loc := range matches {
				if len(loc) < 4 {
					continue
				}
				value := line[loc[2]:loc[3]]
				addFinding(&result, dedup, Finding{
					Category:   "endpoints",
					Type:       req.name,
					Title:      req.title,
					Value:      value,
					Line:       lineNo,
					Column:     loc[2] + 1,
					Context:    context,
					Snippet:    makeSnippet(lines, lineNo),
					Severity:   SevInfo,
					Confidence: req.confidence,
				})
			}
		}

		endpoints := genericEndpointRe.FindAllStringIndex(line, -1)
		if !isCommentLine(trimmed) {
			for _, loc := range endpoints {
				value := strings.Trim(line[loc[0]:loc[1]], `"' )];,`)
				if !looksLikeEndpoint(value) {
					continue
				}
				addFinding(&result, dedup, Finding{
					Category:   "endpoints",
					Type:       "endpoint_literal",
					Title:      "Endpoint Literal",
					Value:      value,
					Line:       lineNo,
					Column:     loc[0] + 1,
					Context:    context,
					Snippet:    makeSnippet(lines, lineNo),
					Severity:   SevInfo,
					Confidence: ConfMedium,
				})
			}
		}

		extractQueryParams(&result, dedup, lines, lineNo, line, context)
		extractFunctionParams(&result, dedup, lines, lineNo, line, context)
	}

	sort.Slice(result.Findings, func(i, j int) bool {
		if result.Findings[i].Line == result.Findings[j].Line {
			if result.Findings[i].Category == result.Findings[j].Category {
				return result.Findings[i].Column < result.Findings[j].Column
			}
			return result.Findings[i].Category < result.Findings[j].Category
		}
		return result.Findings[i].Line < result.Findings[j].Line
	})

	result.CompletedAt = time.Now().UTC().Format(time.RFC3339)
	result.Summary.TotalFindings = len(result.Findings)
	result.Summary.RiskScore, result.Summary.RiskLabel = computeRisk(result.Findings)
	return result
}

func extractQueryParams(result *Result, dedup map[string]bool, lines []string, lineNo int, line, context string) {
	matches := queryParamRe.FindAllStringSubmatchIndex(line, -1)
	for _, loc := range matches {
		if len(loc) < 4 {
			continue
		}
		name := line[loc[2]:loc[3]]
		severity := SevInfo
		confidence := ConfMedium
		title := "URL Query Parameter"
		note := ""
		if isSensitiveParam(name) {
			severity = SevMedium
			confidence = ConfHigh
			title = "Sensitive Query Parameter"
			note = "Sensitive parameter name detected."
		}
		addFinding(result, dedup, Finding{
			Category:   "parameters",
			Type:       "query_parameter",
			Title:      title,
			Value:      name,
			Line:       lineNo,
			Column:     loc[2] + 1,
			Context:    context,
			Snippet:    makeSnippet(lines, lineNo),
			Severity:   severity,
			Confidence: confidence,
			Note:       note,
		})
	}
}

func extractFunctionParams(result *Result, dedup map[string]bool, lines []string, lineNo int, line, context string) {
	paramLists := [][]string{}
	for _, re := range []*regexp.Regexp{functionDeclRe, arrowDeclRe} {
		matches := re.FindAllStringSubmatch(line, -1)
		for _, match := range matches {
			if len(match) < 2 {
				continue
			}
			paramLists = append(paramLists, strings.Split(match[1], ","))
		}
	}
	for _, params := range paramLists {
		for _, raw := range params {
			name := strings.TrimSpace(raw)
			if name == "" {
				continue
			}
			severity := SevInfo
			confidence := ConfMedium
			title := "Function Parameter"
			note := ""
			if isSensitiveParam(name) {
				severity = SevMedium
				confidence = ConfHigh
				title = "Sensitive Function Parameter"
				note = "Sensitive parameter name detected."
			}
			column := strings.Index(line, name)
			if column < 0 {
				column = 0
			}
			addFinding(result, dedup, Finding{
				Category:   "parameters",
				Type:       "function_parameter",
				Title:      title,
				Value:      name,
				Line:       lineNo,
				Column:     column + 1,
				Context:    context,
				Snippet:    makeSnippet(lines, lineNo),
				Severity:   severity,
				Confidence: confidence,
				Note:       note,
			})
		}
	}
}

func addFinding(result *Result, dedup map[string]bool, finding Finding) {
	key := strings.Join([]string{finding.Category, finding.Type, finding.Value, fmt.Sprint(finding.Line)}, ":")
	if dedup[key] {
		return
	}
	dedup[key] = true
	finding.ID = stableID(key)
	result.Findings = append(result.Findings, finding)
	result.Summary.ByCategory[finding.Category]++
	result.Summary.BySeverity[string(finding.Severity)]++
	result.Summary.ByConfidence[string(finding.Confidence)]++
	if finding.Category == "endpoints" {
		result.Summary.NetworkRequests++
	}
	if finding.Category == "parameters" && strings.Contains(strings.ToLower(finding.Title), "sensitive") {
		result.Summary.SensitiveParams++
	}
	if finding.Category == "comments" {
		result.Summary.InterestingComment++
	}
}

func computeRisk(findings []Finding) (int, string) {
	sevWeight := map[Severity]float64{
		SevCritical: 28,
		SevHigh:     12,
		SevMedium:   4,
		SevLow:      1,
		SevInfo:     0.25,
	}
	confWeight := map[Confidence]float64{
		ConfHigh:   1.0,
		ConfMedium: 0.65,
		ConfLow:    0.35,
	}
	raw := 0.0
	for _, finding := range findings {
		raw += sevWeight[finding.Severity] * confWeight[finding.Confidence]
	}
	score := int(100.0 * (1.0 - expApprox(-raw/90.0)))
	switch {
	case score >= 80:
		return score, "critical"
	case score >= 55:
		return score, "high"
	case score >= 28:
		return score, "medium"
	case score >= 10:
		return score, "low"
	default:
		return score, "minimal"
	}
}

func expApprox(x float64) float64 {
	if x < -10 {
		return 0
	}
	total := 1.0
	term := 1.0
	for i := 1; i <= 18; i++ {
		term *= x / float64(i)
		total += term
	}
	return total
}

func adjustConfidence(base Confidence, value, line string) (Confidence, string) {
	if isPlaceholder(value) {
		return ConfLow, "Value looks like a placeholder or example."
	}
	if isCommentLine(strings.TrimSpace(line)) && base == ConfHigh {
		return ConfMedium, "Value appears inside a comment."
	}
	if isCommentLine(strings.TrimSpace(line)) && base == ConfMedium {
		return ConfLow, "Value appears inside a comment."
	}
	return base, ""
}

func isPlaceholder(value string) bool {
	lower := strings.ToLower(value)
	for _, hint := range placeholderHints {
		if strings.Contains(lower, hint) {
			return true
		}
	}
	return false
}

func isCommentLine(line string) bool {
	return strings.HasPrefix(line, "//") || strings.HasPrefix(line, "/*") || strings.HasPrefix(line, "*") || strings.HasPrefix(line, "#")
}

func trimContext(line string) string {
	line = strings.TrimSpace(line)
	if len(line) > 220 {
		return line[:220] + "..."
	}
	return line
}

func makeSnippet(lines []string, lineNo int) string {
	start := lineNo - 2
	if start < 1 {
		start = 1
	}
	end := lineNo + 2
	if end > len(lines) {
		end = len(lines)
	}
	var b strings.Builder
	for i := start; i <= end; i++ {
		b.WriteString(fmt.Sprintf("%4d | %s", i, lines[i-1]))
		if i < end {
			b.WriteByte('\n')
		}
	}
	return b.String()
}

func looksLikeEndpoint(value string) bool {
	if value == "" || value == "/" || value == "//" || strings.HasPrefix(value, "//") {
		return false
	}
	if strings.HasPrefix(value, "/") {
		return strings.Count(value, "/") >= 1
	}
	return strings.HasPrefix(value, "http://") || strings.HasPrefix(value, "https://")
}

func isSensitiveParam(name string) bool {
	lower := strings.ToLower(strings.TrimSpace(name))
	for _, item := range sensitiveParamNames {
		if strings.Contains(lower, item) {
			return true
		}
	}
	return false
}

func normalizeValue(value string) string {
	value = strings.TrimSpace(value)
	value = strings.Trim(value, `"'`)
	if len(value) > 160 {
		return value[:160] + "..."
	}
	return value
}

func appendNote(parts ...string) string {
	var kept []string
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part != "" {
			kept = append(kept, part)
		}
	}
	return strings.Join(kept, " ")
}

func isStrictEmailMatch(line string, start, end int, value string) bool {
	if strings.Count(value, "@") != 1 {
		return false
	}
	localDomain := strings.Split(value, "@")
	if len(localDomain) != 2 || localDomain[0] == "" || localDomain[1] == "" {
		return false
	}
	if strings.Contains(localDomain[1], "..") || strings.HasPrefix(localDomain[1], ".") || strings.HasSuffix(localDomain[1], ".") {
		return false
	}
	if start > 0 {
		prev := line[start-1]
		if prev == '/' || prev == ':' || prev == '@' {
			return false
		}
	}
	if end < len(line) {
		next := line[end]
		if next == '/' || next == ':' || next == '@' {
			return false
		}
	}
	tokenStart := start
	for tokenStart > 0 && !isDelimiter(line[tokenStart-1]) {
		tokenStart--
	}
	tokenEnd := end
	for tokenEnd < len(line) && !isDelimiter(line[tokenEnd]) {
		tokenEnd++
	}
	token := line[tokenStart:tokenEnd]
	if strings.Contains(token, "://") || strings.Contains(token, "/@") || strings.Contains(token, "@/") {
		return false
	}
	return true
}

func isDelimiter(ch byte) bool {
	switch ch {
	case ' ', '\t', '\n', '\r', '"', '\'', '`', '(', ')', '[', ']', '{', '}', ',', ';', '<', '>', '=':
		return true
	default:
		return false
	}
}

func sourceID(input SourceInput) string {
	if input.ID != "" {
		return input.ID
	}
	if input.Origin != "" {
		return SourceKey(input.Kind, input.Origin)
	}
	return SourceKey(input.Kind, input.Name)
}

func fallbackName(input SourceInput) string {
	if input.Name != "" {
		return input.Name
	}
	if input.Origin != "" {
		return input.Origin
	}
	return "source.js"
}

func stableID(value string) string {
	sum := sha1.Sum([]byte(value))
	return hex.EncodeToString(sum[:8])
}

func SourceKey(kind SourceKind, value string) string {
	return stableID(kind.String() + ":" + value)
}

func ReadURLs(r io.Reader) ([]string, error) {
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 0, 64*1024), 2*1024*1024)
	seen := map[string]bool{}
	var items []string
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || seen[line] {
			continue
		}
		seen[line] = true
		items = append(items, line)
	}
	return items, scanner.Err()
}

func (s SourceKind) String() string {
	return string(s)
}
