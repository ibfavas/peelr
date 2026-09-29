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
	"sort"
	"strconv"
	"strings"
	"time"
)

const MaxSourceBytes = 20 << 20

// Performance guardrails. Minified bundles can put megabytes on a single
// line; without chunking and caps, regex scanning and result rendering grind
// to a halt.
const (
	maxChunkLen            = 8192
	chunkStep              = 7936 // maxChunkLen minus 256 bytes of overlap
	maxMatchesPerScan      = 100
	maxMatchesLongLine     = 5000
	maxFindingsPerCategory = 400
	maxTotalFindings       = 3000
)

var browserUA = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0 Safari/537.36"

func LoadURL(raw string) (SourceInput, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return SourceInput{}, fmt.Errorf("empty URL")
	}
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return SourceInput{}, fmt.Errorf("invalid URL: %s", raw)
	}
	req, err := http.NewRequest(http.MethodGet, raw, nil)
	if err != nil {
		return SourceInput{}, err
	}
	req.Header.Set("User-Agent", browserUA)
	req.Header.Set("Accept", "application/javascript, text/javascript, */*")
	client := &http.Client{Timeout: 20 * time.Second}
	resp, err := client.Do(req)
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
	if ct := resp.Header.Get("Content-Type"); !looksLikeJS(ct, parsed.Path) {
		if ct == "" {
			ct = "unknown"
		}
		return SourceInput{}, fmt.Errorf("URL did not return JavaScript (Content-Type: %s)", ct)
	}
	limited := io.LimitReader(resp.Body, MaxSourceBytes+1)
	body, err := io.ReadAll(limited)
	if err != nil {
		return SourceInput{}, err
	}
	if len(body) > MaxSourceBytes {
		return SourceInput{}, fmt.Errorf("file exceeds %d MB limit", MaxSourceBytes>>20)
	}
	name := filepath.Base(parsed.Path)
	if name == "/" || name == "." || name == "" {
		name = parsed.Host
	}
	return SourceInput{
		ID:      SourceKey(SourceURL, raw),
		Name:    name,
		Kind:    SourceURL,
		Origin:  raw,
		Content: string(body),
	}, nil
}

func looksLikeJS(contentType, path string) bool {
	ct := strings.ToLower(contentType)
	if strings.Contains(ct, "javascript") || strings.Contains(ct, "ecmascript") {
		return true
	}
	if strings.HasSuffix(strings.ToLower(path), ".js") {
		return true
	}
	// Permissive: many servers mislabel JS as plain text or octet-stream.
	return ct == "" || strings.HasPrefix(ct, "text/plain") || strings.HasPrefix(ct, "application/octet-stream")
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
			Truncated:    map[string]int{},
		},
	}

	content := strings.ReplaceAll(input.Content, "\r\n", "\n")
	lines := strings.Split(content, "\n")
	result.LineCount = len(lines)
	result.Minified = detectMinified(content, lines)
	dedup := map[string]bool{}

	for i, line := range lines {
		// processSegment handles long (minified) lines internally:
		// literals are extracted once for the whole line, then only the
		// stateless code patterns are scanned in chunks.
		processSegment(&result, dedup, lines, i+1, 0, line)
	}

	sortFindings(result.Findings)

	result.CompletedAt = time.Now().UTC().Format(time.RFC3339)
	result.Summary.TotalFindings = len(result.Findings)
	result.Summary.RiskScore, result.Summary.RiskLabel = computeRisk(result.Findings)
	return result
}

// processSegment analyzes one line (or one window of a long line).
// colOffset is the byte offset of the segment within the line.
func processSegment(result *Result, dedup map[string]bool, lines []string, lineNo, colOffset int, segment string) {
	trimmed := strings.TrimSpace(segment)
	if trimmed == "" {
		return
	}
	context := trimContext(trimmed)

	if isCommentLine(trimmed) {
		for _, d := range commentDetectors {
			if d.re.MatchString(trimmed) {
				addFinding(result, dedup, Finding{
					Category:   d.category,
					Type:       d.name,
					Title:      d.title,
					Value:      context,
					Line:       lineNo,
					Column:     colOffset + 1,
					Context:    context,
					Snippet:    makeSnippet(lines, lineNo),
					Severity:   d.severity,
					Confidence: d.confidence,
					Note:       d.note,
				})
			}
		}
		return
	}

	if len(segment) <= maxChunkLen {
		processChunk(result, dedup, lines, lineNo, colOffset, segment, context)
		return
	}

	// Long (usually minified) line: literal extraction is stateful — a chunk
	// that starts mid-literal would flip quote parity and corrupt every
	// literal in the chunk. So extract literals once for the whole line,
	// then scan the stateless code patterns in overlapping chunks.
	stripped, lits := extractLiterals(segment)
	reqSpans := collectRequestSpans(result, dedup, lines, lineNo, colOffset, segment, context)
	for off := 0; off < len(segment); off += chunkStep {
		end := off + maxChunkLen
		if end > len(segment) {
			end = len(segment)
		}
		processCodePatterns(result, dedup, lines, lineNo, colOffset+off, segment[off:end], stripped[off:end], context)
		if end == len(segment) {
			break
		}
	}
	for _, lit := range lits {
		processLiteral(result, dedup, lines, lineNo, colOffset, segment, lit, reqSpans, context)
	}
}

// processChunk handles a normal-length segment: extract literals, then run
// code patterns and literal patterns.
func processChunk(result *Result, dedup map[string]bool, lines []string, lineNo, colOffset int, segment, context string) {
	stripped, lits := extractLiterals(segment)
	reqSpans := collectRequestSpans(result, dedup, lines, lineNo, colOffset, segment, context)
	processCodePatterns(result, dedup, lines, lineNo, colOffset, segment, stripped, context)
	for _, lit := range lits {
		processLiteral(result, dedup, lines, lineNo, colOffset, segment, lit, reqSpans, context)
	}
}

// collectRequestSpans reports fetch()/axios/... calls and returns their
// match spans so generic endpoint detection can skip already-reported URLs.
func collectRequestSpans(result *Result, dedup map[string]bool, lines []string, lineNo, colOffset int, segment, context string) [][2]int {
	reqSpans := [][2]int{}
	// Long lines may hold thousands of calls; the per-category cap bounds
	// output, so allow more matches here than in a normal chunk.
	limit := maxMatchesPerScan
	if len(segment) > maxChunkLen {
		limit = maxMatchesLongLine
	}
	for _, d := range requestDetectors {
		for _, loc := range d.re.FindAllStringSubmatchIndex(segment, limit) {
			if len(loc) < 4 || loc[2] < 0 {
				continue
			}
			value := segment[loc[2]:loc[3]]
			if !looksLikeEndpoint(value) {
				continue
			}
			reqSpans = append(reqSpans, [2]int{loc[0], loc[1]})
			addFinding(result, dedup, Finding{
				Category:   d.category,
				Type:       d.name,
				Title:      d.title,
				Value:      normalizeValue(value),
				Line:       lineNo,
				Column:     colOffset + loc[2] + 1,
				Context:    context,
				Snippet:    makeSnippet(lines, lineNo),
				Severity:   d.severity,
				Confidence: d.confidence,
			})
		}
	}
	return reqSpans
}

// processCodePatterns runs the code-scope detectors (DOM sinks, function
// parameters) against a segment. `stripped` is the same segment with string
// literal contents blanked; both share coordinates.
func processCodePatterns(result *Result, dedup map[string]bool, lines []string, lineNo, colOffset int, segment, stripped, context string) {
	// DOM sinks run against the line with literals blanked, except
	// detectors marked raw, which need to see string arguments.
	for _, d := range sinkDetectors {
		src := stripped
		if d.raw {
			src = segment
		}
		for _, loc := range d.re.FindAllStringSubmatchIndex(src, maxMatchesPerScan) {
			value := strings.TrimSpace(src[loc[0]:loc[1]])
			conf, note := d.confidence, d.note
			if userInputRe.MatchString(src) {
				conf = ConfHigh
				note = appendNote(note, "User-controlled input appears on the same line.")
			}
			addFinding(result, dedup, Finding{
				Category:   d.category,
				Type:       d.name,
				Title:      d.title,
				Value:      normalizeValue(value),
				Line:       lineNo,
				Column:     colOffset + loc[0] + 1,
				Context:    context,
				Snippet:    makeSnippet(lines, lineNo),
				Severity:   d.severity,
				Confidence: conf,
				Note:       note,
			})
		}
	}

	// Function parameters: only sensitive-named ones are worth reporting.
	seenParams := map[string]bool{}
	for _, match := range functionDeclRe.FindAllStringSubmatchIndex(stripped, maxMatchesPerScan) {
		collectSensitiveParams(result, dedup, lines, lineNo, colOffset, segment, context, match, seenParams)
	}
	for _, match := range arrowDeclRe.FindAllStringSubmatchIndex(stripped, maxMatchesPerScan) {
		collectSensitiveParams(result, dedup, lines, lineNo, colOffset, segment, context, match, seenParams)
	}
}

// processLiteral runs the value-scope detectors (secrets, endpoints,
// parameters, paths, emails) against a single string literal. lit.start is
// the literal's offset within segment; colOffset shifts to line coordinates.
func processLiteral(result *Result, dedup map[string]bool, lines []string, lineNo, colOffset int, segment string, lit strLiteral, reqSpans [][2]int, context string) {
	litCol := colOffset + lit.start
	isEndpoint := false

	for _, d := range secretDetectors {
		for _, loc := range d.re.FindAllStringSubmatchIndex(lit.value, maxMatchesPerScan) {
			g := d.group
			if g < 0 || 2*g+1 >= len(loc) || loc[2*g] < 0 {
				continue
			}
			raw := lit.value[loc[2*g]:loc[2*g+1]]
			value := normalizeValue(raw)
			conf, note := d.confidence, d.note
			if d.validate != nil {
				keep, vconf, vnote := d.validate(raw)
				if !keep {
					continue
				}
				if vconf != "" {
					conf = vconf
				}
				note = appendNote(note, vnote)
			}
			if d.name == "email" && !emailOK(lit.value) {
				continue
			}
			conf, note = downgradePlaceholder(conf, note, raw)
			addFinding(result, dedup, Finding{
				Category:   d.category,
				Type:       d.name,
				Title:      d.title,
				Value:      value,
				Line:       lineNo,
				Column:     litCol + loc[2*g] + 1,
				Context:    context,
				Snippet:    makeSnippet(lines, lineNo),
				Severity:   d.severity,
				Confidence: conf,
				Note:       note,
			})
		}
	}

	// Assigned secrets: a literal whose preceding key is sensitive-named,
	// e.g. const password = "s3cr3t" or {"apiKey": "xyz"}. This catches
	// the common case where key and value are separate literals.
	if key := precedingKey(segment, lit.start); isSensitiveName(key) {
		value := strings.TrimSpace(lit.value)
		// A template literal with interpolation ("Bearer ${token}") holds a
		// variable reference, not a hardcoded value. Email-shaped values are
		// left to the email detector (or dropped as example domains).
		if len(value) >= 4 && !isDummyValue(value) &&
			!strings.Contains(value, "${") && !looksLikeEmail(value) {
			typ, title, sev := "secret_value", "Hardcoded Secret", SevMedium
			switch {
			case isPasswordKey(key):
				typ, title, sev = "password", "Hardcoded Password", SevHigh
			case isUserKey(key):
				typ, title, sev = "username", "Hardcoded Username", SevLow
			}
			conf, note := ConfMedium, "Value assigned to a sensitive-named key ("+key+")."
			if isPlaceholder(value) {
				conf = ConfLow
				note = appendNote(note, "Value looks like a placeholder or example.")
			}
			addFinding(result, dedup, Finding{
				Category:   "credentials",
				Type:       typ,
				Title:      title,
				Value:      normalizeValue(value),
				Line:       lineNo,
				Column:     litCol + 1,
				Context:    context,
				Snippet:    makeSnippet(lines, lineNo),
				Severity:   sev,
				Confidence: conf,
				Note:       note,
			})
		}
	}

	// Generic endpoint literal, unless already reported via a request wrapper.
	if v := strings.TrimSpace(lit.value); looksLikeEndpoint(v) && !spanCovered(reqSpans, lit.start, lit.end) {
		isEndpoint = true
		title := "Endpoint Literal"
		if strings.HasPrefix(v, "ws://") || strings.HasPrefix(v, "wss://") {
			title = "WebSocket Endpoint"
		}
		addFinding(result, dedup, Finding{
			Category:   "endpoints",
			Type:       "endpoint_literal",
			Title:      title,
			Value:      normalizeValue(v),
			Line:       lineNo,
			Column:     litCol + 1,
			Context:    context,
			Snippet:    makeSnippet(lines, lineNo),
			Severity:   SevInfo,
			Confidence: ConfMedium,
		})
	}

	// Query parameters, only inside URL-like literals.
	if strings.Contains(lit.value, "?") {
		for _, loc := range queryParamRe.FindAllStringSubmatchIndex(lit.value, maxMatchesPerScan) {
			if len(loc) < 4 || loc[2] < 0 {
				continue
			}
			name := lit.value[loc[2]:loc[3]]
			severity, confidence, title, note := SevInfo, ConfMedium, "URL Query Parameter", ""
			if isSensitiveName(name) {
				severity, confidence, title = SevMedium, ConfHigh, "Sensitive Query Parameter"
				note = "Sensitive parameter name detected."
			}
			addFinding(result, dedup, Finding{
				Category:   "parameters",
				Type:       "query_parameter",
				Title:      title,
				Value:      name,
				Line:       lineNo,
				Column:     litCol + loc[2] + 1,
				Context:    context,
				Snippet:    makeSnippet(lines, lineNo),
				Severity:   severity,
				Confidence: confidence,
				Note:       note,
			})
		}
	}

	// Path and filename patterns. A literal already reported as an endpoint
	// is not reported again as a generic unix path.
	for _, d := range pathDetectors {
		for _, loc := range d.re.FindAllStringSubmatchIndex(lit.value, maxMatchesPerScan) {
			value := strings.TrimSpace(lit.value[loc[0]:loc[1]])
			if d.name == "unix_path" && isEndpoint {
				continue
			}
			addFinding(result, dedup, Finding{
				Category:   d.category,
				Type:       d.name,
				Title:      d.title,
				Value:      normalizeValue(value),
				Line:       lineNo,
				Column:     litCol + loc[0] + 1,
				Context:    context,
				Snippet:    makeSnippet(lines, lineNo),
				Severity:   d.severity,
				Confidence: d.confidence,
				Note:       d.note,
			})
		}
	}
}

func collectSensitiveParams(result *Result, dedup map[string]bool, lines []string, lineNo, colOffset int, segment, context string, match []int, seen map[string]bool) {
	if len(match) < 4 || match[2] < 0 {
		return
	}
	for _, raw := range strings.Split(segment[match[2]:match[3]], ",") {
		name := strings.TrimSpace(raw)
		// Strip default values and destructuring noise: "opts = {}" -> "opts".
		if idx := strings.IndexAny(name, " =:{"); idx > 0 {
			name = strings.TrimSpace(name[:idx])
		}
		if name == "" || seen[name] || !isSensitiveName(name) {
			continue
		}
		seen[name] = true
		column := strings.Index(segment, name)
		if column < 0 {
			column = 0
		}
		addFinding(result, dedup, Finding{
			Category:   "parameters",
			Type:       "function_parameter",
			Title:      "Sensitive Function Parameter",
			Value:      name,
			Line:       lineNo,
			Column:     colOffset + column + 1,
			Context:    context,
			Snippet:    makeSnippet(lines, lineNo),
			Severity:   SevMedium,
			Confidence: ConfHigh,
			Note:       "Sensitive parameter name detected.",
		})
	}
}

// precedingKey returns the identifier immediately before a string literal's
// opening quote, skipping whitespace, quotes, colons and equals signs.
// For {"password": "x"} or password = "x", it returns "password".
func precedingKey(segment string, quotePos int) string {
	i := quotePos - 1
	for i >= 0 {
		c := segment[i]
		if c == ' ' || c == '\t' || c == '"' || c == '\'' || c == '`' || c == ':' || c == '=' {
			i--
			continue
		}
		break
	}
	end := i
	for i >= 0 {
		c := segment[i]
		if c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '$' {
			i--
			continue
		}
		break
	}
	if end <= i {
		return ""
	}
	return segment[i+1 : end+1]
}

func isPasswordKey(key string) bool {
	for _, t := range tokenizeIdent(key) {
		if t == "password" || t == "passwd" || t == "pwd" {
			return true
		}
	}
	return false
}

func isUserKey(key string) bool {
	for _, t := range tokenizeIdent(key) {
		if t == "user" || t == "username" || t == "login" {
			return true
		}
	}
	return false
}

// emailOK drops literal values that cannot contain a real email address.
func emailOK(literalValue string) bool {
	if strings.Contains(literalValue, "://") {
		return false
	}
	lower := strings.ToLower(literalValue)
	if isPlaceholder(literalValue) {
		return false
	}
	for _, bad := range []string{"@localhost", ".local", ".invalid", "@example.", "@test."} {
		if strings.Contains(lower, bad) {
			return false
		}
	}
	return true
}

func spanCovered(spans [][2]int, start, end int) bool {
	for _, s := range spans {
		if start >= s[0] && end <= s[1] {
			return true
		}
	}
	return false
}

func downgradePlaceholder(conf Confidence, note, value string) (Confidence, string) {
	if isPlaceholder(value) && conf == ConfHigh {
		return ConfMedium, appendNote(note, "Value looks like a placeholder or example.")
	}
	return conf, note
}

// findingKey controls dedup granularity. High-volume categories (endpoints,
// parameters, emails, paths) dedup on value alone — seeing the same string on
// forty lines is one triage item, not forty.
// sortFindings orders findings the way a triager reads them: most severe
// first, then highest confidence, then file order.
func sortFindings(findings []Finding) {
	sevOrder := map[Severity]int{
		SevCritical: 5,
		SevHigh:     4,
		SevMedium:   3,
		SevLow:      2,
		SevInfo:     1,
	}
	confOrder := map[Confidence]int{ConfHigh: 3, ConfMedium: 2, ConfLow: 1}
	sort.Slice(findings, func(i, j int) bool {
		if sevOrder[findings[i].Severity] != sevOrder[findings[j].Severity] {
			return sevOrder[findings[i].Severity] > sevOrder[findings[j].Severity]
		}
		if findings[i].Confidence != findings[j].Confidence {
			return confOrder[findings[i].Confidence] > confOrder[findings[j].Confidence]
		}
		if findings[i].Line != findings[j].Line {
			return findings[i].Line < findings[j].Line
		}
		return findings[i].Column < findings[j].Column
	})
}

func findingKey(f Finding) string {
	switch f.Category {
	case "endpoints", "parameters", "emails", "paths":
		return f.Category + ":" + f.Type + ":" + f.Value
	default:
		return f.Category + ":" + f.Type + ":" + f.Value + ":" + strconv.Itoa(f.Line)
	}
}

func addFinding(result *Result, dedup map[string]bool, finding Finding) {
	if result.Summary.Truncated == nil {
		result.Summary.Truncated = map[string]int{}
	}
	key := findingKey(finding)
	if dedup[key] {
		return
	}
	dedup[key] = true
	if len(result.Findings) >= maxTotalFindings {
		result.Summary.Truncated["total"]++
		return
	}
	if result.Summary.ByCategory[finding.Category] >= maxFindingsPerCategory {
		result.Summary.Truncated[finding.Category]++
		return
	}
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
		SevInfo:     0.15,
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

func detectMinified(content string, lines []string) bool {
	if len(lines) == 0 {
		return false
	}
	if len(content)/len(lines) > 2000 {
		return true
	}
	for _, l := range lines {
		if len(l) > 100000 {
			return true
		}
	}
	return false
}

func isCommentLine(line string) bool {
	return strings.HasPrefix(line, "//") || strings.HasPrefix(line, "/*") ||
		strings.HasPrefix(line, "*") || strings.HasPrefix(line, "#")
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
		content := lines[i-1]
		if len(content) > 400 {
			content = content[:400] + "..."
		}
		b.WriteString(fmt.Sprintf("%4d | %s", i, content))
		if i < end {
			b.WriteByte('\n')
		}
	}
	return b.String()
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
