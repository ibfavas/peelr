package analyzer

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"unicode"
)

// This file holds the precision machinery: string-literal extraction and the
// validators that keep generic patterns from becoming false positives.
//
// Design rule: anything that must look like a *value* (endpoints, secrets,
// paths, emails) is only ever matched inside string literals. Anything that
// must look like *code* (DOM sinks, function parameters) is matched against
// the line with literal contents blanked out. That single split eliminates
// the biggest historical FP sources: division operators parsed as endpoints,
// ternaries parsed as query params, and prose parsed as secrets.

// strLiteral is one quoted string found on a line.
type strLiteral struct {
	value string // inner text, without the quotes
	start int    // byte offset of the opening quote in the line
	end   int    // byte offset just past the closing quote
}

// extractLiterals finds '...', "..." and `...` strings on a line and returns
// a copy of the line with every literal's contents replaced by spaces.
// Column offsets are preserved, so findings keep accurate positions.
func extractLiterals(line string) (stripped string, lits []strLiteral) {
	var b strings.Builder
	b.Grow(len(line))
	n := len(line)
	i := 0
	for i < n {
		c := line[i]
		if c == '\'' || c == '"' || c == '`' {
			j := i + 1
			closed := false
			for j < n {
				if line[j] == '\\' {
					j += 2
					continue
				}
				if line[j] == c {
					closed = true
					break
				}
				j++
			}
			if !closed {
				// Unterminated quote (e.g. apostrophe in a comment tail,
				// or a template literal spanning lines): leave it alone.
				b.WriteByte(c)
				i++
				continue
			}
			lits = append(lits, strLiteral{value: line[i+1 : j], start: i, end: j + 1})
			b.WriteByte(c)
			for k := i + 1; k < j; k++ {
				b.WriteByte(' ')
			}
			b.WriteByte(c)
			i = j + 1
			continue
		}
		b.WriteByte(c)
		i++
	}
	return b.String(), lits
}

// tokenizeIdent splits an identifier into lowercase word tokens on
// camelCase boundaries and separator characters: "apiKey" -> [api key],
// "API_SECRET" -> [api secret], "keyboard" -> [keyboard].
func tokenizeIdent(s string) []string {
	var toks []string
	var cur strings.Builder
	flush := func() {
		if cur.Len() > 0 {
			toks = append(toks, cur.String())
			cur.Reset()
		}
	}
	runes := []rune(s)
	for i, r := range runes {
		switch {
		case r == '_' || r == '-' || r == '.' || r == '/' || r == ' ':
			flush()
		case unicode.IsUpper(r) && i > 0 && unicode.IsLower(runes[i-1]):
			flush()
			cur.WriteRune(unicode.ToLower(r))
		case unicode.IsLetter(r):
			cur.WriteRune(unicode.ToLower(r))
		default:
			flush() // digits and symbols act as separators
		}
	}
	flush()
	return toks
}

var sensitiveTokens = map[string]bool{
	"token": true, "tokens": true,
	"secret": true, "secrets": true,
	"key": true, "keys": true,
	"apikey": true, "apisecret": true, "accesskey": true, "secretkey": true, "clientsecret": true,
	"password": true, "passwd": true, "pwd": true, "passcode": true,
	"auth": true, "authorization": true, "authentication": true, "authenticate": true,
	"session": true, "sessionid": true, "sessionkey": true,
	"email": true,
	"user":  true, "username": true,
	"credential": true, "credentials": true,
	"privatekey": true,
	"login":      true,
}

// isSensitiveName reports whether an identifier contains a whole sensitive
// word token. "apiKey" matches; "keyboard" and "monkey" do not.
func isSensitiveName(name string) bool {
	for _, tok := range tokenizeIdent(name) {
		if sensitiveTokens[tok] {
			return true
		}
	}
	return false
}

var placeholderHints = []string{
	"example", "sample", "test", "placeholder", "your_", "your-", "<your",
	"replace", "changeme", "dummy", "demo", "fake", "localhost", "000000",
	"xxx", "***", "redacted", "todo", "insert",
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

// dummyValues are strings that look like secrets to a regex but are never
// real credentials.
var dummyValues = map[string]bool{
	"password": true, "123456": true, "12345678": true, "qwerty": true,
	"letmein": true, "changeme": true, "admin": true, "test": true,
	"demo": true, "null": true, "undefined": true, "none": true,
	"xxx": true, "***": true, "redacted": true,
}

func isDummyValue(value string) bool {
	return dummyValues[strings.ToLower(strings.TrimSpace(value))]
}

func isPathChar(c rune) bool {
	return unicode.IsLetter(c) || unicode.IsDigit(c) ||
		strings.ContainsRune("._-~/:?&=#%@+", c)
}

// looksLikeEndpoint decides whether a string-literal value is plausibly a
// URL or route. It must not contain whitespace or quote characters, which
// rules out prose, sentences, and most minified-code accidents.
func looksLikeEndpoint(v string) bool {
	if v == "" || v == "/" || v == "//" {
		return false
	}
	if strings.ContainsAny(v, " \t\n\r\"'<>") {
		return false
	}
	if strings.HasPrefix(v, "https://") || strings.HasPrefix(v, "http://") {
		return len(v) >= 12
	}
	if strings.HasPrefix(v, "wss://") || strings.HasPrefix(v, "ws://") {
		return len(v) >= 8
	}
	if strings.HasPrefix(v, "//") {
		return false // protocol-relative URLs are too noisy to call
	}
	if strings.HasPrefix(v, "/") {
		if len(v) < 4 {
			return false
		}
		// System paths are reported as paths, not endpoints.
		for _, prefix := range []string{
			"/etc/", "/var/", "/usr/", "/bin/", "/sbin/", "/tmp/",
			"/home/", "/root/", "/proc/", "/sys/", "/opt/", "/dev/",
			"/run/", "/mnt/", "/srv/",
		} {
			if strings.HasPrefix(v, prefix) {
				return false
			}
		}
		for _, c := range v {
			if !isPathChar(c) {
				return false
			}
		}
		return true
	}
	// Bare relative route such as "api/v1/users".
	if len(v) >= 4 && strings.Contains(v, "/") {
		for _, c := range v {
			if !isPathChar(c) {
				return false
			}
		}
		return true
	}
	return false
}

// validateJWT checks the classic eyJ... three-part shape and, when possible,
// decodes the header to confirm it is really a JWT.
func validateJWT(value string) (keep bool, conf Confidence, note string) {
	parts := strings.Split(value, ".")
	if len(parts) != 3 {
		return false, "", ""
	}
	for _, p := range parts {
		if len(p) < 8 {
			return false, "", ""
		}
	}
	if decoded, err := base64.RawURLEncoding.DecodeString(parts[0]); err == nil {
		var header map[string]any
		if json.Unmarshal(decoded, &header) == nil {
			if _, ok := header["alg"]; ok {
				return true, ConfHigh, "Valid JWT header. Decode the payload to inspect claims and expiry."
			}
		}
	}
	return true, ConfLow, "JWT-like shape, but the header did not decode as JSON. Verify manually."
}

// validateBasicAuth drops prose like "basic authentication" and notes when the
// token actually decodes to a username:password pair.
func validateBasicAuth(value string) (bool, Confidence, string) {
	if isPlaceholder(value) || isDummyValue(value) {
		return false, "", ""
	}
	if !strings.ContainsAny(value, "0123456789+/=") && len(value) < 24 {
		return false, "", ""
	}
	note := ""
	decoded, err := base64.StdEncoding.DecodeString(value)
	if err != nil {
		decoded, err = base64.RawStdEncoding.DecodeString(value)
	}
	if err == nil {
		if parts := strings.SplitN(string(decoded), ":", 2); len(parts) == 2 && parts[0] != "" && parts[1] != "" {
			note = "Decodes to a username:password pair."
		}
	}
	return true, "", note
}

// validateBearer drops template placeholders and documentation examples.
func validateBearer(value string) (bool, Confidence, string) {
	if len(value) < 16 {
		return false, "", ""
	}
	if strings.ContainsAny(value, "${}<>") {
		return false, "", ""
	}
	if isPlaceholder(value) || isDummyValue(value) {
		return false, "", ""
	}
	return true, ConfMedium, ""
}

// validateOpenAIKey excludes Stripe-style keys that share the sk- prefix.
func validateOpenAIKey(value string) (bool, Confidence, string) {
	if strings.HasPrefix(value, "sk_live_") || strings.HasPrefix(value, "sk_test_") {
		return false, "", ""
	}
	if isPlaceholder(value) {
		return false, "", ""
	}
	return true, ConfHigh, ""
}

// validateSecretValue drops placeholders and dummy values for generic
// credential patterns.
func validateSecretValue(value string) (bool, Confidence, string) {
	if isDummyValue(value) {
		return false, "", ""
	}
	if isPlaceholder(value) {
		return true, ConfLow, "Value looks like a placeholder or example."
	}
	return true, "", ""
}
