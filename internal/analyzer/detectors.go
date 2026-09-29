package analyzer

import "regexp"

// Detection tables. Every detector declares a scope:
//
//	scopeCode    - matched against the line with string-literal contents blanked
//	             (for code patterns: DOM sinks, function parameters)
//	scopeLiteral - matched against each string literal's value
//	             (for values: secrets, endpoints, paths, emails)
//	scopeBoth    - matched against both
//
// A detector may also carry a validate func for checks a regex cannot do
// (JWT header decoding, template-placeholder rejection). group selects which
// regex capture group is reported as the finding value (0 = whole match).

type scope int

const (
	scopeCode scope = iota
	scopeLiteral
	scopeBoth
)

type detector struct {
	category   string
	name       string
	title      string
	severity   Severity
	confidence Confidence
	note       string
	scope      scope
	group      int
	// raw matches against the original segment instead of the
	// literal-blanked line (for code patterns that inspect string args).
	raw      bool
	re       *regexp.Regexp
	validate func(value string) (keep bool, conf Confidence, note string)
}

var secretDetectors = []detector{
	{category: "api_keys", name: "aws_access_key", title: "AWS Access Key", severity: SevCritical, confidence: ConfHigh, scope: scopeLiteral, re: regexp.MustCompile(`\bA[KS]IA[0-9A-Z]{16}\b`)},
	{category: "api_keys", name: "aws_secret_key", title: "AWS Secret Key", severity: SevCritical, confidence: ConfMedium, scope: scopeLiteral, note: "Verify the 40-character value before treating as valid.", re: regexp.MustCompile(`(?i)aws.{0,20}secret.{0,20}['"][0-9a-zA-Z/+]{40}['"]`)},
	{category: "api_keys", name: "google_api_key", title: "Google API Key", severity: SevHigh, confidence: ConfHigh, scope: scopeLiteral, re: regexp.MustCompile(`AIza[0-9A-Za-z\-_]{35}`)},
	{category: "api_keys", name: "github_token", title: "GitHub Token", severity: SevCritical, confidence: ConfHigh, scope: scopeLiteral, re: regexp.MustCompile(`\b(?:ghp|gho|ghu|ghs|ghr)_[0-9a-zA-Z]{36}\b|github_pat_[0-9a-zA-Z_]{82}`)},
	{category: "api_keys", name: "gitlab_token", title: "GitLab Token", severity: SevHigh, confidence: ConfHigh, scope: scopeLiteral, re: regexp.MustCompile(`\bglpat-[0-9a-zA-Z\-_]{20,}\b`)},
	{category: "api_keys", name: "openai_key", title: "OpenAI API Key", severity: SevHigh, confidence: ConfHigh, scope: scopeLiteral, re: regexp.MustCompile(`\bsk-[A-Za-z0-9\-_]{20,}\b`), validate: validateOpenAIKey},
	{category: "api_keys", name: "stripe_secret", title: "Stripe Secret Key", severity: SevCritical, confidence: ConfHigh, scope: scopeLiteral, re: regexp.MustCompile(`\bsk_live_[0-9a-zA-Z]{16,}\b`)},
	{category: "api_keys", name: "stripe_public", title: "Stripe Publishable Key", severity: SevMedium, confidence: ConfHigh, scope: scopeLiteral, re: regexp.MustCompile(`\bpk_live_[0-9a-zA-Z]{16,}\b`)},
	{category: "api_keys", name: "slack_token", title: "Slack Token", severity: SevHigh, confidence: ConfHigh, scope: scopeLiteral, re: regexp.MustCompile(`\bxox[baprs]-[0-9a-zA-Z\-]{10,}\b`)},
	{category: "api_keys", name: "slack_webhook", title: "Slack Webhook", severity: SevHigh, confidence: ConfHigh, scope: scopeLiteral, re: regexp.MustCompile(`https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[a-zA-Z0-9]+`)},
	{category: "api_keys", name: "firebase", title: "Firebase Reference", severity: SevMedium, confidence: ConfMedium, scope: scopeLiteral, re: regexp.MustCompile(`[a-z0-9-]+\.firebaseio\.com`)},
	{category: "api_keys", name: "jwt", title: "JWT Token", severity: SevHigh, confidence: ConfHigh, scope: scopeLiteral, re: regexp.MustCompile(`eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}`), validate: validateJWT},
	{category: "api_keys", name: "sendgrid", title: "SendGrid API Key", severity: SevHigh, confidence: ConfHigh, scope: scopeLiteral, re: regexp.MustCompile(`\bSG\.[a-zA-Z0-9_-]{22,}\.[a-zA-Z0-9_-]{43,}\b`)},
	{category: "api_keys", name: "generic_key", title: "Generic API Key", severity: SevMedium, confidence: ConfLow, scope: scopeLiteral, group: 2, note: "Generic key pattern. Validate manually.", re: regexp.MustCompile(`(?i)(?:api[_-]?key|apikey|client[_-]?secret|access[_-]?token)\s*[:=]\s*['"]?([^'"\s;,]{12,})['"]?`), validate: validateSecretValue},

	{category: "credentials", name: "embedded_credential", title: "Embedded Credential Pair", severity: SevHigh, confidence: ConfLow, scope: scopeLiteral, group: 2, note: "Credential-style key=value pair embedded in a string. Validate manually.", re: regexp.MustCompile(`(?i)\b(password|passwd|pwd|api[_-]?key|client[_-]?secret|access[_-]?token)\s*[:=]\s*['"]?([^'"\s;,]{8,})['"]?`), validate: validateSecretValue},
	{category: "credentials", name: "basic_auth", title: "Basic Auth Header", severity: SevHigh, confidence: ConfHigh, scope: scopeLiteral, group: 1, re: regexp.MustCompile(`(?i)\bbasic\s+([A-Za-z0-9+/=]{12,})`), validate: validateBasicAuth},
	{category: "credentials", name: "bearer", title: "Bearer Token", severity: SevMedium, confidence: ConfMedium, scope: scopeLiteral, group: 1, re: regexp.MustCompile(`(?i)\bbearer\s+([A-Za-z0-9\-._~+/=]{8,})`), validate: validateBearer},
	{category: "credentials", name: "db_conn", title: "Database Connection String", severity: SevCritical, confidence: ConfHigh, scope: scopeLiteral, re: regexp.MustCompile(`(?i)(?:mongodb|mysql|postgres|postgresql|redis|amqp|mssql):\/\/[^'">\s]{10,}`)},
	{category: "credentials", name: "private_key", title: "Private Key Block", severity: SevCritical, confidence: ConfHigh, scope: scopeLiteral, re: regexp.MustCompile(`-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----`)},

	{category: "emails", name: "email", title: "Email Address", severity: SevInfo, confidence: ConfMedium, scope: scopeLiteral, re: emailAddrRe},
}

// emailAddrRe matches an email address shape. emailOK applies the
// example-domain and placeholder filtering on top of it.
var emailAddrRe = regexp.MustCompile(`\b[a-zA-Z0-9._%+\-]{1,64}@[a-zA-Z0-9.\-]{1,253}\.[a-zA-Z]{2,24}\b`)

// looksLikeEmail reports whether the value contains an email address shape,
// regardless of the example-domain filtering in emailOK.
func looksLikeEmail(value string) bool {
	return emailAddrRe.MatchString(value)
}

var sinkDetectors = []detector{
	{category: "xss", name: "innerhtml", title: "innerHTML Assignment", severity: SevHigh, confidence: ConfMedium, scope: scopeCode, note: "Check whether user-controlled input reaches the sink.", re: regexp.MustCompile(`\.innerHTML\s*[+]?=`)},
	{category: "xss", name: "outerhtml", title: "outerHTML Assignment", severity: SevHigh, confidence: ConfMedium, scope: scopeCode, note: "Check whether user-controlled input reaches the sink.", re: regexp.MustCompile(`\.outerHTML\s*[+]?=`)},
	{category: "xss", name: "document_write", title: "document.write Usage", severity: SevHigh, confidence: ConfMedium, scope: scopeCode, note: "Check whether user-controlled input reaches the sink.", re: regexp.MustCompile(`document\.write(?:ln)?\s*\(`)},
	{category: "xss", name: "eval", title: "eval() Usage", severity: SevHigh, confidence: ConfMedium, scope: scopeCode, note: "Check whether user-controlled input reaches the sink.", re: regexp.MustCompile(`\beval\s*\(`)},
	{category: "xss", name: "function_ctor", title: "Function Constructor", severity: SevHigh, confidence: ConfMedium, scope: scopeCode, note: "Check whether user-controlled input reaches the sink.", re: regexp.MustCompile(`new\s+Function\s*\(`)},
	{category: "xss", name: "dangerously_set_inner_html", title: "React dangerouslySetInnerHTML", severity: SevHigh, confidence: ConfMedium, scope: scopeCode, note: "Check whether user-controlled input reaches the sink.", re: regexp.MustCompile(`dangerouslySetInnerHTML\s*=\s*\{`)},
	{category: "xss", name: "jquery_html", title: "jQuery html() Injection Point", severity: SevHigh, confidence: ConfMedium, scope: scopeCode, note: "Check whether user-controlled input reaches the sink.", re: regexp.MustCompile(`\$\([^)]+\)\.(?:html|append|prepend|before|after)\s*\(`)},
	{category: "xss", name: "insert_adjacent_html", title: "insertAdjacentHTML Usage", severity: SevHigh, confidence: ConfMedium, scope: scopeCode, note: "Check whether user-controlled input reaches the sink.", re: regexp.MustCompile(`\.insertAdjacentHTML\s*\(`)},
	{category: "xss", name: "srcdoc", title: "srcdoc Assignment", severity: SevHigh, confidence: ConfMedium, scope: scopeCode, note: "Check whether user-controlled input reaches the sink.", re: regexp.MustCompile(`\.srcdoc\s*=`)},
	{category: "xss", name: "postmessage_handler", title: "postMessage Handler", severity: SevMedium, confidence: ConfMedium, scope: scopeCode, raw: true, note: "Check that the handler validates event.origin before trusting the message.", re: regexp.MustCompile(`addEventListener\s*\(\s*['"]message['"]`)},
	{category: "xss", name: "document_domain", title: "document.domain Assignment", severity: SevMedium, confidence: ConfMedium, scope: scopeCode, note: "Relaxing document.domain weakens the same-origin policy.", re: regexp.MustCompile(`document\.domain\s*=[^=]`)},
	{category: "xss", name: "location_sink", title: "Location Sink (Open Redirect)", severity: SevMedium, confidence: ConfMedium, scope: scopeCode, note: "Check whether user-controlled input reaches the redirect target.", re: regexp.MustCompile(`location\.(?:href\s*=|replace\s*\(|assign\s*\()`)},
}

var pathDetectors = []detector{
	{category: "paths", name: "unix_path", title: "Unix Path", severity: SevInfo, confidence: ConfMedium, scope: scopeLiteral, re: regexp.MustCompile(`^/(?:[^/\s]+/)+[^/\s]*$`)},
	{category: "paths", name: "windows_path", title: "Windows Path", severity: SevInfo, confidence: ConfMedium, scope: scopeLiteral, re: regexp.MustCompile(`[A-Za-z]:\\(?:[^<>:"/\\|?*\r\n]+\\)*[^<>:"/\\|?*\r\n]*`)},
	{category: "paths", name: "s3", title: "S3 Reference", severity: SevMedium, confidence: ConfHigh, scope: scopeLiteral, re: regexp.MustCompile(`s3://[a-zA-Z0-9.\-_/]+|[a-zA-Z0-9\-]+\.s3(?:\.[a-z0-9\-]+)?\.amazonaws\.com`)},
	{category: "paths", name: "sensitive_file", title: "Sensitive Filename", severity: SevMedium, confidence: ConfHigh, scope: scopeLiteral, note: "Reference to a file that often holds secrets.", re: regexp.MustCompile(`(?i)(?:^|/)(?:\.env(?:\.[\w.]+)?|id_rsa|id_dsa|\.pem|\.p12|\.pfx|\.keystore|secrets?\.json|config\.json|wp-config\.php|\.git/config)$`)},
}

var commentDetectors = []detector{
	{category: "comments", name: "todo", title: "TODO Comment", severity: SevInfo, confidence: ConfLow, re: regexp.MustCompile(`(?i)\bTODO\b`)},
	{category: "comments", name: "fixme", title: "FIXME Comment", severity: SevInfo, confidence: ConfLow, re: regexp.MustCompile(`(?i)\bFIXME\b`)},
	{category: "comments", name: "hack", title: "HACK Comment", severity: SevLow, confidence: ConfLow, re: regexp.MustCompile(`(?i)\bHACK\b`)},
	{category: "comments", name: "security", title: "Security Comment", severity: SevMedium, confidence: ConfLow, note: "Comment references a sensitive topic. Review surrounding code.", re: regexp.MustCompile(`(?i)\b(security|vuln|bypass|insecure|workaround|token|secret|password|credential)\b`)},
}

// requestDetectors match network-call wrappers in code; group 1 is the URL.
var requestDetectors = []detector{
	{category: "endpoints", name: "fetch", title: "fetch() Request", severity: SevInfo, confidence: ConfHigh, scope: scopeCode, group: 1, re: regexp.MustCompile(`fetch\s*\(\s*['"]([^'"]+)['"]`)},
	{category: "endpoints", name: "axios", title: "axios Request", severity: SevInfo, confidence: ConfHigh, scope: scopeCode, group: 1, re: regexp.MustCompile(`axios(?:\.[a-z]+)?\s*\(\s*['"]([^'"]+)['"]`)},
	{category: "endpoints", name: "xhr", title: "XMLHttpRequest open()", severity: SevInfo, confidence: ConfHigh, scope: scopeCode, group: 1, re: regexp.MustCompile(`\.open\s*\(\s*['"][A-Z]+['"]\s*,\s*['"]([^'"]+)['"]`)},
	{category: "endpoints", name: "jquery_ajax", title: "jQuery AJAX Call", severity: SevInfo, confidence: ConfHigh, scope: scopeCode, group: 1, re: regexp.MustCompile(`\$\.(?:ajax|get|post)\s*\(\s*['"]([^'"]+)['"]`)},
}

var queryParamRe = regexp.MustCompile(`[?&]([a-zA-Z0-9_.\-]{1,64})=`)
var functionDeclRe = regexp.MustCompile(`function(?:\s+[A-Za-z0-9_$]+)?\s*\(([^)]{1,200})\)`)
var arrowDeclRe = regexp.MustCompile(`(?:const|let|var)?\s*[A-Za-z0-9_$]*\s*=\s*\(([^)]{1,200})\)\s*=>`)
var userInputRe = regexp.MustCompile(`location\.(?:hash|search|href)|document\.(?:URL|cookie|referrer)|window\.name|URLSearchParams|event\.data|req\.(?:body|query|params)`)
