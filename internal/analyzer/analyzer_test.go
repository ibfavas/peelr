package analyzer

import (
	"strconv"
	"strings"
	"testing"
)

func analyzeOne(t *testing.T, content string) Result {
	t.Helper()
	return Analyze(SourceInput{
		ID:      "test",
		Name:    "test.js",
		Kind:    SourceFile,
		Origin:  "test.js",
		Content: content,
	})
}

func findingTypes(r Result) map[string]int {
	out := map[string]int{}
	for _, f := range r.Findings {
		out[f.Type]++
	}
	return out
}

func TestDivisionNotEndpoint(t *testing.T) {
	r := analyzeOne(t, "const x = a / b;\nconst y = total/count;\n")
	if n := findingTypes(r)["endpoint_literal"]; n != 0 {
		t.Fatalf("division parsed as endpoint: %d findings", n)
	}
}

func TestStringLiteralEndpoint(t *testing.T) {
	r := analyzeOne(t, "fetch(\"/api/v1/users\");\n")
	types := findingTypes(r)
	if types["fetch"] != 1 {
		t.Fatalf("expected 1 fetch finding, got %d", types["fetch"])
	}
	if types["endpoint_literal"] != 0 {
		t.Fatalf("fetch URL double-reported as endpoint_literal")
	}
}

func TestBarePathLiteralEndpoint(t *testing.T) {
	r := analyzeOne(t, "const p = \"/api/v1/users\";\n")
	if findingTypes(r)["endpoint_literal"] != 1 {
		t.Fatalf("expected bare path literal to be reported")
	}
}

func TestTernaryNotQueryParam(t *testing.T) {
	r := analyzeOne(t, "const x = cond ? a : b;\n")
	if n := findingTypes(r)["query_parameter"]; n != 0 {
		t.Fatalf("ternary parsed as query param: %d", n)
	}
}

func TestSensitiveQueryParam(t *testing.T) {
	r := analyzeOne(t, "const u = \"/api/login?user=x&token=abc\";\n")
	var found *Finding
	for i, f := range r.Findings {
		if f.Type == "query_parameter" && f.Value == "token" {
			found = &r.Findings[i]
		}
	}
	if found == nil {
		t.Fatal("sensitive query param 'token' not found")
	}
	if found.Severity != SevMedium || found.Title != "Sensitive Query Parameter" {
		t.Fatalf("wrong severity/title: %s %s", found.Severity, found.Title)
	}
}

func TestKeyboardNotSensitive(t *testing.T) {
	if isSensitiveName("keyboard") {
		t.Fatal("keyboard flagged as sensitive")
	}
	if isSensitiveName("monkey") {
		t.Fatal("monkey flagged as sensitive")
	}
	if !isSensitiveName("apiKey") {
		t.Fatal("apiKey not flagged as sensitive")
	}
	if !isSensitiveName("session_id") {
		t.Fatal("session_id not flagged as sensitive")
	}
}

func TestOnlySensitiveFunctionParams(t *testing.T) {
	r := analyzeOne(t, "function login(username, password, callback) {}\n")
	types := findingTypes(r)
	if types["function_parameter"] != 2 {
		t.Fatalf("expected only the sensitive params, got %d findings", types["function_parameter"])
	}
}

func TestValidJWT(t *testing.T) {
	// header {"alg":"HS256","typ":"JWT"}, payload {"sub":"1234"}
	jwt := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0In0.signature"
	r := analyzeOne(t, "const t = \""+jwt+"\";\n")
	var found *Finding
	for i, f := range r.Findings {
		if f.Type == "jwt" {
			found = &r.Findings[i]
		}
	}
	if found == nil {
		t.Fatal("valid JWT not detected")
	}
	if found.Confidence != ConfHigh {
		t.Fatalf("expected high confidence, got %s", found.Confidence)
	}
}

func TestJWTLikeGarbageSkipped(t *testing.T) {
	r := analyzeOne(t, "const t = \"eyJ коротко.не-jwt.совсем\";\n")
	if n := findingTypes(r)["jwt"]; n != 0 {
		t.Fatalf("non-JWT shape reported: %d", n)
	}
}

func TestBearerTemplateSkipped(t *testing.T) {
	r := analyzeOne(t, "const h = `Bearer ${token}`;\n")
	if n := findingTypes(r)["bearer"]; n != 0 {
		t.Fatalf("template bearer reported: %d", n)
	}
}

func TestBearerReal(t *testing.T) {
	r := analyzeOne(t, "const h = \"Bearer abcdefghijklmnopqrst\";\n")
	if n := findingTypes(r)["bearer"]; n != 1 {
		t.Fatalf("expected 1 bearer finding, got %d", n)
	}
}

func TestDummyPasswordSkipped(t *testing.T) {
	r := analyzeOne(t, "const cfg = \"password=12345678\";\n")
	if n := findingTypes(r)["embedded_credential"]; n != 0 {
		t.Fatalf("dummy password reported: %d", n)
	}
}

func TestRealPasswordKept(t *testing.T) {
	r := analyzeOne(t, "const cfg = \"password=s3cr3t!value9\";\n")
	if n := findingTypes(r)["embedded_credential"]; n != 1 {
		t.Fatalf("expected 1 embedded credential, got %d", n)
	}
}

func TestAssignedSecret(t *testing.T) {
	r := analyzeOne(t, "const password = \"s3cr3t!x9\";\n")
	var found *Finding
	for i, f := range r.Findings {
		if f.Type == "password" {
			found = &r.Findings[i]
		}
	}
	if found == nil {
		t.Fatal("assigned password not detected")
	}
	if found.Value != "s3cr3t!x9" {
		t.Fatalf("wrong value: %q", found.Value)
	}
}

func TestAssignedSecretSkipsLabel(t *testing.T) {
	r := analyzeOne(t, "const x = {label: \"Password\"};\n")
	if n := findingTypes(r)["password"]; n != 0 {
		t.Fatalf("i18n label reported as password: %d", n)
	}
}

func TestPlaceholderKeyDowngraded(t *testing.T) {
	r := analyzeOne(t, "const k = \"AKIAIOSFODNN7EXAMPLE\";\n")
	var found *Finding
	for i, f := range r.Findings {
		if f.Type == "aws_access_key" {
			found = &r.Findings[i]
		}
	}
	if found == nil {
		t.Fatal("AWS key not detected")
	}
	if found.Confidence != ConfMedium {
		t.Fatalf("expected placeholder downgrade to medium, got %s", found.Confidence)
	}
}

func TestExampleEmailSkipped(t *testing.T) {
	r := analyzeOne(t, "const e = \"security@example.com\";\n")
	if n := findingTypes(r)["email"]; n != 0 {
		t.Fatalf("example email reported: %d", n)
	}
}

func TestRealEmailKept(t *testing.T) {
	r := analyzeOne(t, "const e = \"ops@target-company.io\";\n")
	if n := findingTypes(r)["email"]; n != 1 {
		t.Fatalf("expected 1 email, got %d", n)
	}
}

func TestSinkInStringNotMatched(t *testing.T) {
	r := analyzeOne(t, "const s = \"use .innerHTML = wisely\";\n")
	if n := findingTypes(r)["innerhtml"]; n != 0 {
		t.Fatalf("sink inside string literal matched: %d", n)
	}
}

func TestSinkInCodeMatched(t *testing.T) {
	r := analyzeOne(t, "el.innerHTML = name;\n")
	if n := findingTypes(r)["innerhtml"]; n != 1 {
		t.Fatalf("expected 1 innerHTML sink, got %d", n)
	}
}

func TestUserInputBoost(t *testing.T) {
	r := analyzeOne(t, "el.innerHTML = location.hash;\n")
	var found *Finding
	for i, f := range r.Findings {
		if f.Type == "innerhtml" {
			found = &r.Findings[i]
		}
	}
	if found == nil {
		t.Fatal("sink not found")
	}
	if found.Confidence != ConfHigh {
		t.Fatalf("expected high confidence with user input, got %s", found.Confidence)
	}
}

func TestEndpointDedupByValue(t *testing.T) {
	r := analyzeOne(t, "fetch(\"/api/a\");\nfetch(\"/api/a\");\nfetch(\"/api/a\");\n")
	if n := findingTypes(r)["fetch"]; n != 1 {
		t.Fatalf("expected value-level dedup to yield 1, got %d", n)
	}
}

func TestUnixPathInLiteral(t *testing.T) {
	r := analyzeOne(t, "const p = \"/etc/passwd\";\n")
	if n := findingTypes(r)["unix_path"]; n != 1 {
		t.Fatalf("expected 1 unix path, got %d", n)
	}
}

func TestSensitiveFilename(t *testing.T) {
	r := analyzeOne(t, "const p = \"/app/.env\";\n")
	if n := findingTypes(r)["sensitive_file"]; n != 1 {
		t.Fatalf("expected 1 sensitive file finding, got %d", n)
	}
}

func TestWebSocketEndpoint(t *testing.T) {
	r := analyzeOne(t, "const ws = new WebSocket(\"wss://target.com/socket\");\n")
	var found *Finding
	for i, f := range r.Findings {
		if f.Type == "endpoint_literal" {
			found = &r.Findings[i]
		}
	}
	if found == nil {
		t.Fatal("websocket endpoint not found")
	}
	if found.Title != "WebSocket Endpoint" {
		t.Fatalf("wrong title: %s", found.Title)
	}
}

func TestMinifiedChunking(t *testing.T) {
	// A single 40KB line with a secret buried in the middle.
	pad := strings.Repeat("var a"+strings.Repeat("x", 100)+"=1;", 300)
	secret := "\"AKIAIOSFODNN7EXAMPLE\""
	content := pad + "var k=" + secret + ";" + pad
	r := analyzeOne(t, content)
	if !r.Minified {
		t.Fatal("long line not flagged as minified")
	}
	found := false
	for _, f := range r.Findings {
		if f.Type == "aws_access_key" {
			found = true
		}
	}
	if !found {
		t.Fatal("secret in minified line not found (chunking broke it)")
	}
}

func TestCategoryCap(t *testing.T) {
	var b strings.Builder
	for i := 0; i < 600; i++ {
		b.WriteString("fetch(\"/api/endpoint" + strings.Repeat("x", 10) + string(rune('a'+i%26)) + string(rune('a'+(i/26)%26)) + "\");\n")
	}
	r := analyzeOne(t, b.String())
	if r.Summary.ByCategory["endpoints"] > maxFindingsPerCategory {
		t.Fatalf("category cap exceeded: %d", r.Summary.ByCategory["endpoints"])
	}
	if r.Summary.Truncated["endpoints"] == 0 {
		t.Fatal("expected truncated counter to be set")
	}
}

func TestOpenAIKeyNotStripe(t *testing.T) {
	r := analyzeOne(t, "const k = \"sk_live_abcdefghijklmnop\";\n")
	if n := findingTypes(r)["openai_key"]; n != 0 {
		t.Fatal("stripe key misclassified as OpenAI key")
	}
	if n := findingTypes(r)["stripe_secret"]; n != 1 {
		t.Fatalf("expected stripe_secret, got %d", n)
	}
}

func TestPostMessageHandler(t *testing.T) {
	r := analyzeOne(t, "window.addEventListener(\"message\", handler);\n")
	if n := findingTypes(r)["postmessage_handler"]; n != 1 {
		t.Fatalf("expected 1 postmessage handler, got %d", n)
	}
}

func TestLooksLikeEndpoint(t *testing.T) {
	cases := map[string]bool{
		"https://api.target.com/v1": true,
		"/api/v1/users":             true,
		"wss://target.com/ws":       true,
		"api/v1/users":              true,
		"/a":                        false,
		"just some words here":      false,
		"a / b":                     false,
		"//comment":                 false,
		"":                          false,
	}
	for input, want := range cases {
		if got := looksLikeEndpoint(input); got != want {
			t.Errorf("looksLikeEndpoint(%q) = %v, want %v", input, got, want)
		}
	}
}

func TestAssignedSecretTemplateInterpolationSkipped(t *testing.T) {
	src := "const auth = `Bearer ${jwtToken}`;"
	res := Analyze(SourceInput{ID: "t", Name: "t.js", Kind: SourceJS, Origin: "inline", Content: src})
	for _, f := range res.Findings {
		if f.Category == "credentials" && strings.Contains(f.Value, "jwtToken") {
			t.Fatalf("template-interpolated value reported as hardcoded secret: %q", f.Value)
		}
	}
}

func TestAssignedSecretEmailValueSkipped(t *testing.T) {
	src := `const email = "security@example.com";`
	res := Analyze(SourceInput{ID: "t", Name: "t.js", Kind: SourceJS, Origin: "inline", Content: src})
	for _, f := range res.Findings {
		if f.Category == "credentials" && strings.Contains(f.Value, "@") {
			t.Fatalf("email-shaped value reported as hardcoded secret: %q", f.Value)
		}
	}
}

func TestLongLineLiteralAccountingExact(t *testing.T) {
	var sb strings.Builder
	for i := 0; i < 60000; i++ {
		if i > 0 {
			sb.WriteString(",")
		}
		sb.WriteString(`"/static/chunk` + itoa(i) + `.js"`)
	}
	res := Analyze(SourceInput{ID: "t", Name: "big.js", Kind: SourceJS, Origin: "inline", Content: sb.String()})
	kept := 0
	for _, f := range res.Findings {
		if f.Category == "endpoints" {
			kept++
		}
	}
	truncated := res.Summary.Truncated["endpoints"]
	if kept != 400 || kept+truncated != 60000 {
		t.Fatalf("expected 400 kept + 59600 truncated endpoints, got %d kept + %d truncated", kept, truncated)
	}
}

func itoa(i int) string { return strconv.Itoa(i) }
