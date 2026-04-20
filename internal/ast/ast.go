// Package ast does lightweight source-to-sink matching for JavaScript.
package ast

import (
	"regexp"
	"strings"
)

// FlowFinding represents a detected source→sink data flow.
type FlowFinding struct {
	Source     string `json:"source"`
	SourceLine int    `json:"source_line"`
	Sink       string `json:"sink"`
	SinkLine   int    `json:"sink_line"`
	Variable   string `json:"variable"`
	Context    string `json:"context"`
	Severity   string `json:"severity"`
	Note       string `json:"note"`
}

type sourcePattern struct {
	name string
	re   *regexp.Regexp
}

var sourcePatterns = []sourcePattern{
	{"location.hash", regexp.MustCompile(`location\.hash`)},
	{"location.search", regexp.MustCompile(`location\.search`)},
	{"location.href", regexp.MustCompile(`location\.href`)},
	{"location.pathname", regexp.MustCompile(`location\.pathname`)},
	{"document.URL", regexp.MustCompile(`document\.URL`)},
	{"document.referrer", regexp.MustCompile(`document\.referrer`)},
	{"document.cookie", regexp.MustCompile(`document\.cookie`)},
	{"URLSearchParams", regexp.MustCompile(`new\s+URLSearchParams\s*\(`)},
	{"postMessage data", regexp.MustCompile(`(?:event|e|msg)\.data`)},
	{"window.name", regexp.MustCompile(`window\.name`)},
	{"history.pushState", regexp.MustCompile(`history\.(?:push|replace)State`)},
	{"localStorage.getItem", regexp.MustCompile(`localStorage\.getItem\s*\(`)},
	{"req.body / params", regexp.MustCompile(`req\.(?:body|params|query|headers)`)},
	{"JSON.parse(input)", regexp.MustCompile(`JSON\.parse\s*\(\s*(?:req|body|params|query|input|data)`)},
}

type sinkPattern struct {
	name string
	re   *regexp.Regexp
	note string
}

var sinkPatterns = []sinkPattern{
	{"innerHTML", regexp.MustCompile(`(\w+)\s*(?:\.\w+)*\.innerHTML\s*[+]?=`),
		"Direct HTML injection. Tainted variable reaches innerHTML."},
	{"outerHTML", regexp.MustCompile(`(\w+)\s*(?:\.\w+)*\.outerHTML\s*[+]?=`),
		"Tainted variable reaches outerHTML."},
	{"document.write", regexp.MustCompile(`document\.write(?:ln)?\s*\(\s*(\w+)`),
		"Tainted variable passed to document.write."},
	{"eval", regexp.MustCompile(`\beval\s*\(\s*(\w+)`),
		"Tainted variable passed to eval — likely exploitable."},
	{"Function constructor", regexp.MustCompile(`new\s+Function\s*\([^)]*(\w+)`),
		"Tainted variable in Function constructor argument."},
	{"insertAdjacentHTML", regexp.MustCompile(`insertAdjacentHTML\s*\(\s*['"][^'"]+['"]\s*,\s*(\w+)`),
		"Tainted variable in insertAdjacentHTML second argument."},
	{"jQuery .html()", regexp.MustCompile(`\$\([^)]+\)\.html\s*\(\s*(\w+)`),
		"Tainted variable passed to jQuery .html() sink."},
	{"setTimeout string", regexp.MustCompile(`setTimeout\s*\(\s*(\w+)`),
		"Tainted variable as setTimeout first argument."},
	{"script.src", regexp.MustCompile(`(?:script|el)\.src\s*=\s*(\w+)`),
		"Tainted variable assigned to script.src — script injection."},
	{"window.location assign", regexp.MustCompile(`(?:window\.)?location(?:\.href)?\s*=\s*(\w+)`),
		"Tainted variable controls navigation — open redirect or XSS."},
	{"postMessage", regexp.MustCompile(`\.postMessage\s*\(\s*(\w+)`),
		"Tainted variable propagated via postMessage."},
}

// varAssign matches declarations and plain assignments.
var varAssign = regexp.MustCompile(
	`(?:(?:const|let|var)\s+)?(\w+)\s*=\s*(.+)`)

// Scan looks for simple source-to-sink flows in JavaScript text.
func Scan(content string) []FlowFinding {
	lines := strings.Split(content, "\n")

	type taintEntry struct {
		source string
		line   int
	}
	tainted := map[string]taintEntry{}

	for i, line := range lines {
		lineNo := i + 1
		trimmed := strings.TrimSpace(line)
		if isComment(trimmed) {
			continue
		}

		m := varAssign.FindStringSubmatch(trimmed)
		if len(m) < 3 {
			continue
		}
		varName := m[1]
		rhs := m[2]

		for _, sp := range sourcePatterns {
			if sp.re.MatchString(rhs) {
				tainted[varName] = taintEntry{sp.name, lineNo}
				break
			}
		}
	}

	if len(tainted) == 0 {
		return nil
	}

	var findings []FlowFinding
	seen := map[string]bool{}

	for i, line := range lines {
		lineNo := i + 1
		trimmed := strings.TrimSpace(line)
		if isComment(trimmed) {
			continue
		}

		for _, sk := range sinkPatterns {
			match := sk.re.FindStringSubmatch(trimmed)
			if match == nil {
				continue
			}

			candidates := []string{}
			if len(match) > 1 && match[1] != "" {
				candidates = append(candidates, match[1])
			}
			for v := range tainted {
				if strings.Contains(trimmed, v) {
					candidates = append(candidates, v)
				}
			}

			for _, cand := range candidates {
				entry, ok := tainted[cand]
				if !ok {
					continue
				}
				key := entry.source + "→" + sk.name + ":" + cand
				if seen[key] {
					continue
				}
				seen[key] = true

				ctx := trimmed
				if len(ctx) > 200 {
					ctx = ctx[:200] + "…"
				}

				findings = append(findings, FlowFinding{
					Source:     entry.source,
					SourceLine: entry.line,
					Sink:       sk.name,
					SinkLine:   lineNo,
					Variable:   cand,
					Context:    ctx,
					Severity:   "high",
					Note:       sk.note,
				})
			}
		}
	}

	return findings
}

func isComment(line string) bool {
	return strings.HasPrefix(line, "//") ||
		strings.HasPrefix(line, "/*") ||
		strings.HasPrefix(line, "*") ||
		strings.HasPrefix(line, "#")
}
