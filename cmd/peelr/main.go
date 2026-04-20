package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"sync"
	"text/tabwriter"

	"github.com/ibfavas/peelr/internal/analyzer"
	"github.com/ibfavas/peelr/internal/ast"
	"github.com/ibfavas/peelr/internal/history"
	"github.com/ibfavas/peelr/internal/server"
)

const version = "1.1.0"

const banner = `
 ____           _
|  _ \ ___  ___| |_ __
| |_) / _ \/ _ \ | '__|
|  __/  __/  __/ | |
|_|   \___|\___|_|_|
Peel back every secret. v` + version + `
`

// fullResult matches the combined scan payload used by the server.
type fullResult struct {
	analyzer.AnalysisResult
	Flows []ast.FlowFinding `json:"flows,omitempty"`
}

func runFull(url, content string) fullResult {
	flows := ast.Scan(content)
	result := analyzer.AnalyzeContent(url, content, len(flows))
	return fullResult{AnalysisResult: result, Flows: flows}
}

func fetchAndRun(url string) (fullResult, string) {
	result, content := analyzer.Analyze(url)
	if result.Error != "" {
		return fullResult{AnalysisResult: result}, content
	}
	flows := ast.Scan(content)
	result2 := analyzer.AnalyzeContent(url, content, len(flows))
	result2.Timestamp = result.Timestamp
	return fullResult{AnalysisResult: result2, Flows: flows}, content
}

func main() {
	port := flag.Int("port", 8080, "Web UI port (server mode)")
	listen := flag.String("listen", "127.0.0.1", "Web UI listen address (server mode)")
	urlFlag := flag.String("url", "", "Single JS URL to analyze")
	fileFlag := flag.String("file", "", "File with one URL per line")
	outFmt := flag.String("format", "table", "Output: table | json | plain")
	minConf := flag.String("min-confidence", "", "Filter: high | medium | low")
	minSev := flag.String("min-severity", "", "Filter: critical | high | medium | low | info")
	onlyHigh := flag.Bool("only-high-conf", false, "Only high-confidence findings")
	diffMode := flag.Bool("diff", false, "Show only new findings vs last scan")
	histList := flag.Bool("history", false, "List all previously scanned URLs")
	clearHist := flag.Bool("clear-history", false, "Delete all scan history")
	silent := flag.Bool("silent", false, "No banner or progress output")
	workers := flag.Int("workers", 5, "Concurrent workers for batch/file mode")
	noColor := flag.Bool("no-color", false, "Disable ANSI color output")
	showVer := flag.Bool("version", false, "Print version and exit")
	flag.Parse()

	if *showVer {
		fmt.Println("peelr v" + version)
		os.Exit(0)
	}

	if *clearHist {
		if err := history.ClearHistory(); err != nil {
			fmt.Fprintln(os.Stderr, "error:", err)
			os.Exit(1)
		}
		fmt.Fprintln(os.Stderr, "History cleared.")
		os.Exit(0)
	}
	if *histList {
		records, err := history.ListHistory()
		if err != nil {
			fmt.Fprintln(os.Stderr, "error:", err)
			os.Exit(1)
		}
		if len(records) == 0 {
			fmt.Fprintln(os.Stderr, "No history yet.")
			os.Exit(0)
		}
		for _, rec := range records {
			fmt.Printf("%s\t%d findings\t%s\n", rec.ScannedAt, len(rec.Findings), rec.URL)
		}
		os.Exit(0)
	}

	args := flag.Args()
	stdinPiped := isStdinPiped()
	cliMode := *urlFlag != "" || *fileFlag != "" || len(args) > 0 || stdinPiped

	if !cliMode {
		if !*silent {
			fmt.Print(banner)
		}
		if err := server.Start(fmt.Sprintf("%s:%d", *listen, *port)); err != nil {
			fmt.Fprintln(os.Stderr, "error:", err)
			os.Exit(1)
		}
		return
	}

	if !*silent {
		fmt.Fprint(os.Stderr, banner)
	}

	urls := collectURLs(*urlFlag, *fileFlag, args, stdinPiped)
	if len(urls) == 0 {
		fmt.Fprintln(os.Stderr, "error: no URLs provided")
		os.Exit(1)
	}

	type job struct {
		idx int
		url string
	}
	results := make([]fullResult, len(urls))
	var wg sync.WaitGroup
	sem := make(chan struct{}, *workers)

	for i, u := range urls {
		wg.Add(1)
		go func(idx int, url string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			if !*silent {
				fmt.Fprintf(os.Stderr, "  scanning %s\n", url)
			}
			fr, content := fetchAndRun(url)
			fr.Flows = nil
			_ = content
			// Keep successful CLI scans in history so diff mode works the same as the UI.
			if !*diffMode && fr.Error == "" {
				_ = history.Save(fr.AnalysisResult)
			}
			results[idx] = fr
		}(i, u)
	}
	wg.Wait()

	if *diffMode {
		printDiff(results, *outFmt, !*noColor)
		os.Exit(0)
	}

	sevOrder := map[string]int{"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}
	confOrder := map[string]int{"high": 3, "medium": 2, "low": 1}

	for i := range results {
		var kept []analyzer.Finding
		for _, f := range results[i].Findings {
			if *onlyHigh && f.Confidence != analyzer.ConfHigh {
				continue
			}
			if *minConf != "" && confOrder[string(f.Confidence)] < confOrder[*minConf] {
				continue
			}
			if *minSev != "" && sevOrder[string(f.Severity)] < sevOrder[*minSev] {
				continue
			}
			kept = append(kept, f)
		}
		results[i].Findings = kept
	}

	switch *outFmt {
	case "json":
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if len(results) == 1 {
			enc.Encode(results[0])
		} else {
			enc.Encode(results)
		}
	case "plain":
		printPlain(results)
	default:
		printTable(results, !*noColor)
	}

	// Return a failing exit code when serious findings are present.
	for _, r := range results {
		for _, f := range r.Findings {
			if f.Severity == analyzer.SevCritical || f.Severity == analyzer.SevHigh {
				os.Exit(1)
			}
		}
	}
}

func collectURLs(urlFlag, fileFlag string, args []string, stdinPiped bool) []string {
	seen := map[string]bool{}
	var urls []string
	add := func(u string) {
		u = strings.TrimSpace(u)
		if u == "" || seen[u] {
			return
		}
		seen[u] = true
		urls = append(urls, u)
	}
	if urlFlag != "" {
		add(urlFlag)
	}
	for _, a := range args {
		add(a)
	}
	if fileFlag != "" {
		data, err := os.ReadFile(fileFlag)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error reading %s: %v\n", fileFlag, err)
		} else {
			for _, line := range strings.Split(string(data), "\n") {
				add(line)
			}
		}
	}
	if stdinPiped {
		data, err := io.ReadAll(os.Stdin)
		if err == nil {
			for _, line := range strings.Split(string(data), "\n") {
				add(line)
			}
		}
	}
	return urls
}

const (
	cReset  = "\033[0m"
	cRed    = "\033[31m"
	cYellow = "\033[33m"
	cGreen  = "\033[32m"
	cCyan   = "\033[36m"
	cGray   = "\033[90m"
	cBold   = "\033[1m"
	cOrange = "\033[38;5;208m"
	cBlue   = "\033[34m"
)

func sevCol(s analyzer.Severity, c bool) string {
	if !c {
		return ""
	}
	switch s {
	case analyzer.SevCritical:
		return cRed + cBold
	case analyzer.SevHigh:
		return cOrange
	case analyzer.SevMedium:
		return cYellow
	case analyzer.SevLow:
		return cGreen
	default:
		return cGray
	}
}

func confCol(cf analyzer.Confidence, c bool) string {
	if !c {
		return ""
	}
	switch cf {
	case analyzer.ConfHigh:
		return cGreen
	case analyzer.ConfMedium:
		return cYellow
	default:
		return cGray
	}
}

func rst(c bool) string {
	if !c {
		return ""
	}
	return cReset
}

func printTable(results []fullResult, color bool) {
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)

	// Show the riskiest files first.
	sorted := make([]fullResult, len(results))
	copy(sorted, results)
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].RiskScore > sorted[j].RiskScore
	})

	for _, r := range sorted {
		if r.Error != "" {
			fmt.Fprintf(os.Stderr, "ERROR  %s: %s\n", r.URL, r.Error)
			continue
		}
		if len(r.Findings) == 0 {
			if color {
				fmt.Fprintf(w, "%s# %s — no findings%s\n", cGray, r.URL, cReset)
			} else {
				fmt.Fprintf(w, "# %s — no findings\n", r.URL)
			}
			continue
		}

		riskCol := cGreen
		if color {
			switch r.RiskLabel {
			case "critical":
				riskCol = cRed + cBold
			case "high":
				riskCol = cOrange
			case "medium":
				riskCol = cYellow
			}
		}

		fmt.Fprintf(w, "\n%s%s%s\n", cBold, r.URL, rst(color))
		fmt.Fprintf(w, "%s%d lines · %d findings · risk %s%s%s [%d/100]%s\n",
			cGray, r.LineCount, len(r.Findings),
			riskCol, r.RiskLabel, cGray, r.RiskScore, rst(color))
		fmt.Fprintln(w, strings.Repeat("─", 90))

		fmt.Fprintf(w, "%sSEV\tCONF\tCATEGORY\tTYPE\tVALUE%s\n", cBold, rst(color))
		fmt.Fprintln(w, strings.Repeat("─", 90))
		for _, f := range r.Findings {
			val := f.Value
			if len(val) > 55 {
				val = val[:52] + "..."
			}
			note := ""
			if f.Note != "" {
				note = "  " + cGray + "# " + f.Note + rst(color)
			}
			fmt.Fprintf(w, "%s%-8s%s\t%s%-6s%s\t%-22s\t%-30s\t%s%s\n",
				sevCol(f.Severity, color), strings.ToUpper(string(f.Severity)), rst(color),
				confCol(f.Confidence, color), string(f.Confidence), rst(color),
				f.Category, f.Type, val, note)
		}
		fmt.Fprintln(w)
	}
	w.Flush()

	total, crit, high, med, low := 0, 0, 0, 0, 0
	hc, mc, lc := 0, 0, 0
	for _, r := range results {
		for _, f := range r.Findings {
			total++
			switch f.Severity {
			case analyzer.SevCritical:
				crit++
			case analyzer.SevHigh:
				high++
			case analyzer.SevMedium:
				med++
			default:
				low++
			}
			switch f.Confidence {
			case analyzer.ConfHigh:
				hc++
			case analyzer.ConfMedium:
				mc++
			default:
				lc++
			}
		}
	}
	fmt.Printf("\n%s── Summary %s%s\n", cBold, strings.Repeat("─", 60), rst(color))
	fmt.Printf("  Files:    %d\n", len(results))
	fmt.Printf("  Findings: %d total  (%s%d crit%s  %s%d high%s  %s%d med%s  %d low/info)\n",
		total,
		cRed+cBold, crit, rst(color),
		cOrange, high, rst(color),
		cYellow, med, rst(color), low)
	fmt.Printf("  Confidence: %s%d high%s  %s%d medium%s  %s%d low%s\n",
		cGreen, hc, rst(color), cYellow, mc, rst(color), cGray, lc, rst(color))
}

func printPlain(results []fullResult) {
	for _, r := range results {
		if r.Error != "" {
			fmt.Fprintf(os.Stderr, "ERROR\t%s\t%s\n", r.URL, r.Error)
			continue
		}
		for _, f := range r.Findings {
			fmt.Printf("%s\t%s\t%s\t%s\t%s\t%s\tL%d\n",
				r.URL, f.Severity, f.Confidence, f.Category, f.Type, f.Value, f.Line)
		}
	}
}

func printDiff(results []fullResult, outFmt string, color bool) {
	for _, r := range results {
		if r.Error != "" {
			fmt.Fprintf(os.Stderr, "ERROR  %s: %s\n", r.URL, r.Error)
			continue
		}
		dr, err := history.Diff(r.AnalysisResult)
		if err != nil {
			fmt.Fprintf(os.Stderr, "diff error for %s: %v\n", r.URL, err)
			continue
		}
		if outFmt == "json" {
			enc := json.NewEncoder(os.Stdout)
			enc.SetIndent("", "  ")
			enc.Encode(dr)
			continue
		}
		if dr.IsFirstScan {
			fmt.Fprintf(os.Stderr, "%s[first scan — no previous baseline]%s %s\n",
				cGray, rst(color), r.URL)
		} else {
			fmt.Printf("\n%s%s%s\n", cBold, r.URL, rst(color))
			fmt.Printf("  previous scan: %s\n", dr.PreviousScan)
			fmt.Printf("  %s%d new%s  %d gone  %d unchanged\n",
				cRed+cBold, len(dr.New), rst(color), len(dr.Gone), dr.Unchanged)
		}
		for _, f := range dr.New {
			fmt.Printf("  %s+ NEW%s  %s%-8s%s  %s  %s\n",
				cGreen+cBold, rst(color),
				sevCol(f.Severity, color), strings.ToUpper(string(f.Severity)), rst(color),
				f.Type, f.Value)
		}
		for _, f := range dr.Gone {
			fmt.Printf("  %s- GONE%s %s%-8s%s  %s  %s\n",
				cGray, rst(color),
				sevCol(f.Severity, color), strings.ToUpper(string(f.Severity)), rst(color),
				f.Type, f.Value)
		}
	}
}

func isStdinPiped() bool {
	fi, err := os.Stdin.Stat()
	if err != nil {
		return false
	}
	return (fi.Mode() & os.ModeCharDevice) == 0
}
