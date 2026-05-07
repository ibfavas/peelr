package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"text/tabwriter"

	"github.com/ibfavas/peelr/internal/analyzer"
	"github.com/ibfavas/peelr/internal/history"
	"github.com/ibfavas/peelr/internal/server"
)

const version = "2.0.0"

const banner = `
    ____            __
   / __ \___  ___  / /____
  / /_/ / _ \/ _ \/ / ___/
 / ____/  __/  __/ / /
/_/    \___/\___/_/_/
peelr ` + version + `  |  js recon and triage
`

func main() {
	port := flag.Int("port", 8080, "Web UI port")
	listen := flag.String("listen", "127.0.0.1", "Web UI listen address")
	urlFlag := flag.String("url", "", "Single JavaScript URL to analyze")
	fileFlag := flag.String("file", "", "Text file with one JavaScript URL per line")
	jsFileFlag := flag.String("js-file", "", "JavaScript file, directory, or comma-separated paths to analyze directly")
	formatFlag := flag.String("format", "table", "Output format: table | json | plain")
	diffFlag := flag.Bool("diff", false, "Compare results with the last stored scan")
	historyFlag := flag.Bool("history", false, "List previous scans")
	clearHistoryFlag := flag.Bool("clear-history", false, "Delete saved history")
	workersFlag := flag.Int("workers", 4, "Concurrent workers for URL mode")
	silentFlag := flag.Bool("silent", false, "Suppress banner and progress")
	versionFlag := flag.Bool("version", false, "Print version and exit")
	flag.Parse()

	if *versionFlag {
		fmt.Println("peelr v" + version)
		return
	}
	if *clearHistoryFlag {
		exitIf(history.ClearHistory())
		return
	}
	if *historyFlag {
		printHistory()
		return
	}

	urls := collectURLs(*urlFlag, *fileFlag, flag.Args(), isStdinPiped())
	localFiles := collectJSFiles(*jsFileFlag)
	cliMode := len(urls) > 0 || len(localFiles) > 0
	if !cliMode {
		if !*silentFlag {
			fmt.Print(banner)
		}
		exitIf(server.Start(fmt.Sprintf("%s:%d", *listen, *port)))
		return
	}

	if !*silentFlag {
		fmt.Fprint(os.Stderr, banner)
	}

	results := analyzeURLs(urls, *workersFlag, *silentFlag)
	results = append(results, analyzeFiles(localFiles, *silentFlag)...)

	if *diffFlag {
		printDiff(results, *formatFlag)
		return
	}
	switch *formatFlag {
	case "json":
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(results)
	case "plain":
		printPlain(results)
	default:
		printTable(results)
	}
	for _, result := range results {
		if result.Error != "" {
			os.Exit(1)
		}
		for _, finding := range result.Findings {
			if finding.Severity == analyzer.SevCritical || finding.Severity == analyzer.SevHigh {
				os.Exit(1)
			}
		}
	}
}

func analyzeURLs(urls []string, workers int, silent bool) []analyzer.Result {
	results := make([]analyzer.Result, len(urls))
	var wg sync.WaitGroup
	sem := make(chan struct{}, max(1, workers))
	for i, raw := range urls {
		wg.Add(1)
		go func(idx int, value string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			if !silent {
				fmt.Fprintf(os.Stderr, "  fetching %s\n", value)
			}
			source, err := analyzer.LoadURL(value)
			if err != nil {
				results[idx] = analyzer.Result{
					ID:       analyzer.SourceKey(analyzer.SourceURL, value),
					Name:     value,
					Kind:     analyzer.SourceURL,
					Origin:   value,
					Status:   "failed",
					Findings: nil,
					Summary: analyzer.Summary{
						ByCategory:   map[string]int{},
						BySeverity:   map[string]int{},
						ByConfidence: map[string]int{},
					},
					Error: err.Error(),
				}
				return
			}
			results[idx] = analyzer.Analyze(source)
			_ = history.Save(results[idx])
		}(i, raw)
	}
	wg.Wait()
	return results
}

func analyzeFiles(paths []string, silent bool) []analyzer.Result {
	results := make([]analyzer.Result, 0, len(paths))
	for _, path := range paths {
		if !silent {
			fmt.Fprintf(os.Stderr, "  analyzing %s\n", path)
		}
		body, err := os.ReadFile(path)
		if err != nil {
			results = append(results, analyzer.Result{
				ID:     analyzer.SourceKey(analyzer.SourceFile, path),
				Name:   filepath.Base(path),
				Kind:   analyzer.SourceFile,
				Origin: path,
				Status: "failed",
				Summary: analyzer.Summary{
					ByCategory:   map[string]int{},
					BySeverity:   map[string]int{},
					ByConfidence: map[string]int{},
				},
				Error: err.Error(),
			})
			continue
		}
		result := analyzer.Analyze(analyzer.SourceInput{
			ID:      analyzer.SourceKey(analyzer.SourceFile, path),
			Name:    filepath.Base(path),
			Kind:    analyzer.SourceFile,
			Origin:  path,
			Content: string(body),
		})
		results = append(results, result)
		_ = history.Save(result)
	}
	return results
}

func printTable(results []analyzer.Result) {
	for _, result := range results {
		fmt.Printf("\n%s\n", result.Name)
		if result.Error != "" {
			fmt.Printf("error: %s\n", result.Error)
			continue
		}
		fmt.Printf("%d lines  %d findings  risk %s [%d/100]\n", result.LineCount, len(result.Findings), strings.ToUpper(result.Summary.RiskLabel), result.Summary.RiskScore)
		writer := tabwriter.NewWriter(os.Stdout, 2, 4, 2, ' ', 0)
		fmt.Fprintln(writer, "SEVERITY\tCONFIDENCE\tCATEGORY\tTYPE\tLINE\tVALUE")
		for _, finding := range result.Findings {
			fmt.Fprintf(writer, "%s\t%s\t%s\t%s\t%d\t%s\n",
				finding.Severity, finding.Confidence, finding.Category, finding.Title, finding.Line, truncate(finding.Value, 80))
		}
		_ = writer.Flush()
	}
}

func printPlain(results []analyzer.Result) {
	for _, result := range results {
		for _, finding := range result.Findings {
			fmt.Printf("%s\t%s\t%s\t%s\t%d\t%s\n",
				result.Name, finding.Category, finding.Severity, finding.Title, finding.Line, finding.Value)
		}
		if result.Error != "" {
			fmt.Printf("%s\terror\t-\t-\t0\t%s\n", result.Name, result.Error)
		}
	}
}

func printDiff(results []analyzer.Result, format string) {
	type payload struct {
		Result analyzer.Result    `json:"result"`
		Diff   history.DiffResult `json:"diff"`
		Error  string             `json:"error,omitempty"`
	}
	var out []payload
	for _, result := range results {
		diff, err := history.Diff(result)
		item := payload{Result: result}
		if err != nil {
			item.Error = err.Error()
		} else {
			item.Diff = diff
		}
		out = append(out, item)
	}
	if format == "json" {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(out)
		return
	}
	for _, item := range out {
		fmt.Printf("\n%s\n", item.Result.Name)
		if item.Error != "" {
			fmt.Printf("error: %s\n", item.Error)
			continue
		}
		if item.Diff.IsFirstScan {
			fmt.Printf("first scan: %d new findings\n", len(item.Diff.New))
			continue
		}
		fmt.Printf("new: %d  gone: %d  unchanged: %d\n", len(item.Diff.New), len(item.Diff.Gone), item.Diff.Unchanged)
	}
}

func printHistory() {
	records, err := history.ListHistory()
	exitIf(err)
	if len(records) == 0 {
		fmt.Println("No history yet.")
		return
	}
	for _, record := range records {
		fmt.Printf("%s\t%s\t%d findings\n", record.ScannedAt, record.Name, len(record.Findings))
	}
}

func collectURLs(urlFlag, fileFlag string, args []string, stdinPiped bool) []string {
	seen := map[string]bool{}
	var urls []string
	add := func(value string) {
		value = strings.TrimSpace(value)
		if value == "" || seen[value] {
			return
		}
		seen[value] = true
		urls = append(urls, value)
	}
	if urlFlag != "" {
		add(urlFlag)
	}
	for _, arg := range args {
		if strings.HasPrefix(arg, "http://") || strings.HasPrefix(arg, "https://") {
			add(arg)
		}
	}
	if fileFlag != "" {
		handle, err := os.Open(fileFlag)
		if err == nil {
			found, readErr := analyzer.ReadURLs(handle)
			_ = handle.Close()
			if readErr == nil {
				for _, value := range found {
					add(value)
				}
			}
		}
	}
	if stdinPiped {
		found, err := analyzer.ReadURLs(os.Stdin)
		if err == nil {
			for _, value := range found {
				add(value)
			}
		}
	}
	return urls
}

func collectJSFiles(raw string) []string {
	if strings.TrimSpace(raw) == "" {
		return nil
	}
	seen := map[string]bool{}
	var out []string
	parts := strings.Split(raw, ",")
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		info, err := os.Stat(part)
		if err != nil {
			continue
		}
		if info.IsDir() {
			entries, _ := os.ReadDir(part)
			for _, entry := range entries {
				if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".js") {
					continue
				}
				full := filepath.Join(part, entry.Name())
				if !seen[full] {
					seen[full] = true
					out = append(out, full)
				}
			}
			continue
		}
		if !seen[part] {
			seen[part] = true
			out = append(out, part)
		}
	}
	sort.Strings(out)
	return out
}

func truncate(value string, limit int) string {
	if len(value) <= limit {
		return value
	}
	return value[:limit] + "..."
}

func isStdinPiped() bool {
	stat, err := os.Stdin.Stat()
	if err != nil {
		return false
	}
	return (stat.Mode() & os.ModeCharDevice) == 0
}

func exitIf(err error) {
	if err == nil {
		return
	}
	fmt.Fprintln(os.Stderr, "error:", err)
	os.Exit(1)
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
