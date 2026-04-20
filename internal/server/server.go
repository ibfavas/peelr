package server

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/ibfavas/peelr/internal/analyzer"
	"github.com/ibfavas/peelr/internal/ast"
	"github.com/ibfavas/peelr/internal/history"
)

func Start(addr string) error {
	mux := http.NewServeMux()
	fs := http.FileServer(http.Dir("web/static"))
	mux.Handle("/static/", http.StripPrefix("/static/", fs))
	mux.HandleFunc("/", indexHandler)
	mux.HandleFunc("/api/analyze", analyzeHandler)
	mux.HandleFunc("/api/analyze/batch", batchHandler)
	mux.HandleFunc("/api/history", historyHandler)
	log.Printf("Peelr listening on %s", addr)
	return http.ListenAndServe(addr, mux)
}

func indexHandler(w http.ResponseWriter, r *http.Request) {
	http.ServeFile(w, r, "web/templates/index.html")
}

// fullResult combines scanner output with flow data for the UI.
type fullResult struct {
	analyzer.AnalysisResult
	Flows []ast.FlowFinding `json:"flows"`
}

func runFull(url string) fullResult {
	result, content := analyzer.Analyze(url)
	var flows []ast.FlowFinding
	if content != "" {
		flows = ast.Scan(content)
		// Re-score after flow analysis so the final risk matches the full result.
		result2 := analyzer.AnalyzeContent(url, content, len(flows))
		result2.Timestamp = result.Timestamp
		result = result2
	}
	// History should not block the response path.
	_ = history.Save(result)
	return fullResult{AnalysisResult: result, Flows: flows}
}

type analyzeRequest struct {
	URL  string `json:"url"`
	Diff bool   `json:"diff"`
}

type analyzeResponse struct {
	fullResult
	Diff *history.DiffResult `json:"diff,omitempty"`
}

func analyzeHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", 405)
		return
	}
	var req analyzeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.URL == "" {
		jsonError(w, "invalid request", http.StatusBadRequest)
		return
	}
	url := strings.TrimSpace(req.URL)
	fr := runFull(url)
	resp := analyzeResponse{fullResult: fr}

	if req.Diff {
		dr, err := history.Diff(fr.AnalysisResult)
		if err == nil {
			resp.Diff = &dr
		}
	}
	jsonOK(w, resp)
}

type batchRequest struct {
	URLs []string `json:"urls"`
	Diff bool     `json:"diff"`
}

type batchResponse struct {
	Results   []analyzeResponse `json:"results"`
	Total     int               `json:"total"`
	Succeeded int               `json:"succeeded"`
	Failed    int               `json:"failed"`
	Duration  string            `json:"duration"`
}

func batchHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", 405)
		return
	}
	var req batchRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, "invalid request", http.StatusBadRequest)
		return
	}
	if len(req.URLs) == 0 || len(req.URLs) > 50 {
		jsonError(w, "urls: 1-50 required", http.StatusBadRequest)
		return
	}

	start := time.Now()
	results := make([]analyzeResponse, len(req.URLs))
	var wg sync.WaitGroup
	sem := make(chan struct{}, 5)

	for i, u := range req.URLs {
		wg.Add(1)
		go func(idx int, url string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			fr := runFull(strings.TrimSpace(url))
			resp := analyzeResponse{fullResult: fr}
			if req.Diff {
				dr, err := history.Diff(fr.AnalysisResult)
				if err == nil {
					resp.Diff = &dr
				}
			}
			results[idx] = resp
		}(i, u)
	}
	wg.Wait()

	s, f := 0, 0
	for _, res := range results {
		if res.Error != "" {
			f++
		} else {
			s++
		}
	}
	jsonOK(w, batchResponse{
		Results:   results,
		Total:     len(req.URLs),
		Succeeded: s,
		Failed:    f,
		Duration:  fmt.Sprintf("%.2fs", time.Since(start).Seconds()),
	})
}

func historyHandler(w http.ResponseWriter, r *http.Request) {
	records, err := history.ListHistory()
	if err != nil {
		jsonError(w, err.Error(), 500)
		return
	}
	jsonOK(w, records)
}

func jsonOK(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(v)
}

func jsonError(w http.ResponseWriter, msg string, code int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(map[string]string{"error": msg})
}
