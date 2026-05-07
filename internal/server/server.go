package server

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"mime/multipart"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/ibfavas/peelr/internal/analyzer"
	"github.com/ibfavas/peelr/internal/history"
)

const maxSourcesPerJob = 250

type Job struct {
	ID        string            `json:"id"`
	Mode      string            `json:"mode"`
	Status    string            `json:"status"`
	CreatedAt string            `json:"created_at"`
	UpdatedAt string            `json:"updated_at"`
	Total     int               `json:"total"`
	Completed int               `json:"completed"`
	Results   []analyzer.Result `json:"results"`
	Error     string            `json:"error,omitempty"`
}

type jobStore struct {
	mu   sync.RWMutex
	jobs map[string]*Job
}

var store = &jobStore{jobs: map[string]*Job{}}

func Start(addr string) error {
	mux := http.NewServeMux()
	fs := http.FileServer(http.Dir("web/static"))
	mux.Handle("/static/", http.StripPrefix("/static/", fs))
	mux.HandleFunc("/", indexHandler)
	mux.HandleFunc("/api/jobs", createJobHandler)
	mux.HandleFunc("/api/jobs/", jobHandler)
	mux.HandleFunc("/api/history", historyHandler)
	log.Printf("Peelr listening on %s", addr)
	return http.ListenAndServe(addr, mux)
}

func indexHandler(w http.ResponseWriter, r *http.Request) {
	http.ServeFile(w, r, "web/templates/index.html")
}

func createJobHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if err := r.ParseMultipartForm(32 << 20); err != nil {
		jsonError(w, "invalid multipart form", http.StatusBadRequest)
		return
	}

	sources, err := collectJSSources(r.MultipartForm)
	if err != nil {
		jsonError(w, err.Error(), http.StatusBadRequest)
		return
	}
	if len(sources) == 0 {
		jsonError(w, "no javascript urls provided", http.StatusBadRequest)
		return
	}
	if len(sources) > maxSourcesPerJob {
		jsonError(w, fmt.Sprintf("too many javascript urls: max %d", maxSourcesPerJob), http.StatusBadRequest)
		return
	}

	job := &Job{
		ID:        fmt.Sprintf("%d", time.Now().UnixNano()),
		Mode:      "js",
		Status:    "queued",
		CreatedAt: time.Now().UTC().Format(time.RFC3339),
		UpdatedAt: time.Now().UTC().Format(time.RFC3339),
		Total:     len(sources),
		Results:   make([]analyzer.Result, len(sources)),
	}
	for i, source := range sources {
		job.Results[i] = analyzer.Result{
			ID:        source.ID,
			Name:      source.Name,
			Kind:      source.Kind,
			Origin:    source.Origin,
			Status:    "queued",
			StartedAt: "",
			Summary: analyzer.Summary{
				ByCategory:   map[string]int{},
				BySeverity:   map[string]int{},
				ByConfidence: map[string]int{},
			},
		}
	}

	store.mu.Lock()
	store.jobs[job.ID] = job
	store.mu.Unlock()

	go processJob(job.ID, sources)
	jsonOK(w, map[string]any{"job_id": job.ID})
}

func jobHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	id := strings.TrimPrefix(r.URL.Path, "/api/jobs/")
	store.mu.RLock()
	job, ok := store.jobs[id]
	store.mu.RUnlock()
	if !ok {
		jsonError(w, "job not found", http.StatusNotFound)
		return
	}
	jsonOK(w, job)
}

func historyHandler(w http.ResponseWriter, r *http.Request) {
	records, err := history.ListHistory()
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	jsonOK(w, records)
}

func processJob(jobID string, sources []analyzer.SourceInput) {
	setJobStatus(jobID, "running", "")

	type item struct {
		idx    int
		result analyzer.Result
	}
	results := make(chan item, len(sources))
	var wg sync.WaitGroup
	sem := make(chan struct{}, 4)

	for idx, source := range sources {
		wg.Add(1)
		go func(i int, src analyzer.SourceInput) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			results <- item{idx: i, result: runSource(src)}
		}(idx, source)
	}

	go func() {
		wg.Wait()
		close(results)
	}()

	for item := range results {
		store.mu.Lock()
		job := store.jobs[jobID]
		job.Results[item.idx] = item.result
		job.Completed++
		job.UpdatedAt = time.Now().UTC().Format(time.RFC3339)
		if job.Completed == job.Total {
			job.Status = "completed"
		}
		store.mu.Unlock()
		if item.result.Error == "" {
			_ = history.Save(item.result)
		}
	}
}

func runSource(src analyzer.SourceInput) analyzer.Result {
	input, err := analyzer.LoadURL(src.Origin)
	if err != nil {
		return analyzer.Result{
			ID:        src.ID,
			Name:      src.Name,
			Kind:      src.Kind,
			Origin:    src.Origin,
			Status:    "failed",
			StartedAt: time.Now().UTC().Format(time.RFC3339),
			Summary: analyzer.Summary{
				ByCategory:   map[string]int{},
				BySeverity:   map[string]int{},
				ByConfidence: map[string]int{},
			},
			Error: err.Error(),
		}
	}
	result := analyzer.Analyze(input)
	result.Status = "completed"
	return result
}

func collectJSSources(form *multipart.Form) ([]analyzer.SourceInput, error) {
	urls, err := collectLinesFromForm(form, "urls")
	if err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	var out []analyzer.SourceInput
	for _, raw := range urls {
		jsURL := strings.TrimSpace(raw)
		if jsURL == "" || seen[jsURL] || !looksLikeRemoteJS(jsURL) {
			continue
		}
		seen[jsURL] = true
		out = append(out, analyzer.SourceInput{
			ID:     analyzer.SourceKey(analyzer.SourceURL, jsURL),
			Name:   jsURL,
			Kind:   analyzer.SourceURL,
			Origin: jsURL,
		})
	}
	return out, nil
}

func collectLinesFromForm(form *multipart.Form, field string) ([]string, error) {
	seen := map[string]bool{}
	var out []string
	add := func(value string) {
		value = strings.TrimSpace(value)
		if value == "" || seen[value] {
			return
		}
		seen[value] = true
		out = append(out, value)
	}
	if values, ok := form.Value[field]; ok {
		for _, value := range values {
			for _, line := range strings.Split(value, "\n") {
				add(line)
			}
		}
	}
	for _, headers := range form.File {
		for _, header := range headers {
			lines, err := readUploadedLines(header)
			if err != nil {
				return nil, err
			}
			for _, line := range lines {
				add(line)
			}
		}
	}
	return out, nil
}

func readUploadedLines(header *multipart.FileHeader) ([]string, error) {
	file, err := header.Open()
	if err != nil {
		return nil, err
	}
	defer file.Close()
	limited := io.LimitReader(file, analyzer.MaxSourceBytes+1)
	body, err := io.ReadAll(limited)
	if err != nil {
		return nil, err
	}
	if len(body) > analyzer.MaxSourceBytes {
		return nil, fmt.Errorf("%s exceeds %d MB", header.Filename, analyzer.MaxSourceBytes>>20)
	}
	reader := csv.NewReader(strings.NewReader(string(body)))
	reader.Comma = '\n'
	rows, err := reader.ReadAll()
	if err != nil {
		return nil, err
	}
	var out []string
	for _, row := range rows {
		for _, item := range row {
			item = strings.TrimSpace(item)
			if item != "" {
				out = append(out, item)
			}
		}
	}
	return out, nil
}

func setJobStatus(id, status, errMsg string) {
	store.mu.Lock()
	defer store.mu.Unlock()
	job, ok := store.jobs[id]
	if !ok {
		return
	}
	job.Status = status
	job.Error = errMsg
	job.UpdatedAt = time.Now().UTC().Format(time.RFC3339)
}

func looksLikeRemoteJS(raw string) bool {
	raw = strings.TrimSpace(raw)
	if !(strings.HasPrefix(raw, "http://") || strings.HasPrefix(raw, "https://")) {
		return false
	}
	lower := strings.ToLower(raw)
	return strings.Contains(lower, ".js")
}

func jsonOK(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func jsonError(w http.ResponseWriter, msg string, code int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": msg})
}
