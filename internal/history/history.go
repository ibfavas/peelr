package history

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/ibfavas/peelr/internal/analyzer"
)

func dir() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	d := filepath.Join(home, ".peelr", "history")
	return d, os.MkdirAll(d, 0700)
}

func keyFor(url string) string {
	h := sha256.Sum256([]byte(url))
	return fmt.Sprintf("%x", h[:8])
}

type Record struct {
	URL       string             `json:"url"`
	ScannedAt string             `json:"scanned_at"`
	Findings  []analyzer.Finding `json:"findings"`
}

func Save(result analyzer.AnalysisResult) error {
	d, err := dir()
	if err != nil {
		return err
	}
	rec := Record{
		URL:       result.URL,
		ScannedAt: time.Now().UTC().Format(time.RFC3339),
		Findings:  result.Findings,
	}
	data, err := json.MarshalIndent(rec, "", "  ")
	if err != nil {
		return err
	}
	path := filepath.Join(d, keyFor(result.URL)+".json")
	return os.WriteFile(path, data, 0600)
}

func Load(url string) (*Record, error) {
	d, err := dir()
	if err != nil {
		return nil, err
	}
	path := filepath.Join(d, keyFor(url)+".json")
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var rec Record
	if err := json.Unmarshal(data, &rec); err != nil {
		return nil, err
	}
	return &rec, nil
}

type DiffResult struct {
	URL          string             `json:"url"`
	PreviousScan string             `json:"previous_scan"`
	CurrentScan  string             `json:"current_scan"`
	New          []analyzer.Finding `json:"new"`
	Gone         []analyzer.Finding `json:"gone"`
	Unchanged    int                `json:"unchanged"`
	IsFirstScan  bool               `json:"is_first_scan"`
}

func fingerprintFinding(f analyzer.Finding) string {
	return f.Category + ":" + f.Type + ":" + f.Value
}

// Diff compares the current result with the saved baseline.
func Diff(result analyzer.AnalysisResult) (DiffResult, error) {
	now := time.Now().UTC().Format(time.RFC3339)
	dr := DiffResult{
		URL:         result.URL,
		CurrentScan: now,
	}
	if result.Error != "" {
		return dr, fmt.Errorf("cannot diff failed scan: %s", result.Error)
	}

	prev, err := Load(result.URL)
	if err != nil {
		return dr, err
	}

	if prev == nil {
		dr.IsFirstScan = true
		dr.New = result.Findings
		return dr, Save(result)
	}

	dr.PreviousScan = prev.ScannedAt

	prevSet := map[string]analyzer.Finding{}
	for _, f := range prev.Findings {
		prevSet[fingerprintFinding(f)] = f
	}
	currSet := map[string]analyzer.Finding{}
	for _, f := range result.Findings {
		currSet[fingerprintFinding(f)] = f
	}

	for key, f := range currSet {
		if _, exists := prevSet[key]; !exists {
			dr.New = append(dr.New, f)
		} else {
			dr.Unchanged++
		}
	}
	for key, f := range prevSet {
		if _, exists := currSet[key]; !exists {
			dr.Gone = append(dr.Gone, f)
		}
	}

	return dr, Save(result)
}

func ListHistory() ([]Record, error) {
	d, err := dir()
	if err != nil {
		return nil, err
	}
	entries, err := os.ReadDir(d)
	if err != nil {
		return nil, err
	}
	var records []Record
	for _, e := range entries {
		if filepath.Ext(e.Name()) != ".json" {
			continue
		}
		data, err := os.ReadFile(filepath.Join(d, e.Name()))
		if err != nil {
			continue
		}
		var rec Record
		if err := json.Unmarshal(data, &rec); err != nil {
			continue
		}
		records = append(records, rec)
	}
	return records, nil
}

func ClearHistory() error {
	d, err := dir()
	if err != nil {
		return err
	}
	return os.RemoveAll(d)
}
