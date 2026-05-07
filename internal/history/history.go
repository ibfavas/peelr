package history

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/ibfavas/peelr/internal/analyzer"
)

type Record struct {
	SourceID  string             `json:"source_id"`
	Name      string             `json:"name"`
	Origin    string             `json:"origin"`
	ScannedAt string             `json:"scanned_at"`
	Findings  []analyzer.Finding `json:"findings"`
}

type DiffResult struct {
	SourceID     string             `json:"source_id"`
	PreviousScan string             `json:"previous_scan"`
	CurrentScan  string             `json:"current_scan"`
	New          []analyzer.Finding `json:"new"`
	Gone         []analyzer.Finding `json:"gone"`
	Unchanged    int                `json:"unchanged"`
	IsFirstScan  bool               `json:"is_first_scan"`
}

func dir() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	path := filepath.Join(home, ".peelr", "history")
	return path, os.MkdirAll(path, 0o700)
}

func keyFor(sourceID string) string {
	sum := sha256.Sum256([]byte(sourceID))
	return fmt.Sprintf("%x", sum[:8])
}

func Save(result analyzer.Result) error {
	if result.Error != "" || result.ID == "" {
		return nil
	}
	path, err := dir()
	if err != nil {
		return err
	}
	record := Record{
		SourceID:  result.ID,
		Name:      result.Name,
		Origin:    result.Origin,
		ScannedAt: time.Now().UTC().Format(time.RFC3339),
		Findings:  result.Findings,
	}
	data, err := json.MarshalIndent(record, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(path, keyFor(result.ID)+".json"), data, 0o600)
}

func Load(sourceID string) (*Record, error) {
	path, err := dir()
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(filepath.Join(path, keyFor(sourceID)+".json"))
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var record Record
	if err := json.Unmarshal(data, &record); err != nil {
		return nil, err
	}
	return &record, nil
}

func Diff(result analyzer.Result) (DiffResult, error) {
	now := time.Now().UTC().Format(time.RFC3339)
	out := DiffResult{
		SourceID:    result.ID,
		CurrentScan: now,
	}
	if result.Error != "" {
		return out, fmt.Errorf("cannot diff failed scan: %s", result.Error)
	}
	prev, err := Load(result.ID)
	if err != nil {
		return out, err
	}
	if prev == nil {
		out.IsFirstScan = true
		out.New = result.Findings
		return out, Save(result)
	}
	out.PreviousScan = prev.ScannedAt
	prevSet := map[string]analyzer.Finding{}
	for _, finding := range prev.Findings {
		prevSet[fingerprint(finding)] = finding
	}
	currSet := map[string]analyzer.Finding{}
	for _, finding := range result.Findings {
		currSet[fingerprint(finding)] = finding
	}
	for key, finding := range currSet {
		if _, ok := prevSet[key]; ok {
			out.Unchanged++
			continue
		}
		out.New = append(out.New, finding)
	}
	for key, finding := range prevSet {
		if _, ok := currSet[key]; !ok {
			out.Gone = append(out.Gone, finding)
		}
	}
	sort.Slice(out.New, func(i, j int) bool { return out.New[i].Line < out.New[j].Line })
	sort.Slice(out.Gone, func(i, j int) bool { return out.Gone[i].Line < out.Gone[j].Line })
	return out, Save(result)
}

func ListHistory() ([]Record, error) {
	path, err := dir()
	if err != nil {
		return nil, err
	}
	entries, err := os.ReadDir(path)
	if err != nil {
		return nil, err
	}
	var out []Record
	for _, entry := range entries {
		if filepath.Ext(entry.Name()) != ".json" {
			continue
		}
		data, err := os.ReadFile(filepath.Join(path, entry.Name()))
		if err != nil {
			continue
		}
		var record Record
		if err := json.Unmarshal(data, &record); err != nil {
			continue
		}
		out = append(out, record)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ScannedAt > out[j].ScannedAt })
	return out, nil
}

func ClearHistory() error {
	path, err := dir()
	if err != nil {
		return err
	}
	return os.RemoveAll(path)
}

func fingerprint(f analyzer.Finding) string {
	return fmt.Sprintf("%s:%s:%s:%d", f.Category, f.Type, f.Value, f.Line)
}
