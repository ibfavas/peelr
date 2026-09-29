package analyzer

// Shared types for the Peelr analysis engine. The JSON shapes here are the
// contract consumed by the CLI, the web UI, and the history store — field
// names must stay stable across versions.

type Severity string

const (
	SevCritical Severity = "critical"
	SevHigh     Severity = "high"
	SevMedium   Severity = "medium"
	SevLow      Severity = "low"
	SevInfo     Severity = "info"
)

type Confidence string

const (
	ConfHigh   Confidence = "high"
	ConfMedium Confidence = "medium"
	ConfLow    Confidence = "low"
)

type SourceKind string

const (
	SourceURL  SourceKind = "url"
	SourceJS   SourceKind = "js"
	SourceFile SourceKind = "file"
)

type SourceInput struct {
	ID      string     `json:"id"`
	Name    string     `json:"name"`
	Kind    SourceKind `json:"kind"`
	Origin  string     `json:"origin"`
	Content string     `json:"content"`
}

type Finding struct {
	ID         string     `json:"id"`
	Category   string     `json:"category"`
	Type       string     `json:"type"`
	Title      string     `json:"title"`
	Value      string     `json:"value"`
	Line       int        `json:"line"`
	Column     int        `json:"column"`
	Context    string     `json:"context"`
	Snippet    string     `json:"snippet"`
	Severity   Severity   `json:"severity"`
	Confidence Confidence `json:"confidence"`
	Note       string     `json:"note,omitempty"`
}

type Summary struct {
	TotalFindings      int            `json:"total_findings"`
	ByCategory         map[string]int `json:"by_category"`
	BySeverity         map[string]int `json:"by_severity"`
	ByConfidence       map[string]int `json:"by_confidence"`
	NetworkRequests    int            `json:"network_requests"`
	SensitiveParams    int            `json:"sensitive_params"`
	InterestingComment int            `json:"interesting_comments"`
	// Truncated counts findings dropped by per-category / total caps.
	Truncated map[string]int `json:"truncated,omitempty"`
	RiskScore int            `json:"risk_score"`
	RiskLabel string         `json:"risk_label"`
}

type Result struct {
	ID          string     `json:"id"`
	Name        string     `json:"name"`
	Kind        SourceKind `json:"kind"`
	Origin      string     `json:"origin"`
	Status      string     `json:"status"`
	StartedAt   string     `json:"started_at"`
	CompletedAt string     `json:"completed_at,omitempty"`
	FileSize    int        `json:"file_size"`
	LineCount   int        `json:"line_count"`
	// Minified is set when the source looks like a minified bundle, where
	// line numbers are approximate and string scanning is less precise.
	Minified bool      `json:"minified,omitempty"`
	Summary  Summary   `json:"summary"`
	Findings []Finding `json:"findings"`
	Error    string    `json:"error,omitempty"`
}

func (s SourceKind) String() string {
	return string(s)
}
