package scorer

import (
	"math"

	"github.com/ibfavas/peelr/internal/analyzer"
	"github.com/ibfavas/peelr/internal/ast"
)

var sevWeight = map[analyzer.Severity]float64{
	analyzer.SevCritical: 40,
	analyzer.SevHigh:     15,
	analyzer.SevMedium:   5,
	analyzer.SevLow:      1,
	analyzer.SevInfo:     0,
}

var confMult = map[analyzer.Confidence]float64{
	analyzer.ConfHigh:   1.0,
	analyzer.ConfMedium: 0.6,
	analyzer.ConfLow:    0.3,
}

const flowBonus = 20.0
const maxFlowBonus = 40.0

func Score(findings []analyzer.Finding, flows []ast.FlowFinding) int {
	raw := 0.0

	for _, f := range findings {
		w := sevWeight[f.Severity]
		m := confMult[f.Confidence]
		raw += w * m
	}

	bonus := math.Min(float64(len(flows))*flowBonus, maxFlowBonus)
	raw += bonus

	score := 100.0 * (1.0 - math.Exp(-raw/120.0))
	return int(math.Round(score))
}

func RiskLabel(score int) string {
	switch {
	case score >= 80:
		return "critical"
	case score >= 55:
		return "high"
	case score >= 30:
		return "medium"
	case score >= 10:
		return "low"
	default:
		return "minimal"
	}
}
