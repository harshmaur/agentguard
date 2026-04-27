package output

import (
	"encoding/json"
	"fmt"
	"io"
	"time"

	"github.com/agentguard/agentguard/internal/finding"
)

// JSON is the structured machine-readable output. Use it for piping into
// jq, custom tooling, or the SaaS aggregation layer.
type jsonReport struct {
	Schema      string             `json:"schema"`
	Version     string             `json:"version"`
	GeneratedAt time.Time          `json:"generated_at"`
	Roots       []string           `json:"roots,omitempty"`
	SelfAudit   string             `json:"self_audit,omitempty"`
	Stats       jsonStats          `json:"stats"`
	Findings    []finding.Finding  `json:"findings"`
}

type jsonStats struct {
	FilesSeen   int `json:"files_seen"`
	FilesParsed int `json:"files_parsed"`
	Suppressed  int `json:"suppressed"`
	Skipped     int `json:"skipped"`
	Total       int `json:"total"`
	Critical    int `json:"critical"`
	High        int `json:"high"`
	Medium      int `json:"medium"`
	Low         int `json:"low"`
}

// JSON writes the report as pretty-printed JSON.
func JSON(w io.Writer, r Report) error {
	jr := jsonReport{
		Schema:      "https://agentguard.dev/schema/report.v1.json",
		Version:     nonEmpty(r.Version, "0.0.0-dev"),
		GeneratedAt: r.FinishedAt,
		Roots:       r.Roots,
		SelfAudit:   r.SelfAudit,
		Findings:    r.Findings,
	}
	jr.Stats.FilesSeen = r.FilesSeen
	jr.Stats.FilesParsed = r.FilesParsed
	jr.Stats.Suppressed = r.Suppressed
	jr.Stats.Skipped = r.Skipped
	for _, f := range r.Findings {
		jr.Stats.Total++
		switch f.Severity {
		case finding.SeverityCritical:
			jr.Stats.Critical++
		case finding.SeverityHigh:
			jr.Stats.High++
		case finding.SeverityMedium:
			jr.Stats.Medium++
		case finding.SeverityLow:
			jr.Stats.Low++
		}
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	if err := enc.Encode(jr); err != nil {
		return fmt.Errorf("json marshal: %w", err)
	}
	return nil
}
