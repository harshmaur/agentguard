package output

import (
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"path/filepath"
	"strings"

	"github.com/harshmaur/audr/internal/finding"
)

// SARIF emits SARIF v2.1.0. We hand-roll the minimal subset that GitHub
// Code Scanning's importer accepts; pulling in a full SARIF library brings
// transitive dependencies and more attack surface than we need.
//
// Reference: https://docs.oasis-open.org/sarif/sarif/v2.1.0/os/sarif-v2.1.0-os.html
func SARIF(w io.Writer, r Report) error {
	root := sarifLog{
		Schema:  "https://json.schemastore.org/sarif-2.1.0.json",
		Version: "2.1.0",
		Runs: []sarifRun{
			{
				Tool: sarifTool{
					Driver: sarifDriver{
						Name:           "Audr",
						Version:        nonEmpty(r.Version, "0.0.0-dev"),
						InformationURI: "https://audr.dev",
						Rules:          []sarifRuleDef{},
					},
				},
				Results: []sarifResult{},
				Invocations: []sarifInvocation{
					{
						ExecutionSuccessful: true,
						EndTimeUtc:          r.FinishedAt.UTC().Format("2006-01-02T15:04:05.000Z"),
					},
				},
			},
		},
	}
	// Build rule index so we can include `rules:` once per fired rule.
	seenRule := map[string]bool{}
	if len(r.Warnings) > 0 {
		const warningRuleID = "audr-scan-incomplete"
		seenRule[warningRuleID] = true
		root.Runs[0].Tool.Driver.Rules = append(root.Runs[0].Tool.Driver.Rules, sarifRuleDef{
			ID:               warningRuleID,
			Name:             warningRuleID,
			ShortDescription: sarifText{Text: "Audr scan coverage incomplete"},
			FullDescription:  sarifText{Text: "One or more scanner backends were unavailable or failed, so this report must not be treated as complete."},
			Help:             sarifText{Text: "Run `audr doctor`, install or update the missing scanner backend, then rerun Audr. In CI, use `audr scan --ci --require-deps` to fail instead of producing a partial package-vulnerability report."},
			DefaultConfig:    sarifDefaultConfig{Level: "warning"},
			Properties:       sarifRuleProps{Tags: []string{"coverage", "scanner", "incomplete"}, Taxonomy: "advisory"},
		})
		for _, warning := range r.Warnings {
			root.Runs[0].Results = append(root.Runs[0].Results, sarifResult{
				RuleID:  warningRuleID,
				Level:   "warning",
				Message: sarifMessage{Text: warning},
				Properties: sarifResultProps{
					Taxonomy: "advisory",
				},
			})
		}
	}

	for _, f := range r.Findings {
		if !seenRule[f.RuleID] {
			seenRule[f.RuleID] = true
			root.Runs[0].Tool.Driver.Rules = append(root.Runs[0].Tool.Driver.Rules, sarifRuleDef{
				ID:               f.RuleID,
				Name:             f.RuleID,
				ShortDescription: sarifText{Text: f.Title},
				FullDescription:  sarifText{Text: f.Description},
				Help:             sarifText{Text: f.SuggestedFix},
				DefaultConfig: sarifDefaultConfig{
					Level: sarifLevel(f.Severity),
				},
				Properties: sarifRuleProps{
					Tags:     append([]string{string(f.Taxonomy)}, f.Tags...),
					Taxonomy: string(f.Taxonomy),
				},
			})
		}

		root.Runs[0].Results = append(root.Runs[0].Results, sarifResult{
			RuleID:  f.RuleID,
			Level:   sarifLevel(f.Severity),
			Message: sarifMessage{Text: f.Title + " — " + f.Description},
			Locations: []sarifLocation{
				{
					PhysicalLocation: sarifPhysical{
						ArtifactLocation: sarifArtifact{
							URI: pathToURI(f.Path),
						},
						Region: sarifRegion{
							StartLine: max1(f.Line),
						},
					},
				},
			},
			Properties: sarifResultProps{
				Taxonomy: string(f.Taxonomy),
				Match:    f.Match,
			},
		})
	}

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	if err := enc.Encode(root); err != nil {
		return fmt.Errorf("sarif marshal: %w", err)
	}
	return nil
}

// pathToURI returns a path string suitable for SARIF physicalLocation.uri.
// GitHub Code Scanning expects relative paths for in-repo findings; absolute
// paths need to be turned into file:// URIs.
func pathToURI(p string) string {
	if p == "" {
		return ""
	}
	if filepath.IsAbs(p) {
		// file URIs: percent-escape spaces, etc.
		u := url.URL{Scheme: "file", Path: p}
		return u.String()
	}
	// Relative: just escape the path components.
	return strings.ReplaceAll(p, "\\", "/")
}

func sarifLevel(s finding.Severity) string {
	switch s {
	case finding.SeverityCritical, finding.SeverityHigh:
		return "error"
	case finding.SeverityMedium:
		return "warning"
	case finding.SeverityLow:
		return "note"
	}
	return "none"
}

func nonEmpty(s, fallback string) string {
	if s == "" {
		return fallback
	}
	return s
}

func max1(n int) int {
	if n < 1 {
		return 1
	}
	return n
}

// SARIF schema types (minimal subset).

type sarifLog struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool        sarifTool         `json:"tool"`
	Results     []sarifResult     `json:"results"`
	Invocations []sarifInvocation `json:"invocations,omitempty"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name           string         `json:"name"`
	Version        string         `json:"version,omitempty"`
	InformationURI string         `json:"informationUri,omitempty"`
	Rules          []sarifRuleDef `json:"rules"`
}

type sarifRuleDef struct {
	ID               string             `json:"id"`
	Name             string             `json:"name,omitempty"`
	ShortDescription sarifText          `json:"shortDescription"`
	FullDescription  sarifText          `json:"fullDescription"`
	Help             sarifText          `json:"help,omitempty"`
	DefaultConfig    sarifDefaultConfig `json:"defaultConfiguration"`
	Properties       sarifRuleProps     `json:"properties,omitempty"`
}

type sarifText struct {
	Text string `json:"text"`
}

type sarifDefaultConfig struct {
	Level string `json:"level"`
}

type sarifRuleProps struct {
	Tags     []string `json:"tags,omitempty"`
	Taxonomy string   `json:"taxonomy,omitempty"`
}

type sarifResult struct {
	RuleID     string           `json:"ruleId"`
	Level      string           `json:"level"`
	Message    sarifMessage     `json:"message"`
	Locations  []sarifLocation  `json:"locations,omitempty"`
	Properties sarifResultProps `json:"properties,omitempty"`
}

type sarifMessage struct {
	Text string `json:"text"`
}

type sarifLocation struct {
	PhysicalLocation sarifPhysical `json:"physicalLocation"`
}

type sarifPhysical struct {
	ArtifactLocation sarifArtifact `json:"artifactLocation"`
	Region           sarifRegion   `json:"region"`
}

type sarifArtifact struct {
	URI string `json:"uri"`
}

type sarifRegion struct {
	StartLine int `json:"startLine"`
}

type sarifResultProps struct {
	Taxonomy string `json:"taxonomy,omitempty"`
	Match    string `json:"match,omitempty"`
}

type sarifInvocation struct {
	ExecutionSuccessful bool   `json:"executionSuccessful"`
	EndTimeUtc          string `json:"endTimeUtc,omitempty"`
}
