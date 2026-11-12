package advisor

import (
	"encoding/json"
	"io"
	"path/filepath"
	"strings"
)

// SARIF 2.1.0, the subset GitHub code scanning reads:
// https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html
const (
	sarifVersion = "2.1.0"
	sarifSchema  = "https://json.schemastore.org/sarif-2.1.0.json"
	toolURI      = "https://github.com/moveeeax/dockerfile-slim-advisor"
)

type sarifLog struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool    sarifTool     `json:"tool"`
	Results []sarifResult `json:"results"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name           string      `json:"name"`
	Version        string      `json:"version,omitempty"`
	InformationURI string      `json:"informationUri"`
	Rules          []sarifRule `json:"rules"`
}

type sarifRule struct {
	ID               string       `json:"id"`
	ShortDescription sarifMessage `json:"shortDescription"`
	HelpURI          string       `json:"helpUri"`
}

type sarifMessage struct {
	Text string `json:"text"`
}

type sarifResult struct {
	RuleID       string             `json:"ruleId"`
	Level        string             `json:"level"`
	Message      sarifMessage       `json:"message"`
	Locations    []sarifLocation    `json:"locations"`
	Suppressions []sarifSuppression `json:"suppressions,omitempty"`
}

type sarifLocation struct {
	PhysicalLocation sarifPhysical `json:"physicalLocation"`
}

type sarifPhysical struct {
	ArtifactLocation sarifArtifact `json:"artifactLocation"`
	Region           *sarifRegion  `json:"region,omitempty"`
}

type sarifArtifact struct {
	URI string `json:"uri"`
}

type sarifRegion struct {
	StartLine int `json:"startLine"`
}

type sarifSuppression struct {
	Kind          string `json:"kind"`
	Justification string `json:"justification,omitempty"`
}

// WriteSARIF writes the report as a SARIF 2.1.0 log. Suppressed findings are
// always included, marked with a suppression, which is how SARIF consumers
// tell an accepted finding from an open one.
func (r Report) WriteSARIF(w io.Writer, version string) error {
	run := sarifRun{
		Tool: sarifTool{Driver: sarifDriver{
			Name:           "dockerfile-slim-advisor",
			Version:        version,
			InformationURI: toolURI,
		}},
		Results: []sarifResult{},
	}
	for _, id := range RuleIDs() {
		run.Tool.Driver.Rules = append(run.Tool.Driver.Rules, sarifRule{
			ID:               id,
			ShortDescription: sarifMessage{Text: RuleSummary(id)},
			HelpURI:          toolURI + "#rules",
		})
	}
	uri := filepath.ToSlash(strings.TrimPrefix(r.Path, "./"))
	add := func(f Finding) {
		res := sarifResult{
			RuleID:  f.ID,
			Level:   sarifLevel(f.Severity),
			Message: sarifMessage{Text: f.Title + ". " + f.Detail + " Fix: " + f.Fix},
			Locations: []sarifLocation{{PhysicalLocation: sarifPhysical{
				ArtifactLocation: sarifArtifact{URI: uri},
			}}},
		}
		if f.Line > 0 {
			res.Locations[0].PhysicalLocation.Region = &sarifRegion{StartLine: f.Line}
		}
		if s := f.Suppression; s != nil {
			kind := "external"
			if s.Source == "inline" {
				kind = "inSource"
			}
			res.Suppressions = []sarifSuppression{{Kind: kind, Justification: s.Reason}}
		}
		run.Results = append(run.Results, res)
	}
	for _, f := range r.Findings {
		add(f)
	}
	for _, f := range r.suppressed {
		add(f)
	}

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(sarifLog{Schema: sarifSchema, Version: sarifVersion, Runs: []sarifRun{run}})
}

func sarifLevel(s Severity) string {
	switch s {
	case High:
		return "error"
	case Medium:
		return "warning"
	}
	return "note"
}
