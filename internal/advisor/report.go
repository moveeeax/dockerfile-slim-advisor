package advisor

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
)

// Summary counts findings per severity.
type Summary struct {
	High   int `json:"high"`
	Medium int `json:"medium"`
	Low    int `json:"low"`
	Total  int `json:"total"`
}

// Report is the JSON shape written by --format json.
type Report struct {
	Path     string    `json:"path"`
	Summary  Summary   `json:"summary"`
	Findings []Finding `json:"findings"`
}

// NewReport builds a Report from findings. Findings is never nil so the JSON
// always has an array, which keeps `jq '.findings | length'` working.
func NewReport(path string, fs []Finding) Report {
	r := Report{Path: path, Findings: fs}
	if r.Findings == nil {
		r.Findings = []Finding{}
	}
	for _, f := range fs {
		switch f.Severity {
		case High:
			r.Summary.High++
		case Medium:
			r.Summary.Medium++
		case Low:
			r.Summary.Low++
		}
	}
	r.Summary.Total = len(fs)
	return r
}

// WriteJSON writes the report as indented JSON.
func (r Report) WriteJSON(w io.Writer) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(r)
}

const wrapWidth = 76

// WriteText writes the human-readable report.
func (r Report) WriteText(w io.Writer) error {
	if _, err := fmt.Fprintf(w, "%s\n\n", r.Path); err != nil {
		return err
	}
	if len(r.Findings) == 0 {
		_, err := fmt.Fprintln(w, "no findings")
		return err
	}
	for _, f := range r.Findings {
		if _, err := fmt.Fprintf(w, "%-6s %s  line %-4d %s\n",
			strings.ToUpper(f.SeverityStr), f.ID, f.Line, f.Title); err != nil {
			return err
		}
		for _, line := range wrap(f.Detail, wrapWidth) {
			if _, err := fmt.Fprintf(w, "       %s\n", line); err != nil {
				return err
			}
		}
		for i, line := range wrap("fix: "+f.Fix, wrapWidth) {
			prefix := "       "
			if i > 0 {
				prefix = "            "
			}
			if _, err := fmt.Fprintf(w, "%s%s\n", prefix, line); err != nil {
				return err
			}
		}
		if _, err := fmt.Fprintln(w); err != nil {
			return err
		}
	}
	_, err := fmt.Fprintf(w, "%s: %d high, %d medium, %d low\n",
		plural(r.Summary.Total), r.Summary.High, r.Summary.Medium, r.Summary.Low)
	return err
}

func plural(n int) string {
	if n == 1 {
		return "1 finding"
	}
	return fmt.Sprintf("%d findings", n)
}

// wrap breaks text on spaces at the given width.
func wrap(s string, width int) []string {
	words := strings.Fields(s)
	if len(words) == 0 {
		return nil
	}
	lines := []string{words[0]}
	for _, word := range words[1:] {
		last := len(lines) - 1
		if len(lines[last])+1+len(word) <= width {
			lines[last] += " " + word
			continue
		}
		lines = append(lines, word)
	}
	return lines
}
