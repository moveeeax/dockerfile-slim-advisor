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
	// Suppressed counts findings accepted by an inline comment or the
	// config file. They are not part of Total.
	Suppressed int `json:"suppressed"`
}

// Report is the JSON shape written by --format json.
type Report struct {
	Path     string    `json:"path"`
	Summary  Summary   `json:"summary"`
	Findings []Finding `json:"findings"`
	// Suppressed lists the accepted findings; it is filled only when the
	// caller asks for it (--show-suppressed).
	Suppressed []Finding `json:"suppressed,omitempty"`

	suppressed []Finding // always kept, for SARIF
}

// SetSuppressed records the findings that were suppressed. They are always
// counted; list puts them in the text and JSON output as well.
func (r *Report) SetSuppressed(fs []Finding, list bool) {
	r.suppressed = fs
	r.Summary.Suppressed = len(fs)
	r.Suppressed = nil
	if list && len(fs) > 0 {
		r.Suppressed = fs
	}
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
		if err := r.writeSuppressed(w); err != nil {
			return err
		}
		msg := "no findings"
		if r.Summary.Suppressed > 0 {
			msg += fmt.Sprintf(" (%d suppressed)", r.Summary.Suppressed)
		}
		_, err := fmt.Fprintln(w, msg)
		return err
	}
	for _, f := range r.Findings {
		if _, err := fmt.Fprintf(w, "%-6s %s  %s %s\n",
			strings.ToUpper(f.SeverityStr), f.ID, location(f), f.Title); err != nil {
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
	if err := r.writeSuppressed(w); err != nil {
		return err
	}
	summary := fmt.Sprintf("%s: %d high, %d medium, %d low",
		plural(r.Summary.Total), r.Summary.High, r.Summary.Medium, r.Summary.Low)
	if r.Summary.Suppressed > 0 {
		summary += fmt.Sprintf(", %d suppressed", r.Summary.Suppressed)
	}
	_, err := fmt.Fprintln(w, summary)
	return err
}

// writeSuppressed lists suppressed findings, one line each plus where the
// suppression came from. It writes nothing unless the list was asked for.
func (r Report) writeSuppressed(w io.Writer) error {
	if len(r.Suppressed) == 0 {
		return nil
	}
	if _, err := fmt.Fprintln(w, "suppressed:"); err != nil {
		return err
	}
	for _, f := range r.Suppressed {
		if _, err := fmt.Fprintf(w, "%-6s %s  %s %s\n",
			strings.ToUpper(f.SeverityStr), f.ID, location(f), f.Title); err != nil {
			return err
		}
		if f.Suppression == nil {
			continue
		}
		note := "by " + f.Suppression.Source
		if f.Suppression.Reason != "" {
			note += ": " + f.Suppression.Reason
		}
		for _, line := range wrap(note, wrapWidth) {
			if _, err := fmt.Fprintf(w, "       %s\n", line); err != nil {
				return err
			}
		}
	}
	_, err := fmt.Fprintln(w)
	return err
}

// location is the fixed-width "line N" column. Image findings have no line,
// so the column stays blank to keep titles aligned.
func location(f Finding) string {
	if f.Line <= 0 {
		return fmt.Sprintf("%-9s", "")
	}
	return fmt.Sprintf("line %-4d", f.Line)
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
