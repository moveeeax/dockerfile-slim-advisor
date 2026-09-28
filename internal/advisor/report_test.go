package advisor

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func sample() Report {
	return NewReport("Dockerfile", []Finding{
		{ID: "DSA001", Severity: High, SeverityStr: "high", Line: 3, Instruction: "COPY",
			Title:  "COPY of the whole context precedes `go mod download` on line 4",
			Detail: "Editing any file changes this layer.", Fix: "copy the manifests first"},
		{ID: "DSA006", Severity: Medium, SeverityStr: "medium", Line: 1, Instruction: "FROM",
			Title: "image runs as root", Detail: "No USER instruction.", Fix: "add a non-root USER"},
	})
}

func TestSummaryCounts(t *testing.T) {
	s := sample().Summary
	if s.High != 1 || s.Medium != 1 || s.Low != 0 || s.Total != 2 {
		t.Fatalf("summary = %+v", s)
	}
}

func TestWriteText(t *testing.T) {
	var buf bytes.Buffer
	if err := sample().WriteText(&buf); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	for _, want := range []string{"Dockerfile", "HIGH", "DSA001", "line 3", "fix: copy the manifests first",
		"2 findings: 1 high, 1 medium, 0 low"} {
		if !strings.Contains(out, want) {
			t.Errorf("text output missing %q:\n%s", want, out)
		}
	}
	for _, line := range strings.Split(out, "\n") {
		if len(line) > 100 {
			t.Errorf("line longer than 100 columns: %q", line)
		}
	}
}

func TestWriteTextNoFindings(t *testing.T) {
	var buf bytes.Buffer
	if err := NewReport("Dockerfile", nil).WriteText(&buf); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "no findings") {
		t.Errorf("want a clean-run message, got %q", buf.String())
	}
}

func TestWriteJSON(t *testing.T) {
	var buf bytes.Buffer
	if err := sample().WriteJSON(&buf); err != nil {
		t.Fatal(err)
	}
	var got struct {
		Path    string `json:"path"`
		Summary struct {
			High, Medium, Low, Total int
		} `json:"summary"`
		Findings []struct {
			ID       string `json:"id"`
			Severity string `json:"severity"`
			Line     int    `json:"line"`
			Fix      string `json:"fix"`
		} `json:"findings"`
	}
	if err := json.Unmarshal(buf.Bytes(), &got); err != nil {
		t.Fatalf("output is not valid JSON: %v\n%s", err, buf.String())
	}
	if got.Path != "Dockerfile" || got.Summary.Total != 2 || len(got.Findings) != 2 {
		t.Fatalf("decoded = %+v", got)
	}
	if got.Findings[0].Severity != "high" || got.Findings[0].ID != "DSA001" {
		t.Errorf("first finding = %+v", got.Findings[0])
	}
	if strings.Contains(buf.String(), `"Severity"`) {
		t.Error("the numeric Severity field leaked into JSON")
	}
}

func TestJSONFindingsIsAlwaysAnArray(t *testing.T) {
	var buf bytes.Buffer
	if err := NewReport("Dockerfile", nil).WriteJSON(&buf); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), `"findings": []`) {
		t.Errorf("want an empty array, got %s", buf.String())
	}
}

func TestWrap(t *testing.T) {
	lines := wrap("one two three four five", 9)
	want := []string{"one two", "three", "four five"}
	if len(lines) != len(want) {
		t.Fatalf("wrap = %q", lines)
	}
	for i := range want {
		if lines[i] != want[i] {
			t.Fatalf("wrap = %q, want %q", lines, want)
		}
	}
	if wrap("   ", 10) != nil {
		t.Error("wrap of blank text should be nil")
	}
}
