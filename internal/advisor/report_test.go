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

func suppressedSample() []Finding {
	return []Finding{
		{ID: "DSA009", Severity: Low, SeverityStr: "low", Line: 7, Instruction: "ADD",
			Title: "ADD used where COPY would do", Detail: "d", Fix: "f",
			Suppression: &Suppression{Source: "inline", Reason: "tarball on purpose"}},
		{ID: "DSA002", Severity: High, SeverityStr: "high", Line: 1, Instruction: "FROM",
			Title: "final stage ships a build toolchain", Detail: "d", Fix: "f",
			Suppression: &Suppression{Source: ".slim-advisor.yaml"}},
	}
}

func TestSuppressedAreCountedNotListed(t *testing.T) {
	r := sample()
	r.SetSuppressed(suppressedSample(), false)
	if r.Summary.Suppressed != 2 || r.Summary.Total != 2 {
		t.Fatalf("summary = %+v", r.Summary)
	}
	var buf bytes.Buffer
	if err := r.WriteText(&buf); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if !strings.Contains(out, "2 findings: 1 high, 1 medium, 0 low, 2 suppressed") {
		t.Errorf("summary line missing the suppressed count:\n%s", out)
	}
	if strings.Contains(out, "DSA009") {
		t.Errorf("suppressed findings listed without --show-suppressed:\n%s", out)
	}

	buf.Reset()
	if err := r.WriteJSON(&buf); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), `"suppressed": 2`) || strings.Contains(buf.String(), `"suppressed": [`) {
		t.Errorf("json should count but not list suppressed findings:\n%s", buf.String())
	}
}

func TestShowSuppressed(t *testing.T) {
	r := NewReport("Dockerfile", nil)
	r.SetSuppressed(suppressedSample(), true)
	var buf bytes.Buffer
	if err := r.WriteText(&buf); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	for _, want := range []string{"suppressed:", "DSA009  line 7", "by inline", "reason: tarball on purpose",
		"by .slim-advisor.yaml", "no findings (2 suppressed)"} {
		if !strings.Contains(out, want) {
			t.Errorf("text output missing %q:\n%s", want, out)
		}
	}

	buf.Reset()
	if err := r.WriteJSON(&buf); err != nil {
		t.Fatal(err)
	}
	var got struct {
		Suppressed []struct {
			ID          string `json:"id"`
			Suppression struct {
				Source string `json:"source"`
				Reason string `json:"reason"`
			} `json:"suppression"`
		} `json:"suppressed"`
	}
	if err := json.Unmarshal(buf.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if len(got.Suppressed) != 2 || got.Suppressed[0].Suppression.Reason != "tarball on purpose" {
		t.Errorf("json suppressed = %+v", got.Suppressed)
	}
}

func TestImageFindingHasNoLineColumn(t *testing.T) {
	r := NewReport("ghcr.io/acme/api:1.0", []Finding{{ID: "DSI001", Severity: High, SeverityStr: "high",
		Title: "image config sets no user", Detail: "d", Fix: "f"}})
	var buf bytes.Buffer
	if err := r.WriteText(&buf); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "HIGH   DSI001            image config sets no user") {
		t.Errorf("image finding should keep the title column aligned:\n%s", buf.String())
	}
}

func TestWriteSARIF(t *testing.T) {
	r := sample()
	r.Path = "./build/Dockerfile"
	r.SetSuppressed(suppressedSample(), false)
	var buf bytes.Buffer
	if err := r.WriteSARIF(&buf, "1.2.3"); err != nil {
		t.Fatal(err)
	}
	var log struct {
		Version string `json:"version"`
		Runs    []struct {
			Tool struct {
				Driver struct {
					Name    string `json:"name"`
					Version string `json:"version"`
					Rules   []struct {
						ID string `json:"id"`
					} `json:"rules"`
				} `json:"driver"`
			} `json:"tool"`
			Results []struct {
				RuleID    string `json:"ruleId"`
				Level     string `json:"level"`
				Locations []struct {
					PhysicalLocation struct {
						ArtifactLocation struct {
							URI string `json:"uri"`
						} `json:"artifactLocation"`
						Region *struct {
							StartLine int `json:"startLine"`
						} `json:"region"`
					} `json:"physicalLocation"`
				} `json:"locations"`
				Suppressions []struct {
					Kind          string `json:"kind"`
					Justification string `json:"justification"`
				} `json:"suppressions"`
			} `json:"results"`
		} `json:"runs"`
	}
	if err := json.Unmarshal(buf.Bytes(), &log); err != nil {
		t.Fatalf("invalid SARIF JSON: %v", err)
	}
	if log.Version != "2.1.0" || len(log.Runs) != 1 {
		t.Fatalf("log = %+v", log)
	}
	run := log.Runs[0]
	if run.Tool.Driver.Name != "dockerfile-slim-advisor" || run.Tool.Driver.Version != "1.2.3" || len(run.Tool.Driver.Rules) != len(RuleIDs()) {
		t.Errorf("driver = %+v", run.Tool.Driver)
	}
	if len(run.Results) != 4 {
		t.Fatalf("results = %d, want 2 open + 2 suppressed", len(run.Results))
	}
	first := run.Results[0]
	if first.RuleID != "DSA001" || first.Level != "error" || first.Locations[0].PhysicalLocation.Region.StartLine != 3 ||
		first.Locations[0].PhysicalLocation.ArtifactLocation.URI != "build/Dockerfile" || len(first.Suppressions) != 0 {
		t.Errorf("first result = %+v", first)
	}
	if run.Results[1].Level != "warning" {
		t.Errorf("medium should map to warning, got %q", run.Results[1].Level)
	}
	inline, external := run.Results[2], run.Results[3]
	if inline.Level != "note" || len(inline.Suppressions) != 1 || inline.Suppressions[0].Kind != "inSource" ||
		inline.Suppressions[0].Justification != "tarball on purpose" {
		t.Errorf("inline suppressed result = %+v", inline)
	}
	if len(external.Suppressions) != 1 || external.Suppressions[0].Kind != "external" {
		t.Errorf("config suppressed result = %+v", external)
	}
}

func TestSARIFImageFindingHasNoRegion(t *testing.T) {
	r := NewReport("ghcr.io/acme/api:1.0", []Finding{{ID: "DSI001", Severity: High, Title: "t", Detail: "d", Fix: "f"}})
	var buf bytes.Buffer
	if err := r.WriteSARIF(&buf, "dev"); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(buf.String(), "region") || !strings.Contains(buf.String(), `"uri": "ghcr.io/acme/api:1.0"`) {
		t.Errorf("image results should carry the reference and no region:\n%s", buf.String())
	}
	if !strings.Contains(buf.String(), `"results": [`) {
		t.Error("results must be an array")
	}
}
