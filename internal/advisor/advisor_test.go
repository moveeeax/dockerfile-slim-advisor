package advisor

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// analyzeFile parses a fixture and returns its findings.
func analyzeFile(t *testing.T, name string, opt Options) []Finding {
	t.Helper()
	f, err := os.Open(filepath.Join("testdata", name))
	if err != nil {
		t.Fatalf("open fixture: %v", err)
	}
	defer f.Close()
	df, err := Parse(f, name)
	if err != nil {
		t.Fatalf("parse %s: %v", name, err)
	}
	return Analyze(df, opt)
}

func ids(fs []Finding) []string {
	out := make([]string, 0, len(fs))
	for _, f := range fs {
		out = append(out, f.ID)
	}
	sort.Strings(out)
	return out
}

func find(t *testing.T, fs []Finding, id string) Finding {
	t.Helper()
	for _, f := range fs {
		if f.ID == id {
			return f
		}
	}
	t.Fatalf("expected finding %s, got %v", id, ids(fs))
	return Finding{}
}

func assertIDs(t *testing.T, fs []Finding, want ...string) {
	t.Helper()
	sort.Strings(want)
	got := ids(fs)
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("findings = %v, want %v", got, want)
	}
}

// The acceptance case from the spec: a single-stage Go Dockerfile that copies
// everything first must report both the cache-busting COPY and the missing
// multi-stage build.
func TestSingleStageGoDockerfile(t *testing.T) {
	fs := analyzeFile(t, "bad-go.Dockerfile", Options{})
	assertIDs(t, fs, "DSA001", "DSA002", "DSA006")

	cacheBust := find(t, fs, "DSA001")
	if cacheBust.Line != 3 {
		t.Errorf("DSA001 line = %d, want 3 (the COPY . .)", cacheBust.Line)
	}
	if cacheBust.Severity != High {
		t.Errorf("DSA001 severity = %s, want high", cacheBust.Severity)
	}
	if !strings.Contains(cacheBust.Title, "go mod download") {
		t.Errorf("DSA001 title should name the dependency step, got %q", cacheBust.Title)
	}

	toolchainFinding := find(t, fs, "DSA002")
	if toolchainFinding.Line != 1 {
		t.Errorf("DSA002 line = %d, want 1", toolchainFinding.Line)
	}
	if !strings.Contains(toolchainFinding.Detail, "Go toolchain") {
		t.Errorf("DSA002 detail should name the toolchain, got %q", toolchainFinding.Detail)
	}
}

func TestCleanMultiStageHasNoFindings(t *testing.T) {
	if fs := analyzeFile(t, "good-go.Dockerfile", Options{}); len(fs) != 0 {
		t.Fatalf("expected no findings, got %v", ids(fs))
	}
}

func TestCopyFromOtherStageIsNotCacheBusting(t *testing.T) {
	// fat-multistage copies go.mod first and only pulls the artifact out of
	// the build stage, so the only complaints are about the final image.
	fs := analyzeFile(t, "fat-multistage.Dockerfile", Options{})
	assertIDs(t, fs, "DSA002", "DSA006")
	if f := find(t, fs, "DSA002"); f.Line != 8 {
		t.Errorf("DSA002 line = %d, want 8 (the final FROM)", f.Line)
	}
	if f := find(t, fs, "DSA002"); !strings.Contains(f.Detail, "earlier stages") {
		t.Errorf("DSA002 should note the existing stages, got %q", f.Detail)
	}
}

func TestAptRules(t *testing.T) {
	fs := analyzeFile(t, "apt.Dockerfile", Options{})
	assertIDs(t, fs, "DSA003", "DSA004", "DSA005", "DSA008")

	if f := find(t, fs, "DSA005"); f.Line != 2 {
		t.Errorf("DSA005 line = %d, want 2 (the lone apt-get update)", f.Line)
	}
	if f := find(t, fs, "DSA003"); f.Line != 3 {
		t.Errorf("DSA003 line = %d, want 3", f.Line)
	}
	if f := find(t, fs, "DSA008"); f.Line != 5 {
		t.Errorf("DSA008 line = %d, want 5 (the pip install)", f.Line)
	}
}

// A single RUN that updates, installs with --no-install-recommends and drops
// the lists is the shape we are asking people to write, so it must be silent.
func TestWellFormedAptRunIsSilent(t *testing.T) {
	if fs := analyzeFile(t, "apt-clean.Dockerfile", Options{}); len(fs) != 0 {
		t.Fatalf("expected no findings, got %v", ids(fs))
	}
}

func TestAddRule(t *testing.T) {
	fs := analyzeFile(t, "add.Dockerfile", Options{})
	assertIDs(t, fs, "DSA009")
	if f := find(t, fs, "DSA009"); f.Line != 2 {
		t.Errorf("DSA009 line = %d, want 2; the URL ADD on line 3 is legitimate", f.Line)
	}
}

func TestMovingTag(t *testing.T) {
	fs := analyzeFile(t, "latest.Dockerfile", Options{})
	assertIDs(t, fs, "DSA007")
	if f := find(t, fs, "DSA007"); !strings.Contains(f.Detail, "latest") {
		t.Errorf("DSA007 detail should explain the implicit latest, got %q", f.Detail)
	}
}

func TestDockerignoreRule(t *testing.T) {
	missing := analyzeFile(t, "bad-go.Dockerfile", Options{CheckDockerignore: true})
	if f := find(t, missing, "DSA010"); f.Line != 3 {
		t.Errorf("DSA010 line = %d, want 3", f.Line)
	}

	present := analyzeFile(t, "bad-go.Dockerfile", Options{CheckDockerignore: true, HasDockerignore: true})
	for _, f := range present {
		if f.ID == "DSA010" {
			t.Fatal("DSA010 reported even though a .dockerignore exists")
		}
	}

	// good-go.Dockerfile copies the context too, but only after the manifests,
	// so the dockerignore rule still applies there.
	good := analyzeFile(t, "good-go.Dockerfile", Options{CheckDockerignore: true})
	assertIDs(t, good, "DSA010")
}

func TestFindingsAreRankedBySeverityThenLine(t *testing.T) {
	fs := analyzeFile(t, "apt.Dockerfile", Options{})
	for i := 1; i < len(fs); i++ {
		if fs[i-1].Severity < fs[i].Severity {
			t.Fatalf("findings not ranked: %s(%s) before %s(%s)",
				fs[i-1].ID, fs[i-1].Severity, fs[i].ID, fs[i].Severity)
		}
		if fs[i-1].Severity == fs[i].Severity && fs[i-1].Line > fs[i].Line {
			t.Fatalf("equal severities not ordered by line: %d before %d", fs[i-1].Line, fs[i].Line)
		}
	}
}

func TestEveryFindingIsActionable(t *testing.T) {
	for _, name := range []string{"bad-go.Dockerfile", "apt.Dockerfile", "add.Dockerfile", "latest.Dockerfile"} {
		for _, f := range analyzeFile(t, name, Options{CheckDockerignore: true}) {
			if f.Fix == "" || f.Detail == "" || f.Title == "" {
				t.Errorf("%s: %s has an empty field: %+v", name, f.ID, f)
			}
			if f.SeverityStr == "" || f.SeverityStr == "unknown" {
				t.Errorf("%s: %s has severity %q", name, f.ID, f.SeverityStr)
			}
			if f.Line <= 0 {
				t.Errorf("%s: %s has line %d", name, f.ID, f.Line)
			}
		}
	}
}

func TestWorst(t *testing.T) {
	if got := Worst(nil); got != 0 {
		t.Errorf("Worst(nil) = %v, want 0", got)
	}
	got := Worst([]Finding{{Severity: Low}, {Severity: High}, {Severity: Medium}})
	if got != High {
		t.Errorf("Worst = %v, want high", got)
	}
}

func TestParseSeverity(t *testing.T) {
	for in, want := range map[string]Severity{"high": High, " MEDIUM ": Medium, "low": Low} {
		got, err := ParseSeverity(in)
		if err != nil || got != want {
			t.Errorf("ParseSeverity(%q) = %v, %v", in, got, err)
		}
	}
	if _, err := ParseSeverity("critical"); err == nil {
		t.Error("ParseSeverity(critical) should fail")
	}
}

func TestParseRejectsGarbage(t *testing.T) {
	_, err := Parse(strings.NewReader("# just a comment\n"), "-")
	if err == nil {
		t.Fatal("expected an error for a Dockerfile with no instructions")
	}
	if !strings.Contains(err.Error(), "-") {
		t.Errorf("error should name the input: %v", err)
	}
}

func TestInstructionHelpers(t *testing.T) {
	df, err := Parse(strings.NewReader("FROM alpine:3.20\nCOPY --from=build --chown=1000:1000 /out /app\n"), "-")
	if err != nil {
		t.Fatal(err)
	}
	in := df.Stages[0].Instructions[0]
	if !in.HasFlag("from") || !in.HasFlag("chown") {
		t.Errorf("flags not parsed: %v", in.Flags)
	}
	if in.HasFlag("link") {
		t.Error("HasFlag(link) should be false")
	}
	if in.ArgText() != "/out /app" {
		t.Errorf("ArgText = %q", in.ArgText())
	}
	if !df.Stages[0].Has("COPY") || df.Stages[0].Has("USER") {
		t.Error("Stage.Has is wrong")
	}
	if df.FinalStage() != &df.Stages[len(df.Stages)-1] {
		t.Error("FinalStage should be the last stage")
	}
}

func TestPreambleArgsAreKeptOutOfStages(t *testing.T) {
	df, err := Parse(strings.NewReader("ARG GO_VERSION=1.22\nFROM golang:${GO_VERSION}\nRUN true\n"), "-")
	if err != nil {
		t.Fatal(err)
	}
	if len(df.Preamble) != 1 || df.Preamble[0].Cmd != "ARG" {
		t.Fatalf("preamble = %+v", df.Preamble)
	}
	if len(df.Stages) != 1 || len(df.Stages[0].Instructions) != 1 {
		t.Fatalf("stages = %+v", df.Stages)
	}
	// A variable base image cannot be judged, so no tag or toolchain finding.
	for _, f := range Analyze(df, Options{}) {
		if f.ID == "DSA002" || f.ID == "DSA007" {
			t.Errorf("image rules fired on a variable base image: %s", f.ID)
		}
	}
}

// Instructions before any FROM must not crash the final-stage rules.
func TestDockerfileWithoutStages(t *testing.T) {
	df := &Dockerfile{Path: "-"}
	if df.FinalStage() != nil {
		t.Error("FinalStage should be nil without a FROM")
	}
	if fs := Analyze(df, Options{CheckDockerignore: true}); len(fs) != 0 {
		t.Errorf("expected no findings, got %v", ids(fs))
	}
}
