package advisor

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func parseFixture(t *testing.T, name string) *Dockerfile {
	t.Helper()
	f, err := os.Open(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	df, err := Parse(f, name)
	if err != nil {
		t.Fatal(err)
	}
	return df
}

func TestInlineSuppression(t *testing.T) {
	df := parseFixture(t, "suppress.Dockerfile")
	kept, suppressed := Suppress(df, nil, Analyze(df, Options{}))

	assertIDs(t, kept, "DSA009")
	if kept[0].Line != 12 {
		t.Errorf("kept DSA009 line = %d, want 12 (the ADD with no comment)", kept[0].Line)
	}
	assertIDs(t, suppressed, "DSA002", "DSA006", "DSA009", "DSA009")

	reasons := map[string]string{}
	for _, f := range suppressed {
		if f.Suppression == nil || f.Suppression.Source != "inline" {
			t.Fatalf("%s: suppression = %+v", f.ID, f.Suppression)
		}
		reasons[fmt.Sprintf("%s@%d", f.ID, f.Line)] = f.Suppression.Reason
	}
	if reasons["DSA002@3"] != "runs go generate at start" {
		t.Errorf("quoted reason not kept: %q", reasons["DSA002@3"])
	}
	if reasons["DSA009@9"] != "" {
		t.Errorf("a directive without a reason should have none, got %q", reasons["DSA009@9"])
	}
	if reasons["DSA009@11"] != "lowercase-ids-work" {
		t.Errorf("unquoted reason not kept: %v", reasons)
	}
}

// A directive only covers the instruction it sits above.
func TestInlineSuppressionScope(t *testing.T) {
	body := "FROM alpine:3.20\n# slim-advisor ignore=DSA009\nCOPY a /a\nADD b /b\n"
	df, err := Parse(strings.NewReader(body), "-")
	if err != nil {
		t.Fatal(err)
	}
	kept, suppressed := Suppress(df, nil, Analyze(df, Options{}))
	if len(suppressed) != 0 {
		t.Errorf("suppressed %v, want nothing: the comment is above the COPY", ids(suppressed))
	}
	find(t, kept, "DSA009")
}

func writeConfig(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), ".slim-advisor.yaml")
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestConfigSuppression(t *testing.T) {
	cfg, err := LoadConfig(writeConfig(t, "ignore:\n  - dsa006\n  - id: DSA002\n    reason: builder image on purpose\n"))
	if err != nil {
		t.Fatal(err)
	}
	df := parseFixture(t, "bad-go.Dockerfile")
	kept, suppressed := Suppress(df, cfg, Analyze(df, Options{}))
	assertIDs(t, kept, "DSA001")
	assertIDs(t, suppressed, "DSA002", "DSA006")
	if s := find(t, suppressed, "DSA002").Suppression; s.Source != cfg.Path || s.Reason != "builder image on purpose" {
		t.Errorf("DSA002 suppression = %+v", s)
	}
}

func TestConfigErrors(t *testing.T) {
	for body, want := range map[string]string{
		"ignore: [DSA999]\n":   "unknown rule",
		"ignores: [DSA001]\n":  "not found",
		"ignore: DSA001\n":     "cannot unmarshal",
		"ignore: [{idd: x}]\n": "not found",
	} {
		if _, err := LoadConfig(writeConfig(t, body)); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%q: err = %v, want %q", body, err, want)
		}
	}
	if cfg, err := LoadConfig(writeConfig(t, "")); err != nil || len(cfg.Ignore) != 0 {
		t.Errorf("an empty config should load: %+v, %v", cfg, err)
	}
	if _, err := LoadConfig(filepath.Join(t.TempDir(), "missing.yaml")); err == nil {
		t.Error("a missing --config file should be an error")
	}
}

func TestFindConfig(t *testing.T) {
	a, b := t.TempDir(), t.TempDir()
	if got := FindConfig(a, b); got != "" {
		t.Errorf("FindConfig with no files = %q", got)
	}
	yml := filepath.Join(b, ".slim-advisor.yml")
	if err := os.WriteFile(yml, []byte("ignore: []\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if got := FindConfig(a, b); got != yml {
		t.Errorf("FindConfig = %q, want %q", got, yml)
	}
	yaml := filepath.Join(a, ".slim-advisor.yaml")
	if err := os.WriteFile(yaml, []byte("ignore: []\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if got := FindConfig(a, b); got != yaml {
		t.Errorf("the first directory should win: got %q", got)
	}
}

func TestEveryRuleIsInTheCatalog(t *testing.T) {
	var all []Finding
	for _, name := range []string{"bad-go.Dockerfile", "apt.Dockerfile", "add.Dockerfile", "latest.Dockerfile", "hardened-bad.Dockerfile"} {
		all = append(all, analyzeFile(t, name, Options{CheckDockerignore: true, Profile: ProfileHardened})...)
	}
	for _, f := range all {
		if !KnownRule(f.ID) {
			t.Errorf("%s is missing from the rule catalog", f.ID)
		}
	}
	if len(RuleIDs()) != 24 {
		t.Errorf("catalog has %d rules", len(RuleIDs()))
	}
}
