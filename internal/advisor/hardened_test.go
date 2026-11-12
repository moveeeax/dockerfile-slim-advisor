package advisor

import (
	"strings"
	"testing"
)

func hardened(t *testing.T, name string) []Finding {
	t.Helper()
	return analyzeFile(t, name, Options{Profile: ProfileHardened})
}

func analyzeString(t *testing.T, body string, opt Options) []Finding {
	t.Helper()
	df, err := Parse(strings.NewReader(body), "Dockerfile")
	if err != nil {
		t.Fatal(err)
	}
	return Analyze(df, opt)
}

// The two Dockerfiles docker-hardened-base shipped passed its policy linter,
// so they must pass the hardened profile too.
func TestHardenedImagesFromDockerHardenedBaseAreClean(t *testing.T) {
	for _, name := range []string{"hardened-go.Dockerfile", "hardened-python.Dockerfile"} {
		if fs := hardened(t, name); len(fs) != 0 {
			t.Errorf("%s: expected no findings, got %v", name, ids(fs))
		}
	}
}

func TestHardenedProfileRules(t *testing.T) {
	fs := hardened(t, "hardened-bad.Dockerfile")
	assertIDs(t, fs, "DHB001", "DHB002", "DHB003", "DHB004", "DHB005", "DHB006", "DHB006", "DHB007")

	for _, f := range fs {
		if f.Severity != High {
			t.Errorf("%s severity = %s, want high so the default gate blocks", f.ID, f.Severity)
		}
	}
	if f := find(t, fs, "DHB005"); f.Line != 14 || f.Instruction != "USER" {
		t.Errorf("DHB005 = line %d %s, want line 14 USER", f.Line, f.Instruction)
	}
	if f := find(t, fs, "DHB007"); !strings.Contains(f.Title, "licenses") || strings.Contains(f.Title, "source") {
		t.Errorf("DHB007 should name only the missing licenses label, got %q", f.Title)
	}
	var ports []string
	for _, f := range fs {
		if f.ID == "DHB006" {
			ports = append(ports, f.Title)
		}
	}
	if len(ports) != 2 || !strings.Contains(ports[0], "80") || !strings.Contains(ports[1], "443/tcp") {
		t.Errorf("DHB006 titles = %v, want ports 80 and 443/tcp", ports)
	}
}

// DHB005 and DHB002 are stricter versions of DSA006 and DSA007, so the same
// problem must not be reported twice on the same line.
func TestHardenedProfileReplacesOverlappingDefaults(t *testing.T) {
	body := "FROM alpine\nCOPY app /app\n"
	assertIDs(t, analyzeString(t, body, Options{}), "DSA006", "DSA007")
	assertIDs(t, analyzeString(t, body, Options{Profile: ProfileHardened}), "DHB001", "DHB002", "DHB005", "DHB007")

	// DSA007 on an earlier stage has no DHB counterpart and stays.
	fs := analyzeString(t, "FROM golang AS build\nRUN go build\nFROM scratch\nCOPY --from=build /app /app\nUSER 65532\n"+
		"LABEL org.opencontainers.image.source=x org.opencontainers.image.licenses=MIT\n", Options{Profile: ProfileHardened})
	assertIDs(t, fs, "DSA007")
}

func TestHardenedBaseExemptions(t *testing.T) {
	labels := "LABEL org.opencontainers.image.source=x org.opencontainers.image.licenses=MIT\nUSER 65532\n"
	cases := map[string][]string{
		// A final FROM naming an earlier stage is not a registry image.
		"FROM alpine:3.20@sha256:" + strings.Repeat("a", 64) + " AS base\nFROM base\n" + labels: nil,
		"FROM scratch\n" + labels: nil,
		// A variable base cannot prove a digest pin, but its tag is unknown.
		"ARG BASE=alpine\nFROM ${BASE}\n" + labels: {"DHB001"},
		"FROM alpine:3.20\n" + labels:              {"DHB001"},
		"FROM alpine\n" + labels:                   {"DHB001", "DHB002"},
	}
	for body, want := range cases {
		fs := analyzeString(t, body, Options{Profile: ProfileHardened})
		if strings.Join(ids(fs), ",") != strings.Join(want, ",") {
			t.Errorf("%q: findings = %v, want %v", body, ids(fs), want)
		}
	}
}

func TestDefaultProfileHasNoHardenedRules(t *testing.T) {
	for _, f := range analyzeFile(t, "hardened-bad.Dockerfile", Options{}) {
		if strings.HasPrefix(f.ID, "DHB") {
			t.Errorf("default profile reported %s", f.ID)
		}
	}
}

func TestIsRootUser(t *testing.T) {
	for _, u := range []string{"root", "0", "0:0", "root:root", "000"} {
		if !isRootUser(u) {
			t.Errorf("isRootUser(%q) = false", u)
		}
	}
	for _, u := range []string{"65532", "65532:65532", "nonroot", "10", "rooty"} {
		if isRootUser(u) {
			t.Errorf("isRootUser(%q) = true", u)
		}
	}
}

func TestParseProfile(t *testing.T) {
	for in, want := range map[string]Profile{"": ProfileDefault, "default": ProfileDefault, " Hardened ": ProfileHardened} {
		if got, err := ParseProfile(in); err != nil || got != want {
			t.Errorf("ParseProfile(%q) = %q, %v", in, got, err)
		}
	}
	if _, err := ParseProfile("strict"); err == nil {
		t.Error("ParseProfile(strict) should fail")
	}
}
