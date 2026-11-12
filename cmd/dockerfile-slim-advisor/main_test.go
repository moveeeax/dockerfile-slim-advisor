package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/random"
	"github.com/google/go-containerregistry/pkg/v1/tarball"
)

const badDockerfile = `FROM golang:1.22
WORKDIR /src
COPY . .
RUN go mod download
RUN go build -o /bin/app ./cmd/app
CMD ["/bin/app"]
`

const cleanDockerfile = `FROM golang:1.22.5-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN go build -o /out/app ./cmd/app

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/app /app
USER nonroot
ENTRYPOINT ["/app"]
`

// writeDockerfile drops a Dockerfile (and optionally a .dockerignore) into a
// temp directory and returns the file path.
func writeDockerfile(t *testing.T, body string, withIgnore bool) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "Dockerfile")
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	if withIgnore {
		if err := os.WriteFile(filepath.Join(dir, ".dockerignore"), []byte(".git\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return path
}

// call runs the CLI and returns stdout, stderr and the exit status, mapping
// errors the same way main does.
func call(t *testing.T, stdin string, args ...string) (string, string, int) {
	t.Helper()
	var out, errb bytes.Buffer
	err := run(args, strings.NewReader(stdin), &out, &errb)
	code := 0
	switch e := err.(type) {
	case nil:
	case exitCode:
		code = int(e)
	default:
		errb.WriteString(err.Error())
		code = 2
	}
	return out.String(), errb.String(), code
}

func TestFindingsExitOne(t *testing.T) {
	path := writeDockerfile(t, badDockerfile, true)
	out, _, code := call(t, "", path)
	if code != 1 {
		t.Fatalf("exit = %d, want 1\n%s", code, out)
	}
	for _, want := range []string{"DSA001", "DSA002", "HIGH"} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q:\n%s", want, out)
		}
	}
}

func TestCleanDockerfileExitsZero(t *testing.T) {
	path := writeDockerfile(t, cleanDockerfile, true)
	out, _, code := call(t, "", path)
	if code != 0 {
		t.Fatalf("exit = %d, want 0\n%s", code, out)
	}
	if !strings.Contains(out, "no findings") {
		t.Errorf("output = %q", out)
	}
}

// Only medium findings must not fail the default run, but must fail
// --fail-on medium.
func TestFailOnThreshold(t *testing.T) {
	path := writeDockerfile(t, "FROM alpine\nRUN true\n", true)

	if out, _, code := call(t, "", path); code != 0 {
		t.Fatalf("default fail-on high should pass medium findings, exit = %d\n%s", code, out)
	}
	if _, _, code := call(t, "", "--fail-on", "medium", path); code != 1 {
		t.Fatalf("fail-on medium exit = %d, want 1", code)
	}
	if _, _, code := call(t, "", "--fail-on", "never", writeDockerfile(t, badDockerfile, true)); code != 0 {
		t.Fatalf("fail-on never exit = %d, want 0", code)
	}
	if _, errOut, code := call(t, "", "--fail-on", "critical", path); code != 2 || !strings.Contains(errOut, "unknown severity") {
		t.Fatalf("bad severity should exit 2, got %d and stderr %q", code, errOut)
	}
}

func TestJSONOutput(t *testing.T) {
	path := writeDockerfile(t, badDockerfile, true)
	out, _, code := call(t, "", "--format", "json", path)
	if code != 1 {
		t.Fatalf("exit = %d, want 1", code)
	}
	var report struct {
		Path    string `json:"path"`
		Summary struct {
			High  int `json:"high"`
			Total int `json:"total"`
		} `json:"summary"`
		Findings []struct {
			ID string `json:"id"`
		} `json:"findings"`
	}
	if err := json.Unmarshal([]byte(out), &report); err != nil {
		t.Fatalf("invalid JSON: %v\n%s", err, out)
	}
	if report.Summary.High < 2 || report.Summary.Total != len(report.Findings) {
		t.Fatalf("summary = %+v", report.Summary)
	}
	if report.Path != path {
		t.Errorf("path = %q, want %q", report.Path, path)
	}
}

func TestStdin(t *testing.T) {
	out, _, code := call(t, badDockerfile, "-")
	if code != 1 {
		t.Fatalf("exit = %d, want 1\n%s", code, out)
	}
	if !strings.Contains(out, "<stdin>") {
		t.Errorf("stdin runs should be labelled, got %q", strings.SplitN(out, "\n", 2)[0])
	}
	// There is no directory to look in, so the .dockerignore rule stays quiet.
	if strings.Contains(out, "DSA010") {
		t.Error("DSA010 should not fire for stdin input")
	}
}

func TestDirectoryArgument(t *testing.T) {
	path := writeDockerfile(t, cleanDockerfile, true)
	out, _, code := call(t, "", filepath.Dir(path))
	if code != 0 {
		t.Fatalf("exit = %d, want 0\n%s", code, out)
	}
	if !strings.Contains(out, "Dockerfile") {
		t.Errorf("output should name the resolved file: %q", out)
	}
}

func TestMissingDockerignoreIsReported(t *testing.T) {
	out, _, _ := call(t, "", writeDockerfile(t, badDockerfile, false))
	if !strings.Contains(out, "DSA010") {
		t.Errorf("expected DSA010 without a .dockerignore:\n%s", out)
	}
	out, _, _ = call(t, "", writeDockerfile(t, badDockerfile, true))
	if strings.Contains(out, "DSA010") {
		t.Errorf("DSA010 fired despite a .dockerignore:\n%s", out)
	}
}

func TestVersionFlag(t *testing.T) {
	out, _, code := call(t, "", "--version")
	if code != 0 || strings.TrimSpace(out) != version {
		t.Fatalf("--version printed %q, exit %d", out, code)
	}
}

func TestUsageErrors(t *testing.T) {
	if _, errOut, code := call(t, ""); code != 2 || !strings.Contains(errOut, "path") {
		t.Errorf("no argument: exit %d, stderr %q", code, errOut)
	}
	if _, _, code := call(t, "", "a", "b"); code != 2 {
		t.Errorf("two arguments should exit 2, got %d", code)
	}
}

func TestUnknownFormatAndMissingFile(t *testing.T) {
	var out, errb bytes.Buffer
	if err := run([]string{"--format", "xml", "Dockerfile"}, strings.NewReader(""), &out, &errb); err == nil {
		t.Error("unknown format should be an error")
	}
	if err := run([]string{filepath.Join(t.TempDir(), "nope")}, strings.NewReader(""), &out, &errb); err == nil {
		t.Error("missing file should be an error")
	}
}

func TestHardenedProfile(t *testing.T) {
	path := writeDockerfile(t, cleanDockerfile, true)
	if _, _, code := call(t, "", path); code != 0 {
		t.Fatalf("default profile exit = %d, want 0", code)
	}
	out, _, code := call(t, "", "--profile", "hardened", path)
	if code != 1 || !strings.Contains(out, "DHB001") || !strings.Contains(out, "DHB007") {
		t.Fatalf("hardened profile exit = %d, want 1 with DHB001 and DHB007:\n%s", code, out)
	}
	if _, errOut, code := call(t, "", "--profile", "strict", path); code != 2 || !strings.Contains(errOut, "unknown profile") {
		t.Fatalf("bad profile: exit %d, stderr %q", code, errOut)
	}
}

func TestConfigNextToDockerfile(t *testing.T) {
	path := writeDockerfile(t, badDockerfile, true)
	cfg := filepath.Join(filepath.Dir(path), ".slim-advisor.yaml")
	if err := os.WriteFile(cfg, []byte("ignore:\n  - DSA001\n  - id: DSA002\n    reason: dev image\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	out, _, code := call(t, "", path)
	if code != 0 {
		t.Fatalf("with both high findings ignored exit = %d, want 0\n%s", code, out)
	}
	if !strings.Contains(out, "1 finding: 0 high, 1 medium, 0 low, 2 suppressed") {
		t.Errorf("summary should count the suppressed findings:\n%s", out)
	}

	out, _, _ = call(t, "", "--show-suppressed", path)
	if !strings.Contains(out, "suppressed:") || !strings.Contains(out, "reason: dev image") {
		t.Errorf("--show-suppressed should list them with the reason:\n%s", out)
	}

	// --config overrides discovery.
	empty := filepath.Join(t.TempDir(), "other.yaml")
	if err := os.WriteFile(empty, []byte("ignore: []\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, _, code := call(t, "", "--config", empty, path); code != 1 {
		t.Errorf("--config with an empty list exit = %d, want 1", code)
	}
	if _, errOut, code := call(t, "", "--config", filepath.Join(t.TempDir(), "nope.yaml"), path); code != 2 || errOut == "" {
		t.Errorf("missing --config: exit %d, stderr %q", code, errOut)
	}
}

func TestBadConfigIsAnError(t *testing.T) {
	path := writeDockerfile(t, badDockerfile, true)
	cfg := filepath.Join(filepath.Dir(path), ".slim-advisor.yaml")
	if err := os.WriteFile(cfg, []byte("ignore: [DSA01]\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, errOut, code := call(t, "", path); code != 2 || !strings.Contains(errOut, "unknown rule") {
		t.Fatalf("exit = %d, stderr %q", code, errOut)
	}
}

func TestInlineSuppressionFromCLI(t *testing.T) {
	body := "# slim-advisor ignore=DSA002 reason=\"dev image\"\n" + badDockerfile
	out, _, code := call(t, "", "--format", "json", writeDockerfile(t, body, true))
	if code != 1 {
		t.Fatalf("DSA001 is still open, exit = %d", code)
	}
	var report struct {
		Summary struct {
			Suppressed int `json:"suppressed"`
		} `json:"summary"`
	}
	if err := json.Unmarshal([]byte(out), &report); err != nil || report.Summary.Suppressed != 1 {
		t.Fatalf("summary.suppressed = %d, err %v\n%s", report.Summary.Suppressed, err, out)
	}
}

func TestSARIFFormat(t *testing.T) {
	out, _, code := call(t, "", "--format", "sarif", writeDockerfile(t, badDockerfile, true))
	if code != 1 {
		t.Fatalf("exit = %d, want 1", code)
	}
	var log struct {
		Version string `json:"version"`
		Runs    []struct {
			Results []struct {
				RuleID string `json:"ruleId"`
			} `json:"results"`
		} `json:"runs"`
	}
	if err := json.Unmarshal([]byte(out), &log); err != nil {
		t.Fatalf("invalid SARIF: %v", err)
	}
	if log.Version != "2.1.0" || len(log.Runs) != 1 || len(log.Runs[0].Results) == 0 {
		t.Fatalf("sarif = %+v", log)
	}
}

func TestImageTarball(t *testing.T) {
	img, err := random.Image(256, 1)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "image.tar")
	tag, _ := name.NewTag("example.com/app:1.0")
	if err := tarball.WriteToFile(path, tag, img); err != nil {
		t.Fatal(err)
	}
	// A random image has no user and no entrypoint.
	out, _, code := call(t, "", "--image", path)
	if code != 1 || !strings.Contains(out, "DSI001") {
		t.Fatalf("exit = %d, want 1 with DSI001:\n%s", code, out)
	}
	if !strings.HasPrefix(out, path) {
		t.Errorf("report should be labelled with the image: %q", strings.SplitN(out, "\n", 2)[0])
	}
}

func TestImageUsageErrors(t *testing.T) {
	path := writeDockerfile(t, cleanDockerfile, true)
	if _, _, code := call(t, "", "--image", "example.com/app:1.0", path); code != 2 {
		t.Errorf("--image with a Dockerfile argument should exit 2, got %d", code)
	}
	if _, errOut, code := call(t, "", "--platform", "linux/arm64", path); code != 2 || !strings.Contains(errOut, "--image") {
		t.Errorf("--platform without --image: exit %d, stderr %q", code, errOut)
	}
	if _, errOut, code := call(t, "", "--image", "Not A Ref"); code != 2 || errOut == "" {
		t.Errorf("invalid reference: exit %d, stderr %q", code, errOut)
	}
}
