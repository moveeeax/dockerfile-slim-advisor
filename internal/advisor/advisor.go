package advisor

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
)

// Severity ranks a finding. Rules that cost you a rebuild on every source
// edit, or a few hundred megabytes in the final image, are High.
type Severity int

const (
	Low Severity = iota + 1
	Medium
	High
)

func (s Severity) String() string {
	switch s {
	case High:
		return "high"
	case Medium:
		return "medium"
	case Low:
		return "low"
	}
	return "unknown"
}

// ParseSeverity turns "high"/"medium"/"low" into a Severity.
func ParseSeverity(s string) (Severity, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "high":
		return High, nil
	case "medium":
		return Medium, nil
	case "low":
		return Low, nil
	}
	return 0, fmt.Errorf("unknown severity %q (want high, medium or low)", s)
}

// Finding is one reported anti-pattern.
type Finding struct {
	ID          string   `json:"id"`
	Severity    Severity `json:"-"`
	SeverityStr string   `json:"severity"`
	Line        int      `json:"line"`
	Instruction string   `json:"instruction"`
	Title       string   `json:"title"`
	Detail      string   `json:"detail"`
	Fix         string   `json:"fix"`
}

// Options controls checks that need context beyond the Dockerfile text.
type Options struct {
	// CheckDockerignore enables the .dockerignore rule. It is off when the
	// Dockerfile is read from stdin, where there is no directory to look in.
	CheckDockerignore bool
	HasDockerignore   bool
}

// Analyze runs every rule over a parsed Dockerfile and returns the findings
// ranked by severity, then by line.
func Analyze(df *Dockerfile, opt Options) []Finding {
	var out []Finding
	for i := range df.Stages {
		out = append(out, checkStage(df, &df.Stages[i])...)
	}
	out = append(out, checkFinalStage(df)...)
	out = append(out, checkDockerignore(df, opt)...)

	sort.SliceStable(out, func(a, b int) bool {
		if out[a].Severity != out[b].Severity {
			return out[a].Severity > out[b].Severity
		}
		return out[a].Line < out[b].Line
	})
	for i := range out {
		out[i].SeverityStr = out[i].Severity.String()
	}
	return out
}

// Worst returns the highest severity present, or 0 for no findings.
func Worst(fs []Finding) Severity {
	var w Severity
	for _, f := range fs {
		if f.Severity > w {
			w = f.Severity
		}
	}
	return w
}

var depInstall = []struct {
	re   *regexp.Regexp
	what string
}{
	{regexp.MustCompile(`\bgo\s+mod\s+(download|tidy)\b`), "go mod download"},
	{regexp.MustCompile(`\bgo\s+get\b`), "go get"},
	{regexp.MustCompile(`\bnpm\s+(ci|install|i)\b`), "npm install"},
	{regexp.MustCompile(`\byarn\s+(install|--frozen-lockfile)`), "yarn install"},
	{regexp.MustCompile(`\bpnpm\s+(install|i)\b`), "pnpm install"},
	{regexp.MustCompile(`\bpip3?\s+install\b[^&|;]*(-r|--requirement)\s`), "pip install -r"},
	{regexp.MustCompile(`\bpoetry\s+install\b`), "poetry install"},
	{regexp.MustCompile(`\bpipenv\s+install\b`), "pipenv install"},
	{regexp.MustCompile(`\bbundle\s+install\b`), "bundle install"},
	{regexp.MustCompile(`\bcomposer\s+install\b`), "composer install"},
	{regexp.MustCompile(`(mvn|\./mvnw)\b[^&|;]*dependency:go-offline`), "mvn dependency:go-offline"},
	{regexp.MustCompile(`(gradle|\./gradlew)\b[^&|;]*(dependencies|--refresh-dependencies)`), "gradle dependencies"},
	{regexp.MustCompile(`\bcargo\s+(fetch|build)\b`), "cargo fetch"},
	{regexp.MustCompile(`\bdotnet\s+restore\b`), "dotnet restore"},
}

var (
	aptInstallRe = regexp.MustCompile(`\bapt(-get)?\s+(-[^\s]+\s+)*install\b`)
	aptUpdateRe  = regexp.MustCompile(`\bapt(-get)?\s+(-[^\s]+\s+)*update\b`)
	aptCleanRe   = regexp.MustCompile(`rm\s+-[a-z]*r[a-z]*f?\s+[^&|;]*/var/lib/apt/lists`)
	pipInstallRe = regexp.MustCompile(`\bpip3?\s+install\b`)
	urlRe        = regexp.MustCompile(`^(https?|git)://`)
	spaceRe      = regexp.MustCompile(`\s+`)
)

// runText normalises a RUN body for matching: lower-cased, continuations and
// repeated whitespace collapsed to single spaces.
func runText(in Instruction) string {
	return strings.ToLower(spaceRe.ReplaceAllString(in.ArgText(), " "))
}

// wholeContextCopy reports whether a COPY/ADD pulls in the entire build
// context, which is the copy that invalidates everything below it.
func wholeContextCopy(in Instruction) bool {
	if in.Cmd != "COPY" && in.Cmd != "ADD" {
		return false
	}
	if in.HasFlag("from") { // copying out of another stage, not the context
		return false
	}
	if len(in.Args) < 2 {
		return false
	}
	for _, src := range in.Args[:len(in.Args)-1] {
		switch strings.TrimSuffix(src, "/") {
		case ".", "*", "./*":
			return true
		}
	}
	return false
}

func checkStage(df *Dockerfile, s *Stage) []Finding {
	var out []Finding
	out = append(out, checkBaseTag(df, s)...)
	out = append(out, checkCacheOrder(s)...)
	out = append(out, checkPackageManagers(s)...)
	out = append(out, checkAdd(s)...)
	return out
}

func checkBaseTag(df *Dockerfile, s *Stage) []Finding {
	img := s.BaseImage
	if img == "" || img == "scratch" || strings.Contains(img, "$") {
		return nil
	}
	if df.stageNames(s.Index)[strings.ToLower(img)] {
		return nil // FROM <earlier stage>
	}
	r := splitRef(img)
	if r.Digest != "" {
		return nil
	}
	if r.Tag != "" && r.Tag != "latest" {
		return nil
	}
	tag := r.Tag
	if tag == "" {
		tag = "(none, which means :latest)"
	}
	return []Finding{{
		ID:          "DSA007",
		Severity:    Medium,
		Line:        s.Line,
		Instruction: "FROM",
		Title:       fmt.Sprintf("base image %s has a moving tag", img),
		Detail: fmt.Sprintf("Tag %s resolves to a different image over time, so the whole "+
			"layer cache below this FROM expires without warning and two builds of the same "+
			"commit are not the same image.", tag),
		Fix: fmt.Sprintf("pin a concrete version (%s:1.2.3) or a digest (%s@sha256:...)", r.Repo, r.Repo),
	}}
}

// checkCacheOrder flags a whole-context COPY that happens before a
// dependency install in the same stage.
func checkCacheOrder(s *Stage) []Finding {
	var out []Finding
	copyIdx := -1
	for i, in := range s.Instructions {
		if wholeContextCopy(in) {
			copyIdx = i
			break
		}
	}
	if copyIdx < 0 {
		return nil
	}
	for _, in := range s.Instructions[copyIdx+1:] {
		if in.Cmd != "RUN" {
			continue
		}
		text := runText(in)
		for _, d := range depInstall {
			if !d.re.MatchString(text) {
				continue
			}
			c := s.Instructions[copyIdx]
			out = append(out, Finding{
				ID:          "DSA001",
				Severity:    High,
				Line:        c.Line,
				Instruction: c.Cmd,
				Title:       fmt.Sprintf("%s of the whole context precedes `%s` on line %d", c.Cmd, d.what, in.Line),
				Detail: "Editing any file in the repository changes this layer, so the " +
					"dependency install below it re-runs from scratch on every build, even " +
					"when the manifests did not change.",
				Fix: fmt.Sprintf("copy only the dependency manifests first, run `%s`, then %s the rest of the context",
					d.what, strings.ToLower(c.Cmd)),
			})
			return out
		}
	}
	return out
}

func checkPackageManagers(s *Stage) []Finding {
	var out []Finding
	var updateOnly []Instruction
	installSeen := false

	for _, in := range s.Instructions {
		if in.Cmd != "RUN" {
			continue
		}
		text := runText(in)
		hasInstall := aptInstallRe.MatchString(text)
		hasUpdate := aptUpdateRe.MatchString(text)

		if hasUpdate && !hasInstall {
			updateOnly = append(updateOnly, in)
		}
		if hasInstall {
			installSeen = true
			if !aptCleanRe.MatchString(text) {
				out = append(out, Finding{
					ID:          "DSA003",
					Severity:    Medium,
					Line:        in.Line,
					Instruction: "RUN",
					Title:       "apt package lists are left in the layer",
					Detail: "The indexes under /var/lib/apt/lists are tens of megabytes and are " +
						"useless at runtime. Deleting them in a later layer does not help: the " +
						"bytes stay in this one.",
					Fix: "end the same RUN with `&& rm -rf /var/lib/apt/lists/*`",
				})
			}
			if !strings.Contains(text, "--no-install-recommends") {
				out = append(out, Finding{
					ID:          "DSA004",
					Severity:    Low,
					Line:        in.Line,
					Instruction: "RUN",
					Title:       "apt-get install pulls recommended packages",
					Detail: "Recommends drag in documentation, editors and whole interpreter " +
						"runtimes that nothing in the image asks for.",
					Fix: "add `--no-install-recommends` to the apt-get install call",
				})
			}
		}
		if pipInstallRe.MatchString(text) && !strings.Contains(text, "--no-cache-dir") {
			out = append(out, Finding{
				ID:          "DSA008",
				Severity:    Low,
				Line:        in.Line,
				Instruction: "RUN",
				Title:       "pip keeps its wheel cache in the image",
				Detail: "pip writes downloaded wheels to ~/.cache/pip, which ends up baked into " +
					"the layer and is never read again.",
				Fix: "add `--no-cache-dir` to the pip install call",
			})
		}
	}

	if installSeen {
		for _, in := range updateOnly {
			out = append(out, Finding{
				ID:          "DSA005",
				Severity:    High,
				Line:        in.Line,
				Instruction: "RUN",
				Title:       "apt-get update runs in its own layer",
				Detail: "A cached update layer is paired with a fresh install layer, so the " +
					"install resolves against a stale index and fails with 404s the day a " +
					"package version is superseded.",
				Fix: "put update and install in one RUN: `apt-get update && apt-get install -y --no-install-recommends ... && rm -rf /var/lib/apt/lists/*`",
			})
		}
	}
	return out
}

func checkAdd(s *Stage) []Finding {
	var out []Finding
	for _, in := range s.Instructions {
		if in.Cmd != "ADD" || in.HasFlag("from") || in.HasFlag("checksum") || in.HasFlag("git") {
			continue
		}
		if len(in.Args) < 2 {
			continue
		}
		local := false
		for _, src := range in.Args[:len(in.Args)-1] {
			if urlRe.MatchString(src) || isArchive(src) {
				continue
			}
			local = true
		}
		if !local {
			continue
		}
		out = append(out, Finding{
			ID:          "DSA009",
			Severity:    Low,
			Line:        in.Line,
			Instruction: "ADD",
			Title:       "ADD used where COPY would do",
			Detail: "ADD also fetches URLs and auto-extracts archives, so a source that later " +
				"becomes a .tar.gz silently changes behaviour. COPY has one job.",
			Fix: "use `COPY` for plain files and directories",
		})
	}
	return out
}

func isArchive(name string) bool {
	for _, ext := range []string{".tar", ".tar.gz", ".tgz", ".tar.bz2", ".tbz2", ".tar.xz", ".txz", ".zip", ".gz", ".bz2", ".xz"} {
		if strings.HasSuffix(strings.ToLower(name), ext) {
			return true
		}
	}
	return false
}

// checkFinalStage covers the two rules that only matter for the image that
// actually ships: the toolchain it carries and the user it runs as.
func checkFinalStage(df *Dockerfile) []Finding {
	final := df.FinalStage()
	if final == nil {
		return nil
	}
	var out []Finding

	if what, ok := toolchain(final.BaseImage); ok {
		detail := fmt.Sprintf("The shipped image is built from %s, so it carries %s, its "+
			"package cache and the full source tree into production.", final.BaseImage, what)
		fix := "build in a first stage, then `FROM` a slim runtime or `scratch` and `COPY --from=build` only the artifact"
		if len(df.Stages) > 1 {
			detail += " The file already has earlier stages, so only the last FROM needs changing."
		}
		out = append(out, Finding{
			ID:          "DSA002",
			Severity:    High,
			Line:        final.Line,
			Instruction: "FROM",
			Title:       "final stage ships a build toolchain",
			Detail:      detail,
			Fix:         fix,
		})
	}

	var lastUser *Instruction
	for i := range final.Instructions {
		if final.Instructions[i].Cmd == "USER" {
			lastUser = &final.Instructions[i]
		}
	}
	switch {
	case lastUser == nil:
		out = append(out, Finding{
			ID:          "DSA006",
			Severity:    Medium,
			Line:        final.Line,
			Instruction: "FROM",
			Title:       "image runs as root",
			Detail: "No USER instruction in the final stage, so the container process is uid 0 " +
				"and any bind-mounted path it writes to comes back owned by root.",
			Fix: "add a non-root `USER` before the entrypoint",
		})
	case len(lastUser.Args) > 0 && (lastUser.Args[0] == "root" || strings.HasPrefix(lastUser.Args[0], "0")):
		out = append(out, Finding{
			ID:          "DSA006",
			Severity:    Medium,
			Line:        lastUser.Line,
			Instruction: "USER",
			Title:       "image explicitly runs as root",
			Detail:      "The final USER in the shipped stage is root.",
			Fix:         "switch to a non-root user after the steps that need privileges",
		})
	}
	return out
}

func checkDockerignore(df *Dockerfile, opt Options) []Finding {
	if !opt.CheckDockerignore || opt.HasDockerignore {
		return nil
	}
	for _, s := range df.Stages {
		for _, in := range s.Instructions {
			if !wholeContextCopy(in) {
				continue
			}
			return []Finding{{
				ID:          "DSA010",
				Severity:    Medium,
				Line:        in.Line,
				Instruction: in.Cmd,
				Title:       "whole context copied with no .dockerignore next to the Dockerfile",
				Detail: "Without a .dockerignore the daemon receives .git, node_modules, local " +
					"build output and any stray secret in the working tree, and all of it lands " +
					"in this layer.",
				Fix: "add a .dockerignore with at least `.git`, build output and dependency directories",
			}}
		}
	}
	return nil
}
