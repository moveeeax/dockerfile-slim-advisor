package advisor

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// The hardened profile is the DHB001-DHB007 policy carried over from
// moveeeax/docker-hardened-base. It checks the final stage against the
// promises a hardened runtime image makes: a digest-pinned base, no shell or
// package manager surface, no root, and enough OCI metadata to trace where
// the image came from. Every DHB finding is High so the default --fail-on
// gate blocks on it, which is how the original linter behaved (it exited
// non-zero on any violation).

var (
	pkgManagerRe = regexp.MustCompile(`(^|[\s;&|/(])(apt-get|apt|apk|yum|dnf|microdnf|tdnf|zypper|dpkg|rpm)(\s|$)`)
	portRe       = regexp.MustCompile(`^(\d+)(-\d+)?(/\w+)?$`)
)

// requiredLabels are the OCI annotations DHB007 asks for, from the OCI image
// spec's pre-defined annotation keys.
var requiredLabels = []string{"org.opencontainers.image.source", "org.opencontainers.image.licenses"}

func checkHardened(df *Dockerfile) []Finding {
	final := df.FinalStage()
	if final == nil {
		return nil
	}
	var out []Finding
	out = append(out, checkHardenedBase(df, final)...)

	var lastUser *Instruction
	labels := map[string]bool{}
	for i := range final.Instructions {
		in := &final.Instructions[i]
		switch in.Cmd {
		case "USER":
			lastUser = in
		case "LABEL":
			// buildkit keeps LABEL as key, value, separator triples.
			for j := 0; j < len(in.Args); j += 3 {
				labels[strings.Trim(in.Args[j], `"'`)] = true
			}
		case "EXPOSE":
			out = append(out, checkPrivilegedPorts(*in)...)
		case "RUN":
			out = append(out, Finding{
				ID:          "DHB003",
				Severity:    High,
				Line:        in.Line,
				Instruction: "RUN",
				Title:       "RUN in the final stage needs a shell in the runtime image",
				Detail: "A distroless runtime has no /bin/sh, so a RUN here either fails the build " +
					"or proves the base still ships a shell, which is attack surface the hardened " +
					"image is supposed to remove.",
				Fix: "do the work in a build stage and `COPY --from=` the result into the final stage",
			})
			if pkgManagerRe.MatchString(runText(*in)) {
				out = append(out, Finding{
					ID:          "DHB004",
					Severity:    High,
					Line:        in.Line,
					Instruction: "RUN",
					Title:       "package manager invoked in the final stage",
					Detail: "The runtime image carries a package manager and its database, so " +
						"anyone with a shell in the container can install tools into it.",
					Fix: "install packages in a build stage or pick a base that already has them",
				})
			}
		}
	}

	switch {
	case lastUser == nil:
		out = append(out, Finding{
			ID:          "DHB005",
			Severity:    High,
			Line:        final.Line,
			Instruction: "FROM",
			Title:       "final stage never sets USER",
			Detail: "Without a USER instruction the process runs as uid 0, and a Kubernetes pod " +
				"with runAsNonRoot refuses to start it.",
			Fix: "add a numeric non-root `USER 65532:65532` before the entrypoint",
		})
	case isRootUser(lastUser.ArgText()):
		out = append(out, Finding{
			ID:          "DHB005",
			Severity:    High,
			Line:        lastUser.Line,
			Instruction: "USER",
			Title:       fmt.Sprintf("final stage runs as root (USER %s)", lastUser.ArgText()),
			Detail:      "The last USER in the shipped stage is root, which undoes a nonroot base image.",
			Fix:         "switch to a numeric non-root user after the steps that need privileges",
		})
	}

	var missing []string
	for _, key := range requiredLabels {
		if !labels[key] {
			missing = append(missing, key)
		}
	}
	if len(missing) > 0 {
		out = append(out, Finding{
			ID:          "DHB007",
			Severity:    High,
			Line:        final.Line,
			Instruction: "FROM",
			Title:       "missing OCI label " + strings.Join(missing, " and "),
			Detail: "Without the source and licenses labels a scanner or an auditor cannot trace " +
				"the image back to its repository and terms.",
			Fix: "add `LABEL " + strings.Join(missing, "=... ") + "=...` to the final stage",
		})
	}
	return out
}

// checkHardenedBase covers DHB001 and DHB002, the supply-chain rules on the
// final FROM. A final stage built from an earlier stage, and scratch, have no
// registry image to pin.
func checkHardenedBase(df *Dockerfile, final *Stage) []Finding {
	img := final.BaseImage
	if img == "" || img == "scratch" || df.stageNames(final.Index)[strings.ToLower(img)] {
		return nil
	}
	r := splitRef(img)
	if r.Digest != "" {
		return nil
	}
	out := []Finding{{
		ID:          "DHB001",
		Severity:    High,
		Line:        final.Line,
		Instruction: "FROM",
		Title:       fmt.Sprintf("final base %s is not pinned by digest", img),
		Detail: "A tag can be repointed by whoever controls the registry, so the runtime layer " +
			"of two builds of the same commit can differ without any change in the repository.",
		Fix: fmt.Sprintf("pin the digest: `FROM %s@sha256:...`", img),
	}}
	// A variable base cannot be judged for its tag; DHB001 still applies,
	// because nothing in the file guarantees a digest.
	if strings.Contains(img, "$") {
		return out
	}
	if r.Tag == "" || r.Tag == "latest" {
		out = append(out, Finding{
			ID:          "DHB002",
			Severity:    High,
			Line:        final.Line,
			Instruction: "FROM",
			Title:       fmt.Sprintf("final base %s uses a mutable tag", img),
			Detail:      "The runtime base moves every time upstream pushes, with no review of what changed.",
			Fix:         fmt.Sprintf("pin a version and a digest: `FROM %s:<version>@sha256:...`", r.Repo),
		})
	}
	return out
}

func checkPrivilegedPorts(in Instruction) []Finding {
	var out []Finding
	for _, tok := range in.Args {
		m := portRe.FindStringSubmatch(tok)
		if m == nil {
			continue // a variable or something buildkit will reject anyway
		}
		port, err := strconv.Atoi(m[1])
		if err != nil || port >= 1024 {
			continue
		}
		out = append(out, Finding{
			ID:          "DHB006",
			Severity:    High,
			Line:        in.Line,
			Instruction: "EXPOSE",
			Title:       fmt.Sprintf("EXPOSE %s is a privileged port", tok),
			Detail: "A non-root process cannot bind a port below 1024 without CAP_NET_BIND_SERVICE, " +
				"so either the image runs as root or the service fails to start.",
			Fix: "listen on a port above 1024 (8080, 8443) and map it at the service or ingress",
		})
	}
	return out
}

// isRootUser reports whether a USER value means uid 0: `root`, `0`, or
// either with a group.
func isRootUser(v string) bool {
	u, _, _ := strings.Cut(strings.TrimSpace(v), ":")
	if u == "root" {
		return true
	}
	n, err := strconv.Atoi(u)
	return err == nil && n == 0
}
