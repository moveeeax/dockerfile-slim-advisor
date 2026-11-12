package advisor

import (
	"fmt"
	"sort"
	"strings"
)

// Profile selects an extra rule set on top of the default rules.
type Profile string

const (
	// ProfileDefault runs the size, cache and image-user rules.
	ProfileDefault Profile = "default"
	// ProfileHardened adds the DHB policy for a hardened runtime stage and,
	// in image mode, fails any shell or package manager in the image.
	ProfileHardened Profile = "hardened"
)

// ParseProfile turns "default"/"hardened" into a Profile.
func ParseProfile(s string) (Profile, error) {
	switch p := Profile(strings.ToLower(strings.TrimSpace(s))); p {
	case "", ProfileDefault:
		return ProfileDefault, nil
	case ProfileHardened:
		return p, nil
	}
	return "", fmt.Errorf("unknown profile %q (want default or hardened)", s)
}

// rules is the catalog of every rule id with a one-line summary. It backs
// the SARIF rule table and the validation of ignore lists, so a typo in
// .slim-advisor.yaml is an error instead of a silent no-op.
var rules = map[string]string{
	"DSA001": "whole-context COPY/ADD before a dependency install in the same stage",
	"DSA002": "the final stage is built on a compiler/SDK image",
	"DSA003": "apt-get install without removing /var/lib/apt/lists in the same RUN",
	"DSA004": "apt-get install without --no-install-recommends",
	"DSA005": "apt-get update in a layer of its own, paired with a later install",
	"DSA006": "the final stage has no non-root USER",
	"DSA007": "base image on :latest or no tag at all",
	"DSA008": "pip install without --no-cache-dir",
	"DSA009": "ADD where COPY is meant",
	"DSA010": "the whole context is copied and there is no .dockerignore beside the Dockerfile",

	"DHB001": "final base image is not pinned by @sha256 digest",
	"DHB002": "final base image uses a mutable or :latest tag",
	"DHB003": "RUN in the final stage, which needs a shell in the runtime image",
	"DHB004": "package manager invoked in the final stage",
	"DHB005": "final stage runs as root",
	"DHB006": "EXPOSE of a privileged port (below 1024) that a non-root process cannot bind",
	"DHB007": "final stage lacks the OCI source or licenses label",

	"DSI001": "image config sets no user, so the container runs as root",
	"DSI002": "image runs as uid 0",
	"DSI003": "image user or group is not defined in /etc/passwd or /etc/group",
	"DSI004": "image advertises distroless but ships a shell or package manager",
	"DSI005": "image ships a shell (hardened profile)",
	"DSI006": "image ships a package manager (hardened profile)",
	"DSI007": "entrypoint or its interpreter is missing from the image",
}

// KnownRule reports whether id names a rule.
func KnownRule(id string) bool {
	_, ok := rules[strings.ToUpper(id)]
	return ok
}

// RuleIDs returns every rule id in sorted order.
func RuleIDs() []string {
	out := make([]string, 0, len(rules))
	for id := range rules {
		out = append(out, id)
	}
	sort.Strings(out)
	return out
}

// RuleSummary returns the one-line summary of a rule, or "" when unknown.
func RuleSummary(id string) string { return rules[strings.ToUpper(id)] }
