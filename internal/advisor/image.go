package advisor

import "strings"

// imageRef is a Dockerfile image reference split into its parts.
type imageRef struct {
	Repo   string // registry path without tag or digest, e.g. "mcr.microsoft.com/dotnet/sdk"
	Tag    string // "" when the reference carries no tag
	Digest string // "" when the reference is not pinned by digest
}

// splitRef splits "golang:1.22-alpine" or "repo@sha256:..." into its parts.
func splitRef(ref string) imageRef {
	out := imageRef{Repo: ref}
	if i := strings.Index(out.Repo, "@"); i >= 0 {
		out.Digest = out.Repo[i+1:]
		out.Repo = out.Repo[:i]
	}
	// A colon is only a tag separator when it comes after the last slash,
	// otherwise it is a registry port (localhost:5000/app).
	if i := strings.LastIndex(out.Repo, ":"); i >= 0 && !strings.Contains(out.Repo[i+1:], "/") {
		out.Tag = out.Repo[i+1:]
		out.Repo = out.Repo[:i]
	}
	return out
}

// toolchainImages are base images that ship a full compiler or build system.
// Shipping one as the final image is the classic reason a 20 MB binary ends
// up in a 1 GB image.
var toolchainImages = map[string]string{
	"golang":           "the Go toolchain",
	"rust":             "the Rust toolchain",
	"maven":            "Maven and a full JDK",
	"gradle":           "Gradle and a full JDK",
	"openjdk":          "a full JDK",
	"eclipse-temurin":  "a full JDK",
	"amazoncorretto":   "a full JDK",
	"dotnet/sdk":       "the .NET SDK",
	"swift":            "the Swift toolchain",
	"haskell":          "GHC and cabal",
	"gcc":              "the GCC toolchain",
	"buildpack-deps":   "a full build-dependency set",
	"crystallang/crys": "the Crystal toolchain",
}

// toolchain returns a description of the toolchain a base image carries, and
// whether it carries one at all. JDK-only runtime variants are excluded by
// looking at the tag: eclipse-temurin:21-jre is a runtime, not a toolchain.
func toolchain(ref string) (string, bool) {
	if strings.Contains(ref, "$") { // variable base image, cannot judge
		return "", false
	}
	r := splitRef(ref)
	repo := strings.ToLower(r.Repo)
	tag := strings.ToLower(r.Tag)
	if strings.Contains(tag, "jre") || strings.Contains(tag, "runtime") {
		return "", false
	}
	for key, what := range toolchainImages {
		if repo == key || strings.HasSuffix(repo, "/"+key) {
			return what, true
		}
	}
	return "", false
}
