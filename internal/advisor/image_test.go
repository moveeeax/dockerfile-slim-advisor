package advisor

import "testing"

func TestSplitRef(t *testing.T) {
	cases := []struct {
		in                string
		repo, tag, digest string
	}{
		{"golang:1.22", "golang", "1.22", ""},
		{"golang", "golang", "", ""},
		{"gcr.io/distroless/static-debian12:nonroot", "gcr.io/distroless/static-debian12", "nonroot", ""},
		{"localhost:5000/app", "localhost:5000/app", "", ""},
		{"localhost:5000/app:v2", "localhost:5000/app", "v2", ""},
		{"alpine@sha256:abc", "alpine", "", "sha256:abc"},
		{"alpine:3.20@sha256:abc", "alpine", "3.20", "sha256:abc"},
	}
	for _, c := range cases {
		got := splitRef(c.in)
		if got.Repo != c.repo || got.Tag != c.tag || got.Digest != c.digest {
			t.Errorf("splitRef(%q) = %+v, want repo=%q tag=%q digest=%q", c.in, got, c.repo, c.tag, c.digest)
		}
	}
}

func TestToolchain(t *testing.T) {
	yes := []string{"golang:1.22", "rust:1.79-slim", "maven:3.9", "mcr.microsoft.com/dotnet/sdk:8.0",
		"eclipse-temurin:21-jdk", "public.ecr.aws/docker/library/golang:1.22", "gcc"}
	for _, img := range yes {
		if _, ok := toolchain(img); !ok {
			t.Errorf("toolchain(%q) = false, want true", img)
		}
	}
	no := []string{"alpine:3.20", "debian:12-slim", "gcr.io/distroless/static-debian12:nonroot",
		"eclipse-temurin:21-jre", "mcr.microsoft.com/dotnet/runtime:8.0", "scratch",
		"golang-is-not-this/app:1.0", "${BUILDER_IMAGE}"}
	for _, img := range no {
		if what, ok := toolchain(img); ok {
			t.Errorf("toolchain(%q) = %q, want false", img, what)
		}
	}
}

func TestIsArchive(t *testing.T) {
	for _, n := range []string{"tool.tar.gz", "x.ZIP", "a/b.tgz", "bundle.tar"} {
		if !isArchive(n) {
			t.Errorf("isArchive(%q) = false", n)
		}
	}
	for _, n := range []string{"src", "main.go", "Dockerfile", "notes.gzip"} {
		if isArchive(n) {
			t.Errorf("isArchive(%q) = true", n)
		}
	}
}
