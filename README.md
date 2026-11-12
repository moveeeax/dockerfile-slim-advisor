# dockerfile-slim-advisor

[![ci](https://github.com/moveeeax/dockerfile-slim-advisor/actions/workflows/ci.yml/badge.svg)](https://github.com/moveeeax/dockerfile-slim-advisor/actions/workflows/ci.yml)
[![Go](https://img.shields.io/badge/go-1.26%2B-00ADD8?logo=go&logoColor=white)](https://go.dev)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

A static Dockerfile analyzer for the two things that actually hurt: **image size** and **build cache**.

`hadolint` covers style and shell correctness, and it covers them well. This one only looks at
whether your image is fat and whether your layer order throws away the cache on every commit —
a `COPY . .` above the dependency install, a final stage still built on `golang:1.22`,
`apt-get update` stranded in its own layer, package indexes left in the image.

Every finding names the line, explains what it costs you, and gives the fix.

## Install

```sh
go install github.com/moveeeax/dockerfile-slim-advisor/cmd/dockerfile-slim-advisor@latest
```

## Usage

```sh
dockerfile-slim-advisor ./Dockerfile      # a file
dockerfile-slim-advisor .                 # a directory: uses ./Dockerfile
helm template . | dockerfile-slim-advisor -   # or anything on stdin
dockerfile-slim-advisor --image ghcr.io/acme/api:1.4.2   # a built image, see below
```

Real output against [`examples/bad.Dockerfile`](examples/bad.Dockerfile):

```console
$ dockerfile-slim-advisor examples/bad.Dockerfile
examples/bad.Dockerfile

HIGH   DSA002  line 2    final stage ships a build toolchain
       The shipped image is built from golang:1.22, so it carries the Go toolchain,
       its package cache and the full source tree into production.
       fix: build in a first stage, then `FROM` a slim runtime or `scratch` and
            `COPY --from=build` only the artifact

HIGH   DSA005  line 4    apt-get update runs in its own layer
       A cached update layer is paired with a fresh install layer, so the install
       resolves against a stale index and fails with 404s the day a package version
       is superseded.
       fix: put update and install in one RUN: `apt-get update && apt-get install
            -y --no-install-recommends ... && rm -rf /var/lib/apt/lists/*`

HIGH   DSA001  line 8    COPY of the whole context precedes `go mod download` on line 9
       Editing any file in the repository changes this layer, so the dependency
       install below it re-runs from scratch on every build, even when the
       manifests did not change.
       fix: copy only the dependency manifests first, run `go mod download`, then
            copy the rest of the context

7 findings: 3 high, 2 medium, 2 low
$ echo $?
1
```

[`examples/good.Dockerfile`](examples/good.Dockerfile) is the same build written properly, and
reports nothing.

### Flags

| flag | default | meaning |
| --- | --- | --- |
| `--format` | `text` | `text`, `json` or `sarif` |
| `--fail-on` | `high` | lowest severity that exits 1: `high`, `medium`, `low`, `never` |
| `--profile` | `default` | `hardened` adds the [hardened rules](#hardened-profile) |
| `--config` | | config file; without it `.slim-advisor.yaml` (or `.yml`) is looked up next to the Dockerfile, then in the current directory |
| `--show-suppressed` | | list [suppressed](#suppressions) findings in text and JSON output |
| `--image` | | check a [built image](#checking-a-built-image) instead of a Dockerfile: a registry reference or a `docker save` tarball |
| `--platform` | `linux/amd64` | with `--image`, the platform to pick from a multi-platform index, e.g. `linux/arm64` |
| `--version` | | print the version and exit |

Exit codes: `0` clean (or below the threshold), `1` findings at or above `--fail-on`, `2` a usage
or I/O error.

## Rules

| id | severity | what it catches |
| --- | --- | --- |
| DSA001 | high | whole-context `COPY`/`ADD` before a dependency install in the same stage |
| DSA002 | high | the final stage is built on a compiler/SDK image |
| DSA003 | medium | `apt-get install` without removing `/var/lib/apt/lists` in the same `RUN` |
| DSA004 | low | `apt-get install` without `--no-install-recommends` |
| DSA005 | high | `apt-get update` in a layer of its own, paired with a later install |
| DSA006 | medium | the final stage has no non-root `USER` |
| DSA007 | medium | base image on `:latest` or no tag at all |
| DSA008 | low | `pip install` without `--no-cache-dir` |
| DSA009 | low | `ADD` where `COPY` is meant |
| DSA010 | medium | the whole context is copied and there is no `.dockerignore` beside the Dockerfile |

DSA010 needs a directory to look in, so it is skipped for stdin input.

### Hardened profile

`--profile hardened` checks the final stage against the policy of a hardened runtime image. The
rules come from the archived
[docker-hardened-base](https://github.com/moveeeax/docker-hardened-base) policy linter and keep
its codes. Every DHB finding is `high`, so the default `--fail-on high` blocks on any of them, as
the original linter did.

| id | what it catches |
| --- | --- |
| DHB001 | the final base image is not pinned by `@sha256:` digest |
| DHB002 | the final base image uses `:latest` or no tag |
| DHB003 | a `RUN` in the final stage, which needs a shell in the runtime image |
| DHB004 | a package manager (`apt-get`, `apk`, `dnf`, ...) invoked in the final stage |
| DHB005 | the final stage has no `USER`, or its last `USER` is root |
| DHB006 | `EXPOSE` of a port below 1024, which a non-root process cannot bind |
| DHB007 | the final stage lacks the `org.opencontainers.image.source` or `.licenses` label |

A final stage built `FROM` an earlier stage, and `FROM scratch`, are exempt from DHB001 and DHB002.
A variable base (`FROM ${BASE}`) still gets DHB001, because nothing in the file guarantees a
digest. With the profile on, DHB005 replaces DSA006 and DHB002 replaces DSA007 on the final
`FROM`, so the same problem is not reported twice.

## Checking a built image

A Dockerfile can say `USER nonroot` and still produce an image that runs as root, or start from a
distroless base and get a shell copied back in. `--image` checks the image itself: its config and
the filesystem left after applying every layer, whiteouts included.

```sh
dockerfile-slim-advisor --image ghcr.io/acme/api:1.4.2           # pulled from the registry
dockerfile-slim-advisor --image api.tar                          # docker save -o api.tar ...
dockerfile-slim-advisor --image ghcr.io/acme/api:1.4.2 --platform linux/arm64 --profile hardened
```

An existing file is read as a `docker save` tarball; anything else is a registry reference,
pulled with the credentials in your Docker config, the same ones `docker pull` uses.

| id | severity | what it catches |
| --- | --- | --- |
| DSI001 | high | the image config sets no user, so the container runs as root |
| DSI002 | high | the user is `root`, uid `0`, or a name that `/etc/passwd` maps to uid 0 |
| DSI003 | high | the user or group is a name missing from the image's `/etc/passwd` or `/etc/group` |
| DSI004 | high | the image calls itself distroless and ships a shell or package manager |
| DSI005 | high | the image ships a shell (`sh`, `bash`, `busybox`, ...); hardened profile only |
| DSI006 | high | the image ships a package manager (`apt-get`, `apk`, `rpm`, ...); hardened profile only |
| DSI007 | high | the entrypoint is not in the image, or it is a script whose `#!` interpreter is not |

An image "calls itself distroless" when the reference or any label value contains `distroless`,
for example `org.opencontainers.image.base.name=gcr.io/distroless/static-debian12`. Paths are
resolved through symlinks the way the kernel does, so `/bin/sh` is found on a usrmerge image
where `/bin` links to `usr/bin`. DSI007 covers the case where a hardened final stage is undone by
a copied-in wrapper script that starts with `#!/bin/sh`, or by a shell-form `ENTRYPOINT`.
Image findings have no line number: `line` is `0` in JSON and blank in text output.

## Suppressions

A finding you accept on purpose can be suppressed in the Dockerfile, in the comment block right
above the instruction it is reported on:

```dockerfile
# slim-advisor ignore=DSA002,DSA006 reason="runs go generate at start"
FROM golang:1.22.5
```

or for the whole repository in `.slim-advisor.yaml`:

```yaml
ignore:
  - DSA009
  - id: DSI002
    reason: the init container needs root
```

The config file is looked up next to the Dockerfile, then in the current directory (only the
current directory for `--image` and stdin), or passed with `--config`. An unknown rule id or key
in it is an error, so a typo does not silently leave the gate red. Suppressed findings never
affect the exit code. They are counted in the summary (`7 findings: ..., 2 suppressed`) and
listed with `--show-suppressed`. SARIF output always includes them, marked with a SARIF
`suppressions` entry (`inSource` for a comment, `external` for the config file).

## How it works

The Dockerfile is parsed with BuildKit's own parser (`github.com/moby/buildkit/frontend/dockerfile/parser`),
so line continuations, heredocs and instruction flags are handled exactly the way `docker build`
handles them — the rules never see a raw line of text. The AST is flattened into stages, each
stage keeping its instructions in order, and the rules run over that:

- Cache rules are **per stage** and **order-sensitive**: DSA001 only fires when the whole-context
  copy comes *before* a recognised dependency install (`go mod download`, `npm ci`, `pip install -r`,
  `bundle install`, `dotnet restore` and friends) in the same stage.
- Image-weight rules look only at the **last** stage, because that is the one Docker builds and
  ships by default. A `golang:1.22` builder stage is fine; a `golang:1.22` final stage is not.
- `COPY --from=<stage>` is never treated as a context copy, so a correct multi-stage file stays quiet.

Findings come back ranked: severity first, line number second.

## CI

```yaml
- name: Dockerfile check
  run: |
    go install github.com/moveeeax/dockerfile-slim-advisor/cmd/dockerfile-slim-advisor@latest
    dockerfile-slim-advisor ./Dockerfile
```

Use `--fail-on medium` to tighten the gate, or `--fail-on never` with `--format json` to collect
findings without blocking the build.

To show findings in GitHub code scanning, write SARIF and upload it:

```yaml
- run: dockerfile-slim-advisor --format sarif --fail-on never ./Dockerfile > slim-advisor.sarif
- uses: github/codeql-action/upload-sarif@v4
  with:
    sarif_file: slim-advisor.sarif
```

## Development

```sh
go test ./...
go build -o dockerfile-slim-advisor ./cmd/dockerfile-slim-advisor
```

## License

MIT — see [LICENSE](LICENSE).
