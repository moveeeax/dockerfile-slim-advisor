package advisor

import (
	"archive/tar"
	"bufio"
	"bytes"
	"fmt"
	"io"
	"path"
	"sort"
	"strconv"
	"strings"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
)

// Image mode checks the built image instead of the Dockerfile that claims to
// have built it: the user in the image config, resolved against the image's
// own /etc/passwd, and the flattened filesystem of every layer.

// ImageOptions controls image analysis.
type ImageOptions struct {
	// Ref is the reference or tarball path the image came from. It is one of
	// the places a "distroless" claim is read from.
	Ref     string
	Profile Profile
}

// defaultPath is what Docker uses when the image config sets no PATH.
const defaultPath = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

var (
	binDirs     = []string{"/bin", "/usr/bin", "/usr/local/bin", "/sbin", "/usr/sbin"}
	shells      = []string{"sh", "bash", "ash", "dash", "zsh", "ksh", "mksh", "busybox"}
	pkgManagers = []string{"apt-get", "apt", "dpkg", "apk", "yum", "dnf", "microdnf", "tdnf", "rpm", "zypper", "pacman"}
)

// AnalyzeImage runs the image rules over a v1.Image.
func AnalyzeImage(img v1.Image, opt ImageOptions) ([]Finding, error) {
	cf, err := img.ConfigFile()
	if err != nil {
		return nil, fmt.Errorf("read image config: %w", err)
	}
	fsys, err := readRootfs(img)
	if err != nil {
		return nil, err
	}
	cfg := cf.Config

	var out []Finding
	out = append(out, checkImageUser(cfg.User, fsys)...)
	out = append(out, checkImageSurface(cfg, fsys, opt)...)
	out = append(out, checkEntrypoint(cfg, fsys)...)
	return rank(out), nil
}

func checkImageUser(user string, fsys *rootfs) []Finding {
	user = strings.TrimSpace(user)
	if user == "" {
		return []Finding{{
			ID:          "DSI001",
			Severity:    High,
			Instruction: "USER",
			Title:       "image config sets no user",
			Detail: "The config has no User, so the container process is uid 0 whatever the " +
				"Dockerfile author intended, and a Kubernetes pod with runAsNonRoot refuses to start it.",
			Fix: "add a numeric non-root `USER 65532:65532` to the final stage and rebuild",
		}}
	}
	name, group, _ := strings.Cut(user, ":")
	var out []Finding

	uid, numeric := atoi(name)
	if !numeric {
		if name == "root" {
			uid, numeric = 0, true
		} else if u, ok := fsys.passwd()[name]; ok {
			uid, numeric = u, true
		} else {
			out = append(out, unresolved("user", name, "/etc/passwd", fsys.has("/etc/passwd")))
		}
	}
	if numeric && uid == 0 {
		out = append(out, Finding{
			ID:          "DSI002",
			Severity:    High,
			Instruction: "USER",
			Title:       fmt.Sprintf("image runs as uid 0 (user %q)", user),
			Detail: "The image config resolves to root, so a process escape from the container " +
				"starts with root privileges on the shared kernel.",
			Fix: "set a non-root numeric USER in the final stage",
		})
	}
	if group != "" {
		if _, ok := atoi(group); !ok {
			if _, ok := fsys.groups()[group]; !ok {
				out = append(out, unresolved("group", group, "/etc/group", fsys.has("/etc/group")))
			}
		}
	}
	return out
}

func unresolved(kind, name, file string, fileExists bool) Finding {
	why := file + " has no entry for it"
	if !fileExists {
		why = "the image has no " + file
	}
	return Finding{
		ID:          "DSI003",
		Severity:    High,
		Instruction: "USER",
		Title:       fmt.Sprintf("%s %q is not defined in the image", kind, name),
		Detail: fmt.Sprintf("The config names %s %q, but %s. Names are resolved inside the "+
			"image at start, so runc-based runtimes refuse to start the container with "+
			"\"unable to find %s\".", kind, name, why, kind),
		Fix: "use a numeric uid:gid in USER, or add the entry to " + file + " in the final stage",
	}
}

// checkImageSurface covers the shell and package-manager rules. An image that
// says it is distroless and still ships a shell is always reported; with the
// hardened profile any shell or package manager is.
func checkImageSurface(cfg v1.Config, fsys *rootfs, opt ImageOptions) []Finding {
	shellPaths := fsys.findAny(binDirs, shells)
	pkgPaths := fsys.findAny(binDirs, pkgManagers)
	if len(shellPaths) == 0 && len(pkgPaths) == 0 {
		return nil
	}

	if claim := distrolessClaim(cfg, opt.Ref); claim != "" {
		found := append(append([]string(nil), shellPaths...), pkgPaths...)
		return []Finding{{
			ID:          "DSI004",
			Severity:    High,
			Instruction: "FROM",
			Title:       "distroless image ships " + strings.Join(found, ", "),
			Detail: fmt.Sprintf("The image is presented as distroless (%s), but its filesystem "+
				"has a shell or a package manager, so anyone with exec access gets a working "+
				"toolbox and scanners that trust the label miss it.", claim),
			Fix: "rebuild the final stage on a distroless base and copy in only the artifact; " +
				"check that no `COPY --from` brings busybox or a shell along",
		}}
	}
	if opt.Profile != ProfileHardened {
		return nil
	}
	var out []Finding
	if len(shellPaths) > 0 {
		out = append(out, Finding{
			ID:          "DSI005",
			Severity:    High,
			Instruction: "FROM",
			Title:       "image ships a shell: " + strings.Join(shellPaths, ", "),
			Detail: "A shell in the runtime image is what turns a remote code execution bug " +
				"into an interactive session.",
			Fix: "move the final stage to a base without a shell (distroless, scratch, a hardened image)",
		})
	}
	if len(pkgPaths) > 0 {
		out = append(out, Finding{
			ID:          "DSI006",
			Severity:    High,
			Instruction: "FROM",
			Title:       "image ships a package manager: " + strings.Join(pkgPaths, ", "),
			Detail:      "A package manager in the runtime image lets an attacker install whatever tools they need.",
			Fix:         "install packages in a build stage and copy only the files the service needs",
		})
	}
	return out
}

// distrolessClaim returns where the image calls itself distroless: the
// reference it was pulled by, or any label value such as
// org.opencontainers.image.base.name. "" means no claim.
func distrolessClaim(cfg v1.Config, ref string) string {
	if strings.Contains(strings.ToLower(ref), "distroless") {
		return "reference " + ref
	}
	keys := make([]string, 0, len(cfg.Labels))
	for k := range cfg.Labels {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		if strings.Contains(strings.ToLower(cfg.Labels[k]), "distroless") {
			return fmt.Sprintf("label %s=%s", k, cfg.Labels[k])
		}
	}
	return ""
}

// checkEntrypoint makes sure the process the image starts exists, and that a
// script entrypoint has its interpreter. This is where a hardened final stage
// gets undone in practice: a copied-in wrapper script whose `#!/bin/sh` the
// base does not have, or a shell-form ENTRYPOINT on a shell-less base.
func checkEntrypoint(cfg v1.Config, fsys *rootfs) []Finding {
	argv := append(append([]string(nil), cfg.Entrypoint...), cfg.Cmd...)
	if len(argv) == 0 || strings.Contains(argv[0], "$") {
		return nil
	}
	pathEnv := defaultPath
	for _, e := range cfg.Env {
		if v, ok := strings.CutPrefix(e, "PATH="); ok {
			pathEnv = v
		}
	}
	workdir := cfg.WorkingDir
	if workdir == "" {
		workdir = "/"
	}

	missing := func(title, detail string) []Finding {
		return []Finding{{
			ID:          "DSI007",
			Severity:    High,
			Instruction: "ENTRYPOINT",
			Title:       title,
			Detail:      detail,
			Fix: "use an exec-form ENTRYPOINT that points at a binary in the image, or ship " +
				"the interpreter the script needs",
		}}
	}

	bin, ok := fsys.lookPath(argv[0], pathEnv, workdir)
	if !ok {
		return missing(fmt.Sprintf("entrypoint %s is not in the image", argv[0]),
			fmt.Sprintf("The container starts %q, which does not resolve in the image filesystem "+
				"(PATH=%s), so every start fails with \"executable file not found\".",
				strings.Join(argv, " "), pathEnv))
	}
	interp := fsys.shebang(bin)
	if interp == nil {
		return nil
	}
	target := interp[0]
	if path.Base(target) == "env" && len(interp) > 1 {
		target = interp[1]
	}
	if _, ok := fsys.lookPath(target, pathEnv, workdir); ok {
		return nil
	}
	return missing(fmt.Sprintf("entrypoint %s needs %s, which the image does not have", argv[0], target),
		fmt.Sprintf("%s starts with `#!%s`, and the interpreter is not in the image, so exec "+
			"fails with \"no such file or directory\" on every start.", bin, strings.Join(interp, " ")))
}

func atoi(s string) (int, bool) {
	n, err := strconv.Atoi(s)
	return n, err == nil
}

// rootfs is the flattened image filesystem: every entry that survives the
// layer whiteouts, plus the few file contents the rules need.
type rootfs struct {
	entries  map[string]*tar.Header // clean absolute path -> header
	dirs     map[string]bool        // directories implied by entry paths
	contents map[string][]byte      // /etc/passwd and /etc/group
	shebangs map[string][]string    // executable scripts -> interpreter argv
}

const (
	maxEtcFile  = 1 << 20
	shebangPeek = 256
)

// readRootfs flattens the image layers (mutate.Extract applies whiteouts and
// opaque directories) and indexes the result.
func readRootfs(img v1.Image) (*rootfs, error) {
	fsys := &rootfs{
		entries:  map[string]*tar.Header{},
		dirs:     map[string]bool{"/": true},
		contents: map[string][]byte{},
		shebangs: map[string][]string{},
	}
	rc := mutate.Extract(img)
	defer rc.Close()
	tr := tar.NewReader(rc)
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("read image filesystem: %w", err)
		}
		name := cleanAbs(h.Name)
		fsys.entries[name] = h
		for d := path.Dir(name); !fsys.dirs[d]; d = path.Dir(d) {
			fsys.dirs[d] = true
		}
		if h.Typeflag != tar.TypeReg {
			continue
		}
		switch {
		case name == "/etc/passwd" || name == "/etc/group":
			data, err := io.ReadAll(io.LimitReader(tr, maxEtcFile))
			if err != nil {
				return nil, fmt.Errorf("read %s: %w", name, err)
			}
			fsys.contents[name] = data
		case h.Mode&0o111 != 0 && h.Size > 2:
			head := make([]byte, shebangPeek)
			n, _ := io.ReadFull(tr, head)
			if line, ok := bytes.CutPrefix(head[:n], []byte("#!")); ok {
				line, _, _ = bytes.Cut(line, []byte("\n"))
				if f := strings.Fields(string(line)); len(f) > 0 {
					fsys.shebangs[name] = f
				}
			}
		}
	}
	return fsys, nil
}

func cleanAbs(p string) string { return path.Clean("/" + p) }

// resolve follows symlinks through every path component, the way the kernel
// does, so /bin/sh is found on a usrmerge image where /bin -> usr/bin. It
// returns the final path and its header (nil for an implied directory).
func (r *rootfs) resolve(p string) (string, *tar.Header, bool) {
	parts := splitPath(p)
	cur := "/"
	for hops := 0; len(parts) > 0; {
		next := path.Join(cur, parts[0])
		parts = parts[1:]
		h, ok := r.entries[next]
		if !ok {
			if r.dirs[next] {
				cur = next
				continue
			}
			return "", nil, false
		}
		if h.Typeflag == tar.TypeSymlink {
			if hops++; hops > 40 {
				return "", nil, false
			}
			target := h.Linkname
			if !path.IsAbs(target) {
				target = path.Join(cur, target)
			}
			parts = append(splitPath(target), parts...)
			cur = "/"
			continue
		}
		cur = next
	}
	return cur, r.entries[cur], true
}

func splitPath(p string) []string {
	p = strings.TrimPrefix(cleanAbs(p), "/")
	if p == "" {
		return nil
	}
	return strings.Split(p, "/")
}

// file resolves p and reports whether it is a regular file (or a hardlink to
// one), returning the path its contents live at.
func (r *rootfs) file(p string) (string, bool) {
	name, h, ok := r.resolve(p)
	if !ok || h == nil {
		return "", false
	}
	switch h.Typeflag {
	case tar.TypeReg:
		return name, true
	case tar.TypeLink:
		// A hardlink names the entry that carries the data, which is
		// always a regular file in a well-formed layer.
		if name, h, ok := r.resolve(h.Linkname); ok && h != nil && h.Typeflag == tar.TypeReg {
			return name, true
		}
	}
	return "", false
}

func (r *rootfs) has(p string) bool {
	_, ok := r.file(p)
	return ok
}

// findAny returns, for each name, the first directory in dirs holding it as
// a file. Paths that resolve to a file already listed (a usrmerge alias, a
// busybox applet symlink) are reported once.
func (r *rootfs) findAny(dirs, names []string) []string {
	var out []string
	seen := map[string]bool{}
	for _, n := range names {
		for _, d := range dirs {
			p := path.Join(d, n)
			target, ok := r.file(p)
			if !ok || seen[target] {
				continue
			}
			seen[target] = true
			out = append(out, p)
			break
		}
	}
	return out
}

// lookPath resolves a command the way exec does: a name with a slash is a
// path (relative to the working directory), anything else is searched in PATH.
func (r *rootfs) lookPath(cmd, pathEnv, workdir string) (string, bool) {
	if strings.Contains(cmd, "/") {
		if !path.IsAbs(cmd) {
			cmd = path.Join(workdir, cmd)
		}
		return r.file(cmd)
	}
	for _, dir := range strings.Split(pathEnv, ":") {
		if dir == "" {
			continue
		}
		if p, ok := r.file(path.Join(dir, cmd)); ok {
			return p, true
		}
	}
	return "", false
}

// shebang returns the interpreter argv of a script, or nil for a binary.
func (r *rootfs) shebang(p string) []string {
	if target, ok := r.file(p); ok {
		return r.shebangs[target]
	}
	return nil
}

func (r *rootfs) passwd() map[string]int { return r.idFile("/etc/passwd") }
func (r *rootfs) groups() map[string]int { return r.idFile("/etc/group") }

// idFile parses name:x:id:... lines, the format shared by passwd and group.
func (r *rootfs) idFile(p string) map[string]int {
	out := map[string]int{}
	target, ok := r.file(p)
	if !ok {
		return out
	}
	sc := bufio.NewScanner(bytes.NewReader(r.contents[target]))
	for sc.Scan() {
		f := strings.Split(sc.Text(), ":")
		if len(f) < 3 || strings.HasPrefix(f[0], "#") {
			continue
		}
		if id, ok := atoi(f[2]); ok {
			out[f[0]] = id
		}
	}
	return out
}
