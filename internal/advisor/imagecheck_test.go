package advisor

import (
	"archive/tar"
	"bytes"
	"context"
	"io"
	"log"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/registry"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/tarball"
)

// entry is one file in a test layer. A target makes it a symlink, a body
// starting with "#!" makes it a script, and dir makes it a directory.
type entry struct {
	name   string
	body   string
	target string
	dir    bool
	mode   int64
}

func layer(t *testing.T, entries ...entry) v1.Layer {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for _, e := range entries {
		h := &tar.Header{Name: e.name, Mode: 0o755, Typeflag: tar.TypeReg, Size: int64(len(e.body))}
		if e.mode != 0 {
			h.Mode = e.mode
		}
		switch {
		case e.dir:
			h.Typeflag, h.Size = tar.TypeDir, 0
		case e.target != "":
			h.Typeflag, h.Linkname, h.Size = tar.TypeSymlink, e.target, 0
		}
		if err := tw.WriteHeader(h); err != nil {
			t.Fatal(err)
		}
		if h.Size > 0 {
			if _, err := io.WriteString(tw, e.body); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	data := buf.Bytes()
	l, err := tarball.LayerFromOpener(func() (io.ReadCloser, error) {
		return io.NopCloser(bytes.NewReader(data)), nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return l
}

func image(t *testing.T, cfg v1.Config, layers ...v1.Layer) v1.Image {
	t.Helper()
	img, err := mutate.AppendLayers(empty.Image, layers...)
	if err != nil {
		t.Fatal(err)
	}
	if img, err = mutate.Config(img, cfg); err != nil {
		t.Fatal(err)
	}
	return img
}

func analyzeImage(t *testing.T, img v1.Image, opt ImageOptions) []Finding {
	t.Helper()
	fs, err := AnalyzeImage(img, opt)
	if err != nil {
		t.Fatal(err)
	}
	return fs
}

const passwd = "root:x:0:0:root:/root:/sbin/nologin\nnonroot:x:65532:65532::/home/nonroot:/sbin/nologin\ntoor:x:0:0::/:/sbin/nologin\n"
const group = "root:x:0:\nnonroot:x:65532:\n"

// distroless is the shape of gcr.io/distroless/static:nonroot: a passwd file,
// one static binary, no shell.
func distroless(t *testing.T) v1.Layer {
	return layer(t,
		entry{name: "etc/passwd", body: passwd, mode: 0o644},
		entry{name: "etc/group", body: group, mode: 0o644},
		entry{name: "app", body: "\x7fELF binary"},
	)
}

func TestCleanImageHasNoFindings(t *testing.T) {
	img := image(t, v1.Config{User: "65532:65532", Entrypoint: []string{"/app"}}, distroless(t))
	if fs := analyzeImage(t, img, ImageOptions{Ref: "gcr.io/distroless/static:nonroot", Profile: ProfileHardened}); len(fs) != 0 {
		t.Fatalf("expected no findings, got %v", ids(fs))
	}
}

func TestImageUser(t *testing.T) {
	cases := []struct {
		user string
		want []string
	}{
		{"", []string{"DSI001"}},
		{"root", []string{"DSI002"}},
		{"0:0", []string{"DSI002"}},
		{"toor", []string{"DSI002"}}, // a name that maps to uid 0
		{"nonroot", nil},
		{"nonroot:nonroot", nil},
		{"1000:1000", nil}, // numeric ids need no passwd entry
		{"app", []string{"DSI003"}},
		{"nonroot:staff", []string{"DSI003"}},
	}
	for _, c := range cases {
		img := image(t, v1.Config{User: c.user, Entrypoint: []string{"/app"}}, distroless(t))
		fs := analyzeImage(t, img, ImageOptions{})
		if strings.Join(ids(fs), ",") != strings.Join(c.want, ",") {
			t.Errorf("user %q: findings = %v, want %v", c.user, ids(fs), c.want)
		}
	}
}

func TestNamedUserWithoutPasswdFile(t *testing.T) {
	img := image(t, v1.Config{User: "app", Entrypoint: []string{"/app"}}, layer(t, entry{name: "app", body: "bin"}))
	f := find(t, analyzeImage(t, img, ImageOptions{}), "DSI003")
	if !strings.Contains(f.Detail, "has no /etc/passwd") {
		t.Errorf("DSI003 should say the passwd file is missing, got %q", f.Detail)
	}
}

func TestDistrolessClaimWithShell(t *testing.T) {
	busybox := layer(t,
		entry{name: "bin/busybox", body: "\x7fELF busybox"},
		entry{name: "bin/sh", target: "busybox"},
	)
	cfg := v1.Config{User: "65532", Entrypoint: []string{"/app"}}

	fs := analyzeImage(t, image(t, cfg, distroless(t), busybox), ImageOptions{Ref: "gcr.io/distroless/static:nonroot"})
	assertIDs(t, fs, "DSI004")
	// /bin/sh is a symlink to busybox: one binary, reported once.
	if f := find(t, fs, "DSI004"); f.Title != "distroless image ships /bin/sh" {
		t.Errorf("title = %q", f.Title)
	}

	cfg.Labels = map[string]string{"org.opencontainers.image.base.name": "gcr.io/distroless/base-debian12"}
	fs = analyzeImage(t, image(t, cfg, distroless(t), busybox), ImageOptions{Ref: "ghcr.io/acme/api:1.4.2"})
	if f := find(t, fs, "DSI004"); !strings.Contains(f.Detail, "org.opencontainers.image.base.name") {
		t.Errorf("DSI004 should name the label that makes the claim, got %q", f.Detail)
	}

	// Without a claim the default profile does not care about shells.
	cfg.Labels = nil
	if fs := analyzeImage(t, image(t, cfg, distroless(t), busybox), ImageOptions{Ref: "ghcr.io/acme/api:1.4.2"}); len(fs) != 0 {
		t.Errorf("expected no findings without a distroless claim, got %v", ids(fs))
	}
}

func TestHardenedProfileFailsAnyShell(t *testing.T) {
	// A Debian-style usrmerge layout: /bin is a symlink to usr/bin, so the
	// shell is only reachable by following it.
	debian := layer(t,
		entry{name: "etc/passwd", body: passwd, mode: 0o644},
		entry{name: "usr/", dir: true},
		entry{name: "usr/bin/", dir: true},
		entry{name: "bin", target: "usr/bin"},
		entry{name: "usr/bin/dash", body: "\x7fELF dash"},
		entry{name: "usr/bin/sh", target: "dash"},
		entry{name: "usr/bin/apt-get", body: "\x7fELF apt"},
		entry{name: "app", body: "\x7fELF app"},
	)
	img := image(t, v1.Config{User: "65532", Entrypoint: []string{"/app"}}, debian)

	if fs := analyzeImage(t, img, ImageOptions{}); len(fs) != 0 {
		t.Fatalf("default profile: expected no findings, got %v", ids(fs))
	}
	fs := analyzeImage(t, img, ImageOptions{Profile: ProfileHardened})
	assertIDs(t, fs, "DSI005", "DSI006")
	if f := find(t, fs, "DSI005"); !strings.Contains(f.Title, "/bin/sh") {
		t.Errorf("DSI005 should list the shell by its /bin path, got %q", f.Title)
	}
	if f := find(t, fs, "DSI006"); !strings.Contains(f.Title, "/bin/apt-get") {
		t.Errorf("DSI006 should list apt-get, got %q", f.Title)
	}
}

func TestWhiteoutRemovesShell(t *testing.T) {
	base := layer(t, entry{name: "etc/passwd", body: passwd, mode: 0o644}, entry{name: "bin/sh", body: "\x7fELF sh"}, entry{name: "app", body: "bin"})
	removed := layer(t, entry{name: "bin/.wh.sh", mode: 0o644})
	img := image(t, v1.Config{User: "65532", Entrypoint: []string{"/app"}}, base, removed)
	if fs := analyzeImage(t, img, ImageOptions{Ref: "distroless", Profile: ProfileHardened}); len(fs) != 0 {
		t.Fatalf("a deleted shell must not be reported, got %v", ids(fs))
	}
}

func TestEntrypoint(t *testing.T) {
	cases := []struct {
		name  string
		cfg   v1.Config
		files []entry
		want  string // substring of the DSI007 title, "" for no finding
	}{
		{"binary present", v1.Config{Entrypoint: []string{"/app"}}, nil, ""},
		{"found on PATH", v1.Config{Entrypoint: []string{"app"}, Env: []string{"PATH=/"}}, nil, ""},
		{"not on default PATH", v1.Config{Entrypoint: []string{"app"}}, nil, "entrypoint app is not in the image"},
		{"relative to workdir", v1.Config{Entrypoint: []string{"./app"}, WorkingDir: "/"}, nil, ""},
		{"cmd only", v1.Config{Cmd: []string{"/missing"}}, nil, "/missing is not in the image"},
		{"shell form", v1.Config{Entrypoint: []string{"/bin/sh", "-c", "/app"}}, nil, "/bin/sh is not in the image"},
		{"script without its shell", v1.Config{Entrypoint: []string{"/start.sh"}},
			[]entry{{name: "start.sh", body: "#!/bin/sh\nexec /app\n"}}, "needs /bin/sh"},
		{"env interpreter present", v1.Config{Entrypoint: []string{"/run.py"}},
			[]entry{{name: "run.py", body: "#!/usr/bin/env python3\n"}, {name: "usr/bin/python3", body: "\x7fELF py"}}, ""},
		{"env interpreter missing", v1.Config{Entrypoint: []string{"/run.py"}},
			[]entry{{name: "run.py", body: "#!/usr/bin/env python3\n"}, {name: "usr/bin/env", body: "\x7fELF env"}}, "needs python3"},
		{"variable entrypoint", v1.Config{Entrypoint: []string{"$APP"}}, nil, ""},
	}
	for _, c := range cases {
		c.cfg.User = "65532"
		img := image(t, c.cfg, distroless(t), layer(t, c.files...))
		fs := analyzeImage(t, img, ImageOptions{})
		if c.want == "" {
			if len(fs) != 0 {
				t.Errorf("%s: expected no findings, got %v", c.name, ids(fs))
			}
			continue
		}
		if len(fs) != 1 || fs[0].ID != "DSI007" || !strings.Contains(fs[0].Title, c.want) {
			t.Errorf("%s: findings = %+v, want one DSI007 containing %q", c.name, fs, c.want)
		}
	}
}

func TestImageFindingsAreActionable(t *testing.T) {
	img := image(t, v1.Config{User: "app:staff", Entrypoint: []string{"/start.sh"}},
		layer(t, entry{name: "bin/sh", body: "x"}, entry{name: "usr/bin/apk", body: "x"}, entry{name: "start.sh", body: "#!/bin/bash\n"}))
	fs := analyzeImage(t, img, ImageOptions{Ref: "distroless/static", Profile: ProfileHardened})
	if len(fs) == 0 {
		t.Fatal("expected findings")
	}
	for _, f := range fs {
		if f.Title == "" || f.Detail == "" || f.Fix == "" || f.SeverityStr == "" || !KnownRule(f.ID) {
			t.Errorf("%s is incomplete: %+v", f.ID, f)
		}
		if f.Line != 0 {
			t.Errorf("%s: image findings have no line, got %d", f.ID, f.Line)
		}
	}
}

func TestOpenImageFromTarball(t *testing.T) {
	img := image(t, v1.Config{Entrypoint: []string{"/app"}}, distroless(t))
	path := filepath.Join(t.TempDir(), "image.tar")
	tag, _ := name.NewTag("example.com/app:1.0")
	if err := tarball.WriteToFile(path, tag, img); err != nil {
		t.Fatal(err)
	}
	got, err := OpenImage(context.Background(), path, "")
	if err != nil {
		t.Fatal(err)
	}
	assertIDs(t, analyzeImage(t, got, ImageOptions{Ref: path}), "DSI001")
}

func TestOpenImageFromRegistry(t *testing.T) {
	srv := httptest.NewServer(registry.New(registry.Logger(log.New(io.Discard, "", 0))))
	defer srv.Close()
	ref := strings.TrimPrefix(srv.URL, "http://") + "/acme/api:1.0"
	tag, err := name.NewTag(ref)
	if err != nil {
		t.Fatal(err)
	}
	img := image(t, v1.Config{User: "root", Entrypoint: []string{"/app"}}, distroless(t))
	if err := remote.Write(tag, img); err != nil {
		t.Fatal(err)
	}

	got, err := OpenImage(context.Background(), ref, "")
	if err != nil {
		t.Fatal(err)
	}
	assertIDs(t, analyzeImage(t, got, ImageOptions{Ref: ref}), "DSI002")

	if _, err := OpenImage(context.Background(), ref, "not/a/valid/platform/x"); err == nil {
		t.Error("expected an error for a malformed platform")
	}
	if _, err := OpenImage(context.Background(), "UPPER/Case:tag", ""); err == nil {
		t.Error("expected an error for an invalid reference")
	}
}
