package advisor

import (
	"context"
	"fmt"
	"os"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/tarball"
)

// OpenImage resolves --image. An existing file is read as a `docker save`
// tarball; anything else is a registry reference, pulled with the
// credentials of the local Docker config (the same ones `docker pull` uses).
// platform picks one image out of a multi-platform index, e.g. linux/arm64;
// empty means linux/amd64.
func OpenImage(ctx context.Context, ref, platform string) (v1.Image, error) {
	if info, err := os.Stat(ref); err == nil && !info.IsDir() {
		img, err := tarball.ImageFromPath(ref, nil)
		if err != nil {
			return nil, fmt.Errorf("read image tarball %s: %w", ref, err)
		}
		return img, nil
	}
	r, err := name.ParseReference(ref)
	if err != nil {
		return nil, fmt.Errorf("parse image reference: %w", err)
	}
	opts := []remote.Option{
		remote.WithContext(ctx),
		remote.WithAuthFromKeychain(authn.DefaultKeychain),
	}
	if platform != "" {
		p, err := v1.ParsePlatform(platform)
		if err != nil {
			return nil, fmt.Errorf("parse platform: %w", err)
		}
		opts = append(opts, remote.WithPlatform(*p))
	}
	img, err := remote.Image(r, opts...)
	if err != nil {
		return nil, fmt.Errorf("pull %s: %w", ref, err)
	}
	return img, nil
}
