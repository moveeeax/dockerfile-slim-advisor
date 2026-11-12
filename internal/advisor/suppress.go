package advisor

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"go.yaml.in/yaml/v3"
)

// Suppression records why a finding was accepted instead of reported.
type Suppression struct {
	Source string `json:"source"` // "inline" or the config file path
	Reason string `json:"reason,omitempty"`
}

// ConfigNames are the file names looked up when --config is not given.
var ConfigNames = []string{".slim-advisor.yaml", ".slim-advisor.yml"}

// Config is the .slim-advisor.yaml file.
//
//	ignore:
//	  - DSA009
//	  - id: DSA006
//	    reason: root needed by the init container
type Config struct {
	Path   string       `yaml:"-"`
	Ignore []IgnoreRule `yaml:"ignore"`
}

// IgnoreRule is one entry of the ignore list. It accepts a bare rule id or
// an {id, reason} mapping.
type IgnoreRule struct {
	ID     string `yaml:"id"`
	Reason string `yaml:"reason"`
}

// UnmarshalYAML accepts both `- DSA009` and `- {id: DSA009, reason: ...}`.
func (r *IgnoreRule) UnmarshalYAML(n *yaml.Node) error {
	if n.Kind == yaml.ScalarNode {
		r.ID = n.Value
		return nil
	}
	if n.Kind != yaml.MappingNode {
		return fmt.Errorf("line %d: ignore entry must be a rule id or {id, reason}", n.Line)
	}
	// Decode does not carry KnownFields into a custom unmarshaler, so the
	// keys are checked here.
	for i := 0; i+1 < len(n.Content); i += 2 {
		key, val := n.Content[i], n.Content[i+1]
		switch key.Value {
		case "id":
			r.ID = val.Value
		case "reason":
			r.Reason = val.Value
		default:
			return fmt.Errorf("line %d: field %s not found in ignore entry", key.Line, key.Value)
		}
	}
	return nil
}

// LoadConfig reads and validates a config file. Unknown keys and unknown
// rule ids are errors: a misspelt id would otherwise leave the finding it
// was meant to accept failing the build with no hint why.
func LoadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	cfg := &Config{Path: path}
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(cfg); err != nil && !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	for i, r := range cfg.Ignore {
		id := strings.ToUpper(strings.TrimSpace(r.ID))
		if !KnownRule(id) {
			return nil, fmt.Errorf("%s: ignore[%d]: unknown rule %q", path, i, r.ID)
		}
		cfg.Ignore[i].ID = id
	}
	return cfg, nil
}

// FindConfig returns the first config file found in dirs, in order, or ""
// when there is none.
func FindConfig(dirs ...string) string {
	for _, dir := range dirs {
		for _, name := range ConfigNames {
			p := filepath.Join(dir, name)
			if info, err := os.Stat(p); err == nil && !info.IsDir() {
				return p
			}
		}
	}
	return ""
}

// inlineRe matches `# slim-advisor ignore=DSA006,DSA009 reason="..."`. The
// buildkit parser has already stripped the leading `#`.
var inlineRe = regexp.MustCompile(`^slim-advisor\s+ignore=([A-Za-z0-9,]+)(?:\s+reason=(?:"([^"]*)"|'([^']*)'|(\S+)))?\s*$`)

// inlineIgnores maps an instruction line to the rules its comment block
// suppresses, with their reasons.
func inlineIgnores(df *Dockerfile) map[int]map[string]string {
	out := map[int]map[string]string{}
	add := func(line int, comments []string) {
		for _, c := range comments {
			m := inlineRe.FindStringSubmatch(strings.TrimSpace(c))
			if m == nil {
				continue
			}
			reason := m[2] + m[3] + m[4]
			for _, id := range strings.Split(m[1], ",") {
				if id = strings.ToUpper(strings.TrimSpace(id)); id == "" {
					continue
				}
				if out[line] == nil {
					out[line] = map[string]string{}
				}
				out[line][id] = reason
			}
		}
	}
	for _, in := range df.Preamble {
		add(in.Line, in.Comments)
	}
	for _, s := range df.Stages {
		add(s.Line, s.Comments)
		for _, in := range s.Instructions {
			add(in.Line, in.Comments)
		}
	}
	return out
}

// Suppress splits findings into the ones still reported and the ones
// accepted by an inline comment (df may be nil, as in image mode) or by the
// config ignore list (cfg may be nil). The order of both slices is kept.
func Suppress(df *Dockerfile, cfg *Config, fs []Finding) (kept, suppressed []Finding) {
	var inline map[int]map[string]string
	if df != nil {
		inline = inlineIgnores(df)
	}
	for _, f := range fs {
		if reason, ok := inline[f.Line][f.ID]; ok && f.Line > 0 {
			f.Suppression = &Suppression{Source: "inline", Reason: reason}
			suppressed = append(suppressed, f)
			continue
		}
		if s := cfg.match(f.ID); s != nil {
			f.Suppression = s
			suppressed = append(suppressed, f)
			continue
		}
		kept = append(kept, f)
	}
	return kept, suppressed
}

func (c *Config) match(id string) *Suppression {
	if c == nil {
		return nil
	}
	for _, r := range c.Ignore {
		if r.ID == id {
			return &Suppression{Source: c.Path, Reason: r.Reason}
		}
	}
	return nil
}
