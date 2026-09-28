// Package advisor parses Dockerfiles and reports image-bloat and
// build-cache anti-patterns.
package advisor

import (
	"fmt"
	"io"
	"strings"

	"github.com/moby/buildkit/frontend/dockerfile/parser"
)

// Instruction is a single Dockerfile instruction, flattened out of the
// buildkit AST so the rules can work with plain strings.
type Instruction struct {
	Cmd      string   // upper-cased instruction name, e.g. "COPY"
	Args     []string // arguments in source order
	Flags    []string // instruction flags, e.g. "--from=builder"
	Original string   // original source text, line continuations joined
	Line     int
}

// ArgText returns the arguments as one space-joined string, which is what
// most of the RUN rules want to match against.
func (i Instruction) ArgText() string { return strings.Join(i.Args, " ") }

// HasFlag reports whether the instruction carries a flag with the given
// name, with or without a value (`--from`, `--from=builder`).
func (i Instruction) HasFlag(name string) bool {
	for _, f := range i.Flags {
		if f == "--"+name || strings.HasPrefix(f, "--"+name+"=") {
			return true
		}
	}
	return false
}

// Stage is one FROM ... block.
type Stage struct {
	Index        int
	BaseImage    string // raw image reference as written
	Name         string // lower-cased AS name, empty when unnamed
	Line         int
	Instructions []Instruction
}

// Has reports whether the stage contains at least one instruction with the
// given command.
func (s Stage) Has(cmd string) bool {
	for _, in := range s.Instructions {
		if in.Cmd == cmd {
			return true
		}
	}
	return false
}

// Dockerfile is a parsed Dockerfile.
type Dockerfile struct {
	Path     string
	Preamble []Instruction // instructions before the first FROM (ARG, comments)
	Stages   []Stage
}

// FinalStage returns the stage Docker builds when no --target is given: the
// last one in the file.
func (d *Dockerfile) FinalStage() *Stage {
	if len(d.Stages) == 0 {
		return nil
	}
	return &d.Stages[len(d.Stages)-1]
}

// stageNames returns the set of named stages declared before index i, which
// is what a `FROM builder` or `COPY --from=builder` may refer to.
func (d *Dockerfile) stageNames(before int) map[string]bool {
	names := map[string]bool{}
	for _, s := range d.Stages {
		if s.Index < before && s.Name != "" {
			names[s.Name] = true
		}
	}
	return names
}

// Parse reads a Dockerfile. path is used for reporting only and may be "-".
func Parse(r io.Reader, path string) (*Dockerfile, error) {
	res, err := parser.Parse(r)
	if err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}

	df := &Dockerfile{Path: path}
	for _, node := range res.AST.Children {
		in := Instruction{
			Cmd:      strings.ToUpper(node.Value),
			Flags:    append([]string(nil), node.Flags...),
			Original: node.Original,
			Line:     node.StartLine,
		}
		for n := node.Next; n != nil; n = n.Next {
			in.Args = append(in.Args, n.Value)
		}

		if in.Cmd == "FROM" {
			stage := Stage{Index: len(df.Stages), Line: in.Line}
			if len(in.Args) > 0 {
				stage.BaseImage = in.Args[0]
			}
			// FROM <image> AS <name>
			if len(in.Args) >= 3 && strings.EqualFold(in.Args[1], "as") {
				stage.Name = strings.ToLower(in.Args[2])
			}
			df.Stages = append(df.Stages, stage)
			continue
		}

		if len(df.Stages) == 0 {
			df.Preamble = append(df.Preamble, in)
			continue
		}
		last := &df.Stages[len(df.Stages)-1]
		last.Instructions = append(last.Instructions, in)
	}
	return df, nil
}
