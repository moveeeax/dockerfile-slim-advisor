// Command dockerfile-slim-advisor reports image-bloat and build-cache
// anti-patterns in a Dockerfile.
package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/moveeeax/dockerfile-slim-advisor/internal/advisor"
)

// version is overridden at release time with -ldflags "-X main.version=...".
var version = "dev"

const usage = `dockerfile-slim-advisor [flags] <path>

  path    a Dockerfile, a directory containing one, or - for stdin

flags:
`

func main() {
	if err := run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr); err != nil {
		if code, ok := err.(exitCode); ok {
			os.Exit(int(code))
		}
		fmt.Fprintf(os.Stderr, "dockerfile-slim-advisor: %v\n", err)
		os.Exit(2)
	}
}

// exitCode is returned when the run itself succeeded but findings mean a
// non-zero exit status.
type exitCode int

func (e exitCode) Error() string { return fmt.Sprintf("exit status %d", int(e)) }

func run(args []string, stdin io.Reader, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("dockerfile-slim-advisor", flag.ContinueOnError)
	fs.SetOutput(stderr)
	format := fs.String("format", "text", "output format: text or json")
	failOn := fs.String("fail-on", "high", "lowest severity that exits 1: high, medium, low or never")
	showVersion := fs.Bool("version", false, "print version and exit")
	fs.Usage = func() {
		fmt.Fprint(stderr, usage)
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return exitCode(2)
	}
	if *showVersion {
		fmt.Fprintln(stdout, version)
		return nil
	}
	if fs.NArg() != 1 {
		fs.Usage()
		return exitCode(2)
	}
	if *format != "text" && *format != "json" {
		return fmt.Errorf("unknown format %q (want text or json)", *format)
	}

	var threshold advisor.Severity
	if *failOn != "never" {
		s, err := advisor.ParseSeverity(*failOn)
		if err != nil {
			return err
		}
		threshold = s
	}

	path, opt, src, err := open(fs.Arg(0), stdin)
	if err != nil {
		return err
	}
	defer src.Close()

	df, err := advisor.Parse(src, path)
	if err != nil {
		return err
	}
	report := advisor.NewReport(path, advisor.Analyze(df, opt))

	if *format == "json" {
		err = report.WriteJSON(stdout)
	} else {
		err = report.WriteText(stdout)
	}
	if err != nil {
		return err
	}

	worst := advisor.Worst(report.Findings)
	if threshold != 0 && worst >= threshold {
		return exitCode(1)
	}
	return nil
}

// open resolves the argument to a reader. A directory argument is resolved to
// the Dockerfile inside it, which is what `dockerfile-slim-advisor .` should
// obviously mean.
func open(arg string, stdin io.Reader) (string, advisor.Options, io.ReadCloser, error) {
	if arg == "-" {
		return "<stdin>", advisor.Options{}, io.NopCloser(stdin), nil
	}
	info, err := os.Stat(arg)
	if err != nil {
		return "", advisor.Options{}, nil, err
	}
	path := arg
	if info.IsDir() {
		path = filepath.Join(arg, "Dockerfile")
	}
	f, err := os.Open(path)
	if err != nil {
		return "", advisor.Options{}, nil, err
	}
	opt := advisor.Options{CheckDockerignore: true}
	if _, err := os.Stat(filepath.Join(filepath.Dir(path), ".dockerignore")); err == nil {
		opt.HasDockerignore = true
	}
	return path, opt, f, nil
}
