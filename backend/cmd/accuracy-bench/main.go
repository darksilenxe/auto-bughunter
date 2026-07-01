// Command accuracy-bench grades a corpus of benchmark manifests against a
// set of actual scan-result JSON files and emits a JSON + Markdown report.
//
// Typical usage:
//
//	accuracy-bench \
//	    -corpus backend/cmd/accuracy-bench/testdata/corpus \
//	    -actuals backend/cmd/accuracy-bench/testdata/actuals \
//	    -output-json out/report.json \
//	    -output-md out/report.md
//
// Optional delta gating (used by the nightly workflow to guard against
// probe regressions):
//
//	accuracy-bench -corpus ... -actuals ... \
//	    -baseline path/to/previous-report.json \
//	    -delta-output-md out/delta.md \
//	    -fail-on-regression -tolerance 0.02
//
// The CLI intentionally has no external dependencies (no HTTP, no
// database) so it can run hermetically in CI and locally.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"

	"auto-bughunter/backend/internal/accuracybench"
)

func main() {
	if err := run(os.Args[1:], os.Stdout, os.Stderr); err != nil {
		fmt.Fprintln(os.Stderr, "accuracy-bench:", err)
		os.Exit(1)
	}
}

func run(args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("accuracy-bench", flag.ContinueOnError)
	fs.SetOutput(stderr)
	corpusDir := fs.String("corpus", "", "path to directory of *.json manifests")
	actualsDir := fs.String("actuals", "", "path to directory of *.json actual-scan files")
	outputJSON := fs.String("output-json", "", "path to write the JSON report (default: stdout)")
	outputMD := fs.String("output-md", "", "path to write the markdown report (default: none)")
	baseline := fs.String("baseline", "", "path to a previous JSON report to diff against (optional)")
	deltaMD := fs.String("delta-output-md", "", "path to write the markdown delta report (requires -baseline)")
	tolerance := fs.Float64("tolerance", 0.0, "regression tolerance for -fail-on-regression (e.g. 0.02 = 2 percentage points)")
	failOnRegression := fs.Bool("fail-on-regression", false, "exit non-zero when the candidate regresses vs -baseline")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *corpusDir == "" {
		return fmt.Errorf("-corpus is required")
	}
	if *actualsDir == "" {
		return fmt.Errorf("-actuals is required")
	}

	corpus, err := accuracybench.LoadCorpus(*corpusDir)
	if err != nil {
		return err
	}
	actuals, err := accuracybench.LoadActuals(*actualsDir)
	if err != nil {
		return err
	}
	report := accuracybench.Grade(corpus, actuals)

	if err := writeReport(report, *outputJSON, stdout); err != nil {
		return err
	}
	if *outputMD != "" {
		if err := os.WriteFile(*outputMD, []byte(accuracybench.RenderMarkdown(report)), 0o644); err != nil {
			return fmt.Errorf("write markdown: %w", err)
		}
	}

	if *baseline != "" {
		base, err := loadReport(*baseline)
		if err != nil {
			return err
		}
		delta := accuracybench.DiffReports(base, report)
		regressions := delta.CheckRegressions(*tolerance)
		if *deltaMD != "" {
			if err := os.WriteFile(*deltaMD, []byte(accuracybench.RenderDeltaMarkdown(delta)), 0o644); err != nil {
				return fmt.Errorf("write delta markdown: %w", err)
			}
		}
		if regressions > 0 && *failOnRegression {
			return fmt.Errorf("%d regression(s) exceeded tolerance %v (see delta report)", regressions, *tolerance)
		}
	}
	return nil
}

func writeReport(r accuracybench.Report, path string, stdout io.Writer) error {
	if path == "" {
		return accuracybench.WriteJSON(stdout, r)
	}
	f, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("create report: %w", err)
	}
	defer f.Close()
	return accuracybench.WriteJSON(f, r)
}

func loadReport(path string) (accuracybench.Report, error) {
	var r accuracybench.Report
	data, err := os.ReadFile(path)
	if err != nil {
		return r, fmt.Errorf("read baseline: %w", err)
	}
	if err := json.Unmarshal(data, &r); err != nil {
		return r, fmt.Errorf("parse baseline: %w", err)
	}
	return r, nil
}
