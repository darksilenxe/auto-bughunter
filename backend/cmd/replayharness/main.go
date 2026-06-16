// Command replayharness runs the offline planner replay harness.
//
// It reads a JSON file containing one or more historical scans (see
// replay.HistoricalRun) and replays them through a baseline planner and a
// candidate planner, emitting a baseline-comparison JSON report to stdout or
// to the path supplied via -output.
//
// The supported planner kinds are intentionally limited to ones that need no
// external dependencies so the harness can run hermetically in CI:
//
//	static   - StaticPlanner over the run's AvailableAgents (default baseline).
//	recorded - StaticPlanner over the recorded execution order; acts as an
//	           oracle that always reproduces the historical scan.
//
// Example:
//
//	go run ./backend/cmd/replayharness \
//	    -input testdata/history.json \
//	    -baseline static -candidate recorded \
//	    -output /tmp/replay-report.json
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"

	"auto-bughunter/backend/internal/replay"
)

type gateOptions struct {
	minCandidateMatchRate       float64
	minCandidateFirstChoiceRate float64
	maxCandidateEarlyStops      int
	requireCandidateNotWorse    bool
}

func main() {
	if err := run(os.Args[1:], os.Stdout, os.Stderr); err != nil {
		fmt.Fprintln(os.Stderr, "replayharness:", err)
		os.Exit(1)
	}
}

func run(args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("replayharness", flag.ContinueOnError)
	fs.SetOutput(stderr)
	input := fs.String("input", "", "path to historical-runs JSON file (use '-' for stdin)")
	output := fs.String("output", "", "path to write the comparison report (defaults to stdout)")
	baselineKind := fs.String("baseline", "static", "baseline planner kind: static|recorded")
	candidateKind := fs.String("candidate", "recorded", "candidate planner kind: static|recorded")
	minCandidateMatchRate := fs.Float64("min-candidate-match-rate", -1, "optional floor for candidate aggregate match rate (0..1)")
	minCandidateFirstChoiceRate := fs.Float64("min-candidate-first-choice-rate", -1, "optional floor for candidate aggregate first-choice match rate (0..1)")
	maxCandidateEarlyStops := fs.Int("max-candidate-early-stops", -1, "optional ceiling for candidate early-stop count")
	requireCandidateNotWorse := fs.Bool("require-candidate-not-worse", false, "when set, fail if candidate aggregate rates regress versus baseline")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *input == "" {
		fs.Usage()
		return fmt.Errorf("-input is required")
	}

	runs, err := loadRuns(*input)
	if err != nil {
		return fmt.Errorf("load input: %w", err)
	}

	baseline, err := plannerFactory(*baselineKind)
	if err != nil {
		return fmt.Errorf("baseline: %w", err)
	}
	candidate, err := plannerFactory(*candidateKind)
	if err != nil {
		return fmt.Errorf("candidate: %w", err)
	}

	report, err := replay.Compare(context.Background(), runs, *baselineKind, baseline, *candidateKind, candidate)
	if err != nil {
		return err
	}
	if err := validateGates(report, gateOptions{
		minCandidateMatchRate:       *minCandidateMatchRate,
		minCandidateFirstChoiceRate: *minCandidateFirstChoiceRate,
		maxCandidateEarlyStops:      *maxCandidateEarlyStops,
		requireCandidateNotWorse:    *requireCandidateNotWorse,
	}); err != nil {
		return err
	}

	encoded, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return fmt.Errorf("encode report: %w", err)
	}
	encoded = append(encoded, '\n')

	if *output == "" {
		_, err = stdout.Write(encoded)
		return err
	}
	return os.WriteFile(*output, encoded, 0o644)
}

func loadRuns(path string) ([]replay.HistoricalRun, error) {
	var data []byte
	var err error
	if path == "-" {
		data, err = io.ReadAll(os.Stdin)
	} else {
		data, err = os.ReadFile(path)
	}
	if err != nil {
		return nil, err
	}
	// Accept either a single object or an array for caller convenience.
	trimmed := skipWhitespace(data)
	if len(trimmed) > 0 && trimmed[0] == '{' {
		var single replay.HistoricalRun
		if err := json.Unmarshal(data, &single); err != nil {
			return nil, err
		}
		return []replay.HistoricalRun{single}, nil
	}
	var runs []replay.HistoricalRun
	if err := json.Unmarshal(data, &runs); err != nil {
		return nil, err
	}
	return runs, nil
}

func skipWhitespace(data []byte) []byte {
	for i, b := range data {
		switch b {
		case ' ', '\t', '\n', '\r':
			continue
		default:
			return data[i:]
		}
	}
	return nil
}

func plannerFactory(kind string) (replay.PlannerFactory, error) {
	switch kind {
	case "static":
		return replay.StaticPlannerFactory(), nil
	case "recorded":
		return replay.RecordedOrderPlannerFactory(), nil
	default:
		return nil, fmt.Errorf("unknown planner kind %q (supported: static, recorded)", kind)
	}
}

func validateGates(report replay.ComparisonReport, gates gateOptions) error {
	if gates.minCandidateMatchRate >= 0 {
		if report.Candidate.AggregateMatchRate < gates.minCandidateMatchRate {
			return fmt.Errorf(
				"candidate aggregate match rate %.4f is below required floor %.4f",
				report.Candidate.AggregateMatchRate,
				gates.minCandidateMatchRate,
			)
		}
	}
	if gates.minCandidateFirstChoiceRate >= 0 {
		if report.Candidate.AggregateFirstChoiceMatchRate < gates.minCandidateFirstChoiceRate {
			return fmt.Errorf(
				"candidate aggregate first-choice match rate %.4f is below required floor %.4f",
				report.Candidate.AggregateFirstChoiceMatchRate,
				gates.minCandidateFirstChoiceRate,
			)
		}
	}
	if gates.maxCandidateEarlyStops >= 0 {
		if report.Candidate.EarlyStops > gates.maxCandidateEarlyStops {
			return fmt.Errorf(
				"candidate early stops %d exceed max allowed %d",
				report.Candidate.EarlyStops,
				gates.maxCandidateEarlyStops,
			)
		}
	}
	if gates.requireCandidateNotWorse {
		if report.Candidate.AggregateMatchRate < report.Baseline.AggregateMatchRate {
			return fmt.Errorf(
				"candidate aggregate match rate %.4f regressed from baseline %.4f",
				report.Candidate.AggregateMatchRate,
				report.Baseline.AggregateMatchRate,
			)
		}
		if report.Candidate.AggregateFirstChoiceMatchRate < report.Baseline.AggregateFirstChoiceMatchRate {
			return fmt.Errorf(
				"candidate aggregate first-choice match rate %.4f regressed from baseline %.4f",
				report.Candidate.AggregateFirstChoiceMatchRate,
				report.Baseline.AggregateFirstChoiceMatchRate,
			)
		}
	}
	return nil
}
