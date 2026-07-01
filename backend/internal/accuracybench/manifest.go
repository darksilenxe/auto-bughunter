// Package accuracybench implements the Phase 0 accuracy ground-truth harness.
//
// It provides:
//
//   - A declarative manifest schema (Manifest, ExpectedFinding, SafeEndpoint)
//     that describes what a target is *supposed* to expose so that a scan run
//     can be graded objectively.
//   - A diff engine (Grade) that consumes a manifest plus the list of
//     model.Finding produced by an actual scan and emits per-category
//     precision / recall / F1 numbers plus scan-level pre-report verification
//     pass rate.
//   - A baseline delta helper (DiffReports) that lets CI gate probe changes
//     on "did precision/recall regress against the previous baseline?".
//
// The package intentionally has no dependencies on the scanner or the API
// layer so that it can be reused from the `accuracy-bench` CLI, the nightly
// workflow, unit tests, and any future in-process gating logic without
// pulling in transitive HTTP/database dependencies.
package accuracybench

import (
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"auto-bughunter/backend/internal/model"
)

// Manifest describes the ground truth for a single benchmark target.
//
// A benchmark corpus is a directory of Manifest JSON files, one per target.
// Each manifest lists:
//
//   - ExpectedFindings: vulnerabilities the scanner *must* discover. Missing
//     any of these counts as a false negative.
//   - SafeEndpoints: endpoint + category pairs the scanner *must not* report
//     on. Any finding whose (Category, AffectedURL) matches counts as a
//     false positive even if the manifest does not enumerate it explicitly.
//   - AllowedExtraCategories: categories where extra unexpected findings are
//     tolerated (e.g. informational best-practice signals) and therefore not
//     counted as false positives.
//
// Grading is category-partitioned: a finding is only compared to expected
// entries of the same normalized category. This keeps unrelated probes from
// masking each other's precision.
type Manifest struct {
	// Target is a human-readable label for the benchmark target, e.g.
	// "juice-shop" or "clean-json-api". Used in reports.
	Target string `json:"target"`
	// Description is optional prose describing the target.
	Description string `json:"description,omitempty"`
	// BaseURL is the deployed root URL of the benchmark target. Optional but
	// recommended so that reports can link back to the tested surface.
	BaseURL string `json:"baseUrl,omitempty"`
	// ExpectedFindings enumerates vulnerabilities that must be reported.
	ExpectedFindings []ExpectedFinding `json:"expectedFindings"`
	// SafeEndpoints enumerates endpoint+category pairs that must not be
	// reported. Any actual finding whose (Category, AffectedURL) matches an
	// entry is counted as a false positive.
	SafeEndpoints []SafeEndpoint `json:"safeEndpoints,omitempty"`
	// AllowedExtraCategories lists categories where extra unexpected
	// findings are ignored for precision computation. Useful for
	// informational categories where accuracy is not the goal.
	AllowedExtraCategories []string `json:"allowedExtraCategories,omitempty"`
}

// ExpectedFinding is a single row of ground truth: one vulnerability the
// scanner is expected to surface. Matching is deliberately permissive to
// avoid overfitting the harness to specific evidence strings.
type ExpectedFinding struct {
	Category        string         `json:"category"`
	Endpoint        string         `json:"endpoint"`
	Parameter       string         `json:"parameter,omitempty"`
	MinSeverity     model.Severity `json:"minSeverity,omitempty"`
	Description     string         `json:"description,omitempty"`
	OptionalContext string         `json:"optionalContext,omitempty"`
}

// SafeEndpoint marks an endpoint+category pair that must not produce a
// finding. If Parameter is set, only findings for that specific parameter
// count as false positives; otherwise all findings on the endpoint do.
type SafeEndpoint struct {
	Category  string `json:"category"`
	Endpoint  string `json:"endpoint"`
	Parameter string `json:"parameter,omitempty"`
	Note      string `json:"note,omitempty"`
}

// LoadManifest reads a manifest file from disk.
func LoadManifest(path string) (Manifest, error) {
	var m Manifest
	data, err := os.ReadFile(path)
	if err != nil {
		return m, fmt.Errorf("read manifest %s: %w", path, err)
	}
	if err := json.Unmarshal(data, &m); err != nil {
		return m, fmt.Errorf("parse manifest %s: %w", path, err)
	}
	if strings.TrimSpace(m.Target) == "" {
		m.Target = strings.TrimSuffix(filepath.Base(path), filepath.Ext(path))
	}
	return m, nil
}

// LoadCorpus loads every *.json file directly inside dir as a Manifest and
// returns them sorted by target name. Non-JSON files are ignored so that a
// README.md can live alongside the corpus.
func LoadCorpus(dir string) ([]Manifest, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("read corpus dir %s: %w", dir, err)
	}
	var out []Manifest
	for _, e := range entries {
		if e.IsDir() || !strings.EqualFold(filepath.Ext(e.Name()), ".json") {
			continue
		}
		m, err := LoadManifest(filepath.Join(dir, e.Name()))
		if err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Target < out[j].Target })
	return out, nil
}

// ActualScan bundles the findings produced by one scan of a single target
// along with the pre-report verification signal we want to grade against.
type ActualScan struct {
	// Target must match the Target field of the corresponding Manifest.
	Target string `json:"target"`
	// Findings is the list of findings the scanner produced.
	Findings []model.Finding `json:"findings"`
	// PreReportVerificationPassRate is the fraction (0..1) of high/critical
	// findings that passed pre-report verification during the scan. Set to
	// -1 when unknown so grading can distinguish "not measured" from
	// "measured as zero".
	PreReportVerificationPassRate float64 `json:"preReportVerificationPassRate"`
}

// LoadActuals reads a directory of *.json files each containing an
// ActualScan. Convention: one file per target, filename equal to
// "<target>.json".
func LoadActuals(dir string) (map[string]ActualScan, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("read actuals dir %s: %w", dir, err)
	}
	out := make(map[string]ActualScan)
	for _, e := range entries {
		if e.IsDir() || !strings.EqualFold(filepath.Ext(e.Name()), ".json") {
			continue
		}
		path := filepath.Join(dir, e.Name())
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("read actual %s: %w", path, err)
		}
		var a ActualScan
		if err := json.Unmarshal(data, &a); err != nil {
			return nil, fmt.Errorf("parse actual %s: %w", path, err)
		}
		if strings.TrimSpace(a.Target) == "" {
			a.Target = strings.TrimSuffix(e.Name(), filepath.Ext(e.Name()))
		}
		out[a.Target] = a
	}
	return out, nil
}

// WriteJSON marshals v as pretty JSON to w.
func WriteJSON(w io.Writer, v any) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

// normalizeCategory folds a category string to its canonical form for
// matching. Categories in the codebase are inconsistent (e.g. "sqli" vs
// "SQL Injection" vs "sql_injection"); we collapse whitespace, punctuation
// and case so that comparisons stay stable.
func normalizeCategory(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	if s == "" {
		return ""
	}
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			b.WriteRune(r)
		default:
			// drop separators; "sql-injection" and "sql injection" both fold to "sqlinjection"
		}
	}
	return b.String()
}

// normalizeEndpoint canonicalises an endpoint for matching. It strips the
// scheme+host (so manifests can be host-agnostic), collapses trailing
// slashes, lowercases the path, and drops the query string except for
// parameter *names* — the actual values change per scan.
func normalizeEndpoint(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	// If it parses as a URL, keep only the path. If it doesn't (e.g. the
	// manifest already stores a bare path), treat the whole string as a
	// path.
	path := s
	if u, err := url.Parse(s); err == nil && u.Path != "" {
		path = u.Path
	} else if err == nil && u.Opaque != "" {
		path = u.Opaque
	}
	path = strings.ToLower(path)
	if path != "/" {
		path = strings.TrimRight(path, "/")
	}
	if path == "" {
		path = "/"
	}
	return path
}

// normalizeParameter lowercases and trims a parameter name for matching.
// Empty means "any parameter on the endpoint".
func normalizeParameter(s string) string {
	return strings.ToLower(strings.TrimSpace(s))
}
