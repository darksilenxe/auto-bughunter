package scanner

import (
	"testing"

	"auto-bughunter/backend/internal/model"
)

// zap-baseline.py always prints a summary footer that lists every marker bucket
// (FAIL-NEW, FAIL-INPROG, WARN-NEW, WARN-INPROG, ...) even when their counts are
// zero. The parser must read the numeric counts, not the label headers.
const zapCleanOutput = `2024-01-01 PASS: Vulnerable JS Library [10003]
PASS: In Page Banner Information Leak [10009]
WARN-NEW: Cross-Domain JavaScript Source File Inclusion [10017] x 3
	http://example.com (200 OK)
FAIL-NEW: 0	FAIL-INPROG: 0	WARN-NEW: 1	WARN-INPROG: 0	INFO: 0	IGNORE: 0	PASS: 48`

const zapFailOutput = `FAIL-NEW: Content Security Policy (CSP) Header Not Set [10038] x 2
	http://example.com (200 OK)
WARN-NEW: Cross-Domain JavaScript Source File Inclusion [10017] x 3
FAIL-NEW: 2	FAIL-INPROG: 0	WARN-NEW: 1	WARN-INPROG: 0	INFO: 0	IGNORE: 0	PASS: 40`

func TestCountZAPBaselineMarkers_FooterHeadersNotCounted(t *testing.T) {
	fails, warns := countZAPBaselineMarkers(zapCleanOutput)
	if fails != 0 {
		t.Fatalf("expected 0 fail markers, got %d", fails)
	}
	if warns != 1 {
		t.Fatalf("expected 1 warn marker, got %d", warns)
	}
}

func TestCountZAPBaselineMarkers_RealFails(t *testing.T) {
	fails, warns := countZAPBaselineMarkers(zapFailOutput)
	if fails != 2 {
		t.Fatalf("expected 2 fail markers, got %d", fails)
	}
	if warns != 1 {
		t.Fatalf("expected 1 warn marker, got %d", warns)
	}
}

func TestCountZAPBaselineMarkers_NoFooterFallback(t *testing.T) {
	// Truncated output with no summary footer: count per-alert lines.
	out := "WARN-NEW: Cross-Domain JavaScript Source File Inclusion [10017] x 3\nFAIL-NEW: CSP Header Not Set [10038] x 1\n"
	fails, warns := countZAPBaselineMarkers(out)
	if fails != 1 {
		t.Fatalf("expected 1 fail marker, got %d", fails)
	}
	if warns != 1 {
		t.Fatalf("expected 1 warn marker, got %d", warns)
	}
}

func TestBuildZAPBaselineFinding_CleanRunIsInfo(t *testing.T) {
	// zap-baseline.py exits non-zero when warnings exist, but a clean footer
	// (zero fails) must not produce a High-severity fail-markers finding.
	findings := buildZAPBaselineFinding(zapCleanOutput, "", 1, "")
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].Severity == model.SeverityHigh {
		t.Fatalf("clean ZAP run must not be High severity, got %s", findings[0].Severity)
	}
	if findings[0].Severity != model.SeverityMedium {
		t.Fatalf("expected Medium severity for warn markers, got %s", findings[0].Severity)
	}
}

func TestBuildZAPBaselineFinding_RealFailIsHigh(t *testing.T) {
	findings := buildZAPBaselineFinding(zapFailOutput, "", 1, "")
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].Severity != model.SeverityHigh {
		t.Fatalf("expected High severity for fail markers, got %s", findings[0].Severity)
	}
}
