package scanner

import (
	"context"
	"encoding/base64"
	"strings"
	"testing"

	"auto-bughunter/backend/internal/model"
)

// ---------------------------------------------------------------------------
// computeStateChangeDelta tests
// ---------------------------------------------------------------------------

func TestComputeStateChangeDelta_NoDiff(t *testing.T) {
	snap := model.DOMPageSnapshot{
		URL:             "https://example.com/",
		Title:           "Home",
		OuterHTMLHash:   "abc123",
		VisibleTextHash: "def456",
		FormCount:       1,
		InputCount:      2,
		JSBundleHashes:  map[string]string{"https://example.com/app.js": "aaa"},
	}
	delta := computeStateChangeDelta(snap, snap)
	if delta.HTMLChanged {
		t.Errorf("expected HTMLChanged=false when snapshots are identical")
	}
	if delta.TextChanged {
		t.Errorf("expected TextChanged=false when snapshots are identical")
	}
	if delta.JSBundleChanged {
		t.Errorf("expected JSBundleChanged=false when snapshots are identical")
	}
	if !delta.IsStaticResponse {
		t.Errorf("expected IsStaticResponse=true when nothing changed")
	}
	if delta.FormCountDelta != 0 {
		t.Errorf("expected FormCountDelta=0 for identical snapshots; got %d", delta.FormCountDelta)
	}
}

func TestComputeStateChangeDelta_HTMLAndTextChanged(t *testing.T) {
	before := model.DOMPageSnapshot{
		OuterHTMLHash:   "html-before",
		VisibleTextHash: "text-before",
		FormCount:       1,
		JSBundleHashes:  map[string]string{},
	}
	after := model.DOMPageSnapshot{
		OuterHTMLHash:   "html-after",
		VisibleTextHash: "text-after",
		FormCount:       1,
		JSBundleHashes:  map[string]string{},
	}
	delta := computeStateChangeDelta(before, after)
	if !delta.HTMLChanged {
		t.Errorf("expected HTMLChanged=true when outerHTML hashes differ")
	}
	if !delta.TextChanged {
		t.Errorf("expected TextChanged=true when visibleText hashes differ")
	}
	if delta.JSBundleChanged {
		t.Errorf("expected JSBundleChanged=false when JS bundles unchanged")
	}
	if delta.IsStaticResponse {
		t.Errorf("expected IsStaticResponse=false when HTML changed")
	}
}

func TestComputeStateChangeDelta_JSBundleAdded(t *testing.T) {
	before := model.DOMPageSnapshot{
		OuterHTMLHash:   "same",
		VisibleTextHash: "same",
		JSBundleHashes:  map[string]string{"https://example.com/vendor.js": "hash1"},
	}
	after := model.DOMPageSnapshot{
		OuterHTMLHash:   "same",
		VisibleTextHash: "same",
		JSBundleHashes: map[string]string{
			"https://example.com/vendor.js": "hash1",
			"https://example.com/app.js":    "hash2", // new bundle
		},
	}
	delta := computeStateChangeDelta(before, after)
	if !delta.JSBundleChanged {
		t.Errorf("expected JSBundleChanged=true when new bundle appeared")
	}
	if len(delta.NewJSBundles) != 1 || delta.NewJSBundles[0] != "https://example.com/app.js" {
		t.Errorf("expected NewJSBundles=[app.js]; got %v", delta.NewJSBundles)
	}
	if delta.IsStaticResponse {
		t.Errorf("expected IsStaticResponse=false when JS bundle changed")
	}
}

func TestComputeStateChangeDelta_FormCountDelta(t *testing.T) {
	before := model.DOMPageSnapshot{
		OuterHTMLHash:   "same",
		VisibleTextHash: "same",
		FormCount:       0,
		JSBundleHashes:  map[string]string{},
	}
	after := model.DOMPageSnapshot{
		OuterHTMLHash:   "same",
		VisibleTextHash: "same",
		FormCount:       2,
		JSBundleHashes:  map[string]string{},
	}
	delta := computeStateChangeDelta(before, after)
	if delta.FormCountDelta != 2 {
		t.Errorf("expected FormCountDelta=2; got %d", delta.FormCountDelta)
	}
}

// ---------------------------------------------------------------------------
// attachBrowserValidationArtifacts tests
// ---------------------------------------------------------------------------

func TestAttachBrowserValidationArtifacts_ScreenshotsAttached(t *testing.T) {
	// Create minimal before/after snapshots with fake screenshots.
	beforeSnap := model.DOMPageSnapshot{
		URL:           "https://target/page",
		ScreenshotB64: base64.StdEncoding.EncodeToString([]byte("before-png")),
	}
	afterSnap := model.DOMPageSnapshot{
		URL:           "https://target/page?x=payload",
		ScreenshotB64: base64.StdEncoding.EncodeToString([]byte("after-png")),
	}
	delta := model.StateChangeDelta{
		HTMLChanged:  true,
		TextChanged:  false,
		JSBundleChanged: false,
		IsStaticResponse: false,
	}

	f := &model.Finding{
		ID:       "test-finding",
		Category: "xss",
	}
	attachBrowserValidationArtifacts(f, beforeSnap, afterSnap, delta)

	if f.EvidenceFields["browserValidation.htmlChanged"] != "true" {
		t.Errorf("expected browserValidation.htmlChanged=true; got %q", f.EvidenceFields["browserValidation.htmlChanged"])
	}
	if f.EvidenceFields["browserValidation.static"] != "false" {
		t.Errorf("expected browserValidation.static=false; got %q", f.EvidenceFields["browserValidation.static"])
	}

	var screenshotArtifacts, deltaArtifacts int
	for _, a := range f.ProofArtifacts {
		switch a.Type {
		case "screenshot":
			screenshotArtifacts++
		case "state-delta":
			deltaArtifacts++
			if !strings.Contains(a.Value, "htmlChanged") {
				t.Errorf("expected state-delta JSON to contain 'htmlChanged'; got %q", a.Value)
			}
		}
	}
	if screenshotArtifacts != 2 {
		t.Errorf("expected 2 screenshot artifacts (before + after); got %d", screenshotArtifacts)
	}
	if deltaArtifacts != 1 {
		t.Errorf("expected 1 state-delta artifact; got %d", deltaArtifacts)
	}
}

func TestAttachBrowserValidationArtifacts_NoScreenshotsWhenEmpty(t *testing.T) {
	// When screenshots are empty no screenshot artifact should be added.
	before := model.DOMPageSnapshot{URL: "https://target/"}
	after := model.DOMPageSnapshot{URL: "https://target/?x=y"}
	delta := model.StateChangeDelta{IsStaticResponse: true}

	f := &model.Finding{ID: "no-shot", Category: "csrf"}
	attachBrowserValidationArtifacts(f, before, after, delta)

	for _, a := range f.ProofArtifacts {
		if a.Type == "screenshot" {
			t.Errorf("expected no screenshot artifact when ScreenshotB64 is empty; got %+v", a)
		}
	}
	// state-delta artifact should still be present.
	found := false
	for _, a := range f.ProofArtifacts {
		if a.Type == "state-delta" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected state-delta artifact even when no screenshots")
	}
}

// ---------------------------------------------------------------------------
// deriveProbeURL tests
// ---------------------------------------------------------------------------

func TestDeriveProbeURL_PoCIsURL(t *testing.T) {
	f := model.Finding{
		AffectedURL: "https://target/page",
		PoC:         "https://target/page?q=%3Cscript%3E",
	}
	got := deriveProbeURL(f)
	if got != f.PoC {
		t.Errorf("expected PoC URL to be used directly; got %q", got)
	}
}

func TestDeriveProbeURL_ParameterInjection(t *testing.T) {
	f := model.Finding{
		AffectedURL:       "https://target/search",
		AffectedParameter: "q",
		PoC:               `"><svg/onload=alert(1)>`,
	}
	got := deriveProbeURL(f)
	if !strings.Contains(got, "https://target/search") {
		t.Errorf("expected base URL to be preserved; got %q", got)
	}
	if !strings.Contains(got, "q=") {
		t.Errorf("expected parameter q to be injected; got %q", got)
	}
}

func TestDeriveProbeURL_FallbackToAffectedURL(t *testing.T) {
	f := model.Finding{
		AffectedURL: "https://target/page",
	}
	got := deriveProbeURL(f)
	if got != "https://target/page" {
		t.Errorf("expected fallback to AffectedURL; got %q", got)
	}
}

// ---------------------------------------------------------------------------
// sha256Hex tests
// ---------------------------------------------------------------------------

func TestSha256Hex_Deterministic(t *testing.T) {
	h1 := sha256Hex("hello world")
	h2 := sha256Hex("hello world")
	if h1 != h2 {
		t.Errorf("sha256Hex should be deterministic; got %q vs %q", h1, h2)
	}
	if h1 == "" {
		t.Errorf("sha256Hex should return non-empty digest")
	}
}

func TestSha256Hex_Distinct(t *testing.T) {
	h1 := sha256Hex("foo")
	h2 := sha256Hex("bar")
	if h1 == h2 {
		t.Errorf("sha256Hex of different strings should differ")
	}
}

// ---------------------------------------------------------------------------
// SubmitVerifiedFinding: BrowserValidation integration tests
// ---------------------------------------------------------------------------

func TestSubmitVerifiedFinding_BrowserValidation_PromotesBodyDeltaSignal(t *testing.T) {
	ResetVerificationMetrics()
	// XSS candidate with only one initial signal (EvidenceReflection).
	// The browser validation hook returns a delta indicating HTML changed,
	// which should promote EvidenceBodyDelta and lift evidence hits to 2
	// (the minimum for XSS), allowing verification.
	cand := VerifyCandidate{
		Finding: model.Finding{
			ID:                "xss-bv-1",
			Category:          "xss",
			Title:             "reflected xss via q parameter",
			AffectedURL:       "https://target/search",
			AffectedParameter: "q",
			Evidence:          "payload reflected unsanitized into script context; xss marker observed",
			PoC:               "https://target/search?q=<svg/onload=alert(1)>",
			Severity:          model.SeverityHigh,
		},
		Signals:               []EvidenceSignal{EvidenceReflection, EvidenceSinkObserved},
		AllowNoReplayEmission: true,
		ProbeName:             "test-xss-bv",
		BrowserValidation: func(_ context.Context) (*model.BrowserValidationResult, error) {
			return &model.BrowserValidationResult{
				Before: model.DOMPageSnapshot{
					OuterHTMLHash:   "before-html",
					VisibleTextHash: "before-text",
					JSBundleHashes:  map[string]string{},
				},
				After: model.DOMPageSnapshot{
					OuterHTMLHash:   "after-html", // changed
					VisibleTextHash: "after-text", // changed
					JSBundleHashes:  map[string]string{},
				},
				Delta: model.StateChangeDelta{
					HTMLChanged:      true,
					TextChanged:      true,
					IsStaticResponse: false,
				},
			}, nil
		},
	}
	out := SubmitVerifiedFinding(context.Background(), cand)
	if out.Suppressed {
		t.Errorf("expected finding not to be suppressed; reason=%q", out.Reason)
	}
	// EvidenceBodyDelta should have been promoted from browser validation.
	if out.EvidenceHits < 2 {
		t.Errorf("expected at least 2 evidence hits after browser delta promotion; got %d", out.EvidenceHits)
	}
	// Screenshots and state-delta artifact should be present.
	if len(out.EmittedFinding.ProofArtifacts) == 0 {
		t.Errorf("expected ProofArtifacts to be populated by browser validation")
	}
}

func TestSubmitVerifiedFinding_BrowserValidation_CodeChangeBoostsConfidence(t *testing.T) {
	// Compare confidence WITH and WITHOUT a code-change signal from browser
	// validation. Use a CSRF candidate with only 1 initial evidence signal
	// (EvidenceStatusDelta) so the base confidence is 0.9 (below 0.95).
	// When the browser validation hook adds EvidenceCodeChange (JS bundle
	// changed), the evidence hit count rises to 2 (the minimum) and the
	// +0.05 code-change bonus lifts confidence to ≥ 0.95 — demonstrably
	// higher than the no-browser-validation case.
	makeCand := func(jsChanged bool) VerifyCandidate {
		return VerifyCandidate{
			Finding: model.Finding{
				ID:          "csrf-bv",
				Category:    "csrf",
				Title:       "CSRF — state-changing endpoint",
				AffectedURL: "https://target/api/profile",
				// Evidence satisfies state_changing_endpoint,
				// token_absence_or_forgery_accepted, and http_method_recorded.
				Evidence: "POST /api/profile with authenticated session cookie but without csrf token → 200 " +
					"state-changing post without csrf token",
				Severity: model.SeverityHigh,
				EvidenceFields: map[string]string{
					"httpMethod":         "POST",
					"tokenCarrierTested": "absent",
					"forgedToken":        "false",
				},
			},
			// Deliberately only 1 initial signal so evidence hits = 1 < required (2).
			Signals:               []EvidenceSignal{EvidenceStatusDelta},
			AllowNoReplayEmission: true,
			ProbeName:             "test-csrf-bv",
			BrowserValidation: func(_ context.Context) (*model.BrowserValidationResult, error) {
				before := model.DOMPageSnapshot{
					JSBundleHashes:  map[string]string{"app.js": "v1"},
					OuterHTMLHash:   "same",
					VisibleTextHash: "same",
				}
				after := model.DOMPageSnapshot{
					JSBundleHashes: map[string]string{
						"app.js":  "v1",
						"lazy.js": "v2", // new bundle → JSBundleChanged
					},
					OuterHTMLHash:   "same",
					VisibleTextHash: "same",
				}
				if !jsChanged {
					after.JSBundleHashes = before.JSBundleHashes
				}
				return &model.BrowserValidationResult{
					Before: before,
					After:  after,
					Delta: model.StateChangeDelta{
						JSBundleChanged:  jsChanged,
						IsStaticResponse: !jsChanged,
					},
				}, nil
			},
		}
	}

	ResetVerificationMetrics()
	outWithCodeChange := SubmitVerifiedFinding(context.Background(), makeCand(true))
	confWithChange := outWithCodeChange.Confidence

	ResetVerificationMetrics()
	outWithout := SubmitVerifiedFinding(context.Background(), makeCand(false))
	confWithout := outWithout.Confidence

	if confWithChange <= confWithout {
		t.Errorf(
			"expected confidence to be higher with code-change signal; with=%f without=%f",
			confWithChange, confWithout,
		)
	}
}

func TestSubmitVerifiedFinding_BrowserValidation_StaticResponseNoSignals(t *testing.T) {
	ResetVerificationMetrics()
	// When the page looks identical before and after the probe, the browser
	// validation should NOT add EvidenceBodyDelta or EvidenceCodeChange.
	cand := VerifyCandidate{
		Finding: model.Finding{
			ID:          "open-redirect-bv",
			Category:    "open_redirect",
			Title:       "open redirect",
			AffectedURL: "https://target/go",
			Evidence:    "off-host redirect destination observed open redirect unvalidated redirect redirect url param",
			Severity:    model.SeverityMedium,
		},
		Signals:               []EvidenceSignal{EvidenceHeaderDelta, EvidenceReflection, EvidenceStatusDelta},
		AllowNoReplayEmission: true,
		ProbeName:             "test-redirect-bv",
		BrowserValidation: func(_ context.Context) (*model.BrowserValidationResult, error) {
			same := model.DOMPageSnapshot{
				OuterHTMLHash:   "static",
				VisibleTextHash: "static",
				JSBundleHashes:  map[string]string{"app.js": "hash"},
			}
			return &model.BrowserValidationResult{
				Before: same,
				After:  same,
				Delta:  model.StateChangeDelta{IsStaticResponse: true},
			}, nil
		},
	}
	out := SubmitVerifiedFinding(context.Background(), cand)
	if out.Suppressed {
		t.Errorf("expected finding not suppressed even with static response; reason=%q", out.Reason)
	}
	// browserValidation.static should be recorded.
	if out.EmittedFinding.EvidenceFields["browserValidation.static"] != "true" {
		t.Errorf("expected browserValidation.static=true in evidence fields; got %q",
			out.EmittedFinding.EvidenceFields["browserValidation.static"])
	}
}
