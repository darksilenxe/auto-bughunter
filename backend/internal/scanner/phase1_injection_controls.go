package scanner

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"auto-bughunter/backend/internal/model"
)

func phase1ReadSample(resp *http.Response, limit int64, duration time.Duration) BaselineSample {
	if resp == nil {
		return BaselineSample{Duration: duration}
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, limit))
	_ = resp.Body.Close()
	return BaselineSample{Status: resp.StatusCode, Header: resp.Header, Body: string(body), Duration: duration}
}

func (s *Service) phase1GETSample(ctx context.Context, rawURL string, input RunInput, limit int64) (BaselineSample, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return BaselineSample{}, err
	}
	ApplyAuthProfile(req, input.AuthProfile)
	start := time.Now()
	resp, err := s.doRequestWithRetry(ctx, req, input.Options)
	dur := time.Since(start)
	if err != nil || resp == nil {
		return BaselineSample{}, err
	}
	return phase1ReadSample(resp, limit, dur), nil
}

func phase1QueryURL(rawURL, param, value string, set bool) (string, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return "", err
	}
	q := u.Query()
	if set {
		q.Set(param, value)
	} else {
		q.Del(param)
	}
	u.RawQuery = q.Encode()
	return u.String(), nil
}

func (s *Service) phase1QueryBaselines(ctx context.Context, rawURL, param, value string, set bool, input RunInput, limit int64) (BaselineControls, error) {
	return CaptureTwoControlBaselines(ctx, func(bctx context.Context) (BaselineSample, error) {
		cleanURL, err := phase1QueryURL(rawURL, param, value, set)
		if err != nil {
			return BaselineSample{}, err
		}
		return s.phase1GETSample(bctx, cleanURL, input, limit)
	})
}

func phase1BaselineContains(b BaselineControls, needles ...string) bool {
	for _, needle := range needles {
		if needle == "" {
			continue
		}
		if strings.Contains(b.First.Body, needle) || strings.Contains(b.Second.Body, needle) {
			return true
		}
	}
	return false
}

func phase1DifferentialQuery(ctx context.Context, s *Service, input RunInput, probeName, rawURL, param, originalPayload, safePayload string, limit int64, oracle DifferentialOracle) DifferentialReVerifyOutcome {
	return DifferentialReVerify(ctx, DifferentialReVerifyInput{
		ProbeName:       probeName,
		OriginalPayload: originalPayload,
		SafePayload:     safePayload,
		Exec: func(dctx context.Context, altPayload string) (*http.Response, []byte, error) {
			cleanURL, err := phase1QueryURL(rawURL, param, altPayload, true)
			if err != nil {
				return nil, nil, err
			}
			req, err := http.NewRequestWithContext(dctx, http.MethodGet, cleanURL, nil)
			if err != nil {
				return nil, nil, err
			}
			ApplyAuthProfile(req, input.AuthProfile)
			resp, err := s.doRequestWithRetry(dctx, req, input.Options)
			if err != nil || resp == nil {
				return nil, nil, err
			}
			body, _ := io.ReadAll(io.LimitReader(resp.Body, limit))
			return resp, body, nil
		},
		Oracle: oracle,
	})
}

func phase1SubmitVerified(ctx context.Context, finding model.Finding, canonicalCategory string, signals []EvidenceSignal, probeName string) (model.Finding, bool) {
	originalCategory := finding.Category
	finding.Category = canonicalCategory
	out := SubmitVerifiedFinding(ctx, VerifyCandidate{
		Finding:               finding,
		Signals:               signals,
		AllowNoReplayEmission: true,
		ProbeName:             probeName,
	})
	if out.Suppressed {
		return model.Finding{}, false
	}
	emitted := out.EmittedFinding
	emitted.Category = originalCategory
	return emitted, true
}

func phase1TimingExceeds(observed, b1, b2 time.Duration) bool {
	median := b1
	if b2 < median {
		median = b2
	}
	if observed < median*2+time.Second {
		return false
	}
	return ExceedsControlVariance(float64((observed - median).Milliseconds()), float64(absInt(int(b1.Milliseconds()-b2.Milliseconds()))))
}

func phase1POSTSample(ctx context.Context, s *Service, url, contentType, body string, input RunInput, limit int64) (BaselineSample, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, strings.NewReader(body))
	if err != nil {
		return BaselineSample{}, err
	}
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	ApplyAuthProfile(req, input.AuthProfile)
	start := time.Now()
	resp, err := s.doRequestWithRetry(ctx, req, input.Options)
	dur := time.Since(start)
	if err != nil || resp == nil {
		return BaselineSample{}, err
	}
	return phase1ReadSample(resp, limit, dur), nil
}

func phase1FormatBaselineMs(b BaselineControls) string {
	return fmt.Sprintf("%d,%d", b.First.Duration.Milliseconds(), b.Second.Duration.Milliseconds())
}

func mustPhase1QueryURL(rawURL, param, value string) string {
	out, err := phase1QueryURL(rawURL, param, value, true)
	if err != nil {
		return rawURL
	}
	return out
}
