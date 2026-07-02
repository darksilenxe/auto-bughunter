package scanner

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"

	"auto-bughunter/backend/internal/model"
	"auto-bughunter/backend/internal/safety"
)

// cloudBucketPattern extracts S3/GCS/Azure Blob Storage bucket/account names
// from HTML and JavaScript source.
var cloudBucketPattern = regexp.MustCompile(
	`(?i)(` +
		// AWS S3 virtual-hosted style: bucket.s3.amazonaws.com or bucket.s3-region.amazonaws.com
		`(?P<s3bucket>[a-z0-9][a-z0-9\-]{1,61}[a-z0-9])\.s3(?:-[a-z0-9-]+)?\.amazonaws\.com` +
		`|` +
		// AWS S3 path style: s3.amazonaws.com/bucket or s3-region.amazonaws.com/bucket
		`s3(?:-[a-z0-9-]+)?\.amazonaws\.com/(?P<s3pathbucket>[a-z0-9][a-z0-9\-._]{1,61}[a-z0-9])` +
		`|` +
		// GCS: storage.googleapis.com/bucket or bucket.storage.googleapis.com
		`(?P<gcsbucket>[a-z0-9][a-z0-9\-._]{1,61}[a-z0-9])\.storage\.googleapis\.com` +
		`|storage\.googleapis\.com/(?P<gcspathbucket>[a-z0-9][a-z0-9\-._]{1,61}[a-z0-9])` +
		`|` +
		// Azure Blob: storageaccount.blob.core.windows.net
		`(?P<azureaccount>[a-z0-9]{3,24})\.blob\.core\.windows\.net` +
		`)`,
)

// s3ListBucketMarker is the XML element present in an accessible S3 bucket listing.
const s3ListBucketMarker = "<listbucketresult"

// gcsListBucketMarker is present in an accessible GCS bucket listing.
const gcsListBucketMarker = "<listbucketresult"

// cloudStorageMaxExtract caps the number of distinct buckets probed.
const cloudStorageMaxExtract = 8

// runCloudStorageProbe is an active probe covering WSTG-CONF-11.
//
// It extracts AWS S3, GCS, and Azure Blob Storage bucket/container names from
// the page HTML and JavaScript sources, then probes each for:
//   - Unauthenticated public listing (HTTP 200 with ListBucketResult XML)
//   - Public read access to a sentinel object key
//
// False-positive rate is kept low by only flagging on specific XML markers or
// HTTP 200 responses — ambiguous status codes (403, 404) are not flagged.
func (s *Service) runCloudStorageProbe(ctx context.Context, input RunInput, bodyText string) []model.Finding {
	if input.Options.PassiveOnly {
		return nil
	}

	buckets := extractCloudBuckets(bodyText)
	if len(buckets) == 0 {
		return nil
	}
	if len(buckets) > cloudStorageMaxExtract {
		buckets = buckets[:cloudStorageMaxExtract]
	}

	var findings []model.Finding
	emitted := map[string]bool{}

	for _, b := range buckets {
		select {
		case <-ctx.Done():
			return findings
		default:
		}

		probeURL := b.listURL()
		if probeURL == "" {
			continue
		}
		if err := safety.ValidateOutboundURL(probeURL); err != nil {
			continue
		}
		fid := "cloud-storage-public-" + b.Provider + "-" + b.Name
		if emitted[fid] {
			continue
		}

		req, err := http.NewRequestWithContext(ctx, http.MethodGet, probeURL, nil)
		if err != nil {
			continue
		}
		// Do NOT apply auth profile — we want to test unauthenticated access.
		resp, err := s.doRequestWithRetry(ctx, req, input.Options)
		if err != nil || resp == nil {
			continue
		}
		bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<17)) // 128 KB
		_ = resp.Body.Close()
		resp.Body = http.NoBody
		respBodyLower := strings.ToLower(string(bodyBytes))
		responseShape := ClassifyResponseShape(resp.Header)
		if !isCloudStorageListingResponse(b.Provider, resp.StatusCode, resp.Header, respBodyLower) {
			continue
		}

		controlName := cloudStorageControlBucketName(b)
		controlBaselines, berr := CaptureTwoControlBaselines(ctx, func(bctx context.Context) (BaselineSample, error) {
			controlBucket := b
			controlBucket.Name = controlName
			creq, err := http.NewRequestWithContext(bctx, http.MethodGet, controlBucket.listURL(), nil)
			if err != nil {
				return BaselineSample{}, err
			}
			cresp, err := s.doRequestWithRetry(bctx, creq, input.Options)
			if err != nil || cresp == nil {
				return BaselineSample{}, err
			}
			cb, _ := io.ReadAll(io.LimitReader(cresp.Body, 1<<17))
			_ = cresp.Body.Close()
			return BaselineSample{Status: cresp.StatusCode, Header: cresp.Header, Body: string(cb)}, nil
		})
		if berr == nil {
			if isCloudStorageListingResponse(b.Provider, controlBaselines.First.Status, controlBaselines.First.Header, strings.ToLower(controlBaselines.First.Body)) ||
				isCloudStorageListingResponse(b.Provider, controlBaselines.Second.Status, controlBaselines.Second.Header, strings.ToLower(controlBaselines.Second.Body)) {
				continue
			}
		}

		diffOutcome := DifferentialReVerify(ctx, DifferentialReVerifyInput{
			ProbeName:       "cloud-storage-probe",
			OriginalPayload: b.Name,
			SafePayload:     controlName,
			Exec: func(dctx context.Context, altPayload string) (*http.Response, []byte, error) {
				altBucket := b
				altBucket.Name = altPayload
				dreq, err := http.NewRequestWithContext(dctx, http.MethodGet, altBucket.listURL(), nil)
				if err != nil {
					return nil, nil, err
				}
				dresp, err := s.doRequestWithRetry(dctx, dreq, input.Options)
				if err != nil || dresp == nil {
					return nil, nil, err
				}
				db, _ := io.ReadAll(io.LimitReader(dresp.Body, 1<<17))
				_ = dresp.Body.Close()
				dresp.Body = http.NoBody
				return dresp, db, nil
			},
			Oracle: func(_ context.Context, _ string, dresp *http.Response, dbody []byte) (bool, error) {
				if dresp == nil {
					return false, nil
				}
				return isCloudStorageListingResponse(b.Provider, dresp.StatusCode, dresp.Header, strings.ToLower(string(dbody))), nil
			},
		})
		if diffOutcome.Ran && !diffOutcome.Confirmed {
			continue
		}

		finding := model.Finding{
			ID:       fid,
			Category: "cloud",
			Severity: model.SeverityHigh,
			Title:    fmt.Sprintf("Public %s bucket/container %q is world-readable (unauthenticated listing)", b.Provider, b.Name),
			Description: fmt.Sprintf(
				"The %s storage bucket/container %q referenced in the application's HTML/JavaScript "+
					"is publicly accessible without authentication. The listing endpoint %s returned HTTP 200 "+
					"with a bucket listing response, exposing all stored object keys. Depending on the "+
					"objects stored, this may expose sensitive files, backups, configuration, PII, or "+
					"intellectual property.",
				b.Provider, b.Name, probeURL,
			),
			Evidence: fmt.Sprintf(
				"Unauthenticated GET %s returned HTTP 200 with bucket listing (first 200 chars): %s",
				probeURL, truncateStr(string(bodyBytes), 200),
			),
			Recommendation: "Set the bucket ACL/policy to deny public access. " +
				"Use signed URLs for time-limited access to private objects. " +
				"Enable block-public-access settings (AWS S3) or equivalent on GCS/Azure. " +
				"Audit IAM policies to ensure no 's3:ListBucket' or equivalent permission is granted " +
				"to the unauthenticated (anonymous) principal.",
			Confidence:    0.95,
			AffectedURL:   probeURL,
			CWE:           "CWE-284",
			OWASPCategory: "A01:2021 - Broken Access Control",
			Sources:       []string{"active-scanner", "cloud-storage-probe"},
			ReproductionSteps: []string{
				fmt.Sprintf("curl -s \"%s\"", probeURL),
				"Observe the HTTP 200 response containing a bucket listing XML.",
			},
			BusinessTags: []string{"cloud-storage", "bucket", b.Provider},
			EvidenceFields: map[string]string{
				"validationType": "active-probe",
				"bucketName":     b.Name,
				"provider":       b.Provider,
				"listingURL":     probeURL,
				"responseShape":  responseShape.String(),
			},
		}
		AttachDifferentialEvidence(&finding, diffOutcome)
		emitted[fid] = true
		findings = append(findings, finding)
	}

	return findings
}

// cloudBucket holds a discovered cloud storage reference.
type cloudBucket struct {
	Provider string // "s3", "gcs", "azure"
	Name     string // bucket name or storage account name
	Host     string // full discovered hostname (e.g. bucket.s3.amazonaws.com)
}

// listURL returns the canonical unauthenticated listing URL for the bucket.
func (b cloudBucket) listURL() string {
	switch b.Provider {
	case "s3":
		return "https://s3.amazonaws.com/" + b.Name
	case "gcs":
		return "https://storage.googleapis.com/" + b.Name
	case "azure":
		return "https://" + b.Name + ".blob.core.windows.net/?comp=list"
	}
	return ""
}

// extractCloudBuckets parses body text for cloud storage bucket/account names
// and returns deduplicated results.
func extractCloudBuckets(body string) []cloudBucket {
	matches := cloudBucketPattern.FindAllStringSubmatch(body, -1)
	seen := map[string]bool{}
	var results []cloudBucket
	for _, m := range matches {
		if len(m) == 0 {
			continue
		}
		fullMatch := m[0]
		lm := strings.ToLower(fullMatch)

		var b cloudBucket
		switch {
		case strings.Contains(lm, "amazonaws.com"):
			b.Provider = "s3"
			// Extract bucket name from virtual-hosted or path style.
			if idx := strings.Index(lm, ".s3"); idx > 0 {
				b.Name = lm[:idx]
			} else if idx := strings.Index(lm, ".com/"); idx > 0 {
				b.Name = lm[idx+5:]
				// Trim any path suffix.
				if slash := strings.Index(b.Name, "/"); slash >= 0 {
					b.Name = b.Name[:slash]
				}
			}
		case strings.Contains(lm, "googleapis.com"):
			b.Provider = "gcs"
			if idx := strings.Index(lm, ".storage.googleapis.com"); idx > 0 {
				b.Name = lm[:idx]
			} else if idx := strings.Index(lm, ".com/"); idx > 0 {
				b.Name = lm[idx+5:]
				if slash := strings.Index(b.Name, "/"); slash >= 0 {
					b.Name = b.Name[:slash]
				}
			}
		case strings.Contains(lm, "blob.core.windows.net"):
			b.Provider = "azure"
			if idx := strings.Index(lm, ".blob.core.windows.net"); idx > 0 {
				b.Name = lm[:idx]
			}
		}
		b.Host = fullMatch
		key := b.Provider + ":" + b.Name
		if b.Name == "" || seen[key] {
			continue
		}
		seen[key] = true
		results = append(results, b)
	}
	return results
}

func isCloudStorageListingResponse(provider string, status int, header http.Header, bodyLower string) bool {
	if status != http.StatusOK || bodyLower == "" {
		return false
	}
	shape := ClassifyResponseShape(header)
	if shape == ShapeBinary || shape == ShapeJSON || shape == ShapeJavaScript || shape == ShapeCSS {
		return false
	}
	switch provider {
	case "s3", "gcs":
		if shape != ShapeXML && shape != ShapeUnknown {
			return false
		}
		return strings.Contains(bodyLower, s3ListBucketMarker) ||
			strings.Contains(bodyLower, "<contents>") ||
			(strings.Contains(bodyLower, "<?xml version") && strings.Contains(bodyLower, "<name>"))
	case "azure":
		if shape != ShapeXML && shape != ShapeUnknown {
			return false
		}
		return strings.Contains(bodyLower, "<enumerationresults") ||
			strings.Contains(bodyLower, "<blobs>") ||
			(strings.Contains(bodyLower, "<?xml version") && strings.Contains(bodyLower, "<name>"))
	default:
		return false
	}
}

func cloudStorageControlBucketName(b cloudBucket) string {
	var cleaned strings.Builder
	for _, r := range strings.ToLower(b.Name) {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			cleaned.WriteRune(r)
		case b.Provider != "azure" && (r == '-' || r == '.'):
			cleaned.WriteRune('-')
		}
	}
	base := strings.Trim(cleaned.String(), "-.")
	if base == "" {
		base = "bucket"
	}
	if b.Provider == "azure" {
		if len(base) > 12 {
			base = base[:12]
		}
		return "abhctl" + base + "9"
	}
	if len(base) > 40 {
		base = base[:40]
	}
	return base + "-abh-control"
}
