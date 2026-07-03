package scanner

import (
	"context"
	"net/http"
	"strings"
	"testing"
)

func TestPhase1BatchD_CloudStorageHelpers(t *testing.T) {
	listing := `<?xml version="1.0"?><ListBucketResult><Name>my-bucket</Name><Contents><Key>secret.txt</Key></Contents></ListBucketResult>`
	h := http.Header{"Content-Type": []string{"application/xml"}}
	if !isCloudStorageListingResponse("s3", http.StatusOK, h, strings.ToLower(listing)) {
		t.Fatal("expected XML listing response to be recognised")
	}
	if got := ClassifyResponseShape(h).String(); got != "xml" {
		t.Fatalf("expected responseShape=xml, got %q", got)
	}

	confirmed := DifferentialReVerify(context.Background(), DifferentialReVerifyInput{
		ProbeName:       "cloud-storage-probe",
		OriginalPayload: "my-bucket",
		SafePayload:     cloudStorageControlBucketName(cloudBucket{Provider: "s3", Name: "my-bucket"}),
		Exec: func(_ context.Context, _ string) (*http.Response, []byte, error) {
			return &http.Response{StatusCode: http.StatusNotFound, Header: h}, []byte(`<?xml version="1.0"?><Error><Code>NoSuchBucket</Code></Error>`), nil
		},
		Oracle: func(_ context.Context, _ string, resp *http.Response, body []byte) (bool, error) {
			return isCloudStorageListingResponse("s3", resp.StatusCode, resp.Header, strings.ToLower(string(body))), nil
		},
	})
	if !confirmed.Confirmed {
		t.Fatalf("expected nonexistent-bucket differential to confirm, got %+v", confirmed)
	}

	suppressed := DifferentialReVerify(context.Background(), DifferentialReVerifyInput{
		ProbeName:       "cloud-storage-probe",
		OriginalPayload: "my-bucket",
		SafePayload:     "my-bucket-abh-control",
		Exec: func(_ context.Context, _ string) (*http.Response, []byte, error) {
			return &http.Response{StatusCode: http.StatusOK, Header: h}, []byte(listing), nil
		},
		Oracle: func(_ context.Context, _ string, resp *http.Response, body []byte) (bool, error) {
			return isCloudStorageListingResponse("s3", resp.StatusCode, resp.Header, strings.ToLower(string(body))), nil
		},
	})
	if suppressed.Confirmed || suppressed.Reason == "confirmed" {
		t.Fatalf("expected generic listing control to suppress, got %+v", suppressed)
	}
}

func TestPhase1BatchD_FileUploadHelpers(t *testing.T) {
	h := http.Header{"Content-Type": []string{"application/json"}}
	assessment := assessUploadResponse(http.StatusOK, `{"status":"uploaded"}`)
	if !assessment.Accepted {
		t.Fatal("expected accepted upload response")
	}
	if got := ClassifyResponseShape(h).String(); got != "json" {
		t.Fatalf("expected responseShape=json, got %q", got)
	}

	confirmed := DifferentialReVerify(context.Background(), DifferentialReVerifyInput{
		ProbeName:       "file-upload-probe",
		OriginalPayload: "test.php.jpg",
		SafePayload:     blockedUploadControlFilename("double-extension"),
		Exec: func(_ context.Context, altFilename string) (*http.Response, []byte, error) {
			if altFilename == blockedUploadControlFilename("double-extension") {
				return &http.Response{StatusCode: http.StatusUnsupportedMediaType, Header: h}, []byte(`{"error":"blocked"}`), nil
			}
			return &http.Response{StatusCode: http.StatusUnsupportedMediaType, Header: h}, []byte(`{"error":"blocked"}`), nil
		},
		Oracle: func(_ context.Context, _ string, resp *http.Response, body []byte) (bool, error) {
			return assessUploadResponse(resp.StatusCode, string(body)).Accepted, nil
		},
	})
	if !confirmed.Confirmed {
		t.Fatalf("expected blocked-control differential to confirm, got %+v", confirmed)
	}

	suppressed := DifferentialReVerify(context.Background(), DifferentialReVerifyInput{
		ProbeName:       "file-upload-probe",
		OriginalPayload: "test.php.jpg",
		SafePayload:     blockedUploadControlFilename("double-extension"),
		Exec: func(_ context.Context, _ string) (*http.Response, []byte, error) {
			return &http.Response{StatusCode: http.StatusOK, Header: h}, []byte(`{"status":"uploaded"}`), nil
		},
		Oracle: func(_ context.Context, _ string, resp *http.Response, body []byte) (bool, error) {
			return assessUploadResponse(resp.StatusCode, string(body)).Accepted, nil
		},
	})
	if suppressed.Confirmed || suppressed.Reason == "confirmed" {
		t.Fatalf("expected generic acceptance control to suppress, got %+v", suppressed)
	}
}

func TestPhase1BatchD_DOMXSSReflectionHelpers(t *testing.T) {
	payload := domXSSPayloadFragment(domXSSPayloads[0].hash)
	ctx, ok := domXSSDangerousReflection(`<div>`+domXSSPayloadMarker+`</div>`, domXSSPayloadMarker, payload)
	if !ok || ctx != ContextHTMLText {
		t.Fatalf("expected html-text DOM XSS reflection, got ok=%v ctx=%v", ok, ctx)
	}

	ctx, ok = domXSSDangerousReflection(`<div data-frag="`+domXSSPayloadMarker+`"></div>`, domXSSPayloadMarker, payload)
	if ok || ctx != ContextHTMLAttrDouble {
		t.Fatalf("expected double-quoted attr reflection to be rejected for payload without quote break-out, got ok=%v ctx=%v", ok, ctx)
	}

	if !domXSSOriginalSignalPresent("title "+domXSSPayloadMarker, "", domXSSPayloadMarker, payload) {
		t.Fatal("expected title-based original signal detection for differential oracle")
	}

	title, body := decodeDOMXSSObservation(encodeDOMXSSObservation("title", "<body>ok</body>"))
	if title != "title" || body != "<body>ok</body>" {
		t.Fatalf("unexpected differential observation round-trip: title=%q body=%q", title, body)
	}
}
