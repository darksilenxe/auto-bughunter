package scanner

import (
	"net/http"
	"testing"
)

func header(ct string) http.Header {
	h := http.Header{}
	if ct != "" {
		h.Set("Content-Type", ct)
	}
	return h
}

func TestClassifyResponseShape(t *testing.T) {
	cases := []struct {
		name string
		ct   string
		want ResponseShape
	}{
		{"empty", "", ShapeUnknown},
		{"garbage", "not/a/mediatype/at/all;;;", ShapeUnknown},
		{"html", "text/html; charset=utf-8", ShapeHTML},
		{"xhtml", "application/xhtml+xml", ShapeHTML},
		{"json", "application/json", ShapeJSON},
		{"vnd+json", "application/vnd.api+json", ShapeJSON},
		{"xml", "application/xml", ShapeXML},
		{"text-xml", "text/xml", ShapeXML},
		{"svg", "image/svg+xml", ShapeXML},
		{"js", "application/javascript", ShapeJavaScript},
		{"text-js", "text/javascript; charset=utf-8", ShapeJavaScript},
		{"css", "text/css", ShapeCSS},
		{"plaintext", "text/plain", ShapePlainText},
		{"png", "image/png", ShapeBinary},
		{"mp4", "video/mp4", ShapeBinary},
		{"octet", "application/octet-stream", ShapeBinary},
		{"pdf", "application/pdf", ShapeBinary},
		{"zip", "application/zip", ShapeBinary},
		{"protobuf", "application/x-protobuf", ShapeBinary},
		{"wasm", "application/wasm", ShapeBinary},
		{"form", "application/x-www-form-urlencoded", ShapeOther},
		{"graphql", "application/graphql", ShapeOther},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := ClassifyResponseShape(header(tc.ct))
			if got != tc.want {
				t.Fatalf("ClassifyResponseShape(%q)=%s, want %s", tc.ct, got, tc.want)
			}
		})
	}
}

func TestShapeHelpers(t *testing.T) {
	if !IsHTMLShape(header("")) {
		t.Fatal("empty CT should be treated as HTML (conservative)")
	}
	if !IsHTMLShape(header("text/html")) {
		t.Fatal("text/html should be HTML")
	}
	if IsHTMLShape(header("application/json")) {
		t.Fatal("application/json must not gate as HTML")
	}
	if !IsJSONShape(header("application/vnd.api+json")) {
		t.Fatal("+json should classify as JSON")
	}
	if IsJSONShape(header("")) {
		t.Fatal("missing CT must not gate as JSON")
	}
	if !IsXMLShape(header("text/xml")) {
		t.Fatal("text/xml should be XML")
	}
	if IsXMLShape(header("")) {
		t.Fatal("missing CT must not gate as XML")
	}
	if !IsBinaryShape(header("image/png")) {
		t.Fatal("image/png should be binary")
	}
	if IsBinaryShape(header("")) {
		t.Fatal("missing CT must not gate as binary (no positive evidence)")
	}
	if IsReflectionSafeShape(header("image/png")) {
		t.Fatal("binary responses are not reflection-safe")
	}
	if !IsReflectionSafeShape(header("")) {
		t.Fatal("unknown CT should be reflection-safe (conservative coverage)")
	}
	if !IsReflectionSafeShape(header("application/json")) {
		t.Fatal("JSON responses can still carry reflected payloads")
	}
}

func TestResponseShapeString(t *testing.T) {
	labels := map[ResponseShape]string{
		ShapeUnknown:    "unknown",
		ShapeHTML:       "html",
		ShapeJSON:       "json",
		ShapeXML:        "xml",
		ShapeJavaScript: "javascript",
		ShapeCSS:        "css",
		ShapePlainText:  "text",
		ShapeBinary:     "binary",
		ShapeOther:      "other",
	}
	for s, want := range labels {
		if got := s.String(); got != want {
			t.Fatalf("String(%d)=%s want %s", s, got, want)
		}
	}
}
