package scanner

import (
	"reflect"
	"testing"
 
	"auto-bughunter/backend/internal/model"
)

func TestCollectSupplementalResourceURLs_RespectsScopeAndDedupes(t *testing.T) {
	scope := model.ScanScope{
		IncludeHosts: []string{"1.1.1.1", "8.8.8.8"},
	}
	got := collectSupplementalResourceURLs("https://1.1.1.1/app", []string{
		"/docs",
		"https://8.8.8.8/help",
		"https://8.8.8.8/help",
		"https://9.9.9.9/skip",
		"javascript:alert(1)",
	}, scope, 10)

	want := []string{
		"https://1.1.1.1/docs",
		"https://8.8.8.8/help",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("unexpected supplemental URLs\ngot:  %#v\nwant: %#v", got, want)
	}
}

func TestExtractPlainTextExcerptFromHTML(t *testing.T) {
	html := `<html><head><style>.a{}</style><script>alert(1)</script></head><body><h1>Training</h1><p>Collect plain text only.</p></body></html>`
	got := extractPlainTextExcerptFromHTML(html, 200)
	want := "Training Collect plain text only."
	if got != want {
		t.Fatalf("unexpected plain text excerpt\ngot:  %q\nwant: %q", got, want)
	}
}

func TestRebuildRequestURL(t *testing.T) {
	t.Run("preserves supported http target structure", func(t *testing.T) {
		got, err := rebuildRequestURL("HTTPS://Example.com/api/v1/users?id=7")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		want := "https://Example.com/api/v1/users?id=7"
		if got != want {
			t.Fatalf("unexpected rebuilt URL\ngot:  %q\nwant: %q", got, want)
		}
	})

	t.Run("rejects invalid outbound target", func(t *testing.T) {
		if _, err := rebuildRequestURL("javascript:alert(1)"); err == nil {
			t.Fatal("expected invalid URL error")
		}
	})
}
