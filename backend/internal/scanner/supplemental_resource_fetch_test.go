package scanner

import (
	"reflect"
	"testing"

	"auto-bughunter/backend/internal/model"
)

func TestCollectSupplementalResourceURLs_RespectsScopeAndDedupes(t *testing.T) {
	scope := model.ScanScope{
		IncludeHosts: []string{"1.1.1.1", "one.one.one.one"},
	}
	got := collectSupplementalResourceURLs("https://1.1.1.1/app", []string{
		"/docs",
		"https://one.one.one.one/help",
		"https://one.one.one.one/help",
		"https://8.8.8.8/skip",
		"javascript:alert(1)",
	}, scope, 10)

	want := []string{
		"https://1.1.1.1/docs",
		"https://one.one.one.one/help",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("unexpected supplemental URLs\ngot:  %#v\nwant: %#v", got, want)
	}
}
