package scanner

import (
	"testing"

	"auto-bughunter/backend/internal/model"
)

func TestExtractRuntimeEndpoints_InScopeAndDeduped(t *testing.T) {
	body := `
	<html>
	  <script src="/static/app.js"></script>
	  <script>const a="/api/users"; const b="/graphql"; const c="/api/users";</script>
	</html>`
	scope := model.ScanScope{
		IncludeHosts: []string{"1.1.1.1"},
	}
	got := extractRuntimeEndpoints("https://1.1.1.1/app", body, scope, 20)
	if len(got) == 0 {
		t.Fatalf("expected discovered endpoints, got none")
	}
	seen := map[string]struct{}{}
	for _, v := range got {
		seen[v] = struct{}{}
	}
	for _, want := range []string{
		"https://1.1.1.1/api/users",
		"https://1.1.1.1/graphql",
		"https://1.1.1.1/openapi.json",
	} {
		if _, ok := seen[want]; !ok {
			t.Fatalf("expected endpoint %s in result: %#v", want, got)
		}
	}
}
