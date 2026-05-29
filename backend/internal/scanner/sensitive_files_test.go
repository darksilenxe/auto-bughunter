package scanner

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"auto-bughunter/backend/internal/model"
)

func TestSensitiveFileExposed(t *testing.T) {
	cases := []struct {
		name string
		path string
		code int
		ct   string
		body string
		want bool
	}{
		{"git-head-ref", ".git/HEAD", 200, "text/plain", "ref: refs/heads/main\n", true},
		{"git-head-detached", ".git/HEAD", 200, "text/plain", "0123456789abcdef0123456789abcdef01234567", true},
		{"git-config", ".git/config", 200, "text/plain", "[core]\n\trepositoryformatversion = 0\n", true},
		{"env-with-secret", ".env", 200, "text/plain", "APP_ENV=prod\nDB_PASSWORD=hunter2\n", true},
		{"env-no-secret", ".env", 200, "text/plain", "FOO=bar\nBAZ=qux\n", false},
		{"spa-catchall-html", ".git/config", 200, "text/html", "<!doctype html><html><body>app</body></html>", false},
		{"web-xml", "WEB-INF/web.xml", 200, "application/xml", "<web-app><servlet/></web-app>", true},
		{"not-found", ".env", 404, "text/plain", "APP_KEY=secret\nDB_PASSWORD=x\n", false},
		{"empty", ".env", 200, "text/plain", "   ", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := sensitiveFileExposed(c.path, c.code, c.ct, []byte(c.body)); got != c.want {
				t.Fatalf("sensitiveFileExposed(%q) = %v, want %v", c.path, got, c.want)
			}
		})
	}
}

func TestRunSensitiveFileProbe_PassiveOnlyDisables(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("ref: refs/heads/main\n"))
	}))
	defer srv.Close()
	svc := NewService(Config{})
	got := svc.runSensitiveFileProbe(context.Background(), RunInput{
		Target:  srv.URL,
		Options: model.ScanOptions{PassiveOnly: true},
	}, "")
	if len(got) != 0 {
		t.Fatalf("PassiveOnly must disable the probe, got %d findings", len(got))
	}
}

func TestEnvFileSignature(t *testing.T) {
	if !envFileSignature("APP_KEY=base64:xxxx\nMAIL_HOST=smtp\n") {
		t.Fatal("expected dotenv with APP_KEY to be detected")
	}
	if envFileSignature("# comment only\n\n") {
		t.Fatal("comment-only file must not be flagged")
	}
	if envFileSignature("ONLY=one\n") {
		t.Fatal("single non-sensitive var must not be flagged")
	}
}
