package scanner

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"auto-bughunter/backend/internal/model"
)

func TestRunVerboseErrorProbe_PassiveOnlyDisabled(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	svc := NewService(Config{})
	got := svc.runVerboseErrorProbe(context.Background(), RunInput{
		Target:  srv.URL,
		Options: model.ScanOptions{PassiveOnly: true},
	}, "")
	if len(got) != 0 {
		t.Fatalf("PassiveOnly must disable the probe, got %d findings", len(got))
	}
}

func TestMatchVerboseErrors_DetectsJavaStackTrace(t *testing.T) {
	body := `Internal error:
java.lang.NullPointerException
	at com.example.app.UserService.getUser(UserService.java:42)
	at com.example.app.controllers.UserController.show(UserController.java:21)
`
	matched := matchVerboseErrors(body)
	if len(matched) == 0 {
		t.Fatal("expected at least one match for Java stack trace")
	}
}

func TestMatchVerboseErrors_DetectsPHPError(t *testing.T) {
	body := `Fatal error: Uncaught exception 'PDOException' in /var/www/html/db.php on line 15`
	matched := matchVerboseErrors(body)
	if len(matched) == 0 {
		t.Fatal("expected match for PHP fatal error disclosure")
	}
}

func TestMatchVerboseErrors_NoMatchCleanErrors(t *testing.T) {
	body := `{"error":"invalid input"}`
	matched := matchVerboseErrors(body)
	if len(matched) != 0 {
		t.Fatalf("expected no match for clean error body, got %v", matched)
	}
}

func TestMatchVerboseErrors_DetectsDatabaseError(t *testing.T) {
	body := `SQLSTATE[42000]: You have an error in your SQL syntax; check the manual`
	matched := matchVerboseErrors(body)
	if len(matched) == 0 {
		t.Fatal("expected match for database error disclosure")
	}
}

func TestExtractExcerpt(t *testing.T) {
	// Use a pattern from the php-fatal-error signature (index 3)
	text := "Fatal error: Uncaught exception in /var/www/html/db.php on line 15"
	sig := errorLeakSignatures[3] // php-fatal-error
	excerpt := extractExcerpt(text, sig.pattern, 200)
	if excerpt == "" {
		t.Fatal("expected non-empty excerpt for matching text")
	}
}

