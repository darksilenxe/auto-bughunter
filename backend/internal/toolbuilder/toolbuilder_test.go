package toolbuilder

import "testing"

func TestResolveInterpreter_AllowsPythonForms(t *testing.T) {
	cases := []string{"", "python", "python3", " PYTHON3 "}
	for _, language := range cases {
		interp, ext, err := resolveInterpreter(language)
		if err != nil {
			t.Fatalf("expected language %q to be allowed, got err: %v", language, err)
		}
		if interp != "python3" || ext != ".py" {
			t.Fatalf("expected python3/.py for %q, got %q/%q", language, interp, ext)
		}
	}
}

func TestResolveInterpreter_RejectsBashAndUnknown(t *testing.T) {
	cases := []string{"bash", "sh", "node", "perl"}
	for _, language := range cases {
		if _, _, err := resolveInterpreter(language); err == nil {
			t.Fatalf("expected language %q to be rejected", language)
		}
	}
}

func TestValidateScript_RejectsSubprocessImportForms(t *testing.T) {
	cases := []string{
		"import subprocess\nprint('x')",
		"from subprocess import Popen\nprint('x')",
		"import subprocess as sp\nsp.Popen(['id'])",
	}
	for _, code := range cases {
		if err := validateScript(code); err == nil {
			t.Fatalf("expected subprocess variant to be rejected: %q", code)
		}
	}
}

func TestValidateScript_AllowsSafeStdlibScript(t *testing.T) {
	code := "import urllib.request\nimport json\nprint(json.dumps({'id':'x','title':'ok'}))"
	if err := validateScript(code); err != nil {
		t.Fatalf("expected safe script to pass validation, got %v", err)
	}
}
