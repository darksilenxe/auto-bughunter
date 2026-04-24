package toolbuilder

import "testing"

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
