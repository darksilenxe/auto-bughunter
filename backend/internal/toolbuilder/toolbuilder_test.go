package toolbuilder

import "testing"

func TestResolveInterpreter_AllowsPythonForms(t *testing.T) {
	cases := []struct {
		language   string
		interpWant string
		extWant    string
	}{
		{language: "", interpWant: "python3", extWant: ".py"},
		{language: "python", interpWant: "python3", extWant: ".py"},
		{language: "python3", interpWant: "python3", extWant: ".py"},
		{language: " PYTHON3 ", interpWant: "python3", extWant: ".py"},
		{language: "node", interpWant: "node", extWant: ".js"},
		{language: " perl ", interpWant: "perl", extWant: ".pl"},
		{language: "bash", interpWant: "bash", extWant: ".sh"},
	}
	for _, tc := range cases {
		interp, ext, err := resolveInterpreter(tc.language)
		if err != nil {
			t.Fatalf("expected language %q to be allowed, got err: %v", tc.language, err)
		}
		if interp != tc.interpWant || ext != tc.extWant {
			t.Fatalf("expected %q/%q for %q, got %q/%q", tc.interpWant, tc.extWant, tc.language, interp, ext)
		}
	}
}

func TestResolveInterpreter_RejectsUnknown(t *testing.T) {
	cases := []string{"sh", "nodejs", "ruby", "php"}
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

func TestValidateScript_RejectsOsPopen(t *testing.T) {
	cases := []string{
		"import os\nos.popen('id').read()",
		"result = os.popen('whoami')",
	}
	for _, code := range cases {
		if err := validateScript(code); err == nil {
			t.Fatalf("expected os.popen variant to be rejected: %q", code)
		}
	}
}

func TestValidateScript_RejectsOsExec(t *testing.T) {
	cases := []string{
		"import os\nos.execv('/bin/sh', ['/bin/sh'])",
		"os.execve('/bin/sh', [], {})",
		"os.execvp('bash', ['bash'])",
	}
	for _, code := range cases {
		if err := validateScript(code); err == nil {
			t.Fatalf("expected os.exec* variant to be rejected: %q", code)
		}
	}
}

func TestValidateScript_RejectsImportlib(t *testing.T) {
	cases := []string{
		"import importlib\nimportlib.import_module('os')",
		"from importlib import import_module",
		"m = importlib.util.spec_from_file_location('x','x.py')",
	}
	for _, code := range cases {
		if err := validateScript(code); err == nil {
			t.Fatalf("expected importlib variant to be rejected: %q", code)
		}
	}
}

func TestValidateScript_RejectsCtypes(t *testing.T) {
	cases := []string{
		"import ctypes\nctypes.CDLL('libc.so.6')",
		"from ctypes import CDLL",
		"ctypes.windll.kernel32.WinExec(b'cmd',1)",
	}
	for _, code := range cases {
		if err := validateScript(code); err == nil {
			t.Fatalf("expected ctypes variant to be rejected: %q", code)
		}
	}
}

func TestValidateScript_RejectsPtySpawn(t *testing.T) {
	cases := []string{
		"import pty\npty.spawn('/bin/sh')",
		"from pty import spawn\nspawn('bash')",
	}
	for _, code := range cases {
		if err := validateScript(code); err == nil {
			t.Fatalf("expected pty.spawn variant to be rejected: %q", code)
		}
	}
}
