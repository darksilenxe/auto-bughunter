package api

import "testing"

func TestIsValidIdempotencyKey(t *testing.T) {
	cases := map[string]bool{
		"":                              false,
		"abc":                           true,
		"a-b_c.d":                       true,
		"ABC123":                        true,
		"with space":                    false,
		"with/slash":                    false,
		"with\nnewline":                 false,
		"with\x00null":                  false,
	}
	for in, want := range cases {
		if got := isValidIdempotencyKey(in); got != want {
			t.Errorf("isValidIdempotencyKey(%q)=%v want %v", in, got, want)
		}
	}
	// Length boundary: exactly 200 ok, 201 rejected.
	long200 := make([]byte, 200)
	for i := range long200 {
		long200[i] = 'a'
	}
	if !isValidIdempotencyKey(string(long200)) {
		t.Errorf("200-char key should be allowed")
	}
	if isValidIdempotencyKey(string(long200) + "a") {
		t.Errorf("201-char key should be rejected")
	}
}
