package scanner

import "testing"

func TestClassifyReflectionContext_HTMLText(t *testing.T) {
	body := `<div>hello ZZMARKERZZ world</div>`
	if got := ClassifyReflectionContext(body, "ZZMARKERZZ"); got != ContextHTMLText {
		t.Fatalf("got %s, want html_text", got)
	}
}

func TestClassifyReflectionContext_AttrDouble(t *testing.T) {
	body := `<a title="hello ZZMARKERZZ suffix">x</a>`
	if got := ClassifyReflectionContext(body, "ZZMARKERZZ"); got != ContextHTMLAttrDouble {
		t.Fatalf("got %s, want html_attr_double", got)
	}
}

func TestClassifyReflectionContext_AttrSingle(t *testing.T) {
	body := `<a title='hello ZZMARKERZZ suffix'>x</a>`
	if got := ClassifyReflectionContext(body, "ZZMARKERZZ"); got != ContextHTMLAttrSingle {
		t.Fatalf("got %s, want html_attr_single", got)
	}
}

func TestClassifyReflectionContext_AttrUnquoted(t *testing.T) {
	body := `<a title=ZZMARKERZZ>x</a>`
	if got := ClassifyReflectionContext(body, "ZZMARKERZZ"); got != ContextHTMLAttrUnquoted {
		t.Fatalf("got %s, want html_attr_unquoted", got)
	}
}

func TestClassifyReflectionContext_URLAttr(t *testing.T) {
	body := `<a href="https://example.com/?q=ZZMARKERZZ">x</a>`
	if got := ClassifyReflectionContext(body, "ZZMARKERZZ"); got != ContextURL {
		t.Fatalf("got %s, want url", got)
	}
}

func TestClassifyReflectionContext_HTMLComment(t *testing.T) {
	body := `<div><!-- debug: ZZMARKERZZ --></div>`
	if got := ClassifyReflectionContext(body, "ZZMARKERZZ"); got != ContextHTMLComment {
		t.Fatalf("got %s, want html_comment", got)
	}
}

func TestClassifyReflectionContext_JSString(t *testing.T) {
	body := `<script>var x = "hello ZZMARKERZZ world";</script>`
	if got := ClassifyReflectionContext(body, "ZZMARKERZZ"); got != ContextJSString {
		t.Fatalf("got %s, want js_string", got)
	}
}

func TestClassifyReflectionContext_JSBlock(t *testing.T) {
	body := `<script>console.log(ZZMARKERZZ);</script>`
	if got := ClassifyReflectionContext(body, "ZZMARKERZZ"); got != ContextJSBlock {
		t.Fatalf("got %s, want js_block", got)
	}
}

func TestClassifyReflectionContext_StyleBlock(t *testing.T) {
	body := `<style>.x { color: ZZMARKERZZ; }</style>`
	if got := ClassifyReflectionContext(body, "ZZMARKERZZ"); got != ContextCSSValue {
		t.Fatalf("got %s, want css_value", got)
	}
}

func TestClassifyReflectionContext_Missing(t *testing.T) {
	if got := ClassifyReflectionContext("<div>nothing</div>", "ZZMARKERZZ"); got != ContextUnknown {
		t.Fatalf("got %s, want unknown", got)
	}
	if got := ClassifyReflectionContext("", "ZZMARKERZZ"); got != ContextUnknown {
		t.Fatalf("empty body got %s", got)
	}
	if got := ClassifyReflectionContext("body", ""); got != ContextUnknown {
		t.Fatalf("empty marker got %s", got)
	}
}

func TestPayloadEscapesContext(t *testing.T) {
	cases := []struct {
		name    string
		ctx     ReflectionContext
		payload string
		want    bool
	}{
		{"html-text-escape", ContextHTMLText, `<script>alert(1)</script>`, true},
		{"html-text-no-escape", ContextHTMLText, `alert(1)`, false},
		{"attr-double-escape", ContextHTMLAttrDouble, `" onerror=x`, true},
		{"attr-double-no-escape", ContextHTMLAttrDouble, `onerror=x`, false},
		{"attr-single-escape", ContextHTMLAttrSingle, `' onerror=x`, true},
		{"attr-unquoted-escape", ContextHTMLAttrUnquoted, `x onerror=y`, true},
		{"js-string-escape", ContextJSString, `";alert(1);//`, true},
		{"js-string-close-script", ContextJSString, `</script><script>alert(1)`, true},
		{"js-string-no-escape", ContextJSString, `alert1`, false},
		{"js-block-any", ContextJSBlock, `alert(1)`, true},
		{"js-block-no-syntax", ContextJSBlock, `abc`, false},
		{"url-javascript", ContextURL, `javascript:alert(1)`, true},
		{"url-data", ContextURL, `data:text/html,<script>alert(1)</script>`, true},
		{"url-benign", ContextURL, `/foo/bar`, false},
		{"header-crlf", ContextHeader, "x\r\nSet-Cookie: a=b", true},
		{"header-no-crlf", ContextHeader, "x", false},
		{"unknown", ContextUnknown, "<script>", false},
		{"empty-payload", ContextHTMLText, "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := PayloadEscapesContext(tc.ctx, tc.payload); got != tc.want {
				t.Fatalf("PayloadEscapesContext(%s,%q)=%v want %v", tc.ctx, tc.payload, got, tc.want)
			}
		})
	}
}

func TestReflectionContextString(t *testing.T) {
	labels := map[ReflectionContext]string{
		ContextUnknown:          "unknown",
		ContextHTMLText:         "html_text",
		ContextHTMLAttrDouble:   "html_attr_double",
		ContextHTMLAttrSingle:   "html_attr_single",
		ContextHTMLAttrUnquoted: "html_attr_unquoted",
		ContextHTMLComment:      "html_comment",
		ContextJSString:         "js_string",
		ContextJSBlock:          "js_block",
		ContextCSSValue:         "css_value",
		ContextURL:              "url",
		ContextHeader:           "header",
	}
	for c, want := range labels {
		if got := c.String(); got != want {
			t.Fatalf("String(%d)=%s want %s", c, got, want)
		}
	}
}
