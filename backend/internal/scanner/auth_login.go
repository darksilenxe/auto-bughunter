package scanner

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"time"

	"auto-bughunter/backend/internal/model"
	"auto-bughunter/backend/internal/scope"

	"github.com/chromedp/cdproto/network"
	"github.com/chromedp/chromedp"
)

func hasStandardLoginCredentials(profile model.ScanAuthProfile) bool {
	return strings.TrimSpace(profile.Username) != "" || strings.TrimSpace(profile.Password) != ""
}

func hasCompleteStandardLoginCredentials(profile model.ScanAuthProfile) bool {
	return strings.TrimSpace(profile.Username) != "" && strings.TrimSpace(profile.Password) != ""
}

func candidateLoginURLs(target string, profile model.ScanAuthProfile, scanScope model.ScanScope) []string {
	base, err := url.Parse(target)
	if err != nil {
		return nil
	}

	out := make([]string, 0, 8)
	seen := map[string]struct{}{}
	add := func(raw string) {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			return
		}
		ref, err := url.Parse(raw)
		if err != nil {
			return
		}
		resolved := base.ResolveReference(ref)
		if resolved.Scheme == "" || resolved.Host == "" {
			return
		}
		if !scope.IsURLInScope(resolved.String(), scanScope) {
			return
		}
		if _, ok := seen[resolved.String()]; ok {
			return
		}
		seen[resolved.String()] = struct{}{}
		out = append(out, resolved.String())
	}

	add(profile.LoginURL)
	add(target)

	root := &url.URL{Scheme: base.Scheme, Host: base.Host, Path: "/"}
	add(root.String())
	for _, path := range []string{
		"/login",
		"/signin",
		"/sign-in",
		"/users/sign_in",
		"/account/login",
		"/auth/login",
		"/api/auth/login",
	} {
		add(root.ResolveReference(&url.URL{Path: path}).String())
	}

	return out
}

func bootstrapStandardAuthProfile(parent context.Context, target string, profile model.ScanAuthProfile, scanScope model.ScanScope, emit func(model.ScanEvent)) (model.ScanAuthProfile, []model.Finding) {
	if !hasStandardLoginCredentials(profile) {
		return profile, nil
	}
	if !hasCompleteStandardLoginCredentials(profile) {
		return profile, []model.Finding{{
			ID:             "standard-auth-bootstrap-incomplete",
			Category:       "coverage",
			Severity:       model.SeverityLow,
			Title:          "Standard application credentials were incomplete",
			Description:    "Username/password login bootstrap was skipped because only one credential field was provided.",
			Evidence:       "Provide both username and password to enable standard application login.",
			Recommendation: "Enter both username and password, or leave both empty for an unauthenticated scan.",
		}}
	}

	ctx, cancel := chromedpContext(parent)
	defer cancel()

	ctx, timeoutCancel := context.WithTimeout(ctx, 35*time.Second)
	defer timeoutCancel()

	extraHeaders := make(network.Headers)
	for key, value := range profile.Headers {
		if strings.TrimSpace(key) != "" {
			extraHeaders[key] = value
		}
	}
	if strings.TrimSpace(profile.UserAgent) != "" {
		extraHeaders["User-Agent"] = profile.UserAgent
	}

	if err := chromedp.Run(ctx,
		network.Enable(),
		chromedp.ActionFunc(func(ctx context.Context) error {
			if len(extraHeaders) > 0 {
				if err := network.SetExtraHTTPHeaders(extraHeaders).Do(ctx); err != nil {
					return err
				}
			}
			return seedBrowserCookies(ctx, target, profile.Cookies)
		}),
	); err != nil {
		return profile, []model.Finding{{
			ID:             "standard-auth-bootstrap-error",
			Category:       "coverage",
			Severity:       model.SeverityLow,
			Title:          "Standard application login bootstrap failed",
			Description:    "The browser-based login bootstrap could not initialize, so the scan continued with the provided auth profile only.",
			Evidence:       err.Error(),
			Recommendation: "Verify Chromium connectivity and try again with refreshed credentials or pre-captured cookies.",
		}}
	}

	for _, loginURL := range candidateLoginURLs(target, profile, scanScope) {
		var submit loginFormSubmitResult
		var currentURL string
		if err := chromedp.Run(ctx,
			chromedp.Navigate(loginURL),
			chromedp.Sleep(1200*time.Millisecond),
			chromedp.Evaluate(buildLoginBootstrapScript(profile.Username, profile.Password), &submit),
			chromedp.Sleep(2200*time.Millisecond),
			chromedp.Location(&currentURL),
		); err != nil || !submit.OK {
			continue
		}

		cookies, err := network.GetCookies().WithUrls([]string{target, loginURL, currentURL}).Do(ctx)
		if err != nil {
			continue
		}
		sessionCookies := extractBrowserCookies(cookies)
		if len(sessionCookies) == 0 {
			continue
		}

		merged := profile
		if merged.Cookies == nil {
			merged.Cookies = map[string]string{}
		}
		for name, value := range sessionCookies {
			merged.Cookies[name] = value
		}
		if emit != nil {
			emit(model.ScanEvent{
				Type:    model.ScanEventInfo,
				Message: fmt.Sprintf("Standard application login bootstrap succeeded via %s", currentURL),
			})
		}
		return merged, nil
	}

	return profile, []model.Finding{{
		ID:             "standard-auth-bootstrap-failed",
		Category:       "coverage",
		Severity:       model.SeverityLow,
		Title:          "Standard application login bootstrap did not establish a session",
		Description:    "The scan continued without a captured application session after the username/password login attempt did not produce usable cookies.",
		Evidence:       strings.Join(candidateLoginURLs(target, profile, scanScope), ", "),
		Recommendation: "Provide a direct login URL, or use captured headers/cookies/basic auth when the app relies on a non-standard login flow.",
	}}
}

type loginFormSubmitResult struct {
	OK     bool   `json:"ok"`
	Reason string `json:"reason"`
	Action string `json:"action"`
}

func buildLoginBootstrapScript(username, password string) string {
	userJSON, _ := json.Marshal(username)
	passJSON, _ := json.Marshal(password)
	return fmt.Sprintf(`(() => {
  const usernameValue = %s;
  const passwordValue = %s;
  const textFor = (el) => [
    el?.name,
    el?.id,
    el?.placeholder,
    el?.autocomplete,
    el?.getAttribute?.('aria-label'),
    Array.from(el?.labels || []).map(label => label.textContent || '').join(' ')
  ].filter(Boolean).join(' ').toLowerCase();
  const score = (el) => {
    const text = textFor(el);
    let value = 0;
    if ((el.type || '').toLowerCase() === 'email') value += 9;
    if (text.includes('email')) value += 8;
    if (text.includes('user')) value += 7;
    if (text.includes('login')) value += 7;
    if (text.includes('sign in')) value += 7;
    if (text.includes('identifier')) value += 6;
    return value;
  };
  const forms = Array.from(document.forms)
    .map(form => ({ form, passwordInput: form.querySelector('input[type="password"]') }))
    .filter(entry => entry.passwordInput);
  if (!forms.length) return { ok: false, reason: 'no-login-form' };
  const candidate = forms
    .map(entry => ({
      ...entry,
      score: Array.from(entry.form.querySelectorAll('input')).reduce((sum, input) => sum + score(input), 0)
    }))
    .sort((a, b) => b.score - a.score)[0];
  const usernameInput = Array.from(candidate.form.querySelectorAll('input'))
    .filter(input => !['hidden', 'submit', 'button', 'checkbox', 'radio', 'password'].includes((input.type || '').toLowerCase()))
    .sort((a, b) => score(b) - score(a))[0];
  if (!usernameInput || !candidate.passwordInput) return { ok: false, reason: 'missing-inputs' };
  const setValue = (el, value) => {
    el.focus();
    el.value = value;
    el.dispatchEvent(new Event('input', { bubbles: true }));
    el.dispatchEvent(new Event('change', { bubbles: true }));
  };
  setValue(usernameInput, usernameValue);
  setValue(candidate.passwordInput, passwordValue);
  const submit = candidate.form.querySelector('button[type="submit"],input[type="submit"]');
  if (submit) {
    submit.click();
  } else {
    candidate.form.submit();
  }
  return { ok: true, reason: 'submitted', action: candidate.form.action || window.location.href };
})()`, userJSON, passJSON)
}

func seedBrowserCookies(ctx context.Context, target string, cookies map[string]string) error {
	if len(cookies) == 0 {
		return nil
	}
	targetURL, err := url.Parse(target)
	if err != nil {
		return err
	}
	host := targetURL.Hostname()
	if host == "" {
		return nil
	}
	for name, value := range cookies {
		if err := network.SetCookie(name, value).
			WithDomain(host).
			WithHTTPOnly(false).
			Do(ctx); err != nil {
			return err
		}
	}
	return nil
}

func extractBrowserCookies(cookies []*network.Cookie) map[string]string {
	out := make(map[string]string, len(cookies))
	for _, cookie := range cookies {
		if cookie == nil || strings.TrimSpace(cookie.Name) == "" {
			continue
		}
		out[cookie.Name] = cookie.Value
	}
	return out
}
