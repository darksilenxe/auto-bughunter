package scanner

import (
	"context"
	"fmt"
	"net/url"
	"strings"
	"time"

	"auto-bughunter/backend/internal/model"

	"github.com/chromedp/cdproto/network"
	"github.com/chromedp/chromedp"
)

func headlessChecks(parent context.Context, target string, profile model.ScanAuthProfile) ([]model.Finding, error) {
	ctx, cancel := chromedp.NewContext(parent)
	defer cancel()

	ctx, timeoutCancel := context.WithTimeout(ctx, 35*time.Second)
	defer timeoutCancel()

	var formCount int
	var csrfLikeCount int
	var title string
	var links []string
	u, _ := url.Parse(target)
	host := ""
	if u != nil {
		host = u.Hostname()
	}

	extraHeaders := make(network.Headers)
	for key, value := range profile.Headers {
		if strings.TrimSpace(key) != "" {
			extraHeaders[key] = value
		}
	}
	if profile.UserAgent != "" {
		extraHeaders["User-Agent"] = profile.UserAgent
	}

	tasks := make(chromedp.Tasks, 0, 10)
	tasks = append(tasks,
		network.Enable(),
		chromedp.ActionFunc(func(ctx context.Context) error {
			if len(extraHeaders) > 0 {
				if err := network.SetExtraHTTPHeaders(extraHeaders).Do(ctx); err != nil {
					return err
				}
			}
			for name, value := range profile.Cookies {
				if host == "" {
					break
				}
				if err := network.SetCookie(name, value).
					WithDomain(host).
					WithHTTPOnly(false).
					Do(ctx); err != nil {
					return err
				}
			}
			return nil
		}),
	)

	tasks = append(tasks,
		chromedp.Navigate(target),
		chromedp.Title(&title),
		chromedp.Evaluate(`Array.from(document.querySelectorAll('a[href]')).map(a => a.href).slice(0, 100)`, &links),
		chromedp.Evaluate(`document.querySelectorAll('form').length`, &formCount),
		chromedp.Evaluate(`Array.from(document.querySelectorAll('form')).filter(f => {
			const html = f.innerHTML.toLowerCase();
			return html.includes('csrf') || html.includes('_token') || html.includes('xsrf');
		}).length`, &csrfLikeCount),
	)

	err := chromedp.Run(ctx, tasks...)
	if err != nil {
		return nil, err
	}

	findings := []model.Finding{
		{
			ID:             "browser-page-fingerprint",
			Category:       "discovery",
			Severity:       model.SeverityInfo,
			Title:          "Headless crawl completed",
			Description:    "Basic client-side reconnaissance data was collected for remediation planning.",
			Evidence:       fmt.Sprintf("title=%q links=%d forms=%d", title, len(links), formCount),
			Recommendation: "Review exposed routes and forms; reduce unnecessary attack surface.",
		},
	}

	if formCount > 0 && csrfLikeCount == 0 {
		findings = append(findings, model.Finding{
			ID:             "browser-form-csrf-indicator",
			Category:       "csrf",
			Severity:       model.SeverityMedium,
			Title:          "Forms detected without visible CSRF indicator",
			Description:    "No obvious CSRF token markers were observed in form markup during static DOM inspection.",
			Evidence:       fmt.Sprintf("forms=%d csrfLike=%d", formCount, csrfLikeCount),
			Recommendation: "Implement verified anti-CSRF controls server-side and validate on submission.",
		})
	}

	if len(links) > 0 {
		external := 0
		for _, l := range links {
			if !strings.Contains(l, hostFromURL(target)) {
				external++
			}
		}
		if external > 0 {
			findings = append(findings, model.Finding{
				ID:             "browser-external-links",
				Category:       "surface",
				Severity:       model.SeverityLow,
				Title:          "External links found",
				Description:    "The app references external domains that may affect data flow and trust boundaries.",
				Evidence:       fmt.Sprintf("externalLinks=%d", external),
				Recommendation: "Review third-party integrations and enforce strict content/security policies.",
			})
		}
	}

	return findings, nil
}
