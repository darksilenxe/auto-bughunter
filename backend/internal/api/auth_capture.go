package api

import (
	"sort"
	"time"

	"auto-bughunter/backend/internal/model"
)

const proxySessionMaxAge = 60 * time.Minute

func mergeScanAuthProfile(explicit, captured model.ScanAuthProfile) model.ScanAuthProfile {
	merged := cloneScanAuthProfile(captured)
	if merged.Headers == nil && len(explicit.Headers) > 0 {
		merged.Headers = map[string]string{}
	}
	for key, value := range explicit.Headers {
		merged.Headers[key] = value
	}
	if merged.Cookies == nil && len(explicit.Cookies) > 0 {
		merged.Cookies = map[string]string{}
	}
	for key, value := range explicit.Cookies {
		merged.Cookies[key] = value
	}
	if explicit.UserAgent != "" {
		merged.UserAgent = explicit.UserAgent
	}
	if explicit.BasicAuthUsername != "" {
		merged.BasicAuthUsername = explicit.BasicAuthUsername
	}
	if explicit.BasicAuthPassword != "" {
		merged.BasicAuthPassword = explicit.BasicAuthPassword
	}
	if explicit.LoginURL != "" {
		merged.LoginURL = explicit.LoginURL
	}
	if explicit.Username != "" {
		merged.Username = explicit.Username
	}
	if explicit.Password != "" {
		merged.Password = explicit.Password
	}
	if len(explicit.LoginSteps) > 0 {
		merged.LoginSteps = append([]model.ScanAuthLoginStep(nil), explicit.LoginSteps...)
	}
	return merged
}

func cloneScanAuthProfile(profile model.ScanAuthProfile) model.ScanAuthProfile {
	cloned := profile
	if len(profile.Headers) > 0 {
		cloned.Headers = make(map[string]string, len(profile.Headers))
		for key, value := range profile.Headers {
			cloned.Headers[key] = value
		}
	}
	if len(profile.Cookies) > 0 {
		cloned.Cookies = make(map[string]string, len(profile.Cookies))
		for key, value := range profile.Cookies {
			cloned.Cookies[key] = value
		}
	}
	if len(profile.LoginSteps) > 0 {
		cloned.LoginSteps = append([]model.ScanAuthLoginStep(nil), profile.LoginSteps...)
	}
	return cloned
}

func authProfilesEqual(left, right model.ScanAuthProfile) bool {
	return scanAuthProfileSignature(left) == scanAuthProfileSignature(right)
}

func scanAuthProfileSignature(profile model.ScanAuthProfile) string {
	summary := model.SummarizeAuthProfile(profile)
	if summary == nil {
		return ""
	}
	return summary.UserAgent + "|" + summary.LoginURL + "|" +
		boolString(summary.HasBasicAuth) + "|" +
		boolString(summary.HasStandardAuth) + "|" +
		joinSorted(summary.HeaderKeys) + "|" +
		joinSorted(summary.CookieNames)
}

func boolString(value bool) string {
	if value {
		return "1"
	}
	return "0"
}

func joinSorted(items []string) string {
	if len(items) == 0 {
		return ""
	}
	cp := append([]string(nil), items...)
	sort.Strings(cp)
	out := cp[0]
	for _, item := range cp[1:] {
		out += "," + item
	}
	return out
}

func (s *Server) applyCapturedProxyAuthProfile(target string, explicit model.ScanAuthProfile) (model.ScanAuthProfile, bool) {
	if s == nil || s.proxyServer == nil {
		return explicit, false
	}
	captured, ok := s.proxyServer.LatestAuthProfileForTarget(target, proxySessionMaxAge)
	if !ok {
		return explicit, false
	}
	merged := mergeScanAuthProfile(explicit, captured)
	return merged, !authProfilesEqual(explicit, merged)
}
