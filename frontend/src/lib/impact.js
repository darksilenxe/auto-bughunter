export const IMPACT_GOALS = [
  {
    id: "account_takeover",
    label: "Account takeover",
    shortLabel: "ATO",
    description: "Prove login/session takeover or password reset abuse.",
  },
  {
    id: "cross_tenant_access",
    label: "Cross-tenant access",
    shortLabel: "Tenant breakout",
    description: "Demonstrate unauthorized cross-account or cross-tenant access.",
  },
  {
    id: "sensitive_data_exposure",
    label: "Sensitive data exposure",
    shortLabel: "Data exposure",
    description: "Show access to high-value customer, token, or secret data.",
  },
  {
    id: "payment_abuse",
    label: "Payment abuse",
    shortLabel: "Payment abuse",
    description: "Target invoice, coupon, credit, or checkout abuse scenarios.",
  },
  {
    id: "auth_bypass",
    label: "Auth bypass",
    shortLabel: "Auth bypass",
    description: "Focus on meaningful bypasses of authentication or authorization.",
  },
  {
    id: "stored_xss",
    label: "Stored XSS",
    shortLabel: "Stored XSS",
    description: "Prioritize durable victim impact and session abuse from XSS.",
  },
];

export const DEFAULT_IMPACT_GOALS = IMPACT_GOALS.map((goal) => goal.id);

export function scoreFinding(finding) {
  return Number(finding?.bountyScore ?? finding?.impactScore ?? finding?.confidence ?? 0);
}

export function severityWeight(severity) {
  switch ((severity || "").toLowerCase()) {
    case "critical":
      return 5;
    case "high":
      return 4;
    case "medium":
      return 3;
    case "low":
      return 2;
    default:
      return 1;
  }
}

export function proofStateLabel(state) {
  return (state || "suspected").replaceAll("_", " ");
}

export function proofStateWeight(state) {
  switch ((state || "").toLowerCase()) {
    case "submission_ready":
      return 5;
    case "impact_demonstrated":
      return 4;
    case "exploited":
      return 3;
    case "validated":
      return 2;
    default:
      return 1;
  }
}

export function compareFindings(a, b) {
  const bountyDelta = Number(b?.bountyScore || 0) - Number(a?.bountyScore || 0);
  if (bountyDelta !== 0) return bountyDelta;
  const impactDelta = Number(b?.impactScore || 0) - Number(a?.impactScore || 0);
  if (impactDelta !== 0) return impactDelta;
  const proofDelta = proofStateWeight(b?.proofState) - proofStateWeight(a?.proofState);
  if (proofDelta !== 0) return proofDelta;
  const severityDelta = severityWeight(b?.severity) - severityWeight(a?.severity);
  if (severityDelta !== 0) return severityDelta;
  return Number(b?.confidence || 0) - Number(a?.confidence || 0);
}

export function sortFindings(findings = []) {
  return [...findings].sort(compareFindings);
}

export function summarizeFindings(findings = []) {
  const ordered = sortFindings(findings);
  const summary = {
    total: ordered.length,
    submissionReady: 0,
    demonstrated: 0,
    chains: 0,
    proofArtifacts: 0,
    avgBountyScore: 0,
    topFinding: ordered[0] || null,
    severities: { critical: 0, high: 0, medium: 0, low: 0, info: 0 },
  };

  if (!ordered.length) return summary;

  let bountySum = 0;
  for (const finding of ordered) {
    const severity = (finding?.severity || "info").toLowerCase();
    if (summary.severities[severity] !== undefined) summary.severities[severity] += 1;
    if (finding?.proofState === "submission_ready") summary.submissionReady += 1;
    if (finding?.proofState === "impact_demonstrated" || finding?.proofState === "submission_ready") {
      summary.demonstrated += 1;
    }
    if ((finding?.businessTags || []).some((tag) => String(tag).includes("chain:")) || String(finding?.id || "").includes("chain")) {
      summary.chains += 1;
    }
    summary.proofArtifacts += Array.isArray(finding?.proofArtifacts) ? finding.proofArtifacts.length : 0;
    bountySum += Number(finding?.bountyScore || 0);
  }
  summary.avgBountyScore = bountySum / ordered.length;
  return summary;
}

export function topGoals(findings = []) {
  const counts = new Map();
  for (const finding of findings) {
    for (const goal of finding?.impactGoals || []) {
      counts.set(goal, (counts.get(goal) || 0) + 1);
    }
  }
  return [...counts.entries()]
    .sort((a, b) => b[1] - a[1])
    .slice(0, 4)
    .map(([goal, count]) => ({ goal, count }));
}

export function impactGoalMeta(goal) {
  const fallbackLabel = (goal || "").replaceAll("_", " ");
  return IMPACT_GOALS.find((item) => item.id === goal) || {
    id: goal,
    label: fallbackLabel,
    shortLabel: fallbackLabel,
    description: "",
  };
}
