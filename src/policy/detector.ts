import type { DetectionResult, Severity } from "../types.js";
import type { CompiledPolicyRule, PolicyRule } from "./types.js";

export function compileRules(rules: PolicyRule[]): CompiledPolicyRule[] {
  return rules.map((r) => ({
    name: r.name,
    pattern: r.pattern instanceof RegExp ? r.pattern : new RegExp(r.pattern, "i"),
    severity: r.severity,
    reason: r.reason ?? `Policy rule "${r.name}" matched`,
  }));
}

export function detectPolicy(
  prompt: string,
  rules: CompiledPolicyRule[]
): DetectionResult {
  const matches: string[] = [];
  let maxSeverity: Severity | undefined;

  const severityOrder: Severity[] = ["low", "medium", "high", "critical"];

  for (const rule of rules) {
    const match = prompt.match(rule.pattern);
    if (match) {
      matches.push(rule.name);
      if (
        maxSeverity === undefined ||
        severityOrder.indexOf(rule.severity) > severityOrder.indexOf(maxSeverity)
      ) {
        maxSeverity = rule.severity;
      }
    }
  }

  if (matches.length === 0) {
    return { detector: "policy", triggered: false };
  }

  // Build a reason from all matched rule names
  const triggeredRules = rules.filter((r) => matches.includes(r.name));
  const reason = triggeredRules.map((r) => r.reason).join("; ");

  return {
    detector: "policy",
    triggered: true,
    severity: maxSeverity,
    reason,
    matches,
  };
}
