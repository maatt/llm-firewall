import type { Severity } from "../types.js";

export interface PolicyRule {
  /** Unique name for this rule — appears in detection matches */
  name: string;
  /** RegExp or string pattern (strings are compiled to case-insensitive RegExp) */
  pattern: RegExp | string;
  severity: Severity;
  /** Human-readable reason shown in detection results */
  reason?: string;
}

export interface CompiledPolicyRule {
  name: string;
  pattern: RegExp;
  severity: Severity;
  reason: string;
}
