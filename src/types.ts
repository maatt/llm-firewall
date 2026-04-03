export type DetectorName = "injection" | "pii" | "harmful" | "judge" | "policy";

export type Severity = "low" | "medium" | "high" | "critical";

export type HarmCategory =
  | "weapons"
  | "explosives"
  | "firearms"
  | "chemical-weapons"
  | "bioweapons"
  | "radiological"
  | "drugs"
  | "cyberattack"
  | "fraud"
  | "human-trafficking"
  | "csam"
  | "self-harm"
  | "violence"
  | "terrorism"
  | "personal-targeting"
  | "extremism"
  | "financial-crime";

export interface DetectionResult {
  detector: DetectorName;
  triggered: boolean;
  severity?: Severity;
  reason?: string;
  matches?: string[];
  categories?: HarmCategory[];
  /** Populated when detector is "judge" — the model's reasoning for its verdict. */
  judgeReasoning?: string;
}

export interface FirewallResult {
  allowed: boolean;
  detections: DetectionResult[];
  prompt: string;
}

export interface FirewallConfig {
  detectors?: DetectorName[];
  blockOnSeverity?: Severity[];
}

export interface AnalyzeRequest {
  prompt: string;
  config?: FirewallConfig;
}
