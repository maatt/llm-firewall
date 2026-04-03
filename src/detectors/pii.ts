import type { DetectionResult } from "../types.js";

const PII_PATTERNS: Array<{ name: string; pattern: RegExp; severity: "low" | "medium" | "high" | "critical" }> = [
  // ─── CLOUD / SERVICE CREDENTIALS ─────────────────────────────────────────────
  { name: "aws-access-key", pattern: /AKIA[0-9A-Z]{16}/i, severity: "critical" },
  { name: "aws-secret-key", pattern: /(?:aws[_-]?secret[_-]?(?:access[_-]?)?key)\s*[:=]\s*['"]?[A-Za-z0-9/+]{40}/i, severity: "critical" },
  { name: "gcp-api-key", pattern: /AIza[0-9A-Za-z\-_]{35}/, severity: "critical" },
  { name: "github-token", pattern: /(?:ghp|gho|ghu|ghs|ghr|github_pat)_[A-Za-z0-9_]{36,255}/, severity: "critical" },
  { name: "slack-token", pattern: /xox[bpars]-[0-9A-Za-z\-]{10,72}/, severity: "critical" },
  { name: "stripe-key", pattern: /(?:sk|pk)_(?:live|test)_[0-9a-zA-Z]{24,}/, severity: "critical" },
  { name: "twilio-key", pattern: /SK[0-9a-fA-F]{32}/, severity: "critical" },
  { name: "sendgrid-key", pattern: /SG\.[A-Za-z0-9\-_]{22}\.[A-Za-z0-9\-_]{43}/, severity: "critical" },
  { name: "shopify-token", pattern: /shpss?_[a-fA-F0-9]{32}/, severity: "critical" },
  { name: "discord-token", pattern: /[MN][A-Za-z0-9]{23}\.[A-Za-z0-9_-]{6}\.[A-Za-z0-9_-]{27,}/, severity: "critical" },
  { name: "firebase-url", pattern: /https:\/\/[a-z0-9\-]+\.firebaseio\.com/, severity: "high" },

  // ─── GENERIC SECRETS ─────────────────────────────────────────────────────────
  { name: "api-key", pattern: /(?:api[_-]?key|apikey)\s*[:=]\s*['"]?[A-Za-z0-9_\-]{16,}/i, severity: "critical" },
  { name: "secret-key", pattern: /(?:secret[_-]?key|client[_-]?secret)\s*[:=]\s*['"]?[A-Za-z0-9_\-]{16,}/i, severity: "critical" },
  { name: "password", pattern: /(?:password|passwd|pwd)\s*[:=]\s*['"]?.{6,}/i, severity: "critical" },
  { name: "bearer-token", pattern: /bearer\s+[A-Za-z0-9\-._~+/]+=*/i, severity: "critical" },
  { name: "private-key-block", pattern: /-----BEGIN\s+(?:RSA\s+|EC\s+|DSA\s+|OPENSSH\s+)?PRIVATE\s+KEY-----/, severity: "critical" },
  { name: "connection-string", pattern: /(?:mongodb(?:\+srv)?|postgresql|mysql|redis|amqp|rabbitmq):\/\/[^:]+:[^@]+@/, severity: "critical" },
  { name: "jwt", pattern: /eyJ[A-Za-z0-9\-_]+\.eyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+/, severity: "high" },
  { name: "basic-auth", pattern: /Authorization:\s*Basic\s+[A-Za-z0-9+/=]{8,}/i, severity: "critical" },

  // ─── FINANCIAL ───────────────────────────────────────────────────────────────
  { name: "credit-card", pattern: /\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12}|3(?:0[0-5]|[68][0-9])[0-9]{11})\b/, severity: "high" },
  { name: "iban", pattern: /\b[A-Z]{2}\d{2}[A-Z0-9]{1,30}\b/, severity: "high" },
  { name: "ssn", pattern: /\b(?!000|666|9\d{2})\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b/, severity: "high" },
  { name: "sort-code", pattern: /\b\d{2}-\d{2}-\d{2}\b/, severity: "medium" },
  { name: "bank-account", pattern: /(?:account\s+(?:number|no\.?)|bank\s+account)\s*[:=]?\s*\d{6,18}/i, severity: "high" },

  // ─── GOVERNMENT / IDENTITY DOCUMENTS ─────────────────────────────────────────
  { name: "passport", pattern: /(?:passport\s+(?:number|no\.?))\s*[:=]?\s*[A-Z]{1,2}\d{6,9}/i, severity: "high" },
  { name: "national-insurance", pattern: /\b[A-CEGHJ-PR-TW-Z]{1}[A-CEGHJ-NPR-TW-Z]{1}[0-9]{6}[A-D]{1}\b/i, severity: "high" },
  { name: "driving-licence", pattern: /(?:driving\s+licen[cs]e?|driver(?:'s)?\s+licen[cs]e?)\s*(?:number|no\.?)?\s*[:=]?\s*[A-Z0-9]{5,20}/i, severity: "medium" },
  { name: "date-of-birth", pattern: /(?:date\s+of\s+birth|dob|born\s+on?|birthday)\s*[:=]?\s*(?:\d{1,2}[\/\-\.]\d{1,2}[\/\-\.]\d{2,4}|\d{4}[\/\-\.]\d{2}[\/\-\.]\d{2})/i, severity: "medium" },

  // ─── MEDICAL / HEALTH ─────────────────────────────────────────────────────────
  { name: "medical-record", pattern: /(?:mrn|medical\s+record\s+(?:number|no\.?)|patient\s+id)\s*[:=]?\s*[A-Z0-9]{5,20}/i, severity: "high" },
  { name: "health-insurance", pattern: /(?:health\s+insurance\s+(?:number|policy)|nhs\s+number|medicare\s+(?:number|id))\s*[:=]?\s*[A-Z0-9\-\s]{6,20}/i, severity: "high" },

  // ─── CONTACT INFORMATION ─────────────────────────────────────────────────────
  { name: "email", pattern: /\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b/, severity: "low" },
  { name: "phone-us", pattern: /\b(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b/, severity: "low" },
  { name: "phone-intl", pattern: /\+(?:[0-9]\s?){6,14}[0-9]/, severity: "low" },
  { name: "home-address", pattern: /\b\d{1,5}\s+[A-Za-z0-9\s]+(?:street|st|avenue|ave|road|rd|boulevard|blvd|lane|ln|drive|dr|court|ct|way|pl|place)\b/i, severity: "medium" },
  { name: "postcode-uk", pattern: /\b[A-Z]{1,2}\d[A-Z\d]?\s*\d[A-Z]{2}\b/i, severity: "low" },
  { name: "zip-code", pattern: /\b\d{5}(?:-\d{4})?\b/, severity: "low" },
  { name: "ip-address", pattern: /\b(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b/, severity: "low" },

  // ─── CRYPTO ──────────────────────────────────────────────────────────────────
  { name: "crypto-private-key", pattern: /(?:private\s+key|seed\s+phrase|mnemonic)\s*[:=]?\s*(?:[a-z]+\s+){11,23}[a-z]+/i, severity: "critical" },
  { name: "bitcoin-wif", pattern: /[5KL][1-9A-HJ-NP-Za-km-z]{50,51}/, severity: "critical" },
  { name: "ethereum-key", pattern: /0x[a-fA-F0-9]{64}/, severity: "critical" },
];

export function detectPII(prompt: string): DetectionResult {
  const matches: string[] = [];
  let maxSeverity: "low" | "medium" | "high" | "critical" | undefined;

  const severityOrder = ["low", "medium", "high", "critical"];

  for (const { name, pattern, severity } of PII_PATTERNS) {
    if (pattern.test(prompt)) {
      matches.push(name);
      if (
        maxSeverity === undefined ||
        severityOrder.indexOf(severity) > severityOrder.indexOf(maxSeverity)
      ) {
        maxSeverity = severity;
      }
    }
  }

  if (matches.length === 0) {
    return { detector: "pii", triggered: false };
  }

  return {
    detector: "pii",
    triggered: true,
    severity: maxSeverity,
    reason: "Sensitive data detected in prompt",
    matches,
  };
}
