/**
 * Redaction — strip sensitive data from a prompt instead of blocking it.
 *
 * Matches the same PII patterns as the pii detector but replaces each
 * match in-place with a [REDACTED:type] placeholder, producing a
 * sanitized prompt safe to forward to your LLM.
 */

export interface Redaction {
  /** The PII type that was redacted, e.g. "email", "api-key" */
  type: string;
  /** The placeholder that replaced it, e.g. "[REDACTED:email]" */
  replacement: string;
}

export interface RedactResult {
  /** The sanitized prompt with all sensitive data replaced */
  redacted: string;
  /** The original unmodified prompt */
  original: string;
  /** One entry per unique PII type that was found and replaced */
  redactions: Redaction[];
}

interface RedactPattern {
  name: string;
  pattern: RegExp;
}

// Mirror of pii.ts patterns but with global flag for replaceAll
const REDACT_PATTERNS: RedactPattern[] = [
  // Cloud / service credentials
  { name: "aws-access-key", pattern: /AKIA[0-9A-Z]{16}/gi },
  { name: "aws-secret-key", pattern: /(?:aws[_-]?secret[_-]?(?:access[_-]?)?key)\s*[:=]\s*['"]?[A-Za-z0-9/+]{40}/gi },
  { name: "gcp-api-key", pattern: /AIza[0-9A-Za-z\-_]{35}/g },
  { name: "github-token", pattern: /(?:ghp|gho|ghu|ghs|ghr|github_pat)_[A-Za-z0-9_]{36,255}/g },
  { name: "slack-token", pattern: /xox[bpars]-[0-9A-Za-z\-]{10,72}/g },
  { name: "stripe-key", pattern: /(?:sk|pk)_(?:live|test)_[0-9a-zA-Z]{24,}/g },
  { name: "twilio-key", pattern: /SK[0-9a-fA-F]{32}/g },
  { name: "sendgrid-key", pattern: /SG\.[A-Za-z0-9\-_]{22}\.[A-Za-z0-9\-_]{43}/g },
  { name: "discord-token", pattern: /[MN][A-Za-z0-9]{23}\.[A-Za-z0-9_-]{6}\.[A-Za-z0-9_-]{27,}/g },

  // Generic secrets
  { name: "api-key", pattern: /(?:api[_-]?key|apikey)\s*[:=]\s*['"]?[A-Za-z0-9_\-]{16,}/gi },
  { name: "secret-key", pattern: /(?:secret[_-]?key|client[_-]?secret)\s*[:=]\s*['"]?[A-Za-z0-9_\-]{16,}/gi },
  { name: "password", pattern: /(?:password|passwd|pwd)\s*[:=]\s*['"]?.{6,}/gi },
  { name: "jwt", pattern: /eyJ[A-Za-z0-9\-_]+\.eyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+/g },
  { name: "bearer-token", pattern: /bearer(?:\s+token)?\s*[:=]?\s+[A-Za-z0-9\-._~+/]{8,}=*/gi },
  { name: "private-key", pattern: /-----BEGIN\s+(?:RSA\s+|EC\s+|DSA\s+|OPENSSH\s+)?PRIVATE\s+KEY-----.+?-----END[^-]+PRIVATE\s+KEY-----/gs },
  { name: "connection-string", pattern: /(?:mongodb(?:\+srv)?|postgresql|mysql|redis|amqp|rabbitmq):\/\/[^:]+:[^@]+@[^\s"']+/gi },
  { name: "basic-auth", pattern: /Authorization:\s*Basic\s+[A-Za-z0-9+/=]{8,}/gi },

  // Financial
  { name: "credit-card", pattern: /\b(?:4[0-9]{3}(?:[ \-]?[0-9]{4}){3}|5[1-5][0-9]{2}(?:[ \-]?[0-9]{4}){3}|3[47][0-9]{2}[ \-]?[0-9]{6}[ \-]?[0-9]{5}|6(?:011|5[0-9]{2})(?:[ \-]?[0-9]{4}){3}|3(?:0[0-5]|[68][0-9])[0-9]{2}[ \-]?[0-9]{6}[ \-]?[0-9]{4})\b/g },
  { name: "ssn", pattern: /\b(?!000|666|9\d{2})\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b/g },
  { name: "iban", pattern: /\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b/g },

  // Identity
  { name: "passport", pattern: /(?:passport\s+(?:number|no\.?))\s*[:=]?\s*[A-Z]{1,2}\d{6,9}/gi },
  { name: "national-insurance", pattern: /\b[A-CEGHJ-PR-TW-Z]{1}[A-CEGHJ-NPR-TW-Z]{1}[0-9]{6}[A-D]{1}\b/gi },

  // Contact
  { name: "email", pattern: /\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b/g },
  { name: "phone", pattern: /\b(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b/g },

  // Crypto
  { name: "ethereum-key", pattern: /0x[a-fA-F0-9]{64}/g },
  { name: "bitcoin-wif", pattern: /[5KL][1-9A-HJ-NP-Za-km-z]{50,51}/g },
];

/**
 * Scan a prompt for sensitive data and replace each match with a
 * [REDACTED:type] placeholder.
 *
 * @example
 * const { redacted, redactions } = redact("My email is foo@bar.com and key is AKIAIOSFODNN7EXAMPLE");
 * // redacted  → "My email is [REDACTED:email] and key is [REDACTED:aws-access-key]"
 * // redactions → [{ type: "email", ... }, { type: "aws-access-key", ... }]
 *
 * // Use the sanitized prompt instead of the original
 * const result = firewall.analyze(redacted);
 */
export function redact(prompt: string): RedactResult {
  let redacted = prompt;
  const seen = new Set<string>();
  const redactions: Redaction[] = [];

  for (const { name, pattern } of REDACT_PATTERNS) {
    const replacement = `[REDACTED:${name}]`;
    const replaced = redacted.replace(pattern, replacement);

    if (replaced !== redacted) {
      redacted = replaced;
      if (!seen.has(name)) {
        seen.add(name);
        redactions.push({ type: name, replacement });
      }
    }
  }

  return { original: prompt, redacted, redactions };
}
