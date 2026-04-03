import type { DetectionResult } from "../types.js";

const INJECTION_PATTERNS: Array<{ pattern: RegExp; severity: "low" | "medium" | "high" | "critical" }> = [
  // ─── DIRECT INSTRUCTION OVERRIDE ─────────────────────────────────────────────
  { pattern: /ignore\s+(all\s+)?(previous|prior|above|earlier)\s+instructions?/i, severity: "critical" },
  { pattern: /disregard\s+(all\s+)?(previous|prior|above|earlier)\s+instructions?/i, severity: "critical" },
  { pattern: /forget\s+(all\s+)?(previous|prior|above|earlier)\s+instructions?/i, severity: "critical" },
  { pattern: /override\s+(all\s+)?(previous|prior|above|earlier|your)\s+instructions?/i, severity: "critical" },
  { pattern: /do\s+not\s+follow\s+(your\s+)?(previous|prior|original|system)\s+instructions?/i, severity: "critical" },
  { pattern: /from\s+now\s+on[,\s]+(?:you\s+(?:must|will|should)|ignore|disregard)/i, severity: "high" },
  { pattern: /your\s+new\s+(?:instructions?|rules?|directives?|guidelines?)\s+are/i, severity: "high" },
  { pattern: /replace\s+(your\s+)?(previous|prior|system|all)\s+instructions?\s+with/i, severity: "high" },

  // ─── SYSTEM PROMPT EXTRACTION ─────────────────────────────────────────────────
  { pattern: /repeat\s+(your\s+)?(system|initial|original)\s+prompt/i, severity: "high" },
  { pattern: /print\s+(your\s+)?(system|initial|original)\s+prompt/i, severity: "high" },
  { pattern: /output\s+(your\s+)?(system|initial|original|full)\s+prompt/i, severity: "high" },
  { pattern: /reveal\s+(your\s+)?(system|initial|hidden|original)\s+(prompt|instructions?|context)/i, severity: "high" },
  { pattern: /show\s+me\s+(your\s+)?(system|initial|hidden|original)\s+(prompt|instructions?)/i, severity: "high" },
  { pattern: /what\s+(?:are|were)\s+your\s+(?:original\s+)?(?:system\s+)?instructions/i, severity: "medium" },
  { pattern: /what\s+(?:is|was)\s+(?:in\s+)?your\s+system\s+prompt/i, severity: "medium" },
  { pattern: /display\s+(the\s+)?(contents?\s+of\s+)?(?:your\s+)?(?:system|initial)\s+(?:prompt|message)/i, severity: "high" },
  { pattern: /leak\s+(your\s+)?(system\s+)?(?:prompt|instructions?|context)/i, severity: "high" },
  { pattern: /dump\s+(your\s+)?(system\s+)?(?:prompt|instructions?|context|memory)/i, severity: "high" },
  { pattern: /summarize\s+(your\s+)?(system\s+)?(?:prompt|instructions?)/i, severity: "medium" },
  { pattern: /translate\s+(your\s+)?(?:system\s+)?(?:prompt|instructions?)\s+(?:to|into)/i, severity: "medium" },

  // ─── ROLE / PERSONA OVERRIDE ──────────────────────────────────────────────────
  { pattern: /you\s+are\s+now\s+(?:a\s+)?(?!assistant|helpful)[^\s.,!?]+/i, severity: "medium" },
  { pattern: /act\s+as\s+(?:if\s+you\s+(?:are|were)\s+)?(?!an?\s+assistant)[^\s.,!?]+/i, severity: "medium" },
  { pattern: /pretend\s+(?:you\s+are|to\s+be)\s+/i, severity: "medium" },
  { pattern: /roleplay\s+as\s+/i, severity: "low" },
  { pattern: /simulate\s+(?:being|a)\s+(?!helpful)[^\s.,!?]+/i, severity: "medium" },
  { pattern: /behave\s+(?:like|as)\s+(?:a\s+)?(?!helpful|an?\s+assistant)[^\s.,!?]+/i, severity: "medium" },
  { pattern: /you\s+are\s+(?:no\s+longer|not)\s+(?:an?\s+)?(?:ai|assistant|language\s+model|chatbot)/i, severity: "high" },
  { pattern: /switch\s+(?:to|into)\s+(?:developer|admin|unrestricted|jailbreak(?:ed)?|unfiltered)\s+mode/i, severity: "critical" },
  { pattern: /(?:enable|activate|enter)\s+(?:developer|admin|unrestricted|jailbreak(?:ed)?|unfiltered|god)\s+mode/i, severity: "critical" },
  { pattern: /jailbreak/i, severity: "high" },
  { pattern: /DAN\s+mode/i, severity: "high" },
  { pattern: /do\s+anything\s+now/i, severity: "high" },
  { pattern: /(?:you\s+have\s+)?no\s+(?:restrictions?|limitations?|filters?|guidelines?|rules?)/i, severity: "high" },
  { pattern: /(?:bypass|remove|disable|ignore)\s+(all\s+)?(?:safety|content|ethical)\s+(?:filter|guideline|restriction|rule|check)/i, severity: "critical" },
  { pattern: /your\s+(?:safety|ethical|content)\s+(?:filter|guideline|restriction|rule)\s+(?:is|are)\s+(?:disabled|removed|off)/i, severity: "critical" },

  // ─── HYPOTHETICAL / FICTIONAL FRAMING TO BYPASS ──────────────────────────────
  { pattern: /hypothetically[,\s]+(?:if\s+)?(?:you\s+(?:could|had\s+to|were\s+allowed))/i, severity: "low" },
  { pattern: /in\s+a\s+fictional\s+(?:world|story|scenario)[,\s]+(?:where\s+)?(?:there\s+are\s+no\s+rules|you\s+can)/i, severity: "medium" },
  { pattern: /for\s+(?:a\s+)?(?:story|novel|game|fiction)[,\s]+(?:write|describe|explain)\s+(?:how\s+to|the\s+process\s+of)/i, severity: "low" },
  { pattern: /imagine\s+(?:you\s+are\s+a|there\s+are\s+no)\s+(?:different\s+ai|unrestricted|no\s+rules|evil)/i, severity: "medium" },
  { pattern: /(?:in\s+)?character\s+(?:as|named)\s+(?:\w+\s+)?who\s+(?:has\s+no|ignores|doesn't\s+have)\s+(?:restrictions?|ethics?|rules?|guidelines?)/i, severity: "high" },

  // ─── INDIRECT / SECOND-ORDER INJECTION ───────────────────────────────────────
  { pattern: /(?:the\s+(?:document|file|page|article|email|message)\s+(?:says?|contains?|instructs?|tells?\s+you)\s*:?\s*)ignore/i, severity: "high" },
  { pattern: /\[(?:system|admin|override|inject)\]/i, severity: "high" },
  { pattern: /<<(?:SYS|INST|OVERRIDE)>>/i, severity: "high" },
  { pattern: /\/\/\s*(?:system|override|inject)\s*:/i, severity: "medium" },

  // ─── TOKEN / FORMAT INJECTION ────────────────────────────────────────────────
  { pattern: /\[INST\]|\[\/INST\]/i, severity: "medium" },
  { pattern: /<\|system\|>|<\|user\|>|<\|assistant\|>|<\|im_start\|>|<\|im_end\|>/i, severity: "high" },
  { pattern: /###\s*(?:instruction|system|override|human|assistant)/i, severity: "medium" },
  { pattern: /<s>\s*\[INST\]/i, severity: "high" },
  { pattern: /\u200b|\u200c|\u200d|\ufeff|\u00ad/u, severity: "medium" }, // zero-width chars
  { pattern: /&#x200[bcd];|&#8203;|&#8204;|&#8205;/i, severity: "medium" }, // HTML zero-width
  { pattern: /prompt\s*injection/i, severity: "high" },

  // ─── ENCODING / OBFUSCATION ───────────────────────────────────────────────────
  { pattern: /base64[:\s]+[A-Za-z0-9+/=]{20,}/i, severity: "low" },
  { pattern: /(?:decode|run|execute)\s+(?:this\s+)?(?:base64|hex|rot13|encoded)/i, severity: "medium" },
  { pattern: /(?:the\s+following|this)\s+is\s+(?:encoded|encrypted|obfuscated)[:\s]/i, severity: "medium" },

  // ─── CONTEXT MANIPULATION ────────────────────────────────────────────────────
  { pattern: /as\s+(?:we|I)\s+(?:discussed|agreed|established|decided)\s+(?:earlier|before|previously)/i, severity: "low" },
  { pattern: /you\s+(?:already\s+)?(?:agreed|said|told\s+me|confirmed)\s+(?:that\s+)?you\s+(?:would|can|will)/i, severity: "medium" },
  { pattern: /(?:your\s+)?previous\s+(?:response|message|output)\s+(?:was|said|contained)/i, severity: "low" },
  { pattern: /continue\s+(?:from|where\s+you\s+left\s+off|the\s+(?:following|previous))\s*:/i, severity: "low" },

  // ─── PROMPT COMPLETION ATTACKS ───────────────────────────────────────────────
  { pattern: /complete\s+the\s+following\s+(?:without\s+(?:restrictions?|filters?)|ignoring)/i, severity: "high" },
  { pattern: /finish\s+(?:this|the\s+following)\s+sentence[:\s]+(?:sure|yes|i\s+will|of\s+course|here\s+is)/i, severity: "medium" },
];

export function detectInjection(prompt: string): DetectionResult {
  const matches: string[] = [];
  let maxSeverity: "low" | "medium" | "high" | "critical" | undefined;

  const severityOrder = ["low", "medium", "high", "critical"];

  for (const { pattern, severity } of INJECTION_PATTERNS) {
    const match = prompt.match(pattern);
    if (match) {
      matches.push(match[0]);
      if (
        maxSeverity === undefined ||
        severityOrder.indexOf(severity) > severityOrder.indexOf(maxSeverity)
      ) {
        maxSeverity = severity;
      }
    }
  }

  if (matches.length === 0) {
    return { detector: "injection", triggered: false };
  }

  return {
    detector: "injection",
    triggered: true,
    severity: maxSeverity,
    reason: "Prompt injection pattern detected",
    matches,
  };
}
