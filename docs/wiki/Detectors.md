# Detectors

Three built-in rule-based detectors, all enabled by default. They run synchronously with zero dependencies.

## Built-in detectors

| Detector | What it catches |
|----------|-----------------|
| `injection` | Jailbreaks, DAN/god mode, named personas (AIM, STAN, EvilBot…), system prompt extraction, instruction overrides, token injection, zero-width char obfuscation, encoding bypass, multi-turn setup attacks |
| `pii` | API keys (AWS, GCP, GitHub, Slack, Stripe, Twilio…), passwords, bearer tokens, JWTs, connection strings, credit cards, SSNs, IBANs, passports, NHS/NI numbers, crypto private keys |
| `harmful` | Weapons, explosives, 3D-printed firearms, chemical/bio/radiological, drugs, malware, phishing, fraud, human trafficking, CSAM, self-harm, eating disorders, terrorism, swatting, acid attacks, infrastructure attacks, sexual solicitation |

## Configuring detectors

```ts
const firewall = new Firewall()
  .use("injection", "harmful")      // run only these detectors
  .blockOn("high", "critical");     // block only on these severities
```

`.use()` accepts any combination of `"injection"`, `"pii"`, `"harmful"`. Omit it to run all three.

`.blockOn()` accepts any combination of `"low"`, `"medium"`, `"high"`, `"critical"`. Default is `["high", "critical"]`.

## Using detectors directly

```ts
import { detectInjection, detectPII, detectHarmful } from "llm-firewall";

const result = detectInjection(prompt);
// {
//   detector: "injection",
//   triggered: true,
//   severity: "critical",
//   reason: "Prompt injection pattern detected",
//   matches: ["Ignore all previous instructions"]
// }
```

Each function returns a `DetectionResult`:

```ts
interface DetectionResult {
  detector: "injection" | "pii" | "harmful" | "judge" | "policy";
  triggered: boolean;
  severity?: "low" | "medium" | "high" | "critical";
  reason?: string;
  matches?: string[];
  categories?: HarmCategory[];
  judgeReasoning?: string;
}
```

---

## Harm categories

Returned in `detections[].categories` when the `harmful` detector or judge triggers.

| Category | Examples |
|----------|----------|
| `explosives` | Bomb-making, IED assembly, C4/TATP/ANFO synthesis |
| `firearms` | Auto conversions, ghost guns, 3D-printed weapons, Glock switches, trafficking |
| `chemical-weapons` | Nerve agents, ricin, toxic gas dispersal |
| `bioweapons` | Pathogen enhancement, gain-of-function, aerosolization |
| `radiological` | Dirty bombs, uranium enrichment, nuclear devices |
| `drugs` | Fentanyl/meth synthesis, darknet sourcing, drink spiking, drug test evasion |
| `cyberattack` | Malware, ransomware, phishing kits, named exploits, infrastructure attacks |
| `fraud` | Scams, deepfakes, SIM swap, fake documents, tech support fraud, money laundering |
| `human-trafficking` | Smuggling, forced labor, exploitation |
| `csam` | Sexual content involving minors, grooming |
| `self-harm` | Suicide methods, self-cutting, pro-ana/eating disorder content |
| `violence` | Murder planning, acid attacks, swatting, poisoning, assault |
| `terrorism` | Attack planning, manifestos, mass casualty |
| `extremism` | Radicalization, hate group recruitment, propaganda |
| `personal-targeting` | Stalking, doxxing, revenge porn, harassment campaigns |
| `financial-crime` | Insider trading, tax evasion, benefits fraud |
| `weapons` | Illegal weapons trafficking |
| `sexual` | Sexual solicitation, explicit content requests |

---

## Severity levels

| Level | Examples | Blocked by default? |
|-------|----------|---------------------|
| `low` | Email address, phone number, roleplay request | No |
| `medium` | Persona override attempt, disinformation campaign | No |
| `high` | System prompt extraction, self-harm methods, phishing, sexual solicitation | **Yes** |
| `critical` | Jailbreak, API key, nerve agent synthesis, CSAM, bomb-making | **Yes** |

---

## PII types detected

| Type | Examples |
|------|----------|
| Cloud credentials | AWS access/secret keys, GCP API keys, Firebase URLs |
| Service tokens | GitHub PATs, Slack tokens, Stripe keys, Twilio keys, SendGrid keys, Shopify tokens, Discord tokens |
| Generic secrets | `api_key=…`, `secret_key=…`, `password=…`, Bearer tokens, `Authorization: Basic …` |
| Cryptographic | PEM private key blocks, Bitcoin WIF keys, Ethereum private keys, seed phrases |
| Auth tokens | JWTs, connection strings (MongoDB, PostgreSQL, MySQL, Redis, AMQP) |
| Financial | Visa/Mastercard/Amex/Discover credit cards (plain and spaced), IBANs, SSNs, sort codes, bank account numbers |
| Identity documents | Passports, National Insurance numbers, driving licences |
| Medical | Medical record numbers, NHS numbers, health insurance policy numbers |
| Contact info | Email addresses, US/international phone numbers, home addresses, UK postcodes, ZIP codes |
| Network | IPv4 addresses |
