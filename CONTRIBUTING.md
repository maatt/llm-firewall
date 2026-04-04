# Contributing to llm-firewall

Thanks for your interest in contributing. This doc covers everything you need.

## Prerequisites

- Node.js **>=20**
- npm

## Setup

```bash
git clone https://github.com/maatt/llm-firewall.git
cd llm-firewall
npm install
```

## Development workflow

```bash
npm test           # run the test suite
npm run typecheck  # TypeScript type check (no emit)
npm run build      # compile to dist/ (ESM + CJS)
npm run dev        # watch mode
```

All three checks (typecheck, test, build) must pass before a PR is merged. CI runs them on Node 20 and 22.

## Project layout

```
src/
  detectors/        # Rule-based detectors (injection, pii, harmful)
  judge/
    providers/      # LLM judge adapters (Anthropic, OpenAI, …)
    prompt.ts       # Shared system prompt for all judges
  audit/
    loggers/        # ConsoleLogger, FileLogger, WebhookLogger
  policy/           # Custom policy rule support
  firewall.ts       # Firewall class + functional API
  redact.ts         # PII redaction
  types.ts          # Shared types
  lib.ts            # Public exports
examples/           # Runnable examples (tsx)
tests/              # Vitest test suite
```

## Adding or improving detection patterns

Detector patterns live in `src/detectors/`. Each file exports a single `detect*` function that returns a `DetectionResult`.

**Rules for new patterns:**

- Add a test case in `tests/` before adding the pattern — a failing test is the best spec
- Be precise: prefer anchored or context-aware patterns over broad matches
- Avoid false positives on common, benign text (e.g. educational discussions, security research context)
- Assign severity using the existing scale:
  - `low` — informational, unlikely to cause direct harm
  - `medium` — suspicious intent, warrants review
  - `high` — clear harmful or extraction intent
  - `critical` — immediate threat (jailbreak, weapon synthesis, CSAM, live credentials)
- Group new patterns under the nearest existing comment section, or add a new clearly labelled section

## Adding a new judge provider

1. Create `src/judge/providers/<name>.ts`
2. Implement the `JudgeProvider` interface:
   ```ts
   export class MyJudge implements JudgeProvider {
     async evaluate(prompt: string): Promise<JudgeVerdict> { … }
   }
   ```
3. Use duck typing — do **not** import the provider's SDK directly; define a minimal interface for the client you accept
4. Export from `src/lib.ts`
5. Add usage docs to `docs/wiki/Judge-Providers.md` and a section to the README judge table
6. Add a test in `tests/`

## Adding a new audit logger

1. Create `src/audit/loggers/<name>.ts`
2. Implement `AuditLogger`:
   ```ts
   export class MyLogger implements AuditLogger {
     async log(entry: AuditEntry): Promise<void> { … }
   }
   ```
3. Export from `src/lib.ts`
4. Errors must be silently swallowed — loggers must never affect firewall behaviour

## Tests

Tests live in `tests/` and use [Vitest](https://vitest.dev). Run them with:

```bash
npm test          # single run
npm run test:watch  # watch mode
```

Every new feature or bug fix should include a test. Detector tests use plain strings — no mocks needed.

## Pull requests

- Keep PRs focused — one feature or fix per PR
- Run `npm test && npm run typecheck` locally before pushing
- Describe *what* the change does and *why* in the PR body
- If adding patterns, include example prompts that triggered the gap

## Reporting issues

Use [GitHub Issues](https://github.com/maatt/llm-firewall/issues). For security-sensitive findings (e.g. a bypass technique you don't want public), open a private security advisory instead.

## Licence

By contributing you agree your changes will be released under the [MIT Licence](./LICENSE).
