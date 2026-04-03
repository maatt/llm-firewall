import { describe, it, expect } from "vitest";
import { redact } from "../src/redact.js";

describe("redact", () => {
  it("returns original unchanged when no PII found", () => {
    const result = redact("What is the capital of France?");
    expect(result.redacted).toBe("What is the capital of France?");
    expect(result.redactions).toHaveLength(0);
  });

  it("redacts email addresses", () => {
    const result = redact("Contact me at alice@example.com please");
    expect(result.redacted).toContain("[REDACTED:email]");
    expect(result.redacted).not.toContain("alice@example.com");
    expect(result.redactions.map((r) => r.type)).toContain("email");
  });

  it("redacts AWS access keys", () => {
    const result = redact("My key is AKIAIOSFODNN7EXAMPLE, why isn't it working?");
    expect(result.redacted).toContain("[REDACTED:aws-access-key]");
    expect(result.redacted).not.toContain("AKIAIOSFODNN7EXAMPLE");
  });

  it("redacts GitHub tokens", () => {
    const result = redact("token: ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ1234567890abcdef");
    expect(result.redacted).toContain("[REDACTED:github-token]");
  });

  it("redacts JWT tokens", () => {
    const token = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyMTIzIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
    const result = redact(`Bearer token: ${token}`);
    expect(result.redacted).toContain("[REDACTED:jwt]");
    expect(result.redacted).not.toContain(token);
  });

  it("redacts credit card numbers", () => {
    const result = redact("Card: 4111111111111111");
    expect(result.redacted).toContain("[REDACTED:credit-card]");
  });

  it("redacts SSNs", () => {
    const result = redact("SSN: 123-45-6789");
    expect(result.redacted).toContain("[REDACTED:ssn]");
  });

  it("redacts multiple different PII types in one prompt", () => {
    const result = redact("Email: foo@bar.com, Card: 4111111111111111");
    expect(result.redacted).toContain("[REDACTED:email]");
    expect(result.redacted).toContain("[REDACTED:credit-card]");
    expect(result.redactions).toHaveLength(2);
  });

  it("preserves the original prompt", () => {
    const original = "My email is foo@bar.com";
    const result = redact(original);
    expect(result.original).toBe(original);
  });

  it("redacts multiple occurrences of the same type", () => {
    const result = redact("Email a@b.com and c@d.com");
    expect(result.redacted).not.toContain("a@b.com");
    expect(result.redacted).not.toContain("c@d.com");
    // Only one entry in redactions per type
    expect(result.redactions.filter((r) => r.type === "email")).toHaveLength(1);
  });

  it("connection strings are redacted", () => {
    const result = redact("Connect to postgresql://user:s3cr3t@db.example.com/mydb");
    expect(result.redacted).toContain("[REDACTED:connection-string]");
    expect(result.redacted).not.toContain("s3cr3t");
  });
});
