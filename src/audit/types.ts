import type { DetectionResult } from "../types.js";

export interface AuditEntry {
  /** ISO 8601 timestamp */
  timestamp: string;
  /** Whether the prompt was allowed through */
  allowed: boolean;
  /** The evaluated prompt */
  prompt: string;
  /** Per-detector results */
  detections: DetectionResult[];
  /** How long the analysis took in milliseconds */
  durationMs: number;
  /** Optional caller-supplied context (userId, sessionId, requestId, etc.) */
  metadata?: Record<string, unknown>;
}

/**
 * Implement this interface to send audit logs anywhere.
 * Errors thrown by log() are silently swallowed — a logging failure will
 * never cause the firewall to reject a prompt.
 */
export interface AuditLogger {
  log(entry: AuditEntry): void | Promise<void>;
}
