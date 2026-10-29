/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

export type LogFormat = 'rfc3164_syslog' | 'combined_log' | 'generic';

export type EventConfidence = 'exact' | 'inferred' | 'skew-corrected';

export type EventType =
  | 'auth_fail'
  | 'auth_success'
  | 'privilege_escalation'
  | 'web_access'
  | 'web_error'
  | 'suspicious_activity'
  | 'system_notice'
  | 'unparsed';

export interface RawReference {
  fileId: string;
  fileName: string;
  lineNumber: number;
  rawText: string;
  lineHash: string; // SHA-256 of raw line
}

export interface ParsedEvent {
  id: string;
  host: string;
  source: string; // Source label / name
  service: string; // e.g. sshd, sudo, nginx
  user?: string; // e.g. root, deploy, alice
  src_ip?: string; // e.g. 203.0.113.14
  event_type: EventType;
  message: string;
  original_timestamp: string;
  normalized_utc: string; // ISO-8601 UTC e.g. 2026-10-09T03:14:12.000Z
  normalization_notes: string;
  confidence: EventConfidence;
  raw_ref: RawReference;
  isTampered?: boolean;
}

export interface LogSource {
  id: string;
  name: string;
  hostLabel: string;
  format: LogFormat;
  timezone: string; // IANA timezone e.g. "UTC", "America/New_York"
  clockOffsetSeconds: number; // e.g. -180s (fast clock) or +120s (slow clock)
  fileId?: string;
  fileName?: string;
  eventCount?: number;
  unparsedCount?: number;
}

export interface CustodyLedgerEntry {
  blockIndex: number;
  fileId: string;
  fileName: string;
  fileSizeBytes: number;
  fileSha256: string;
  utcCollectionTime: string;
  examinerName: string;
  sourceHost: string;
  previousEntryHash: string; // "0".repeat(64) for genesis
  blockHash: string; // SHA-256 of block data
  tampered?: boolean;
}

export interface EvidenceFile {
  id: string;
  name: string;
  sizeBytes: number;
  sha256: string;
  lineHashes: string[];
  rawContent: string;
  uploadedAtUtc: string;
  assignedSourceId?: string;
  isTampered?: boolean;
}

export interface CaseMetadata {
  id: string;
  caseNumber: string;
  title: string;
  investigator: string;
  referenceDate: string; // YYYY-MM-DD used to infer syslog year
  description: string;
  createdAtUtc: string;
  updatedAtUtc: string;
}

export interface ParseContext {
  referenceYear: number;
  referenceDateIso: string;
  source: LogSource;
}

export interface IntegrityReport {
  timestamp: string;
  allValid: boolean;
  totalFiles: number;
  filesPassed: number;
  filesFailed: number;
  ledgerValid: boolean;
  tamperedItems: Array<{
    type: 'file' | 'line' | 'ledger';
    id: string;
    details: string;
    expectedHash: string;
    actualHash: string;
  }>;
}

export interface AITriageRule {
  id: string;
  name: string;
  description: string;
  patternType: 'regex' | 'heuristic' | 'semantic';
  matchField: 'message' | 'service' | 'user' | 'src_ip' | 'event_type';
  patternValue: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';
  mitreTechnique?: string; // e.g. "T1110 (Brute Force)"
  recommendation: string;
  enabled: boolean;
}

export interface AIInvestigationReport {
  summary: string;
  threatLevel: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  attackTimeline: Array<{
    timestamp: string;
    phase: string;
    description: string;
    evidenceIds: string[];
  }>;
  affectedEntities: {
    hosts: string[];
    users: string[];
    ips: string[];
  };
  mitreMappings: Array<{
    id: string;
    technique: string;
    tactic: string;
    evidence: string;
  }>;
  recommendedActions: string[];
  generatedBy: 'gemini-3.8-flash' | 'local-heuristic-engine';
}
