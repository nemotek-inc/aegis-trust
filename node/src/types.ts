// Public type definitions for aegis-trust.
// Mirror of aegis-trust (PyPI) python/src/aegis_trust/types.py.

export enum Mode {
  LITE = "lite",
  FULL = "full",
  AUTO = "auto",
}

export interface AccessPolicy {
  readonly purpose: string;
  readonly scope: ReadonlyArray<string>;
  readonly denyFields: ReadonlyArray<string>;
}

export interface AuditEntry {
  readonly seq: number;
  readonly timestamp: string;
  readonly hash: string;
  readonly action: string;
}

export interface ShieldResult<T = unknown> {
  readonly data: T;
  readonly mode: Mode;
  readonly purpose: string;
  readonly scope: ReadonlyArray<string>;
  readonly filteredKeys: ReadonlyArray<string>;
}

// ── Shield API types (parity with Python types.py) ────────

export interface IngestEntry {
  readonly function: string;
  readonly purpose: string;
  readonly scope: ReadonlyArray<string>;
  readonly blockedFields: ReadonlyArray<string>;
  readonly timestamp: string;
  readonly count: number;
  readonly denyFields: ReadonlyArray<string>;
  // Cross-review round 3 P0-4: trace_id rides on the FULL-mode ingest
  // payload so the gateway audit chain and the local JSONL share one trace.
  readonly trace_id?: string;
}

export interface IngestResponse {
  readonly ingested: number;
  readonly auditSeqStart: number;
  readonly auditSeqEnd: number;
}

export interface AuditChainStatus {
  readonly chainValid: boolean;
  readonly totalEntries: number;
}

export interface PolicySyncEntry {
  readonly scope: ReadonlyArray<string>;
  readonly denyFields: ReadonlyArray<string>;
}

export interface PolicySyncResponse {
  readonly synced: number;
  readonly added: ReadonlyArray<string>;
  readonly updated: ReadonlyArray<string>;
}

export interface PurposeStats {
  readonly calls: number;
  readonly blocked: number;
}

export interface FieldStats {
  readonly blockedCount: number;
}

export interface FunctionStats {
  readonly calls: number;
  readonly purposes: ReadonlyArray<string>;
}

export interface ShieldStats {
  readonly periodFrom: string;
  readonly periodTo: string;
  readonly totalCalls: number;
  readonly totalBlockedFields: number;
  readonly byPurpose: Readonly<Record<string, PurposeStats>>;
  readonly byField: Readonly<Record<string, FieldStats>>;
  readonly byFunction: Readonly<Record<string, FunctionStats>>;
}

// ── Shield options ────────────────────────────────────────

export interface ShieldOptions {
  readonly purpose: string;
  readonly scope?: ReadonlyArray<string>;
  readonly denyFields?: ReadonlyArray<string>;
  readonly mode?: Mode;
}

// ── Internal path tree ────────────────────────────────────

export type PathTree = { [key: string]: PathTree };
