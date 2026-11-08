import type { FindingStatus, L1Verdict, Role, Severity } from './constants.js';
import type { TacticId } from './mitre.js';

export interface UserDTO {
  id: string;
  username: string;
  fullName: string;
  role: Role;
  isActive: boolean;
  mustChangePassword: boolean;
  lastLoginAt: string | null;
  createdAt: string;
}

export interface UploadDTO {
  id: string;
  originalName: string;
  storedName: string;
  sha256: string;
  sizeBytes: number;
  sheetName: string;
  rowCount: number;
  uploadedAt: string;
  uploadedBy: string;
  analysisCount: number;
  latestAnalysisId: string | null;
}

export interface LogEventDTO {
  id: number;
  rowNumber: number;
  logId: string;
  ts: string | null;
  hostname: string | null;
  eventId: string | null;
  user: string | null;
  sourceIp: string | null;
  destination: string | null;
  logSource: string | null;
  description: string | null;
  commandLine: string | null;
  result: string | null;
  severitySrc: string | null;
}

export interface Paged<T> {
  items: T[];
  total: number;
  page: number;
  pageSize: number;
}

export interface MitreRef {
  id: string;
  name: string;
  tactics: TacticId[];
}

export interface Entities {
  hosts: string[];
  users: string[];
  ips: string[];
}

export interface ActionPlan {
  investigate: string[];
  contain: string[];
  remediate: string[];
}

export interface ScoreFactor {
  label: string;
  points: number;
}

export interface FindingDTO {
  id: string;
  ruleId: string;
  title: string;
  /** Criticidad calculada por el motor */
  severity: Severity;
  /** Criticidad final (override del L2 si existe) */
  effectiveSeverity: Severity;
  score: number;
  scoreFactors: ScoreFactor[];
  justification: string;
  mitre: MitreRef[];
  entities: Entities;
  firstSeen: string | null;
  lastSeen: string | null;
  eventCount: number;
  summary: string;
  technicalExplanation: string;
  impact: string;
  actionPlan: ActionPlan;
  evidenceLogIds: string[];
  incidentKey: string | null;
  status: FindingStatus;
  l1Verdict: L1Verdict | null;
  l1Rationale: string | null;
  narrativeSource: 'ai' | 'engine';
  severityOverride: Severity | null;
  analystNotes: string | null;
  reviewedBy: string | null;
  reviewedAt: string | null;
}

export interface IncidentDTO {
  key: string;
  title: string;
  severity: Severity;
  findingIds: string[];
  tactics: TacticId[];
  firstSeen: string | null;
  lastSeen: string | null;
  entities: Entities;
  correlation: string[];
}

export interface DataQualityNote {
  type: string;
  message: string;
  values: string[];
}

export interface CountItem {
  key: string;
  count: number;
}

export interface AnalysisStats {
  totalEvents: number;
  timeRange: { from: string | null; to: string | null };
  byLogSource: CountItem[];
  byEventId: CountItem[];
  byHost: CountItem[];
  bySourceSeverity: CountItem[];
  findingsBySeverity: Record<Severity, number>;
  byTactic: CountItem[];
  /** Línea de tiempo en intervalos de 15 min: total de eventos y eventos que son evidencia de algún hallazgo */
  timeline: { bucket: string; total: number; suspicious: number }[];
  topSuspiciousIps: CountItem[];
  suspiciousEventCount: number;
}

export type AiStatus = 'disabled' | 'pending' | 'completed' | 'failed';

export interface AnalysisDTO {
  id: string;
  uploadId: string;
  uploadName: string;
  createdAt: string;
  createdBy: string;
  status: 'running' | 'completed' | 'failed';
  engineVersion: string;
  stats: AnalysisStats | null;
  aiStatus: AiStatus;
  aiModel: string | null;
  aiError: string | null;
  aiRejected: string[];
  executiveSummary: string | null;
  generalRecommendations: string[];
  dataQuality: DataQualityNote[];
  incidents: IncidentDTO[];
  findings: FindingDTO[];
  error: string | null;
}

export interface AnalysisListItem {
  id: string;
  uploadId: string;
  uploadName: string;
  createdAt: string;
  createdBy: string;
  status: string;
  findingsCount: number;
  criticalCount: number;
  highCount: number;
  pendingCount: number;
}

export interface ReportDTO {
  id: string;
  analysisId: string;
  fileName: string;
  sha256: string;
  sizeBytes: number;
  generatedAt: string;
  generatedBy: string;
}

export interface AuditEntryDTO {
  id: number;
  at: string;
  username: string | null;
  action: string;
  entityType: string | null;
  entityId: string | null;
  ip: string | null;
  details: Record<string, unknown> | null;
}

export interface MeDTO {
  user: UserDTO;
  permissions: string[];
  aiEnabled: boolean;
  aiProvider: 'anthropic' | 'gemini' | null;
  aiModel: string | null;
  timezone: string;
}
