import type { SVGProps } from "react";

/* =====================================================
 * ICON
 * ===================================================== */
export type IconSvgProps = SVGProps<SVGSVGElement> & {
  size?: number;
};

/* =====================================================
 * SENSOR & METRIC (GIỮ NGUYÊN)
 * ===================================================== */
export type SensorType = "Client" | "DMZ" | "ServerFarm";

export type SensorMetric = {
  date: string;
  type: SensorType;
  value: number;
};

export interface TrafficInfo {
  src_ip: string;
  src_port: number;
  dst_ip: string;
  dst_port: number;
  proto: string;
}

export interface SensorLog {
  id?: string;
  timestamp: string;
  traffic: TrafficInfo;
  rule: string;
  action: string;
  direction: string;
  sensor: string;
  tactic: string;
  confidence: number;
}

/* =====================================================
 * RULES (GIỮ NGUYÊN)
 * ===================================================== */
export type RulePriority = string | number;

export interface RuleType {
  sid: number;
  msg: string;
  category: string;
  proto: string;
  priority: RulePriority;
  status: string;
  hits24h: number;
  raw: string;

  // OPTIONAL FIELDS
  rev?: number;
  src?: string;
  src_port?: string;
  dst?: string;
  dst_port?: string;
  direction?: string;

  mitre?: {
    tactic: string;
    technique: string;
  };

  source: string;
}

/* =====================================================
 * SENSOR STATUS (GIỮ NGUYÊN)
 * ===================================================== */
export type SensorStatus = "active" | "warning" | "critical" | "offline";

export interface SensorInfo {
  id: string;
  hostname: string;
  ip: string;
  status: SensorStatus;
  zone: string;
  type: string;
  version: string;
  lastUpdate: string;
  description: string;
}

/* =====================================================
 * MITRE / ATTACK CHAIN (GIỮ NGUYÊN)
 * ===================================================== */
export interface AttackChain {
  id: string;
  startTime: string;
  endTime: string;
  tactics: string[];
  confidence: number;
}

export interface MitreLog {
  id: string;
  timestamp: string;
  sensor: string;
  msg: string;
  tactic: string;
  technique: string;
  confidence: number;
}

export interface RuleSetInfo {
  sid: string; // ObjectId
  msg: string;
  category: string;
  status: string;
  count: number;
}

/* =====================================================
 * ================== CORRELATION ======================
 * PHẦN MỚI – KHÔNG ẢNH HƯỞNG CODE CŨ
 * ===================================================== */

/* ---------- Evidence ---------- */
export interface MessageFrequency {
  [message: string]: number;
}

export interface CorrelationEvidence {
  message_frequency?: MessageFrequency;
}

/* ---------- Interpretation (heuristic) ---------- */
export type ConfidenceHint = "low" | "medium" | "high";

export interface CorrelationInterpretation {
  dominant_tactic?: string | null;
  confidence_hint: ConfidenceHint;
  lateral_movement?: boolean;
}

/* ---------- Statistics ---------- */
export interface CorrelationStatistics {
  event_count: number;
  behavior_frequency?: Record<string, number>;
}

/* ---------- Attack Window Summary ---------- */
export interface AttackWindowSummary {
  actor_ip: string;
  target_ip: string;

  time?: {
    start: string;
    end: string;
  };

  statistics: CorrelationStatistics;
  interpretation: CorrelationInterpretation;
  evidence?: CorrelationEvidence;
}

/* ---------- API: /run_from_mongo (NO AI) ---------- */
export interface CorrelationWindowResult {
  summary: AttackWindowSummary;
  ai_triggered: false;
  analysis: null;
}

export interface CorrelationRunResponse {
  status: "ok";
  event_count: number;
  window_count: number;
  results: CorrelationWindowResult[];
}

/* ---------- GPT Correlation (MANUAL AI) ---------- */
export type RiskLevel = "low" | "medium" | "high";

export interface GPTLateralMovement {
  detected: boolean;
  evidence: string[];
}

export interface GPTAnalysisResult {
  attack_chain: boolean;
  suspected_stages: string[];
  top_findings: string[];
  lateral_movement: GPTLateralMovement;
  confidence: number; // 0.0 – 1.0
  risk_level: RiskLevel;
  recommended_actions: string[];
}

export interface GPTAnalysisResponse {
  status: "ok";
  analysis: GPTAnalysisResult;
}
