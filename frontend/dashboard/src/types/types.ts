import type { SVGProps } from "react";

export type IconSvgProps = SVGProps<SVGSVGElement> & {
  size?: number;
};

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
  sid: string;       // dùng ObjectId
  msg: string;
  category: string;
  status: string;
  count: number;
}
