export const mitreLogs = [
  {
    id: "l1",
    timestamp: "2025-11-20 10:21:13",
    sensor: "snort-serverfarm",
    msg: "Suspicious HTTP payload detected",
    tactic: "Initial Access",
    technique: "T1190 — Exploit Public-Facing Application",
    confidence: 87,
  },
  {
    id: "l2",
    timestamp: "2025-11-20 10:22:40",
    sensor: "snort-serverfarm",
    msg: "Encoded PowerShell command detected",
    tactic: "Execution",
    technique: "T1059 — Command Execution",
    confidence: 76,
  },
  {
    id: "l3",
    timestamp: "2025-11-20 10:23:58",
    sensor: "snort-serverfarm",
    msg: "Registry Run key modification",
    tactic: "Persistence",
    technique: "T1547 — Boot or Logon Autostart Execution",
    confidence: 71,
  },
];
