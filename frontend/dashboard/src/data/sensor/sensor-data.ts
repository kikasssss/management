import type { SensorInfo } from "@/types/types";

export const sensors: SensorInfo[] = [
  {
    id: "S001",
    hostname: "snort-client",
    ip: "192.168.220.51",
    status: "active",
    zone: "Client Zone",
    type: "Snort IDS",
    version: "3.2.0.0",
    lastUpdate: "2s ago",
    description: "Client-side intrusion detection sensor",
  },

  {
    id: "S002",
    hostname: "snort-dmz",
    ip: "192.168.220.52",
    status: "active",
    zone: "DMZ",
    type: "Snort IDS",
    version: "3.2.0.0",
    lastUpdate: "4s ago",
    description: "Monitoring inbound/outbound DMZ traffic",
  },

  {
    id: "S003",
    hostname: "snort-serverfarm",
    ip: "192.168.220.53",
    status: "warning",
    zone: "Server Farm",
    type: "Snort IDS",
    version: "3.2.0.0",
    lastUpdate: "10s ago",
    description: "Server farm protection against lateral attacks",
  },
];
