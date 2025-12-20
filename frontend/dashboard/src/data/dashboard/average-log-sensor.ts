import type { SensorType } from "@/types/types";

export type SensorLog = {
  date: string;
  sensor: SensorType;   // tên sensor
  alerts: number;       // số alert
};

export const sensorLogs: SensorLog[] = [

  { date: "2023-12-18", sensor: "Client", alerts: 120 },
  { date: "2023-12-19", sensor: "Client", alerts: 150 },
  { date: "2023-12-20", sensor: "Client", alerts: 180 },
  { date: "2023-12-21", sensor: "Client", alerts: 160 },
  { date: "2023-12-22", sensor: "Client", alerts: 155 },
  { date: "2023-12-23", sensor: "Client", alerts: 200 },
  { date: "2023-12-24", sensor: "Client", alerts: 175 },

  { date: "2023-12-18", sensor: "DMZ", alerts: 80 },
  { date: "2023-12-19", sensor: "DMZ", alerts: 95 },
  { date: "2023-12-20", sensor: "DMZ", alerts: 110 },
  { date: "2023-12-21", sensor: "DMZ", alerts: 105 },
  { date: "2023-12-22", sensor: "DMZ", alerts: 100 },
  { date: "2023-12-23", sensor: "DMZ", alerts: 130 },
  { date: "2023-12-24", sensor: "DMZ", alerts: 120 },

  { date: "2023-12-18", sensor: "ServerFarm", alerts: 210 },
  { date: "2023-12-19", sensor: "ServerFarm", alerts: 240 },
  { date: "2023-12-20", sensor: "ServerFarm", alerts: 250 },
  { date: "2023-12-21", sensor: "ServerFarm", alerts: 230 },
  { date: "2023-12-22", sensor: "ServerFarm", alerts: 250 },
  { date: "2023-12-23", sensor: "ServerFarm", alerts: 270 },
  { date: "2023-12-24", sensor: "ServerFarm", alerts: 260 },
];
