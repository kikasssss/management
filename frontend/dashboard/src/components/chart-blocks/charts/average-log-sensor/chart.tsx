"use client";

import { useAtomValue } from "jotai";
import { VChart } from "@visactor/react-vchart";
import type { IBarChartSpec } from "@visactor/vchart";
import { sensorChartDataAtom } from "@/lib/atoms";
import type { SensorMetric } from "@/types/types";

const generateSpec = (data: SensorMetric[]): IBarChartSpec => ({
  type: "bar",
  data: [
    {
      id: "sensorData",
      values: data,
    },
  ],
  xField: ["date", "type"], 
  yField: "value",
  seriesField: "type",
  padding: [10, 0, 10, 0],
  legends: {
    visible: true,
  },
  stack: false,
  tooltip: {
    trigger: ["click", "hover"],
  },
  bar: {
    state: {
      hover: {
        outerBorder: {
          distance: 2,
          lineWidth: 2,
        },
      },
    },
    style: {
      cornerRadius: [12, 12, 12, 12],
      zIndex: (datum) => {
        return datum.type === "resolved" ? 2 : 1;
      },
    },
  },
  
  color: [
    "#60C2FB", // Client
    "#3161F8", // DMZ
    "#003cffff", // ServerFarm
  ],
});

export default function Chart() {
  const sensorChartData = useAtomValue(sensorChartDataAtom);
  const spec = generateSpec(sensorChartData);
  return <VChart spec={spec} />;
}
