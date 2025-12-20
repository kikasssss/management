"use client";

import { useAtomValue } from "jotai";
import { FilePlus2 } from "lucide-react";
import { sensorChartDataAtom } from "@/lib/atoms";
import type { SensorMetric } from "@/types/types";
import ChartTitle from "../../components/chart-title";
import Chart from "./chart";
import { DatePickerWithRange } from "./components/date-range-picker";
import MetricCard from "./components/metric-card";

const calMetricCardValue = (
  data: SensorMetric[],
  sensor: SensorMetric["type"]
) => {
  const filteredData = data.filter((item) => item.type === sensor);
  return Math.round(
    filteredData.reduce((acc, curr) => acc + curr.value, 0) /
      filteredData.length,
  );
};

export default function AverageLogSensor() {
  const sensorChartData = useAtomValue(sensorChartDataAtom);
  const avgClient = calMetricCardValue(sensorChartData, "Client");
  const avgDMZ = calMetricCardValue(sensorChartData, "DMZ");
  const avgServer = calMetricCardValue(sensorChartData, "ServerFarm");

  return (
    <section className="flex h-full flex-col gap-2">
      <div className="flex flex-wrap items-start justify-between gap-4">
        <ChartTitle title="Average Log Sensor" icon={FilePlus2} />
        <DatePickerWithRange className="" />
      </div>
      <div className="flex flex-wrap">
        <div className="my-4 flex w-52 shrink-0 flex-col justify-center gap-6">
          <MetricCard
            title="Avg. Client"
            value={avgClient}
            color="#60C2FB"
          />
          <MetricCard
            title="Avg. DMZ"
            value={avgDMZ}
            color="#3161F8"
          />
          <MetricCard
            title="Avg. Server Farm"
            value={avgServer}
            color="#003cffff"
          />
        </div>
        <div className="relative h-96 min-w-[320px] flex-1">
          <Chart />
        </div>
      </div>
    </section>
  );
}
