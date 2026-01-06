"use client";

import { useEffect, useState } from "react";
import { VChart } from "@visactor/react-vchart";
import type { ICirclePackingChartSpec } from "@visactor/vchart";
import { addThousandsSeparator } from "@/lib/utils";

/* ===== TYPE ===== */
interface LogClassificationItem {
  name: string;
  value: number;
}

export default function Chart() {
  const [data, setData] = useState<LogClassificationItem[]>([]);
  const [loading, setLoading] = useState(true);

  /* ===== FETCH BACKEND ===== */
  useEffect(() => {
    async function load() {
      setLoading(true);

      const today = new Date().toISOString().slice(0, 10);

      const url =
        `http://100.100.100.100:5000/api/v1/mitre/summary?date=${today}`;

      try {
        const res = await fetch(url);
        const json = await res.json();

        /**
         * json.by_tactic = [{ name, count }]
         * → map sang { name, value }
         */
        const formatted: LogClassificationItem[] =
          json.by_tactic.map((item: any) => ({
            name: item.name,
            value: item.count,
          }));

        setData(formatted);
      } catch (err) {
        console.error("Failed to fetch log classification", err);
      } finally {
        setLoading(false);
      }
    }

    load();
  }, []);

  /* ===== CHART SPEC ===== */
  const spec: ICirclePackingChartSpec = {
    data: [
      {
        id: "data",
        values: data,
      },
    ],
    type: "circlePacking",
    categoryField: "name",
    valueField: "value",
    drill: true,
    padding: 0,
    layoutPadding: 5,

    label: {
      style: {
        fill: "white",
        stroke: false,
        visible: (d) => d.depth === 0,
        text: (d) => addThousandsSeparator(d.value),
        fontSize: (d) => d.radius / 2,
        dy: (d) => d.radius / 8,
      },
    },

    legends: [
      {
        visible: true,
        orient: "top",
        position: "start",
        padding: 0,
      },
    ],

    tooltip: {
      trigger: ["hover", "click"],
      mark: {
        content: {
          value: (d) => addThousandsSeparator(d?.value),
        },
      },
    },

    animationEnter: { easing: "cubicInOut" },
    animationExit: { easing: "cubicInOut" },
    animationUpdate: { easing: "cubicInOut" },
  };

  /* ===== RENDER ===== */
  if (loading) {
    return (
      <div className="text-xs text-gray-500">
        Loading log classification…
      </div>
    );
  }

  return <VChart spec={spec} />;
}
