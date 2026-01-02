"use client";

import { atom } from "jotai";
import type { DateRange } from "react-day-picker";
import { addDays } from "date-fns";
import type { SensorMetric } from "@/types/types";

/* ---------------- Date range ---------------- */

const defaultStartDate = new Date();

export const dateRangeAtom = atom<DateRange | undefined>({
  from: addDays(defaultStartDate, -1),
  to: defaultStartDate,
});

/* ---------------- Fetch data atom ---------------- */

export const sensorChartDataAtom = atom<Promise<SensorMetric[]>>(async (get) => {
  const range = get(dateRangeAtom);
  if (!range?.from || !range?.to) return [];

  const from = range.from.toISOString();
  const to = range.to.toISOString();

  const res = await fetch(
    `/api/elastic/avg/?from=${from}&to=${to}`,
    { cache: "no-store" },
  );

  if (!res.ok) {
    console.error("Failed to fetch sensor chart data");
    return [];
  }

  const json = await res.json();
  return json.data as SensorMetric[];
});
