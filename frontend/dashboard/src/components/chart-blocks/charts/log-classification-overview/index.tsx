import { CirclePercent } from "lucide-react";
import { addThousandsSeparator } from "@/lib/utils";
import ChartTitle from "../../components/chart-title";
import Chart from "./chart";

/* ===== INDICATOR ===== */
function Indicator() {
  return (
    <div className="mt-3">
      <span className="mr-1 text-2xl font-medium">
        0
      </span>
      <span className="text-muted-foreground/60">
        Logs
      </span>
    </div>
  );
}

export default function Convertions() {
  return (
    <section className="flex h-full flex-col gap-2">
      <ChartTitle
        title="Log Classification Overview"
        icon={CirclePercent}
      />

      <div className="relative max-h-80 flex-grow">
        <Chart />
      </div>
    </section>
  );
}
