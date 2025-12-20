import { CirclePercent } from "lucide-react";
import { logClassificationOverview } from "@/data/dashboard/logclassificationoverview";
import { addThousandsSeparator } from "@/lib/utils";
import ChartTitle from "../../components/chart-title";
import Chart from "./chart";

export default function Convertions() {
  return (
    <section className="flex h-full flex-col gap-2">
      <ChartTitle title="Log Classification Overview" icon={CirclePercent} />
      <Indicator />
      <div className="relative max-h-80 flex-grow">
        <Chart />
      </div>
    </section>
  );
}

function Indicator() {
  return (
    <div className="mt-3">
      <span className="mr-1 text-2xl font-medium">
        {addThousandsSeparator(
          logClassificationOverview.reduce((acc, curr) => acc + curr.value, 0),
        )}
      </span>
      <span className="text-muted-foreground/60">Sales</span>
    </div>
  );
}
