import { SmilePlus, ThumbsDown, ThumbsUp } from "lucide-react";
import {
  aiLogClassification,
  totalAnalyzedLogs,
} from "@/data/dashboard/ai-log";
import ChartTitle from "../../components/chart-title";
import LinearProgress from "./components/linear-progress";

const aiLogClassificationOptions = [
  {
    label: "High",
    color: "#5fb67a",
    percentage: aiLogClassification.high,
    icon: <ThumbsUp className="h-6 w-6" stroke="#5fb67a" fill="#5fb67a" />,
  },
  {
    label: "Medium",
    color: "#f5c36e",
    percentage: aiLogClassification.medium,
    icon: <ThumbsUp className="h-6 w-6" stroke="#f5c36e" fill="#f5c36e" />,
  },
  {
    label: "Low",
    color: "#da6d67",
    percentage: aiLogClassification.low,
    icon: <ThumbsDown className="h-6 w-6" stroke="#da6d67" fill="#da6d67" />,
  },
];

export default function AiLogClassificationOptions() {
  return (
    <section className="flex h-full flex-col gap-2">
      <ChartTitle title="AI Log Severity Analysis" icon={SmilePlus} />
      <div className="my-4 flex h-full items-center justify-between">
        <div className="mx-auto grid w-full grid-cols-2 gap-6">
          <TotalAnalyzedLogs />
          {aiLogClassificationOptions.map((option) => (
            <LinearProgress
              key={option.label}
              label={option.label}
              color={option.color}
              percentage={option.percentage}
              icon={option.icon}
            />
          ))}
        </div>
      </div>
    </section>
  );
}

function TotalAnalyzedLogs() {
  return (
    <div className="flex flex-col items-start justify-center">
      <div className="text-xs text-muted-foreground">Responses Received</div>
      <div className="text-2xl font-medium">{totalAnalyzedLogs} log</div>
    </div>
  );
}
