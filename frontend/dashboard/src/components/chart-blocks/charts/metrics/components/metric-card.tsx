import { chartTitle } from "@/components/primitives";
import { cn } from "@/lib/utils";

export default function MetricCard({
  title,
  value,
  className,
}: {
  title: string;
  value: string | number;
  className?: string;
}) {
  return (
    <section className={cn("flex flex-col", className)}>
      <h2
        className={cn(
          chartTitle({ color: "mute", size: "sm" }),
          "mb-1",
        )}
      >
        {title}
      </h2>

      <div className="flex items-center gap-2">
        <span className="text-xl font-medium">
          {value}
        </span>
      </div>
    </section>
  );
}
