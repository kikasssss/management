"use client";

import { format } from "date-fns";
import { useAtom } from "jotai";
import { Calendar as CalendarIcon } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Calendar } from "@/components/ui/calendar";
import {
  Popover,
  PopoverContent,
  PopoverTrigger,
} from "@/components/ui/popover";

import { dateRangeAtom } from "@/lib/atoms";
import { cn } from "@/lib/utils";

export function DatePickerWithRange({
  className,
}: React.HTMLAttributes<HTMLDivElement>) {
  const [dateRange, setDateRange] = useAtom(dateRangeAtom);

  // 🔥 ngày log gần nhất = hôm nay
  const today = new Date();

  // (tuỳ chọn) giới hạn quá khứ, ví dụ 30 ngày
  const firstAvailableDate = new Date();
  firstAvailableDate.setDate(today.getDate() - 30);

  return (
    <div className={cn("grid gap-2", className)}>
      <Popover>
        <PopoverTrigger asChild>
          <Button
            id="date"
            variant="outline"
            className={cn(
              "w-[276px] justify-start text-left font-normal",
              !dateRange && "text-muted-foreground",
            )}
          >
            <CalendarIcon className="mr-2 h-4 w-4" />
            {dateRange?.from ? (
              dateRange.to ? (
                <>
                  {format(dateRange.from, "LLL dd, y")} -{" "}
                  {format(dateRange.to, "LLL dd, y")}
                </>
              ) : (
                format(dateRange.from, "LLL dd, y")
              )
            ) : (
              <span>Pick a date</span>
            )}
          </Button>
        </PopoverTrigger>

        <PopoverContent className="w-auto p-0" align="start">
          <Calendar
            initialFocus
            mode="range"
            defaultMonth={dateRange?.from ?? today}
            selected={dateRange}
            onSelect={setDateRange}
            numberOfMonths={2}
            fromDate={firstAvailableDate}
            toDate={today}   // 🔥 không cho chọn tương lai
          />
        </PopoverContent>
      </Popover>
    </div>
  );
}
