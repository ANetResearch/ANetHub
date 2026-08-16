import * as React from "react";
import { cn } from "../../lib/utils";

/** shadcn 风格 Tabs（受控，无 radix）。 */
export function Tabs({
  value,
  onValueChange,
  items,
  className,
}: {
  value: string;
  onValueChange: (v: string) => void;
  items: { value: string; label: string; accent?: boolean }[];
  className?: string;
}) {
  return (
    <div className={cn("flex flex-wrap gap-2", className)} role="tablist">
      {items.map((it) => {
        const active = it.value === value;
        return (
          <button
            key={it.value}
            role="tab"
            aria-selected={active}
            onClick={() => onValueChange(it.value)}
            className={cn(
              "px-3.5 py-1.5 text-[13px] font-medium border transition-colors cursor-pointer",
              active
                ? "border-[#E60000] bg-[#E60000] text-white"
                : "border-gray-300 bg-white text-gray-600 hover:border-[#E60000] hover:text-[#E60000]",
              it.accent && !active && "border-dashed",
            )}
          >
            {it.label}
          </button>
        );
      })}
    </div>
  );
}
