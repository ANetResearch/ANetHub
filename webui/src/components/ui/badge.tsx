import * as React from "react";
import { cn } from "../../lib/utils";

type Variant = "default" | "outline" | "brand" | "soft";

const variants: Record<Variant, string> = {
  default: "bg-black text-white",
  outline: "border border-gray-300 text-gray-600",
  brand: "bg-[#E60000] text-white",
  soft: "bg-[#E60000]/8 text-[#E60000] border border-[#E60000]/25",
};

export function Badge({
  className,
  variant = "outline",
  ...props
}: React.HTMLAttributes<HTMLSpanElement> & { variant?: Variant }) {
  return (
    <span
      className={cn(
        "inline-flex items-center gap-1 px-2 py-0.5 text-[11px] font-medium whitespace-nowrap",
        variants[variant],
        className,
      )}
      {...props}
    />
  );
}
