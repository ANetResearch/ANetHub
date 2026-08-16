import * as React from "react";
import { cn } from "../../lib/utils";

/** 首字母方块头像（黑底白字，hover 由父级控制变红）。 */
export function Avatar({
  name,
  className,
}: {
  name?: string;
  className?: string;
}) {
  const initial = (name || "A").trim().charAt(0).toUpperCase() || "A";
  return (
    <div
      className={cn(
        "flex size-10 shrink-0 items-center justify-center bg-black text-white font-bebas text-lg",
        className,
      )}
    >
      {initial}
    </div>
  );
}
