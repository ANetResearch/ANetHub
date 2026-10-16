import { cn } from "../../lib/utils";

/** Initial in a square tile. */
export function Avatar({ name, className }: { name?: string; className?: string }) {
  const initial = (name || "A").trim().charAt(0).toUpperCase() || "A";
  return (
    <div
      aria-hidden="true"
      className={cn(
        "flex size-10 shrink-0 items-center justify-center rounded-md border border-line bg-surface-2 text-base font-semibold text-fg",
        className,
      )}
    >
      {initial}
    </div>
  );
}
