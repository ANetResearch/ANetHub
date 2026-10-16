import type { IconNode } from "morphicons/react";

/**
 * Static stroke icon for glyphs that never change shape (rating stars, tags,
 * capability marks). It renders the geometry directly and avoids the
 * per-instance setup of the morphing Icon, which matters in lists.
 */
export function StaticIcon({ icon, size = 16, className }: { icon: IconNode; size?: number; className?: string }) {
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth={1.75}
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden="true"
      className={className}
    >
      {(icon as unknown as [string, Record<string, string | number>][]).map(([tag, attrs], i) => {
        const Tag = tag as "path";
        const { key: _k, ...rest } = attrs as Record<string, string | number>;
        return <Tag key={i} {...(rest as object)} />;
      })}
    </svg>
  );
}
