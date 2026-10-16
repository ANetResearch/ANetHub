import { MorphIcon } from "morphicons/react";
import type { IconNode } from "morphicons/react";

/** Stroke icon. Changing `icon` between renders morphs the glyph (copy to check, menu to close, sun to moon). */
export function Icon({ icon, size = 16, label, className }: { icon: IconNode; size?: number; label?: string; className?: string }) {
  return <MorphIcon icon={icon} size={size} strokeWidth={1.75} reducedMotion="user" label={label} className={className} />;
}
