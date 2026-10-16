import * as React from "react";
import { Icon } from "../Icon";
import { X } from "../../lib/icons";
import { cn } from "../../lib/utils";

const FOCUSABLE = 'a[href],button:not([disabled]),input,select,textarea,[tabindex]:not([tabindex="-1"])';

/** Modal dialog: Escape and backdrop close it, Tab stays inside it, and focus returns to the opener. */
export function Dialog({
  open,
  onClose,
  children,
  className,
  label,
  closeLabel = "Close",
}: {
  open: boolean;
  onClose: () => void;
  children: React.ReactNode;
  className?: string;
  label: string;
  closeLabel?: string;
}) {
  const panel = React.useRef<HTMLDivElement>(null);
  // The caller passes a new onClose on every render; keeping it in a ref stops the effect from
  // re-running (and moving focus) whenever the page behind the dialog refreshes.
  const closeRef = React.useRef(onClose);
  closeRef.current = onClose;
  React.useEffect(() => {
    if (!open) return;
    const opener = document.activeElement as HTMLElement | null;
    panel.current?.querySelector<HTMLElement>("button")?.focus();
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") {
        closeRef.current();
        return;
      }
      if (e.key !== "Tab" || !panel.current) return;
      const items = Array.from(panel.current.querySelectorAll<HTMLElement>(FOCUSABLE));
      if (!items.length) return;
      const first = items[0];
      const last = items[items.length - 1];
      if (e.shiftKey && document.activeElement === first) {
        e.preventDefault();
        last.focus();
      } else if (!e.shiftKey && document.activeElement === last) {
        e.preventDefault();
        first.focus();
      }
    };
    window.addEventListener("keydown", onKey);
    document.body.style.overflow = "hidden";
    return () => {
      window.removeEventListener("keydown", onKey);
      document.body.style.overflow = "";
      opener?.focus?.();
    };
  }, [open]);

  if (!open) return null;
  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center p-0 md:p-6"
      style={{ background: "var(--overlay)" }}
      onMouseDown={(e) => {
        if (e.target === e.currentTarget) onClose();
      }}
    >
      <div
        ref={panel}
        role="dialog"
        aria-modal="true"
        aria-label={label}
        className={cn(
          "relative flex h-full max-h-full w-full max-w-2xl flex-col bg-surface text-fg md:h-auto md:max-h-[88vh] md:rounded-lg md:border md:border-line",
          className,
        )}
      >
        <button
          type="button"
          aria-label={closeLabel}
          onClick={onClose}
          className="btn btn-icon absolute right-3 top-3 z-10 border-transparent"
        >
          <Icon icon={X} size={18} />
        </button>
        {children}
      </div>
    </div>
  );
}
