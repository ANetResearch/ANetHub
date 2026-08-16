import * as React from "react";
import { X } from "lucide-react";
import { cn } from "../../lib/utils";

/** shadcn 风格 Dialog（无 radix 依赖）：遮罩 + 居中面板，Esc / 遮罩点击关闭。 */
export function Dialog({
  open,
  onClose,
  children,
  className,
  closeButton = true,
}: {
  open: boolean;
  onClose: () => void;
  children: React.ReactNode;
  className?: string;
  closeButton?: boolean;
}) {
  React.useEffect(() => {
    if (!open) return;
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") onClose();
    };
    window.addEventListener("keydown", onKey);
    document.body.style.overflow = "hidden";
    return () => {
      window.removeEventListener("keydown", onKey);
      document.body.style.overflow = "";
    };
  }, [open, onClose]);

  if (!open) return null;
  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/55 backdrop-blur-[2px] p-0 md:p-6"
      onMouseDown={(e) => {
        if (e.target === e.currentTarget) onClose();
      }}
    >
      <div
        className={cn(
          "relative flex w-full max-w-2xl flex-col bg-white shadow-2xl",
          "h-full max-h-full md:h-auto md:max-h-[88vh]",
          className,
        )}
      >
        {closeButton && (
          <button
            aria-label="关闭"
            onClick={onClose}
            className="absolute right-3 top-3 z-10 inline-flex size-8 items-center justify-center text-gray-400 transition-colors hover:text-[#E60000] cursor-pointer"
          >
            <X className="size-5" />
          </button>
        )}
        {children}
      </div>
    </div>
  );
}
