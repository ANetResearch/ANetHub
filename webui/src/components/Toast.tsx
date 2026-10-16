import { useCallback, useRef, useState } from "react";
import { cn } from "../lib/utils";

export function useToast() {
  const [state, setState] = useState<{ msg: string; err: boolean; show: boolean }>({
    msg: "",
    err: false,
    show: false,
  });
  const timer = useRef<ReturnType<typeof setTimeout> | null>(null);
  const toast = useCallback((msg: string, isErr?: boolean) => {
    setState({ msg, err: !!isErr, show: true });
    if (timer.current) clearTimeout(timer.current);
    timer.current = setTimeout(() => setState((s) => ({ ...s, show: false })), 3200);
  }, []);
  return { toast, toastState: state };
}

/** Status message. An error carries the accent border and a text prefix, so colour is never the only signal. */
export function Toast({ state }: { state: { msg: string; err: boolean; show: boolean } }) {
  return (
    <div
      role={state.err ? "alert" : "status"}
      aria-live={state.err ? "assertive" : "polite"}
      className={cn(
        "fixed bottom-6 left-1/2 z-[60] max-w-[calc(100vw-32px)] -translate-x-1/2 rounded-md border bg-surface px-4 py-2.5 text-sm text-fg transition-all duration-200",
        state.err ? "border-accent" : "border-line",
        state.show ? "translate-y-0 opacity-100" : "pointer-events-none translate-y-3 opacity-0",
      )}
    >
      {state.err && <span className="mr-2 font-semibold text-accent-text">!</span>}
      {state.msg}
    </div>
  );
}
