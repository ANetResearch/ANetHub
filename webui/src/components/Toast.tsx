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

export function Toast({ state }: { state: { msg: string; err: boolean; show: boolean } }) {
  return (
    <div
      className={cn(
        "fixed bottom-7 left-1/2 z-[60] max-w-[80vw] -translate-x-1/2 border px-4 py-2.5 text-sm shadow-lg transition-all duration-200",
        state.err ? "border-[#E60000] bg-[#E60000] text-white" : "border-gray-800 bg-black text-white",
        state.show ? "translate-y-0 opacity-100" : "pointer-events-none translate-y-3 opacity-0",
      )}
    >
      {state.msg}
    </div>
  );
}
