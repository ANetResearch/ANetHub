import { useSyncExternalStore } from "react";

// Theme follows the system until the operator chooses one; the choice is
// kept in localStorage and applied as data-theme on <html>.
export type Theme = "light" | "dark";
const KEY = "anet-theme";

function systemTheme(): Theme {
  return typeof matchMedia !== "undefined" && matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light";
}

function stored(): Theme | null {
  try {
    const v = localStorage.getItem(KEY);
    return v === "light" || v === "dark" ? v : null;
  } catch {
    return null;
  }
}

let current: Theme = stored() ?? systemTheme();
const listeners = new Set<() => void>();

export function applyTheme(t: Theme) {
  current = t;
  if (typeof document !== "undefined") document.documentElement.dataset.theme = t;
  listeners.forEach((l) => l());
}

export function setTheme(t: Theme) {
  try {
    localStorage.setItem(KEY, t);
  } catch {
    /* storage may be blocked */
  }
  applyTheme(t);
}

export function toggleTheme() {
  setTheme(current === "dark" ? "light" : "dark");
}

export function useTheme(): Theme {
  return useSyncExternalStore(
    (cb) => {
      listeners.add(cb);
      return () => listeners.delete(cb);
    },
    () => current,
    () => "light",
  );
}

if (stored()) applyTheme(stored() as Theme);
