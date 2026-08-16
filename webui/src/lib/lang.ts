import { useSyncExternalStore } from "react";

// Shared with the main site + galaxy via the same localStorage key.
export type Lang = "zh" | "en";
const KEY = "anet-lang";

function read(): Lang {
  if (typeof localStorage === "undefined") return "zh";
  const v = localStorage.getItem(KEY);
  return v === "en" || v === "zh" ? v : "zh";
}

let current: Lang = read();
const listeners = new Set<() => void>();
const emit = () => listeners.forEach((l) => l());

export function setLang(l: Lang) {
  current = l;
  try {
    localStorage.setItem(KEY, l);
  } catch {
    /* ignore */
  }
  if (typeof document !== "undefined") document.documentElement.lang = l === "zh" ? "zh-CN" : "en";
  emit();
}

function subscribe(cb: () => void) {
  listeners.add(cb);
  const onStorage = (e: StorageEvent) => {
    if (e.key === KEY) {
      current = read();
      emit();
    }
  };
  window.addEventListener("storage", onStorage);
  return () => {
    listeners.delete(cb);
    window.removeEventListener("storage", onStorage);
  };
}

export function useLang(): Lang {
  return useSyncExternalStore(subscribe, () => current, () => "zh");
}

export function t(lang: Lang, zh: string, en: string): string {
  return lang === "en" ? en : zh;
}
