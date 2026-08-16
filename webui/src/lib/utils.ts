import { clsx, type ClassValue } from "clsx";
import { twMerge } from "tailwind-merge";

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}

export function shortAid(aid: string): string {
  if (!aid) return "";
  return aid.length > 16 ? aid.slice(0, 10) + "…" + aid.slice(-4) : aid;
}

export function fmtTime(ms?: number): string {
  if (!ms) return "";
  try {
    return new Date(Number(ms)).toLocaleString();
  } catch {
    return "";
  }
}

export function fmtBytes(n: number): string {
  n = Number(n) || 0;
  if (n < 1024) return n + " B";
  if (n < 1024 * 1024) return (n / 1024).toFixed(1) + " KB";
  return (n / 1024 / 1024).toFixed(1) + " MB";
}

/** File → base64 (分块，避免大文件爆栈)。 */
export async function fileToB64(f: File): Promise<string> {
  const b = new Uint8Array(await f.arrayBuffer());
  let s = "";
  const CH = 0x8000;
  for (let i = 0; i < b.length; i += CH) {
    s += String.fromCharCode.apply(null, Array.from(b.subarray(i, i + CH)));
  }
  return btoa(s);
}

export async function copyText(t: string): Promise<boolean> {
  try {
    await navigator.clipboard.writeText(t);
    return true;
  } catch {
    // http fallback
    try {
      const ta = document.createElement("textarea");
      ta.value = t;
      ta.style.position = "fixed";
      ta.style.opacity = "0";
      document.body.appendChild(ta);
      ta.select();
      const ok = document.execCommand("copy");
      document.body.removeChild(ta);
      return ok;
    } catch {
      return false;
    }
  }
}
