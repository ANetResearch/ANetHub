import { useEffect, useRef } from "react";
import { buildScene, STILL, stage, type Density } from "./scene";
import { DARK, LIGHT, drawVoxels } from "./render";
import { useTheme } from "../lib/theme";

const NARROW = 768;

/** Canvas pixel ratio: lower on narrow screens. */
export function dprCap(width: number, devicePixelRatio: number): number {
  const cap = width < NARROW ? 1.5 : 2;
  return Math.max(1, Math.min(devicePixelRatio || 1, cap));
}

export function densityFor(width: number): Density {
  return width < NARROW ? "lite" : "full";
}

/** scrollProgress is the fraction of the page that has scrolled past the top. */
export function scrollProgress(): number {
  const el = document.documentElement;
  const max = el.scrollHeight - window.innerHeight;
  return max > 0 ? Math.min(1, Math.max(0, window.scrollY / max)) : 0;
}

/**
 * Fixed full-viewport background. The cubes scatter, gather into a network
 * as the page scrolls and then travel along it. It paints at most 30 times a
 * second, only while the page is visible, and once only when reduced motion
 * is requested.
 */
export function VoxelBackground() {
  const ref = useRef<HTMLCanvasElement>(null);
  const theme = useTheme();

  useEffect(() => {
    const canvas = ref.current;
    if (!canvas) return;
    const ctx = canvas.getContext("2d");
    if (!ctx) return;
    const reduced = typeof matchMedia !== "undefined" && matchMedia("(prefers-reduced-motion: reduce)").matches;
    const view = { width: 0, height: 0, dpr: 1 };
    let density: Density = "full";
    let scene = buildScene(density);
    let raf = 0;
    let last = 0;
    let running = false;
    let inView = true;
    const t0 = performance.now();
    const pal = () => (theme === "dark" ? DARK : LIGHT);

    const paint = (now: number) => {
      const st = reduced ? STILL : stage(scrollProgress());
      drawVoxels(ctx, scene, st, reduced ? 0 : (now - t0) / 1000, view, pal());
    };
    const resize = () => {
      const w = window.innerWidth;
      const h = window.innerHeight;
      const d = densityFor(w);
      if (d !== density) {
        density = d;
        scene = buildScene(d);
      }
      view.width = w;
      view.height = h;
      view.dpr = dprCap(w, window.devicePixelRatio);
      canvas.width = Math.round(w * view.dpr);
      canvas.height = Math.round(h * view.dpr);
      paint(performance.now());
    };
    const loop = (now: number) => {
      raf = requestAnimationFrame(loop);
      if (now - last < (density === "lite" ? 66 : 33)) return;
      last = now;
      paint(now);
    };
    const start = () => {
      if (reduced || running || document.hidden || !inView) return;
      running = true;
      raf = requestAnimationFrame(loop);
    };
    const stop = () => {
      running = false;
      cancelAnimationFrame(raf);
    };
    const onVisibility = () => (document.hidden ? stop() : start());

    // The background is decoration: it is first painted once the page has
    // loaded and the browser is idle, so that it does not compete with the
    // content for the first seconds.
    let begun = false;
    let idle = 0;
    const begin = () => {
      if (begun) return;
      begun = true;
      resize();
      start();
    };
    const afterLoad = () => {
      const ric = (window as unknown as { requestIdleCallback?: (f: () => void, o?: { timeout: number }) => number }).requestIdleCallback;
      idle = ric ? ric(begin, { timeout: 2500 }) : window.setTimeout(begin, 800);
    };
    if (document.readyState === "complete") afterLoad();
    else window.addEventListener("load", afterLoad, { once: true });
    const onResize = () => {
      if (begun) resize();
    };
    window.addEventListener("resize", onResize);
    document.addEventListener("visibilitychange", onVisibility);
    let io: IntersectionObserver | undefined;
    if (typeof IntersectionObserver !== "undefined") {
      io = new IntersectionObserver((es) => {
        inView = es.some((e) => e.isIntersecting);
        if (inView) start();
        else stop();
      });
      io.observe(canvas);
    }
    return () => {
      begun = true;
      window.removeEventListener("load", afterLoad);
      const cic = (window as unknown as { cancelIdleCallback?: (n: number) => void }).cancelIdleCallback;
      if (cic) cic(idle);
      else clearTimeout(idle);
      stop();
      io?.disconnect();
      window.removeEventListener("resize", onResize);
      document.removeEventListener("visibilitychange", onVisibility);
    };
  }, [theme]);

  return <canvas ref={ref} className="voxel-bg" aria-hidden="true" />;
}
