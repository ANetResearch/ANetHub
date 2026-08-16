import { useEffect, useRef } from "react";

/** 品牌「星空/星座」意象：深色 band 上的 canvas 星点 + 若干淡红色连线（constellation）。 */
export function Starfield({ className }: { className?: string }) {
  const ref = useRef<HTMLCanvasElement>(null);

  useEffect(() => {
    const canvas = ref.current;
    if (!canvas) return;
    const ctx = canvas.getContext("2d");
    if (!ctx) return;
    let raf = 0;
    let W = 0;
    let H = 0;
    const DPR = Math.min(window.devicePixelRatio || 1, 2);

    interface Star {
      x: number;
      y: number;
      r: number;
      a: number;
      s: number;
      red: boolean;
    }
    const stars: Star[] = Array.from({ length: 160 }, (_, i) => ({
      x: Math.random(),
      y: Math.random(),
      r: Math.random() * 1.3 + 0.3,
      a: Math.random() * 0.5 + 0.15,
      s: Math.random() * 0.6 + 0.2,
      red: i % 17 === 0,
    }));
    // 固定几条“星座”连线（取前 N 颗星按邻近连一小段折线）
    const linked = stars.slice(0, 26);

    const resize = () => {
      const rect = canvas.getBoundingClientRect();
      W = canvas.width = Math.max(1, Math.round(rect.width * DPR));
      H = canvas.height = Math.max(1, Math.round(rect.height * DPR));
    };
    resize();
    const ro = new ResizeObserver(resize);
    ro.observe(canvas);

    let t = 0;
    const draw = () => {
      t += 0.016;
      ctx.clearRect(0, 0, W, H);
      // constellation edges
      ctx.lineWidth = Math.max(1, 0.6 * DPR);
      for (let i = 0; i < linked.length - 1; i++) {
        const a = linked[i];
        const b = linked[i + 1];
        const dx = a.x - b.x;
        const dy = a.y - b.y;
        if (dx * dx + dy * dy > 0.045) continue; // 只连相邻的
        const alpha = 0.1 + 0.06 * Math.sin(t * 0.7 + i);
        ctx.strokeStyle = `rgba(230,0,0,${alpha})`;
        ctx.beginPath();
        ctx.moveTo(a.x * W, a.y * H);
        ctx.lineTo(b.x * W, b.y * H);
        ctx.stroke();
      }
      for (const s of stars) {
        const a = s.a * (0.55 + 0.45 * Math.sin(t * s.s + s.x * 10));
        ctx.beginPath();
        ctx.arc(s.x * W, s.y * H, s.r * DPR, 0, Math.PI * 2);
        ctx.fillStyle = s.red ? `rgba(255,80,80,${a})` : `rgba(230,238,255,${a})`;
        ctx.fill();
      }
      raf = requestAnimationFrame(draw);
    };
    raf = requestAnimationFrame(draw);
    return () => {
      cancelAnimationFrame(raf);
      ro.disconnect();
    };
  }, []);

  return <canvas ref={ref} className={className} aria-hidden="true" />;
}
