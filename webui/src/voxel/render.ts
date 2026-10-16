import { COS30, byDepth, iso, lerpCam, place, stage, STILL, type Placed, type Scene, type Stage } from "./scene";

export interface Palette {
  top: string;
  left: string;
  right: string;
  edge: string;
  accTop: string;
  accLeft: string;
  accRight: string;
}

export const LIGHT: Palette = {
  top: "#c9ccd1", left: "#aeb2b9", right: "#92969e", edge: "rgba(11,11,12,0.2)",
  accTop: "#e93024", accLeft: "#c4281d", accRight: "#98201a",
};
export const DARK: Palette = {
  top: "#7a7d86", left: "#585a61", right: "#3e4046", edge: "rgba(236,236,238,0.14)",
  accTop: "#e93024", accLeft: "#b72a20", accRight: "#8a211a",
};

export interface View {
  width: number; // CSS pixels
  height: number;
  dpr: number;
}

/** Pixels per world unit for a viewport width. */
export function unitScale(width: number): number {
  return Math.max(22, Math.min(48, width / 14));
}

function poly(ctx: CanvasRenderingContext2D, pts: number[], fill: string, edge: string) {
  ctx.beginPath();
  ctx.moveTo(pts[0], pts[1]);
  for (let i = 2; i < pts.length; i += 2) ctx.lineTo(pts[i], pts[i + 1]);
  ctx.closePath();
  ctx.fillStyle = fill;
  ctx.fill();
  ctx.strokeStyle = edge;
  ctx.stroke();
}

/**
 * drawVoxels paints one frame. The caller supplies the scroll stage and the
 * time; nothing here reads the DOM.
 */
export function drawVoxels(
  ctx: CanvasRenderingContext2D,
  scene: Scene,
  st: Stage,
  time: number,
  view: View,
  pal: Palette,
) {
  const { width: W, height: H, dpr } = view;
  ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
  ctx.clearRect(0, 0, W, H);
  ctx.lineWidth = 1;
  ctx.lineJoin = "round";
  const s = unitScale(W);
  const camX = lerpCam(scene, st.pan);
  const cx = W * 0.5;
  const cy = H * 0.5;
  const [ox, oy] = iso(camX, 0, 2);
  const placed: Placed[] = place(scene, st, time);
  placed.sort(byDepth);
  for (const p of placed) {
    const { x, y, z, v } = p;
    const a = v.size;
    // Corners of the cube in screen space.
    const P = (dx: number, dy: number, dz: number): [number, number] => {
      const [px, py] = iso(x + dx, y + dy, z + dz);
      return [cx + (px - ox) * s, cy + (py - oy) * s];
    };
    const t00 = P(0, a, 0), t10 = P(a, a, 0), t11 = P(a, a, a), t01 = P(0, a, a);
    const b10 = P(a, 0, 0), b11 = P(a, 0, a), b01 = P(0, 0, a);
    // Skip cubes that are entirely off screen.
    const minX = Math.min(t00[0], t01[0], b01[0]);
    const maxX = Math.max(t10[0], b10[0], b11[0]);
    if (maxX < -40 || minX > W + 40) continue;
    const pulse = v.active ? 0.7 + 0.3 * Math.sin(time * 1.6 + v.phase) : 1;
    ctx.globalAlpha = v.active ? pulse : 1;
    const top = v.active ? pal.accTop : pal.top;
    const left = v.active ? pal.accLeft : pal.left;
    const right = v.active ? pal.accRight : pal.right;
    poly(ctx, [...t01, ...t11, ...t10, ...t00], top, pal.edge);
    poly(ctx, [...t01, ...t11, ...b11, ...b01], left, pal.edge);
    poly(ctx, [...t11, ...t10, ...b10, ...b11], right, pal.edge);
  }
  ctx.globalAlpha = 1;
}

export { COS30, stage, STILL };
