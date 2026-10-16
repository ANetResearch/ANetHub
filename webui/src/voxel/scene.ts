// Voxel network scene for the landing page background.
//
// The scene is a fixed set of cubes. Each cube has two resting places: a
// scattered position and a position in a network topology (large cubes are
// nodes, small cubes laid between them are links). Scroll progress moves
// the cubes from the first to the second (aggregation) and then pans the
// camera along the network. Everything here is pure and deterministic so
// that it can be tested without a canvas.

export type Density = "full" | "lite";

export interface Voxel {
  /** Edge length in world units. */
  size: number;
  /** Scattered resting position. */
  sx: number;
  sy: number;
  sz: number;
  /** Position inside the network. */
  nx: number;
  ny: number;
  nz: number;
  /** Start of this cube's move, 0..0.4 of the aggregation range. */
  delay: number;
  /** Phase of the idle drift. */
  phase: number;
  kind: "node" | "link" | "dust";
  /** Lit in the accent colour. Only a few nodes are. */
  active: boolean;
}

export interface Scene {
  voxels: Voxel[];
  /** World x of the first and last node column: the camera pans between them. */
  panFrom: number;
  panTo: number;
}

/** Small deterministic generator (mulberry32). */
export function rng(seed: number): () => number {
  let a = seed >>> 0;
  return () => {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

const GAP = 3; // lattice spacing in world units

/**
 * buildScene lays the nodes on a two-row lattice and joins neighbours with
 * axis-aligned runs of small cubes. "lite" has fewer columns and less dust,
 * for narrow screens.
 */
export function buildScene(density: Density, seed = 7): Scene {
  const r = rng(seed);
  const cols = density === "full" ? 8 : 5;
  const rows = 2;
  const dust = density === "full" ? 26 : 10;
  const voxels: Voxel[] = [];
  const scatter = (): [number, number, number] => [-6 + r() * 26, -5 + r() * 10, -7 + r() * 14];

  const nodeAt = (i: number, j: number) => ({ x: i * GAP, z: j * GAP });
  // Three nodes, spread across the lattice, carry the accent colour.
  const activeKeys = new Set(density === "full" ? ["1:0", "4:1", "6:0"] : ["1:0", "3:1"]);

  for (let i = 0; i < cols; i++) {
    for (let j = 0; j < rows; j++) {
      const p = nodeAt(i, j);
      const [sx, sy, sz] = scatter();
      voxels.push({
        size: 1, sx, sy, sz, nx: p.x, ny: 0, nz: p.z,
        delay: r() * 0.4, phase: r() * 6.28, kind: "node", active: activeKeys.has(`${i}:${j}`),
      });
    }
  }
  const link = (x: number, z: number) => {
    const [sx, sy, sz] = scatter();
    voxels.push({
      size: 0.5, sx, sy, sz, nx: x + 0.25, ny: 0.25, nz: z + 0.25,
      delay: r() * 0.4, phase: r() * 6.28, kind: "link", active: false,
    });
  };
  for (let i = 0; i < cols; i++) {
    for (let j = 0; j < rows; j++) {
      const a = nodeAt(i, j);
      if (i + 1 < cols) {
        link(a.x + 1.0, a.z + 0.25);
        link(a.x + 1.75, a.z + 0.25);
      }
      // Cross links between the two rows on every other column.
      if (j + 1 < rows && i % 2 === 0) {
        link(a.x + 0.25, a.z + 1.0);
        link(a.x + 0.25, a.z + 1.75);
      }
    }
  }
  for (let k = 0; k < dust; k++) {
    const [sx, sy, sz] = scatter();
    // Dust settles near the lattice as loose cubes, off the links.
    const nx = r() * (cols - 1) * GAP;
    const nz = -2.5 + r() * 9;
    voxels.push({
      size: 0.3 + r() * 0.2, sx, sy, sz, nx, ny: -0.6 - r() * 1.2, nz,
      delay: r() * 0.4, phase: r() * 6.28, kind: "dust", active: false,
    });
  }
  return { voxels, panFrom: 4, panTo: (cols - 1) * GAP - 2 };
}

export function clamp01(x: number): number {
  return x < 0 ? 0 : x > 1 ? 1 : x;
}
export function smooth(a: number, b: number, x: number): number {
  const t = clamp01((x - a) / (b - a));
  return t * t * (3 - 2 * t);
}

export interface Stage {
  /** 0 scattered .. 1 aggregated into the network. */
  mix: number;
  /** 0 .. 1 camera travel along the network. */
  pan: number;
}

/** stage maps page scroll progress (0..1) to the three phases: scatter, aggregate, pan. */
export function stage(progress: number): Stage {
  const p = clamp01(progress);
  return { mix: smooth(0.03, 0.4, p), pan: smooth(0.4, 1, p) };
}

/** The frame shown when motion is reduced: the aggregated network, camera at the start. */
export const STILL: Stage = { mix: 1, pan: 0 };

export interface Placed {
  x: number;
  y: number;
  z: number;
  v: Voxel;
}

/** place computes the world position of every cube for a stage and time (seconds). */
export function place(scene: Scene, st: Stage, time: number): Placed[] {
  const out: Placed[] = [];
  for (const v of scene.voxels) {
    const m = smooth(v.delay, v.delay + 0.6, st.mix * 1.0);
    const drift = (1 - m) * Math.sin(time * 0.5 + v.phase) * 0.35;
    out.push({
      x: v.sx + (v.nx - v.sx) * m,
      y: v.sy + (v.ny - v.sy) * m + drift,
      z: v.sz + (v.nz - v.sz) * m,
      v,
    });
  }
  return out;
}

export const COS30 = 0.8660254;

/** Isometric projection of a world point to screen units (before scale and offset). */
export function iso(x: number, y: number, z: number): [number, number] {
  return [(x - z) * COS30, (x + z) * 0.5 - y];
}

/** Painter's order: far cubes first. */
export function byDepth(a: Placed, b: Placed): number {
  return a.x + a.z + a.y - (b.x + b.z + b.y);
}

/** Camera world x for a pan value. */
export function lerpCam(scene: Scene, pan: number): number {
  return scene.panFrom + (scene.panTo - scene.panFrom) * clamp01(pan);
}
