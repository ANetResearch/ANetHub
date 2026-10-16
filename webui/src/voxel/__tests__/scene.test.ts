import { describe, it, expect } from "vitest";
import { buildScene, place, stage, STILL, byDepth, lerpCam } from "../scene";
import { dprCap, densityFor } from "../VoxelBackground";
import { unitScale } from "../render";

describe("voxel scene", () => {
  it("is deterministic", () => {
    expect(buildScene("full")).toEqual(buildScene("full"));
  });

  it("uses fewer cubes on narrow screens", () => {
    const full = buildScene("full").voxels.length;
    const lite = buildScene("lite").voxels.length;
    expect(lite).toBeLessThan(full * 0.6);
    expect(full).toBeLessThan(140);
  });

  it("lights only a few nodes", () => {
    for (const d of ["full", "lite"] as const) {
      const v = buildScene(d).voxels;
      const active = v.filter((x) => x.active);
      expect(active.length).toBeGreaterThanOrEqual(2);
      expect(active.length).toBeLessThanOrEqual(3);
      expect(active.every((x) => x.kind === "node")).toBe(true);
    }
  });

  it("scatters at the top of the page, aggregates and then pans", () => {
    expect(stage(0)).toEqual({ mix: 0, pan: 0 });
    expect(stage(0.4)).toEqual({ mix: 1, pan: 0 });
    expect(stage(1)).toEqual({ mix: 1, pan: 1 });
    expect(stage(-5)).toEqual({ mix: 0, pan: 0 });
    expect(stage(9)).toEqual({ mix: 1, pan: 1 });
    const mid = stage(0.2);
    expect(mid.mix).toBeGreaterThan(0);
    expect(mid.mix).toBeLessThan(1);
  });

  it("places every cube at its network position once aggregated", () => {
    const sc = buildScene("full");
    const placed = place(sc, STILL, 12.3);
    placed.forEach((p) => {
      expect(p.x).toBeCloseTo(p.v.nx, 6);
      expect(p.y).toBeCloseTo(p.v.ny, 6);
      expect(p.z).toBeCloseTo(p.v.nz, 6);
    });
  });

  it("starts from the scattered positions", () => {
    const sc = buildScene("lite");
    const placed = place(sc, { mix: 0, pan: 0 }, 0);
    placed.forEach((p) => {
      expect(p.x).toBeCloseTo(p.v.sx, 6);
      expect(p.z).toBeCloseTo(p.v.sz, 6);
    });
  });

  it("sorts far cubes before near ones and keeps the camera inside the network", () => {
    const a = { x: 0, y: 0, z: 0, v: buildScene("lite").voxels[0] };
    const b = { x: 3, y: 0, z: 3, v: a.v };
    expect([b, a].sort(byDepth)[0]).toBe(a);
    const sc = buildScene("full");
    expect(lerpCam(sc, -1)).toBe(sc.panFrom);
    expect(lerpCam(sc, 2)).toBe(sc.panTo);
  });
});

describe("voxel limits for small screens", () => {
  it("caps the pixel ratio at 1.5 below 768 px and 2 above", () => {
    expect(dprCap(375, 3)).toBe(1.5);
    expect(dprCap(1440, 3)).toBe(2);
    expect(dprCap(375, 1)).toBe(1);
    expect(dprCap(375, 0)).toBe(1);
  });
  it("selects the lite scene below 768 px", () => {
    expect(densityFor(375)).toBe("lite");
    expect(densityFor(768)).toBe("full");
  });
  it("keeps the unit scale within bounds", () => {
    expect(unitScale(200)).toBe(22);
    expect(unitScale(5000)).toBe(48);
  });
});
