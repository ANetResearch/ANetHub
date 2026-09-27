import { describe, it, expect, vi, afterEach, beforeAll } from "vitest";
import { act } from "react";
import { createRoot, type Root } from "react-dom/client";
import App from "../App";

// The task board is an opt-in hub module (-tags taskboard): a default hub
// has no board and no /tasks routes. The page learns which modules the hub
// has from /stats.modules. hasTaskboard is tested on its own in
// Tasks.test.tsx; this checks that the page acts on it — the section, the
// navigation entry and the board request all follow the hub's answer.

(globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true;

function respond(body: unknown): Response {
  return { ok: true, status: 200, text: async () => JSON.stringify(body) } as unknown as Response;
}

beforeAll(() => {
  // jsdom has no canvas; the hero's starfield checks for a null context.
  HTMLCanvasElement.prototype.getContext = (() => null) as typeof HTMLCanvasElement.prototype.getContext;
  if (!("ResizeObserver" in globalThis)) {
    vi.stubGlobal(
      "ResizeObserver",
      class {
        observe() {}
        disconnect() {}
      },
    );
  }
});

let mounted: { root: Root; el: HTMLElement } | null = null;

afterEach(async () => {
  if (mounted) {
    const { root, el } = mounted;
    await act(async () => root.unmount());
    el.remove();
    mounted = null;
  }
  vi.unstubAllGlobals();
});

/** Renders the page against a hub whose /stats carries `modules` (undefined: the field is absent). */
async function renderAgainstHub(modules: string[] | undefined) {
  const requested: string[] = [];
  vi.stubGlobal("fetch", async (input: string) => {
    const url = String(input);
    requested.push(url);
    if (url === "/stats") {
      return respond({ agents: 1, federated_agents: 0, tasks_completed: 0, reviews: 0, avg_rating: 0, modules });
    }
    if (url.startsWith("/agents")) return respond({ agents: [] });
    if (url === "/tasks/board") return respond({ columns: [] });
    return respond({});
  });
  const el = document.createElement("div");
  document.body.appendChild(el);
  const root = createRoot(el);
  mounted = { root, el };
  await act(async () => root.render(<App />));
  // Let the /stats and /agents requests settle and the board, if shown,
  // make its first request.
  await act(async () => {
    await new Promise((r) => setTimeout(r, 20));
  });
  await act(async () => {
    await new Promise((r) => setTimeout(r, 20));
  });
  return { el, requested };
}

describe("the task board follows /stats.modules", () => {
  it("is absent, unlinked and not requested when the hub does not list it", async () => {
    for (const modules of [["federation"], [], undefined]) {
      const { el, requested } = await renderAgainstHub(modules);
      expect(requested).toContain("/stats");
      expect(el.querySelector("#tasks")).toBeNull();
      expect(el.querySelector('a[href="#tasks"]')).toBeNull();
      expect(requested).not.toContain("/tasks/board");
      await act(async () => mounted!.root.unmount());
      mounted!.el.remove();
      mounted = null;
      vi.unstubAllGlobals();
    }
  });

  it("is shown, linked and loaded when the hub lists it", async () => {
    const { el, requested } = await renderAgainstHub(["federation", "taskboard"]);
    expect(el.querySelector("#tasks")).not.toBeNull();
    expect(el.querySelector('a[href="#tasks"]')).not.toBeNull();
    expect(requested).toContain("/tasks/board");
  });
});
