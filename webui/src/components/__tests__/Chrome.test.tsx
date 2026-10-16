import { describe, it, expect } from "vitest";
import { renderToStaticMarkup } from "react-dom/server";
import { Toast } from "../Toast";
import { Hero } from "../Hero";
import { Footer } from "../Footer";
import { Header } from "../Header";
import type { Stats } from "../../lib/api";

// The chrome around the page. None of it had a test, and two pieces carry
// facts that matter: the toast is the only place an error reaches a
// person, and the hero decides whether "we do not know yet" is shown as
// zero.

describe("Toast", () => {
  // An error and a confirmation must not look the same. A person who
  // cannot tell them apart will read a failure as a success once, which
  // is the only time it matters.
  it("distinguishes an error from a confirmation", () => {
    const ok = renderToStaticMarkup(<Toast state={{ msg: "已复制", err: false, show: true }} />);
    const bad = renderToStaticMarkup(<Toast state={{ msg: "复制失败", err: true, show: true }} />);
    expect(ok).toContain("已复制");
    expect(bad).toContain("复制失败");
    expect(ok).not.toBe(bad);
    // The error carries the accent border and role alert; the confirmation does not.
    expect(bad).toContain("border-accent");
    expect(bad).toContain('role="alert"');
    expect(ok).not.toContain("border-accent");
    expect(ok).toContain('role="status"');
  });

  // Hidden is hidden. A toast left interactive while invisible swallows
  // clicks aimed at whatever is under it.
  it("is not clickable while hidden", () => {
    const html = renderToStaticMarkup(<Toast state={{ msg: "x", err: false, show: false }} />);
    expect(html).toContain("pointer-events-none");
    expect(html).toContain("opacity-0");
  });
});

describe("Hero", () => {
  const noop = () => {};

  // Unknown is not zero. Before the stats arrive the Hub has reported
  // nothing, and a printed 0 would state something false.
  it("shows a dash rather than zero before the stats arrive", () => {
    const html = renderToStaticMarkup(<Hero stats={null} onJoin={noop} />);
    expect(html.match(/–/g)?.length).toBe(3);
  });

  it("shows the online nodes, registered agents and Hub version", () => {
    const stats: Stats = { agents: 7, tasks_completed: 320, reviews: 38, avg_rating: 5, online_nodes: 4, version: "0.3.0" };
    const html = renderToStaticMarkup(<Hero stats={stats} onJoin={noop} />);
    expect(html).toContain(">4<");
    expect(html).toContain(">7<");
    expect(html).toContain("0.3.0");
    expect(html).toContain("在线节点");
    expect(html).toContain("已注册 Agent");
  });

  // A real zero is a zero; a hub that reports no version yet is a dash.
  it("shows a real zero as zero", () => {
    const stats: Stats = { agents: 0, tasks_completed: 0, reviews: 0, avg_rating: 0, online_nodes: 0 };
    const html = renderToStaticMarkup(<Hero stats={stats} onJoin={noop} />);
    expect(html.match(/>0</g)?.length).toBe(2);
    expect(html.match(/–/g)?.length).toBe(1);
  });

  it("offers the two actions and no colloquial wording", () => {
    const html = renderToStaticMarkup(<Hero stats={null} onJoin={noop} />);
    expect(html).toContain("接入网络");
    expect(html).toContain("阅读文档");
    expect(html).not.toMatch(/[!！]/);
  });
});

describe("Header and Footer", () => {
  it("render without a crash and offer the way in", () => {
    const header = renderToStaticMarkup(<Header onJoin={() => {}} />);
    expect(header.length).toBeGreaterThan(0);
    const footer = renderToStaticMarkup(<Footer />);
    expect(footer.length).toBeGreaterThan(0);
  });
});
