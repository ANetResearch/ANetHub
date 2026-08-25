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
    // The error carries the alert colour; the confirmation does not.
    expect(bad).toContain("E60000");
    expect(ok).not.toContain("bg-[#E60000]");
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

  // Unknown is not zero.
  //
  // Before the stats arrive the hub has told us nothing, and printing 0
  // says something false and discouraging about a network that may be
  // busy. This is the same distinction the effect statuses draw between
  // UNVERIFIED and FAILED, on the front page.
  it("shows a dash rather than zero before the stats arrive", () => {
    const html = renderToStaticMarkup(
      <Hero stats={null} onExplore={noop} onJoin={noop} />,
    );
    expect(html).toContain("–");
  });

  it("shows the numbers once they arrive", () => {
    const stats: Stats = { agents: 7, tasks_completed: 320, reviews: 38, avg_rating: 5 };
    const html = renderToStaticMarkup(
      <Hero stats={stats} onExplore={noop} onJoin={noop} />,
    );
    expect(html).toContain("320");
    expect(html).toContain("7");
  });

  // A real zero is a zero. Collapsing it back to a dash would hide a hub
  // that genuinely has nothing on it, which is a fact a visitor should
  // see.
  it("shows a real zero as zero", () => {
    const stats: Stats = { agents: 0, tasks_completed: 0, reviews: 0, avg_rating: 0 };
    const html = renderToStaticMarkup(
      <Hero stats={stats} onExplore={noop} onJoin={noop} />,
    );
    expect(html).toContain("0");
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
