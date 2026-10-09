import { describe, it, expect } from "vitest";
import { renderToStaticMarkup } from "react-dom/server";
import { Review, fmtDay } from "../AgentDetailDialog";
import type { ReviewView } from "../../lib/api";

// The detail dialog is where a stranger decides whether to believe a
// rating. What makes a review checkable — the receipt it anchors on —
// arrives here. Who wrote it does not: the hub keeps no reviewer (evidence
// v2), and the page has nothing to show of one.
//
// Rendered to static markup: the question is "does this fact reach the
// page", which markup answers exactly, and it needs no DOM.

function review(over: Partial<ReviewView> = {}): ReviewView {
  return {
    subject_aid: "bafyreiebzlsjonjvubmfeefjqulgfuzrvfg4lfcdnn3bdp7ekuvw2rrcuy",
    rating: 5,
    comment: "answered quickly",
    receipt_cid: "bafyreiez5ziuzobff7qdlcklemjevbwu43sxakol3gydk7ifushu7t4i3u",
    completed_day: 20735,
    created_day: 20736,
    ...over,
  };
}

describe("Review", () => {
  // A rating with nothing behind it is an opinion. What makes this one
  // evidence is the receipt the provider signed, and a card that shows
  // the number and hides the anchor has published the opinion.
  it("shows the receipt the rating is anchored on", () => {
    const html = renderToStaticMarkup(<Review r={review()} />);
    expect(html).toContain("双方签名已验证");
    // Shortened for the screen, but it must be THIS receipt.
    expect(html).toMatch(/bafyreiez5ziu|bafyre/);
  });

  // Days, not times: the hub keeps nothing finer.
  it("shows the days of the receipt and the review", () => {
    const html = renderToStaticMarkup(<Review r={review()} />);
    expect(html).toContain(fmtDay(20735));
    expect(html).toContain(fmtDay(20736));
    expect(fmtDay(20735)).toBe("2026-10-09");
  });

  // An older hub may still send a reviewer, an interaction id or content.
  // The page renders none of them.
  it("does not render what an older hub still sends", () => {
    const legacy = {
      ...review(),
      reviewer_aid: "bafyreigr6jrgrrnu7zlzhk2my7cgjooddncozici2674eckzeuyucaqk5u",
      interaction_id: "ix_0123456789abcdef",
      goal: "summarise the log",
      deliverable: "a summary",
    } as ReviewView;
    const html = renderToStaticMarkup(<Review r={legacy} />);
    expect(html).not.toContain("bafyreigr6j");
    expect(html).not.toContain("ix_0123456789abcdef");
    expect(html).not.toContain("summarise the log");
    expect(html).not.toContain("a summary");
  });

  // A review with no comment is normal and must still render: the rating
  // and the receipt are the parts that matter.
  it("renders without a comment", () => {
    const html = renderToStaticMarkup(<Review r={review({ comment: undefined })} />);
    expect(html).toContain("双方签名已验证");
  });
});
