import { describe, it, expect } from "vitest";
import { renderToStaticMarkup } from "react-dom/server";
import { Review, contentBindingLabel } from "../AgentDetailDialog";
import type { ReviewView } from "../../lib/api";

// The detail dialog is where a stranger decides whether to believe a
// rating. What makes a review checkable — who signed it and which receipt
// it anchors on — arrives here. What the hub did NOT check has to arrive
// too: it holds no interaction content, so it cannot say whether the
// receipt's request_cid and result_cid match anything.
//
// Rendered to static markup: the question is "does this fact reach the
// page", which markup answers exactly, and it needs no DOM.

function review(over: Partial<ReviewView> = {}): ReviewView {
  return {
    interaction_id: "ix_0123456789abcdef",
    subject_aid: "bafyreiebzlsjonjvubmfeefjqulgfuzrvfg4lfcdnn3bdp7ekuvw2rrcuy",
    reviewer_aid: "bafyreigr6jrgrrnu7zlzhk2my7cgjooddncozici2674eckzeuyucaqk5u",
    rating: 5,
    comment: "answered quickly",
    receipt_cid: "bafyreiez5ziuzobff7qdlcklemjevbwu43sxakol3gydk7ifushu7t4i3u",
    request_cid: "bafyreirequest",
    result_cid: "bafyreiresult",
    content_binding: "UNVERIFIED",
    completed_at: 1787580930527,
    created_at: 1787580960000,
    ...over,
  };
}

describe("Review", () => {
  // A rating with nothing behind it is an opinion. What makes this one
  // evidence is the receipt both parties signed, and a card that shows
  // the number and hides the anchor has published the opinion.
  it("shows the receipt the rating is anchored on", () => {
    const html = renderToStaticMarkup(<Review r={review()} />);
    expect(html).toContain("双方签名已验证");
    // Shortened for the screen, but it must be THIS receipt.
    expect(html).toMatch(/bafyreiez5ziu|bafyre/);
    expect(html).toContain("bafyreirequest");
    expect(html).toContain("bafyreiresult");
  });

  // "Not checked" and "checked and fine" are different states. The page
  // used to show "✓ 内容已验证" next to the goal and the transcript; the
  // hub no longer receives either, and a badge claiming a check nobody
  // made would state something false.
  it("states that the content binding was not checked", () => {
    const html = renderToStaticMarkup(<Review r={review()} />);
    expect(html).toContain("内容绑定未核对");
    expect(html).not.toContain("内容已验证");
  });

  // A hub that has not been upgraded sends no content_binding at all.
  // Absent is read as not checked, never as checked.
  it("reads an absent content binding as not checked", () => {
    const html = renderToStaticMarkup(<Review r={review({ content_binding: "" })} />);
    expect(html).toContain("内容绑定未核对");
    expect(contentBindingLabel(undefined)).toContain("未核对");
  });

  // An older hub may still send goal and deliverable. The page does not
  // render them: interaction content is not something the directory
  // shows.
  it("does not render content an older hub still sends", () => {
    const legacy = { ...review(), goal: "summarise the log", deliverable: "a summary" } as ReviewView;
    const html = renderToStaticMarkup(<Review r={legacy} />);
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
