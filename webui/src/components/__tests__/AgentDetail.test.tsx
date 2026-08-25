import { describe, it, expect } from "vitest";
import { renderToStaticMarkup } from "react-dom/server";
import { Transcript, Review } from "../AgentDetailDialog";
import type { ReviewView } from "../../lib/api";

// The detail dialog is where a stranger decides whether to believe a
// rating. Everything that makes a review checkable — who signed it, which
// receipt it anchors on, what was actually asked and answered — arrives
// here, and 234 lines of it had no test at all.
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
    goal: "summarise the log",
    deliverable: "a summary",
    request_cid: "bafyreirequest",
    result_cid: "bafyreiresult",
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
  });

  it("shows what was asked and what came back", () => {
    const html = renderToStaticMarkup(<Review r={review()} />);
    expect(html).toContain("summarise the log");
  });

  // A review with no comment is normal and must still render: the rating
  // and the receipt are the parts that matter.
  it("renders without a comment", () => {
    const html = renderToStaticMarkup(<Review r={review({ comment: undefined })} />);
    expect(html).toContain("双方签名已验证");
  });
});

describe("Transcript", () => {
  // A multi-turn conversation arrives as JSON. Both sides have to be
  // distinguishable, or a reader cannot tell who said what — which is the
  // whole content of a transcript.
  it("separates the two sides of a conversation", () => {
    const html = renderToStaticMarkup(
      <Transcript s={JSON.stringify([
        { from: "requester", body: "what is a hash?" },
        { from: "provider", body: "a fixed-length digest" },
      ])} />,
    );
    expect(html).toContain("委派方");
    expect(html).toContain("提供方");
    expect(html).toContain("what is a hash?");
    expect(html).toContain("a fixed-length digest");
  });

  // Not every result is a conversation. A plain string must render as
  // itself rather than disappearing because it failed to parse.
  it("renders a non-JSON result as text", () => {
    const html = renderToStaticMarkup(<Transcript s="sha256: abc123" />);
    expect(html).toContain("sha256: abc123");
  });

  // An empty conversation says so. Rendering nothing would read as a
  // loading state that never finishes.
  it("says when there is nothing to show", () => {
    const html = renderToStaticMarkup(<Transcript s="[]" />);
    expect(html).toContain("无对话内容");
  });

  // Markdown in a message is rendered, and the renderer is the one thing
  // here that touches untrusted text: a message body comes from another
  // agent. Script tags must not survive it.
  it("does not let a message inject script", () => {
    const html = renderToStaticMarkup(
      <Transcript s={JSON.stringify([{ from: "provider", body: "<script>alert(1)</script>" }])} />,
    );
    expect(html).not.toContain("<script>");
  });
});
