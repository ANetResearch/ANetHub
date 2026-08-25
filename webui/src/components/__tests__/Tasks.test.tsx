import { describe, it, expect } from "vitest";
import { renderToStaticMarkup } from "react-dom/server";
import { Column } from "../TasksSection";
import type { BoardColumn } from "../../lib/api";

// The board is the hub's public evidence that anything is happening. What
// a column shows — a card's state, who holds it, which document it is
// about — is what an outsider judges by, and 107 lines of it had no test.
//
// Everything above Column is a fetch in an effect, which a static render
// can only ever observe as "loading". Splitting the column out is what
// makes the part that matters testable at all.

function col(over: Partial<BoardColumn> = {}): BoardColumn {
  return {
    key: "ready",
    name: "Ready",
    cards: [
      {
        id: "card-1", title: "summarise the log", taskdoc_cid: "bafyreitaskdoc",
        state: "created", column: "ready", creator_aid: "did:anet:a",
        created_at: 1, updated_at: 1,
      },
    ],
    ...over,
  } as BoardColumn;
}

describe("Column", () => {
  // A card is a view; the truth is its TaskDoc. Showing the title and
  // hiding the document would present the summary as the thing itself.
  it("shows the card's title and the document it is about", () => {
    const html = renderToStaticMarkup(<Column col={col()} lang="zh" />);
    expect(html).toContain("summarise the log");
    expect(html).toContain("bafyreitaskdoc");
  });

  it("shows the card's state", () => {
    const html = renderToStaticMarkup(<Column col={col()} lang="zh" />);
    expect(html).toContain("created");
  });

  // Who holds a card is the difference between work available and work
  // taken. Absent when unclaimed, present when claimed.
  it("names the assignee only when there is one", () => {
    const plain = renderToStaticMarkup(<Column col={col()} lang="zh" />);
    expect(plain).not.toContain("→");
    const held = col();
    (held.cards[0] as Record<string, unknown>).assignee_aid =
      "bafyreigr6jrgrrnu7zlzhk2my7cgjooddncozici2674eckzeuyucaqk5u";
    held.cards[0].state = "claimed";
    const html = renderToStaticMarkup(<Column col={held} lang="zh" />);
    expect(html).toContain("→");
  });

  // An empty column says it is empty. Rendering nothing looks like a
  // column that failed to load.
  it("marks an empty column", () => {
    const html = renderToStaticMarkup(<Column col={col({ cards: [] })} lang="zh" />);
    expect(html).toContain("—");
    expect(html).toContain("0");
  });

  // A long column is truncated, and says how much it truncated. A silent
  // cut reads as "that is all there is".
  it("says how many cards it did not show", () => {
    const many = col({
      cards: Array.from({ length: 11 }, (_, i) => ({
        id: `c${i}`, title: `card ${i}`, taskdoc_cid: "bafy", state: "created",
        column: "ready", creator_aid: "did:anet:a", created_at: 1, updated_at: 1,
      })),
    } as Partial<BoardColumn>);
    const html = renderToStaticMarkup(<Column col={many} lang="zh" />);
    expect(html).toContain("+3");
    expect(html).toContain("11");
  });
});
