import { describe, it, expect } from "vitest";
import { renderToStaticMarkup } from "react-dom/server";
import { AgentCard, Stars } from "../AgentsSection";
import type { AgentView } from "../../lib/api";

// The card is where a person decides who to send work to. Three facts
// arrive from the hub that bear on that decision, and until now none of
// them reached the screen: whether the agent lives on another hub,
// whether it has stopped collecting its mail, and when it last did.
//
// Rendered to static markup rather than mounted. No new dependency, and
// the question here is "does this fact reach the page", which markup
// answers exactly.

function agent(over: Partial<AgentView> = {}): AgentView {
  return {
    aid: "bafyreiebzlsjonjvubmfeefjqulgfuzrvfg4lfcdnn3bdp7ekuvw2rrcuy",
    name: "Worker",
    caps: ["text.digest"],
    listed: true,
    guest_quota: 0,
    avg_rating: 0,
    review_count: 0,
    registered_at: "2026-08-23T00:00:00Z",
    ...over,
  };
}

const render = (a: AgentView) => renderToStaticMarkup(<AgentCard a={a} onOpen={() => {}} />);

describe("what the card tells a person before they delegate", () => {
  it("says when an agent lives on another hub", () => {
    const html = render(agent({ home_hub: "http://other.example:4001" }));
    expect(html).toContain("其他 hub");
    expect(html).toContain("http://other.example:4001");
  });

  it("does not mark a local agent as being elsewhere", () => {
    expect(render(agent())).not.toContain("其他 hub");
  });

  it("says when an agent has stopped collecting its mail", () => {
    // The agent is still listed and still deliverable-to. Work sent to it
    // is accepted and waits for a poll that may never come, so this is
    // the fact a reader most needs and would never think to ask for.
    const html = render(agent({ quiet: true, last_seen: "2026-08-20T00:00:00Z" }));
    expect(html).toContain("静默");
    expect(html).toContain("2026-08-20T00:00:00Z");
  });

  it("does not mark a live agent as quiet", () => {
    // omitempty means a healthy agent carries no quiet field at all. An
    // absent field must read as "not quiet", not as "unknown".
    expect(render(agent({ last_seen: "2026-08-23T00:00:00Z" }))).not.toContain("静默");
    expect(render(agent())).not.toContain("静默");
  });

  it("shows both marks together when both apply", () => {
    const html = render(agent({ home_hub: "http://other.example:4001", quiet: true }));
    expect(html).toContain("其他 hub");
    expect(html).toContain("静默");
  });

  it("renders a quiet agent with no last_seen without breaking", () => {
    expect(render(agent({ quiet: true }))).toContain("静默");
  });
});

describe("the parts that were already on the card", () => {
  it("falls back to the short AID when an agent has no name", () => {
    const html = render(agent({ name: "" }));
    expect(html).toContain("bafyreiebz");
    expect(html).toContain("rcuy");
  });

  it("says so when there is no summary rather than leaving a gap", () => {
    expect(render(agent())).toContain("还没有填写简介");
  });

  it("shows the rating only when there is one", () => {
    expect(render(agent({ review_count: 3, avg_rating: 4.5 }))).toContain("4.5");
    expect(render(agent())).not.toContain("4.5");
  });

  it("offers a guest trial only when the agent allows it", () => {
    expect(render(agent({ guest_quota: 5 }))).toContain("可试聊 5 条");
    expect(render(agent({ guest_quota: 0 }))).not.toContain("可试聊");
  });

  it("survives caps being null, which the hub sends for an agent with none", () => {
    // The wire type is `string[] | null`, and a null here would throw
    // during render — taking the whole directory page with it.
    expect(() => render(agent({ caps: null }))).not.toThrow();
  });
});

describe("Stars", () => {
  it("fills to the rating without overstating it", () => {
    const filled = (avg: number) =>
      (renderToStaticMarkup(<Stars avg={avg} />).match(/fill-\[#E60000\]/g) || []).length;
    expect(filled(0)).toBe(0);
    expect(filled(5)).toBe(5);
    // Rounding up would show four stars for 3.6, overstating the agent to
    // the person choosing it.
    expect(filled(3.6)).toBeLessThanOrEqual(4);
  });
});
