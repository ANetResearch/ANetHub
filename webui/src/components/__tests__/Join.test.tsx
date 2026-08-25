import { describe, it, expect } from "vitest";
import { joinPrompt } from "../JoinSection";

// This is the text a new user copies and pastes. Every command in it is
// one they will run verbatim, and a name that has drifted from the CLI
// stops them at the first step — with nothing to tell them the page was
// wrong rather than their typing.
//
// Nothing was watching for that drift. These assertions are the watch:
// they pin the command names, the flags, and the fact that every backend
// the page offers actually produces guidance.

const HUB = "https://hub.agentnetwork.org.cn";
const BACKENDS = ["cursor", "claude", "codex", "openclaw", "hermes", "openai"];

describe("joinPrompt", () => {
  it("gives guidance for every backend the page offers", () => {
    for (const b of BACKENDS) {
      const g = joinPrompt(b, HUB);
      expect(g.hint, `${b} hint`).toBeTruthy();
      expect(g.prompt, `${b} prompt`).toContain(HUB);
    }
  });

  // An unknown backend must not produce an empty page. Falling back to a
  // working one is better than rendering nothing and looking broken.
  it("falls back rather than producing nothing", () => {
    const g = joinPrompt("something-nobody-implemented", HUB);
    expect(g.prompt).toContain("anet ");
  });

  // The exec backends name two commands. Both are real, and both take
  // --agent with the id the tab is for.
  for (const agent of ["cursor", "claude", "codex", "openclaw", "hermes"]) {
    it(`tells a ${agent} user the commands that exist`, () => {
      const { prompt } = joinPrompt(agent, HUB);
      expect(prompt).toContain(`anet install --agent ${agent}`);
      expect(prompt).toContain(`anet autoreply set --backend exec --agent ${agent}`);
    });
  }

  // The openai backend needs an endpoint and a model, and the page has to
  // say so: "set --backend openai" alone fails with a message about
  // missing api_base, which reads as a bug in anet rather than a step the
  // page left out.
  it("tells an openai user which flags are required", () => {
    const { prompt } = joinPrompt("openai", HUB);
    expect(prompt).toContain("--backend openai");
    expect(prompt).toContain("--api-base");
    expect(prompt).toContain("--model");
  });

  // Every path ends by telling the user how to check it locally and how
  // to turn it off. A page that switches a node into answering strangers
  // and does not say how to stop is not finished.
  it("always says how to verify and how to stop", () => {
    for (const b of BACKENDS) {
      const { prompt } = joinPrompt(b, HUB);
      expect(prompt, `${b}`).toContain("anet autoreply test");
      expect(prompt, `${b}`).toContain("anet autoreply off");
    }
  });

  // The hub URL is whatever page the user is reading, not a constant.
  // Hard-coding it would send someone reading a private hub's page to a
  // public one.
  it("points at the hub the page is served from", () => {
    const { prompt } = joinPrompt("cursor", "http://10.0.0.5:8088");
    expect(prompt).toContain("http://10.0.0.5:8088/llms.txt");
    expect(prompt).not.toContain("agentnetwork.org.cn");
  });
});
