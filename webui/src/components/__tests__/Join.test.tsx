import { describe, it, expect } from "vitest";
import { cliSteps, joinOneLiner, joinPrompt } from "../JoinSection";

// This is the text a new user copies and pastes. Every command in it is
// one they will run verbatim, and a name that has drifted from the CLI
// stops them at the first step — with nothing to tell them the page was
// wrong rather than their typing.
//
// Nothing was watching for that drift. These assertions are the watch:
// they pin the command names, the flags, and the fact that every backend
// the page offers actually produces guidance. The commands are those of
// A2A-DESIGN §13 (anet update / init / doctor / agents wire), the same as
// /llms.txt (internal/aghub/llms_test.go pins that side).

const HUB = "https://hub.agentnetwork.org.cn";
const BACKENDS = ["cursor", "claude", "codex", "openclaw", "hermes", "openai"];
// The tools `anet agents wire` knows. OpenClaw is not one of them.
const WIRED = ["cursor", "claude", "codex", "hermes"];

// Commands the CLI no longer has: `anet install --agent` became
// `anet agents wire`, and there is no `whoami`.
const GONE = ["anet install", "whoami", "accept-end"];

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

  // The exec backends name the commands that exist, with the id of the
  // tab: `anet agents wire <tool>` where the tool is one wire knows, and
  // the auto-reply command for all of them.
  for (const agent of ["cursor", "claude", "codex", "openclaw", "hermes"]) {
    it(`tells a ${agent} user the commands that exist`, () => {
      const { prompt } = joinPrompt(agent, HUB);
      expect(prompt).toContain(`anet autoreply set --backend exec --agent ${agent}`);
      if (WIRED.includes(agent)) {
        expect(prompt).toContain(`anet agents wire ${agent}`);
      } else {
        expect(prompt).not.toContain("anet agents wire");
      }
    });
  }

  it("names no command the CLI has dropped", () => {
    for (const b of BACKENDS) {
      for (const gone of GONE) {
        expect(joinPrompt(b, HUB).prompt, `${b}`).not.toContain(gone);
      }
    }
    for (const gone of GONE) {
      expect(joinOneLiner(HUB)).not.toContain(gone);
    }
  });

  // Step 0 of /llms.txt: update an installed anet, install only on a fresh
  // machine. The prompts used to leave that to the page they point at, and
  // the page next to them said to run the installer again.
  it("updates before it installs", () => {
    for (const b of BACKENDS) {
      expect(joinPrompt(b, HUB).prompt, `${b}`).toContain("anet update");
    }
    expect(joinOneLiner(HUB)).toContain("anet update");
    expect(joinOneLiner(HUB)).toContain(`${HUB}/llms.txt`);
  });

  // A fresh node accepts nobody, and an exec backend runs the local agent
  // only for trusted peers (A2A-DESIGN SI-5). A prompt that switches
  // auto-reply on without saying so leaves the user thinking the node is
  // serving.
  it("says who the node will answer", () => {
    for (const b of BACKENDS) {
      expect(joinPrompt(b, HUB).prompt, `${b}`).toContain("anet peers allow <AID>");
    }
    for (const agent of ["cursor", "claude", "codex", "openclaw", "hermes"]) {
      expect(joinPrompt(agent, HUB).prompt, `${agent}`).toContain("anet peers trust <AID>");
    }
  });

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

describe("cliSteps", () => {
  const steps = cliSteps(HUB);
  const all = steps.flatMap((s) => s.blocks).join("\n");

  // Each block is a copy button. The update and the installer in one block
  // would reinstall on every machine the block is pasted on — the page
  // used to say "installed already? run the installer again".
  it("keeps the update and the installer apart", () => {
    const blocks = steps[0].blocks;
    const update = blocks.findIndex((b) => b.includes("anet update"));
    const install = blocks.findIndex((b) => b.includes("install.sh"));
    expect(update).toBeGreaterThanOrEqual(0);
    expect(install).toBeGreaterThan(update);
    expect(blocks[update]).not.toContain("install.sh");
    expect(blocks[install]).not.toContain("anet update");
    expect(blocks[install]).toContain("curl --proto '=https'");
    expect(steps[0].note).not.toContain("再跑一次");
  });

  it("uses the commands of the current CLI", () => {
    for (const want of [
      "anet init",
      `anet hub-register ${HUB}`,
      "anet doctor",
      "anet agents wire",
      "anet peers allow <对端 AID>",
      "anet peers trust <对端 AID>",
      "anet autoreply set --backend exec --agent claude",
      "anet autoreply off",
    ]) {
      expect(all).toContain(want);
    }
    for (const gone of GONE) {
      expect(all).not.toContain(gone);
    }
  });

  // Access comes before auto-reply: a reader who stops after the
  // auto-reply line must already have been told who it will answer.
  it("grants before it switches auto-reply on", () => {
    expect(all.indexOf("anet peers trust")).toBeLessThan(all.indexOf("anet autoreply set"));
  });
});
