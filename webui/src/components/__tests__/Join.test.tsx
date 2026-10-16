import { describe, it, expect } from "vitest";
import { joinSteps } from "../JoinSection";

// The join checklist is text a reader copies and runs. Every command in it
// is executed verbatim, and a name that has drifted from the CLI stops the
// reader at the step with nothing to say the page was wrong rather than the
// typing. These assertions pin the five steps, their order and the command
// names.

const HUB = "https://hub.agentnetwork.org.cn";
const GONE = ["anet install", "whoami", "accept-end", "--invite"];

describe("joinSteps", () => {
  const steps = joinSteps(HUB, "zh");

  it("has the five steps in order, one command and one sentence each", () => {
    expect(steps.map((s) => s.id)).toEqual(["install", "init", "verify", "wire", "delegation"]);
    for (const s of steps) {
      expect(s.command, s.id).toBeTruthy();
      expect(s.command, `${s.id} is one line`).not.toContain("\n");
      expect(s.note, s.id).toBeTruthy();
      expect(s.title, s.id).toBeTruthy();
    }
  });

  it("installs with a verified installer and updates with anet update", () => {
    expect(steps[0].command).toContain("curl --proto '=https'");
    expect(steps[0].note).toContain("anet update");
  });

  it("registers with the hub the page is served from", () => {
    expect(steps[1].command).toContain("anet init");
    expect(steps[1].command).toContain(`anet hub-register ${HUB}`);
    expect(joinSteps("http://10.0.0.5:8088")[1].command).toContain("http://10.0.0.5:8088");
    expect(steps.map((s) => s.command).join("\n")).not.toContain("agentnetwork.org.cn/agents");
  });

  it("uses the commands of the current CLI", () => {
    const all = steps.map((s) => s.command).join("\n");
    for (const want of ["anet doctor", "anet status", "anet agents wire", "anet peers allow <AID>"]) {
      expect(all).toContain(want);
    }
    for (const gone of GONE) expect(all).not.toContain(gone);
  });

  // A new node accepts nobody; the page must say so at the delegation step.
  it("states that delegation is closed until a peer is allowed", () => {
    expect(steps[4].note).toContain("缺省不接受任何委派");
    expect(joinSteps(HUB, "en")[4].note).toContain("no delegation by default");
  });

  it("is available in both languages", () => {
    const en = joinSteps(HUB, "en");
    expect(en[0].title).toBe("Install");
    expect(en.map((s) => s.note).join("")).not.toMatch(/[一-鿿]/);
  });
});
