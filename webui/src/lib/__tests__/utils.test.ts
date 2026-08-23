import { describe, it, expect } from "vitest";
import { shortAid, fmtBytes, fmtTime } from "../utils";

// Small functions, every one of them on screen. A wrong byte count or a
// truncated AID is not a crash — it is a page that quietly says something
// untrue, which is the failure this project cares about most.

describe("shortAid", () => {
  it("keeps both ends, because that is what a person compares", () => {
    const aid = "bafyreiebzlsjonjvubmfeefjqulgfuzrvfg4lfcdnn3bdp7ekuvw2rrcuy";
    const short = shortAid(aid);
    expect(short.startsWith(aid.slice(0, 10))).toBe(true);
    expect(short.endsWith(aid.slice(-4))).toBe(true);
    // Two different AIDs must not shorten to the same string, or the page
    // shows one identity where there are two.
    const other = "bafyreiebzlsjonjvubmfeefjqulgfuzrvfg4lfcdnn3bdp7ekuvw2rrxyz";
    expect(shortAid(aid)).not.toBe(shortAid(other));
  });

  it("leaves a short id alone rather than padding it", () => {
    expect(shortAid("did:anet:a")).toBe("did:anet:a");
  });

  it("renders nothing for nothing", () => {
    expect(shortAid("")).toBe("");
  });
});

describe("fmtBytes", () => {
  it("uses the unit a reader expects at each scale", () => {
    expect(fmtBytes(0)).toBe("0 B");
    expect(fmtBytes(1023)).toBe("1023 B");
    expect(fmtBytes(1024)).toBe("1.0 KB");
    expect(fmtBytes(1024 * 1024)).toBe("1.0 MB");
    // The guest attachment cap, which is the number a reader most often
    // sees this function render.
    expect(fmtBytes(12 * 1024 * 1024)).toBe("12.0 MB");
  });

  it("does not render NaN at a reader", () => {
    expect(fmtBytes(NaN)).toBe("0 B");
    expect(fmtBytes(undefined as unknown as number)).toBe("0 B");
  });
});

describe("fmtTime", () => {
  it("renders nothing for a missing timestamp instead of the epoch", () => {
    // Zero is what an absent unix-millis field decodes to, and rendering
    // it would put "1970-01-01" on the page as if it meant something.
    expect(fmtTime(0)).toBe("");
    expect(fmtTime(undefined)).toBe("");
  });

  it("renders a real timestamp", () => {
    expect(fmtTime(1787418055000)).not.toBe("");
  });
});
