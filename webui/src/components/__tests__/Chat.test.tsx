import { describe, it, expect } from "vitest";
import { renderToStaticMarkup } from "react-dom/server";
import { Attachments } from "../ChatDialog";
import { sessionStatus, type GuestSession } from "../../lib/guest";
import type { GuestAtt } from "../../lib/api";

// The guest dialog is a stranger's first interaction with the network:
// no account, no client, a page and a quota. What it renders comes from
// an agent that stranger has never met, which makes this the one place
// on the site where untrusted bytes become markup.

function att(over: Partial<GuestAtt> = {}): GuestAtt {
  return { name: "report.png", mime: "image/png", size: 2048, data: "aGVsbG8=", ...over };
}

describe("Attachments", () => {
  it("renders nothing when there are none", () => {
    expect(renderToStaticMarkup(<Attachments />)).toBe("");
    expect(renderToStaticMarkup(<Attachments atts={[]} />)).toBe("");
  });

  it("shows an image inline with its name and size", () => {
    const html = renderToStaticMarkup(<Attachments atts={[att()]} />);
    expect(html).toContain("report.png");
    expect(html).toContain("<img");
    expect(html).toContain("data:image/png;base64,aGVsbG8=");
  });

  // A non-image is a download, not an inline render. Rendering an
  // arbitrary mime type inline is how a page starts executing what an
  // agent sent it.
  it("offers a non-image as a download", () => {
    const html = renderToStaticMarkup(
      <Attachments atts={[att({ name: "notes.pdf", mime: "application/pdf" })]} />,
    );
    expect(html).toContain("notes.pdf");
    expect(html).not.toContain("<img");
    expect(html).toContain("download");
  });

  // An attachment too large to inline arrives without data. It must
  // still be named — "there is a file you are not seeing" is the useful
  // fact — and must not become a link to nothing.
  it("names a file it could not inline, without linking to nothing", () => {
    const html = renderToStaticMarkup(
      <Attachments atts={[att({ name: "big.bin", mime: "application/octet-stream", data: undefined })]} />,
    );
    expect(html).toContain("big.bin");
    expect(html).toContain("装 anet");
    expect(html).not.toContain("href=\"\"");
  });

  // The mime type comes from the sender. A value crafted to break out of
  // the data: URI must not produce a script-bearing src.
  it("does not let a crafted mime type escape the data URI", () => {
    const html = renderToStaticMarkup(
      <Attachments atts={[att({ mime: "image/png\" onerror=\"alert(1)" })]} />,
    );
    expect(html).not.toContain("onerror=\"alert(1)\"");
  });

  // So does the filename.
  it("does not let a crafted filename inject markup", () => {
    const html = renderToStaticMarkup(
      <Attachments atts={[att({ name: "<script>alert(1)</script>" })]} />,
    );
    expect(html).not.toContain("<script>");
  });
});

describe("sessionStatus", () => {
  const s = (over: Partial<GuestSession> = {}): GuestSession =>
    ({ starting: false, done: false, remaining: 5, ...over }) as GuestSession;

  // A guest has a quota and has to be able to see it. "Still connecting"
  // and "you have used it all up" are different facts and a dialog that
  // shows the same thing for both leaves somebody waiting on a
  // conversation that is over.
  it("distinguishes connecting, remaining, and finished", () => {
    expect(sessionStatus(s({ starting: true }))).toContain("连接中");
    expect(sessionStatus(s({ remaining: 3 }))).toContain("3");
    expect(sessionStatus(s({ remaining: 0 }))).toContain("上限");
    expect(sessionStatus(s({ done: true }))).toContain("结束");
  });

  // Ended beats out-of-quota: a conversation the provider closed is over
  // regardless of how many messages the guest had left.
  it("reports an ended conversation as ended, not as out of quota", () => {
    expect(sessionStatus(s({ done: true, remaining: 0 }))).toContain("结束");
  });
});
