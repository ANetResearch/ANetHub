import { describe, expect, it } from "vitest";
import { esc, renderMd } from "../markdown";

// This renderer's output goes through dangerouslySetInnerHTML, and its
// input is prose an agent wrote about itself. Anyone can register and
// write anything, so every one of these is something a stranger can put
// into the page that everyone else reads while deciding who to trust.
describe("markdown escaping", () => {
  it("escapes the characters that end a tag or an attribute", () => {
    expect(esc(`<script>`)).toBe("&lt;script&gt;");
    expect(esc(`" onload="x`)).toBe("&quot; onload=&quot;x");
    expect(esc(`a & b`)).toBe("a &amp; b");
  });

  it("does not let a readme open a tag", () => {
    const html = renderMd(`<script>alert(1)</script>`);
    expect(html).not.toContain("<script>");
    expect(html).toContain("&lt;script&gt;");
  });

  it("does not let a heading smuggle markup", () => {
    const html = renderMd(`# <img src=x onerror=alert(1)>`);
    expect(html).not.toContain("<img");
    expect(html).toContain("&lt;img");
  });

  it("keeps a fenced block inert", () => {
    const html = renderMd("```\n<script>alert(1)</script>\n```");
    expect(html).not.toContain("<script>");
    expect(html).toContain("&lt;script&gt;");
  });

  it("only links http and https", () => {
    // The link rule matches an absolute http(s) URL and nothing else, so
    // a javascript: target never becomes an href.
    // The link rule matches an absolute http(s) URL and nothing else, so
    // a javascript: target is never turned into a link at all. It stays
    // as escaped text, which is harmless and is the point: not linking it
    // is the protection, not hiding the word.
    const js = renderMd(`[click](javascript:alert(1))`);
    expect(js).not.toContain("href=");
    expect(js).not.toContain("<a ");

    const ok = renderMd(`[docs](https://example.org/x)`);
    expect(ok).toContain(`href="https://example.org/x"`);
    // An external link must not hand the opener over.
    expect(ok).toContain(`rel="noopener"`);
  });

  it("does not let a link label carry markup", () => {
    const html = renderMd(`[<img src=x onerror=alert(1)>](https://example.org)`);
    expect(html).not.toContain("<img");
  });

  it("escapes inside emphasis and code spans", () => {
    expect(renderMd("**<b>bold</b>**")).not.toContain("<b>");
    expect(renderMd("`<i>x</i>`")).not.toContain("<i>x</i>");
  });
});

describe("markdown rendering", () => {
  it("renders headings at the level asked for", () => {
    expect(renderMd("## Title")).toContain("<h2>Title</h2>");
    expect(renderMd("###### Six")).toContain("<h6>Six</h6>");
    // Seven hashes is not a heading at all — CommonMark stops at six, and
    // so does this. It becomes a paragraph, which is the right answer
    // rather than a clamped h6.
    expect(renderMd("####### Deep")).toContain("<p>####### Deep</p>");
  });

  it("renders a fenced block as preformatted text", () => {
    expect(renderMd("```\nanet up\n```")).toContain(`<pre class="mdpre">anet up</pre>`);
  });

  it("handles CRLF, because a readme may come from anywhere", () => {
    expect(renderMd("# A\r\n\r\n# B")).toContain("<h1>A</h1>");
  });

  it("survives an empty document", () => {
    expect(renderMd("")).toBe("");
  });
});
