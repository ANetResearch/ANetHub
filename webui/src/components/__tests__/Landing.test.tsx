import { describe, it, expect } from "vitest";
import { renderToStaticMarkup } from "react-dom/server";
import { capabilities } from "../Capabilities";
import { CapabilitiesSection } from "../Capabilities";
import { Header, navItems } from "../Header";

describe("landing structure", () => {
  it("lists the four capabilities in both languages", () => {
    for (const lang of ["zh", "en"] as const) {
      const c = capabilities(lang);
      expect(c.map((x) => x.id)).toEqual(["identity", "sealed", "a2a", "x402"]);
      c.forEach((x) => {
        expect(x.title.length).toBeGreaterThan(3);
        expect(x.body.length).toBeGreaterThan(20);
        expect(x.title + x.body).not.toMatch(/[!！?？]/);
      });
    }
    expect(capabilities("zh")[0].title).toBe("身份与密钥轮换");
    expect(capabilities("zh")[1].title).toBe("封闭发送与前向保密");
  });

  it("renders the overview as a landmark with a heading", () => {
    const html = renderToStaticMarkup(<CapabilitiesSection />);
    expect(html).toContain('id="network"');
    expect(html).toContain("aria-labelledby=\"network-title\"");
    expect(html.match(/<li /g)?.length).toBe(4);
  });

  it("navigates to network, agents, documentation and GitHub", () => {
    const ids = navItems(false).map((n) => n.id);
    expect(ids).toEqual(["network", "agents", "docs", "github"]);
    expect(navItems(true).map((n) => n.id)).toContain("tasks");
    navItems(false).filter((n) => n.external).forEach((n) => expect(n.href).toMatch(/^https:\/\//));
  });

  it("renders the drawer closed, with the toggle labelled", () => {
    const html = renderToStaticMarkup(<Header onJoin={() => {}} />);
    expect(html).toContain('aria-expanded="false"');
    expect(html).toContain('aria-controls="nav-drawer"');
    expect(html).toContain("hidden");
  });
});
