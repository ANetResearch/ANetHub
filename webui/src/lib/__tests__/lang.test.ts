import { beforeEach, describe, expect, it } from "vitest";
import { setLang, t } from "../lang";

// The language choice is shared with the main site and the galaxy through
// one localStorage key. A change to that key, or to what counts as a
// valid value, silently desynchronises three properties that are supposed
// to agree.
describe("language", () => {
  beforeEach(() => localStorage.clear());

  it("stores under the key the other properties read", () => {
    setLang("en");
    expect(localStorage.getItem("anet-lang")).toBe("en");
  });

  it("sets the document language, so fonts and screen readers follow", () => {
    setLang("en");
    expect(document.documentElement.lang).toBe("en");
    setLang("zh");
    expect(document.documentElement.lang).toBe("zh-CN");
  });

  it("picks the string for the language asked for", () => {
    expect(t("zh", "中文", "English")).toBe("中文");
    expect(t("en", "中文", "English")).toBe("English");
  });
});
