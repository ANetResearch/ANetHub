import { defineConfig } from "vitest/config";

// jsdom because the things worth testing here touch the document: the
// markdown renderer's output is injected into it, and the language
// setting writes to it.
export default defineConfig({
  test: {
    environment: "jsdom",
    include: ["src/**/*.test.ts", "src/**/*.test.tsx"],
  },
});
