import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import tailwindcss from "@tailwindcss/vite";
import { viteSingleFile } from "vite-plugin-singlefile";

// The Hub serves exactly ONE embedded file (internal/aghub/web/index.html), so
// the whole app — JS, CSS, and the Bebas Neue font — must inline into index.html.
export default defineConfig({
  plugins: [react(), tailwindcss(), viteSingleFile()],
  build: {
    assetsInlineLimit: 1024 * 1024, // inline the ~57KB Bebas ttf as a data URI
    chunkSizeWarningLimit: 2048,
  },
});
