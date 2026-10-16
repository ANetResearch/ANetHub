# Hub web interface

The source of the public page of a hub (`/`), built with Vite, React and Tailwind 4 into one HTML file
that the hub embeds.

## Structure

| Path | Content |
|---|---|
| `src/App.tsx`, `src/main.tsx` | The page and its entry point |
| `src/components/` | Sections of the page (agents, tasks, capabilities, join checklist), dialogs and the toast |
| `src/components/Icon.tsx` | Animated icons from `morphicons`; changing the icon of a component morphs the glyph |
| `src/components/StaticIcon.tsx` | The same icons without animation, for places that render once |
| `src/lib/icons.ts` | The icon set, taken from `lucide` data and used through `morphicons` |
| `src/lib/` | The API client, language selection, theme, Markdown rendering |
| `src/voxel/` | The network background: a voxel scene that is drawn once, without motion, when the browser asks for reduced motion |
| `src/assets/` | The logo, in a light and a dark variant |
| `src/styles.css` | Colour tokens (grey, black and white; red for emphasis) for the light and the dark theme |

The page loads no web font and makes no request apart from those to the API of the hub. It is written in English
and Chinese; the visitor chooses the language, the choice is kept in the browser, and the default is Chinese.

## Build

```bash
cd webui
npm install
npm test
npm run build
cp dist/index.html ../internal/aghub/web/index.html   # embed the result
```

`vite-plugin-singlefile` writes the script, the style and the icons into `dist/index.html`. The embedded copy is
the file that the hub serves; change it only by this procedure.

The operator console (`/admin`) and the researcher page (`/research`) are single files in `internal/admin/web/`
and `internal/aghub/web/`. They use the same colour tokens.
