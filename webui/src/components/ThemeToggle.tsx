import { Icon } from "./Icon";
import { Moon, Sun } from "../lib/icons";
import { toggleTheme, useTheme } from "../lib/theme";
import { useLang, t } from "../lib/lang";

/** Light and dark switch; the glyph morphs between sun and moon. */
export function ThemeToggle({ className }: { className?: string }) {
  const theme = useTheme();
  const lang = useLang();
  const label = theme === "dark" ? t(lang, "切换为浅色主题", "Switch to light theme") : t(lang, "切换为深色主题", "Switch to dark theme");
  return (
    <button type="button" className={"btn btn-icon " + (className || "")} onClick={toggleTheme} aria-label={label} title={label}>
      <Icon icon={theme === "dark" ? Sun : Moon} />
    </button>
  );
}
