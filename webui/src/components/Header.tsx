import { useEffect, useRef, useState } from "react";
import { Icon } from "./Icon";
import { Menu, X } from "../lib/icons";
import { ThemeToggle } from "./ThemeToggle";
import { useLang, setLang, t, type Lang } from "../lib/lang";
import logoLight from "../assets/anet-logo.svg";
import logoDark from "../assets/anet-logo-dark.svg";

export const DOCS_URL = "https://docs.agentnetwork.org.cn/docs/";
export const GITHUB_URL = "https://github.com/ANetResearch";

interface NavItem {
  id: string;
  zh: string;
  en: string;
  href: string;
  external?: boolean;
}

/** navItems lists the header navigation. The task board entry exists only when the Hub was built with that module. */
export function navItems(showTasks: boolean): NavItem[] {
  const items: NavItem[] = [
    { id: "network", zh: "网络", en: "Network", href: "#network" },
    { id: "agents", zh: "Agents", en: "Agents", href: "#agents" },
  ];
  if (showTasks) items.push({ id: "tasks", zh: "任务板", en: "Task board", href: "#tasks" });
  items.push(
    { id: "docs", zh: "文档", en: "Documentation", href: DOCS_URL, external: true },
    { id: "github", zh: "GitHub", en: "GitHub", href: GITHUB_URL, external: true },
  );
  return items;
}

export function Logo() {
  return (
    <a href="#top" className="logo" aria-label="Agent Network">
      <img className="logo-light" src={logoLight} alt="Agent Network" width="140" height="24" />
      <img className="logo-dark" src={logoDark} alt="" aria-hidden="true" width="140" height="24" />
    </a>
  );
}

function LangToggle() {
  const lang = useLang();
  const next: Lang = lang === "zh" ? "en" : "zh";
  return (
    <button
      type="button"
      className="btn tap"
      lang={next === "zh" ? "zh-CN" : "en"}
      aria-label={next === "zh" ? "中文，切换为中文界面" : "EN, switch to the English interface"}
      title={t(lang, "English", "中文")}
      onClick={() => setLang(next)}
    >
      {next === "zh" ? "中文" : "EN"}
    </button>
  );
}

/**
 * Header: logo, navigation, language and theme. Below 768 px the navigation
 * moves into a drawer that traps focus and closes on Escape.
 */
export function Header({ onJoin, showTasks = false }: { onJoin?: () => void; showTasks?: boolean }) {
  const lang = useLang();
  const items = navItems(showTasks);
  const [open, setOpen] = useState(false);
  const drawer = useRef<HTMLDivElement>(null);
  const opener = useRef<HTMLButtonElement>(null);

  useEffect(() => {
    if (!open) return;
    const root = drawer.current;
    const focusable = () =>
      Array.from(root?.querySelectorAll<HTMLElement>("a[href], button:not([disabled])") ?? []);
    focusable()[0]?.focus();
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") {
        setOpen(false);
        opener.current?.focus();
        return;
      }
      if (e.key !== "Tab") return;
      const f = focusable();
      if (!f.length) return;
      const first = f[0];
      const last = f[f.length - 1];
      if (e.shiftKey && document.activeElement === first) {
        e.preventDefault();
        last.focus();
      } else if (!e.shiftKey && document.activeElement === last) {
        e.preventDefault();
        first.focus();
      }
    };
    document.addEventListener("keydown", onKey);
    const prev = document.body.style.overflow;
    document.body.style.overflow = "hidden";
    return () => {
      document.removeEventListener("keydown", onKey);
      document.body.style.overflow = prev;
    };
  }, [open]);

  const link = (n: NavItem, onClick?: () => void) => (
    <a
      key={n.id}
      href={n.href}
      target={n.external ? "_blank" : undefined}
      rel={n.external ? "noopener" : undefined}
      onClick={onClick}
    >
      {t(lang, n.zh, n.en)}
    </a>
  );

  return (
    <>
    <header className="site-header">
      <div className="site-header-in">
        <Logo />
        <nav className="nav-desktop" aria-label={t(lang, "主导航", "Primary")}>
          {items.map((n) => link(n))}
        </nav>
        <div className="header-tools">
          <LangToggle />
          <ThemeToggle className="tap" />
          <button
            ref={opener}
            type="button"
            className="btn btn-icon tap nav-toggle"
            aria-label={open ? t(lang, "关闭导航", "Close navigation") : t(lang, "打开导航", "Open navigation")}
            aria-expanded={open}
            aria-controls="nav-drawer"
            onClick={() => setOpen(!open)}
          >
            <Icon icon={open ? X : Menu} size={20} />
          </button>
        </div>
      </div>
    </header>
      {open && <div className="drawer-scrim" onClick={() => setOpen(false)} />}
      <div
        id="nav-drawer"
        ref={drawer}
        className={"drawer" + (open ? " drawer-open" : "")}
        role="dialog"
        aria-modal="true"
        aria-label={t(lang, "导航", "Navigation")}
        hidden={!open}
      >
        <nav aria-label={t(lang, "移动端导航", "Mobile")}>
          {items.map((n) => link(n, () => setOpen(false)))}
          {onJoin && (
            <button
              type="button"
              className="btn btn-primary tap"
              onClick={() => {
                setOpen(false);
                onJoin();
              }}
            >
              {t(lang, "接入网络", "Join the network")}
            </button>
          )}
        </nav>
      </div>
    </>
  );
}
