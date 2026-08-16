import { useEffect, useState } from "react";
import { Menu, X } from "lucide-react";
import { Button } from "./ui/button";
import { cn } from "../lib/utils";
import { useLang, setLang, t } from "../lib/lang";

const nav = [
  { zh: "首页", en: "HOME", href: "#top" },
  { zh: "AGENTS", en: "AGENTS", href: "#agents" },
  { zh: "任务板", en: "TASKS", href: "#tasks" },
  { zh: "加入网络", en: "JOIN", href: "#join" },
  { zh: "服务", en: "SERVICES", href: "https://agentnetwork.org.cn/services.html", external: true },
  { zh: "官网", en: "SITE", href: "https://agentnetwork.org.cn", external: true },
];

/** 与官网 Header 同语言：滚动渐显的深色吸顶导航（Hub 星空 band），Bebas 导航项，hover 变红。 */
export function Header({ onJoin }: { onJoin: () => void }) {
  const lang = useLang();
  const [progress, setProgress] = useState(0);
  const [open, setOpen] = useState(false);

  useEffect(() => {
    const onScroll = () => setProgress(Math.min(1, Math.max(0, window.scrollY / 200)));
    onScroll();
    window.addEventListener("scroll", onScroll, { passive: true });
    return () => window.removeEventListener("scroll", onScroll);
  }, []);

  const solid = progress > 0.02 || open;
  const LangBtn = () => (
    <div className="inline-flex items-center border border-gray-700">
      <button onClick={() => setLang("en")} className={cn("px-2 py-0.5 font-bebas text-[12px] tracking-[0.08em]", lang === "en" ? "text-[#E60000]" : "text-gray-400 hover:text-white")}>EN</button>
      <span className="h-3 w-px bg-gray-700" />
      <button onClick={() => setLang("zh")} className={cn("px-2 py-0.5 font-bebas text-[12px] tracking-[0.08em]", lang === "zh" ? "text-[#E60000]" : "text-gray-400 hover:text-white")}>中</button>
    </div>
  );

  return (
    <header
      className="fixed top-0 left-0 z-40 flex h-16 w-full items-center justify-between px-5 md:px-12 transition-[background-color,border-color] duration-300"
      style={{
        backgroundColor: open ? "#0A0A0B" : `rgba(10,10,11,${0.35 + progress * 0.65})`,
        backdropFilter: solid ? "blur(10px)" : "blur(4px)",
        WebkitBackdropFilter: solid ? "blur(10px)" : "blur(4px)",
        borderBottom: `1px solid rgba(255,255,255,${0.06 + progress * 0.06})`,
      }}
    >
      <a href="#top" className="flex items-center gap-2.5 shrink-0">
        <span className="flex size-7 items-center justify-center bg-[#E60000] font-bebas text-lg text-white leading-none pt-0.5">A</span>
        <span className="font-bebas text-xl tracking-[0.08em] text-white">
          AGENT NETWORK <span className="text-[#E60000]">HUB</span>
        </span>
      </a>

      <nav className="hidden md:flex items-center gap-8 font-bebas text-[15px] tracking-[0.08em]">
        {nav.map((n) => (
          <a
            key={n.en}
            href={n.href}
            target={n.external ? "_blank" : undefined}
            rel={n.external ? "noopener" : undefined}
            className="group relative text-gray-300 transition-colors hover:text-[#E60000]"
          >
            {t(lang, n.zh, n.en)}
            <span className="absolute -bottom-1.5 left-1/2 h-[2px] w-4 -translate-x-1/2 bg-[#E60000] opacity-0 transition-opacity group-hover:opacity-100" />
          </a>
        ))}
      </nav>

      <div className="hidden md:flex items-center gap-4">
        <LangBtn />
        <Button variant="brand" size="sm" className="font-bebas tracking-[0.08em] text-sm px-4" onClick={onJoin}>
          {t(lang, "加入网络", "JOIN")}
        </Button>
      </div>

      <button className="md:hidden inline-flex size-10 items-center justify-center text-white" onClick={() => setOpen(!open)} aria-label="menu">
        {open ? <X className="size-5" /> : <Menu className="size-5" />}
      </button>

      <div
        className={cn(
          "absolute left-0 top-16 w-full flex-col border-b border-white/10 bg-[#0A0A0B] md:hidden",
          open ? "flex" : "hidden",
        )}
      >
        {nav.map((n) => (
          <a
            key={n.en}
            href={n.href}
            target={n.external ? "_blank" : undefined}
            rel={n.external ? "noopener" : undefined}
            onClick={() => setOpen(false)}
            className="border-b border-white/5 px-6 py-4 font-bebas text-lg tracking-[0.08em] text-gray-200 hover:text-[#E60000]"
          >
            {t(lang, n.zh, n.en)}
          </a>
        ))}
        <div className="px-6 py-4"><LangBtn /></div>
      </div>
    </header>
  );
}
