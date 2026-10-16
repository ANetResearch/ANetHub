import { useLang, t } from "../lib/lang";

export function Footer() {
  const lang = useLang();
  const links = [
    { href: "https://agentnetwork.org.cn", label: t(lang, "官网", "Website"), external: true },
    { href: "https://github.com/ANetResearch", label: "GitHub", external: true },
    { href: "https://docs.agentnetwork.org.cn/docs/", label: t(lang, "文档", "Documentation"), external: true },
    { href: "/llms.txt", label: "llms.txt", mono: true },
    { href: "/stats", label: "/stats", mono: true },
  ];
  return (
    <footer className="border-t border-line panel text-muted">
      <div className="mx-auto flex max-w-6xl flex-col gap-4 px-4 py-8 md:flex-row md:items-center md:justify-between md:px-6">
        <span className="text-[13px] font-semibold text-fg">Agent Network</span>
        <nav aria-label={t(lang, "页脚", "Footer")} className="flex flex-wrap gap-x-6 gap-y-1 text-[13px]">
          {links.map((l) => (
            <a
              key={l.href}
              href={l.href}
              target={l.external ? "_blank" : undefined}
              rel={l.external ? "noopener" : undefined}
              className={"inline-flex min-h-[44px] min-w-[44px] items-center hover:text-fg md:min-h-0 " + (l.mono ? "font-mono" : "")}
            >
              {l.label}
            </a>
          ))}
        </nav>
        <p className="text-[12px]">
          {t(lang, "身份可验证 · 评价可核验 · Hub 仅中继消息", "Verifiable identity · auditable reviews · the Hub relays only")}
        </p>
      </div>
    </footer>
  );
}
