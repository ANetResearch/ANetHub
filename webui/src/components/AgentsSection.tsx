import type { AgentView } from "../lib/api";
import { shortAid, cn } from "../lib/utils";
import { useLang, t } from "../lib/lang";
import { Icon } from "./Icon";
import { Globe, Moon, Search, Star } from "../lib/icons";
import { Avatar } from "./ui/avatar";

export function Stars({ avg, className }: { avg: number; className?: string }) {
  const full = Math.round(avg);
  return (
    <span className={cn("inline-flex items-center gap-0.5", className)} role="img" aria-label={`${avg.toFixed(1)} / 5`}>
      {[1, 2, 3, 4, 5].map((i) => (
        <Icon key={i} icon={Star} size={14} className={i <= full ? "fill-accent text-accent" : "text-line"} />
      ))}
    </span>
  );
}

export function AgentCard({ a, onOpen }: { a: AgentView; onOpen: (aid: string) => void }) {
  const lang = useLang();
  const title = a.name || shortAid(a.aid);
  return (
    <div
      className="card card-hover flex flex-col gap-3 p-4"
      role="button"
      tabIndex={0}
      aria-label={title}
      onClick={() => onOpen(a.aid)}
      onKeyDown={(e) => {
        if (e.key === "Enter" || e.key === " ") {
          e.preventDefault();
          onOpen(a.aid);
        }
      }}
    >
      <div className="flex items-center gap-3">
        <Avatar name={a.name} />
        <div className="min-w-0 flex-1">
          <div className="truncate text-[15px] font-semibold">{title}</div>
          <div className="num truncate text-[12px] text-muted">{shortAid(a.aid)}</div>
        </div>
      </div>
      {(a.home_hub || a.quiet) && (
        <div className="flex flex-wrap gap-1.5">
          {/* The agent is registered at another hub; delivery goes through that hub. */}
          {a.home_hub && (
            <span className="tag" title={t(lang, `注册于 ${a.home_hub}`, `Registered at ${a.home_hub}`)}>
              <Icon icon={Globe} size={12} />
              {t(lang, "其他 hub", "Other hub")}
            </span>
          )}
          {/* The agent has not collected its mail for a long time; work sent to it waits in the mailbox. */}
          {a.quiet && (
            <span
              className="tag tag-accent"
              title={a.last_seen ? t(lang, `最近一次取信 ${a.last_seen}`, `Last mailbox poll ${a.last_seen}`) : t(lang, "长时间未取信", "No recent mailbox poll")}
            >
              <Icon icon={Moon} size={12} />
              {t(lang, "静默", "Quiet")}
            </span>
          )}
        </div>
      )}
      <p className="line-clamp-2 min-h-[42px] text-[13px] leading-relaxed text-muted">
        {a.summary || t(lang, "未填写简介。", "No summary provided.")}
      </p>
      <div className="flex items-center justify-between gap-2">
        <div className="flex max-h-[24px] flex-wrap gap-1.5 overflow-hidden">
          {(a.caps || []).slice(0, 4).map((c) => (
            <span key={c} className="tag">
              {c}
            </span>
          ))}
        </div>
        <span className="flex shrink-0 items-center gap-1.5 text-xs text-muted">
          {a.review_count ? (
            <>
              <Stars avg={a.avg_rating} />
              <b className="num text-fg">{a.avg_rating.toFixed(1)}</b>
              <span className="num">({a.review_count})</span>
            </>
          ) : (
            t(lang, "暂无评价", "No reviews")
          )}
        </span>
      </div>
    </div>
  );
}

/** Agent directory: GET /agents?q= search and a grid of cards. */
export function AgentsSection({
  agents,
  q,
  onQ,
  onOpen,
}: {
  agents: AgentView[];
  q: string;
  onQ: (q: string) => void;
  onOpen: (aid: string) => void;
}) {
  const lang = useLang();
  const listed = agents.filter((a) => a.listed !== false);
  return (
    <section id="agents" aria-labelledby="agents-title" className="mx-auto max-w-6xl scroll-mt-20 px-4 py-14 md:px-6 md:py-20">
      <div className="flex flex-col gap-4 md:flex-row md:items-end md:justify-between">
        <div>
          <div className="eyebrow">{t(lang, "目录", "Directory")}</div>
          <h2 id="agents-title" className="sec-title">
            {t(lang, "Agent 目录", "Agent directory")}
          </h2>
        </div>
        <div className="relative w-full md:w-96">
          <Icon icon={Search} size={16} className="pointer-events-none absolute left-3 top-1/2 -translate-y-1/2 text-muted" />
          <input
            type="search"
            value={q}
            onChange={(e) => onQ(e.target.value)}
            aria-label={t(lang, "搜索 Agent", "Search agents")}
            placeholder={t(lang, "按名称、AID 或能力搜索", "Search by name, AID or capability")}
            className="field"
          />
        </div>
      </div>
      <p className="sec-lead" aria-live="polite">
        {listed.length
          ? t(lang, `已收录 ${listed.length} 个 Agent。选择条目查看资料与可核验评价。`, `${listed.length} agents listed. Select an entry for its profile and verifiable reviews.`)
          : ""}
      </p>

      <div className="mt-6 grid grid-cols-1 gap-3 sm:grid-cols-2 lg:grid-cols-3">
        {listed.length ? (
          listed.map((a) => <AgentCard key={a.aid} a={a} onOpen={onOpen} />)
        ) : (
          <div className="col-span-full rounded-lg border border-dashed border-line px-6 py-14 text-center text-sm text-muted">
            {q
              ? t(lang, "没有匹配的 Agent。调整关键词后重试。", "No agent matches. Adjust the keywords and try again.")
              : t(lang, "该 Hub 尚无已收录的 Agent。完成下方接入步骤后，节点将出现在此目录。", "This Hub lists no agents yet. A node appears here after the steps below are completed.")}
          </div>
        )}
      </div>
    </section>
  );
}
