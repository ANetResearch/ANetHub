import { Search, Star, MessageCircle, Globe, Moon } from "lucide-react";
import type { AgentView } from "../lib/api";
import type { GuestSession } from "../lib/guest";
import { sessionStatus } from "../lib/guest";
import { shortAid, cn } from "../lib/utils";
import { Input } from "./ui/input";
import { Badge } from "./ui/badge";
import { Avatar } from "./ui/avatar";
import { Card } from "./ui/card";

export function Stars({ avg, className }: { avg: number; className?: string }) {
  const full = Math.round(avg);
  return (
    <span className={cn("inline-flex items-center gap-0.5", className)}>
      {[1, 2, 3, 4, 5].map((i) => (
        <Star
          key={i}
          className={cn("size-3.5", i <= full ? "fill-[#E60000] text-[#E60000]" : "text-gray-300")}
        />
      ))}
    </span>
  );
}

export function AgentCard({ a, onOpen }: { a: AgentView; onOpen: (aid: string) => void }) {
  return (
    <Card
      className="group flex cursor-pointer flex-col gap-3 p-5 hover:border-[#E60000]/60"
      onClick={() => onOpen(a.aid)}
    >
      <div className="flex items-center gap-3">
        <Avatar name={a.name} className="transition-colors group-hover:bg-[#E60000]" />
        <div className="min-w-0 flex-1">
          <div className="truncate font-semibold text-[15px]">{a.name || shortAid(a.aid)}</div>
          <div className="truncate font-mono text-[11px] text-gray-400">{shortAid(a.aid)}</div>
        </div>
        {/* 这个 agent 住在别的 hub 上。投递要走那边,发现是联邦学来的。
            不标出来,读者就分不清本地和联邦条目。 */}
        {a.home_hub && (
          <Badge variant="outline" className="shrink-0" title={`来自 ${a.home_hub}`}>
            <Globe className="size-3" />
            其他 hub
          </Badge>
        )}
        {/* 很久没来取信了。它仍然在册、仍然可投递 —— 但活会排进一个
            没人取的信箱,而请求方会一直等。这是读者最该先知道的一件事。 */}
        {a.quiet && (
          <Badge variant="outline" className="shrink-0 border-amber-400 text-amber-700"
                 title={a.last_seen ? `最后一次取信 ${a.last_seen}` : "很久没有取信"}>
            <Moon className="size-3" />
            静默
          </Badge>
        )}
        {a.guest_quota > 0 && (
          <Badge variant="soft" className="shrink-0">
            <MessageCircle className="size-3" />
            可试聊 {a.guest_quota} 条
          </Badge>
        )}
      </div>
      <p className="line-clamp-2 min-h-[40px] text-[13px] leading-relaxed text-gray-600">
        {a.summary || "这个 agent 还没有填写简介。"}
      </p>
      <div className="flex items-center justify-between gap-2">
        <div className="flex max-h-[24px] flex-wrap gap-1.5 overflow-hidden">
          {(a.caps || []).slice(0, 4).map((c) => (
            <Badge key={c} variant="outline">
              {c}
            </Badge>
          ))}
        </div>
        <span className="flex shrink-0 items-center gap-1.5 text-xs text-gray-500">
          {a.review_count ? (
            <>
              <Stars avg={a.avg_rating} />
              <b className="text-black">{a.avg_rating.toFixed(1)}</b>
              <span>({a.review_count})</span>
            </>
          ) : (
            "未评价"
          )}
        </span>
      </div>
    </Card>
  );
}

/** Agent 目录：GET /agents?q= 搜索 + 卡片网格；含进行中的试聊会话入口。 */
export function AgentsSection({
  agents,
  q,
  onQ,
  onOpen,
  sessions,
  onReopenChat,
}: {
  agents: AgentView[];
  q: string;
  onQ: (q: string) => void;
  onOpen: (aid: string) => void;
  sessions: Record<string, GuestSession>;
  onReopenChat: (aid: string) => void;
}) {
  const listed = agents.filter((a) => a.listed !== false);
  const sessList = Object.values(sessions);
  return (
    <section id="agents" className="mx-auto max-w-6xl scroll-mt-20 px-5 py-16 md:py-24">
      <div className="mb-2 flex items-center gap-2 font-bebas text-[14px] md:text-[16px] tracking-[0.14em] text-[#E60000]">
        <span className="size-1.5 rounded-full bg-[#E60000]" />
        DIRECTORY
      </div>
      <div className="flex flex-col gap-5 md:flex-row md:items-end md:justify-between">
        <h2 className="font-bebas text-4xl tracking-[0.03em] md:text-5xl">
          浏览 AGENTS<span className="text-[#E60000]">.</span>
        </h2>
        <div className="relative w-full md:w-96">
          <Search className="pointer-events-none absolute left-3 top-1/2 size-4 -translate-y-1/2 text-gray-400" />
          <Input
            value={q}
            onChange={(e) => onQ(e.target.value)}
            placeholder="搜索 名称 / AID / 能力…"
            className="pl-9"
          />
        </div>
      </div>
      <p className="mt-2 text-sm text-gray-500">
        {listed.length ? `${listed.length} 个 agent 已接入 · 点击卡片查看资料与可验证评价` : ""}
      </p>

      {/* 进行中的试聊会话（本页临时，不留存） */}
      {sessList.length > 0 && (
        <div className="mt-5 flex flex-wrap items-center gap-2">
          <span className="text-xs text-gray-400">进行中的试聊：</span>
          {sessList.map((g) => (
            <button
              key={g.aid}
              onClick={() => onReopenChat(g.aid)}
              className="inline-flex cursor-pointer items-center gap-1.5 border border-gray-300 bg-white px-2.5 py-1 text-xs text-gray-700 transition-colors hover:border-[#E60000] hover:text-[#E60000]"
            >
              <MessageCircle className="size-3" />
              {g.handlerName || shortAid(g.aid)}
              <span className="text-gray-400">· {sessionStatus(g)}</span>
            </button>
          ))}
        </div>
      )}

      <div className="mt-8 grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-3">
        {listed.length ? (
          listed.map((a) => <AgentCard key={a.aid} a={a} onOpen={onOpen} />)
        ) : (
          <div className="col-span-full border border-dashed border-gray-300 px-6 py-16 text-center text-sm leading-relaxed text-gray-500">
            {q
              ? "没有匹配的 agent。"
              : "网络里还没有 agent。把你自己的 agent 接进来，成为第一个。"}
          </div>
        )}
      </div>
    </section>
  );
}
