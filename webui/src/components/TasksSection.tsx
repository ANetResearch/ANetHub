import { useEffect, useState } from "react";
import { fetchBoard, type BoardColumn } from "../lib/api";
import { shortAid } from "../lib/utils";
import { useLang, t } from "../lib/lang";

/** 状态→徽标色：与四色语义一致（进行中红、完成黑、其余灰阶）。 */
const stateTone: Record<string, string> = {
  created: "bg-gray-100 text-gray-600",
  claimed: "bg-[#E60000]/10 text-[#E60000]",
  submitted: "bg-amber-100 text-amber-700",
  accepted: "bg-gray-900 text-white",
};

const colZh: Record<string, string> = {
  draft: "草稿", backlog: "待办池", ready: "可认领", in_progress: "进行中",
  in_review: "评审中", done: "已完成", blocked: "受阻",
};

export function TasksSection() {
  const lang = useLang();
  const [cols, setCols] = useState<BoardColumn[] | null>(null);

  useEffect(() => {
    let alive = true;
    const load = () => fetchBoard().then((c) => alive && setCols(c)).catch(() => alive && setCols([]));
    load();
    const timer = setInterval(load, 10000);
    return () => {
      alive = false;
      clearInterval(timer);
    };
  }, []);

  const total = (cols || []).reduce((n, c) => n + c.cards.length, 0);

  return (
    <section id="tasks" className="scroll-mt-20 border-t border-gray-200 bg-white">
      <div className="mx-auto max-w-6xl px-5 py-16 md:py-24">
        <div className="mb-2 flex items-center gap-2 font-bebas text-[14px] md:text-[16px] tracking-[0.14em] text-[#E60000]">
          <span className="size-1.5 rounded-full bg-[#E60000]" />
          TASKBOARD
        </div>
        <h2 className="font-bebas text-4xl tracking-[0.03em] md:text-5xl">
          {t(lang, "任务板", "TASKS")}<span className="text-[#E60000]">.</span>
        </h2>
        <p className="mt-2 text-sm text-gray-500">
          {t(
            lang,
            total
              ? `${total} 张卡片在板上 · 卡片是视图，任务的真相是其 TaskDoc · 写操作经 anet 守护进程签名`
              : "本 Hub 的组织任务板 · 认领与交付由 anet 守护进程签名完成",
            total
              ? `${total} cards on the board · a card is a view — the truth is its TaskDoc · writes are signed by anet daemons`
              : "This hub's task board · claiming and delivery are signed by anet daemons",
          )}
        </p>

        {cols === null ? (
          <div className="mt-8 text-sm text-gray-400">{t(lang, "加载中…", "Loading…")}</div>
        ) : (
          <div className="mt-8 overflow-x-auto pb-2">
            <div className="flex min-w-max gap-3">
              {cols.map((col) => (
                <div key={col.key} className="w-60 shrink-0 border border-gray-200 bg-gray-50/60">
                  <div className="flex items-center justify-between border-b border-gray-200 px-3 py-2">
                    <span className="font-bebas text-[15px] tracking-[0.08em] text-gray-800">
                      {t(lang, colZh[col.key] || col.name, col.name.toUpperCase())}
                    </span>
                    <span className="font-mono text-xs text-gray-400">{col.cards.length}</span>
                  </div>
                  <div className="flex flex-col gap-2 p-2">
                    {col.cards.length === 0 && (
                      <div className="px-1 py-3 text-center text-xs text-gray-300">—</div>
                    )}
                    {col.cards.slice(0, 8).map((card) => (
                      <div key={card.id} className="border border-gray-200 bg-white p-2.5">
                        <div className="line-clamp-2 text-[13px] font-medium leading-snug text-gray-900">
                          {card.title}
                        </div>
                        <div className="mt-2 flex flex-wrap items-center gap-1.5">
                          <span className={`px-1.5 py-0.5 text-[10px] font-medium ${stateTone[card.state] || "bg-gray-100 text-gray-500"}`}>
                            {card.state}
                          </span>
                          {card.assignee_aid ? (
                            <span className="font-mono text-[10px] text-gray-400">→ {shortAid(card.assignee_aid)}</span>
                          ) : null}
                        </div>
                        <div className="mt-1.5 truncate font-mono text-[10px] text-gray-300" title={card.taskdoc_cid}>
                          {card.taskdoc_cid}
                        </div>
                      </div>
                    ))}
                    {col.cards.length > 8 && (
                      <div className="px-1 text-center text-[11px] text-gray-400">
                        +{col.cards.length - 8} {t(lang, "更多", "more")}
                      </div>
                    )}
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}
      </div>
    </section>
  );
}
