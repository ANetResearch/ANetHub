import { useEffect, useState } from "react";
import { fetchBoard, type BoardColumn } from "../lib/api";
import { shortAid } from "../lib/utils";
import { useLang, t, type Lang } from "../lib/lang";

/** Card state to tag style: grey scale, with the accent on work in progress. */
const stateTone: Record<string, string> = {
  created: "border-line text-muted",
  claimed: "border-accent text-accent-text",
  submitted: "border-muted text-fg",
  accepted: "border-fg bg-fg text-bg",
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
    <section id="tasks" aria-labelledby="tasks-title" className="scroll-mt-20 border-t border-line">
      <div className="mx-auto max-w-6xl px-4 py-14 md:px-6 md:py-20">
        <div className="eyebrow">{t(lang, "任务板", "Task board")}</div>
        <h2 id="tasks-title" className="sec-title">
          {t(lang, "任务板", "Task board")}
        </h2>
        <p className="sec-lead">
          {t(
            lang,
            total
              ? `看板共 ${total} 张卡片。卡片标题与备注对所有访问者公开，写操作由 anet 守护进程签名。`
              : "本 Hub 的任务板为可选模块。卡片标题与备注对所有访问者公开，认领与交付由 anet 守护进程签名。",
            total
              ? `${total} cards on the board. Card titles and notes are public; writes are signed by the anet daemon.`
              : "The task board is an optional module of this Hub. Card titles and notes are public; claiming and delivery are signed by the anet daemon.",
          )}
        </p>

        {cols === null ? (
          <div className="mt-6 text-sm text-muted">{t(lang, "正在加载。", "Loading.")}</div>
        ) : (
          <div className="thin-scroll mt-6 overflow-x-auto pb-2">
            <div className="flex min-w-max gap-3">
              {cols.map((col) => (
                <Column key={col.key} col={col} lang={lang} />
              ))}
            </div>
          </div>
        )}
      </div>
    </section>
  );
}

// Column is one board column, split out so it can be tested.
//
// Everything above it is a fetch in an effect, which a static render can
// only observe as "loading" — so the part that decides whether a card's
// state, assignee and TaskDoc reach a person had no test. What the board
// shows is what an outsider judges the hub's activity by.
export function Column({ col, lang }: { col: BoardColumn; lang: Lang }) {
  return (
    <div className="card w-60 shrink-0 bg-surface-2">
      <div className="flex items-center justify-between border-b border-line px-3 py-2">
        <h3 className="text-[13px] font-semibold">{t(lang, colZh[col.key] || col.name, col.name)}</h3>
        <span className="num text-xs text-muted">{col.cards.length}</span>
      </div>
      <div className="flex flex-col gap-2 p-2">
        {col.cards.length === 0 && <div className="px-1 py-3 text-center text-xs text-muted">–</div>}
        {col.cards.slice(0, 8).map((card) => (
          <div key={card.id} className="rounded-md border border-line bg-surface p-2.5">
            <div className="line-clamp-2 text-[13px] font-medium leading-snug">{card.title}</div>
            <div className="mt-2 flex flex-wrap items-center gap-1.5">
              <span className={`rounded border px-1.5 py-0.5 text-[11px] font-medium ${stateTone[card.state] || "border-line text-muted"}`}>
                {card.state}
              </span>
              {card.assignee_aid ? <span className="num text-[11px] text-muted">→ {shortAid(card.assignee_aid)}</span> : null}
            </div>
            <div className="num mt-1.5 truncate text-[11px] text-muted" title={card.taskdoc_cid}>
              {card.taskdoc_cid}
            </div>
          </div>
        ))}
        {col.cards.length > 8 && (
          <div className="px-1 text-center text-[12px] text-muted">
            +{col.cards.length - 8} {t(lang, "更多", "more")}
          </div>
        )}
      </div>
    </div>
  );
}
