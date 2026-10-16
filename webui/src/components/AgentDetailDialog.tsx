import { useEffect, useState } from "react";
import { fetchAgent, type AgentView, type ReviewView } from "../lib/api";
import { renderMd } from "../lib/markdown";
import { shortAid, copyText } from "../lib/utils";
import { useLang, t } from "../lib/lang";
import { Dialog } from "./ui/dialog";
import { Avatar } from "./ui/avatar";
import { Icon } from "./Icon";
import { BadgeCheck, Check, Copy } from "../lib/icons";
import { Stars } from "./AgentsSection";

/** A UTC day number (days since 1970-01-01) as YYYY-MM-DD. Reviews are kept to the day only. */
export function fmtDay(day?: number): string {
  return day ? new Date(day * 86400000).toISOString().slice(0, 10) : "";
}

// Exported for tests. A review carries the rating, the comment, the receipt
// it is anchored on and the days of the receipt and of the review. It names no
// reviewer and no interaction: the hub keeps neither (evidence v2) and never
// receives the request or the deliverable (A2A-DESIGN §9). The hub verified
// the provider's signature on the receipt and the review's signature by the
// one-time key the receipt names; the verification line states exactly that.
export function Review({ r }: { r: ReviewView }) {
  const lang = useLang();
  return (
    <div className="card p-4">
      <div className="flex items-center justify-between gap-2">
        <Stars avg={r.rating} />
        {r.created_day ? <span className="num text-[12px] text-muted">{fmtDay(r.created_day)}</span> : null}
      </div>
      {r.comment && <p className="mt-2 text-[13px] leading-relaxed">{r.comment}</p>}
      {r.completed_day ? (
        <div className="num mt-3 border-t border-line pt-3 text-[12px] text-muted">
          {t(lang, "完成日期", "Completed")} {fmtDay(r.completed_day)}
        </div>
      ) : null}
      <div className="mt-3 flex items-center gap-1.5 text-[12px] text-accent-text">
        <Icon icon={BadgeCheck} size={14} />
        {t(lang, "双方签名已验证 · 回执", "Both signatures verified · receipt")} <span className="num">{shortAid(r.receipt_cid)}</span>
      </div>
    </div>
  );
}

/** Agent detail dialog: GET /agents/{aid} — profile and verifiable reviews. */
export function AgentDetailDialog({
  aid,
  onClose,
  toast,
}: {
  aid: string | null;
  onClose: () => void;
  toast: (msg: string, isErr?: boolean) => void;
}) {
  const lang = useLang();
  const [data, setData] = useState<{ agent: AgentView; reviews: ReviewView[] } | null>(null);
  const [err, setErr] = useState(false);
  const [copied, setCopied] = useState(false);

  useEffect(() => {
    setData(null);
    setErr(false);
    setCopied(false);
    if (!aid) return;
    let alive = true;
    fetchAgent(aid)
      .then((d) => alive && setData(d))
      .catch(() => alive && setErr(true));
    return () => {
      alive = false;
    };
  }, [aid]);

  const a = data?.agent;
  return (
    <Dialog open={!!aid} onClose={onClose} label={t(lang, "Agent 详情", "Agent details")} closeLabel={t(lang, "关闭", "Close")} className="max-w-2xl">
      {!data && !err && <div className="p-10 text-center text-sm text-muted">{t(lang, "正在加载。", "Loading.")}</div>}
      {err && <div className="p-10 text-center text-sm text-muted">{t(lang, "加载失败。稍后重试。", "Loading failed. Try again later.")}</div>}
      {a && (
        <>
          <div className="border-b border-line p-5 pr-14 md:p-6 md:pr-14">
            <div className="flex items-start gap-4">
              <Avatar name={a.name} className="size-12 text-xl" />
              <div className="min-w-0 flex-1">
                <div className="flex flex-wrap items-center gap-2">
                  <h3 className="text-xl font-semibold leading-tight">{a.name || shortAid(a.aid)}</h3>
                  <button
                    type="button"
                    className="btn min-h-[32px] px-2 text-[12px]"
                    onClick={async () => {
                      const ok = await copyText(a.aid);
                      setCopied(ok);
                      toast(ok ? t(lang, "已复制 AID。", "AID copied.") : t(lang, "复制失败。", "Copy failed."), !ok);
                      setTimeout(() => setCopied(false), 1600);
                    }}
                  >
                    <Icon icon={copied ? Check : Copy} size={14} />
                    {copied ? t(lang, "已复制", "Copied") : t(lang, "复制 AID", "Copy AID")}
                  </button>
                </div>
                <div className="mt-2 flex flex-wrap gap-1.5">
                  {(a.caps || []).map((c) => (
                    <span key={c} className="tag">
                      {c}
                    </span>
                  ))}
                </div>
                <div className="mt-3 flex items-baseline gap-2.5">
                  <span className="num text-3xl font-semibold leading-none">{a.review_count ? a.avg_rating.toFixed(1) : "–"}</span>
                  <span className="text-xs text-muted">
                    {a.review_count ? (
                      <>
                        <Stars avg={a.avg_rating} className="mr-1 align-middle" />
                        {t(lang, `${a.review_count} 条可核验评价`, `${a.review_count} verifiable reviews`)}
                      </>
                    ) : (
                      t(lang, "暂无评价", "No reviews")
                    )}
                  </span>
                </div>
              </div>
            </div>
          </div>

          <div className="thin-scroll flex-1 overflow-y-auto p-5 md:p-6">
            {a.summary && <p className="mb-3 text-[14px] leading-relaxed">{a.summary}</p>}
            {a.readme && (
              <div
                className="md mb-3 rounded-md border border-line bg-surface-2 p-4 text-[13px] leading-relaxed"
                dangerouslySetInnerHTML={{ __html: renderMd(a.readme) }}
              />
            )}

            <h4 className="mb-1 mt-6 text-[15px] font-semibold">{t(lang, "可核验评价", "Verifiable reviews")}</h4>
            <p className="mb-3 text-[12px] text-muted">
              {t(lang, "评价的签名与回执已验证，不含交互内容与评价人。", "Signatures and receipts are verified. Reviews contain no interaction content and no reviewer identity.")}
            </p>
            {data!.reviews.length ? (
              <div className="space-y-3">
                {data!.reviews.map((r, i) => (
                  <Review key={r.receipt_cid + i} r={r} />
                ))}
              </div>
            ) : (
              <p className="py-2 text-[13px] leading-relaxed text-muted">
                {t(lang, "暂无可信评价。评价须锚定一次双方签名的交互回执，Hub 验签通过后方可显示。", "No verified reviews. A review must be anchored on a receipt signed by both parties and is shown after the Hub verifies it.")}
              </p>
            )}
          </div>
        </>
      )}
    </Dialog>
  );
}
