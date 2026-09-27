import { useEffect, useState } from "react";
import { BadgeCheck, Copy, Check } from "lucide-react";
import { fetchAgent, type AgentView, type ReviewView } from "../lib/api";
import { renderMd } from "../lib/markdown";
import { shortAid, fmtTime, copyText } from "../lib/utils";
import { Dialog } from "./ui/dialog";
import { Badge } from "./ui/badge";
import { Avatar } from "./ui/avatar";
import { Stars } from "./AgentsSection";

/** 内容绑定的状态文字。hub 不持有交互内容,无法核对回执里的 request_cid / result_cid
 *  是否对应某份内容;"未核对"必须如实显示,不得显示成"已验证"。 */
export function contentBindingLabel(state: string | undefined): string {
  if (state === "UNVERIFIED" || !state) return "内容绑定未核对（hub 不持有交互内容）";
  return "内容绑定：" + state;
}

// Exported for tests. What a review looks like on screen is where the
// evidence surface either reaches a person or does not.
//
// A review carries the rating, the reviewer's comment and the receipt it
// is anchored on. It carries no request and no deliverable: the hub never
// receives them (A2A-DESIGN §9), so there is nothing to show and nothing
// the hub could have checked. The two signatures and their interlock are
// what the hub verified, and that is what the green line says.
export function Review({ r }: { r: ReviewView }) {
  return (
    <div className="border border-gray-200 bg-white p-4">
      <div className="flex items-center justify-between gap-2">
        <Stars avg={r.rating} />
        <span className="font-mono text-[11px] text-gray-400">by {shortAid(r.reviewer_aid)}</span>
      </div>
      {r.comment && <p className="mt-2 text-[13px] italic leading-relaxed text-gray-800">“{r.comment}”</p>}
      <div className="mt-3 space-y-0.5 border-t border-dashed border-gray-200 pt-3 font-mono text-[10px] leading-relaxed text-gray-400">
        {r.request_cid && (
          <div className="truncate">
            <b className="text-gray-500">request_cid</b> {r.request_cid}
          </div>
        )}
        {r.result_cid && (
          <div className="truncate">
            <b className="text-gray-500">result_cid</b> {r.result_cid}
          </div>
        )}
        {r.completed_at ? (
          <div>
            <b className="text-gray-500">completed</b> {fmtTime(r.completed_at)}
          </div>
        ) : null}
        <div className="font-body text-[11px] text-gray-500">{contentBindingLabel(r.content_binding)}</div>
      </div>
      <div className="mt-3 flex items-center gap-1.5 text-[11px] text-[#E60000]">
        <BadgeCheck className="size-3.5" />
        双方签名已验证 · 回执 {shortAid(r.receipt_cid)}
        {r.created_at ? <span className="text-gray-400"> · {fmtTime(r.created_at)}</span> : null}
      </div>
    </div>
  );
}

/** Agent 详情弹窗：GET /agents/{aid} —— 资料 + 可验证评价列表。 */
export function AgentDetailDialog({
  aid,
  onClose,
  toast,
}: {
  aid: string | null;
  onClose: () => void;
  toast: (msg: string, isErr?: boolean) => void;
}) {
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
    <Dialog open={!!aid} onClose={onClose} className="max-w-2xl">
      {!data && !err && (
        <div className="p-10 text-center text-sm text-gray-400">加载中…</div>
      )}
      {err && <div className="p-10 text-center text-sm text-gray-400">加载失败，请稍后再试。</div>}
      {a && (
        <>
          <div className="border-b border-gray-200 p-6 pr-14">
            <div className="flex items-start gap-4">
              <Avatar name={a.name} className="size-12 text-xl" />
              <div className="min-w-0 flex-1">
                <div className="flex flex-wrap items-center gap-2">
                  <h3 className="text-xl font-bold leading-tight">{a.name || shortAid(a.aid)}</h3>
                  <button
                    className="inline-flex cursor-pointer items-center gap-1 border border-gray-300 px-2 py-0.5 text-[11px] text-gray-500 transition-colors hover:border-[#E60000] hover:text-[#E60000]"
                    onClick={async () => {
                      const ok = await copyText(a.aid);
                      setCopied(ok);
                      toast(ok ? "已复制 AID" : "复制失败", !ok);
                      setTimeout(() => setCopied(false), 1600);
                    }}
                  >
                    {copied ? <Check className="size-3" /> : <Copy className="size-3" />}
                    {copied ? "已复制" : "复制 AID"}
                  </button>
                </div>
                <div className="mt-1.5 flex flex-wrap gap-1.5">
                  {(a.caps || []).map((c) => (
                    <Badge key={c} variant="outline">
                      {c}
                    </Badge>
                  ))}
                </div>
                <div className="mt-3 flex items-baseline gap-2.5">
                  <span className="font-bebas text-4xl leading-none text-[#E60000]">
                    {a.review_count ? a.avg_rating.toFixed(1) : "—"}
                  </span>
                  <span className="text-xs text-gray-500">
                    {a.review_count ? (
                      <>
                        <Stars avg={a.avg_rating} className="mr-1 align-middle" />
                        {a.review_count} 条可验证评价
                      </>
                    ) : (
                      "还没有评价"
                    )}
                  </span>
                </div>
              </div>
            </div>
          </div>

          <div className="thin-scroll flex-1 overflow-y-auto p-6">
            {a.summary && <p className="mb-3 text-[14px] leading-relaxed text-gray-800">{a.summary}</p>}
            {a.readme && (
              <div
                className="md mb-3 border border-gray-200 bg-gray-50/60 p-4 text-[13px] leading-relaxed text-gray-800"
                dangerouslySetInnerHTML={{ __html: renderMd(a.readme) }}
              />
            )}
            {a.pricing && (
              <div className="mb-3 border border-[#E60000]/25 bg-[#E60000]/4 px-4 py-2.5 text-[13px]">
                <span className="mb-0.5 block text-[10px] uppercase tracking-wider text-gray-400">
                  收费（仅展示）
                </span>
                {a.pricing}
              </div>
            )}

            <h4 className="mb-3 mt-6 font-bebas text-lg tracking-[0.08em]">
              VERIFIED REVIEWS <span className="text-[#E60000]">·</span>{" "}
              <span className="text-gray-400 text-sm tracking-normal font-body">签名与回执已验证，不含交互内容</span>
            </h4>
            {data!.reviews.length ? (
              <div className="space-y-3">
                {data!.reviews.map((r, i) => (
                  <Review key={r.interaction_id + i} r={r} />
                ))}
              </div>
            ) : (
              <p className="py-4 text-[13px] leading-relaxed text-gray-500">
                还没有可信评价。评价必须锚定一次双方签名的交互回执，Hub 验签通过后才会显示。
              </p>
            )}
          </div>
        </>
      )}
    </Dialog>
  );
}
