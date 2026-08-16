import { useEffect, useState } from "react";
import { BadgeCheck, Copy, Check } from "lucide-react";
import { fetchAgent, type AgentView, type ReviewView } from "../lib/api";
import { renderMd } from "../lib/markdown";
import { shortAid, fmtTime, copyText } from "../lib/utils";
import { Dialog } from "./ui/dialog";
import { Button } from "./ui/button";
import { Badge } from "./ui/badge";
import { Avatar } from "./ui/avatar";
import { Stars } from "./AgentsSection";

/** 评价附带的对话记录（deliverable 为 JSON 数组时渲染成气泡）。 */
function Transcript({ s }: { s: string }) {
  let arr: { from?: string; body?: string }[] | null = null;
  try {
    const p = JSON.parse(s);
    if (Array.isArray(p)) arr = p;
  } catch {
    /* not json */
  }
  if (!arr) {
    return (
      <pre className="max-h-40 overflow-auto thin-scroll whitespace-pre-wrap break-words border border-gray-200 bg-gray-50 p-2.5 text-[11px] leading-relaxed text-gray-700">
        {s}
      </pre>
    );
  }
  if (!arr.length) return <div className="text-xs text-gray-400">（无对话内容）</div>;
  return (
    <div className="flex max-h-60 flex-col gap-1.5 overflow-auto thin-scroll">
      {arr.map((m, i) => {
        const prov = m && m.from === "provider";
        return (
          <div
            key={i}
            className={
              "max-w-[88%] px-2.5 py-1.5 text-[12px] leading-relaxed border " +
              (prov
                ? "self-end border-[#E60000]/25 bg-[#E60000]/5"
                : "self-start border-gray-200 bg-gray-50")
            }
          >
            <span className="mb-0.5 block text-[9px] uppercase tracking-wider text-gray-400">
              {prov ? "提供方" : "委派方"}
            </span>
            <div className="md" dangerouslySetInnerHTML={{ __html: renderMd(String(m?.body || "")) }} />
          </div>
        );
      })}
    </div>
  );
}

function Review({ r }: { r: ReviewView }) {
  return (
    <div className="border border-gray-200 bg-white p-4">
      <div className="flex items-center justify-between gap-2">
        <Stars avg={r.rating} />
        <span className="font-mono text-[11px] text-gray-400">by {shortAid(r.reviewer_aid)}</span>
      </div>
      {r.comment && <p className="mt-2 text-[13px] italic leading-relaxed text-gray-800">“{r.comment}”</p>}
      {(r.goal || r.deliverable) && (
        <div className="mt-3 border-t border-dashed border-gray-200 pt-3">
          {r.goal && (
            <>
              <div className="mb-1 flex items-center gap-1.5 text-[10px] uppercase tracking-wider text-gray-400">
                请求
                <Badge variant="soft" className="text-[9px] px-1.5 py-0">✓ 内容已验证</Badge>
              </div>
              <p className="mb-2.5 text-[13px] leading-relaxed text-gray-800">{r.goal}</p>
            </>
          )}
          {r.deliverable && (
            <>
              <div className="mb-1 flex items-center gap-1.5 text-[10px] uppercase tracking-wider text-gray-400">
                对话记录
                <Badge variant="soft" className="text-[9px] px-1.5 py-0">✓ 内容已验证</Badge>
              </div>
              <Transcript s={r.deliverable} />
            </>
          )}
          <div className="mt-2.5 space-y-0.5 font-mono text-[10px] leading-relaxed text-gray-400">
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
          </div>
        </div>
      )}
      <div className="mt-3 flex items-center gap-1.5 text-[11px] text-[#E60000]">
        <BadgeCheck className="size-3.5" />
        双方签名已验证 · 回执 {shortAid(r.receipt_cid)}
        {r.created_at ? <span className="text-gray-400"> · {fmtTime(r.created_at)}</span> : null}
      </div>
    </div>
  );
}

/** Agent 详情弹窗：GET /agents/{aid} —— 资料 + 可验证评价列表 + 试聊入口。 */
export function AgentDetailDialog({
  aid,
  onClose,
  onChat,
  toast,
}: {
  aid: string | null;
  onClose: () => void;
  onChat: (aid: string) => void;
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
            <Button variant="brand" className="mt-4 w-full font-bebas tracking-[0.1em] text-base" onClick={() => onChat(a.aid)}>
              开始聊天（访客试玩）→
            </Button>
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
              <span className="text-gray-400 text-sm tracking-normal font-body">附完整交互内容</span>
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
