import { useEffect, useRef, useState } from "react";
import { Paperclip, Send, X, FileText } from "lucide-react";
import type { GuestAtt } from "../lib/api";
import { type GuestSession, sessionStatus, GUEST_ATT_MAX, GUEST_ATT_COUNT } from "../lib/guest";
import { renderMd } from "../lib/markdown";
import { fmtBytes, cn } from "../lib/utils";
import { Dialog } from "./ui/dialog";
import { Button } from "./ui/button";
import { Textarea } from "./ui/input";

function attSrc(a: GuestAtt): string {
  return a.data ? "data:" + (a.mime || "application/octet-stream") + ";base64," + a.data : "";
}

function Attachments({ atts }: { atts?: GuestAtt[] }) {
  if (!atts || !atts.length) return null;
  return (
    <div className="mt-2 flex flex-wrap gap-2">
      {atts.map((a, i) => {
        const src = attSrc(a);
        const isImg = String(a.mime || "").startsWith("image/") && src;
        if (isImg)
          return (
            <a key={i} href={src} target="_blank" rel="noopener" className="block max-w-[220px] overflow-hidden border border-gray-200 bg-white">
              <img src={src} alt={a.name} className="block max-h-[220px] max-w-[220px] object-cover" />
              <span className="block break-all px-2 py-1 text-[10px] text-gray-500">
                {a.name} · {fmtBytes(a.size)}
              </span>
            </a>
          );
        if (src)
          return (
            <a
              key={i}
              href={src}
              download={a.name}
              className="inline-flex items-center gap-1.5 break-all border border-gray-300 bg-white px-2.5 py-1.5 text-[12px] text-gray-700 hover:border-[#E60000] hover:text-[#E60000]"
            >
              <FileText className="size-3.5" />
              {a.name} · {fmtBytes(a.size)}
            </a>
          );
        return (
          <span key={i} title="安装 anet 后即可接收完整文件" className="inline-flex items-center gap-1.5 border border-gray-200 bg-gray-50 px-2.5 py-1.5 text-[12px] text-gray-400">
            <FileText className="size-3.5" />
            {a.name} · {fmtBytes(a.size)}（装 anet 接收）
          </span>
        );
      })}
    </div>
  );
}

/** 访客试聊弹窗：完整保留旧版会话语义（轮询、剩余条数、结束提议、试玩结束 CTA、附件）。 */
export function ChatDialog({
  session,
  agentName,
  onClose,
  onSend,
  onEnd,
  onOpenJoin,
  toast,
}: {
  session: GuestSession | null;
  agentName: string;
  onClose: () => void;
  onSend: (aid: string, body: string, files: File[]) => Promise<void>;
  onEnd: (aid: string) => void;
  onOpenJoin: () => void;
  toast: (msg: string, isErr?: boolean) => void;
}) {
  const [text, setText] = useState("");
  const [files, setFiles] = useState<File[]>([]);
  const [sending, setSending] = useState(false);
  const boxRef = useRef<HTMLDivElement>(null);
  const fileRef = useRef<HTMLInputElement>(null);
  const aid = session?.aid || "";

  // 新消息自动滚到底
  useEffect(() => {
    const box = boxRef.current;
    if (box) box.scrollTop = box.scrollHeight;
  }, [session?.messages.length, session?.done, session?.endProposed]);

  // 切换会话时清空草稿
  useEffect(() => {
    setText("");
    setFiles([]);
  }, [aid]);

  if (!session) return null;
  const g = session;

  const pickFiles = (list: FileList | null) => {
    if (!list) return;
    const next = [...files];
    for (const f of Array.from(list)) {
      if (next.length >= GUEST_ATT_COUNT) {
        toast(`一次最多 ${GUEST_ATT_COUNT} 个文件`, true);
        break;
      }
      if (f.size > GUEST_ATT_MAX) {
        toast(`「${f.name}」超过 ${(GUEST_ATT_MAX / 1024 / 1024).toFixed(0)} MiB 上限`, true);
        continue;
      }
      next.push(f);
    }
    setFiles(next);
  };

  const doSend = async () => {
    const body = text.trim();
    if ((!body && !files.length) || g.done || g.starting || sending) return;
    setSending(true);
    const fs = files.slice();
    setText("");
    setFiles([]);
    try {
      await onSend(aid, body, fs);
    } catch (e: any) {
      toast(String(e?.message || e), true);
    }
    setSending(false);
  };

  const last = g.messages[g.messages.length - 1];
  const waiting = last && last.role === "me" && !g.done;

  return (
    <Dialog open onClose={onClose} className="max-w-2xl md:h-[82vh]" closeButton={false}>
      {/* header */}
      <div className="flex items-center gap-3 border-b border-gray-200 px-5 py-3.5">
        <div className="flex size-8 items-center justify-center bg-black font-bebas text-white">
          {(agentName || "A").trim().charAt(0).toUpperCase()}
        </div>
        <div className="min-w-0 flex-1">
          <div className="flex items-center gap-2">
            <span className="truncate font-semibold">{agentName}</span>
            <span className="bg-[#E60000] px-1.5 py-0.5 text-[9px] font-bold text-white">访客试玩</span>
          </div>
          <div className="text-[11px] text-gray-400">{sessionStatus(g)}</div>
        </div>
        {!g.done && !g.starting && (
          <Button variant="outline" size="sm" onClick={() => onEnd(aid)}>
            结束对话
          </Button>
        )}
        <button
          aria-label="关闭"
          onClick={onClose}
          className="inline-flex size-8 cursor-pointer items-center justify-center text-gray-400 transition-colors hover:text-[#E60000]"
        >
          <X className="size-5" />
        </button>
      </div>

      {/* messages */}
      <div ref={boxRef} className="thin-scroll flex flex-1 flex-col gap-3 overflow-y-auto bg-gray-50/50 p-5">
        {g.messages.map((m, i) => {
          if (m.role === "sys")
            return (
              <div key={i} className="self-center border border-gray-200 bg-white px-4 py-1.5 text-center text-[11px] text-gray-500">
                {m.body}
              </div>
            );
          const mine = m.role === "me";
          return (
            <div
              key={i}
              className={cn(
                "max-w-[78%] border px-3.5 py-2.5 text-[13px] leading-relaxed break-words",
                mine
                  ? "self-end border-black bg-black text-white"
                  : "bubble-them self-start border-gray-200 bg-white text-gray-900",
              )}
            >
              {mine ? (
                <span className="whitespace-pre-wrap">{m.body}</span>
              ) : (
                <div className="md" dangerouslySetInnerHTML={{ __html: renderMd(m.body || "") }} />
              )}
              <Attachments atts={m.attachments} />
            </div>
          );
        })}
        {waiting && (
          <div className="flex items-center gap-2 self-start px-1 text-[12px] text-gray-400">
            <span className="flex gap-1">
              <span className="dot-pulse size-1.5 rounded-full bg-[#E60000]" />
              <span className="dot-pulse size-1.5 rounded-full bg-[#E60000]" />
              <span className="dot-pulse size-1.5 rounded-full bg-[#E60000]" />
            </span>
            已送达，等待对方回复…（对方可能是真人，请稍候，回复会自动出现）
          </div>
        )}
        {g.endProposed && !g.done && (
          <div className="self-center border border-[#E60000]/30 bg-[#E60000]/5 px-4 py-2.5 text-center text-[12px]">
            对方提议结束这次对话。{" "}
            <button className="cursor-pointer font-bold text-[#E60000] underline underline-offset-2" onClick={() => onEnd(aid)}>
              结束对话 →
            </button>
          </div>
        )}
        {g.done && (
          <div className="mx-auto max-w-md border border-[#E60000]/30 bg-white px-4 py-3 text-center text-[12px] leading-relaxed">
            🎉 试玩到这里啦！想<b>真正</b>把任务委派给网络里的 agent、拿到可验证结果并打分？装上 anet
            加入网络再回来即可。{" "}
            <button
              className="cursor-pointer font-bold text-[#E60000] underline underline-offset-2"
              onClick={() => {
                onClose();
                onOpenJoin();
              }}
            >
              查看接入指引 →
            </button>
          </div>
        )}
      </div>

      {/* composer */}
      <div className="border-t border-gray-200 p-4">
        {files.length > 0 && (
          <div className="mb-2 flex flex-wrap gap-1.5">
            {files.map((f, i) => (
              <span key={i} className="inline-flex max-w-full items-center gap-1.5 border border-gray-300 bg-gray-50 px-2 py-1 text-[11px]">
                <span className="max-w-[180px] truncate">{f.name}</span>
                <span className="text-gray-400">· {fmtBytes(f.size)}</span>
                <button
                  className="cursor-pointer font-bold text-gray-400 hover:text-[#E60000]"
                  onClick={() => setFiles(files.filter((_, j) => j !== i))}
                >
                  ✕
                </button>
              </span>
            ))}
          </div>
        )}
        <Textarea
          rows={2}
          value={text}
          disabled={g.done || g.starting}
          onChange={(e) => setText(e.target.value)}
          onKeyDown={(e) => {
            if (e.key === "Enter" && !e.shiftKey) {
              e.preventDefault();
              doSend();
            }
          }}
          placeholder={g.done ? "对话已结束" : "发条消息试试…（可传图片/文件，例如让 TA 识图）"}
        />
        <div className="mt-2 flex items-center justify-between gap-3">
          <span className="text-[11px] text-gray-400">anet 只中继消息，不跑模型</span>
          <div className="flex items-center gap-2">
            <input
              ref={fileRef}
              type="file"
              multiple
              className="hidden"
              onChange={(e) => {
                pickFiles(e.target.files);
                e.target.value = "";
              }}
            />
            <Button
              variant="outline"
              size="icon"
              title="添加图片 / 文件"
              disabled={g.done || g.starting}
              onClick={() => fileRef.current?.click()}
            >
              <Paperclip className="size-4" />
            </Button>
            <Button variant="brand" disabled={g.done || g.starting || sending} onClick={doSend}>
              <Send className="size-4" />
              发送
            </Button>
          </div>
        </div>
      </div>
    </Dialog>
  );
}
