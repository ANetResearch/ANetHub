// 访客试聊会话管理：/guest/start → /guest/send → /guest/poll →( /guest/end )。
// 与旧版语义一致：对方可能是真人，回复可能很慢 —— 只要聊天窗开着就持续轮询（2.5s），
// 晚到的回复照样出现；每个会话有 Hub 下发的剩余条数上限。

import { useCallback, useEffect, useRef, useState } from "react";
import * as api from "./api";
import { fileToB64 } from "./utils";

export interface GuestMsg {
  role: "me" | "them" | "sys";
  body: string;
  attachments?: api.GuestAtt[];
}

export interface GuestSession {
  aid: string;
  session: string;
  handlerName: string;
  remaining: number;
  done: boolean;
  starting: boolean;
  endProposed: boolean;
  messages: GuestMsg[];
}

export const GUEST_ATT_MAX = 12 * 1024 * 1024;
export const GUEST_ATT_COUNT = 4;

export function useGuest(agentName: (aid: string) => string) {
  const [sessions, setSessions] = useState<Record<string, GuestSession>>({});
  const [activeAid, setActiveAid] = useState<string>("");
  const sessionsRef = useRef(sessions);
  sessionsRef.current = sessions;
  const activeRef = useRef(activeAid);
  activeRef.current = activeAid;
  const inFlight = useRef(false);

  const patch = useCallback((aid: string, fn: (g: GuestSession) => GuestSession) => {
    setSessions((prev) => {
      const g = prev[aid];
      if (!g) return prev;
      return { ...prev, [aid]: fn(g) };
    });
  }, []);

  /** 打开（并按需创建）与某 agent 的试聊会话。 */
  const open = useCallback(
    async (aid: string) => {
      setActiveAid(aid);
      if (sessionsRef.current[aid]) return;
      const fresh: GuestSession = {
        aid,
        session: "",
        handlerName: "",
        remaining: 0,
        done: false,
        starting: true,
        endProposed: false,
        messages: [],
      };
      setSessions((prev) => ({ ...prev, [aid]: fresh }));
      let j: Awaited<ReturnType<typeof api.guestStart>> | null = null;
      try {
        j = await api.guestStart(aid);
      } catch {
        j = null;
      }
      patch(aid, (g) => {
        if (!j || !j.enabled || !j.session) {
          return {
            ...g,
            starting: false,
            done: true,
            messages: [
              ...g.messages,
              {
                role: "sys",
                body: "这个 agent 暂未开放访客试玩。安装 anet 后即可向 TA 发起正式、可评价的委派。",
              },
            ],
          };
        }
        const nm = agentName(aid) || j.handler || aid.slice(0, 10);
        return {
          ...g,
          starting: false,
          session: j.session!,
          handlerName: nm,
          remaining: j.remaining || 0,
          messages: [
            ...g.messages,
            {
              role: "them",
              body: `👋 你好！你正以「访客」身份直接对话「${nm}」——发条消息，我会真实转发并把回复带回来。最多可发 ${j.remaining} 条。`,
            },
          ],
        };
      });
    },
    [agentName, patch],
  );

  const close = useCallback(() => setActiveAid(""), []);

  const pollOnce = useCallback(
    async (aid: string) => {
      if (inFlight.current) return;
      const g = sessionsRef.current[aid];
      if (!g || !g.session) return;
      inFlight.current = true;
      try {
        const j = await api.guestPoll(g.session);
        if (j && j.messages && j.messages.length) {
          patch(aid, (cur) => {
            let done = cur.done;
            let endProposed = cur.endProposed;
            const msgs = [...cur.messages];
            for (const m of j.messages!) {
              msgs.push({
                role: m.system ? "sys" : "them",
                body: m.body,
                attachments: m.attachments,
              });
              if (m.end === "proposed") endProposed = true;
              else if (m.end === "accepted") {
                done = true;
                endProposed = false;
              }
            }
            return { ...cur, messages: msgs, done, endProposed };
          });
        }
      } catch {
        /* transient; next tick retries */
      }
      inFlight.current = false;
    },
    [patch],
  );

  // 聊天窗开着就持续轮询：对方可能是真人，回复可能几分钟后才到。
  useEffect(() => {
    const t = setInterval(() => {
      const aid = activeRef.current;
      if (aid) pollOnce(aid);
    }, 2500);
    return () => clearInterval(t);
  }, [pollOnce]);

  const send = useCallback(
    async (aid: string, body: string, files: File[]) => {
      const g = sessionsRef.current[aid];
      if (!g || g.done || g.starting) return;
      if (!body && !files.length) return;
      if (g.remaining <= 0) {
        patch(aid, (cur) => ({ ...cur, done: true }));
        return;
      }
      const ups: { name: string; mime: string; data: string }[] = [];
      const echo: api.GuestAtt[] = [];
      try {
        for (const f of files) {
          const data = await fileToB64(f);
          ups.push({ name: f.name, mime: f.type || "", data });
          echo.push({ name: f.name, mime: f.type || "", size: f.size, data });
        }
      } catch {
        throw new Error("读取文件失败");
      }
      patch(aid, (cur) => ({
        ...cur,
        messages: [...cur.messages, { role: "me", body, attachments: echo }],
      }));
      try {
        const j = await api.guestSend(g.session, body, ups);
        patch(aid, (cur) => {
          let remaining = cur.remaining;
          if (j.limit_reached) remaining = 0;
          else if (typeof j.remaining === "number") remaining = j.remaining;
          return { ...cur, remaining, done: remaining <= 0 ? true : cur.done };
        });
      } catch (e: any) {
        patch(aid, (cur) => ({
          ...cur,
          messages: [...cur.messages, { role: "sys", body: "发送失败：" + (e?.message || e) }],
        }));
      }
      pollOnce(aid); // 立即戳一次；随后由定时轮询接管
    },
    [patch, pollOnce],
  );

  /** 结束试聊（对方已提议时等价于「同意结束」）。 */
  const end = useCallback(
    async (aid: string) => {
      const g = sessionsRef.current[aid];
      if (!g || !g.session || g.done) return;
      try {
        await api.guestEnd(g.session);
      } catch {
        patch(aid, (cur) => ({
          ...cur,
          messages: [...cur.messages, { role: "sys", body: "结束失败，请稍后再试" }],
        }));
        return;
      }
      patch(aid, (cur) => ({
        ...cur,
        done: true,
        endProposed: false,
        messages: [...cur.messages, { role: "sys", body: "你已结束这次对话。" }],
      }));
    },
    [patch],
  );

  return { sessions, activeAid, open, close, send, end };
}

export function sessionStatus(g: GuestSession): string {
  if (g.starting) return "连接中…";
  if (g.done) return "对话已结束";
  if (g.remaining > 0) return `还可发送 ${g.remaining} 条`;
  return "已达试玩上限";
}
