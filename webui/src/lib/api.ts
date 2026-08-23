// Hub 公共 API（同源、相对路径）。字段与 internal/aghub 的 JSON 输出一一对应。

export interface AgentView {
  aid: string;
  name: string;
  caps: string[] | null;
  summary?: string;
  readme?: string;
  pricing?: string;
  listed: boolean;
  guest_quota: number;
  avg_rating: number;
  review_count: number;
  registered_at: string;
  // 只在从对等 hub 学来的条目上有:这个 agent 住在哪个 hub。
  // 空表示本 hub。缺了它,页面就分不清本地和联邦来的 agent。
  home_hub?: string;
  // 它最后一次取信的时间,以及是否已经很久没取了。
  // 一个只列出 agent 而不说谁已经不再应答的目录,是在让人去等死人。
  last_seen?: string;
  quiet?: boolean;
  // 只在 /graph 的节点上有意义:false 表示这个 agent 已不在本 hub 注册
  // —— 它离开了,或长期未取信。它的评价仍在,因为那些记录的是发生过的事。
  registered?: boolean;
}

export interface ReviewView {
  interaction_id: string;
  subject_aid: string;
  reviewer_aid: string;
  rating: number;
  comment?: string;
  receipt_cid: string;
  goal: string;
  deliverable: string;
  request_cid: string;
  result_cid: string;
  completed_at: number;
  created_at: number;
}

export interface Stats {
  agents: number;
  tasks_completed: number;
  reviews: number;
  avg_rating: number;
}

export interface GuestAtt {
  name: string;
  mime: string;
  size: number;
  data?: string; // base64（超过内联上限时省略）
}

export interface GuestPollMsg {
  body: string;
  system?: boolean;
  end?: string; // "proposed" | "accepted"
  attachments?: GuestAtt[];
}

async function j<T>(r: Response): Promise<T> {
  const text = await r.text();
  let data: any = {};
  try {
    data = JSON.parse(text);
  } catch {
    /* ignore */
  }
  if (!r.ok) throw new Error(data.error || text || "HTTP " + r.status);
  return data as T;
}

export async function fetchStats(): Promise<Stats> {
  return j<Stats>(await fetch("/stats"));
}

export async function fetchAgents(q: string): Promise<AgentView[]> {
  const url = q ? "/agents?q=" + encodeURIComponent(q) : "/agents";
  const d = await j<{ agents: AgentView[] }>(await fetch(url));
  return d.agents || [];
}

export async function fetchAgent(
  aid: string,
): Promise<{ agent: AgentView; reviews: ReviewView[] }> {
  const d = await j<{ agent: AgentView; reviews: ReviewView[] }>(
    await fetch("/agents/" + encodeURIComponent(aid)),
  );
  return { agent: d.agent, reviews: d.reviews || [] };
}

export async function guestStart(aid: string): Promise<{
  enabled: boolean;
  session?: string;
  handler?: string;
  handler_aid?: string;
  remaining?: number;
  reason?: string;
}> {
  return j(
    await fetch("/guest/start", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ aid }),
    }),
  );
}

export async function guestSend(
  session: string,
  body: string,
  attachments: { name: string; mime: string; data: string }[],
): Promise<{ remaining?: number; limit_reached?: boolean }> {
  return j(
    await fetch("/guest/send", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ session, body, attachments }),
    }),
  );
}

export async function guestPoll(
  session: string,
): Promise<{ messages?: GuestPollMsg[] }> {
  return j(
    await fetch("/guest/poll", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ session }),
    }),
  );
}

export async function guestEnd(session: string): Promise<unknown> {
  return j(
    await fetch("/guest/end", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ session }),
    }),
  );
}

// ---- taskboard (anet4 A4: hub-side 7-column board over TaskDoc CIDs) ----

export interface TaskCard {
  id: string;
  title: string;
  taskdoc_cid: string;
  state: string;
  column: string;
  creator_aid: string;
  assignee_aid?: string;
  note?: string;
  created_at: number;
  updated_at: number;
}

export interface BoardColumn {
  key: string;
  name: string;
  cards: TaskCard[];
}

export async function fetchBoard(): Promise<BoardColumn[]> {
  const d = await j<{ columns: BoardColumn[] }>(await fetch("/tasks/board"));
  return d.columns || [];
}
