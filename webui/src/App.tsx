import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { fetchAgents, fetchStats, type AgentView, type Stats } from "./lib/api";
import { useGuest } from "./lib/guest";
import { shortAid } from "./lib/utils";
import { Header } from "./components/Header";
import { Hero } from "./components/Hero";
import { AgentsSection } from "./components/AgentsSection";
import { AgentDetailDialog } from "./components/AgentDetailDialog";
import { ChatDialog } from "./components/ChatDialog";
import { JoinSection } from "./components/JoinSection";
import { TasksSection } from "./components/TasksSection";
import { Footer } from "./components/Footer";
import { Toast, useToast } from "./components/Toast";

export default function App() {
  const [stats, setStats] = useState<Stats | null>(null);
  const [agents, setAgents] = useState<AgentView[]>([]);
  const [q, setQ] = useState("");
  const [detailAid, setDetailAid] = useState<string | null>(null);
  const { toast, toastState } = useToast();

  const agentsRef = useRef(agents);
  agentsRef.current = agents;
  const agentName = useCallback((aid: string) => {
    const a = agentsRef.current.find((x) => x.aid === aid);
    return (a && a.name) || "";
  }, []);

  const guest = useGuest(agentName);

  // /stats：首屏 + 周期刷新
  useEffect(() => {
    let alive = true;
    const load = () => fetchStats().then((s) => alive && setStats(s)).catch(() => {});
    load();
    const t = setInterval(load, 10000);
    return () => {
      alive = false;
      clearInterval(t);
    };
  }, []);

  // /agents?q=：搜索防抖 + 空闲时周期刷新
  useEffect(() => {
    let alive = true;
    const run = () => fetchAgents(q).then((a) => alive && setAgents(a)).catch(() => {});
    const debounce = setTimeout(run, q ? 220 : 0);
    const t = setInterval(run, 10000);
    return () => {
      alive = false;
      clearTimeout(debounce);
      clearInterval(t);
    };
  }, [q]);

  const scrollTo = (id: string) => {
    document.getElementById(id)?.scrollIntoView({ behavior: "smooth" });
  };

  const openChat = useCallback(
    (aid: string) => {
      setDetailAid(null);
      guest.open(aid);
    },
    [guest],
  );

  const activeSession = guest.activeAid ? guest.sessions[guest.activeAid] || null : null;
  const activeName = useMemo(() => {
    if (!activeSession) return "";
    return activeSession.handlerName || agentName(activeSession.aid) || shortAid(activeSession.aid);
  }, [activeSession, agentName]);

  return (
    <div className="min-h-screen bg-white text-black">
      <Header onJoin={() => scrollTo("join")} />
      <Hero stats={stats} onExplore={() => scrollTo("agents")} onJoin={() => scrollTo("join")} />
      <AgentsSection
        agents={agents}
        q={q}
        onQ={setQ}
        onOpen={setDetailAid}
        sessions={guest.sessions}
        onReopenChat={openChat}
      />
      <TasksSection />
      <JoinSection toast={toast} />
      <Footer />

      <AgentDetailDialog aid={detailAid} onClose={() => setDetailAid(null)} onChat={openChat} toast={toast} />
      {activeSession && (
        <ChatDialog
          session={activeSession}
          agentName={activeName}
          onClose={guest.close}
          onSend={guest.send}
          onEnd={guest.end}
          onOpenJoin={() => scrollTo("join")}
          toast={toast}
        />
      )}
      <Toast state={toastState} />
    </div>
  );
}
