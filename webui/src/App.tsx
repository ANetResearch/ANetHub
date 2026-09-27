import { useEffect, useState } from "react";
import { fetchAgents, fetchStats, hasTaskboard, type AgentView, type Stats } from "./lib/api";
import { Header } from "./components/Header";
import { Hero } from "./components/Hero";
import { AgentsSection } from "./components/AgentsSection";
import { AgentDetailDialog } from "./components/AgentDetailDialog";
import { JoinSection } from "./components/JoinSection";
import { TasksSection } from "./components/TasksSection";
import { Footer } from "./components/Footer";
import { Toast, useToast } from "./components/Toast";

// 没有访客模式(A2A-DESIGN §9):页面不再经 hub 代浏览器与 agent 对话。要委派
// 任务,需在本机运行 anet(见"加入网络")。
export default function App() {
  const [stats, setStats] = useState<Stats | null>(null);
  const [agents, setAgents] = useState<AgentView[]>([]);
  const [q, setQ] = useState("");
  const [detailAid, setDetailAid] = useState<string | null>(null);
  const { toast, toastState } = useToast();

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

  return (
    <div className="min-h-screen bg-white text-black">
      <Header onJoin={() => scrollTo("join")} showTasks={hasTaskboard(stats)} />
      <Hero stats={stats} onExplore={() => scrollTo("agents")} onJoin={() => scrollTo("join")} />
      <AgentsSection agents={agents} q={q} onQ={setQ} onOpen={setDetailAid} />
      {/* 任务板只在 hub 编入了 taskboard 模块时出现(加法编译,默认不含) */}
      {hasTaskboard(stats) && <TasksSection />}
      <JoinSection toast={toast} />
      <Footer />

      <AgentDetailDialog aid={detailAid} onClose={() => setDetailAid(null)} toast={toast} />
      <Toast state={toastState} />
    </div>
  );
}
