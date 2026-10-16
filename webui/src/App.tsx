import { useEffect, useState } from "react";
import { fetchAgents, fetchStats, hasTaskboard, type AgentView, type Stats } from "./lib/api";
import { Header } from "./components/Header";
import { Hero } from "./components/Hero";
import { AgentsSection } from "./components/AgentsSection";
import { AgentDetailDialog } from "./components/AgentDetailDialog";
import { JoinSection } from "./components/JoinSection";
import { TasksSection } from "./components/TasksSection";
import { CapabilitiesSection } from "./components/Capabilities";
import { VoxelBackground } from "./voxel/VoxelBackground";
import { Footer } from "./components/Footer";
import { Toast, useToast } from "./components/Toast";
import { useLang, t } from "./lib/lang";

// 没有访客模式(A2A-DESIGN §9):页面不再经 hub 代浏览器与 agent 对话。要委派
// 任务,需在本机运行 anet(见"加入网络")。
export default function App() {
  const [stats, setStats] = useState<Stats | null>(null);
  const [agents, setAgents] = useState<AgentView[]>([]);
  const [q, setQ] = useState("");
  const [detailAid, setDetailAid] = useState<string | null>(null);
  const { toast, toastState } = useToast();
  const lang = useLang();

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

  // A link of the form /#agent/<aid> (the researcher directory uses it) opens that agent's profile.
  useEffect(() => {
    const open = () => {
      const m = /^#agent\/(.+)$/.exec(location.hash);
      if (m) setDetailAid(decodeURIComponent(m[1]));
    };
    open();
    window.addEventListener("hashchange", open);
    return () => window.removeEventListener("hashchange", open);
  }, []);

  const scrollTo = (id: string) => {
    document.getElementById(id)?.scrollIntoView({ behavior: "smooth" });
  };

  return (
    <div className="min-h-screen text-fg">
      <VoxelBackground />
      <a href="#main" className="skip-link">{t(lang, "跳到正文", "Skip to content")}</a>
      <Header onJoin={() => scrollTo("join")} showTasks={hasTaskboard(stats)} />
      <main id="main">
        <Hero stats={stats} onJoin={() => scrollTo("join")} />
        <CapabilitiesSection />
        <div className="panel">
          <AgentsSection agents={agents} q={q} onQ={setQ} onOpen={setDetailAid} />
        </div>
        {/* The task board appears only when the Hub was built with the taskboard module. */}
        {hasTaskboard(stats) && <div className="panel"><TasksSection /></div>}
        <JoinSection toast={toast} />
      </main>
      <Footer />

      <AgentDetailDialog aid={detailAid} onClose={() => {
          setDetailAid(null);
          if (location.hash.startsWith("#agent/")) history.replaceState(null, "", location.pathname + location.search);
        }} toast={toast} />
      <Toast state={toastState} />
    </div>
  );
}
