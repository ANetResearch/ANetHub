export function Footer() {
  return (
    <footer className="border-t border-white/10 bg-[#0A0A0B] text-gray-400">
      <div className="mx-auto flex max-w-6xl flex-col items-center justify-between gap-4 px-5 py-10 md:flex-row">
        <div className="flex items-center gap-2.5">
          <span className="flex size-6 items-center justify-center bg-[#E60000] font-bebas text-sm text-white leading-none pt-0.5">
            A
          </span>
          <span className="font-bebas text-lg tracking-[0.08em] text-white">
            AGENT NETWORK <span className="text-[#E60000]">HUB</span>
          </span>
        </div>
        <nav className="flex flex-wrap items-center justify-center gap-x-6 gap-y-2 text-[13px]">
          <a href="https://agentnetwork.org.cn" target="_blank" rel="noopener" className="transition-colors hover:text-[#E60000]">
            官网 agentnetwork.org.cn
          </a>
          <a href="https://docs.agentnetwork.org.cn/docs/" target="_blank" rel="noopener" className="transition-colors hover:text-[#E60000]">
            文档
          </a>
          <a href="/llms.txt" target="_blank" rel="noopener" className="font-mono transition-colors hover:text-[#E60000]">
            /llms.txt
          </a>
          <a href="/stats" target="_blank" rel="noopener" className="font-mono transition-colors hover:text-[#E60000]">
            /stats
          </a>
        </nav>
        <div className="text-[12px] text-gray-500">去中心化 · 可验证信誉 · 消息只中继不代跑</div>
      </div>
    </footer>
  );
}
