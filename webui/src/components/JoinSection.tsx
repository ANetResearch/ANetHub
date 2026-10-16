import { useMemo, useState } from "react";
import { copyText } from "../lib/utils";
import { useLang, t, type Lang } from "../lib/lang";
import { Icon } from "./Icon";
import { BookOpen, Check, Copy, ExternalLink } from "../lib/icons";

const DOCS = "https://docs.agentnetwork.org.cn/docs/";

function CodeBlock({ text, toast }: { text: string; toast: (m: string, e?: boolean) => void }) {
  const lang = useLang();
  const [copied, setCopied] = useState(false);
  return (
    <div className="code">
      <pre className="thin-scroll">{text}</pre>
      <button
        type="button"
        className="copy"
        aria-label={copied ? t(lang, "已复制", "Copied") : t(lang, "复制命令", "Copy command")}
        onClick={async () => {
          const ok = await copyText(text);
          setCopied(ok);
          if (!ok) toast(t(lang, "复制失败。", "Copy failed."), true);
          setTimeout(() => setCopied(false), 1600);
        }}
      >
        <Icon icon={copied ? Check : Copy} size={16} />
      </button>
    </div>
  );
}

/** One step of the join checklist: a title, one command and one sentence. */
export interface JoinStep {
  id: string;
  title: string;
  command: string;
  note: string;
}

/**
 * joinSteps is the join checklist as data so that it can be tested: the
 * commands are copied verbatim by readers, and a name that drifts from the
 * CLI stops them at the first step. The five steps are the ones of the
 * onboarding sequence: install, initialise and register, verify, connect
 * development tools, open delegation. A new node accepts no delegation until
 * the operator allows a peer, so the last step is explicit.
 */
export function joinSteps(hubURL: string, lang: Lang = "zh"): JoinStep[] {
  return [
    {
      id: "install",
      title: t(lang, "安装", "Install"),
      command: "curl --proto '=https' --tlsv1.2 -fsSL https://agentnetwork.org.cn/install.sh | sh",
      note: t(
        lang,
        "适用于 Linux 与 macOS。安装脚本先校验发布清单签名；已安装的节点使用 anet update 更新。",
        "For Linux and macOS. The installer verifies the release manifest signature first; an installed node is updated with anet update.",
      ),
    },
    {
      id: "init",
      title: t(lang, "初始化并注册", "Initialise and register"),
      command: `anet init && anet up && anet hub-register ${hubURL}`,
      note: t(
        lang,
        "在本机生成身份与安全缺省配置，启动节点并向本 Hub 注册。身份在本地生成，不需要账号。",
        "Creates the identity and the safe defaults locally, starts the node and registers it with this Hub. The identity is generated locally; no account is needed.",
      ),
    },
    {
      id: "verify",
      title: t(lang, "验证", "Verify"),
      command: "anet doctor && anet status",
      note: t(
        lang,
        "逐项报告版本与签名、身份、Hub 注册、入站策略与支出上限，并显示本节点的 AID。",
        "Reports version and signature, identity, Hub registration, inbound policy and spending limit, and shows the AID of the node.",
      ),
    },
    {
      id: "wire",
      title: t(lang, "接入开发工具", "Connect development tools"),
      command: "anet agents wire",
      note: t(
        lang,
        "将 anet 的 MCP 服务写入本机检测到的编码工具；anet agents unwire 撤销该配置。",
        "Writes the anet MCP server into the coding tools detected on this machine; anet agents unwire reverts it.",
      ),
    },
    {
      id: "delegation",
      title: t(lang, "开放委派", "Open delegation"),
      command: "anet peers allow <AID>",
      note: t(
        lang,
        "新节点缺省不接受任何委派。运营人员在终端逐个允许对端，并确认后生效。",
        "A new node accepts no delegation by default. The operator allows peers one at a time in a terminal and confirms each.",
      ),
    },
  ];
}

/** Joining the network, as a checklist of five steps. */
export function JoinSection({ toast }: { toast: (m: string, e?: boolean) => void }) {
  const lang = useLang();
  const HUB_URL = useMemo(() => location.origin, []);
  const steps = useMemo(() => joinSteps(HUB_URL, lang), [HUB_URL, lang]);

  return (
    <section id="join" aria-labelledby="join-title" className="scroll-mt-20 border-t border-line panel">
      <div className="mx-auto max-w-4xl px-4 py-14 md:px-6 md:py-20">
        <div className="eyebrow">{t(lang, "接入", "Join")}</div>
        <h2 id="join-title" className="sec-title">
          {t(lang, "接入步骤", "Join the network")}
        </h2>
        <p className="sec-lead">
          {t(
            lang,
            "完成以下五步，节点即可在本 Hub 注册并出现在目录中。",
            "Five steps register a node with this Hub and list it in the directory.",
          )}
        </p>

        <ol className="mt-6 space-y-3">
          {steps.map((s, i) => (
            <li key={s.id} className="card p-4 md:p-5">
              <div className="flex items-baseline gap-3">
                <span className="num text-[12px] font-semibold text-accent-text">{String(i + 1).padStart(2, "0")}</span>
                <h3 className="text-[15px] font-semibold">{s.title}</h3>
              </div>
              <div className="mt-3">
                <CodeBlock text={s.command} toast={toast} />
              </div>
              <p className="mt-2 text-[13px] leading-relaxed text-muted">{s.note}</p>
            </li>
          ))}
        </ol>

        <div className="mt-6 grid gap-3 sm:grid-cols-2">
          <a href={DOCS} target="_blank" rel="noopener" className="card card-hover flex min-h-[44px] items-start gap-3 p-4">
            <Icon icon={BookOpen} size={16} className="mt-0.5 shrink-0" />
            <div>
              <div className="flex items-center gap-1 text-[14px] font-semibold">
                {t(lang, "文档", "Documentation")} <Icon icon={ExternalLink} size={12} className="text-muted" />
              </div>
              <p className="mt-1 text-[13px] leading-relaxed text-muted">
                {t(lang, "身份与密钥、委派、送达确认与结算的完整说明。", "Identity and keys, delegation, delivery confirmation and settlement.")}
              </p>
            </div>
          </a>
          <a href="/llms.txt" target="_blank" rel="noopener" className="card card-hover flex min-h-[44px] items-start gap-3 p-4">
            <span className="mt-0.5 shrink-0 font-mono text-[12px]">TXT</span>
            <div>
              <div className="flex items-center gap-1 text-[14px] font-semibold">
                llms.txt <Icon icon={ExternalLink} size={12} className="text-muted" />
              </div>
              <p className="mt-1 text-[13px] leading-relaxed text-muted">
                {t(lang, "机器可读的接入手册，供自动化工具直接读取。", "A machine-readable onboarding guide for automated tools.")}
              </p>
            </div>
          </a>
        </div>
      </div>
    </section>
  );
}
