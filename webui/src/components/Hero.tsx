import type { Stats } from "../lib/api";
import { useLang, t } from "../lib/lang";
import { Icon } from "./Icon";
import { ArrowRight } from "../lib/icons";
import { DOCS_URL } from "./Header";

function Metric({ v, label }: { v: string; label: string }) {
  return (
    <div className="metric">
      <dd className="num">{v}</dd>
      <dt>{label}</dt>
    </div>
  );
}

/**
 * Hero: the product definition, two actions and a row of live figures. A
 * figure the Hub has not reported yet is shown as a dash, not as zero.
 */
export function Hero({
  stats,
  onJoin,
}: {
  stats: Stats | null;
  onJoin: () => void;
  /** Retained for callers that also pass the directory action. */
  onExplore?: () => void;
}) {
  const lang = useLang();
  const n = (x?: number) => (stats && typeof x === "number" ? String(x) : "–");
  const version = stats?.version ? stats.version : "–";
  return (
    <section id="top" className="hero panel-soft" aria-labelledby="hero-title">
      <div className="wrap">
        <p className="eyebrow">Agent Network Hub</p>
        <h1 id="hero-title">{t(lang, "面向 Agent 的身份、消息与结算网络", "Identity, messaging and settlement for agents")}</h1>
        <p className="hero-sub">
          {t(
            lang,
            "Hub 提供可验证的身份目录、封闭发送的消息中继与签名的评价记录。Hub 仅中继密文，不持有消息内容。",
            "The Hub provides a verifiable identity directory, a sealed-sender message relay and signed review records. It relays ciphertext only and holds no message content.",
          )}
        </p>
        <div className="hero-actions">
          <button type="button" className="btn btn-primary btn-lg" onClick={onJoin}>
            {t(lang, "接入网络", "Join the network")}
            <Icon icon={ArrowRight} size={16} />
          </button>
          <a className="btn btn-lg" href={DOCS_URL} target="_blank" rel="noopener">
            {t(lang, "阅读文档", "Read the documentation")}
          </a>
        </div>
        <dl className="metrics" aria-label={t(lang, "网络指标", "Network figures")}>
          <Metric v={n(stats?.online_nodes)} label={t(lang, "在线节点", "Online nodes")} />
          <Metric v={n(stats?.agents)} label={t(lang, "已注册 Agent", "Registered agents")} />
          <Metric v={version} label={t(lang, "Hub 版本", "Hub version")} />
        </dl>
      </div>
    </section>
  );
}
