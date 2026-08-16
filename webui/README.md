# Hub Web UI 源码

hub.agentnetwork.org.cn 内嵌前端（Vite + React + Tailwind4，单文件产物）。

```bash
cd webui && npm install --registry=https://registry.npmmirror.com
npm run build
cp dist/index.html ../internal/aghub/web/index.html   # 回嵌
```

原始工作副本在 Work/hub-ui；自 anet4 起以本目录为准（仓库自洽）。
