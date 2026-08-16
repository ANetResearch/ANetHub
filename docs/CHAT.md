# 多模态在线聊天（/chat）

`https://hub.agentnetwork.org.cn/chat` —— Telegram 风格的多模态 agent 聊天客户端。它把 Hub 的在线
调用从「纯文本访客试聊」升级为**全模态**：用户可发文本/图像/多图/音频/视频/文件/链接，agent 亦可
全模态输出，每个模态有独立 UI 组件。

## 架构
- 单文件内嵌页（`internal/aghub/web/chat.html`，~60KB，零外部请求、GFW 安全），经 go:embed 服务于
  `GET /chat`（`server.go` hChat）。
- 后端沿用 **guest-broker API**（`/guest/start|send|poll|end`）——Hub 持一个隐形 broker 身份，代访客
  签名委派并中转，附件内联 base64。**公网面零改动**，只加了 `/chat` 路由。
- 多模态上限（`guest.go`）：单附件 20 MiB、每条消息 10 个附件（相册）。

## 已实现（对照 Telegram）
- 双栏布局：左侧 agent 列表（46px 首字母头像 + 名称 + 能力 chips + 评分），右侧会话；窄屏折叠 + 返回。
- 气泡系统：收/发对齐、15 分钟同发件人分组、气泡内时间戳、发送态（sending→sent）、agent 工作中动画。
- 逐模态渲染组件：
  - 文本（markdown：粗/斜/`code`/链接 + 裸 URL 自动链接 + 链接卡）
  - 单图（等比 430/100，点击全屏灯箱 + 下载）
  - **相册（2–10 张）**：从 Telegram `grouped_layout.cpp` 移植的马赛克布局算法（n=1–4 分支 + n=5–10
    行评分布局器，4px 间隙，逐块圆角，灯箱翻页）
  - 视频（封面 + 播放键 + 时长徽标 → 灯箱 `<video controls>`）
  - 语音/音频（44px 播放键 + 波形（WebAudio 解码，静态兜底）+ 时长 + 点击 seek）
  - 文件（44px 图标行 + 文件名 + 大小 + 下载）
  - 超大附件 → 元数据 chip（"安装 anet 以接收"）
- 输入区：自增长文本框（Enter 发送/Shift+Enter 换行）、附件菜单、**粘贴图片**、**拖放上传**、
  暂存区（多图预览为相册马赛克 + 逐个移除）、**录音**（MediaRecorder webm/opus + 计时 + 取消/发送）、
  发送键麦克风↔箭头形变。
- 会话头：名称 + 短 AID（mono）+ 能力 chips + 剩余额度 + 结束会话（对方提议结束时变"确认结束"）。
- 健壮性：enabled:false / error / 会话过期重载 / poll 退避 / 限额友好提示 / end 协商。

## 实测（2026-07-20，生产）
- 文本往返：CMax Vision 6s 回复。
- **多模态图像往返**：上传 64×64 PNG（蓝底红方块）→ 视觉 agent 16s 正确识别「蓝色背景 + 中央红色
  正方形，主色蓝色」。附件路径（浏览器 base64 → guest send → 委派附件 → agent → 回交）全程打通。

## 未尽 / 升级路径
- 录音用点击切换（非 Telegram 的滑动取消/上锁手势）。
- 发送失败仅提示，未接「点击重试」（guest API 无已读回执，状态止于 sent）。
- 链接预览为域名+URL 卡片（无服务端 unfurl）。
