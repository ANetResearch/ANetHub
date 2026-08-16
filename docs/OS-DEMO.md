# ANetOS 智能相框演示（/os）

`https://hub.agentnetwork.org.cn/os` —— 全屏后模拟 ANetOS 运行在智能相框（RK3566/OrangePi）上的纯网页
应用，用于给 KTC（显示屏厂商）演示我们实现的全部 AI 能力。设计遵循 gpt-5.6-sol 的多轮产品建议
（"不是 AI 功能列表，而是一台会主动工作的智能相框"）。

## 架构
- 前端：单文件 `cmd/anet-osdemo/web/os.html`（~82KB，零外部请求，背景/照片用 canvas 程序化生成）。
  DeviceShell 设备外壳 + 场景机（待机→唤醒→场景→AI 应用→任务执行→结果播放）。
- 后端：`cmd/anet-osdemo`（emax 127.0.0.1:8068，unit `anet-osdemo.service`），**token 门控的 Gravitex
  代理**——密钥服务端注入（`/data/projs/anet-osdemo/secrets.env`，0600），绝不进浏览器。nginx `location ^~ /os`。
- 语音输入用浏览器 Web Speech API（按键触发，非常驻唤醒——跨浏览器可靠性考虑）。

## 后端 API（token: X-OS-Token / ?t=，来自环境变量）
```
GET  /os/api/health            -> {ok, live}     # live=false → 前端自动进 Rehearsal（离线样例）
POST /os/api/chat   {prompt}   -> {text}          # 家庭记忆问答 / 对话
POST /os/api/vision {prompt,image} -> {text}      # 看图讲故事
POST /os/api/image  {prompt}   -> {b64,mime}      # 文生图 / 音乐成画 / 环境画布
POST /os/api/edit   {prompt,image} -> {b64,mime}  # 老照片修复/风格化
POST /os/api/tts    {text}     -> {audio_b64,mime}# 相框朗读/讲述
POST /os/api/video  {prompt}   -> {url}           # 让照片动起来（慢，可能 504 → 前端回退 sample）
GET  /os/api/sample/{name}     -> 预生成兜底素材   # restored.jpg/art.jpg/canvas.jpg/standby*.jpg/story.mp4
```

## 演示场景（均映射真实调用）
- 对话相框/看图讲述 → vision + **tts（相框开口讲故事）**；后续可"创作艺术画"→ image。
- 老照片修复 → edit → 前后对比滑块。
- 让照片动起来 → video（慢/失败回退 sample/story.mp4，再回退 canvas Ken-Burns）。
- 音乐成画 → image + 流动画布可视化。
- 家庭记忆管家 → chat（家庭记忆 system prompt）+ 时间线；答案可 tts。
- 环境自适应画布 → image → 设为待机背景。

## 三种模式（现场可靠性）
- **Live**：全部真实调用。
- **Hybrid（默认）**：真实调用，出错/超时回退预生成样例。
- **Rehearsal**：全用样例/兜底，断网可完成整场演示。

## 隐藏演示控制台
Ctrl+Shift+D / 右上角连点 5 次 / `?demo=1`：任意场景跳转、模式切换、**一键彩排**（7 步脚本，离线安全）、
预设语音指令、一键复位/唤醒、Demo Token 编辑、产品线与能力清单。快捷键：Ctrl+Shift+R 待机、
Ctrl+Shift+N 下一步、Ctrl+Shift+F 全屏；遥控：方向键=焦点、Enter=激活、Esc=返回、H=首页、P=待机、V=按住说话。
`?kiosk=1` 跳过启动页，`?scene=` 深链。

## 实测（2026-07-20，生产）
chat（欢迎语）、image（756KB jpeg 实时生成）、token 门（未授权 401）、样例服务（restored.jpg 979KB /
story.mp4 5.8MB）全部通过。

## 未尽（gpt-5.6-sol P1/P2）
图生视频受网关限制为文生视频（用真实海报的 Ken-Burns 兜底保证 still→motion 连续）；展前自检页
/os/preflight、第二屏遥控、PWA 离线缓存、25 服务全目录为后续产品化项。
