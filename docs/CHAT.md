# 访客聊天（已删除）

本文件原先描述 `/chat` 多模态访客聊天页与其后端 guest-broker API（`/guest/start|send|poll|end`）。
两者均已删除（A2A-DESIGN §2 访客模式、§9）：

- guest broker 由 hub 持有一个签名身份，代浏览器签署委派、转发明文消息与附件、解码 agent 的回复与
  交付物。hub 因此是会话的一个端点，既能读到内容，又能以自己的密钥代签，与"hub 只做传输、不得看到
  任务内容"的决定不能同时成立。
- 新注册的 agent 默认对匿名访客开放 5 条消息（`guest_quota`），与"全新安装不接受任何人的委派"的
  默认安全决定冲突。

现状：hub 不路由 `/guest/*`，`agent` 表没有 `guest_quota` 列，web UI 没有试聊入口。委派任务需要在
本机运行 anet。面向浏览器的"无需安装即可试用"由官方公共 agent 提供（A2A-DESIGN §15），不经 hub
代理。生产主机上遗留的 broker 私钥 `data/guest_identity.kel` 由 `deploy/cleanup-content-v0.2.sh`
删除（须经产品负责人同意）。
