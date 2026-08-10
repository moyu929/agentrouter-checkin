# AgentRouter 自动签到（GitHub Actions）

针对 https://agentrouter.org 的每日签到自动化。

## 原理

AgentRouter **没有签到 API**，签到是 OAuth 登录的副作用——每次成功登录时后端自动发放每日额度，响应中返回 `checked_in: true`。

本脚本通过模拟 GitHub OAuth 登录流程触发签到：
1. `GET /api/oauth/state` → 获取 state + acw_tc cookie
2. `GET github.com/login/oauth/authorize` → 用 GitHub `user_session` cookie 自动授权，从 302 提取 code
3. `GET /api/oauth/github?code=...&state=...` → 回调登录，触发签到

## Secrets 配置

fork 本项目或 push 到你自己的仓库后，在 **Settings → Secrets and variables → Actions** 添加：

| Secret 名称 | 是否必填 | 说明 |
|---|---|---|
| `GITHUB_SESSION` | ✅ 必填 | GitHub 的 `user_session` cookie 值 |
| `PROXY_URL` | ❌ 可选 | 代理地址（如 `http://host:port` 或 `socks5://host:port`），GitHub Actions 数据中心 IP 可能被阿里云 WAF 拦截时使用 |

## 获取 GitHub `user_session`

1. 浏览器登录 https://github.com
2. 按 F12（或右键 → 检查）
3. 顶部切到 **Application / 应用程序 → Cookies → `https://github.com`**
4. 找到名为 `user_session` 的 Cookie，复制它的值
5. 填入仓库 `GITHUB_SESSION` Secret

> 💡 `user_session` 有效期通常为数月，比 agentrouter session 划算得多。失效后脚本会报 `GitHub user_session 已失效`，重新获取即可。

## 验证授权

首次使用前，在已登录 GitHub 的浏览器访问以下 URL，确认能自动跳转回 agentrouter（不显示授权页面）：

```
https://github.com/login/oauth/authorize?client_id=Ov23lidtiR4LeVZvVRNL&state=test123
```

如果跳转到 agentrouter 说明已授权过；如果显示授权页面，点击 Authorize 即可。

## 工作流

- 定时：每天 `01:00 UTC`（北京时间 09:00）自动触发一次
- 手动：**Actions → AgentRouter Daily Check-in → Run workflow**
- 完成后会清理旧的 run 记录，保留最近 1 条

## 关于 IP 信誉问题

GitHub Actions 使用 Azure 数据中心 IP，可能被阿里云 WAF 的 IP 信誉机制拦截。如遇到 WAF 拦截，配置 `PROXY_URL` Secret 走代理即可。
