#!/usr/bin/env python3
"""
AgentRouter 自动签到（GitHub OAuth 重放方案）

原理：AgentRouter 没有签到 API，签到是 OAuth 登录的副作用。
本脚本通过模拟 GitHub OAuth 登录流程触发签到：
  1. GET /api/oauth/state          → 获取 state + acw_tc cookie
  2. GET github.com/login/oauth/authorize  → 用 GitHub user_session cookie 自动授权，从 302 提取 code
  3. GET /api/oauth/github?code=...&state=... → 回调登录，触发签到，返回 checked_in

所需环境变量：
  GH_SESSION      GitHub 的 user_session cookie 值（必填）
  PROXY_URL       HTTP/SOCKS5 代理地址（可选，GitHub Actions 数据中心 IP 可能被 WAF 拦截时使用）
"""

import os
import sys
import re
import json
import requests
import traceback
from datetime import datetime

# 环境变量配置
GH_SESSION = os.getenv("GH_SESSION", "").strip()  # GitHub 的 user_session cookie
PROXY_URL      = os.getenv("PROXY_URL", "").strip()       # 可选代理，如 http://127.0.0.1:7890 或 socks5://...

SITE_URL = "https://agentrouter.org"
GITHUB_CLIENT_ID = "Ov23lidtiR4LeVZvVRNL"  # agentrouter 的 GitHub OAuth client_id（从 /api/status 获取）
QUOTA_PER_DOLLAR = 500000

UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/138.0.0.0 Safari/537.36"
)


def log(level: str, msg: str):
    """日志输出。DEBUG 级别受 DEBUG 环境变量控制（默认开启便于诊断）"""
    if level == "DEBUG" and os.getenv("DEBUG", "1").lower() in ("0", "false", "no"):
        return
    ts = datetime.now().strftime("%H:%M:%S")
    print(f"[{ts}] [{level}] {msg}", flush=True)


def build_session() -> requests.Session:
    """构建请求会话，按需配置代理"""
    sess = requests.Session()
    sess.headers.update({
        "User-Agent": UA,
        "Accept": "application/json, text/plain, */*",
        "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8",
        "Referer": SITE_URL,
        "Origin": SITE_URL,
    })
    if PROXY_URL:
        proxies = {"http": PROXY_URL, "https": PROXY_URL}
        sess.proxies.update(proxies)
        log("INFO", f"使用代理: {PROXY_URL}")
    else:
        log("INFO", "直连模式（未配置代理）")
    return sess


def get_oauth_state(sess: requests.Session) -> str | None:
    """Step 1: 获取 OAuth state，同时拿到 acw_tc + session cookie"""
    log("INFO", "Step 1: 获取 OAuth state...")
    req_url = f"{SITE_URL}/api/oauth/state?mode=login"
    log("DEBUG", f"请求: GET {req_url}")
    log("DEBUG", f"当前会话 cookies: {dict(sess.cookies)}")

    try:
        resp = sess.get(req_url, timeout=30)
    except Exception as e:
        log("ERROR", f"请求 /api/oauth/state 失败: {type(e).__name__}: {e}")
        return None

    log("DEBUG", f"响应: HTTP {resp.status_code}")
    log("DEBUG", f"响应头: Content-Type={resp.headers.get('Content-Type')}, Content-Length={resp.headers.get('Content-Length')}")
    log("DEBUG", f"Set-Cookie: {resp.headers.get('Set-Cookie', '(无)')}")
    log("DEBUG", f"响应 body 前 500 字符: {resp.text[:500]!r}")

    if "aliyun_waf_aa" in resp.text:
        log("ERROR", "被阿里云 WAF 拦截（IP 信誉或频率限制），请配置代理或稍后重试")
        log("ERROR", f"完整 WAF 拦截页面前 1000 字符:\n{resp.text[:1000]}")
        return None

    try:
        data = resp.json()
    except Exception:
        log("ERROR", f"响应非 JSON: HTTP {resp.status_code}, body={resp.text[:200]!r}")
        return None

    if not data.get("success"):
        log("ERROR", f"获取 state 失败: {data}")
        return None

    state = data.get("data", "")
    if not state:
        log("ERROR", "state 为空")
        return None

    log("INFO", f"✅ 获取 state 成功: {state[:32]}... (cookies: {list(sess.cookies.keys())})")
    return state


def get_github_code(sess: requests.Session, state: str) -> str | None:
    """Step 2: 用 GitHub user_session 访问授权 URL，从 302 Location 提取 code"""
    log("INFO", "Step 2: GitHub OAuth 授权，提取 code...")
    auth_url = f"https://github.com/login/oauth/authorize?client_id={GITHUB_CLIENT_ID}&state={state}"
    github_cookies = {"user_session": GH_SESSION}
    log("DEBUG", f"请求: GET {auth_url}")
    log("DEBUG", f"GitHub user_session 长度: {len(GH_SESSION)}, 前 8 字符: {GH_SESSION[:8]}...")
    log("DEBUG", f"附加 cookies: {list(github_cookies.keys())}")

    try:
        # 不自动跟随重定向，从 Location 头提取 code
        resp = sess.get(auth_url, cookies=github_cookies, allow_redirects=False, timeout=30)
    except Exception as e:
        log("ERROR", f"请求 GitHub 授权失败: {type(e).__name__}: {e}")
        return None

    log("DEBUG", f"响应: HTTP {resp.status_code}")
    log("DEBUG", f"响应头 Location: {resp.headers.get('Location', '(无)')}")
    log("DEBUG", f"响应头 Set-Cookie: {resp.headers.get('Set-Cookie', '(无)')}")
    log("DEBUG", f"响应 body 前 500 字符: {resp.text[:500]!r}")

    if resp.status_code == 401 or resp.status_code == 403:
        log("ERROR", f"GitHub user_session 已失效（HTTP {resp.status_code}），请重新获取")
        return None

    if resp.status_code != 302:
        log("ERROR", f"GitHub 未返回 302 重定向（HTTP {resp.status_code}），user_session 可能已失效")
        log("ERROR", f"响应 body 前 500: {resp.text[:500]!r}")
        return None

    location = resp.headers.get("Location", "")
    if not location:
        log("ERROR", "302 响应缺少 Location 头")
        return None

    code_match = re.search(r"[?&]code=([^&]+)", location)
    if not code_match:
        log("ERROR", f"Location 中未找到 code: {location[:200]}")
        return None

    code = code_match.group(1)
    log("INFO", f"✅ 提取到 GitHub code: {code[:16]}...")
    log("DEBUG", f"完整 Location: {location}")
    return code


def oauth_callback(sess: requests.Session, code: str, state: str) -> dict | None:
    """Step 3: 调用 /api/oauth/github 回调，触发签到"""
    log("INFO", "Step 3: OAuth 回调，触发签到...")
    callback_url = f"{SITE_URL}/api/oauth/github?code={code}&state={state}&mode=login"
    log("DEBUG", f"请求: GET {callback_url}")
    log("DEBUG", f"会话 cookies: {dict(sess.cookies)}")

    try:
        resp = sess.get(callback_url, timeout=30)
    except Exception as e:
        log("ERROR", f"OAuth 回调请求失败: {type(e).__name__}: {e}")
        return None

    log("DEBUG", f"响应: HTTP {resp.status_code}")
    log("DEBUG", f"响应头: Content-Type={resp.headers.get('Content-Type')}")
    log("DEBUG", f"Set-Cookie: {resp.headers.get('Set-Cookie', '(无)')}")
    log("DEBUG", f"响应 body 前 1000 字符: {resp.text[:1000]!r}")

    if "aliyun_waf_aa" in resp.text:
        log("ERROR", "回调被阿里云 WAF 拦截")
        log("ERROR", f"完整 WAF 拦截页面前 1000 字符:\n{resp.text[:1000]}")
        return None

    try:
        data = resp.json()
    except Exception:
        log("ERROR", f"回调响应非 JSON: HTTP {resp.status_code}, body={resp.text[:500]!r}")
        return None

    if not data.get("success"):
        log("ERROR", f"OAuth 回调失败: {data}")
        return None

    user_data = data.get("data", {})
    log("DEBUG", f"回调返回字段: {list(user_data.keys())}")
    return user_data


def format_balance(quota: int) -> str:
    if quota is None:
        return "N/A"
    balance = quota / QUOTA_PER_DOLLAR
    if balance == int(balance):
        return f"{int(balance)}$"
    return f"{balance:.2f}$"


def run_checkin():
    log("INFO", "=" * 50)
    log("INFO", "AgentRouter 签到脚本启动（OAuth 重放方案）")
    log("INFO", f"时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    log("INFO", "=" * 50)

    if not GH_SESSION:
        log("ERROR", "GH_SESSION 未配置！请设置 GitHub 的 user_session cookie")
        log("ERROR", "获取方式：浏览器登录 github.com → F12 → Application → Cookies → user_session")
        sys.exit(1)

    sess = build_session()

    # 检测出口 IP（诊断代理是否生效）
    if PROXY_URL:
        try:
            ip_resp = sess.get("https://api.ipify.org?format=json", timeout=15)
            exit_ip = ip_resp.json().get("ip", "unknown")
            log("INFO", f"当前出口 IP: {exit_ip}")
        except Exception as e:
            log("WARN", f"无法获取出口 IP: {e}")

    # Step 1: 获取 state
    state = get_oauth_state(sess)
    if not state:
        sys.exit(1)

    # Step 2: GitHub 授权拿 code
    code = get_github_code(sess, state)
    if not code:
        sys.exit(1)

    # Step 3: OAuth 回调触发签到
    user_data = oauth_callback(sess, code, state)
    if not user_data:
        sys.exit(1)

    # 结果展示
    username   = user_data.get("username", "")
    display    = user_data.get("display_name", "")
    uid        = user_data.get("id", "")
    quota      = user_data.get("quota", 0)
    used       = user_data.get("used_quota", 0)
    checked_in = user_data.get("checked_in")

    log("INFO", "=" * 50)
    log("INFO", f"✅ 登录成功: {username} ({display})")
    log("INFO", f"   用户 ID: {uid}")
    log("INFO", f"   当前余额: {format_balance(quota)} (quota={quota})")
    log("INFO", f"   已用额度: {format_balance(used)} (used_quota={used})")
    log("INFO", f"   今日签到: {'✅ 已签到' if checked_in else '❌ 未签到'}")
    log("INFO", "=" * 50)
    log("INFO", "=== 签到流程完成 ===")


def main():
    try:
        run_checkin()
    except KeyboardInterrupt:
        log("WARN", "用户中断")
        sys.exit(130)
    except Exception as e:
        log("ERROR", f"脚本执行出错: {type(e).__name__}: {e}")
        log("ERROR", traceback.format_exc())
        sys.exit(1)


if __name__ == "__main__":
    main()
