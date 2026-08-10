#!/usr/bin/env python3

import os
import sys
import base64
import json
import time
import subprocess
import requests
import traceback
from datetime import datetime, timezone, timedelta
from playwright.sync_api import sync_playwright

# 环境变量配置(session建议填写secrets,需要自动更新)
# 单账号：SESSION="xxx"
# 多账号：SESSIONS 传 JSON，例如 [{"name":"a","session":"xxx1","user_id":"1"},{"name":"b","session":"xxx2","user_id":"2"}]
#         或用逗号分隔的 SESSION 列表：SESSION="xxx1,xxx2" （与 SESSION_USER_IDS 按顺序对应）
USER_ID      = os.getenv("USER_ID") or ""  # 单账号:用户ID,必填或自动获取
SESSION      = os.getenv("SESSION") or ""  # 单账号 session 或 逗号分隔多 session
SESSIONS     = os.getenv("SESSIONS") or ""  # 多账号 JSON 列表
SESSION_IDS  = os.getenv("SESSION_IDS") or ""  # 与逗号分隔 SESSION 对应的 user_id 列表
TG_BOT_TOKEN = os.getenv("TG_BOT_TOKEN") or ""  # Telegram bot token,不需要通知可以留空
TG_CHAT_ID   = os.getenv("TG_CHAT_ID") or ""    # Telegram chat id

SITE_URL = "https://agentrouter.org"
SESSION_TTL_DAYS = 30
SESSION_THRESHOLD_DAYS = 3
QUOTA_PER_DOLLAR = 500000
WAF_COOKIE_NAMES = ["acw_tc", "cdn_sec_tc", "acw_sc__v2"]

# 工具函数
def log(level: str, msg: str):
    ts = datetime.now().strftime("%H:%M:%S")
    print(f"[{ts}] [{level}] {msg}", flush=True)

def decode_session_timestamp(session_value: str) -> int | None:
    if not session_value:
        return None
    parts = session_value.split("|")
    if parts and parts[0].strip().isdigit():
        return int(parts[0].strip())
    if "%7C" in session_value or "%7c" in session_value:
        decoded_url = session_value.replace("%7C", "|").replace("%7c", "|")
        parts = decoded_url.split("|")
        if parts and parts[0].strip().isdigit():
            return int(parts[0].strip())
    try:
        padded = session_value + "=" * (4 - len(session_value) % 4) if len(session_value) % 4 else session_value
        try:
            decoded = base64.urlsafe_b64decode(padded)
        except Exception:
            decoded = base64.b64decode(padded)
        decoded_str = decoded.decode("utf-8", errors="ignore")
        parts = decoded_str.split("|")
        if parts and parts[0].strip().isdigit():
            return int(parts[0].strip())
    except Exception:
        pass
    return None

def check_session_expiry(session_value: str):
    timestamp = decode_session_timestamp(session_value)
    if not timestamp:
        log("WARN", "无法解码 Session 时间戳，跳过期检查")
        return None, False
    created_time = datetime.fromtimestamp(timestamp, tz=timezone.utc)
    expiry_time = created_time + timedelta(days=SESSION_TTL_DAYS)
    now = datetime.now(tz=timezone.utc)
    remaining = expiry_time - now
    remaining_days = remaining.total_seconds() / 86400
    created_local = created_time.astimezone().strftime("%Y-%m-%d %H:%M:%S")
    expiry_local = expiry_time.astimezone().strftime("%Y-%m-%d %H:%M:%S")
    log("INFO", f"Session 创建时间: {created_local}")
    log("INFO", f"Session 过期时间: {expiry_local}")
    log("INFO", f"剩余有效时间: {remaining_days:.2f} 天")
    need_update = remaining_days < SESSION_THRESHOLD_DAYS
    if need_update:
        log("WARN", f"Session 剩余 {remaining_days:.2f} 天 < {SESSION_THRESHOLD_DAYS} 天，需要更新！")
    return remaining_days, need_update

def update_github_secret(secret_name: str, new_value: str) -> bool:
    if not new_value:
        log("WARN", f"跳过更新 {secret_name}：新值为空")
        return False
    masked = new_value[:4] + "..." + new_value[-4:] if len(new_value) > 8 else "***"
    log("INFO", f"🔄 更新 Secret: {secret_name} (新值: {masked})")
    try:
        proc = subprocess.run(
            ["gh", "secret", "set", secret_name, "--body", new_value],
            capture_output=True, text=True, timeout=30, check=False,
        )
        if proc.returncode == 0:
            log("INFO", f"✅ {secret_name} 更新成功")
            return True
        else:
            log("ERROR", f"更新失败: {proc.stderr.strip()}")
            return False
    except Exception as e:
        log("ERROR", f"异常: {e}")
        return False

def send_telegram(message: str) -> bool:
    if not TG_BOT_TOKEN or not TG_CHAT_ID:
        log("WARN", "Telegram 配置不完整，跳过发送")
        print(f"--- 消息内容 ---\n{message}\n---------------")
        return False
    try:
        url = f"https://api.telegram.org/bot{TG_BOT_TOKEN}/sendMessage"
        data = {"chat_id": TG_CHAT_ID, "text": message, "parse_mode": "HTML"}
        resp = requests.post(url, json=data, timeout=30)
        resp.raise_for_status()
        log("INFO", "Telegram 消息发送成功")
        return True
    except Exception as e:
        log("ERROR", f"Telegram 发送失败: {e}")
        return False

# WAF Cookie 获取
def get_waf_cookies() -> dict:
    log("INFO", f"使用浏览器获取 WAF Cookie（访问 {SITE_URL}）...")
    waf_cookies = {}
    with sync_playwright() as p:
        browser = p.chromium.launch(
            headless=True,
            args=[
                "--no-sandbox",
                "--disable-setuid-sandbox",
                "--disable-dev-shm-usage",
                "--disable-gpu",
            ],
        )
        context = browser.new_context(
            viewport={"width": 1280, "height": 720},
            user_agent=(
                "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
                "(KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36"
            ),
        )
        page = context.new_page()
        try:
            # networkidle 等待网络空闲，确保阿里云 WAF 的 JS 挑战脚本执行完成
            page.goto(f"{SITE_URL}", wait_until="networkidle", timeout=30000)
        except Exception as e:
            log("WARN", f"访问首页失败: {e}")
        # 显式等待 WAF 挑战完成会种下 acw_sc__v2（关键），最多等 15 秒
        deadline = time.time() + 15
        got_critical = False
        while time.time() < deadline:
            current = {c.get("name"): c.get("value") for c in context.cookies()}
            if "acw_sc__v2" in current:
                got_critical = True
                break
            page.wait_for_timeout(500)
        if not got_critical:
            log("WARN", "等待 acw_sc__v2 超时（WAF 挑战可能未通过），继续尝试使用已有 cookie")
        cookies = context.cookies()
        for cookie in cookies:
            name = cookie.get("name")
            value = cookie.get("value")
            if name in WAF_COOKIE_NAMES and value:
                waf_cookies[name] = value
        browser.close()
    if waf_cookies:
        log("INFO", f"获取到 {len(waf_cookies)} 个 WAF Cookie: {list(waf_cookies.keys())}")
    else:
        log("WARN", "未获取到 WAF Cookie")
    return waf_cookies

# API 调用
def build_headers() -> dict:
    return {
        "User-Agent": (
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
            "(KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36"
        ),
        "Accept": "application/json, text/plain, */*",
        "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8",
        "Accept-Encoding": "gzip, deflate, br, zstd",
        "Referer": SITE_URL,
        "Origin": SITE_URL,
        "Connection": "keep-alive",
        "Sec-Fetch-Dest": "empty",
        "Sec-Fetch-Mode": "cors",
        "Sec-Fetch-Site": "same-origin",
        "new-api-user": USER_ID,
    }

def get_user_info(session: requests.Session, headers: dict) -> dict | None:
    url = f"{SITE_URL}/api/user/self"
    try:
        resp = session.get(url, headers=headers, timeout=30)
        content_type = resp.headers.get("Content-Type", "")
        # 200 但响应不是 JSON（WAF 拦截页、空响应等）：打印真实内容便于排查
        if "application/json" not in content_type.lower() and not resp.text.lstrip().startswith(("{", "[")):
            preview = resp.text[:300].replace("\n", " ")
            log("WARN", f"API 响应非 JSON: HTTP {resp.status_code}, Content-Type={content_type!r}, body={preview!r}")
            return None
        if resp.status_code == 200:
            data = resp.json()
            if data.get("success"):
                user_data = data.get("data", {})
                return {
                    "quota": user_data.get("quota", 0),
                    "used_quota": user_data.get("used_quota", 0),
                    "username": user_data.get("username", ""),
                    "id": user_data.get("id", 0),
                    "raw": user_data,
                }
            else:
                log("WARN", f"API 返回非成功: {data}")
        else:
            preview = resp.text[:300].replace("\n", " ")
            log("WARN", f"API HTTP {resp.status_code}: Content-Type={content_type!r}, body={preview!r}")
    except Exception as e:
        # 兜底：异常时也尽量输出当时拿到的响应体片段
        try:
            preview = resp.text[:300].replace("\n", " ")
        except Exception:
            preview = "<no response body>"
        log("WARN", f"获取用户信息失败: {e} | body={preview!r}")
    return None

def do_check_in(session: requests.Session, headers: dict) -> bool:
    # New API 标准签到接口；部分部署用 /api/user/sign_in
    for path in ("/api/user/sign_in", "/api/user/checkin"):
        url = f"{SITE_URL}{path}"
        checkin_headers = headers.copy()
        checkin_headers["Content-Type"] = "application/json"
        checkin_headers["X-Requested-With"] = "XMLHttpRequest"
        try:
            resp = session.post(url, headers=checkin_headers, timeout=30)
            log("INFO", f"签到接口响应 ({path}): HTTP {resp.status_code}")
            if resp.status_code == 200:
                try:
                    result = resp.json()
                    if result.get("ret") == 1 or result.get("code") == 0 or result.get("success"):
                        log("INFO", "✅ 签到成功！")
                        return True
                    error_msg = result.get("msg", result.get("message", "Unknown error"))
                    already_keywords = ["已经签到", "已签到", "重复签到", "already checked", "already signed"]
                    if any(kw in str(error_msg).lower() for kw in already_keywords):
                        log("INFO", "今日已签到过")
                        return True
                    log("WARN", f"签到失败: {error_msg}")
                except json.JSONDecodeError:
                    if "success" in resp.text.lower():
                        log("INFO", "✅ 签到成功！")
                        return True
                    log("WARN", f"签到响应格式异常: {resp.text[:200]}")
            else:
                log("WARN", f"签到失败: HTTP {resp.status_code}: {resp.text[:200]}")
        except Exception as e:
            log("ERROR", f"签到请求异常: {e}")
    return False

def format_balance(quota: int) -> str:
    if quota is None:
        return "N/A"
    balance = quota / QUOTA_PER_DOLLAR
    if balance == int(balance):
        return f"{int(balance)}$"
    return f"{balance:.2f}$"

# 主流程
def parse_accounts() -> list[dict]:
    """解析账号列表，返回 [{name, session, user_id?}, ...]

    兼容三种填法：
      1) SESSIONS 为 JSON 数组：[{"name":"A","session":"xxx","user_id":"1"}, ...]
      2) SESSIONS 为逗号分隔的纯 session：sess1,sess2
      3) 单账号 SESSION：xxx（或 SESSION 逗号分隔多账号）
    """
    accounts: list[dict] = []
    if SESSIONS and SESSIONS.strip():
        txt = SESSIONS.strip().lstrip("\ufeff").strip()
        # 尝试按 JSON 解析
        try:
            data = json.loads(txt)
            if isinstance(data, list):
                for item in data:
                    if isinstance(item, dict) and item.get("session"):
                        accounts.append({
                            "name": str(item.get("name") or str(item["session"])[:8]),
                            "session": str(item["session"]),
                            "user_id": str(item.get("user_id") or ""),
                        })
        except Exception:
            pass
        # JSON 解析失败或没解析出账号：按逗号分隔纯 session 处理
        if not accounts:
            sessions = [s.strip() for s in txt.replace("\n", ",").split(",") if s.strip()]
            accounts = [
                {"name": f"账号{i+1}", "session": s, "user_id": ""}
                for i, s in enumerate(sessions)
            ]
        if accounts:
            return accounts
    if SESSION:
        sessions = [s.strip() for s in SESSION.split(",") if s.strip()]
        ids = [s.strip() for s in SESSION_IDS.split(",") if s.strip()] if SESSION_IDS else []
        accounts = [
            {"name": f"账号{i+1}", "session": s, "user_id": ids[i] if i < len(ids) else ""}
            for i, s in enumerate(sessions)
        ]
    return accounts

def run_account_checkin(account: dict) -> dict:
    """对单个账号执行签到，返回结果统计"""
    SESSION  = account["session"]
    USER_ID  = account.get("user_id") or ""
    acct_name = account.get("name", SESSION[:8])
    now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log("INFO", "=" * 50)
    log("INFO", f"Agentrouter 领币脚本启动 - {acct_name}")
    log("INFO", f"时间: {now_str}")
    log("INFO", f"用户 ID: {USER_ID or 'auto'}")
    log("INFO", "=" * 50)

    if not SESSION:
        log("ERROR", "SESSION 未配置，请设置 SESSION 环境变量")
        return {"name": acct_name, "ok": False, "reason": "SESSION 未配置"}

    waf_cookies = get_waf_cookies()
    session = requests.Session()
    domain = SITE_URL.replace("https://", "").replace("http://", "").split("/")[0]
    all_cookies = {}
    all_cookies.update(waf_cookies)
    all_cookies["session"] = SESSION
    if USER_ID:
        all_cookies["user_id"] = USER_ID
    for name, value in all_cookies.items():
        session.cookies.set(name, value, domain=domain, path="/")
    log("INFO", f"已设置 {len(all_cookies)} 个 Cookie: {list(all_cookies.keys())}")

    headers = build_headers()
    user_info_1 = get_user_info(session, headers)
    if not user_info_1:
        log("ERROR", f"[{acct_name}] API 验证失败，Session 可能已过期")
        return {"name": acct_name, "ok": False, "reason": "session 过期或 WAF 未通过"}

    log("INFO", f"✅ 登录成功: {user_info_1.get('username')} (id={user_info_1.get('id')})")
    if not USER_ID and user_info_1.get("id"):
        headers["new-api-user"] = str(user_info_1["id"])

    first_balance = format_balance(user_info_1.get("quota", 0))
    log("INFO", f"初始余额: {first_balance}")

    checkin_success = do_check_in(session, headers)
    time.sleep(3)
    user_info_2 = get_user_info(session, headers)
    second_balance = format_balance(user_info_2.get("quota", 0)) if user_info_2 else "N/A"
    log("INFO", f"刷新后余额: {second_balance}")

    result = {
        "name": acct_name,
        "ok": checkin_success,
        "username": user_info_1.get("username", ""),
        "first": first_balance,
        "second": second_balance,
        "success": checkin_success,
    }
    log("INFO", f"[{acct_name}] 执行完毕: 签到={'成功' if checkin_success else '失败/重复'}")
    return result

def run_checkin():
    accounts = parse_accounts()
    if not accounts:
        log("ERROR", "未配置任何账号！请设置 SESSIONS（JSON 数组或逗号分隔 session）或 SESSION")
        sys.exit(1)
    log("INFO", f"共解析 {len(accounts)} 个账号: {[a['name'] for a in accounts]}")

    lines = ["🎁 <b>Agentrouter 签到通知</b>", f"📅 {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", ""]
    all_result = []
    for acct in accounts:
        r = run_account_checkin(acct)
        all_result.append(r)
        icon = "✅" if r.get("ok") else "❌"
        lines.append(f"{icon} {r.get('name','')} ({r.get('username','')})  {r.get('first','')}→{r.get('second','')}  {r.get('reason','')}")
    send_telegram("\n".join(lines))
    log("INFO", "=== 全部账号执行完毕 ===")

def main():
    try:
        run_checkin()
    except KeyboardInterrupt:
        log("WARN", "用户中断")
        sys.exit(130)
    except Exception as e:
        error_msg = f"{type(e).__name__}: {e}"
        log("ERROR", f"脚本执行出错: {error_msg}")
        log("ERROR", traceback.format_exc())
        send_telegram(
            f"❌ <b>Agentrouter 脚本异常</b>\n"
            f"👤 账户: {USER_ID or 'unknown'}\n"
            f"⏱️ 时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
            f"📝 错误: {error_msg}"
        )
        sys.exit(1)

if __name__ == "__main__":
    main()
