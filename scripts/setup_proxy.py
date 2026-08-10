#!/usr/bin/env python3
"""拉取订阅并生成 mihomo 配置文件。

支持格式：
  - Clash YAML 配置（直接保存）
  - Base64 编码的 vmess/vless/trojan/ss 订阅

用法:
  python setup_proxy.py <订阅 URL> <输出文件路径>
"""
import sys
import base64
import json
import requests
import yaml


def decode_base64(text: str) -> str:
    """安全解码 base64，自动补齐 padding。"""
    text = text.strip()
    try:
        return base64.b64decode(text + "=" * (-len(text) % 4)).decode("utf-8")
    except Exception:
        return text


def parse_vmess(uri: str) -> dict:
    """解析 vmess:// 链接。"""
    info = json.loads(decode_base64(uri[8:]))
    proxy = {
        "name": info.get("ps") or f"{info.get('add')}:{info.get('port')}",
        "type": "vmess",
        "server": info.get("add"),
        "port": int(info.get("port", 0)),
        "uuid": info.get("id"),
        "alterId": int(info.get("aid", 0)),
        "cipher": info.get("scy", "auto"),
        "network": info.get("net", "ws"),
    }
    if info.get("net", "ws") == "ws":
        ws_opts = {"path": info.get("path", "/")}
        host = info.get("host") or info.get("add")
        if host:
            ws_opts["headers"] = {"Host": host}
        proxy["ws-opts"] = ws_opts
    if info.get("tls") == "tls":
        proxy["tls"] = True
        proxy["servername"] = info.get("sni") or info.get("add")
    return proxy


def parse_vless(uri: str) -> dict:
    """解析 vless:// 链接。"""
    from urllib.parse import urlparse, parse_qs, unquote

    parsed = urlparse(uri)
    query = parse_qs(parsed.query)
    name = unquote(parsed.fragment) or f"{parsed.hostname}:{parsed.port}"
    proxy = {
        "name": name,
        "type": "vless",
        "server": parsed.hostname,
        "port": parsed.port or 443,
        "uuid": parsed.username,
        "network": query.get("type", ["tcp"])[0],
        "tls": query.get("security", [""])[0] == "tls",
        "udp": True,
    }
    if proxy["network"] == "ws":
        proxy["ws-opts"] = {"path": query.get("path", ["/"])[0]}
        host = query.get("host", [None])[0]
        if host:
            proxy["ws-opts"]["headers"] = {"Host": host}
    return proxy


def parse_trojan(uri: str) -> dict:
    """解析 trojan:// 链接。"""
    from urllib.parse import urlparse, parse_qs, unquote

    parsed = urlparse(uri)
    query = parse_qs(parsed.query)
    name = unquote(parsed.fragment) or f"{parsed.hostname}:{parsed.port}"
    return {
        "name": name,
        "type": "trojan",
        "server": parsed.hostname,
        "port": parsed.port or 443,
        "password": parsed.username,
        "sni": query.get("sni", [parsed.hostname])[0],
        "udp": True,
    }


def parse_ss(uri: str) -> dict:
    """解析 ss:// 链接。"""
    from urllib.parse import urlparse, unquote

    # ss://base64(method:password)@host:port#name  或  ss://base64@host:port#name
    parsed = urlparse(uri)
    name = unquote(parsed.fragment) or f"{parsed.hostname}:{parsed.port}"
    user_info = parsed.username or ""
    try:
        decoded = decode_base64(user_info)
        method, password = decoded.split(":", 1)
    except Exception:
        method, password = user_info.split(":", 1) if ":" in user_info else ("none", "")
    return {
        "name": name,
        "type": "ss",
        "server": parsed.hostname,
        "port": parsed.port or 443,
        "cipher": method,
        "password": password,
    }


def parse_subscription(content: str) -> list:
    """解析订阅内容，返回 mihomo proxies 列表。"""
    content = content.strip()

    # 1. 尝试作为 Clash YAML 解析
    if content.startswith(("{", "port", "mixed-port", "proxies")):
        try:
            data = yaml.safe_load(content)
            if isinstance(data, dict) and "proxies" in data:
                return data["proxies"]
        except Exception:
            pass

    # 2. 尝试作为 base64 编码的订阅链接列表解码
    decoded = decode_base64(content)
    if "://" not in decoded:
        decoded = content  # 可能本身就是明文链接列表

    proxies = []
    for line in decoded.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            if line.startswith("vmess://"):
                proxies.append(parse_vmess(line))
            elif line.startswith("vless://"):
                proxies.append(parse_vless(line))
            elif line.startswith("trojan://"):
                proxies.append(parse_trojan(line))
            elif line.startswith("ss://"):
                proxies.append(parse_ss(line))
        except Exception as e:
            print(f"跳过无法解析的节点: {e}", file=sys.stderr)

    return proxies


def generate_mihomo_config(proxies: list) -> dict:
    """生成 mihomo 配置字典。"""
    # 过滤掉明显无效的节点（如"剩余流量""套餐到期""过滤掉"）
    valid_proxies = []
    for p in proxies:
        name = p.get("name", "")
        if any(kw in name for kw in ["剩余流量", "套餐到期", "过期", "官网", "过滤"]):
            continue
        valid_proxies.append(p)

    if not valid_proxies:
        raise ValueError("没有可用的代理节点")

    return {
        "mixed-port": 7890,
        "mode": "rule",
        "log-level": "warning",
        "proxies": valid_proxies,
        "proxy-groups": [
            {
                "name": "PROXY",
                "type": "url-test",
                "proxies": [p["name"] for p in valid_proxies],
                "url": "https://www.gstatic.com/generate_204",
                "interval": 300,
            }
        ],
        "rules": ["MATCH,PROXY"],
    }


def main():
    if len(sys.argv) != 3:
        print("用法: python setup_proxy.py <订阅 URL> <输出文件路径>")
        sys.exit(1)

    sub_url, output_path = sys.argv[1], sys.argv[2]

    # 脱敏：只显示域名，隐藏 token 等敏感参数
    from urllib.parse import urlparse
    parsed = urlparse(sub_url)
    masked_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
    print(f"拉取订阅: {masked_url}")
    r = requests.get(sub_url, timeout=30, headers={"User-Agent": "clash-meta"})
    r.raise_for_status()

    print(f"解析订阅内容 (长度: {len(r.text)})...")
    proxies = parse_subscription(r.text)
    print(f"解析到 {len(proxies)} 个节点")

    config = generate_mihomo_config(proxies)
    print(f"生成 mihomo 配置 ({len(config['proxies'])} 个有效节点)")

    with open(output_path, "w", encoding="utf-8") as f:
        yaml.dump(config, f, allow_unicode=True, default_flow_style=False)

    print(f"配置已保存到: {output_path}")
    print(f"首个节点: {config['proxies'][0]['name']}")


if __name__ == "__main__":
    main()
