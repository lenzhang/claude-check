#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Claude AI - 终极环境安全深度检测工具 (Pro 版)
融合本地网络防漏检测 (IPv6/DNS/时区/语言) + 目标服务器 WAF 穿透探测
零依赖，原生支持 macOS / Linux / Windows
"""

import argparse
import datetime
import json
import locale
import os
import platform
import re
import socket
import sys
import time
import urllib.error
import urllib.request

# ─── 常量 ───────────────────────────────────────────────────────────────

CHROME_UA = (
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) '
    'AppleWebKit/537.36 (KHTML, like Gecko) '
    'Chrome/125.0.0.0 Safari/537.36'
)

# 模拟浏览器的完整请求头（注意：仍无法模拟浏览器 TLS/HTTP2 指纹，
# Under Attack 模式下非浏览器客户端必定收到 challenge）
BROWSER_HEADERS = {
    'User-Agent': CHROME_UA,
    'Accept': ('text/html,application/xhtml+xml,application/xml;q=0.9,'
               'image/avif,image/webp,*/*;q=0.8'),
    'Accept-Language': 'en-US,en;q=0.9',
    'Sec-Ch-Ua': '"Chromium";v="125", "Google Chrome";v="125", "Not.A/Brand";v="24"',
    'Sec-Ch-Ua-Mobile': '?0',
    'Sec-Ch-Ua-Platform': '"Windows"',
    'Sec-Fetch-Dest': 'document',
    'Sec-Fetch-Mode': 'navigate',
    'Sec-Fetch-Site': 'none',
    'Sec-Fetch-User': '?1',
    'Upgrade-Insecure-Requests': '1',
}

# Cloudflare cf-mitigated 中代表"不可解硬拦截"的值（浏览器也过不去）
HARD_BLOCK_MARKERS = ['block']

CF_CHALLENGE_MARKERS = [
    'challenges.cloudflare.com',
    'cf-turnstile',
    '_cf_chl_opt',
    'managed_checking',
]

IPAPI_FIELDS = ("status,country,countryCode,city,isp,org,as,"
                "mobile,proxy,hosting,query,timezone,offset")

# 国家代码 → 常见系统语言前缀映射（用于语言匹配检测）
COUNTRY_LANG_MAP = {
    'US': ['en'], 'GB': ['en'], 'AU': ['en'], 'CA': ['en', 'fr'],
    'JP': ['ja'], 'KR': ['ko'], 'DE': ['de'], 'FR': ['fr'],
    'TW': ['zh'], 'HK': ['zh', 'en'], 'SG': ['en', 'zh'],
    'BR': ['pt'], 'RU': ['ru'], 'IN': ['en', 'hi'],
    'NL': ['nl', 'en'], 'SE': ['sv', 'en'], 'NO': ['no', 'nb', 'nn', 'en'],
    'DK': ['da', 'en'], 'FI': ['fi', 'en'], 'IT': ['it'],
    'ES': ['es'], 'MX': ['es'], 'AR': ['es'],
    'TH': ['th'], 'VN': ['vi'], 'PH': ['en', 'fil'],
    'MY': ['ms', 'en'], 'ID': ['id'],
    'TR': ['tr'], 'PL': ['pl'], 'CZ': ['cs'],
}

# ─── 颜色 ───────────────────────────────────────────────────────────────

class Colors:
    GREEN = '\033[92m'
    RED = '\033[91m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    MAGENTA = '\033[95m'
    DIM = '\033[2m'
    BOLD = '\033[1m'
    RESET = '\033[0m'

    @classmethod
    def disable(cls):
        for attr in ('GREEN', 'RED', 'YELLOW', 'BLUE', 'CYAN', 'MAGENTA',
                      'DIM', 'BOLD', 'RESET'):
            setattr(cls, attr, '')


def _init_colors(force_no_color=False):
    """初始化终端颜色支持。"""
    if force_no_color or not sys.stdout.isatty():
        Colors.disable()
        return
    if platform.system() == 'Windows':
        try:
            import ctypes
            kernel32 = ctypes.windll.kernel32
            kernel32.SetConsoleMode(kernel32.GetStdHandle(-11), 7)
        except Exception:
            Colors.disable()

# ─── 工具函数 ────────────────────────────────────────────────────────────

def _urlopen_read(req, timeout=10):
    """发起 HTTP 请求并返回 (decoded_text, response_headers)。"""
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        data = resp.read()
        charset = resp.headers.get_content_charset() or 'utf-8'
        return data.decode(charset), resp.headers


def _timed_request(url, timeout=10, headers=None):
    """发起请求并返回 (elapsed_ms, status_code)。仅测量延迟，不读取完整响应体。"""
    hdrs = {'User-Agent': CHROME_UA}
    if headers:
        hdrs.update(headers)
    req = urllib.request.Request(url, headers=hdrs)
    start = time.monotonic()
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            _ = resp.read(1)  # 触发实际连接
            elapsed = (time.monotonic() - start) * 1000
            return elapsed, resp.status
    except urllib.error.HTTPError as e:
        elapsed = (time.monotonic() - start) * 1000
        return elapsed, e.code
    except Exception:
        return None, None


def _fmt_offset(seconds):
    """将秒数格式化为 UTC±X.X 字符串。"""
    return f"UTC{seconds / 3600:+.1f}"


def _fmt_latency(ms):
    """格式化延迟值并附加颜色。"""
    if ms is None:
        return f"{Colors.RED}超时{Colors.RESET}"
    if ms < 250:
        return f"{Colors.GREEN}{ms:.0f}ms (快){Colors.RESET}"
    elif ms < 500:
        return f"{Colors.YELLOW}{ms:.0f}ms (一般){Colors.RESET}"
    else:
        return f"{Colors.RED}{ms:.0f}ms (慢){Colors.RESET}"


def _get_system_lang():
    """获取系统语言前缀，如 'en'、'zh'。"""
    lang = os.environ.get('LANG') or os.environ.get('LANGUAGE') or ''
    if not lang:
        try:
            lang = locale.getdefaultlocale()[0] or ''
        except Exception:
            lang = ''
    # 提取语言前缀: zh_CN.UTF-8 -> zh, en_US -> en
    m = re.match(r'^([a-z]{2})', lang.lower())
    return m.group(1) if m else None


def _query_ipapi(ip=None):
    """查询 ip-api 获取 IP 地理信息。

    ip=None 表示自动探测当前默认路由出口。
    返回成功时的 data dict，失败返回 None（并打印错误）。
    """
    url = f"http://ip-api.com/json/{ip or ''}?fields={IPAPI_FIELDS}"
    try:
        req = urllib.request.Request(url, headers={'User-Agent': 'curl/8.7.1'})
        text, _ = _urlopen_read(req, timeout=10)
        data = json.loads(text)
        if data.get('status') != 'success':
            return None
        return data
    except urllib.error.HTTPError as e:
        if e.code == 429:
            retry_after = e.headers.get('Retry-After', '60')
            print(f"  {Colors.YELLOW}⚠️ IP 查询 API 限流 (429)，请 {retry_after} 秒后重试{Colors.RESET}")
        else:
            print(f"  {Colors.RED}❌ IP 查询异常 (HTTP {e.code}){Colors.RESET}")
    except (urllib.error.URLError, socket.timeout) as e:
        print(f"  {Colors.RED}❌ 网络请求异常: {e}{Colors.RESET}")
    except (json.JSONDecodeError, KeyError):
        print(f"  {Colors.RED}❌ IP 查询返回数据异常{Colors.RESET}")
    return None

# ─── 检测模块 ────────────────────────────────────────────────────────────

def check_local_env(results):
    """1. 本地网络与防泄漏体检"""
    print(f"{Colors.BOLD}[*] 1. 本地网络与防泄漏体检 (Local Network & Leak Check){Colors.RESET}")

    # ── 代理环境变量 ──
    proxies = {k: v for k, v in os.environ.items()
               if k.lower() in ('http_proxy', 'https_proxy', 'all_proxy')}
    results['proxy_env'] = {'found': bool(proxies), 'vars': proxies}
    if proxies:
        print(f"  {Colors.GREEN}✅ 发现系统代理环境变量:{Colors.RESET}")
        for k, v in proxies.items():
            print(f"     - {k}: {v}")
    else:
        print(f"  {Colors.YELLOW}⚠️ 未检测到系统代理环境变量 (HTTP_PROXY等)，"
              f"可能依赖 Tun/Tap 虚拟网卡或路由器透明代理。{Colors.RESET}")

    # ── IPv6 泄漏检测 ──
    ipv6_connected, ipv6_addr = _check_ipv6()
    results['ipv6'] = {'connected': ipv6_connected, 'addr': ipv6_addr}
    if ipv6_connected:
        print(f"  {Colors.RED}❌ 警告: 检测到 IPv6 已开启 ({ipv6_addr}){Colors.RESET}")
        print(f"     -> 极度危险：多数代理软件不接管 IPv6，"
              f"会导致你的真实国内 IP 裸奔直连 Claude。强烈建议在网络设置中禁用 IPv6！")
    else:
        print(f"  {Colors.GREEN}✅ IPv6 处于关闭或不可达状态 (安全，无绕过代理泄漏风险){Colors.RESET}")

    # ── DNS 泄漏检测 ──
    # 注意：HTTP 方式的 DNS 检测可能经过代理的远程 DNS，
    # 检测结果反映的是代理出口的 DNS 而非本机真实 DNS。
    # 这对于判断"代理是否正确配置了远程 DNS"仍然有价值。
    dns_result = {'status': 'unknown', 'ip': None, 'geo': None}
    try:
        req = urllib.request.Request("http://edns.ip-api.com/json")
        text, _ = _urlopen_read(req, timeout=5)
        dns_data = json.loads(text)
        dns_ip = dns_data.get('dns', {}).get('ip', 'Unknown')
        dns_geo = dns_data.get('dns', {}).get('geo', 'Unknown')
        dns_result['ip'] = dns_ip
        dns_result['geo'] = dns_geo

        if 'China' in dns_geo or 'CN' in dns_geo:
            dns_result['status'] = 'leaked'
            print(f"  {Colors.RED}❌ DNS 发生泄漏！出口 DNS 为国内节点: {dns_ip} ({dns_geo}){Colors.RESET}")
            print(f"     -> 风控雷达：DNS 泄漏会直接暴露你的真实地理位置，"
                  f"请在代理软件中开启「远程 DNS 解析」。")
        else:
            dns_result['status'] = 'safe'
            print(f"  {Colors.GREEN}✅ DNS 无国内泄漏。海外出口 DNS 为: {dns_ip} ({dns_geo}){Colors.RESET}")
    except (urllib.error.URLError, socket.timeout):
        print(f"  {Colors.YELLOW}⚠️ DNS 泄漏检测超时或网络不通{Colors.RESET}")
    except (json.JSONDecodeError, KeyError):
        print(f"  {Colors.YELLOW}⚠️ DNS 泄漏检测返回数据异常{Colors.RESET}")
    results['dns_leak'] = dns_result

    # ── 本地时区 ──
    now = datetime.datetime.now(datetime.timezone.utc).astimezone()
    local_offset_sec = int(now.utcoffset().total_seconds())
    local_tz_name = now.tzname() or time.tzname[0]
    results['timezone'] = {'local_offset': local_offset_sec, 'local_tz': local_tz_name}
    print(f"  🕒 本机系统时区: {local_tz_name} ({_fmt_offset(local_offset_sec)})")

    # ── 本地语言 ──
    sys_lang = _get_system_lang()
    results['system_lang'] = sys_lang
    if sys_lang:
        print(f"  🌍 本机系统语言: {sys_lang}")


def _check_ipv6():
    """检测 IPv6 外部连通性。返回 (connected: bool, addr: str|None)。"""
    if not socket.has_ipv6:
        return False, None

    targets = [
        ("2001:4860:4860::8888", 53),   # Google DNS
        ("2606:4700:4700::1111", 53),    # Cloudflare DNS
    ]
    sock = None
    try:
        sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
        sock.settimeout(3)
        for target in targets:
            try:
                sock.connect(target)
                return True, sock.getsockname()[0]
            except OSError:
                continue
        return False, None
    except OSError:
        return False, None
    finally:
        if sock:
            sock.close()


def check_ip_attributes(results):
    """3. 落地 IP 质量与时区/语言匹配度（以 Claude 实际视角为参照）"""
    print(f"\n{Colors.BOLD}[*] 3. 落地 IP 质量与环境匹配度 (IP Quality & Fingerprint Match){Colors.RESET}")

    ip_result = {'status': 'unknown'}

    # 本机默认路由出口（自动探测）
    default_data = _query_ipapi()
    default_ip = default_data.get('query') if default_data else None
    results['default_exit_ip'] = default_ip

    # 参照 IP：优先使用 Claude/Cloudflare 实际看到的出口（来自 trace），
    # 因为封禁与风控都是打在这个 IP 上的；无 trace 结果时退回默认出口。
    cf_ip = results.get('cf_trace', {}).get('ip')
    if cf_ip and cf_ip != default_ip:
        ref_data = _query_ipapi(cf_ip)
        reference = 'cloudflare_trace'
        if ref_data is None:
            ref_data = default_data
            reference = 'default_exit'
        else:
            print(f"  {Colors.CYAN}👁 Claude 实际出口: {cf_ip}{Colors.RESET} "
                  f"{Colors.DIM}(本机默认路由出口为 {default_ip}，以下按 Claude 视角检测){Colors.RESET}")
    else:
        ref_data = default_data
        reference = 'default_exit'

    if not ref_data:
        ip_result['status'] = 'failed'
        print(f"  {Colors.RED}❌ 无法获取 IP 信息{Colors.RESET}")
        results['ip_quality'] = ip_result
        return

    ip_result.update({
        'status': 'ok',
        'ip': ref_data.get('query'),
        'reference': reference,
        'country': ref_data.get('country'),
        'country_code': ref_data.get('countryCode'),
        'city': ref_data.get('city'),
        'isp': ref_data.get('isp'),
        'as': ref_data.get('as'),
        'hosting': ref_data.get('hosting', False),
        'proxy': ref_data.get('proxy', False),
    })

    print(f"  📍 物理位置: {ref_data.get('country')} ({ref_data.get('countryCode')}) - {ref_data.get('city')}")
    print(f"  🌐 出口 IP : {ref_data.get('query')}")
    print(f"  🏢 归属 ASN: {ref_data.get('as')}")
    print(f"  📡 运营商  : {ref_data.get('isp')}")

    # IP 属性判定
    is_hosting = ref_data.get('hosting', False)
    is_proxy = ref_data.get('proxy', False)
    if is_hosting or is_proxy:
        labels = []
        if is_hosting:
            labels.append('商用机房 Hosting')
        if is_proxy:
            labels.append('代理节点')
        print(f"  {Colors.RED}⚠️  IP 质量风险: 检测为 [{' / '.join(labels)}]{Colors.RESET}"
              f" -> 极易引发连坐封号")
    else:
        print(f"  {Colors.GREEN}✅ IP 质量优秀: 检测为 [真实家庭宽带/原生ISP]{Colors.RESET}"
              f" -> 适合防封")

    # 时区一致性校验（对照参照 IP）
    proxy_offset_sec = ref_data.get('offset')
    proxy_tz = ref_data.get('timezone')
    local_offset_sec = results.get('timezone', {}).get('local_offset')
    tz_match = None

    if proxy_offset_sec is not None and local_offset_sec is not None:
        tz_match = (local_offset_sec == proxy_offset_sec)
        if tz_match:
            print(f"  {Colors.GREEN}✅ 时区匹配：本机时区与出口 IP 时区完全一致: "
                  f"{proxy_tz} ({_fmt_offset(proxy_offset_sec)}){Colors.RESET}")
        else:
            print(f"  {Colors.RED}❌ 时区不匹配！本机({_fmt_offset(local_offset_sec)}) "
                  f"vs 出口节点({_fmt_offset(proxy_offset_sec)}){Colors.RESET}")
            print(f"     -> 高危特征：Claude 会通过浏览器 JS 获取你的系统时间，"
                  f"并与你 IP 所在地的时间做对比。偏差证明了你是代理翻墙用户。请修改电脑系统时区！")

    ip_result['timezone_match'] = tz_match
    ip_result['proxy_tz'] = proxy_tz

    # 语言一致性校验（对照参照 IP）
    country_code = ref_data.get('countryCode', '')
    sys_lang = results.get('system_lang')
    lang_match = None

    if sys_lang and country_code in COUNTRY_LANG_MAP:
        expected_langs = COUNTRY_LANG_MAP[country_code]
        lang_match = sys_lang in expected_langs
        ip_result['lang_match'] = lang_match
        if lang_match:
            print(f"  {Colors.GREEN}✅ 语言匹配：系统语言 ({sys_lang}) 与出口地区 ({country_code}) 一致{Colors.RESET}")
        else:
            print(f"  {Colors.YELLOW}⚠️ 语言不匹配：系统语言 ({sys_lang}) 与出口地区 ({country_code}) "
                  f"常用语言 ({'/'.join(expected_langs)}) 不一致{Colors.RESET}")
            print(f"     -> 风控参考：语言环境不一致是常见的代理用户特征，"
                  f"建议修改系统语言或使用浏览器语言覆盖。")
    else:
        ip_result['lang_match'] = None

    # IP 一致性：默认路由出口 vs Claude 实际出口（分流泄漏检测）
    ip_consistent = None
    if default_ip and cf_ip:
        ip_consistent = (default_ip == cf_ip)
        if ip_consistent:
            print(f"  {Colors.GREEN}✅ IP 一致：默认出口 ({default_ip}) = Claude 出口 ({cf_ip})，"
                  f"无分流泄漏{Colors.RESET}")
        else:
            print(f"  {Colors.YELLOW}⚠️  IP 不一致：默认出口 ({default_ip}) ≠ Claude 出口 ({cf_ip}){Colors.RESET}")
            print(f"     -> 流量按域名分流。若你有意让 AI 流量单独走某节点，此提示可忽略；"
                  f"若期望全流量同出口，请检查代理分流规则。")
    results.setdefault('cf_trace', {})['ip_consistent'] = ip_consistent

    results['ip_quality'] = ip_result


def _parse_trace(text):
    """解析 Cloudflare trace 键值对格式: key=value。"""
    trace_data = {}
    for line in text.strip().splitlines():
        if '=' in line:
            k, v = line.split('=', 1)
            trace_data[k.strip()] = v.strip()
    return trace_data


def check_cloudflare_trace(results):
    """2. Cloudflare Trace 真实出口 IP（后续检测的参照系）+ 会话稳定性采样"""
    print(f"\n{Colors.BOLD}[*] 2. Cloudflare Trace 真实出口 IP (Claude 视角){Colors.RESET}")

    trace_result = {'status': 'unknown', 'samples': [], 'stable': None,
                    'ip_consistent': None}  # ip_consistent 由后续 IP 质量检测填充

    SAMPLES = 3
    for i in range(SAMPLES):
        try:
            req = urllib.request.Request("https://claude.ai/cdn-cgi/trace",
                                         headers={'User-Agent': CHROME_UA})
            text, _ = _urlopen_read(req, timeout=10)
            trace_data = _parse_trace(text)
            trace_result['samples'].append({
                'ip': trace_data.get('ip', ''),
                'colo': trace_data.get('colo', ''),
                'loc': trace_data.get('loc', ''),
            })
        except urllib.error.HTTPError as e:
            if not trace_result['samples']:
                trace_result['status'] = f'http_{e.code}'
                print(f"  {Colors.YELLOW}⚠️ Cloudflare Trace 异常 (HTTP {e.code}){Colors.RESET}")
        except (urllib.error.URLError, socket.timeout) as e:
            if not trace_result['samples']:
                trace_result['status'] = 'error'
                print(f"  {Colors.RED}❌ Cloudflare Trace 请求失败: {e}{Colors.RESET}")
        if i < SAMPLES - 1 and trace_result['samples']:
            time.sleep(1.5)

    if trace_result['samples']:
        trace_result['status'] = 'ok'
        first = trace_result['samples'][0]
        trace_result['ip'] = first['ip']
        trace_result['loc'] = first['loc']
        trace_result['colo'] = first['colo']
        print(f"  🎯 Claude 看到的 IP: {first['ip']}")
        print(f"  📍 Cloudflare 边缘 : {first['colo']} ({first['loc']})")

        # 会话稳定性：同一会话内多次采样出口是否漂移
        distinct = {s['ip'] for s in trace_result['samples'] if s['ip']}
        if len(trace_result['samples']) > 1:
            trace_result['stable'] = len(distinct) == 1
            if trace_result['stable']:
                print(f"  {Colors.GREEN}🔁 会话稳定: {len(trace_result['samples'])} 次采样出口 IP 一致{Colors.RESET}")
            else:
                print(f"  {Colors.YELLOW}⚠️  出口 IP 漂移: {' / '.join(sorted(distinct))}{Colors.RESET}")
                print(f"     -> 节点多出口/轮换特征：同会话内频繁换 IP 易触发 Claude 风控。")

    results['cf_trace'] = trace_result


def check_claude_web(results):
    """4. 探测 Claude 前端 Web 盾防御策略"""
    print(f"\n{Colors.BOLD}[*] 4. 探测 Claude 前端 Web 盾防御策略 (Cloudflare WAF Check){Colors.RESET}")

    url = "https://claude.ai/login"
    req = urllib.request.Request(url, headers=BROWSER_HEADERS)
    waf_result = {'status': 'unknown'}

    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            body_snippet = resp.read(4096).decode('utf-8', errors='ignore')
            has_challenge = any(m in body_snippet for m in CF_CHALLENGE_MARKERS)

            if has_challenge:
                waf_result['status'] = 'js_challenge'
                print(f"  {Colors.YELLOW}⚠️ 收到 HTTP 200 但包含 Cloudflare JS Challenge，"
                      f"浏览器访问时需通过人机验证。{Colors.RESET}")
                print(f"     -> 该 IP 可能信誉较低，被 Cloudflare 标记为需验证。")
            else:
                waf_result['status'] = 'pass'
                print(f"  {Colors.GREEN}✅ 网页直连通过: 无 Cloudflare 人机拦截，"
                      f"Web 盾前置放行！{Colors.RESET}")

    except urllib.error.HTTPError as e:
        cf_status = (e.headers.get('cf-mitigated') or '').lower()
        if e.code == 403 and any(m in cf_status for m in HARD_BLOCK_MARKERS):
            waf_result['status'] = 'blocked'
            print(f"  {Colors.RED}❌ 网页被硬拦截 (cf-mitigated: {cf_status}): "
                  f"浏览器也无法通过，该 IP 段已被 Cloudflare 拉黑。{Colors.RESET}")
            print(f"     -> 说明：该 IP 段有滥用黑历史，如果强行注册，"
                  f"接码和账号关联大概率被污染。")
        elif e.code == 403 and ('challenge' in cf_status or 'bot_fight' in cf_status):
            waf_result['status'] = 'browser_challenge'
            print(f"  {Colors.CYAN}ℹ️ Cloudflare 对 curl 发起了 JS Challenge (cf-mitigated: {cf_status})。{Colors.RESET}")
            print(f"     -> 这是盾对「非浏览器客户端」的默认行为（curl 无法模拟浏览器 "
                  f"TLS/HTTP2 指纹），与出口 IP 信誉无关，浏览器通常会自动通过。")
            print(f"     -> 请以浏览器实际访问为准；若浏览器也被拦，才考虑更换节点。")
        else:
            waf_result['status'] = f'http_{e.code}'
            print(f"  {Colors.YELLOW}⚠️ 网页状态异常 (HTTP {e.code}): "
                  f"节点可能被部分限制{Colors.RESET}")
    except (urllib.error.URLError, socket.timeout) as e:
        waf_result['status'] = 'error'
        print(f"  {Colors.RED}❌ 网页访问失败: {e}{Colors.RESET}")

    results['cloudflare_waf'] = waf_result


def check_claude_api(results):
    """5. 逆向探测 Anthropic API 底层连通性"""
    print(f"\n{Colors.BOLD}[*] 5. 逆向探测 Anthropic API 底层连通性 (API Hard-Ban Check){Colors.RESET}")

    url = "https://api.anthropic.com/v1/messages"
    req = urllib.request.Request(url, data=b'{}', headers={
        'User-Agent': CHROME_UA,
        'x-api-key': 'ant-api-fake-probe-key',
        'anthropic-version': '2023-06-01',
        'Content-Type': 'application/json',
    }, method='POST')
    api_result = {'status': 'unknown'}

    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            api_result['status'] = f'http_{resp.status}'
            print(f"  {Colors.YELLOW}⚠️ API 返回非预期成功状态 (HTTP {resp.status}){Colors.RESET}")
    except urllib.error.HTTPError as e:
        body = e.read().decode('utf-8', errors='ignore')
        if e.code == 401 and 'authentication_error' in body:
            api_result['status'] = 'reachable'
            print(f"  {Colors.GREEN}✅ API 穿透成功: 流量直达 Anthropic 核心后端，"
                  f"IP 未在硬封锁黑名单中！{Colors.RESET}")
        elif e.code == 403:
            api_result['status'] = 'hard_banned'
            print(f"  {Colors.RED}❌ API 被硬封锁 (HTTP 403): "
                  f"该节点已被官方彻底拉黑，100% 无法调用 API！{Colors.RESET}")
        else:
            api_result['status'] = f'http_{e.code}'
            print(f"  {Colors.YELLOW}⚠️ API 状态异常 (HTTP {e.code}): "
                  f"未知封锁策略{Colors.RESET}")
    except (urllib.error.URLError, socket.timeout) as e:
        api_result['status'] = 'error'
        print(f"  {Colors.RED}❌ API 连接失败: {e}{Colors.RESET}")

    results['api_connectivity'] = api_result


def check_latency_and_status(results):
    """6. 延迟测试与服务状态"""
    print(f"\n{Colors.BOLD}[*] 6. 连接延迟与 Anthropic 服务状态 (Latency & Status){Colors.RESET}")

    latency_result = {}

    # ── 延迟测试 ──
    targets = [
        ("claude.ai", "https://claude.ai/cdn-cgi/trace"),
        ("api.anthropic.com", "https://api.anthropic.com"),
    ]
    for name, url in targets:
        ms, code = _timed_request(url, timeout=10)
        latency_result[name] = {'latency_ms': round(ms, 1) if ms else None, 'status_code': code}
        print(f"  ⏱️  {name:25s} : {_fmt_latency(ms)}"
              + (f" {Colors.DIM}(HTTP {code}){Colors.RESET}" if code else ""))

    # ── Anthropic 官方服务状态 ──
    status_result = {'status': 'unknown'}
    try:
        req = urllib.request.Request("https://status.anthropic.com/api/v2/status.json",
                                     headers={'User-Agent': CHROME_UA})
        text, _ = _urlopen_read(req, timeout=8)
        status_data = json.loads(text)
        indicator = status_data.get('status', {}).get('indicator', '')
        description = status_data.get('status', {}).get('description', '')
        status_result = {'status': indicator, 'description': description}

        indicator_map = {
            'none': (Colors.GREEN, '✅', '所有系统正常'),
            'minor': (Colors.YELLOW, '⚠️', '部分系统异常'),
            'major': (Colors.RED, '❌', '主要系统故障'),
            'critical': (Colors.RED, '🚨', '严重故障'),
        }
        color, icon, label = indicator_map.get(indicator, (Colors.YELLOW, '❓', indicator))
        print(f"  📡 Anthropic 服务状态  : {color}{icon} {description or label}{Colors.RESET}")

    except Exception:
        print(f"  {Colors.YELLOW}⚠️ 无法获取 Anthropic 服务状态{Colors.RESET}")

    results['latency'] = latency_result
    results['service_status'] = status_result


def check_ip_reputation(results):
    """7. 深度 IP 信誉（滥用投诉计数 / VPN·机房判定）

    深度数据需要免费 API key，通过环境变量提供：
      IPINFO_TOKEN   -> ipinfo.io privacy 字段 (vpn/proxy/tor/hosting)
      ABUSEIPDB_KEY  -> AbuseIPDB 滥用投诉计数与置信度
    无 key 时退回 ipapi.is 免费档（公司/ASN 交叉核对）。
    """
    print(f"\n{Colors.BOLD}[*] 7. 深度 IP 信誉 (Deep IP Reputation){Colors.RESET}")

    rep = {'status': 'unknown'}
    ref_ip = results.get('ip_quality', {}).get('ip')
    if not ref_ip:
        print(f"  {Colors.YELLOW}⚠️ 无参照 IP，跳过{Colors.RESET}")
        results['reputation'] = rep
        return

    rep['ip'] = ref_ip
    token = os.environ.get('IPINFO_TOKEN')
    abuse_key = os.environ.get('ABUSEIPDB_KEY')

    # ── ipinfo.io privacy（需免费 token）──
    if token:
        try:
            req = urllib.request.Request(
                f"https://ipinfo.io/{ref_ip}/json?token={token}",
                headers={'User-Agent': 'curl/8.7.1'})
            text, _ = _urlopen_read(req, timeout=8)
            priv = json.loads(text).get('privacy', {})
            rep.update({
                'vpn': priv.get('vpn'), 'proxy': priv.get('proxy'),
                'tor': priv.get('tor'), 'hosting': priv.get('hosting'),
                'service': priv.get('service'),
            })
            flags = [k for k in ('vpn', 'proxy', 'tor', 'hosting') if rep.get(k)]
            if flags:
                print(f"  {Colors.YELLOW}⚠️  ipinfo 判定为 [{' / '.join(flags)}]{Colors.RESET}")
            else:
                print(f"  {Colors.GREEN}✅ ipinfo privacy: 非 VPN/代理/Tor/机房{Colors.RESET}")
            rep['status'] = 'ok'
        except Exception:
            print(f"  {Colors.YELLOW}⚠️ ipinfo 查询失败{Colors.RESET}")

    # ── AbuseIPDB 滥用投诉（需免费 key）──
    if abuse_key:
        try:
            req = urllib.request.Request(
                f"https://api.abuseipdb.com/api/v2/check?ipAddress={ref_ip}&maxAgeInDays=90",
                headers={'Key': abuse_key, 'User-Agent': CHROME_UA})
            text, _ = _urlopen_read(req, timeout=8)
            data = json.loads(text).get('data', {})
            rep['abuse_count'] = int(data.get('abuseReportsCount') or 0)
            rep['abuse_confidence'] = int(data.get('abuseConfidenceScore') or 0)
            rep['status'] = 'ok'
            if rep['abuse_confidence'] >= 25 or rep['abuse_count'] >= 5:
                print(f"  {Colors.YELLOW}⚠️  AbuseIPDB: 投诉 {rep['abuse_count']} 次，"
                      f"置信度 {rep['abuse_confidence']}%{Colors.RESET}")
                print(f"     -> 该 IP 近 90 天有滥用记录，连坐风控概率上升。")
            elif rep['abuse_count'] > 0:
                print(f"  ✅ AbuseIPDB: 少量投诉 ({rep['abuse_count']} 次，"
                      f"置信度 {rep['abuse_confidence']}%)")
            else:
                print(f"  {Colors.GREEN}✅ AbuseIPDB: 无滥用投诉记录，信誉良好{Colors.RESET}")
        except Exception:
            print(f"  {Colors.YELLOW}⚠️ AbuseIPDB 查询失败{Colors.RESET}")

    # ── ipapi.is 免费档：公司/ASN 交叉核对 ──
    try:
        req = urllib.request.Request(f"https://api.ipapi.is/?query={ref_ip}",
                                     headers={'User-Agent': 'curl/8.7.1'})
        text, _ = _urlopen_read(req, timeout=8)
        data = json.loads(text)
        rep['company'] = data.get('company')
        print(f"  🏢 线路归属核对: {data.get('company')} ({data.get('asn')})")
        if rep['status'] == 'unknown':
            rep['status'] = 'basic'
    except Exception:
        pass

    if not token and not abuse_key:
        print(f"  {Colors.DIM}(深度数据需免费 key: IPINFO_TOKEN / ABUSEIPDB_KEY "
              f"环境变量，注册后即可解锁 VPN/滥用投诉等判定){Colors.RESET}")

    results['reputation'] = rep


# 在浏览器内收集 WebRTC ICE 候选（srflx = STUN 探测到的公网真实 IP）
WEBRTC_JS = """
() => new Promise((resolve) => {
  const pc = new RTCPeerConnection({iceServers: [{urls: 'stun:stun.l.google.com:19302'}]});
  pc.addTransceiver('video', {direction: 'recvonly'});
  const found = new Set();
  pc.onicecandidate = (e) => {
    if (!e.candidate) { resolve([...found]); return; }
    const c = e.candidate.candidate;
    const ipm = c.match(/([0-9]{1,3}\\.){3}[0-9]{1,3}/);
    const typ = (c.match(/typ ([a-z]+)/) || [])[1] || 'unknown';
    if (ipm) found.add(typ + ':' + ipm[0]);
  };
  pc.onicegatheringstatechange = () => {
    if (pc.iceGatheringState === 'complete') resolve([...found]);
  };
  setTimeout(() => resolve([...found]), 6000);
})
"""


def check_browser_verify(results):
    """8. 真实浏览器验证（需 playwright：独立 Chromium、全新 profile ≈ 无痕）

    - WAF: 用真实浏览器指纹过 Cloudflare JS 盾，curl 做不到的闭环
    - WebRTC: srflx 候选暴露的公网 IP 若与出口 IP 不一致，说明 WebRTC 绕过代理泄漏
    """
    print(f"\n{Colors.BOLD}[*] 8. 真实浏览器验证 (Playwright WAF + WebRTC){Colors.RESET}")

    browser_result = {'status': 'unavailable'}
    webrtc_result = {'status': 'unavailable'}
    results['browser_waf'] = browser_result
    results['webrtc'] = webrtc_result

    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        print(f"  {Colors.YELLOW}⚠️ 未安装 playwright:{Colors.RESET}")
        print(f"     pip3 install playwright && python3 -m playwright install chromium")
        return

    exit_ip = (results.get('cf_trace', {}).get('ip')
               or results.get('default_exit_ip'))
    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(
                headless=True,
                args=['--disable-blink-features=AutomationControlled'])
            ctx = browser.new_context(user_agent=CHROME_UA, locale='en-US')
            page = ctx.new_page()
            page.goto('https://claude.ai/', wait_until='domcontentloaded',
                      timeout=30000)
            # Cloudflare JS 盾会先显示 "Just a moment..."，浏览器可自动解
            deadline = time.monotonic() + 20
            while time.monotonic() < deadline:
                t = (page.title() or '').lower()
                if 'just a moment' not in t and 'verifying' not in t and 'checking' not in t:
                    break
                time.sleep(1)
            title = page.title() or ''
            content = page.content()
            stuck = ('just a moment' in title.lower()
                     or 'verifying you are human' in content
                     or any(m in content for m in CF_CHALLENGE_MARKERS))
            if stuck:
                browser_result = {'status': 'blocked', 'title': title, 'url': page.url}
                print(f"  {Colors.RED}❌ 真实浏览器被 Cloudflare 拦截: {title!r}{Colors.RESET}")
                print(f"     -> 浏览器也过不去 = 该出口 IP 确实被拉黑，必须换节点。")
            else:
                browser_result = {'status': 'pass', 'title': title, 'url': page.url}
                print(f"  {Colors.GREEN}✅ 真实浏览器穿透成功: {title} ({page.url}){Colors.RESET}")

            # ── WebRTC 泄漏检测（就在 claude.ai 页面上跑，同一出口）──
            cands = None
            for attempt in range(3):
                try:
                    page.wait_for_load_state('domcontentloaded')
                    cands = page.evaluate(WEBRTC_JS)
                    break
                except Exception as e:
                    if 'Execution context was destroyed' in str(e) and attempt < 2:
                        time.sleep(2)  # SPA 跳转中，等页面稳定后重试
                        continue
                    print(f"  {Colors.YELLOW}⚠️ WebRTC 检测失败: {e}{Colors.RESET}")
                    break
            if cands is not None:
                srflx = [c.split(':', 1)[1] for c in cands if c.startswith('srflx:')]
                webrtc_result['candidates'] = cands
                if not srflx:
                    webrtc_result['status'] = 'blocked'
                    print(f"  {Colors.GREEN}✅ WebRTC 被阻断/不可用（安全，无泄漏路径）{Colors.RESET}")
                elif exit_ip and all(ip == exit_ip for ip in srflx):
                    webrtc_result['status'] = 'safe'
                    print(f"  {Colors.GREEN}✅ WebRTC 出口与代理一致: {', '.join(srflx)}{Colors.RESET}")
                else:
                    webrtc_result['status'] = 'leaked'
                    print(f"  {Colors.RED}❌ WebRTC 泄漏! STUN 探测到真实 IP: {', '.join(srflx)}{Colors.RESET}")
                    print(f"     -> 代理出口为 {exit_ip}，WebRTC (UDP) 绕过了代理直连。")
                    print(f"     -> 请在浏览器禁用 WebRTC 或让代理接管 UDP。")
                local = [c.split(':', 1)[1] for c in cands if c.startswith('host:')]
                if local:
                    print(f"  {Colors.DIM}(本地候选参考: {', '.join(local)}){Colors.RESET}")

            browser.close()
    except Exception as e:
        print(f"  {Colors.RED}❌ 浏览器验证失败: {e}{Colors.RESET}")

    results['browser_waf'] = browser_result
    results['webrtc'] = webrtc_result

# ─── 信任评分 ────────────────────────────────────────────────────────────

def calculate_trust_score(results):
    """
    计算 0-100 的信任评分。
    满分 100，各项扣分。分数越高越安全。
    """
    score = 100
    details = {}

    # IPv6 泄漏 (-20)
    if results.get('ipv6', {}).get('connected'):
        score -= 20
        details['ipv6'] = -20
    else:
        details['ipv6'] = 0

    # DNS 泄漏 (-20)
    dns_status = results.get('dns_leak', {}).get('status')
    if dns_status == 'leaked':
        score -= 20
        details['dns'] = -20
    elif dns_status == 'unknown':
        score -= 5
        details['dns'] = -5
    else:
        details['dns'] = 0

    # 时区匹配 (-15)
    tz_match = results.get('ip_quality', {}).get('timezone_match')
    if tz_match is False:
        score -= 15
        details['timezone'] = -15
    elif tz_match is None:
        score -= 3
        details['timezone'] = -3
    else:
        details['timezone'] = 0

    # 语言匹配 (-5)
    lang_match = results.get('ip_quality', {}).get('lang_match')
    if lang_match is False:
        score -= 5
        details['language'] = -5
    else:
        details['language'] = 0

    # IP 质量 (-15: hosting, -10: proxy only)
    ip_q = results.get('ip_quality', {})
    if ip_q.get('hosting'):
        score -= 15
        details['ip_type'] = -15
    elif ip_q.get('proxy'):
        score -= 10
        details['ip_type'] = -10
    else:
        details['ip_type'] = 0

    # IP 一致性 (-10)
    cf_consistent = results.get('cf_trace', {}).get('ip_consistent')
    if cf_consistent is False:
        score -= 10
        details['ip_consistency'] = -10
    else:
        details['ip_consistency'] = 0

    # WAF (-15)。若做过真实浏览器验证，以浏览器结论为准覆盖 curl 分类
    waf_status = results.get('cloudflare_waf', {}).get('status')
    if waf_status == 'blocked':
        details['waf'] = -15
    elif waf_status == 'js_challenge':
        details['waf'] = -8
    elif waf_status == 'browser_challenge':
        # curl 无浏览器指纹必被挑战，与 IP 信誉无关，不构成风险信号
        details['waf'] = 0
    elif waf_status not in ('pass', 'skipped'):
        details['waf'] = -3
    else:
        details['waf'] = 0

    browser_waf = results.get('browser_waf', {}).get('status')
    if browser_waf == 'pass':
        details['waf'] = 0
    elif browser_waf == 'blocked':
        details['waf'] = -15

    score += details['waf']

    # API (-15)
    api_status = results.get('api_connectivity', {}).get('status')
    if api_status == 'hard_banned':
        score -= 15
        details['api'] = -15
    elif api_status == 'error':
        score -= 5
        details['api'] = -5
    elif api_status not in ('reachable', 'skipped'):
        score -= 3
        details['api'] = -3
    else:
        details['api'] = 0

    # WebRTC 泄漏 (-15)
    webrtc_status = results.get('webrtc', {}).get('status')
    if webrtc_status == 'leaked':
        score -= 15
        details['webrtc'] = -15
    else:
        details['webrtc'] = 0

    # 会话出口漂移 (-5)
    if results.get('cf_trace', {}).get('stable') is False:
        score -= 5
        details['trace_stability'] = -5
    else:
        details['trace_stability'] = 0

    # IP 滥用投诉 (-5)
    rep = results.get('reputation', {})
    if rep.get('abuse_count', 0) >= 5:
        score -= 5
        details['abuse'] = -5
    else:
        details['abuse'] = 0

    score = max(0, score)
    return score, details


def _score_label(score):
    """返回 (颜色, 标签)。"""
    if score >= 90:
        return Colors.GREEN, '极度纯净'
    elif score >= 75:
        return Colors.GREEN, '纯净'
    elif score >= 50:
        return Colors.YELLOW, '良好'
    elif score >= 25:
        return Colors.YELLOW, '中性'
    else:
        return Colors.RED, '危险'


def _score_bar(score):
    """生成分数进度条。"""
    filled = score // 5  # 0-20 格
    empty = 20 - filled
    color, _ = _score_label(score)
    return f"{color}{'█' * filled}{Colors.DIM}{'░' * empty}{Colors.RESET}"

# ─── 综合评估 ────────────────────────────────────────────────────────────

def calculate_risk(results):
    """根据各项检测结果计算综合风险等级。返回 (level, suggestions)。"""
    red_flags = 0
    yellow_flags = 0
    suggestions = []

    if results.get('ipv6', {}).get('connected'):
        red_flags += 1
        suggestions.append('在网络设置中禁用 IPv6')

    dns_status = results.get('dns_leak', {}).get('status')
    if dns_status == 'leaked':
        red_flags += 1
        suggestions.append('在代理软件中开启「远程 DNS 解析」')
    elif dns_status == 'unknown':
        yellow_flags += 1

    tz_match = results.get('ip_quality', {}).get('timezone_match')
    if tz_match is False:
        red_flags += 1
        suggestions.append('修改系统时区为代理节点所在时区')

    lang_match = results.get('ip_quality', {}).get('lang_match')
    if lang_match is False:
        yellow_flags += 1
        suggestions.append('修改系统语言为代理节点所在地区常用语言')

    ip_q = results.get('ip_quality', {})
    if ip_q.get('hosting') or ip_q.get('proxy'):
        yellow_flags += 1
        suggestions.append('考虑更换为住宅 IP / 原生 ISP 节点')

    cf_consistent = results.get('cf_trace', {}).get('ip_consistent')
    if cf_consistent is False:
        yellow_flags += 1
        suggestions.append('检查代理分流规则，确保 claude.ai 流量经过代理')

    waf_status = results.get('cloudflare_waf', {}).get('status')
    if waf_status == 'blocked':
        red_flags += 1
        suggestions.append('更换 IP 节点，当前 IP 段已被 Cloudflare 硬拦截（浏览器也无法通过）')
    elif waf_status == 'js_challenge':
        yellow_flags += 1
        suggestions.append('当前 IP 需通过 JS Challenge，建议更换更干净的节点')
    elif waf_status == 'browser_challenge':
        # 非浏览器客户端必然收到挑战，无风险信号；仅提示用浏览器确认
        suggestions.append('curl 被 Cloudflare 挑战属默认行为，建议用浏览器实测确认 '
                           '(claude_check --browser-check)；若浏览器也被拦再更换节点')

    api_status = results.get('api_connectivity', {}).get('status')
    if api_status == 'hard_banned':
        red_flags += 1
        suggestions.append('API 层面已被硬封，必须更换 IP 节点')
    elif api_status == 'error':
        yellow_flags += 1

    # 真实浏览器验证：浏览器结论优先级最高
    browser_waf = results.get('browser_waf', {}).get('status')
    if browser_waf == 'blocked':
        red_flags += 1
        suggestions.append('真实浏览器也被 Cloudflare 拦截，必须更换 IP 节点')

    # WebRTC 泄漏
    if results.get('webrtc', {}).get('status') == 'leaked':
        red_flags += 1
        suggestions.append('WebRTC 绕过代理泄漏真实 IP：禁用浏览器 WebRTC '
                           '或让代理接管 UDP 流量')

    # 会话出口漂移
    if results.get('cf_trace', {}).get('stable') is False:
        yellow_flags += 1
        suggestions.append('同会话内出口 IP 漂移，建议更换单一出口的节点')

    # IP 滥用投诉
    rep = results.get('reputation', {})
    if rep.get('abuse_count', 0) >= 5:
        yellow_flags += 1
        suggestions.append(f"出口 IP 有 {rep['abuse_count']} 次滥用投诉记录，"
                           f"连坐风控概率上升，可考虑更换")

    if red_flags >= 2:
        level = 'CRITICAL'
    elif red_flags >= 1:
        level = 'HIGH'
    elif yellow_flags >= 1:
        level = 'MEDIUM'
    else:
        level = 'LOW'

    return level, suggestions


def print_summary(results):
    """打印综合风险评估报告。"""
    level, suggestions = calculate_risk(results)
    score, score_details = calculate_trust_score(results)
    results['overall_risk'] = level
    results['suggestions'] = suggestions
    results['trust_score'] = score
    results['trust_score_details'] = score_details

    level_colors = {
        'LOW': Colors.GREEN,
        'MEDIUM': Colors.YELLOW,
        'HIGH': Colors.RED,
        'CRITICAL': Colors.RED,
    }
    level_labels = {
        'LOW': '低风险 (LOW)',
        'MEDIUM': '中风险 (MEDIUM)',
        'HIGH': '高风险 (HIGH)',
        'CRITICAL': '极高风险 (CRITICAL)',
    }

    def _status_icon(ok):
        if ok is True:
            return f'{Colors.GREEN}✅ 安全{Colors.RESET}'
        elif ok is False:
            return f'{Colors.RED}❌ 异常{Colors.RESET}'
        return f'{Colors.YELLOW}⚠️ 未知{Colors.RESET}'

    ipv6_ok = not results.get('ipv6', {}).get('connected', False)
    dns_ok = results.get('dns_leak', {}).get('status') == 'safe'
    dns_unknown = results.get('dns_leak', {}).get('status') == 'unknown'
    tz_ok = results.get('ip_quality', {}).get('timezone_match')
    lang_ok = results.get('ip_quality', {}).get('lang_match')
    ip_clean = not (results.get('ip_quality', {}).get('hosting') or
                    results.get('ip_quality', {}).get('proxy'))
    cf_consistent = results.get('cf_trace', {}).get('ip_consistent')
    cf_unknown = results.get('cf_trace', {}).get('status') in ('unknown', 'error')
    waf_status = results.get('cloudflare_waf', {}).get('status')
    waf_ok = waf_status == 'pass'
    # browser_challenge 是 curl 被通用 JS 盾拦截（浏览器通常可过），显示为 ⚠️
    waf_unknown = waf_status in ('unknown', 'error', 'skipped', 'browser_challenge')
    api_ok = results.get('api_connectivity', {}).get('status') == 'reachable'
    api_unknown = results.get('api_connectivity', {}).get('status') in ('unknown', 'error', 'skipped')

    c = level_colors.get(level, '')
    score_color, score_text = _score_label(score)

    print(f"\n{Colors.BOLD}{'=' * 68}")
    print(f"                        综合风险评估")
    print(f"{'=' * 68}{Colors.RESET}")

    # 信任评分（大字显示）
    print(f"\n  {Colors.BOLD}信任评分{Colors.RESET}  {score_color}{Colors.BOLD}{score}/100{Colors.RESET}"
          f"  {score_color}{score_text}{Colors.RESET}")
    print(f"  {_score_bar(score)}\n")

    # 检测项明细
    print(f"  {'检测项':<14s}{'结果':s}")
    print(f"  {'─' * 40}")
    print(f"  {'IPv6 泄漏':<12s}: {_status_icon(ipv6_ok)}")
    print(f"  {'DNS 泄漏':<12s}: {_status_icon(dns_ok if not dns_unknown else None)}")
    print(f"  {'时区匹配':<12s}: {_status_icon(tz_ok)}")
    print(f"  {'语言匹配':<12s}: {_status_icon(lang_ok)}")
    print(f"  {'IP 质量':<12s}: {_status_icon(ip_clean if results.get('ip_quality', {}).get('status') == 'ok' else None)}")
    print(f"  {'IP 一致性':<11s}: {_status_icon(cf_consistent if not cf_unknown else None)}")
    print(f"  {'Web WAF':<13s}: {_status_icon(waf_ok if not waf_unknown else None)}")
    print(f"  {'API 连通':<12s}: {_status_icon(api_ok if not api_unknown else None)}")
    print(f"  {'会话稳定':<12s}: {_status_icon(results.get('cf_trace', {}).get('stable'))}")

    # 附加检测项（仅在做过时显示）
    rep = results.get('reputation', {})
    if rep.get('status') == 'ok':
        abuse_ok = rep.get('abuse_count', 0) < 5
        print(f"  {'IP 信誉':<13s}: {_status_icon(abuse_ok)}")
    bw = results.get('browser_waf', {}).get('status')
    if bw in ('pass', 'blocked'):
        print(f"  {'浏览器盾':<12s}: {_status_icon(bw == 'pass')}")
    ws = results.get('webrtc', {}).get('status')
    if ws in ('safe', 'blocked', 'leaked'):
        print(f"  {'WebRTC':<14s}: {_status_icon(ws in ('safe', 'blocked'))}")

    print(f"\n  🔒 综合风险等级: {c}{Colors.BOLD}{level_labels.get(level, level)}{Colors.RESET}")

    if suggestions:
        print(f"\n  📋 改进建议:")
        for i, s in enumerate(suggestions, 1):
            print(f"     {i}. {s}")

    print(f"\n{Colors.BOLD}{'=' * 68}{Colors.RESET}\n")

# ─── 入口 ────────────────────────────────────────────────────────────────

def print_banner():
    print(f"{Colors.BLUE}{Colors.BOLD}")
    print("================================================================")
    print("       🤖 Claude AI - 终极环境安全深度检测工具 (Pro 版)         ")
    print("================================================================")
    print(f"{Colors.RESET}")


def parse_args():
    parser = argparse.ArgumentParser(
        description='Claude AI 环境安全深度检测工具 - 一键检查代理环境是否安全',
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument('--skip-api', action='store_true',
                        help='跳过 API 连通性检测')
    parser.add_argument('--skip-web', action='store_true',
                        help='跳过 Web WAF 检测')
    parser.add_argument('--json', action='store_true', dest='json_output',
                        help='以 JSON 格式输出结果（适合脚本集成）')
    parser.add_argument('--no-color', action='store_true',
                        help='禁用彩色输出')
    parser.add_argument('--browser-check', action='store_true',
                        dest='browser_check',
                        help='用 playwright 起独立 Chromium 做真实浏览器 WAF 验证 + '
                             'WebRTC 泄漏检测（全新 profile，≈无痕，不碰你的浏览器登录态）')
    return parser.parse_args()


def main():
    args = parse_args()
    _init_colors(force_no_color=args.no_color or args.json_output)

    if not args.json_output:
        print_banner()

    results = {}

    check_local_env(results)
    check_cloudflare_trace(results)   # 先拿 Claude 视角出口，作为后续检测参照
    check_ip_attributes(results)

    if not args.skip_web:
        check_claude_web(results)
    else:
        results['cloudflare_waf'] = {'status': 'skipped'}
        if not args.json_output:
            print(f"\n{Colors.BOLD}[*] 4. Web WAF 检测 — 已跳过 (--skip-web){Colors.RESET}")

    if not args.skip_api:
        check_claude_api(results)
    else:
        results['api_connectivity'] = {'status': 'skipped'}
        if not args.json_output:
            print(f"\n{Colors.BOLD}[*] 5. API 连通性检测 — 已跳过 (--skip-api){Colors.RESET}")

    check_latency_and_status(results)
    check_ip_reputation(results)

    if args.browser_check:
        check_browser_verify(results)

    if args.json_output:
        level, suggestions = calculate_risk(results)
        score, score_details = calculate_trust_score(results)
        results['overall_risk'] = level
        results['suggestions'] = suggestions
        results['trust_score'] = score
        results['trust_score_details'] = score_details
        print(json.dumps(results, ensure_ascii=False, indent=2))
    else:
        print_summary(results)

    # 退出码: 0=LOW, 1=HIGH/CRITICAL, 2=MEDIUM
    level = results.get('overall_risk', 'LOW')
    if level in ('HIGH', 'CRITICAL'):
        sys.exit(1)
    elif level == 'MEDIUM':
        sys.exit(2)
    sys.exit(0)


if __name__ == '__main__':
    main()
