#!/usr/bin/env python3
"""resi-agent: VPNGate -> OpenVPN -> SOCKS5/HTTP proxy, managed by the Cloudflare hub.

只依赖 Python3 标准库 + openvpn + iproute2。必须以 root 运行（SO_BINDTODEVICE / ip rule）。
"""
import asyncio, base64, csv, hmac, io, ipaddress, json, os, random, socket, struct, time
import urllib.request
from collections import deque
from urllib.parse import urlsplit

HUB = os.environ["HUB_URL"].rstrip("/")
TOKEN = os.environ["AGENT_TOKEN"]
NODE_ID = os.environ.get("NODE_ID") or socket.gethostname()
WORKDIR = os.environ.get("WORKDIR", "/opt/resi-agent")
ALLOW_HOSTING = os.environ.get("ALLOW_HOSTING", "0") == "1"  # 1 = 不过滤机房 IP
DEV, TABLE = "tun_rp", "100"
VPNGATE_API = "http://www.vpngate.net/api/iphone/"
SO_BINDTODEVICE = getattr(socket, "SO_BINDTODEVICE", 25)

S = dict(country="US", port=7920, user="", pw="", nonce=None, ready=False, status="starting",
         exit_ip="", cc="", isp="", hosting=False, latency=0)
PENDING = deque(maxlen=200)
rotate_ev = port_ev = SEM = None  # 在 main() 里创建，兼容 Python 3.9


def log(msg):
    line = f"{time.strftime('%H:%M:%S')} {msg}"
    print(line, flush=True)
    PENDING.append(line)


# ---------------------------------------------------------------- hub
def hub_post(path, obj):
    req = urllib.request.Request(
        HUB + path, data=json.dumps(obj).encode(),
        headers={"Authorization": "Bearer " + TOKEN, "Content-Type": "application/json",
                 "User-Agent": "resi-agent/1.0"})
    with urllib.request.urlopen(req, timeout=10) as r:
        return json.loads(r.read())


def apply_policy(r):
    p = r["policy"]
    country, port = str(p["country"]).upper(), int(p["port"])
    S["user"], S["pw"] = p.get("proxy_user", ""), p.get("proxy_pass", "")
    if S["nonce"] is None:
        S["nonce"] = r["rotate_nonce"]
    elif r["rotate_nonce"] != S["nonce"]:
        S["nonce"] = r["rotate_nonce"]
        log("收到面板的换 IP 指令")
        rotate_ev.set()
    if S["ready"] and country != S["country"]:
        log(f"目标国家变更 {S['country']} -> {country}")
        rotate_ev.set()
    S["country"] = country
    if port != S["port"]:
        S["port"] = port
        port_ev.set()
    S["ready"] = True

def get_public_ip():
    try:
        return urllib.request.urlopen("https://api.ipify.org", timeout=8).read().decode().strip()
    except Exception:
        return ""

async def heartbeat_loop():
    loop = asyncio.get_running_loop()
    while True:
        lines = [PENDING.popleft() for _ in range(min(20, len(PENDING)))]
        body = dict(node_id=NODE_ID, status=S["status"], exit_ip=S["exit_ip"], country=S["cc"],
                    isp=S["isp"], hosting=S["hosting"], latency=S["latency"], port=S["port"], logs=lines)
        try:
            apply_policy(await loop.run_in_executor(None, hub_post, "/api/agent/heartbeat", body))
        except Exception as e:
            print(f"heartbeat failed: {e}", flush=True)
            for l in reversed(lines):  # 放回去，下次再发
                PENDING.appendleft(l)
        await asyncio.sleep(15)


# ---------------------------------------------------------------- tunnel-bound sockets / DNS
def tun_sock(kind=socket.SOCK_STREAM):
    s = socket.socket(socket.AF_INET, kind)
    s.setsockopt(socket.SOL_SOCKET, SO_BINDTODEVICE, DEV.encode())
    return s


def _skip_name(d, i):
    while True:
        n = d[i]
        if n == 0:
            return i + 1
        if n & 0xC0 == 0xC0:
            return i + 2
        i += n + 1


def parse_a(d):
    qd, an = struct.unpack("!HH", d[4:8])
    i = 12
    for _ in range(qd):
        i = _skip_name(d, i) + 4
    for _ in range(an):
        i = _skip_name(d, i)
        t, _c, _ttl, rl = struct.unpack("!HHIH", d[i:i + 10])
        i += 10
        if t == 1 and rl == 4:
            return socket.inet_ntoa(d[i:i + 4])
        i += rl
    return None


def tun_resolve(name):
    """通过隧道向 1.1.1.1 / 8.8.8.8 查询 A 记录，避免 DNS 走本机出口泄漏。"""
    try:
        ipaddress.ip_address(name)
        return name
    except ValueError:
        pass
    labels = name.rstrip(".").encode("idna").split(b".")
    q = struct.pack("!HHHHHH", random.randrange(65536), 0x0100, 1, 0, 0, 0)
    q += b"".join(bytes([len(x)]) + x for x in labels) + b"\0" + struct.pack("!HH", 1, 1)
    for server in ("1.1.1.1", "8.8.8.8"):
        s = tun_sock(socket.SOCK_DGRAM)
        s.settimeout(3)
        try:
            s.sendto(q, (server, 53))
            ip = parse_a(s.recvfrom(1500)[0])
            if ip:
                return ip
        except OSError:
            pass
        finally:
            s.close()
    raise OSError("dns failed: " + name)


def ident():
    """经隧道查询出口 IP / 国家 / ISP / 是否机房（ip-api.com，仅 HTTP）。"""
    s = tun_sock()
    s.settimeout(8)
    try:
        s.connect((tun_resolve("ip-api.com"), 80))
        s.sendall(b"GET /json/?fields=status,query,countryCode,isp,hosting HTTP/1.0\r\nHost: ip-api.com\r\n\r\n")
        data = b""
        while True:
            chunk = s.recv(4096)
            if not chunk:
                break
            data += chunk
        return json.loads(data.split(b"\r\n\r\n", 1)[1])
    finally:
        s.close()


def probe():
    t = time.time()
    s = tun_sock()
    s.settimeout(5)
    try:
        s.connect(("1.1.1.1", 443))
        return int((time.time() - t) * 1000)
    except OSError:
        return None
    finally:
        s.close()


# ---------------------------------------------------------------- VPNGate / OpenVPN
def fetch_vpngate():
    req = urllib.request.Request(VPNGATE_API, headers={"User-Agent": "Mozilla/5.0"})
    raw = urllib.request.urlopen(req, timeout=30).read().decode("utf-8", "ignore")
    lines = [l for l in raw.splitlines() if l and not l.startswith("*")]
    lines[0] = lines[0].lstrip("#")
    out = []
    for row in csv.DictReader(io.StringIO("\n".join(lines))):
        try:
            text = base64.b64decode(row["OpenVPN_ConfigData_Base64"]).decode("utf-8", "ignore")
            proto = "udp" if "proto udp" in text else "tcp"
            remote = next(l.split() for l in text.splitlines() if l.startswith("remote "))
            out.append(dict(ip=row["IP"], cc=row["CountryShort"].upper(), score=int(row["Score"]),
                            ping=int(row["Ping"]) if row["Ping"].isdigit() else 9999,
                            text=text, proto=proto, host=remote[1], port=int(remote[2])))
        except Exception:
            continue
    return out


async def tcp_alive(c):
    if c["proto"] != "tcp":
        return True
    try:
        _, w = await asyncio.wait_for(asyncio.open_connection(c["host"], c["port"]), 4)
        w.close()
        return True
    except Exception:
        return False


async def sh(*cmd):
    p = await asyncio.create_subprocess_exec(*cmd, stdout=asyncio.subprocess.DEVNULL,
                                             stderr=asyncio.subprocess.DEVNULL)
    return await p.wait()


async def cleanup_routes():
    for _ in range(3):
        await sh("ip", "rule", "del", "oif", DEV, "lookup", TABLE)
    await sh("ip", "route", "flush", "table", TABLE)


async def start_vpn(c):
    keep = [l for l in c["text"].splitlines()
            if not l.startswith(("dev ", "dev-type", "script-security", "up ", "down ", "redirect-gateway"))]
    keep += [f"dev {DEV}", "dev-type tun", "route-nopull", "nobind",
             "data-ciphers AES-256-GCM:AES-128-GCM:AES-128-CBC", "data-ciphers-fallback AES-128-CBC", "verb 3"]
    path = os.path.join(WORKDIR, "current.ovpn")
    with open(path, "w") as f:
        f.write("\n".join(keep) + "\n")
    proc = await asyncio.create_subprocess_exec("openvpn", "--config", path,
                                                stdout=asyncio.subprocess.PIPE,
                                                stderr=asyncio.subprocess.STDOUT)

    async def wait_ready():
        while True:
            line = await proc.stdout.readline()
            if not line:
                return False
            if b"Initialization Sequence Completed" in line:
                return True

    try:
        ok = await asyncio.wait_for(wait_ready(), 30)
    except asyncio.TimeoutError:
        ok = False

    async def drain():
        while await proc.stdout.readline():
            pass

    if ok:
        asyncio.create_task(drain())
    return proc, ok


async def stop_vpn(proc):
    if proc and proc.returncode is None:
        proc.terminate()
        try:
            await asyncio.wait_for(proc.wait(), 5)
        except asyncio.TimeoutError:
            proc.kill()
    await cleanup_routes()
    S.update(exit_ip="", cc="", isp="", hosting=False, latency=0)


async def verify(c):
    """路由 + 出口质检；通过才算可用。"""
    await cleanup_routes()
    await sh("ip", "route", "replace", "default", "dev", DEV, "table", TABLE)
    await sh("ip", "rule", "add", "oif", DEV, "lookup", TABLE, "priority", "100")
    loop = asyncio.get_running_loop()
    try:
        info = await loop.run_in_executor(None, ident)
    except Exception as e:
        log(f"出口检测失败: {e}")
        return False
    if info.get("status") != "success":
        log("出口检测无结果")
        return False
    if S["country"] != "ANY" and info["countryCode"] != S["country"]:
        log(f"出口国家 {info['countryCode']} 与目标 {S['country']} 不符")
        return False
    if info.get("hosting") and not ALLOW_HOSTING:
        log(f"出口 {info['query']} 被判定为机房 IP，跳过")
        return False
    S.update(exit_ip=info["query"], cc=info["countryCode"], isp=info.get("isp", ""),
             hosting=bool(info.get("hosting")), latency=await loop.run_in_executor(None, probe) or 0)
    return True


async def monitor(proc):
    loop = asyncio.get_running_loop()
    fails, tick = 0, 0
    while True:
        try:
            await asyncio.wait_for(rotate_ev.wait(), 5)
            return "换 IP / 策略变更"
        except asyncio.TimeoutError:
            pass
        if proc.returncode is not None:
            return "openvpn 已退出"
        tick += 1
        if tick % 3 == 0:
            ms = await loop.run_in_executor(None, probe)
            if ms is None:
                fails += 1
                if fails >= 2:
                    return "探测连续失败"
            else:
                fails, S["latency"] = 0, ms


async def tunnel_loop():
    black, cache, cache_t = set(), [], 0
    while True:
        S["status"] = "connecting"
        want = S["country"]
        try:
            if not cache or time.time() - cache_t > 600:
                cache = await asyncio.get_running_loop().run_in_executor(None, fetch_vpngate)
                cache_t = time.time()
                log(f"VPNGate 节点列表 {len(cache)} 条")
        except Exception as e:
            log(f"拉取 VPNGate 失败: {e}")
            await asyncio.sleep(30)
            continue
        cands = [c for c in cache if (want == "ANY" or c["cc"] == want) and c["ip"] not in black]
        cands.sort(key=lambda c: (-c["score"], c["ping"]))
        alive = await asyncio.gather(*(tcp_alive(c) for c in cands[:40]))
        cands = [c for c, ok in zip(cands[:40], alive) if ok]
        if not cands:
            log(f"{want} 暂无可用候选，30 秒后重试")
            black.clear()
            cache_t = 0
            await asyncio.sleep(30)
            continue
        for c in cands:
            if S["country"] != want:
                break
            log(f"尝试 {c['ip']} ({c['cc']}, {c['proto']}/{c['port']})")
            proc = None
            try:
                proc, ok = await start_vpn(c)
                if ok and await verify(c):
                    S["status"] = "up"
                    log(f"隧道就绪: 出口 {S['exit_ip']} {S['cc']} {S['isp']} {S['latency']}ms")
                    reason = await monitor(proc)
                    log(f"隧道结束: {reason}")
                    rotate_ev.clear()
            finally:
                await stop_vpn(proc)
            black.add(c["ip"])
            S["status"] = "connecting"


# ---------------------------------------------------------------- proxy server (SOCKS5 + HTTP, 同端口)
def auth_ok(user, pw):
    if not S["user"] or not S["pw"]:
        return False  # 未配置凭据一律拒绝，避免变成开放代理
    a = hmac.compare_digest(user.encode(), S["user"].encode())
    b = hmac.compare_digest(pw.encode(), S["pw"].encode())
    return a and b


async def open_out(host, port):
    if S["status"] != "up":
        raise OSError("tunnel down")
    loop = asyncio.get_running_loop()
    ip = await loop.run_in_executor(None, tun_resolve, host)
    a = ipaddress.ip_address(ip)
    if a.version != 4 or not a.is_global:
        raise OSError("blocked address")
    s = tun_sock()
    s.setblocking(False)
    try:
        await asyncio.wait_for(loop.sock_connect(s, (ip, port)), 15)
    except BaseException:
        s.close()
        raise
    return await asyncio.open_connection(sock=s)


async def pipe(r, w):
    try:
        while True:
            d = await asyncio.wait_for(r.read(65536), 300)
            if not d:
                break
            w.write(d)
            await w.drain()
    except Exception:
        pass
    finally:
        try:
            w.close()
        except Exception:
            pass


async def relay(cr, cw, rr, rw):
    await asyncio.gather(pipe(cr, rw), pipe(rr, cw))


async def socks5(cr, cw):
    n = (await cr.readexactly(1))[0]
    methods = await cr.readexactly(n)
    if 2 not in methods:
        cw.write(b"\x05\xff")
        return
    cw.write(b"\x05\x02")
    await cr.readexactly(1)
    user = await cr.readexactly((await cr.readexactly(1))[0])
    pw = await cr.readexactly((await cr.readexactly(1))[0])
    if not auth_ok(user.decode("utf-8", "ignore"), pw.decode("utf-8", "ignore")):
        cw.write(b"\x01\x01")
        return
    cw.write(b"\x01\x00")
    _ver, cmd, _rsv, atyp = await cr.readexactly(4)
    if cmd != 1:
        cw.write(b"\x05\x07\x00\x01\0\0\0\0\0\0")
        return
    if atyp == 1:
        host = socket.inet_ntoa(await cr.readexactly(4))
    elif atyp == 3:
        host = (await cr.readexactly((await cr.readexactly(1))[0])).decode("utf-8", "ignore")
    else:
        cw.write(b"\x05\x08\x00\x01\0\0\0\0\0\0")
        return
    port = struct.unpack("!H", await cr.readexactly(2))[0]
    try:
        rr, rw = await open_out(host, port)
    except Exception:
        cw.write(b"\x05\x04\x00\x01\0\0\0\0\0\0")
        return
    cw.write(b"\x05\x00\x00\x01\0\0\0\0\0\0")
    await cw.drain()
    await relay(cr, cw, rr, rw)


async def http_proxy(first, cr, cw):
    head = first + await asyncio.wait_for(cr.readuntil(b"\r\n\r\n"), 10)
    lines = head.split(b"\r\n")
    method, target, ver = lines[0].decode("latin1").split(" ", 2)
    hdrs, auth = [], ""
    for l in lines[1:]:
        if not l:
            continue
        k, _, v = l.decode("latin1").partition(":")
        kl = k.strip().lower()
        if kl == "proxy-authorization":
            auth = v.strip()
        elif kl not in ("proxy-connection", "connection"):
            hdrs.append((k.strip(), v.strip()))
    ok = False
    if auth.lower().startswith("basic "):
        try:
            u, _, p = base64.b64decode(auth[6:]).decode("utf-8", "ignore").partition(":")
            ok = auth_ok(u, p)
        except Exception:
            pass
    if not ok:
        cw.write(b'HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm="proxy"\r\n'
                 b"Content-Length: 0\r\nConnection: close\r\n\r\n")
        return
    try:
        if method == "CONNECT":
            host, _, port = target.rpartition(":")
            rr, rw = await open_out(host.strip("[]"), int(port))
            cw.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        else:
            u = urlsplit(target)
            rr, rw = await open_out(u.hostname, u.port or 80)
            path = (u.path or "/") + ("?" + u.query if u.query else "")
            out = f"{method} {path} {ver}\r\n" + "".join(f"{k}: {v}\r\n" for k, v in hdrs) + "Connection: close\r\n\r\n"
            rw.write(out.encode("latin1"))
    except Exception:
        cw.write(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
        return
    await relay(cr, cw, rr, rw)


async def handle(cr, cw):
    async with SEM:
        try:
            first = await asyncio.wait_for(cr.readexactly(1), 10)
            if first == b"\x05":
                await socks5(cr, cw)
            else:
                await http_proxy(first, cr, cw)
        except Exception:
            pass
        finally:
            try:
                cw.close()
            except Exception:
                pass


async def proxy_supervisor():
    while True:
        port_ev.clear()
        port = S["port"]
        try:
            srv = await asyncio.start_server(handle, "0.0.0.0", port)
        except OSError as e:
            log(f"监听 :{port} 失败: {e}")
            await asyncio.sleep(10)
            continue
        log(f"代理监听 :{port}（SOCKS5 / HTTP，需认证）")
        await port_ev.wait()
        srv.close()


async def main():
    global rotate_ev, port_ev, SEM
    rotate_ev, port_ev, SEM = asyncio.Event(), asyncio.Event(), asyncio.Semaphore(500)
    os.makedirs(WORKDIR, exist_ok=True)
    await cleanup_routes()
    asyncio.create_task(heartbeat_loop())
    while not S["ready"]:
        await asyncio.sleep(1)
    await asyncio.gather(proxy_supervisor(), tunnel_loop())


if __name__ == "__main__":
    asyncio.run(main())
