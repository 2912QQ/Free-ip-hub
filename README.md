# resi-proxy-hub：家宽代理调度系统（Cloudflare Workers + D1 + VPS agent）

```
 浏览器 ──Basic Auth──▶ Cloudflare Worker (面板 + API) ◀──心跳/策略──▶ VPS agent
                              │                                        │
                          D1 (节点/策略/日志)                 VPNGate → OpenVPN(tun_rp)
                                                                       │
                                            你的程序 ──SOCKS5/HTTP(带认证)──▶ 出口 IP
```

- **控制面（Cloudflare）**：Worker 提供面板与 API，D1 存节点、策略、日志，表结构首次请求自动创建。
- **数据面（VPS）**：`agent.py` 从 VPNGate 拉节点 → 按国家筛选、TCP 预检 → 起 OpenVPN → 用 ip-api 做出口质检（过滤机房 IP）→ 在同一端口提供 SOCKS5 + HTTP 代理。
- 掉线自动切换（探测连续失败 / openvpn 退出），面板可一键换 IP、改目标国家和端口。
- 代理强制认证，凭据未配置时 agent 拒绝一切连接；DNS 经隧道解析，目标地址限制为公网 IPv4。

## 部署

### 1. Cloudflare 侧

```bash
npm install
npx wrangler d1 create proxy-db        # 把输出的 database_id 填进 wrangler.toml

npx wrangler secret put WEB_USER       # 面板用户名
npx wrangler secret put WEB_PASS       # 面板密码
npx wrangler secret put AGENT_TOKEN    # agent 通信令牌，建议 `openssl rand -hex 24`
npx wrangler secret put PROXY_USER     # 代理用户名
npx wrangler secret put PROXY_PASS     # 代理密码

npx wrangler deploy
```

也可以把仓库推到 GitHub，用 Workers Builds 连接自动部署（secret 在 Dashboard 的 Settings → Variables 里设置，D1 在 Bindings 里绑定为 `DB`）。

> 本项目没有默认口令：`WEB_USER/WEB_PASS` 未设置时面板返回 503。

### 2. VPS 侧

要求：海外 Linux VPS，root，开启 TUN/TAP，**OpenVPN ≥ 2.5**（Debian 11+/Ubuntu 22.04+）。

打开面板，复制「接入新节点」里的命令，在 VPS 上执行即可（安装依赖、写入 systemd 服务、自动启动）。然后在防火墙/安全组放行代理端口（默认 7920）。

### 3. 使用

面板的「可用代理列表」会给出 `socks5://用户:密码@VPS_IP:端口`，也可以直接拉取：

```bash
curl -u admin:密码 "https://你的worker域名/api/proxies"                 # 纯文本
curl -u admin:密码 "https://你的worker域名/api/proxies?format=json"     # JSON
curl -u admin:密码 "https://你的worker域名/api/proxies?scheme=http"     # HTTP 格式
curl --proxy socks5h://proxy:密码@VPS_IP:7920 https://api.ipify.org     # 验证出口
```

## 目录

| 文件 | 作用 |
| --- | --- |
| `src/index.js` | Worker：路由、鉴权、心跳、策略、代理列表 |
| `src/panel.html` | 面板前端（无外部依赖，随 Worker 下发） |
| `src/agent.py` | VPS agent（仅标准库） |
| `src/install.sh` | 一键安装脚本模板 |
| `wrangler.toml` | Worker / D1 / 文本打包规则 |

## 已知限制

- VPNGate 是志愿者节点，**“家宽”属性靠 ip-api 的 hosting 标记过滤，只能做到尽力而为**；出口质量、稳定性、速度都有波动，不适合需要稳定 SLA 的场景。
- 目前是单隧道 + 自动重选；参考项目里的“主备双隧道零中断切换”可作为下一步（在 agent 里并行维护两个 tun 设备并用 ip rule 切换）。
- ip-api 免费接口仅 HTTP、有频率限制（只在建链时调用一次）；需要更严格的 IP 质检可换成 IPinfo / IP2Location 等付费 API。
- 免费节点由第三方运营，**不要通过它传输敏感信息**。
- 请只用于合法用途，并遵守 VPNGate、Cloudflare 以及目标站点的服务条款；开放端口时务必保持认证开启，避免变成公共开放代理。
