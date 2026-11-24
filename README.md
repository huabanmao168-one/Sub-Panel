# Sub-Panel

V2Board 订阅前置网关 —— 可信 Nginx 来源校验、黑白名单、风控规则、GeoIP 和 Web 管理面板。

## 特性

- 🛡️ **反代清洗**:挡掉浏览器直访、云厂商 IP、海外节点扫描
- 🌍 **GeoIP**:ip2region xdb 满载版,本地 mmap 内存查询
- 🎯 **触发规则**：订阅频次、多 IP、滑窗模型，命中直接返回 HTTP 403，不请求上游
- 📊 **管理面板**:租户管理 / 请求日志 / 异常事件 / 检测规则 / Top IP 地区 ISP
- **可信入口**：直连和未匹配的订阅路径返回 HTTP 404，不写日志、不进入风控和统计
- 🔐 **一键透传**:紧急回滚开关,跳过所有规则
- 📦 **单二进制**:零依赖,systemd 托管,在线升级保留数据

## 一键安装

```bash
curl -fsSL https://raw.githubusercontent.com/huabanmao168-one/Sub-Panel/main/install.sh | sudo bash
```

支持 Linux amd64 / arm64，需要 systemd。安装器只下载已发布的 Release，不部署未打标签的 PR。可先验证下载，不安装、不停服务：

```bash
curl -fsSL https://raw.githubusercontent.com/huabanmao168-one/Sub-Panel/main/install.sh | bash -s -- --check
```

要固定版本，在执行安装脚本时传入 `SUB_PANEL_VERSION=vX.Y.Z`。

## 升级

再跑一次同样的命令即可。会自动:

- 下载并校验发行包和 GeoIP 后才停服务；备份本地二进制、配置、数据库目录和原 unit，再替换文件并重启。
- 保留 `/opt/Sub-Panel/data/`、已有的旧 `config.yml` 和 systemd drop-in。备份保存在 `/opt/Sub-Panel/upgrade-backup.*`；外置数据库和盐文件请自行另行备份。启动失败时不会自动拿旧程序打开已迁移的数据库。
- 首次升级由程序将旧 YAML 的系统设置导入 SQLite。数据库里已有的机场、触发规则（包括空列表）和已修改过的管理员密码不会被覆盖。迁移成功后不再读取 YAML。
- 如果旧 `storage.sqlite_path` 不是默认路径，升级前给 systemd 添加 drop-in，清空原有 `ExecStart=` 后写入 `ExecStart=/opt/Sub-Panel/sub-panel -db /你的路径/sub-panel.db`。如果旧 YAML 不在默认位置，首次迁移追加 `-c /你的路径/config.yml`。

## 目录结构

```
/opt/Sub-Panel/
├── sub-panel              # 主二进制
├── config.yml             # 仅旧版本可能存在；用于一次性迁移，新安装不生成
├── ip2region.xdb          # GeoIP IPv4 数据（旧默认路径在 systemd 私有 /tmp 中兼容）
├── uninstall.sh           # 卸载脚本
└── data/
    ├── sub-panel.db       # SQLite 配置与业务库
    └── salt               # HMAC 盐(首启自动生成)
```

## 首次登录

全新安装的管理面默认只监听 `127.0.0.1:19090`。远程管理时可先运行 `ssh -N -L 19090:127.0.0.1:19090 <用户>@<服务器>`，然后打开 `http://127.0.0.1:19090/`。

账号为 `admin`；随机初始密码保存在 `/opt/Sub-Panel/data/sub-panel.db.initial-password`（权限 `0600`），安装脚本和服务日志不会打印密码。首次登录后请在「设置」修改密码，修改成功后清理初始密码文件。全新安装也会生成上报密钥；升级保留旧实例的监听配置和凭据。

## 管理菜单与常用命令

通过安装脚本安装或升级后，在终端输入 `sub-panel` 打开管理菜单，可查看状态、重启、启动、停止和查看最近日志。需要管理员权限的操作会调用 `sudo`。若终端的 `PATH` 未包含 `/usr/local/bin`，使用 `/usr/local/bin/sub-panel`。

```bash
sub-panel                         # 打开管理菜单
sub-panel status                  # 查看状态
sub-panel restart                 # 重启服务
sub-panel logs -f                 # 实时日志（Ctrl+C 结束）

bash /opt/Sub-Panel/uninstall.sh           # 卸载(保留 config + data)
bash /opt/Sub-Panel/uninstall.sh --purge   # 完全卸载
```

## 监听端口

| 端口    | 用途                       |
|---------|----------------------------|
| `18443` | 供前置 Nginx 使用的订阅网关（新装默认 `127.0.0.1`） |
| `19090` | 管理面板 + API             |

在管理面 → **设置 → 系统配置**修改。系统设置保存到 SQLite 后，重启 `sub-panel` 生效；页面会显示当前实际监听地址和是否有待生效变更。数据库文件的位置用启动参数 `-db` 指定，因为程序读配置前必须先找到数据库。

| 设置入口 | 生效方式 |
|---|---|
| 系统配置：监听地址、外部上报基址、真实 IP、GeoIP 路径、日志保留与批量写入、管理员账号、会话时长和 Lumi 兼容 | 服务重启后生效 |
| 管理员密码、上报密钥、全局跳过风控 | 保存后生效；改密码会使所有会话失效 |
| 机场、名单、触发规则、订阅展示 | 各自页面配置，热生效；超出当前滑窗容量的规则不会保存 |

升级前备份旧 YAML、SQLite 数据库及盐文件。迁移会将历史订阅 Token 转为带密钥的标识并清理历史请求路径；旧备份、外部访问日志仍可能带原始凭据，请限制访问权限，必要时轮换旧令牌。UI 仍支持用原始 Token 或完整标识查日志。已有标识的数据库不要丢失盐文件。

如果改监听后管理面不可达，停止服务后运行 `/opt/Sub-Panel/sub-panel restore-settings`（自定义库时追加 `-db <路径>`），再启动服务。该命令只恢复上一份系统设置，不回滚密码、机场、名单或日志。[改造及验收记录](docs/refactor-audit.md)。

## 配置前置代理

在「设置 → 系统配置 → 订阅入口模式」选择链路。入口校验覆盖订阅和 `/r/` 上报；白名单和应急透传不会绕过它。`/healthz` 不计入统计，管理端不受此规则影响。

### 直连前置代理

网关只接受配置中的 TCP 对端，默认 `127.0.0.1` 与 `::1`。

- **同机部署**：让 Nginx 反代 `http://127.0.0.1:18443`。已有实例可在设置中将订阅监听地址改为回环，重启后生效。
- **跨机或 Docker**：在管理面填入网关实际看到的 Nginx 来源地址（可能是容器网桥或 NAT 出口），保存后重启。若网关监听非回环地址，请用防火墙限制端口只对 Nginx 开放，不要将整个公网或不受信网络放入允许列表。该校验识别连接地址，不能区分同一可信主机上不同进程。
- 需要正确识别客户端 IP 时，将 Nginx 来源同时加入「真实 IP 请求头的可信代理」，并在 Nginx 覆盖而不是沿用客户端传来的请求头。V2Board 上报应使用经 Nginx 转发的公开基址，不再指向网关裸端口。示例可用于同机部署的订阅和上报反代：

```nginx
location / {
    proxy_pass http://127.0.0.1:18443;
    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Forwarded-For $remote_addr;
}
```

### 用户 → 国内 Nginx → Cloudflare → Sub-Panel

1. 选择对应模式，填写 **国内 Nginx 连接 Cloudflare 时的公网出口 IPv4 / IPv6**，每行一个，保存后重启。不要填 Cloudflare IP、Nginx 的内网地址或域名。如果 Nginx 的公网出口变更，需要更新这里；Cloudflare 网段则由程序维护。
2. 程序启动后及每 6 小时从 Cloudflare 官方 API 获取 IPv4/IPv6 回源网段。最新有效名单缓存在 SQLite；同步失败不会清空当前名单，新装无缓存时才用程序附带的初始名单。
3. 网关先校验 TCP 对端在 Cloudflare 官方网段内，再检查由 Cloudflare 设置的 `CF-Connecting-IP` 是否等于某个 Nginx 出口地址。条件未通过的请求不计数。此模式适用于 Cloudflare 普通代理直接回源到 Sub-Panel；如果使用 Tunnel、另一层本机代理、会修改该头的 Worker 或 Pseudo IPv4 覆盖模式，看到的地址会变化，不能直接按这条链配置。
4. 如果要按**原始用户 IP**统计和风控，在国内 Nginx 对应的反代 `location` 里配置 `proxy_set_header X-Sub-Panel-Client-IP $remote_addr;`（必须覆盖传入的同名头），再在设置开启「使用国内 Nginx 写入的原始用户 IP」，保存并重启。不启用或缺少有效头时，日志使用 Nginx 的出口 IP；多个用户会共享该 IP，可能影响 IP 频次规则。若 Nginx 前还有一层代理，先正确设置 Nginx 的可信真实 IP 提取。

首次启用可信入口时，概览、请求日志与异常统计从该次升级时刻开始计算。旧记录不删除；因为之前没有可信的来源信息，不再混入当前面板统计。

## 配置租户

管理面 → 租户管理 → 新增,填:

- `name`:租户标识(英文)
- `subscribe_path`:订阅路径前缀(如 `/sub/cat`)
- `upstream`:上游 V2Board 地址(如 `https://panel.example.com`)
- `upstream_path`:上游订阅路径(一般 `/api/v1/client/subscribe`)

## 本地构建

```bash
git clone https://github.com/huabanmao168-one/Sub-Panel.git
cd Sub-Panel
go build -o sub-panel ./cmd/sub-panel
```

## License

MIT
