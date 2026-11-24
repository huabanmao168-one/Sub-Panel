# Sub-Panel 改造与审查记录

范围：启动与升级、SQLite 配置、管理台、订阅路由、V2Board 上报和订阅响应改写。改动以本地代码和测试为准；没有操作生产机器。

## 问题与处理结果

| 问题 | 处理 | 相关代码 |
|---|---|---|
| 运行设置分散在 YAML 和数据库，旧 YAML 可能在空表时恢复已删除的设置 | SQLite 为唯一运行配置源。旧 YAML 一次性、事务式迁移；已有数据和空列表都保留。系统设置从 UI 保存并显示待重启。新增离线 `restore-settings`，只回滚上一份系统设置 | `cmd/sub-panel/settings.go`、`internal/store/settings.go`、`internal/webui/admin_settings.go` |
| 默认凭据公开；管理端默认对外监听；上报默认无密钥 | 新装改为随机初始密码文件（`0600`）、管理面回环监听、随机上报密钥；旧库不更改现有监听和凭据，保留旧上报兼容。清空上报密钥需要显式提交，UI 会确认 | `internal/config/runtime.go`、`cmd/sub-panel/settings.go`、`internal/webui/suspects.go` |
| 机场和触发规则改名先删后写；机场改名可能更换 `report_id` | 事务内原地改名，对重名和路径冲突返回错误并保留旧记录；机场保留原有上报 ID，关联的已落库事件、上报、展示规则和已处理记录随之迁移 | `internal/store/rename.go`、`internal/webui/webui.go`、`internal/webui/detect_rules.go` |
| `token_hash` 保存的是原始凭据，请求路径也可能带原始 Token | 使用现有盐做 HMAC 标识；历史日志、上报和已处理标记事务迁移并清理旧路径，后续仅存机场配置路径。日志 UI 可查询原始 Token 或完整标识，查询凭据不再放在 URL 里 | `internal/token/token.go`、`internal/store/token_privacy.go`、`internal/webui/webui.go` |
| 伪造订阅已不再需要 | 删除伪造和节点投毒模块、配置、界面筛选与指标。黑名单和触发规则命中直接返回 HTTP 403，不访问上游，正常记录拒绝事件 | `internal/proxy/proxy.go`、`internal/webui/assets/` |
| 绕过 Nginx 的访问及扫描污染订阅统计 | 只接受配置中的 TCP 对端访问订阅和上报；未知订阅路由不写事件。升级后的可信统计独立于无来源标记的旧记录 | `internal/config/ingress.go`、`internal/proxy/proxy.go`、`internal/store/settings.go` |
| Lumi 兼容开关和失败原因不清晰 | 正常放行仍使用可配置的原有 Lumi 格式，拒绝请求不返回订阅；解码错误记录失败。没有改变既有的 UA 判定和客户端加密协议 | `internal/proxy/proxy.go`、`internal/proxy/lumi.go`、`internal/webui/assets/` |
| 加大规则滑窗后运行时仍悄悄按旧容量计算 | 基线容量改为 24 小时，保留库中更大的旧规则；保存时拒绝超出当前容量的配置。计数仍按分钟桶近似 | `internal/detector/detector.go`、`internal/webui/detect_rules.go` |
| 反代、TLS 或独立域名下生成的上报地址不可靠 | 可在数据库/UI 指定外部上报基址；未配置时明确标注当前地址是推算值。接入代码正确转义字符串 | `internal/config/runtime.go`、`internal/webui/suspects.go`、`internal/webui/assets/app.js` |
| 查询和刷新重复绑定；offset 分页遇到写入或白名单过滤会跳页/重复；慢响应覆盖新请求 | 只保留一套事件处理；按 `(时间戳, 记录 ID)` 游标分页，分页时保留原筛选，忽略陈旧响应。支持旧 API 访问方式 | `internal/webui/event_page.go`、`internal/store/store.go`、`internal/webui/assets/app.js` |
| 页面和弹窗视觉不统一，表格空状态跨错列，移动端长文本撑出滚动，Esc 不能关闭全部弹窗 | 统一中文登录页、导航、标题、卡片、状态提示、表格和操作按钮。支持窄屏菜单和页面直达；横向滚动限制在表格容器；弹窗稳定滚动、Esc 关闭、焦点返回，支持减少动画设置 | `internal/webui/assets/` |
| 展示规则编辑器把所有匹配方式都保存成邮箱后缀，还可能接受空替换 | UI 支持并保留原匹配类型；未改替换内容时保留原规则，错误格式和无有效替换会给出反馈 | `internal/webui/assets/`、`internal/store/display_rules.go` |
| 安装器可能把新 systemd unit 装给旧二进制 | 从同一发行版获取 unit，仅为需要 YAML 的旧发行版补齐缺失配置；不覆盖已有 YAML | `install.sh`、`scripts/sub-panel.service` |

## 验收与部署注意事项

- 本地回归覆盖：旧库设置迁移、新装凭据、订阅标识迁移及跨表查询、事务改名与冲突、系统设置回滚、游标不受同时间戳新记录干扰、Lumi 放行兼容、可信入口匹配、直连和未匹配路径不计入统计，以及 HTTP 403 拒绝不访问上游。
- Chromium 使用模拟机场和 123 条请求，检查 1440px、320px 两种宽度下的 12 个页面；四个主要弹窗在 320px 下适配、Esc 可关闭且焦点返回。单次查询只发出一条日志请求，三页显示 50、100、123 条。窄屏横向滚动限制在表格容器内。
- 升级前用数据库副本试跑，尤其是大型日志库；备份 SQLite、旧 YAML 和原有盐文件。已存在的旧备份、外部访问日志、管理员手填备注不在数据库字段迁移范围内。
- 旧安装可能仍用公开口令或清空上报密钥；迁移不会擅自替换，应在设置中检查。生产 systemd 升级、真实 V2Board 反代及真实 Lumi 客户端仍需上线前验收。
- Lumi 的旧格式只用于放行后的客户端兼容，不是安全边界；风控拒绝直接返回 HTTP 403。
