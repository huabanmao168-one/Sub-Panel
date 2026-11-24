#!/usr/bin/env bash
# Install or upgrade a tagged Sub-Panel release. --check verifies artifacts only.
set -euo pipefail
umask 077

REPO="huabanmao168-one/Sub-Panel"
INSTALL_DIR="/opt/Sub-Panel"
SERVICE_NAME="sub-panel.service"
SERVICE_FILE="/etc/systemd/system/${SERVICE_NAME}"
XDB_URL="https://raw.githubusercontent.com/lionsoul2014/ip2region/f1781b7f9b7a17c96246433d83804404f0a22120/data/ip2region_v4.xdb"
XDB_SHA256="a29fb3e8b204dfdf45b9bc082e12845b5eaac18cd467849d2888baa9fde383c8"

log() { printf '[Sub-Panel] %s\n' "$*"; }
warn() { printf '[Sub-Panel] %s\n' "$*" >&2; }
die() { warn "$*"; exit 1; }

check=0
case "${1:-}" in
  '') ;;
  --check) check=1 ;;
  -h|--help) printf '用法: bash install.sh [--check]\n可选环境变量: SUB_PANEL_VERSION=vX.Y.Z, SUB_PANEL_REFRESH_XDB=1\n'; exit 0 ;;
  *) die "不支持的参数: $1" ;;
esac
[[ "$#" -le 1 ]] || die '只接受一个参数'
[[ "$(uname -s)" == Linux ]] || die '仅支持使用 systemd 的 Linux'
case "$(uname -m)" in
  x86_64|amd64) arch=amd64 ;;
  aarch64|arm64) arch=arm64 ;;
  *) die '仅支持 Linux amd64 / arm64' ;;
esac
for cmd in curl tar sha256sum awk grep mktemp install; do
  command -v "$cmd" >/dev/null || die "缺少命令: $cmd"
done
if (( ! check )); then
  [[ $EUID -eq 0 ]] || die '请以 root 或 sudo 运行'
  for cmd in systemctl flock; do command -v "$cmd" >/dev/null || die "缺少命令: $cmd"; done
  systemctl show --property=Version --value >/dev/null || die '无法连接到 systemd，未修改服务'
  exec 9>/run/lock/sub-panel-install.lock
  flock -n 9 || die '另一个 Sub-Panel 安装任务正在运行'
fi

tmp="$(mktemp -d)"
backup=''
was_active=0
replacing=0
cleanup() {
  local status=$?
  rm -rf -- "$tmp"
  if (( status != 0 )); then
    if (( was_active && ! replacing )); then
      systemctl start "$SERVICE_NAME" || warn '备份未完成，旧服务也未能重新启动。'
    elif [[ -n "$backup" ]]; then
      warn "升级未完成，原文件和默认数据目录的备份位于 $backup。请勿用旧二进制直接运行已迁移的数据库。"
    fi
  fi
}
trap cleanup EXIT

download() { curl --fail --silent --show-error --location --retry 2 --retry-delay 1 --connect-timeout 10 --max-time 180 --output "$2" "$1"; }
verify_sha() {
  local expected=${1,,} actual
  [[ "$expected" =~ ^[0-9a-f]{64}$ ]] || return 1
  actual="$(sha256sum -- "$2")" || return 1
  [[ "${actual%% *}" == "$expected" ]]
}

tag=${SUB_PANEL_VERSION:-}
if [[ -z "$tag" ]]; then
  download "https://api.github.com/repos/${REPO}/releases/latest" "$tmp/release.json" || die '无法读取最新发行版；可设置 SUB_PANEL_VERSION=vX.Y.Z'
  tag="$(awk -F '"' '/^[[:space:]]*"tag_name"[[:space:]]*:/ {print $4; exit}' "$tmp/release.json")"
fi
[[ "$tag" =~ ^v[0-9]+(\.[0-9]+){2}([-+][A-Za-z0-9._-]+)?$ ]] || die '无效的发行版版本号'
asset="sub-panel-linux-${arch}.tar.gz"
release="https://github.com/${REPO}/releases/download/${tag}"
raw="https://raw.githubusercontent.com/${REPO}/${tag}"
log "正在下载并校验 ${tag} (${arch})"
download "$release/$asset" "$tmp/$asset" || die '二进制下载失败'
download "$release/$asset.sha256" "$tmp/$asset.sha256" || die 'SHA-256 文件下载失败'
expected="$(awk 'NR==1 {print $1}' "$tmp/$asset.sha256")"
verify_sha "$expected" "$tmp/$asset" || die '发行包 SHA-256 校验失败，未修改服务'
# Extract only named regular content into newly created files.
tar -xzOf "$tmp/$asset" sub-panel > "$tmp/sub-panel" || die '发行包缺少二进制'
chmod 0755 "$tmp/sub-panel"
[[ "$("$tmp/sub-panel" version)" == "${tag#v}" ]] || die '发行包中的二进制版本与标签不符'
if ! tar -xzOf "$tmp/$asset" sub-panel.service > "$tmp/sub-panel.service" 2>/dev/null; then
  download "$raw/scripts/sub-panel.service" "$tmp/sub-panel.service" || die '无法获取同版本的 systemd unit'
fi
grep -Eq '^ExecStart=/opt/Sub-Panel/sub-panel([[:space:]]|$)' "$tmp/sub-panel.service" || die '发行版的 systemd unit 缺少预期启动命令'
legacy=0
if grep -Eq '^ExecStart=.*[[:space:]]-c[[:space:]]' "$tmp/sub-panel.service"; then
  legacy=1
  if [[ ! -e "$INSTALL_DIR/config.yml" ]] || (( check )); then
    download "$raw/configs/config.example.yml" "$tmp/config.yml" || die '无法获取旧版默认配置'
  fi
fi

if (( check )) || [[ ! -s "$INSTALL_DIR/ip2region.xdb" ]] || [[ "${SUB_PANEL_REFRESH_XDB:-0}" == 1 ]]; then
  log '正在下载并校验 GeoIP IPv4 数据库'
  if ! download "$XDB_URL" "$tmp/ip2region.xdb" || ! verify_sha "$XDB_SHA256" "$tmp/ip2region.xdb"; then
    rm -f -- "$tmp/ip2region.xdb"
    if (( check )); then die 'GeoIP 下载或校验失败'; fi
    warn 'GeoIP 下载或校验失败，保留现有库；新装可在设置页补配。'
  fi
fi
if (( check )); then
  log "${tag} ($arch) 发行包、systemd unit 和 GeoIP 下载验证通过；未修改系统"
  exit 0
fi

# Catch legacy databases outside the standard location before stopping an
# installation that has no systemd drop-in to select the custom database.
if (( ! legacy )) && [[ -f "$INSTALL_DIR/config.yml" ]]; then
  dropins="$(systemctl show "$SERVICE_NAME" --property=DropInPaths --value 2>/dev/null || true)"
  if [[ -z "$dropins" && ! -f "$INSTALL_DIR/data/.sqlite-bootstrap" ]]; then
    db_hint="$("$tmp/sub-panel" legacy-db-path "$INSTALL_DIR/config.yml")" || die '旧 YAML 无法读取；请先确认数据库位置，服务未停止'
    if [[ "$db_hint" != "$INSTALL_DIR/data/sub-panel.db" ]]; then
      die '旧实例使用自定义 SQLite 路径。请先备份并按 README 添加 -db 的 systemd drop-in，服务未停止。'
    fi
  fi
fi

mkdir -p -- "$INSTALL_DIR/data"
if [[ -x "$INSTALL_DIR/sub-panel" || -e "$SERVICE_FILE" ]]; then
  log '停止旧服务并备份现有文件'
  if systemctl is-active --quiet "$SERVICE_NAME"; then was_active=1; fi
  if [[ "$(systemctl show "$SERVICE_NAME" --property=LoadState --value)" != not-found ]]; then
    systemctl stop "$SERVICE_NAME"
  fi
  backup="$(mktemp -d "$INSTALL_DIR/upgrade-backup.XXXXXXXX")"
  for file in sub-panel config.yml data ip2region.xdb; do
    if [[ -e "$INSTALL_DIR/$file" ]]; then cp -a -- "$INSTALL_DIR/$file" "$backup/"; fi
  done
  if [[ -f "$SERVICE_FILE" ]]; then cp -a -- "$SERVICE_FILE" "$backup/"; fi
  log "备份位置: $backup（外置数据库、盐及自定义 unit drop-in 请单独备份）"
fi

# Stage beside the destination so rename cannot expose a partial executable.
replace_file() {
  local source=$1 target=$2 mode=$3 staging
  staging="$(mktemp "${target}.new.XXXXXXXX")"
  if ! install -m "$mode" -- "$source" "$staging" || ! mv -fT -- "$staging" "$target"; then
    rm -f -- "$staging"
    return 1
  fi
}
replacing=1
replace_file "$tmp/sub-panel" "$INSTALL_DIR/sub-panel" 0755
replace_file "$tmp/sub-panel.service" "$SERVICE_FILE" 0644
if [[ -f "$tmp/config.yml" && ! -e "$INSTALL_DIR/config.yml" ]]; then
  replace_file "$tmp/config.yml" "$INSTALL_DIR/config.yml" 0600
fi
if [[ -f "$tmp/ip2region.xdb" ]]; then
  replace_file "$tmp/ip2region.xdb" "$INSTALL_DIR/ip2region.xdb" 0644
fi

cat > "$tmp/uninstall.sh" <<'UNINST'
#!/usr/bin/env bash
set -euo pipefail
[[ $EUID -eq 0 ]] || { echo '请以 root 或 sudo 运行' >&2; exit 1; }
case "${1:-}" in ''|--purge) ;; *) echo '用法: uninstall.sh [--purge]' >&2; exit 2 ;; esac
systemctl disable --now sub-panel.service
rm -f -- /etc/systemd/system/sub-panel.service
systemctl daemon-reload
if [[ "${1:-}" == '--purge' ]]; then
  rm -rf -- /opt/Sub-Panel
  echo '已卸载并删除 /opt/Sub-Panel；外置数据和 systemd drop-in 未删除。'
else
  rm -f -- /opt/Sub-Panel/sub-panel
  echo '已卸载；保留配置、SQLite、盐文件和升级备份。'
fi
UNINST
replace_file "$tmp/uninstall.sh" "$INSTALL_DIR/uninstall.sh" 0755

systemctl daemon-reload
systemctl restart "$SERVICE_NAME" || die "启动失败，请查看 journalctl -u $SERVICE_NAME -n 50 --no-pager"
for _ in 1 2 3 4 5; do
  sleep 1
  systemctl is-active --quiet "$SERVICE_NAME" || die "服务未稳定运行，请查看 journalctl -u $SERVICE_NAME -n 50 --no-pager"
done
systemctl enable "$SERVICE_NAME" >/dev/null
if (( ! legacy )); then touch "$INSTALL_DIR/data/.sqlite-bootstrap"; fi
log "${tag} 安装完成；管理面地址见 journalctl -u $SERVICE_NAME（管理面监听中）"
if [[ -f "$INSTALL_DIR/data/sub-panel.db.initial-password" ]]; then
  log '新装管理面默认只监听 127.0.0.1:19090，建议通过 SSH 端口转发访问。'
  log "初始凭据: admin；密码文件 $INSTALL_DIR/data/sub-panel.db.initial-password（请登录后改密）"
fi
log '前置 Nginx 及跨机升级配置见仓库 README；本脚本不会修改防火墙或 Nginx。'
