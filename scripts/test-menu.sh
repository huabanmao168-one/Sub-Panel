#!/usr/bin/env bash
# Smoke-test the installer-generated menu without touching the real service.
set -euo pipefail
cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.."
tmp=$(mktemp -d)
trap 'rm -rf -- "$tmp"' EXIT
mkdir "$tmp/bin"
awk '/^cat .*<<.MENU.$/ { reading=1; next } reading && /^MENU$/ { exit } reading { print }' install.sh > "$tmp/sub-panel"
test -s "$tmp/sub-panel"
bash -n "$tmp/sub-panel"
cat > "$tmp/bin/systemctl" <<'MOCK'
#!/usr/bin/env bash
printf 'systemctl %s\n' "$*"
MOCK
cat > "$tmp/bin/journalctl" <<'MOCK'
#!/usr/bin/env bash
printf 'journalctl %s\n' "$*"
MOCK
cat > "$tmp/bin/sudo" <<'MOCK'
#!/usr/bin/env bash
exec "$@"
MOCK
chmod +x "$tmp/sub-panel" "$tmp/bin/"*
export PATH="$tmp/bin:$PATH"

[[ $("$tmp/sub-panel" restart) == *'systemctl restart sub-panel.service'* ]]
[[ $("$tmp/sub-panel" logs -f) == 'journalctl --unit sub-panel.service --lines 50 --no-pager -f' ]]
ret=0
"$tmp/sub-panel" </dev/null > "$tmp/no-tty" 2>&1 || ret=$?
[[ $ret == 2 ]]
grep -q '交互菜单需要终端' "$tmp/no-tty"
printf '1\n2\n3\n4\n5\n0\n' | timeout 10 script -qec "$tmp/sub-panel" /dev/null > "$tmp/interactive"
for output in 'Sub-Panel 管理菜单' 'systemctl status --no-pager sub-panel.service' \
  'systemctl restart sub-panel.service' 'systemctl start sub-panel.service' \
  'systemctl stop sub-panel.service' 'journalctl --unit sub-panel.service'; do
  grep -Fq "$output" "$tmp/interactive"
done
printf '安装器管理菜单测试通过。\n'
