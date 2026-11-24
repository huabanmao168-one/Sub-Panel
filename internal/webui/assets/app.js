// Sub-Panel web UI

const state = { tenant: '', window: '24h' };

const $ = sel => document.querySelector(sel);
const $$ = sel => Array.from(document.querySelectorAll(sel));

function fmtTime(ts) {
  if (!ts) return '';
  const d = new Date(ts);
  return d.toLocaleString('zh-CN', { hour12: false });
}
function fmtSince(ts) {
  if (!ts) return '从未';
  const diff = Date.now() - new Date(ts).getTime();
  if (diff < 60_000) return Math.floor(diff/1000) + ' 秒前';
  if (diff < 3600_000) return Math.floor(diff/60_000) + ' 分钟前';
  if (diff < 86400_000) return Math.floor(diff/3600_000) + ' 小时前';
  return Math.floor(diff/86400_000) + ' 天前';
}
function escapeHTML(s) {
  if (s == null) return '';
  return String(s).replace(/[&<>"']/g, c => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'
  }[c]));
}
function tokenShort(id) {
  const value = String(id || '');
  return value.length > 26 ? value.slice(0, 18) + '…' + value.slice(-6) : value;
}
const ACTION_CN = {
  pass: '放行',
  deny: '拒绝',
  lumi_failed: 'Lumi 订阅处理失败',
  display: '展示改写',
  display_failed: '展示处理失败',
};
function actionLabel(a) { return ACTION_CN[a] || a || '-'; }

// tag 中文翻译。带 `:` 的 tag(如 bl_oversea:US / cloud_ip:aws / token_freq=10>=5 window=60s)
// 拆开拼:前缀翻译 + 后缀(国家/服务商/数值)原样附加。
const TAG_PREFIX_CN = {
  // 全局黑名单
  'bl_oversea':     '黑名单·海外',
  'bl_cloud':       '黑名单·云厂商',
  'bl_cn_idc':      '黑名单·国内IDC',
  'bl_browser':     '黑名单·浏览器直访',
  'bl_isp':         '黑名单·运营商',
  // 白名单 / 路径
  'ip_whitelist':   '白名单放行',
  'banlist_ip':     'IP 黑名单',
  'passthrough_all': '全局跳过风控',
  'lumi_encrypt': 'Lumi 兼容处理',
  'encrypt_failed': 'Lumi 加密失败',
  'decode_failed': '订阅解压失败',
  'body_too_large': '订阅正文过大',
  // 上游
  'upstream_bad':   '上游异常',
  // 触发规则
  'token_freq':           '单 token 频次',
  'ip_freq':              '单 IP 频次',
  'token_distinct_ips':   '单 token 多 IP',
  'ip_distinct_tokens':   '单 IP 多 token',
  'cloud_ip':             '命中云厂商',
  'country_in':           '国家命中',
  'country_not_in':       '国家排除',
  'usage_type_in':        '用途命中',
  'usage_type_not_in':    '用途排除',
  'isp_contains':         '运营商关键字',
};

// usage_type 中文映射(IPIP xdb 字段值)
const USAGE_LABEL = {
  'IDC':   '数据中心',
  'CDN':   '内容分发',
  'DNS':   '域名解析',
  'EDU':   '教育机构',
  'GTW':   '企业专线',
  'GOV':   '政府机构',
  'DYN':   '家庭宽带',
  'MOB':   '移动网络',
  'COM':   '商业宽带',
  'ORG':   '组织机构',
  'NET':   '基础设施',
  'BOGON': '保留IP',
};
function usageLabel(u) {
  if (!u) return '';
  const k = String(u).toUpperCase().trim();
  return USAGE_LABEL[k] || u;
}

function tagLabel(t) {
  if (!t) return '';
  // 处理 token_freq=10>=5 window=60s 这种带 = 的格式
  const eqIdx = t.indexOf('=');
  if (eqIdx > 0) {
    const head = t.slice(0, eqIdx);
    if (TAG_PREFIX_CN[head]) return TAG_PREFIX_CN[head] + ' ' + t.slice(eqIdx + 1);
  }
  // 处理 bl_oversea:US / cloud_ip:aws / banlist_ip:reason 这种带 : 的
  const colonIdx = t.indexOf(':');
  if (colonIdx > 0) {
    const head = t.slice(0, colonIdx);
    if (TAG_PREFIX_CN[head]) return TAG_PREFIX_CN[head] + '(' + t.slice(colonIdx + 1) + ')';
  }
  return TAG_PREFIX_CN[t] || t;
}

let toastTimer;
function toast(msg, kind = '') {
  const t = $('#toast');
  t.textContent = msg;
  t.className = 'toast show ' + kind;
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => t.className = 'toast ' + kind, 3000);
}

let inflightRequests = 0;
let progressTimer;
async function requestJSON(path, method = 'GET', body, headers = {}) {
  const bar = $('#progressBar');
  clearTimeout(progressTimer);
  if (++inflightRequests === 1) bar.className = 'progress-bar loading';
  try {
    const options = method === 'GET' ? { headers } : {
      method, headers: { 'Content-Type': 'application/json', ...headers }, body: JSON.stringify(body || {}),
    };
    const r = await fetch(path, options);
    if (r.status === 401) { location.href = '/login'; return null; }
    const data = await r.json().catch(() => null);
    if (!r.ok) return { ...data, ok: false, error: data?.error || data?.msg || '请求失败（' + r.status + '）' };
    return data ?? { ok: false, error: '服务器返回了无效数据' };
  } catch {
    return { ok: false, error: '无法连接管理服务，请检查网络后重试' };
  } finally {
    if (--inflightRequests === 0) {
      bar.className = 'progress-bar done';
      progressTimer = setTimeout(() => { bar.className = 'progress-bar'; }, 500);
    }
  }
}
async function api(path, headers) {
  const data = await requestJSON(path, 'GET', undefined, headers);
  if (data?.ok === false) { toast(data.error, 'error'); return null; }
  return data;
}
function apiPost(path, body) { return requestJSON(path, 'POST', body); }

// ---- 路由 ----

const TAB_TITLES = {
  'dashboard': '概览',
  'events': '请求日志',
  'resolved': '已处理 Token',
  'ip-bans': '黑名单',
  'ip-whitelist': 'IP 白名单',
  'ua-blacklist': 'UA 黑名单',
  'detect-rules': '触发规则',
  'cloud-ip': 'GeoIP 库',
  'suspects': '嫌疑用户',
  'tenants': '机场管理',
  'display-rules': '订阅展示',
  'settings': '设置',
};

const TAB_DESCRIPTIONS = {
  dashboard: '仅统计经可信前置 Nginx 转发的有效订阅路由请求。',
  events: '筛选订阅请求，核查命中规则或异常访问。',
  resolved: '查看已处理的订阅，并按需恢复到请求日志。',
  'ip-bans': '维护封禁 IP 与全局拦截规则。',
  'ip-whitelist': '允许指定 IP 或网段跳过风控。',
  'ua-blacklist': '管理需要拦截的客户端标识。',
  'display-rules': '按机场和匹配条件定制订阅的显示名称。',
  'cloud-ip': '检查地理库状态，查询 IP 的位置和用途。',
  'detect-rules': '设置请求频次、IP 分布与地理匹配条件。',
  suspects: '结合上报数据与订阅请求，核查异常用户。',
  tenants: '配置订阅入口、上游地址与上报接入。',
  settings: '管理系统配置、管理员密码与应急开关。',
};

const TAB_LOADERS = {
  'dashboard': () => loadSummary(),
  'events': () => loadEvents(),
  'resolved': () => loadResolved(),
  'ip-bans': () => loadBans(),
  'ip-whitelist': () => loadIPWhitelist(),
  'ua-blacklist': () => loadUABlacklist(),
  'display-rules': () => loadDisplayRules(),
  'cloud-ip': () => loadGeoIPInfo(),
  'detect-rules': () => loadRulesTable(),
  'suspects': () => loadSuspects(),
  'tenants': () => loadTenantsTable(),
  'settings': () => Promise.all([loadSettings(), loadPassthrough(), loadReportSecret()]),
};

const tenantFilterTabs = new Set(['dashboard', 'events', 'resolved', 'suspects']);
const windowFilterTabs = new Set(['dashboard', 'events']);
function updateTopbar(tab) {
  $('#tenantSel').hidden = !tenantFilterTabs.has(tab);
  $('#windowSel').hidden = !windowFilterTabs.has(tab);
}
function setMenuOpen(open) {
  $('#sidebar').classList.toggle('menu-open', open);
  $('#navToggle').setAttribute('aria-expanded', String(open));
}
let activeTab;
function currentTab() {
  const tab = location.hash.slice(1);
  return Object.hasOwn(TAB_LOADERS, tab) ? tab : 'dashboard';
}
function activateTab(tab) {
  if (activeTab === tab) return;
  closeActiveDialog();
  activeTab = tab;
  for (const a of $$('.navlink')) {
    const active = a.dataset.tab === tab;
    a.classList.toggle('active', active);
    if (active) a.setAttribute('aria-current', 'page');
    else a.removeAttribute('aria-current');
  }
  $$('.tab').forEach(s => s.classList.toggle('active', s.id === 'tab-' + tab));
  $('#pageTitle').textContent = TAB_TITLES[tab];
  $('#pageDescription').textContent = TAB_DESCRIPTIONS[tab];
  document.title = `${TAB_TITLES[tab]} · Sub-Panel`;
  updateTopbar(tab);
  window.scrollTo(0, 0);
  TAB_LOADERS[tab]();
}
$('#navToggle').addEventListener('click', () => {
  const open = !$('#sidebar').classList.contains('menu-open');
  setMenuOpen(open);
  if (open) $('.navlink.active')?.focus();
});
$$('.navlink').forEach(a => {
  a.href = '#' + a.dataset.tab;
  a.addEventListener('click', e => {
    if (e.ctrlKey || e.metaKey || e.shiftKey || e.altKey) return;
    e.preventDefault();
    if ($('#sidebar').classList.contains('menu-open')) {
      setMenuOpen(false);
      $('#navToggle').focus();
    }
    if (location.hash !== a.hash) history.pushState(null, '', a.hash);
    activateTab(a.dataset.tab);
  });
});
window.addEventListener('hashchange', () => activateTab(currentTab()));
$('.skip-link').addEventListener('click', e => {
  e.preventDefault();
  $('#main-content').focus();
});

$('#refreshBtn').addEventListener('click', e => withLoading(e.currentTarget, () => TAB_LOADERS[activeTab || 'dashboard']()));

$('#logoutBtn').addEventListener('click', async () => {
  const r = await apiPost('/api/logout', {});
  if (r?.ok) location.href = '/login';
  else if (r) toast(r.error || '退出失败', 'error');
});

$('#tenantSel').addEventListener('change', e => {
  state.tenant = e.target.value;
  TAB_LOADERS[activeTab || 'dashboard']();
});

$('#windowSel').addEventListener('change', e => {
  state.window = e.target.value;
  TAB_LOADERS[activeTab || 'dashboard']();
});

// ---- tenants ----
async function loadTenants() {
  const ts = await api('/api/tenants');
  if (!ts) return;
  refreshTenantSelector(ts);
}

// ---- dashboard ----
let summaryRequest = 0;
async function loadSummary() {
  const request = ++summaryRequest;
  const q = new URLSearchParams({ tenant: state.tenant, window: state.window });
  const s = await api('/api/summary?' + q);
  if (request !== summaryRequest || !s) return;
  const cards = $('#summaryCards');
  cards.innerHTML = '';
  const data = [
    ['total', '总请求', s.total_events],
    ['pass', '放行', s.pass],
    ['deny', '拒绝或失败', s.deny],
    ['', '独立 IP', s.unique_ips],
    ['', '独立订阅', s.unique_tokens],
  ];
  for (const [cls, label, val] of data) {
    const c = document.createElement('div');
    c.className = 'stat-card ' + cls;
    c.innerHTML = `<div class="label">${cls ? '<span class="dot"></span>' : ''}${label}</div><div class="value">${Number(val ?? 0).toLocaleString('zh-CN')}</div>`;
    cards.appendChild(c);
  }
  const ipTbody = $('#topIPs tbody'); ipTbody.innerHTML = '';
  (s.top_ips || []).forEach(k => {
    const tr = document.createElement('tr');
    const isp = k.isp ? escapeHTML(k.isp) : '<span class="muted">未知</span>';
    tr.innerHTML = `<td class="mono">${escapeHTML(k.key)}</td><td>${k.region ? escapeHTML(k.region) : '<span class="muted">未知</span>'}</td><td>${isp}</td><td style="text-align:right" class="mono">${k.count}</td>`;
    ipTbody.appendChild(tr);
  });
  const tokTbody = $('#topTokens tbody'); tokTbody.innerHTML = '';
  (s.top_tokens || []).forEach(k => {
    const tr = document.createElement('tr');
    tr.innerHTML = `<td class="mono copyable ev-token-expand" data-copy="${escapeHTML(k.key)}" data-full="${escapeHTML(k.key)}" data-short="${escapeHTML(tokenShort(k.key))}" title="点击展开 / 再点复制">${escapeHTML(tokenShort(k.key))}</td><td style="text-align:right" class="mono">${k.count}</td>`;
    tokTbody.appendChild(tr);
  });
  if (!ipTbody.children.length) setEmptyRow(ipTbody, '当前范围内没有 IP 记录');
  if (!tokTbody.children.length) setEmptyRow(tokTbody, '当前范围内没有订阅记录');
  bindCopyHandlers(tokTbody);
}

// ---- events ----
const EV_PAGE_SIZE = 50;
let evPage = { query: null, cursor: '', count: 0, loading: false };

function renderEventCard(e) {
  const card = document.createElement('div');
  card.className = 'ev-card';
  const region = [e.CountryName, e.Province, e.City].filter(x => x && x !== '0').join(' · ') || '未知';
  const isp = e.ISP && e.ISP !== '0' ? escapeHTML(e.ISP) : '<span class="muted">未知</span>';
  const tags = (e.RuleTags || []).length
    ? (e.RuleTags || []).map(t => `<span class="pill tag" title="${escapeHTML(t)}">${escapeHTML(tagLabel(t))}</span>`).join(' ')
    : '';
  const tokenFull = e.TokenHash || '';
  const ua = e.UA || '';
  const flagBit = e.Flag ? `<span class="kv-sep">·</span><span class="mono">${escapeHTML(e.Flag)}</span>` : '';
  const tenantBit = (e.Tenant && e.Tenant !== '_unmatched') ? `<span class="kv-sep">·</span><span class="ev-tenant">${escapeHTML(e.Tenant)}</span>` : '';
  const pathBit = e.Path ? `<span class="mono ev-path" title="${escapeHTML(e.Path)}">${escapeHTML(e.Path)}</span>` : '<span class="muted">(无)</span>';
  const usageBit = e.Usage
    ? `<span class="pill usage ${escapeHTML(String(e.Usage).toLowerCase())}" title="${escapeHTML(e.Usage)}">${escapeHTML(usageLabel(e.Usage))}</span>`
    : '';
  // 已处理按钮:仅当有 token 时显示。data-tenant 用事件自己的 tenant(不是当前过滤)。
  const resolveBtn = tokenFull
    ? `<button class="ev-resolve" data-token="${escapeHTML(tokenFull)}" data-tenant="${escapeHTML(e.Tenant || '')}" title="标记此 token 为已处理,后续不再出现">已处理</button>`
    : '';
  // 重置滑窗按钮:把此 token 在风控滑窗里的累计计数清掉,把它"拉出来"。
  const resetBtn = (tokenFull && e.Action === 'deny')
    ? `<button class="ev-reset" data-token="${escapeHTML(tokenFull)}" title="清除该订阅的频率累计，不解除名单或规则限制">重置窗口</button>`
    : '';
  card.innerHTML = `
    <div class="ev-card-head">
      <span class="pill ${e.Action || ''}">${escapeHTML(actionLabel(e.Action))}</span>
      <span class="ev-time mono">${escapeHTML(fmtTime(e.TS))}</span>
      <span class="ev-status mono">HTTP ${e.Status || '—'}</span>
      <span class="ev-spacer"></span>
      ${tags}
      ${resetBtn}
      ${resolveBtn}
    </div>
    <div class="ev-row-full">
      <span class="ev-label">订阅</span>
      ${tokenFull
        ? `<span class="mono copyable ev-token ev-token-expand" data-copy="${escapeHTML(tokenFull)}" data-full="${escapeHTML(tokenFull)}" data-short="${escapeHTML(tokenShort(tokenFull))}" title="点击展开 / 再点复制">${escapeHTML(tokenShort(tokenFull))}</span>`
        : '<span class="muted">(无)</span>'}
      ${flagBit}${tenantBit}
    </div>
    <div class="ev-row-full">
      <span class="ev-label">路径</span>
      ${pathBit}
    </div>
    <div class="ev-row-full">
      <span class="ev-label">UA</span>
      ${ua
        ? `<span class="mono ev-ua">${escapeHTML(ua)}</span>`
        : '<span class="muted">(无)</span>'}
    </div>
    <div class="ev-meta">
      <span class="ev-meta-item"><span class="ev-label">IP</span>
        <span class="mono">${escapeHTML(e.ClientIP || '—')}</span>
      </span>
      <span class="ev-meta-item"><span class="ev-label">地区</span><span>${escapeHTML(region)}</span></span>
      <span class="ev-meta-item"><span class="ev-label">ISP</span><span>${isp}</span></span>
      <span class="ev-meta-item"><span class="ev-label">ASN</span><span class="mono">${e.ASN ? escapeHTML(e.ASN) : '—'}</span></span>
      ${usageBit ? `<span class="ev-meta-item"><span class="ev-label">用途</span>${usageBit}</span>` : ''}
    </div>
  `;
  return card;
}

function bindCopyHandlers(scope) {
  scope.querySelectorAll('.copyable').forEach(el => {
    if (el.dataset.copyBound) return;
    el.dataset.copyBound = '1';
    el.addEventListener('click', async () => {
      // 带 ev-token-expand:第一次点展开,展开后再点才复制
      if (el.classList.contains('ev-token-expand') && !el.classList.contains('expanded')) {
        el.textContent = el.dataset.full || '';
        el.classList.add('expanded');
        el.setAttribute('title', '点击复制完整 token / 再点收起');
        return;
      }
      const txt = el.getAttribute('data-copy') || '';
      if (!txt) return;
      let ok = false;
      try {
        if (navigator.clipboard && window.isSecureContext) {
          await navigator.clipboard.writeText(txt);
          ok = true;
        } else {
          const ta = document.createElement('textarea');
          ta.value = txt;
          ta.style.position = 'fixed';
          ta.style.opacity = '0';
          ta.style.left = '-9999px';
          document.body.appendChild(ta);
          ta.focus(); ta.select();
          ok = document.execCommand('copy');
          document.body.removeChild(ta);
        }
      } catch (err) {
        console.warn('复制失败', err);
      }
      if (ok) {
        el.classList.add('copied');
        const old = el.getAttribute('title') || '';
        el.setAttribute('title', '已复制 ✓');
        setTimeout(() => { el.classList.remove('copied'); el.setAttribute('title', old); }, 1200);
      }
    });
  });
}

async function loadEvents(append = false) {
  if (append && (!evPage.cursor || evPage.loading)) return;
  const list = $('#evList');
  if (!append) {
    evPage = { cursor: '', count: 0, loading: false, query: new URLSearchParams({
      page: 'cursor', tenant: state.tenant, window: state.window, limit: String(EV_PAGE_SIZE),
      ip: $('#evIP').value.trim(), token: $('#evToken').value.trim(), action: $('#evAction').value,
      usage: $('#evUsage').value, ua: $('#evUA').value.trim(),
      show_whitelist: $('#evShowWL').checked ? '1' : '0',
    }) };
    setEventEmpty('正在查询请求日志…');
    loadEvTopIP(evPage);
  }
  const page = evPage;
  const q = new URLSearchParams(page.query);
  if (append) q.set('cursor', page.cursor);
  page.loading = true;
  updateEvMore();
  list.setAttribute('aria-busy', 'true');
  const tokenFilter = q.get('token');
  q.delete('token');
  const result = await api('/api/events?' + q, tokenFilter ? { 'X-Subscription-Lookup': encodeURIComponent(tokenFilter) } : {});
  if (page !== evPage) return;
  page.loading = false;
  list.setAttribute('aria-busy', 'false');
  if (!result) {
    if (!append) setEventEmpty('查询失败，请重试。');
    updateEvMore();
    return;
  }
  if (page.count === 0) list.replaceChildren();
  const keywords = [q.get('ip'), tokenFilter].filter(Boolean);
  for (const event of result.items) {
    const card = renderEventCard(event);
    highlightTerms(card, keywords);
    bindCopyHandlers(card);
    list.append(card);
  }
  page.count += result.items.length;
  page.cursor = result.next_cursor;
  if (!page.count) setEventEmpty(page.cursor ? '这批日志没有可见记录，可继续加载。' : '没有匹配的请求日志。');
  updateEvMore();
}

function setEventEmpty(message) {
  const row = document.createElement('div');
  row.className = 'empty-state';
  row.textContent = message;
  $('#evList').replaceChildren(row);
}
function updateEvMore() {
  const btn = $('#evMoreBtn');
  btn.hidden = !evPage.cursor;
  btn.disabled = evPage.loading;
  btn.textContent = evPage.loading ? '正在加载…' : `加载更多 · 已显示 ${evPage.count} 条`;
}
$('#evMoreBtn').addEventListener('click', () => loadEvents(true));
$('#evQuery').addEventListener('click', e => withLoading(e.currentTarget, () => loadEvents()));

// 清空日志:针对当前选中的机场;选"全部机场"时清全部。
// 二次确认 + 显示删了多少行。
$('#evPurge').addEventListener('click', async () => {
  const t = state.tenant || '';
  const scope = t ? `机场 [${t}]` : '【全部机场】';
  if (!confirm(`确定清空 ${scope} 的请求日志和异常记录?\n\n此操作不可撤销!`)) return;
  const body = t ? { tenant: t } : { all: true };
  const r = await apiPost('/api/events/purge', body);
  if (r && r.ok) {
    toast(`已清空 ${r.events_deleted} 条请求、${r.incidents_deleted} 条异常记录。`, 'success');
    loadEvents();
  } else if (r) {
    toast(r.error || '清空失败', 'error');
  }
});

// 事件卡片"已处理"按钮:事件委托。
$('#evList').addEventListener('click', async (e) => {
  const resetBtn = e.target.closest('.ev-reset');
  if (resetBtn) {
    const token = resetBtn.dataset.token || '';
    if (!token) return;
    if (!confirm('清除该订阅的频率累计？这不会解除黑名单，也不影响之后重新命中的规则。')) return;
    const r = await apiPost('/api/detector/reset-token', { token });
    if (r && r.ok) {
      toast('已重置滑窗,客户端刷一下订阅试试', 'success');
    } else {
      alert('重置失败:' + (r && r.error ? r.error : '未知错误'));
    }
    return;
  }
  const btn = e.target.closest('.ev-resolve');
  if (!btn) return;
  const token = btn.dataset.token || '';
  const tenant = btn.dataset.tenant || '';
  if (!token) return;
  const note = prompt(`标记 token 为已处理(备注可选):\n\n${token}`, '');
  if (note === null) return; // 用户取消
  const r = await apiPost('/api/resolved/add', { token, tenant, note });
  if (r && r.ok) {
    loadEvents(false);
  } else {
    alert('标记失败:' + (r && r.error ? r.error : '未知错误'));
  }
});

// ---- 已处理 Token 列表 ----
let resolvedRequest = 0;
async function loadResolved() {
  const request = ++resolvedRequest;
  const q = new URLSearchParams();
  if (state.tenant) q.set('tenant', state.tenant);
  const rows = await api('/api/resolved' + (q.toString() ? '?' + q : ''));
  if (request !== resolvedRequest || !rows) return;
  const tbody = $('#resolvedTbody');
  tbody.replaceChildren();
  if (!rows.length) { setEmptyRow(tbody, '没有已处理的订阅'); return; }
  for (const r of rows) {
    const tr = document.createElement('tr');
    tr.innerHTML = `
      <td class="mono copyable" data-copy="${escapeHTML(r.token)}" title="点击复制">${escapeHTML(r.token)}</td>
      <td>${escapeHTML(r.tenant || '-')}</td>
      <td>${escapeHTML(r.note || '-')}</td>
      <td class="mono">${escapeHTML(fmtTime(new Date(r.resolved_ts)))}</td>
      <td><button class="danger res-restore" data-token="${escapeHTML(r.token)}">恢复</button></td>
    `;
    tbody.appendChild(tr);
  }
  bindCopyHandlers(tbody);
}
$('#resolvedTbody')?.addEventListener('click', async (e) => {
  const btn = e.target.closest('.res-restore');
  if (!btn) return;
  if (!confirm('恢复后此 token 将重新出现在请求日志里,确定?')) return;
  const r = await apiPost('/api/resolved/remove', { token: btn.dataset.token });
  if (r && r.ok) loadResolved();
  else alert('恢复失败:' + (r && r.error ? r.error : '未知错误'));
});

$('#resolvedClearAll')?.addEventListener('click', async () => {
  if (!confirm('确定清空全部已处理 token? 此操作不可撤销!')) return;
  const r = await apiPost('/api/resolved/clear', {});
  if (r && r.ok) loadResolved();
  else alert('清空失败:' + (r && r.error ? r.error : '未知错误'));
});

// ---- 请求日志页顶部:异常 IP Top 20(复用 /api/incidents/agg_ip) ----
async function loadEvTopIP(page) {
  const q = new URLSearchParams({
    tenant: page.query.get('tenant'), window: page.query.get('window'), limit: '20',
    action: page.query.get('action'),
  });
  const tbody = $('#evTopIPTbody');
  setEmptyRow(tbody, '正在统计异常 IP…');
  const aggs = await api('/api/incidents/agg_ip?' + q);
  if (page !== evPage) return;
  tbody.replaceChildren();
  if (!aggs?.length) { setEmptyRow(tbody, aggs ? '当前范围内没有异常 IP' : '统计加载失败'); return; }
  for (const a of aggs) {
    const tr = document.createElement('tr');
    const actsHTML = (a.actions || [])
      .map(x => `<span class="pill ${x}">${escapeHTML(actionLabel(x))}</span>`).join(' ');
    const tagsHTML = (a.tags || []).map(t => `<code title="${escapeHTML(t)}">${escapeHTML(tagLabel(t))}</code>`).join(' ');
    tr.innerHTML = `
      <td class="mono">${escapeHTML(a.client_ip)}</td>
      <td style="text-align:right" class="mono"><strong>${a.count}</strong></td>
      <td>${actsHTML}</td>
      <td class="mono" style="font-size:11.5px">${tagsHTML}</td>
      <td class="mono" style="white-space:nowrap">${escapeHTML(fmtTime(new Date(a.last_ts)))}</td>
      <td>
        <button class="btn-mini" data-ip="${escapeHTML(a.client_ip)}" data-act="filter">看详情</button>
        <button class="danger btn-mini" data-ip="${escapeHTML(a.client_ip)}" data-act="ban">封禁</button>
      </td>
    `;
    tbody.appendChild(tr);
  }
  $$('#evTopIPTbody button[data-act="filter"]').forEach(btn => {
    btn.addEventListener('click', () => {
      $('#evIP').value = btn.dataset.ip;
      loadEvents();
    });
  });
  $$('#evTopIPTbody button[data-act="ban"]').forEach(btn => {
    btn.addEventListener('click', async () => {
      const ip = btn.dataset.ip;
      if (!confirm('封禁 ' + ip + ' ?')) return;
      const r = await apiPost('/api/bans/add', { kind: 'ip', target: ip, reason: '请求日志页手动封禁' });
      if (r && r.ok) { toast('已封禁 ' + ip, 'success'); }
      else { toast((r && r.error) || '封禁失败', 'error'); }
    });
  });
}

// ---- bans (仅 IP,token 黑名单已废弃) ----
async function loadBans() {
  const [, bs] = await Promise.all([loadBlacklistCfg(), api('/api/bans')]);
  if (!bs) return;
  const ipTbody = $('#ipBanTbody'); ipTbody.innerHTML = '';
  let ipCount = 0;
  for (const b of bs || []) {
    if (b.Kind !== 'ip') continue;  // 兼容老库残留的 token 行,直接跳过
    const exp = b.ExpiresTS ? fmtTime(b.ExpiresTS) : '<span style="color:var(--danger)">永久</span>';
    const tr = document.createElement('tr');
    tr.innerHTML = `
      <td class="mono" title="${escapeHTML(b.Target)}">${escapeHTML(b.Target)}</td>
      <td>${escapeHTML(b.Reason || '')}</td>
      <td class="mono" title="${escapeHTML((b.RuleTags || []).join(','))}">${escapeHTML((b.RuleTags || []).map(tagLabel).join(','))}</td>
      <td class="mono" style="white-space:nowrap">${escapeHTML(fmtTime(b.CreatedTS))}</td>
      <td class="mono" style="white-space:nowrap">${exp}</td>
      <td><span class="pill ${b.CreatedBy === 'auto' ? 'red' : ''}">${b.CreatedBy === 'auto' ? '自动' : (b.CreatedBy === 'manual' ? '手动' : escapeHTML(b.CreatedBy))}</span></td>
      <td><button class="danger" data-kind="${escapeHTML(b.Kind)}" data-target="${escapeHTML(b.Target)}">解封</button></td>
    `;
    ipTbody.appendChild(tr); ipCount++;
  }
  if (!ipCount) setEmptyRow(ipTbody, '当前没有封禁的 IP');
  $$('#ipBanTbody button.danger').forEach(btn => {
    btn.addEventListener('click', async () => {
      if (!confirm('解封 ' + btn.dataset.target + ' ?')) return;
      const r = await apiPost('/api/bans/remove', { kind: btn.dataset.kind, target: btn.dataset.target });
      if (r && r.ok) { toast('已解封', 'success'); loadBans(); }
      else toast((r && r.error) || '失败', 'error');
    });
  });
}

$('#banIPAddBtn').addEventListener('click', async () => {
  const target = $('#banIPTarget').value.trim();
  if (!target) return toast('IP 不能为空', 'error');
  const r = await apiPost('/api/bans/add', {
    kind: 'ip', target,
    reason: $('#banIPReason').value.trim(),
    ttl: $('#banIPTTL').value.trim(),
  });
  if (r && r.ok) {
    $('#banIPTarget').value = ''; $('#banIPReason').value = ''; $('#banIPTTL').value = '';
    toast('已添加', 'success'); loadBans();
  } else toast((r && r.error) || '失败', 'error');
});

// token 黑名单已废弃(v2board 重置 token 后 hash 失效),不再注册按钮。

// ---- 全局黑名单配置(海外/云/ISP/浏览器)----
async function loadBlacklistCfg() {
  const btn = $('#blSaveBtn');
  btn.disabled = true;
  const cfg = await api('/api/blacklist');
  if (!cfg) return;
  $('#blOversea').checked = !!cfg.oversea_enabled;
  $('#blCloud').checked = !!cfg.cloud_enabled;
  $('#blCNIDC').checked = !!cfg.cn_idc_enabled;
  $('#blBrowser').checked = !!cfg.browser_enabled;
  $('#blISPKw').value = (cfg.isp_keywords || []).join(', ');
  btn.disabled = false;
}
$('#blSaveBtn').addEventListener('click', async () => {
  const kw = $('#blISPKw').value.split(',').map(s => s.trim()).filter(Boolean);
  const r = await apiPost('/api/blacklist/save', {
    oversea_enabled: $('#blOversea').checked,
    cloud_enabled: $('#blCloud').checked,
    cn_idc_enabled: $('#blCNIDC').checked,
    browser_enabled: $('#blBrowser').checked,
    isp_keywords: kw,
  });
  if (r && r.ok) toast('已保存', 'success');
  else toast((r && r.msg) || '保存失败', 'error');
});

// ---- IP 白名单 ----
async function loadIPWhitelist() {
  const list = await api('/api/ip-whitelist');
  if (!list) return;
  const tbody = $('#ipWLTbody'); tbody.replaceChildren();
  if (!list.length) { setEmptyRow(tbody, '暂无 IP 白名单条目'); return; }
  for (const e of list) {
    const tr = document.createElement('tr');
    tr.dataset.id = e.ID;
    tr.dataset.target = e.Target || '';
    tr.dataset.note = e.Note || '';
    tr.innerHTML = `
      <td class="mono ipwl-target">${escapeHTML(e.Target)}</td>
      <td class="ipwl-note">${escapeHTML(e.Note || '')}</td>
      <td class="mono">${escapeHTML(fmtTime(e.CreatedTS))}</td>
      <td class="ipwl-ops">
        <button class="ipwl-edit" data-id="${e.ID}">编辑</button>
        <button class="danger ipwl-del" data-id="${e.ID}">删除</button>
      </td>
    `;
    tbody.appendChild(tr);
  }
}

// 行内编辑:点'编辑'把两格替换成 input,按钮换'保存/取消'。
$('#ipWLTbody').addEventListener('click', async (ev) => {
  const tr = ev.target.closest('tr'); if (!tr) return;
  const id = parseInt(tr.dataset.id, 10);

  if (ev.target.matches('.ipwl-del')) {
    if (!confirm('删除该白名单?')) return;
    const r = await apiPost('/api/ip-whitelist/remove', { id });
    if (r && r.ok) { toast('已删除', 'success'); loadIPWhitelist(); }
    else toast((r && r.error) || '失败', 'error');
    return;
  }

  if (ev.target.matches('.ipwl-edit')) {
    const curTarget = tr.dataset.target;
    const curNote = tr.dataset.note;
    tr.querySelector('.ipwl-target').innerHTML = `<input class="ipwl-edit-target" value="${escapeHTML(curTarget)}" style="width:100%">`;
    tr.querySelector('.ipwl-note').innerHTML = `<input class="ipwl-edit-note" value="${escapeHTML(curNote)}" style="width:100%">`;
    tr.querySelector('.ipwl-ops').innerHTML = `
      <button class="primary ipwl-save" data-id="${id}">保存</button>
      <button class="ipwl-cancel">取消</button>
    `;
    tr.querySelector('.ipwl-edit-target').focus();
    return;
  }

  if (ev.target.matches('.ipwl-cancel')) {
    loadIPWhitelist();
    return;
  }

  if (ev.target.matches('.ipwl-save')) {
    const target = tr.querySelector('.ipwl-edit-target').value.trim();
    const note = tr.querySelector('.ipwl-edit-note').value.trim();
    if (!target) return toast('IP/CIDR 不能为空', 'error');
    const r = await apiPost('/api/ip-whitelist/update', { id, target, note });
    if (r && r.ok) { toast('已保存', 'success'); loadIPWhitelist(); }
    else toast((r && r.error) || '保存失败', 'error');
    return;
  }
});

$('#ipWLAddBtn').addEventListener('click', async () => {
  const target = $('#ipWLTarget').value.trim();
  if (!target) return toast('请输入 IP/CIDR', 'error');
  const r = await apiPost('/api/ip-whitelist/add', { target, note: $('#ipWLNote').value.trim() });
  if (r && r.ok) {
    $('#ipWLTarget').value = ''; $('#ipWLNote').value = '';
    toast('已添加', 'success'); loadIPWhitelist();
  } else toast((r && r.error) || '失败', 'error');
});

// ---- UA 黑名单 ----
async function loadUABlacklist() {
  const list = await api('/api/ua-blacklist');
  if (!list) return;
  const tbody = $('#uaBlTbody'); tbody.replaceChildren();
  if (!list.length) { setEmptyRow(tbody, '暂无 UA 黑名单条目'); return; }
  for (const e of list) {
    const tr = document.createElement('tr');
    tr.innerHTML = `
      <td class="mono">${escapeHTML(e.Pattern)}</td>
      <td>${escapeHTML(e.Note || '')}</td>
      <td class="mono">${escapeHTML(fmtTime(e.CreatedTS))}</td>
      <td><button class="danger uabl-del" data-id="${e.ID}">删除</button></td>
    `;
    tbody.appendChild(tr);
  }
}

$('#uaBlTbody').addEventListener('click', async (ev) => {
  if (!ev.target.matches('.uabl-del')) return;
  if (!confirm('删除该 UA 黑名单?')) return;
  const id = parseInt(ev.target.dataset.id, 10);
  const r = await apiPost('/api/ua-blacklist/remove', { id });
  if (r && r.ok) { toast('已删除', 'success'); loadUABlacklist(); }
  else toast((r && r.error) || '失败', 'error');
});

$('#uaBlAddBtn').addEventListener('click', async () => {
  const pattern = $('#uaBlPattern').value.trim();
  if (!pattern) return toast('请输入 UA 关键词', 'error');
  const r = await apiPost('/api/ua-blacklist/add', { pattern, note: $('#uaBlNote').value.trim() });
  if (r && r.ok) {
    $('#uaBlPattern').value = ''; $('#uaBlNote').value = '';
    toast('已添加', 'success'); loadUABlacklist();
  } else toast((r && r.error) || '失败', 'error');
});

// ---- 云 IP ----
async function loadGeoIPInfo() {
  const s = await api('/api/geoip');
  if (!s) return;
  const el = $('#geoipStatus');
  if (s.loaded) {
    el.innerHTML = `已加载 · 版本 <strong>${escapeHTML(s.version || '-')}</strong> · 路径 <code>${escapeHTML(s.path || '-')}</code>`;
  } else {
    el.innerHTML = `<span style="color:var(--danger)">未加载</span> — 请检查 <code>geoip.xdb_path</code> 配置`;
  }
}

function renderGeoInfo(info) {
  // 字段空的不显示,保持精简
  const rows = [
    ['国家', info.country, info.iso_code ? ` (${info.iso_code})` : ''],
    ['省市区', [info.province, info.city, info.district].filter(Boolean).join(' / ')],
    ['ISP', info.isp],
    ['用途', info.usage_type ? `${usageLabel(info.usage_type)} (${info.usage_type})` : ''],
    ['云厂商', info.cloud_provider],
    ['ASN', info.asn],
    ['经纬度', (info.lon && info.lat) ? `${info.lon}, ${info.lat}` : ''],
    ['时区', info.timezone],
    ['邮编', info.zip_code],
  ];
  let html = '<table style="width:100%;border-collapse:collapse"><tbody>';
  for (const [k, v, suffix] of rows) {
    if (!v) continue;
    html += `<tr><td style="padding:6px 12px 6px 0;color:var(--muted);width:90px;vertical-align:top">${k}</td>
             <td style="padding:6px 0"><strong>${escapeHTML(String(v))}</strong>${suffix ? '<span class="muted">' + escapeHTML(suffix) + '</span>' : ''}</td></tr>`;
  }
  html += '</tbody></table>';
  // 云厂商单独标红/橙
  if (info.cloud_provider) {
    html = `<div style="margin-bottom:10px;padding:8px 12px;background:#fff7ed;border-left:3px solid #f97316;border-radius:4px">
      命中云厂商 IP · <strong>${escapeHTML(info.cloud_provider)}</strong>
    </div>` + html;
  }
  return html;
}

$('#cloudCheckBtn').addEventListener('click', async () => {
  const ip = $('#cloudCheckIP').value.trim();
  if (!ip) return;
  const r = await api('/api/geoip/lookup?ip=' + encodeURIComponent(ip));
  const el = $('#geoipResult');
  if (!r) { el.innerHTML = '<span class="muted">请求失败</span>'; return; }
  if (!r.found) {
    el.innerHTML = `<span class="muted">未找到 ${escapeHTML(ip)} 的记录(IP 不在 xdb 库内或格式错误)</span>`;
    return;
  }
  el.innerHTML = renderGeoInfo(r.info);
});
$('#cloudCheckIP').addEventListener('keydown', e => {
  if (e.key === 'Enter') $('#cloudCheckBtn').click();
});

// ---- SQLite 系统配置 ----
const runtimeForm = $('#runtimeSettingsForm');
const runtimeFields = $('#runtimeFields');
const runtimeStatus = $('#runtimeStatus');
const ingressMode = runtimeForm.elements.namedItem('ingress_mode');
let runtimeBusy = false;
function updateIngressFields() {
  const chain = ingressMode.value === 'nginx_cloudflare';
  $('#ingressDirectFields').hidden = chain;
  $('#ingressChainFields').hidden = !chain;
  runtimeForm.elements.namedItem('ingress_proxies').required = !chain;
  runtimeForm.elements.namedItem('nginx_egress_ips').required = chain;
}
ingressMode.addEventListener('change', updateIngressFields);
function renderRuntimeSettings(result) {
  for (const [key, value] of Object.entries(result.saved)) {
    const field = runtimeForm.elements.namedItem(key);
    if (!field) continue;
    if (field.type === 'checkbox') field.checked = value;
    else field.value = Array.isArray(value) ? value.join('\n') : value;
  }
  updateIngressFields();
  runtimeStatus.dataset.state = result.restart_required ? 'pending' : 'active';
  const mode = result.active.ingress_mode === 'nginx_cloudflare' ? 'Nginx → Cloudflare → Sub-Panel' : '直连前置代理';
  const addresses = ` 当前监听：订阅 ${result.active.listen}，管理 ${result.active.admin_listen}。当前入口：${mode}。`;
  runtimeStatus.textContent = (result.restart_required ? '已保存，等待重启。' : '数据库配置已生效。') + addresses;
}
async function loadSettings() {
  if (runtimeBusy) return;
  runtimeBusy = true;
  runtimeFields.disabled = true;
  runtimeStatus.dataset.state = 'loading';
  runtimeStatus.textContent = '正在加载配置…';
  const result = await api('/api/settings/runtime');
  runtimeBusy = false;
  if (!result) { runtimeStatus.dataset.state = 'error'; runtimeStatus.textContent = '加载失败，请刷新重试。'; return; }
  renderRuntimeSettings(result);
  runtimeFields.disabled = false;
}
runtimeForm.addEventListener('submit', async e => {
  e.preventDefault();
  if (runtimeBusy) return;
  const body = {};
  for (const field of runtimeForm.elements) {
    if (!field.name) continue;
    if (field.type === 'checkbox') body[field.name] = field.checked;
    else if (field.type === 'number') body[field.name] = Number(field.value);
    else if (field.tagName === 'TEXTAREA') body[field.name] = field.value.split('\n').map(x => x.trim()).filter(Boolean);
    else body[field.name] = field.value.trim();
  }
  runtimeBusy = true;
  runtimeFields.disabled = true;
  const result = await requestJSON('/api/settings/runtime', 'PUT', body);
  runtimeBusy = false;
  runtimeFields.disabled = false;
  if (!result || result.ok === false) { toast(result?.error || '保存失败', 'error'); return; }
  renderRuntimeSettings(result);
  toast(result.restart_required ? '已保存，重启后生效' : '已保存', 'success');
});

// ---- 工具(token hash 工具已删除,v2board 重置就失效) ----

// ---- 启动 ----
(async function () {
  api('/api/session').then(session => {
    if (!session?.username) return;
    $('#userName').textContent = session.username;
    $('#userAvatar').textContent = Array.from(session.username)[0].toUpperCase();
  });
  await loadTenants();
  if (!activeTab) activateTab(currentTab());
})();

// ---- 机场管理 ----
async function loadTenantsTable() {
  const list = await api('/api/tenants');
  if (!list) return;
  refreshTenantSelector(list);
  const tbody = $('#tenantsTbody'); tbody.innerHTML = '';
  if (!list.length) {
    setEmptyRow(tbody, '暂无机场，可用「新增机场」创建订阅入口。');
    return;
  }
  for (const t of list) {
    const tr = document.createElement('tr');
    const upPath = t.upstream_path ? escapeHTML(t.upstream_path) : '<span class="muted">(透传)</span>';
    const statusBadge = t.enabled ? '<span class="pill pass">已启用</span>' : '<span class="pill empty">已停用</span>';
    tr.innerHTML = `
      <td><strong>${escapeHTML(t.name)}</strong></td>
      <td class="mono">${escapeHTML(t.subscribe_path)}</td>
      <td class="mono" style="max-width:220px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="${escapeHTML(t.upstream)}">${escapeHTML(t.upstream)}</td>
      <td class="mono">${upPath}</td>
      <td>${statusBadge}</td>
      <td>
        <div class="table-actions">
          <button data-act="edit" data-name="${escapeHTML(t.name)}">编辑</button>
          <button data-act="report" data-name="${escapeHTML(t.name)}">接入代码</button>
          <button data-act="toggle" data-name="${escapeHTML(t.name)}">${t.enabled ? '停用' : '启用'}</button>
          <button class="danger" data-act="del" data-name="${escapeHTML(t.name)}">删除</button>
        </div>
      </td>
    `;
    tbody.appendChild(tr);
  }
  $$('#tenantsTbody button').forEach(btn => {
    btn.addEventListener('click', () => onTenantAction(btn.dataset.act, btn.dataset.name, list));
  });
}

function refreshTenantSelector(list) {
  const sel = $('#tenantSel');
  if (!sel) return;
  const cur = sel.value;
  sel.innerHTML = '<option value="">全部机场</option>';
  for (const t of list) {
    const opt = document.createElement('option');
    opt.value = t.name; opt.textContent = t.name;
    sel.appendChild(opt);
  }
  // 当前选中机场如果还在,保持选中
  if ([...sel.options].some(o => o.value === cur)) sel.value = cur;
  state.tenant = sel.value;
}

async function onTenantAction(act, name, list) {
  const t = list.find(x => x.name === name);
  if (!t) return;
  if (act === 'edit') {
    openTenantModal(t);
    return;
  }
  if (act === 'report') {
    openReportCodeModal(t.name, t.report_id);
    return;
  }
  if (act === 'toggle') {
    const r = await apiPost('/api/tenants/save', {
      name: t.name,
      subscribe_path: t.subscribe_path,
      upstream: t.upstream,
      upstream_path: t.upstream_path,
      enabled: !t.enabled,
      original_name: t.name,
    });
    if (r && r.ok) { toast(t.enabled ? '已禁用' : '已启用', 'success'); loadTenantsTable(); }
    else toast((r && r.error) || '失败', 'error');
    return;
  }
  if (act === 'del') {
    if (!confirm(`确定删除机场「${name}」? 客户端订阅将立即失效。`)) return;
    const r = await apiPost('/api/tenants/remove', { name });
    if (r && r.ok) { toast('已删除', 'success'); loadTenantsTable(); }
    else toast((r && r.error) || '失败', 'error');
  }
}

function openTenantModal(t) {
  const isEdit = !!t;
  $('#tenantModalTitle').textContent = isEdit ? `编辑机场 - ${t.name}` : '新增机场';
  $('#tenantFormName').value = isEdit ? t.name : '';
  $('#tenantFormSubPath').value = isEdit ? t.subscribe_path : '';
  $('#tenantFormUpstream').value = isEdit ? t.upstream : '';
  $('#tenantFormUpPath').value = isEdit ? (t.upstream_path || '') : '';
  $('#tenantFormEnabled').checked = isEdit ? !!t.enabled : true;
  $('#tenantModal').dataset.originalName = isEdit ? t.name : '';
  showDialog('tenantModal', '#tenantFormName');
}

function closeTenantModal() { closeActiveDialog('tenantModal'); }

$('#tenantAddBtn').addEventListener('click', () => openTenantModal(null));
$('#tenantModalClose').addEventListener('click', closeTenantModal);
$('#tenantFormCancel').addEventListener('click', closeTenantModal);
$('#tenantModal').addEventListener('click', e => {
  if (e.target.id === 'tenantModal') closeTenantModal();
});

$('#tenantFormSave').addEventListener('click', async () => {
  const original = $('#tenantModal').dataset.originalName || '';
  const body = {
    name: $('#tenantFormName').value.trim(),
    subscribe_path: $('#tenantFormSubPath').value.trim(),
    upstream: $('#tenantFormUpstream').value.trim(),
    upstream_path: $('#tenantFormUpPath').value.trim(),
    enabled: $('#tenantFormEnabled').checked,
    original_name: original,
  };
  if (!body.name || !body.subscribe_path || !body.upstream) {
    return toast('机场名、订阅路径、上游地址都必填', 'error');
  }
  const r = await apiPost('/api/tenants/save', body);
  if (r && r.ok) {
    toast(original ? '已更新' : '已新增', 'success');
    closeTenantModal();
    loadTenantsTable();
  } else {
    toast((r && r.error) || '失败', 'error');
  }
});

// ============ 上报接入代码弹窗 ============

async function openReportCodeModal(tenantName, reportId) {
  const info = await api('/api/report-info');
  if (!info) return;
  if (!reportId) { toast('该机场未分配上报地址，请刷新后重试。', 'error'); return; }
  const base = info.report_base_url;
  const guessed = new URL('http://' + location.hostname);
  guessed.port = (info.sub_listen || ':80').split(':').pop();
  const reportUrl = `${base || guessed.origin}/r/${encodeURIComponent(reportId)}`;
  const secret = info.report_secret || '';
  const phpString = value => String(value).replaceAll('\\', '\\\\').replaceAll("'", "\\'");
  $('#reportURLHint').hidden = Boolean(base);

  $('#reportCodeTitle').textContent = `上报接入 — ${tenantName}`;
  $('#reportCodeURL').textContent = reportUrl;
  $('#reportCodeURL').dataset.copy = reportUrl;
  $('#reportCodeKey').textContent = secret ? '已配置 · 点击复制密钥' : '未配置';
  $('#reportCodeKey').dataset.copy = secret;

  const phpCode = `// ─── Sub-Panel 上报 ───
$subPanelUrl = '${phpString(reportUrl)}';
$subPanelKey = '${phpString(secret)}';

$reportData = [
    'token'              => $user->token,
    'uuid'               => $user->uuid,
    'email'              => $user->email,
    'traffic_used'       => $user->u + $user->d,
    'traffic_total'      => $user->transfer_enable,
    'wallet_balance'     => $user->balance ?? 0,
    'commission_balance' => $user->commission_balance ?? 0,
    'user_created_at'    => (string)$user->created_at,
    'ip'                 => $request->ip(),
    'user_agent'         => $request->userAgent() ?? '',
    'site_domain'        => $request->getHost(),
];

try {
    \\Illuminate\\Support\\Facades\\Http::timeout(3)
        ->withHeaders(['X-Report-Key' => $subPanelKey])
        ->post($subPanelUrl, $reportData);
} catch (\\Exception $e) {
    // 静默失败,不影响订阅下发
}
// ─── Sub-Panel 上报结束 ───`;

  $('#reportCodePHP').textContent = phpCode;
  $('#reportCodeModal').dataset.php = phpCode;
  if (activeTab === 'tenants') showDialog('reportCodeModal', '#reportCodeClose');
  bindCopyHandlers($('#reportCodeModal'));
}

function closeReportCodeModal() { closeActiveDialog('reportCodeModal'); }
$('#reportCodeClose').addEventListener('click', closeReportCodeModal);
$('#reportCodeModal').addEventListener('click', e => {
  if (e.target.id === 'reportCodeModal') closeReportCodeModal();
});
$('#reportCodeCopyBtn').addEventListener('click', async () => {
  const code = $('#reportCodeModal').dataset.php || '';
  try {
    if (navigator.clipboard && window.isSecureContext) {
      await navigator.clipboard.writeText(code);
    } else {
      const ta = document.createElement('textarea');
      ta.value = code; ta.style.position = 'fixed'; ta.style.opacity = '0';
      document.body.appendChild(ta); ta.select(); document.execCommand('copy');
      document.body.removeChild(ta);
    }
    toast('已复制 PHP 代码', 'success');
  } catch (e) { toast('复制失败', 'error'); }
});

// ============ 触发规则 ============

const SEV_CN = {}; // 等级已废弃,保留空对象避免外部偶发引用报错

function escapeHtml(s) {
  return String(s == null ? '' : s)
    .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
}

function fmtTs(unix) {
  if (!unix) return '-';
  const d = new Date(unix * 1000);
  const pad = n => String(n).padStart(2, '0');
  return `${d.getFullYear()}-${pad(d.getMonth()+1)}-${pad(d.getDate())} ${pad(d.getHours())}:${pad(d.getMinutes())}`;
}

// 把 API 规则压成一行人话摘要,放表格里看。
function ruleSummary(r) {
  const parts = [];
  const fmt = (label, win, gte, suffix) => {
    if (win > 0 && gte > 0) {
      parts.push(`<strong>${label}</strong> ${win}s/${gte}${suffix}`);
    }
  };
  fmt('Tok频', r.token_freq_window_sec, r.token_freq_gte, '次');
  fmt('IP频',  r.ip_freq_window_sec, r.ip_freq_gte, '次');
  fmt('Tok×IP', r.token_distinct_ips_window_sec, r.token_distinct_ips_gte, 'IP');
  fmt('IP×Tok', r.ip_distinct_tokens_window_sec, r.ip_distinct_tokens_gte, 'Tok');
  if (r.from_cloud_ip) parts.push('<strong>云IP</strong>');
  if (r.country_in && r.country_in.length) parts.push(`<strong>国家∈</strong>${r.country_in.join(',')}`);
  if (r.country_not_in && r.country_not_in.length) parts.push(`<strong>国家∉</strong>${r.country_not_in.join(',')}`);
  if (r.usage_type_in && r.usage_type_in.length) parts.push(`<strong>用途∈</strong>${r.usage_type_in.map(usageLabel).join(',')}`);
  if (r.usage_type_not_in && r.usage_type_not_in.length) parts.push(`<strong>用途∉</strong>${r.usage_type_not_in.map(usageLabel).join(',')}`);
  if (r.isp_contains && r.isp_contains.length) parts.push(`<strong>ISP⊇</strong>${r.isp_contains.join(',')}`);
  return parts.length ? parts.join(' · ') : '<span style="color:#dc2626">⚠ 无任何条件</span>';
}

async function loadRulesTable() {
  const r = await api('/api/detect_rules');
  const tbody = $('#rulesTbody'); tbody.innerHTML = '';
  if (!Array.isArray(r) || !r.length) {
    setEmptyRow(tbody, '暂无触发规则，可新增规则。');
    return;
  }
  for (const x of r) {
    const tr = document.createElement('tr');
    tr.innerHTML = `
      <td class="mono">${escapeHtml(x.name)}</td>
      <td>${escapeHtml(x.desc || '-')}</td>
      <td class="rule-summary">${ruleSummary(x)}</td>
      <td>${x.enabled ? '✓' : '<span style="color:#9ca3af">×</span>'}</td>
      <td class="mono" style="color:#6b7280">${fmtTs(x.updated_ts)}</td>
      <td>
        <button data-act="edit"   data-name="${escapeHtml(x.name)}">编辑</button>
        <button data-act="toggle" data-name="${escapeHtml(x.name)}">${x.enabled ? '禁用' : '启用'}</button>
        <button data-act="delete" data-name="${escapeHtml(x.name)}" class="danger">删除</button>
      </td>`;
    tbody.appendChild(tr);
  }
  $$('#rulesTbody button').forEach(btn => {
    btn.addEventListener('click', () => onRuleAction(btn.dataset.act, btn.dataset.name, r));
  });
}

async function onRuleAction(act, name, list) {
  const item = list.find(x => x.name === name);
  if (!item) return;
  if (act === 'edit') { openRuleModal(item); return; }
  if (act === 'toggle') {
    const body = { ...item, enabled: !item.enabled, original_name: item.name };
    const r = await apiPost('/api/detect_rules/save', body);
    if (r && r.ok) { toast(item.enabled ? '已禁用' : '已启用', 'success'); loadRulesTable(); }
    else toast((r && r.error) || '失败', 'error');
    return;
  }
  if (act === 'delete') {
    if (!confirm(`确认删除规则 ${name}?(立即热生效,不可撤销)`)) return;
    const r = await apiPost('/api/detect_rules/remove', { name });
    if (r && r.ok) { toast('已删除', 'success'); loadRulesTable(); }
    else toast((r && r.error) || '失败', 'error');
  }
}

function listToCSV(list) { return (list && list.length) ? list.join(', ') : ''; }
function csvToList(s) {
  return String(s || '').split(/[,，\s]+/).map(x => x.trim()).filter(Boolean);
}

function openRuleModal(r) {
  const isEdit = !!r;
  $('#ruleModalTitle').textContent = isEdit ? `编辑规则 - ${r.name}` : '新增规则';
  const set = (id, v) => { $('#' + id).value = v == null ? '' : v; };
  set('ruleFormName',          isEdit ? r.name : '');
  set('ruleFormDesc',          isEdit ? r.desc : '');
  set('ruleFormTfWin',         isEdit ? (r.token_freq_window_sec || '') : '');
  set('ruleFormTfGte',         isEdit ? (r.token_freq_gte || '') : '');
  set('ruleFormIfWin',         isEdit ? (r.ip_freq_window_sec || '') : '');
  set('ruleFormIfGte',         isEdit ? (r.ip_freq_gte || '') : '');
  set('ruleFormTdWin',         isEdit ? (r.token_distinct_ips_window_sec || '') : '');
  set('ruleFormTdGte',         isEdit ? (r.token_distinct_ips_gte || '') : '');
  set('ruleFormIdWin',         isEdit ? (r.ip_distinct_tokens_window_sec || '') : '');
  set('ruleFormIdGte',         isEdit ? (r.ip_distinct_tokens_gte || '') : '');
  set('ruleFormCountryIn',     isEdit ? listToCSV(r.country_in) : '');
  set('ruleFormCountryNotIn',  isEdit ? listToCSV(r.country_not_in) : '');
  set('ruleFormUsageIn',       isEdit ? listToCSV(r.usage_type_in) : '');
  set('ruleFormUsageNotIn',    isEdit ? listToCSV(r.usage_type_not_in) : '');
  set('ruleFormISP',           isEdit ? listToCSV(r.isp_contains) : '');
  $('#ruleFormFromCloud').checked = isEdit ? !!r.from_cloud_ip : false;
  const enabledOn = isEdit ? !!r.enabled : true;
  $('#ruleFormEnabledOn').checked  = enabledOn;
  $('#ruleFormEnabledOff').checked = !enabledOn;
  $('#ruleModal').dataset.originalName = isEdit ? r.name : '';
  $('#ruleModal').dataset.sortOrder = isEdit ? String(r.sort_order || 0) : '0';
  showDialog('ruleModal', '#ruleFormName');
}

function closeRuleModal() { closeActiveDialog('ruleModal'); }

$('#ruleAddBtn').addEventListener('click', () => openRuleModal(null));
$('#ruleModalClose').addEventListener('click', closeRuleModal);
$('#ruleFormCancel').addEventListener('click', closeRuleModal);
$('#ruleModal').addEventListener('click', e => {
  if (e.target.id === 'ruleModal') closeRuleModal();
});

$('#ruleFormSave').addEventListener('click', async () => {
  const num = id => {
    const v = parseInt($('#' + id).value, 10);
    return isNaN(v) || v < 0 ? 0 : v;
  };
  const name = $('#ruleFormName').value.trim();
  if (!name) { toast('规则名必填', 'error'); return; }
  const body = {
    original_name:                     $('#ruleModal').dataset.originalName || '',
    name,
    desc:                              $('#ruleFormDesc').value.trim(),
    enabled:                           $('#ruleFormEnabledOn').checked,
    sort_order:                        parseInt($('#ruleModal').dataset.sortOrder || '0', 10),
    token_freq_window_sec:             num('ruleFormTfWin'),
    token_freq_gte:                    num('ruleFormTfGte'),
    ip_freq_window_sec:                num('ruleFormIfWin'),
    ip_freq_gte:                       num('ruleFormIfGte'),
    token_distinct_ips_window_sec:     num('ruleFormTdWin'),
    token_distinct_ips_gte:            num('ruleFormTdGte'),
    ip_distinct_tokens_window_sec:     num('ruleFormIdWin'),
    ip_distinct_tokens_gte:            num('ruleFormIdGte'),
    from_cloud_ip:                     $('#ruleFormFromCloud').checked,
    country_in:                        csvToList($('#ruleFormCountryIn').value),
    country_not_in:                    csvToList($('#ruleFormCountryNotIn').value),
    usage_type_in:                     csvToList($('#ruleFormUsageIn').value),
    usage_type_not_in:                 csvToList($('#ruleFormUsageNotIn').value),
    isp_contains:                      csvToList($('#ruleFormISP').value),
  };
  const r = await apiPost('/api/detect_rules/save', body);
  if (r && r.ok) {
    toast('已保存,热生效中', 'success');
    closeRuleModal();
    loadRulesTable();
  } else {
    toast((r && r.error) || '失败', 'error');
  }
});

// ────────────────────────────────────────────────
// 修改密码 + 一键透传(设置页)
// ────────────────────────────────────────────────
let passthroughBusy = false;
function renderPassthrough(enabled) {
  $('#passthroughToggle').checked = enabled;
  $('#passthroughLabel').textContent = enabled ? '已开启' : '已关闭';
  $('#passthroughStatusPill').style.display = enabled ? '' : 'none';
}
async function loadPassthrough() {
  if (passthroughBusy) return;
  passthroughBusy = true;
  const cb = $('#passthroughToggle');
  cb.disabled = true;
  $('#passthroughLabel').textContent = '正在读取状态…';
  const r = await api('/api/settings/passthrough');
  passthroughBusy = false;
  if (!r) { $('#passthroughLabel').textContent = '状态读取失败，请刷新'; return; }
  renderPassthrough(r.enabled);
  cb.disabled = false;
}

let reportBusy = false;
const reportInput = $('#reportSecretInput');
const reportSave = $('#reportSecretSave');
async function loadReportSecret() {
  if (reportBusy) return;
  reportBusy = true;
  reportInput.disabled = reportSave.disabled = true;
  const r = await api('/api/report-info');
  reportBusy = false;
  if (!r) return;
  reportInput.value = r.report_secret || '';
  reportInput.disabled = reportSave.disabled = false;
}

reportSave.addEventListener('click', async () => {
  const val = reportInput.value.trim();
  if (!val && !confirm('清除密钥后，上报接口将不再校验密钥。确认清除？')) return;
  reportBusy = true;
  reportInput.disabled = reportSave.disabled = true;
  const r = await apiPost('/api/report-info/save', { report_secret: val });
  reportBusy = false;
  reportInput.disabled = reportSave.disabled = false;
  if (r?.ok) {
    reportInput.value = val;
    toast(val ? '密钥已保存。请同步更新各机场的上报代码。' : '密钥已清除（上报接口不校验）', 'success');
  } else if (r) {
    toast(r.error || '保存失败', 'error');
  }
});

$('#pwSaveBtn')?.addEventListener('click', async e => {
  const oldP = $('#pwOld').value;
  const newP = $('#pwNew').value;
  const newP2 = $('#pwNew2').value;
  if (!oldP || !newP) { toast('请填写原密码和新密码', 'error'); return; }
  const bytes = new TextEncoder().encode(newP).length;
  if (bytes < 8 || bytes > 72) { toast('新密码须为 8–72 字节', 'error'); return; }
  if (newP !== newP2) { toast('两次输入的新密码不一致', 'error'); return; }
  const btn = e.currentTarget;
  btn.disabled = true;
  const r = await apiPost('/api/auth/change_password', { old_password: oldP, new_password: newP });
  if (r?.ok) {
    for (const id of ['#pwOld', '#pwNew', '#pwNew2']) $(id).value = '';
    toast('密码已修改，即将退出登录…', 'success');
    setTimeout(() => { location.href = '/login'; }, 1500);
  } else {
    btn.disabled = false;
    if (r) toast(r.error || '修改失败', 'error');
  }
});

$('#passthroughToggle')?.addEventListener('change', async (e) => {
  const cb = e.currentTarget;
  const want = cb.checked;
  const msg = want
    ? '开启后，匹配订阅路径的请求将跳过名单和触发规则；订阅展示和 Lumi 兼容处理仍可能生效。确认开启？'
    : '关闭后恢复正常规则处理。确认关闭？';
  cb.checked = !want;
  if (!confirm(msg)) return;
  passthroughBusy = true;
  cb.disabled = true;
  const r = await apiPost('/api/settings/passthrough', { enabled: want });
  passthroughBusy = false;
  if (r?.ok) {
    renderPassthrough(r.enabled);
    cb.disabled = false;
    toast(r.enabled ? '一键透传已开启' : '一键透传已关闭', r.enabled ? 'warning' : 'success');
  } else if (r) {
    toast(r.error || '保存失败', 'error');
    await loadPassthrough();
  }
});

// ════════════════════════════════════════════════════
// 嫌疑用户
// ════════════════════════════════════════════════════

function fmtBytes(b) {
  if (!b || b <= 0) return '0';
  const units = ['B', 'KB', 'MB', 'GB', 'TB'];
  let i = 0;
  let v = b;
  while (v >= 1024 && i < units.length - 1) { v /= 1024; i++; }
  return v.toFixed(i > 1 ? 1 : 0) + ' ' + units[i];
}

let suspectsRequest = 0;
async function loadSuspects() {
  const request = ++suspectsRequest;
  const q = new URLSearchParams({
    tenant: state.tenant,
    window: $('#suspectWindow').value || '168h',
  });
  const rows = await api('/api/suspects?' + q);
  if (request !== suspectsRequest || !rows) return;
  window._suspectsData = rows;
  renderSuspects();
}

function renderSuspects() {
  let rows = window._suspectsData || [];
  const list = $('#suspectsList'); list.innerHTML = '';

  // 搜索过滤
  const search = ($('#suspectSearch').value || '').trim().toLowerCase();
  if (search) {
    rows = rows.filter(r =>
      (r.token || '').toLowerCase().includes(search) ||
      (r.email || '').toLowerCase().includes(search) ||
      (r.last_ip || '').toLowerCase().includes(search)
    );
  }

  // 排序
  const sort = $('#suspectSort').value;
  rows = [...rows].sort((a, b) => {
    if (sort === 'pull') return b.pull_count - a.pull_count;
    if (sort === 'uas') return b.distinct_uas - a.distinct_uas || b.distinct_ips - a.distinct_ips;
    if (sort === 'usage') {
      const ra = a.traffic_total > 0 ? a.traffic_used / a.traffic_total : 2;
      const rb = b.traffic_total > 0 ? b.traffic_used / b.traffic_total : 2;
      return ra - rb; // 低使用率排前面
    }
    // 默认 + ips: 独立IP 降序,同分按拉取降序
    return b.distinct_ips - a.distinct_ips || b.pull_count - a.pull_count;
  });

  if (!rows.length) {
    list.innerHTML = '<div class="empty-state">暂无上报数据或无匹配结果</div>';
    return;
  }
  for (const r of rows) {
    list.appendChild(renderSuspectCard(r));
  }
  bindCopyHandlers(list);
}

// 嫌疑用户卡片:与请求日志 .ev-card 同款样式
function renderSuspectCard(r) {
  const card = document.createElement('div');
  card.className = 'ev-card';
  const tokenFull = r.token || '';
  const usageRatio = r.traffic_total > 0 ? (r.traffic_used / r.traffic_total * 100) : -1;
  // 主指标:独立 IP 数。共享/倒卖最直观的信号 → 卡片头部大号数字,按数量上色阶
  // <5 正常(灰) / 5-9 注意(琥珀) / 10+ 高危(红)
  const ipCls = r.distinct_ips >= 10 ? 'sus-ip-hi' : (r.distinct_ips >= 5 ? 'sus-ip-mid' : 'sus-ip-lo');
  // 使用率 pill:<5% 红、<20% 黄、其余靛蓝
  const usageCls = usageRatio < 0 ? 'empty' : (usageRatio < 5 ? 'danger' : (usageRatio < 20 ? 'yellow' : 'tag'));
  const usageTxt = usageRatio < 0 ? '使用率 -' : usageRatio.toFixed(0) + '%';

  card.innerHTML = `
    <div class="ev-card-head sus-head">
      <span class="sus-ip ${ipCls}">
        <span class="sus-ip-num">${r.distinct_ips}</span>
        <span class="sus-ip-lbl">独立 IP</span>
      </span>
      <span class="pill tag"><strong>${r.pull_count}</strong> 拉取</span>
      <span class="pill ${usageCls}">${usageTxt}</span>
      <span class="ev-spacer"></span>
      <span class="ev-tenant mono">${escapeHTML(r.tenant)}</span>
    </div>
    <div class="ev-row-full">
      <span class="ev-label">订阅</span>
      ${tokenFull
        ? `<span class="mono copyable ev-token ev-token-expand" data-copy="${escapeHTML(tokenFull)}" data-full="${escapeHTML(tokenFull)}" data-short="${escapeHTML(tokenShort(tokenFull))}" title="点击展开 / 再点复制">${escapeHTML(tokenShort(tokenFull))}</span>`
        : '<span class="muted">(无)</span>'}
    </div>
    <div class="ev-row-full">
      <span class="ev-label">邮箱</span>
      ${r.email ? `<span class="mono">${escapeHTML(r.email)}</span>` : '<span class="muted">(无)</span>'}
      <span class="ev-spacer"></span>
      <span class="muted" style="font-size:11px">${r.distinct_uas} UA · ${fmtBytes(r.traffic_used)} / ${fmtBytes(r.traffic_total)}</span>
    </div>
    <div class="sus-actions">
      ${tokenFull ? `<button class="sus-resolve" data-token="${escapeHTML(tokenFull)}" data-tenant="${escapeHTML(r.tenant || '')}">标记已处理</button>` : ''}
    </div>
    <div class="suspect-detail" style="display:none"></div>
  `;
  card.style.cursor = 'pointer';
  card.title = '点击展开详情';
  card.addEventListener('click', (e) => {
    // 排除复制、按钮、筛选框的点击
    if (e.target.closest('.copyable') || 
        e.target.closest('.sus-resolve') || 
        e.target.closest('.suspect-detail')) return;
    toggleSuspectDetail(card, r);
  });
  return card;
}

async function toggleSuspectDetail(card, r) {
  const box = card.querySelector('.suspect-detail');
  if (!box) return;
  // 已展开 → 收起
  if (box.style.display !== 'none' && box.dataset.loaded) {
    box.style.display = 'none';
    card.title = '点击展开详情';
    return;
  }
  // 收起其他已展开的
  document.querySelectorAll('#suspectsList .suspect-detail').forEach(el => {
    if (el !== box) { el.style.display = 'none'; }
  });
  document.querySelectorAll('#suspectsList .ev-card').forEach(c => {
    if (c !== card) c.title = '点击展开详情';
  });

  box.style.display = 'block';
  card.title = '点击收起详情';
  if (box.dataset.loaded) return; // 已加载过,直接显示

  box.innerHTML = '<div style="padding:8px 0;color:#6b7280;font-size:12px">加载中...</div>';

  const q = new URLSearchParams({
    token: r.token,
    tenant: r.tenant,
    window: $('#suspectWindow').value || '168h',
  });
  const detail = await api('/api/suspect-detail?' + q);
  if (!detail) { box.innerHTML = '<div style="padding:8px 0;color:#ef4444">加载失败</div>'; return; }

  // 筛选栏 + 表格容器
  const filterId = 'filter_' + Math.random().toString(36).slice(2, 9);
  let html = `<div style="margin-top:10px;padding-top:10px;border-top:1px dashed var(--border)">`;
  html += `<div style="display:flex;gap:8px;margin-bottom:10px;flex-wrap:wrap">`;
  html += `<button id="${filterId}_clear" style="font-size:12px;padding:4px 10px;border:1px solid #d1d5db;border-radius:4px;background:#f9fafb;color:#6b7280;cursor:pointer">清除筛选</button>`;
  html += `<span class="muted" style="font-size:11px;margin-left:auto;align-self:center" id="${filterId}_count"></span>`;
  html += `</div>`;
  html += `<div style="display:grid;grid-template-columns:1fr 1fr;gap:16px">`;

  // IP 列表容器
  html += `<div><div style="font-weight:600;font-size:12px;margin-bottom:6px;color:#374151">IP 列表</div>`;
  html += `<div id="${filterId}_ips"></div></div>`;

  // UA 列表容器
  html += `<div><div style="font-weight:600;font-size:12px;margin-bottom:6px;color:#374151">UA 列表</div>`;
  html += `<div id="${filterId}_uas"></div></div></div></div>`;

  box.innerHTML = html;
  box.dataset.loaded = '1';

  // 挂载筛选逻辑
  const ipsContainer = box.querySelector('#' + filterId + '_ips');
  const uasContainer = box.querySelector('#' + filterId + '_uas');
  const countLabel = box.querySelector('#' + filterId + '_count');
  const clearBtn = box.querySelector('#' + filterId + '_clear');

  // 构建绑定关系索引
  const bindings = detail.bindings || [];
  const ipToUAs = {}; // {ip: [{ua, count}]}
  const uaToIPs = {}; // {ua: [{ip, count}]}
  for (const b of bindings) {
    if (!ipToUAs[b.ip]) ipToUAs[b.ip] = [];
    ipToUAs[b.ip].push({ua: b.ua, count: b.count});
    if (!uaToIPs[b.ua]) uaToIPs[b.ua] = [];
    uaToIPs[b.ua].push({ip: b.ip, count: b.count});
  }

  let selectedIP = null;
  let selectedUA = null;

  function renderIPs(ips, highlightIP) {
    if (!ips || !ips.length) {
      ipsContainer.innerHTML = '<div style="color:#9ca3af;font-size:11px">无匹配 IP</div>';
      return;
    }
    let t = '<table style="width:100%;font-size:11.5px;border-collapse:collapse;cursor:pointer">';
    t += '<tr style="color:#6b7280;border-bottom:1px solid #e5e7eb"><th style="text-align:left;padding:2px 6px">IP</th><th style="text-align:left;padding:2px 6px">位置</th><th style="text-align:left;padding:2px 6px">ISP</th><th style="text-align:left;padding:2px 6px">类型</th><th style="text-align:right;padding:2px 6px">次数</th><th style="text-align:right;padding:2px 6px">UA数</th></tr>';
    for (const ip of ips) {
      const loc = ip.country || '-';
      const isp = ip.isp || '-';
      const usage = ip.usage_type ? usageLabel(ip.usage_type) : '-';
      const uaCount = (ipToUAs[ip.ip] || []).length;
      const bg = highlightIP === ip.ip ? 'background:rgba(99,102,241,0.12)' : '';
      t += `<tr data-ip="${escapeHTML(ip.ip)}" style="border-bottom:1px solid #f3f4f6;${bg}" class="sus-ip-row"><td class="mono" style="padding:3px 6px">${escapeHTML(ip.ip)}</td><td style="padding:3px 6px">${escapeHTML(loc)}</td><td style="padding:3px 6px">${escapeHTML(isp)}</td><td style="padding:3px 6px">${escapeHTML(usage)}</td><td class="mono" style="text-align:right;padding:3px 6px">${ip.hit_count}</td><td class="mono" style="text-align:right;padding:3px 6px;color:#6366f1">${uaCount}</td></tr>`;
    }
    t += '</table>';
    ipsContainer.innerHTML = t;

    // 点击 IP 行 → 筛选 UA
    ipsContainer.querySelectorAll('.sus-ip-row').forEach(row => {
      row.addEventListener('click', (e) => {
        e.stopPropagation(); // 阻止冒泡到卡片
        const ip = row.dataset.ip;
        if (selectedIP === ip) {
          selectedIP = null;
          renderUAs(detail.uas, null);
          renderIPs(getFilteredIPs(), null);
        } else {
          selectedIP = ip;
          selectedUA = null;
          const relatedUAs = (ipToUAs[ip] || []).map(x => x.ua);
          const filteredUAs = (detail.uas || []).filter(u => relatedUAs.includes(u.ua));
          renderUAs(filteredUAs, null);
          renderIPs(getFilteredIPs(), ip);
        }
      });
    });
  }

  function renderUAs(uas, highlightUA) {
    if (!uas || !uas.length) {
      uasContainer.innerHTML = '<div style="color:#9ca3af;font-size:11px">无匹配 UA</div>';
      return;
    }
    let t = '<table style="width:100%;font-size:11.5px;border-collapse:collapse;cursor:pointer">';
    t += '<tr style="color:#6b7280;border-bottom:1px solid #e5e7eb"><th style="text-align:left;padding:2px 6px">User-Agent</th><th style="text-align:right;padding:2px 6px">次数</th><th style="text-align:right;padding:2px 6px">IP数</th></tr>';
    for (const ua of uas) {
      const ipCount = (uaToIPs[ua.ua] || []).length;
      const bg = highlightUA === ua.ua ? 'background:rgba(99,102,241,0.12)' : '';
      t += `<tr data-ua="${escapeHTML(ua.ua)}" style="border-bottom:1px solid #f3f4f6;${bg}" class="sus-ua-row"><td class="mono" style="padding:3px 6px;max-width:280px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="${escapeHTML(ua.ua)}">${escapeHTML(ua.ua)}</td><td class="mono" style="text-align:right;padding:3px 6px">${ua.hit_count}</td><td class="mono" style="text-align:right;padding:3px 6px;color:#6366f1">${ipCount}</td></tr>`;
    }
    t += '</table>';
    uasContainer.innerHTML = t;

    // 点击 UA 行 → 筛选 IP
    uasContainer.querySelectorAll('.sus-ua-row').forEach(row => {
      row.addEventListener('click', (e) => {
        e.stopPropagation(); // 阻止冒泡到卡片
        const ua = row.dataset.ua;
        if (selectedUA === ua) {
          selectedUA = null;
          renderIPs(getFilteredIPs(), null);
          renderUAs(detail.uas, null);
        } else {
          selectedUA = ua;
          selectedIP = null;
          const relatedIPs = (uaToIPs[ua] || []).map(x => x.ip);
          const filteredIPs = (detail.ips || []).filter(i => relatedIPs.includes(i.ip));
          renderIPs(filteredIPs, null);
          renderUAs(detail.uas, ua);
        }
      });
    });
  }

  function getFilteredIPs() {
    return detail.ips || [];
  }

  function resetFilters() {
    selectedIP = null;
    selectedUA = null;
    countLabel.textContent = '';
    renderIPs(detail.ips, null);
    renderUAs(detail.uas, null);
  }

  clearBtn.addEventListener('click', resetFilters);

  renderIPs(detail.ips, null);
  renderUAs(detail.uas, null);
}

$('#suspectWindow').addEventListener('change', () => loadSuspects());
$('#suspectSort').addEventListener('change', () => renderSuspects());
$('#suspectSearch').addEventListener('input', () => renderSuspects());

// 嫌疑卡片"已处理"按钮:事件委托
$('#suspectsList').addEventListener('click', async (e) => {
  const btn = e.target.closest('.sus-resolve');
  if (!btn) return;
  e.stopPropagation();
  const token = btn.dataset.token;
  const tenant = btn.dataset.tenant || '';
  const note = prompt(`标记 token 为已处理(备注可选):\n\n${token}`, '');
  if (note === null) return;
  const r = await apiPost('/api/resolved/add', { token, tenant, note });
  if (r && r.ok) loadSuspects();
});

// Shared view helpers
function setEmptyRow(tbody, message) {
  tbody.replaceChildren();
  const cell = tbody.insertRow().insertCell();
  cell.colSpan = tbody.closest('table').tHead.rows[0].cells.length;
  cell.className = 'empty-state';
  cell.textContent = message;
}
function highlightTerms(root, keywords) {
  if (!keywords.length) return;
  const walker = document.createTreeWalker(root, NodeFilter.SHOW_TEXT);
  const hits = [];
  while (walker.nextNode()) {
    const node = walker.currentNode;
    const term = keywords.find(x => node.nodeValue.includes(x));
    if (term) hits.push([node, term]);
  }
  for (const [node, term] of hits) {
    const fragment = document.createDocumentFragment();
    node.nodeValue.split(term).forEach((text, index) => {
      if (index) {
        const mark = document.createElement('mark');
        mark.className = 'hl';
        mark.textContent = term;
        fragment.append(mark);
      }
      fragment.append(text);
    });
    node.replaceWith(fragment);
  }
}
let activeDialog, dialogOpener;
function showDialog(id, initial) {
  closeActiveDialog();
  const overlay = document.getElementById(id);
  dialogOpener = document.activeElement;
  if (overlay.parentElement !== document.body) document.body.append(overlay);
  activeDialog = overlay;
  $('.app').inert = true;
  overlay.hidden = false;
  document.body.classList.add('has-modal');
  (overlay.querySelector(initial) || overlay.querySelector('[role="dialog"]')).focus();
}
function closeActiveDialog(id) {
  if (!activeDialog || (id && activeDialog.id !== id)) return;
  activeDialog.hidden = true;
  activeDialog = null;
  $('.app').inert = false;
  document.body.classList.remove('has-modal');
  dialogOpener?.focus();
  dialogOpener = null;
}
document.addEventListener('keydown', e => {
  if (activeDialog) {
    if (e.key === 'Escape') { e.preventDefault(); closeActiveDialog(); }
    if (e.key === 'Tab') {
      const targets = [...activeDialog.querySelectorAll('button:not(:disabled), input:not(:disabled), textarea:not(:disabled), select:not(:disabled), a[href]')]
        .filter(el => el.getClientRects().length && el.tabIndex >= 0);
      const first = targets[0], last = targets.at(-1);
      if (!first) { e.preventDefault(); return; }
      if (!activeDialog.contains(document.activeElement) || (e.shiftKey && document.activeElement === first) || (!e.shiftKey && document.activeElement === last)) {
        e.preventDefault();
        (e.shiftKey ? last : first).focus();
      }
    }
    return;
  }
  if (e.key === 'Escape' && $('#sidebar').classList.contains('menu-open')) {
    setMenuOpen(false);
    $('#navToggle').focus();
    return;
  }
  if (e.ctrlKey || e.metaKey || e.altKey || e.isComposing || document.activeElement?.closest('input, textarea, select, [contenteditable]')) return;
  if (e.key.toLowerCase() === 'r') { e.preventDefault(); $('#refreshBtn').click(); }
  if (e.key === '/' && activeTab === 'events') { e.preventDefault(); $('#evIP').focus(); }
});

async function withLoading(btn, run) {
  if (btn.disabled) return;
  btn.disabled = true;
  btn.classList.add('loading');
  btn.setAttribute('aria-busy', 'true');
  try { await run(); }
  finally {
    btn.disabled = false;
    btn.classList.remove('loading');
    btn.removeAttribute('aria-busy');
  }
}

// ---- 订阅展示规则 ----
let drEditingId = 0;
let drEditingSort = 0;
let drOriginalReplacements = '';
const DR_MATCH_LABELS = { email_suffix: '邮箱后缀', email_exact: '完整邮箱', email_keyword: '邮箱关键词', all: '全部订阅' };
let drRules = [];
let drTenants = [];

async function loadDisplayRules() {
  const [rules, tenants] = await Promise.all([api('/api/display-rules'), api('/api/tenants')]);
  if (!rules || !tenants) return;
  drRules = rules;
  drTenants = tenants;
  const tbody = $('#drTbody');
  if (!tbody) return;
  tbody.innerHTML = '';
  if (!drRules.length) {
    setEmptyRow(tbody, '暂无订阅展示规则');
    return;
  }
  for (const r of drRules) {
    const tr = document.createElement('tr');
    tr.innerHTML = `
      <td>${escapeHTML(r.name)}</td>
      <td>${escapeHTML(r.tenant || '')}</td>
      <td>${escapeHTML(DR_MATCH_LABELS[r.match_type] || '未知')} ${r.match_type === 'all' ? '' : escapeHTML(r.match_value || '—')}</td>
      <td>${escapeHTML(r.airport_to || '不改')}</td>
      <td>${r.enabled ? '启用' : '禁用'}</td>
      <td>
        <button class="dr-edit" data-id="${r.id}">编辑</button>
        <button class="danger dr-del" data-id="${r.id}">删除</button>
      </td>
    `;
    tbody.appendChild(tr);
  }
}

function drFillTenantSelect(current) {
  const sel = $('#drTenant');
  sel.innerHTML = '';
  const names = drTenants.map(t => t.name);
  if (current && !names.includes(current)) {
    const o = document.createElement('option');
    o.value = current;
    o.textContent = current + '(已删除)';
    sel.appendChild(o);
  }
  for (const t of drTenants) {
    const o = document.createElement('option');
    o.value = t.name;
    o.textContent = t.name;
    sel.appendChild(o);
  }
  if (current) sel.value = current;
}

function drRepsToText(json) {
  let reps = [];
  try { reps = JSON.parse(json || '[]') || []; } catch (e) { reps = []; }
  return reps.map(p => (p.from || '') + '=' + (p.to || '')).join('\n');
}

function drTextToReps(text) {
  if (text === drRepsToText(drOriginalReplacements)) return drOriginalReplacements || '[]';
  const out = [];
  for (const [index, line] of text.split(/\r?\n/).entries()) {
    if (!line.trim()) continue;
    const i = line.indexOf('=');
    const from = i < 0 ? '' : line.slice(0, i).trim();
    if (!from) throw new Error(`第 ${index + 1} 行应使用「旧词=新词」格式。`);
    out.push({ from, to: line.slice(i + 1), regex: false });
  }
  return JSON.stringify(out);
}
function drUpdateMatch() {
  const type = $('#drMatchType').value;
  $('#drMatchRow').hidden = type === 'all';
  $('#drMatchValue').disabled = type === 'all';
  $('#drMatchValue').placeholder = type === 'email_suffix' ? '例如：example.com' : type === 'email_exact' ? '例如：user@example.com' : '例如：team';
}
$('#drMatchType').addEventListener('change', drUpdateMatch);

function drResetForm(r) {
  drEditingId = r ? r.id : 0;
  drEditingSort = r ? r.sort_order : drRules.length * 10;
  $('#drModalTitle').textContent = r ? '编辑规则' : '新增规则';
  $('#drName').value = r ? (r.name || '') : '';
  drFillTenantSelect(r ? r.tenant : '');
  $('#drMatchType').value = r?.match_type || 'email_suffix';
  $('#drMatchValue').value = r?.match_value || '';
  drUpdateMatch();
  $('#drAirportFrom').value = r ? (r.airport_from || '') : '';
  $('#drAirportTo').value = r ? (r.airport_to || '') : '';
  drOriginalReplacements = r?.replacements || '';
  $('#drReps').value = drRepsToText(drOriginalReplacements);
  $('#drEnabled').checked = r ? !!r.enabled : true;
}

function drOpenModal(r) {
  if (!drTenants.length) return toast('请先在机场管理里添加机场', 'error');
  drResetForm(r);
  showDialog('drModal', '#drName');
}

function drCloseModal() {
  closeActiveDialog('drModal');
}

function drPayload() {
  const type = $('#drMatchType').value;
  const match = $('#drMatchValue').value.trim();
  return {
    id: drEditingId,
    name: $('#drName').value.trim(),
    tenant: $('#drTenant').value,
    match_type: type,
    match_value: type === 'all' ? '' : type === 'email_suffix' ? match.replace(/^@/, '') : match,
    airport_from: $('#drAirportFrom').value.trim(),
    airport_to: $('#drAirportTo').value.trim(),
    replacements: drTextToReps($('#drReps').value),
    scope_node: true,
    scope_group: true,
    scope_header: true,
    enabled: $('#drEnabled').checked,
    sort_order: drEditingSort,
  };
}

$('#drAddBtn').addEventListener('click', () => drOpenModal(null));
$('#drClose').addEventListener('click', drCloseModal);
$('#drCancel').addEventListener('click', drCloseModal);

$('#drTbody').addEventListener('click', async (ev) => {
  const editBtn = ev.target.closest('.dr-edit');
  const delBtn = ev.target.closest('.dr-del');
  if (editBtn) {
    const id = parseInt(editBtn.dataset.id, 10);
    const r = drRules.find(x => x.id === id);
    if (r) drOpenModal(r);
    return;
  }
  if (delBtn) {
    if (!confirm('删除该展示规则?')) return;
    const id = parseInt(delBtn.dataset.id, 10);
    const res = await apiPost('/api/display-rules/remove', { id });
    if (res && res.ok) { toast('已删除', 'success'); loadDisplayRules(); }
    else toast((res && res.error) || '删除失败', 'error');
  }
});

$('#drSave').addEventListener('click', e => withLoading(e.currentTarget, async () => {
  let body;
  try { body = drPayload(); } catch (err) { return toast(err.message, 'error'); }
  if (!body.name) return toast('请填写规则名', 'error');
  if (!body.tenant) return toast('请选择机场', 'error');
  if (body.match_type !== 'all' && !body.match_value) return toast('请填写匹配值', 'error');
  if (!body.airport_to && !JSON.parse(body.replacements).length) return toast('请填写新机场名或至少一条关键词替换。', 'error');
  const res = await apiPost('/api/display-rules/save', body);
  if (res && res.ok) {
    toast('已保存', 'success');
    drCloseModal();
    loadDisplayRules();
  } else {
    toast((res && res.error) || '保存失败', 'error');
  }
}));
