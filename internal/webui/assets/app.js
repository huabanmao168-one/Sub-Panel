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
function actionClass(a) {
  const key = String(a || '').trim().toLowerCase();
  return Object.hasOwn(ACTION_CN, key) ? key : 'empty';
}
function actionLabel(a) { return ACTION_CN[actionClass(a)] || a || '—'; }

// tag 中文翻译。带 `:` 的 tag(如 bl_oversea:US / cloud_ip:aws / token_freq=10>=5 window=60s)
// 拆开拼:前缀翻译 + 后缀(国家/服务商/数值)原样附加。
const TAG_PREFIX_CN = {
  // 全局黑名单
  'bl_oversea': '全局策略：海外来源',
  'bl_cloud': '全局策略：云厂商 IP',
  'bl_cn_idc': '全局策略：国内数据中心',
  'bl_browser': '全局策略：浏览器直访',
  'bl_isp': '全局策略：运营商关键字',
  'ip_whitelist': 'IP 白名单放行',
  'ua_blacklist': 'UA 黑名单拦截',
  'banlist_ip': 'IP 黑名单拦截',
  'detector_window': '触发滑窗规则',
  'passthrough_all': '全局跳过风控',
  'lumi_encrypt': 'Lumi 兼容处理',
  'encrypt_failed': 'Lumi 加密失败',
  'decode_failed': '订阅解压失败',
  'body_too_large': '订阅正文过大',
  'no_proxy': '未配置可用上游',
  'display_rewrite': '已应用订阅展示规则',
  'display_nomatch': '未匹配订阅展示规则',
  'path_not_match': '未匹配订阅路径',
  // 上游
  'upstream_bad':   '上游异常',
  // 触发规则
  'token_freq': '单订阅拉取频次',
  'ip_freq': '单 IP 拉取频次',
  'token_distinct_ips': '单订阅多 IP',
  'ip_distinct_tokens': '单 IP 多订阅',
  'token_freq_extreme': '单订阅高频拉取',
  'token_multi_ip': '单订阅多 IP',
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

function tagKey(t) { return String(t || '').trim().split(/[:=]/, 1)[0].trim().toLowerCase(); }
function tagLabel(t) {
  const raw = String(t || '').trim();
  const key = tagKey(raw);
  if (!Object.hasOwn(TAG_PREFIX_CN, key)) {
    if (key.startsWith('fmt_')) return '订阅格式：' + raw.slice(4);
    return raw; // Keep administrator-defined rule names intact.
  }
  const i = raw.search(/[:=]/);
  const suffix = i < 0 ? '' : raw.slice(i + 1).trim();
  const label = TAG_PREFIX_CN[key];
  if (!suffix) return label;
  const detail = suffix.toLowerCase() === 'unknown' ? '未知' : suffix.replace('>=', '≥').replace(/\bwindow=/, '窗口 ');
  return `${label}（${detail}）`;
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
  'resolved': '已处理订阅',
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
  'suspects': () => Promise.all([loadSuspects(), loadDeniedRanking(true)]),
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
  const resetBtn = (tokenFull && actionClass(e.Action) === 'deny' && (e.RuleTags || []).some(t => tagKey(t) === 'detector_window'))
    ? `<button class="ev-reset" data-token="${escapeHTML(tokenFull)}" title="清除该订阅的频率累计，不解除名单或规则限制">重置窗口</button>`
    : '';
  card.innerHTML = `
    <div class="ev-card-head">
      <span class="pill ${actionClass(e.Action)}">${escapeHTML(actionLabel(e.Action))}</span>
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

function openRequestView({ip = '', token = '', action = '', tenant, window: range} = {}) {
  $('#evIP').value = ip;
  $('#evToken').value = token;
  $('#evAction').value = action;
  for (const id of ['#evUsage', '#evUA']) $(id).value = '';
  $('#evShowWL').checked = true;
  if (tenant !== undefined) {
    const select = $('#tenantSel');
    select.value = tenant;
    state.tenant = select.value;
  }
  if (range) { $('#windowSel').value = range; state.window = $('#windowSel').value || '24h'; }
  if (activeTab === 'events') loadEvents();
  else $('.navlink[data-tab="events"]').click();
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
$('#evFilterForm').addEventListener('submit', e => {
  e.preventDefault();
  withLoading($('#evQuery'), () => loadEvents());
});

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
      <td><button class="danger res-restore" data-token="${escapeHTML(r.token)}" data-tenant="${escapeHTML(r.tenant)}">恢复</button></td>
    `;
    tbody.appendChild(tr);
  }
  bindCopyHandlers(tbody);
}
$('#resolvedTbody')?.addEventListener('click', async (e) => {
  const btn = e.target.closest('.res-restore');
  if (!btn) return;
  if (!confirm('恢复后此 token 将重新出现在请求日志里,确定?')) return;
  const r = await apiPost('/api/resolved/remove', { token: btn.dataset.token, tenant: btn.dataset.tenant });
  if (r && r.ok) loadResolved();
  else alert('恢复失败:' + (r && r.error ? r.error : '未知错误'));
});

$('#resolvedClearAll')?.addEventListener('click', async () => {
  if (!confirm('确定清空全部已处理 token? 此操作不可撤销!')) return;
  const r = await apiPost('/api/resolved/clear', {});
  if (r && r.ok) loadResolved();
  else alert('清空失败:' + (r && r.error ? r.error : '未知错误'));
});

// Refused requests are ranked once per scope, independently of log pagination.
let rankingRequest = 0;
let rankingKey = '';
async function loadDeniedRanking(force = false) {
  if (!$('#suspectIPRanking').open) return;
  const q = new URLSearchParams({tenant: state.tenant, window: $('#suspectWindow').value, limit: '20', action: 'deny'});
  if (!force && rankingKey === q.toString()) return;
  rankingKey = q.toString();
  const request = ++rankingRequest;
  const tbody = $('#suspectRankingTbody');
  setEmptyRow(tbody, '正在聚合拒绝请求…');
  const rows = await api('/api/incidents/agg_ip?' + q);
  if (request !== rankingRequest) return;
  tbody.replaceChildren();
  if (!Array.isArray(rows)) {
    rankingKey = '';
    setEmptyRow(tbody, '异常 IP 统计读取失败，请点击刷新重试。');
    return;
  }
  if (!rows.length) { setEmptyRow(tbody, '这个范围内没有被拒绝的请求。'); return; }
  for (const row of rows) {
    const ip = escapeHTML(row.client_ip);
    const tags = [...new Set((row.tags || []).map(tagLabel))].sort((a, b) => a.localeCompare(b, 'zh-CN'));
    const tr = tbody.insertRow();
    tr.innerHTML = `<td class="mono">${ip}</td><td class="numeric"><strong>${Number(row.count)}</strong></td>
      <td>${tags.length ? tags.map(t => `<span class="pill tag">${escapeHTML(t)}</span>`).join('') : '—'}</td>
      <td class="nowrap">${escapeHTML(fmtTime(row.last_ts))}</td><td><div class="table-actions">
      <button type="button" data-rank-action="logs" data-ip="${ip}">查看拒绝日志</button>
      <button type="button" class="danger" data-rank-action="ban" data-ip="${ip}">去封禁</button></div></td>`;
  }
}
$('#suspectIPRanking').addEventListener('toggle', () => loadDeniedRanking());
$('#suspectRankingTbody').addEventListener('click', e => {
  const btn = e.target.closest('[data-rank-action]');
  if (!btn) return;
  const ip = btn.dataset.ip;
  if (btn.dataset.rankAction === 'logs') {
    openRequestView({ip, tenant: state.tenant, action: 'deny', window: $('#suspectWindow').value});
  } else {
    $('.navlink[data-tab="ip-bans"]').click();
    $('#banIPTarget').value = ip;
    $('#banIPReason').value = '异常 IP 排行人工确认';
    $('#banIPTarget').focus();
  }
});

// ---- bans (仅 IP,token 黑名单已废弃) ----
function loadBans() { return Promise.all([loadBlacklistCfg(), loadIPBans()]); }
let bansData = null;
let bansRequest = 0;
async function loadIPBans() {
  const request = ++bansRequest;
  if (bansData === null) setEmptyRow($('#ipBanTbody'), '正在加载封禁名单…');
  const result = await requestJSON('/api/bans');
  if (request !== bansRequest || result === null) return;
  if (!Array.isArray(result)) {
    $('#banSummary').textContent = '封禁名单加载失败';
    if (bansData === null) setEmptyRow($('#ipBanTbody'), '读取失败，请点击刷新重试。');
    else $('#banSummary').textContent = '加载失败，正在显示上次读取的名单。';
    toast(result.error || '封禁名单格式有误', 'error');
    return;
  }
  bansData = result;
  renderIPBans();
}
function renderIPBans() {
  if (!bansData) return;
  const term = $('#banSearch').value.trim().toLowerCase();
  const scope = $('#banScope').value;
  const permanent = bansData.filter(b => !b.ExpiresTS).length;
  const rows = bansData.filter(b => (scope === 'all' || (scope === 'permanent') === !b.ExpiresTS) &&
    (!term || [b.Target, b.Reason].some(x => (x || '').toLowerCase().includes(term))));
  $('#banSummary').textContent = `共 ${bansData.length} 条 · 临时 ${bansData.length - permanent} · 永久 ${permanent}` +
    (term || scope !== 'all' ? ` · 当前显示 ${rows.length} 条` : '');
  const tbody = $('#ipBanTbody'); tbody.replaceChildren();
  if (!rows.length) { setEmptyRow(tbody, bansData.length ? '没有符合筛选条件的封禁。' : '暂无生效中的 IP 封禁。'); return; }
  for (const b of rows) {
    const tr = tbody.insertRow();
    const exp = b.ExpiresTS ? `<time datetime="${escapeHTML(b.ExpiresTS)}">${escapeHTML(fmtTime(b.ExpiresTS))}</time>` : '<span class="pill empty">永久</span>';
    const source = {manual: '手动', auto: '自动'}[b.CreatedBy] || b.CreatedBy || '—';
    tr.innerHTML = `<td class="mono">${escapeHTML(b.Target)}</td><td>${escapeHTML(b.Reason || '—')}</td>
      <td class="nowrap">${escapeHTML(fmtTime(b.CreatedTS))}</td><td class="nowrap">${exp}</td>
      <td><span class="pill state-soft">${escapeHTML(source)}</span></td><td><div class="table-actions">
        <button type="button" data-ban-action="logs" data-ip="${escapeHTML(b.Target)}">查看日志</button>
        <button type="button" class="danger" data-ban-action="remove" data-ip="${escapeHTML(b.Target)}">解封</button>
      </div></td>`;
  }
}
$('#banSearch').addEventListener('input', renderIPBans);
$('#banScope').addEventListener('change', renderIPBans);
$('#ipBanTbody').addEventListener('click', e => {
  const button = e.target.closest('button[data-ban-action]');
  if (!button) return;
  const ip = button.dataset.ip;
  if (button.dataset.banAction === 'logs') { openRequestView({ip, tenant: ''}); return; }
  if (!confirm(`确定解除对 ${ip} 的 IP 封禁？其他拦截规则不受影响。`)) return;
  withLoading(button, async () => {
    const r = await apiPost('/api/bans/remove', { kind: 'ip', target: ip });
    if (r?.ok) { toast('已解封', 'success'); await loadIPBans(); }
    else if (r) toast(r.error || '解封失败', 'error');
  });
});
function updateBanDuration() {
  const custom = $('#banIPDuration').value === 'custom';
  $('#banCustomTTL').hidden = !custom;
  $('#banIPTTL').required = custom;
}
$('#banIPDuration').addEventListener('change', updateBanDuration);
$('#banIPForm').addEventListener('submit', e => {
  e.preventDefault();
  const target = $('#banIPTarget').value.trim();
  const duration = $('#banIPDuration').value;
  const ttl = duration === 'custom' ? $('#banIPTTL').value.trim() : duration;
  if (!target || (duration === 'custom' && !ttl)) { toast('请填写 IP 地址和封禁时长', 'error'); return; }
  const existing = bansData?.some(b => b.Target === target);
  if ((existing || ttl === '') && !confirm(existing ? `更新 ${target} 的原有封禁？` : `对 ${target} 永久封禁？`)) return;
  withLoading($('#banIPAddBtn'), async () => {
    const r = await apiPost('/api/bans/add', {kind: 'ip', target, reason: $('#banIPReason').value.trim(), ttl});
    if (r?.ok) {
      $('#banIPForm').reset(); updateBanDuration();
      toast(existing ? '封禁已更新' : '已添加封禁', 'success');
      await loadIPBans();
    } else if (r) toast(r.error || '添加失败', 'error');
  });
});

// Global policy drafts are independent of the manual IP list.
const blControls = {oversea_enabled: '#blOversea', cloud_enabled: '#blCloud', cn_idc_enabled: '#blCNIDC', browser_enabled: '#blBrowser'};
let blSaved = null;
let blBusy = false;
function readBlacklistForm() {
  const cfg = {};
  for (const [field, selector] of Object.entries(blControls)) cfg[field] = $(selector).checked;
  cfg.isp_keywords = [...new Set($('#blISPKw').value.split(/[,，\n]/).map(s => s.trim()).filter(Boolean))];
  return cfg;
}
function writeBlacklistForm(cfg) {
  for (const [field, selector] of Object.entries(blControls)) $(selector).checked = Boolean(cfg[field]);
  $('#blISPKw').value = (cfg.isp_keywords || []).join(', ');
}
function updateBlacklistState() {
  const status = $('#blStatus');
  const changed = blSaved !== null && JSON.stringify(readBlacklistForm()) !== JSON.stringify(blSaved);
  $('#blSaveBtn').disabled = $('#blResetBtn').disabled = !changed || blBusy;
  status.className = 'pill ' + (changed ? 'state-warning' : 'state-soft');
  status.textContent = blBusy ? '处理中…' : changed ? '有未保存的修改' : blSaved ? '已与运行状态同步' : '读取失败，请刷新';
  return changed;
}
async function loadBlacklistCfg() {
  if (blBusy || (blSaved && updateBlacklistState())) return;
  blBusy = true;
  $('#blFields').disabled = true;
  updateBlacklistState();
  const cfg = await api('/api/blacklist');
  blBusy = false;
  if (cfg) { writeBlacklistForm(cfg); blSaved = readBlacklistForm(); }
  $('#blFields').disabled = !blSaved;
  updateBlacklistState();
}
$('#blForm').addEventListener('input', updateBlacklistState);
$('#blResetBtn').addEventListener('click', () => { if (blSaved) writeBlacklistForm(blSaved); updateBlacklistState(); });
$('#blForm').addEventListener('submit', async e => {
  e.preventDefault();
  if (blBusy || !updateBlacklistState()) return;
  const draft = readBlacklistForm();
  blBusy = true;
  $('#blFields').disabled = true;
  updateBlacklistState();
  const r = await apiPost('/api/blacklist/save', draft);
  blBusy = false;
  $('#blFields').disabled = false;
  if (r?.ok) { blSaved = draft; writeBlacklistForm(draft); toast('策略已保存并生效', 'success'); }
  else if (r) toast(r.error || r.msg || '保存策略失败', 'error');
  updateBlacklistState();
});

function filterList(data, term, columns, statusID) {
  const needle = term.trim().toLowerCase();
  const visible = data.filter(row => !needle || columns.some(k => String(row[k] || '').toLowerCase().includes(needle)));
  $(statusID).textContent = needle ? `显示 ${visible.length} / ${data.length} 条` : `共 ${data.length} 条`;
  return visible;
}

// ---- IP 白名单 ----
let ipWhitelist = [];
async function loadIPWhitelist() {
  const list = await api('/api/ip-whitelist');
  if (!Array.isArray(list)) { $('#ipWLSummary').textContent = '加载失败，请刷新重试。'; return; }
  ipWhitelist = list;
  renderIPWhitelist();
}
function renderIPWhitelist() {
  const list = filterList(ipWhitelist, $('#ipWLSearch').value, ['Target', 'Note'], '#ipWLSummary');
  const tbody = $('#ipWLTbody'); tbody.replaceChildren();
  if (!list.length) { setEmptyRow(tbody, ipWhitelist.length ? '没有匹配的白名单条目。' : '暂无 IP 白名单条目。'); return; }
  for (const e of list) {
    const tr = document.createElement('tr');
    tr.dataset.id = e.ID;
    tr.dataset.target = e.Target || '';
    tr.dataset.note = e.Note || '';
    tr.innerHTML = `
      <td class="mono ipwl-target">${escapeHTML(e.Target)}</td>
      <td class="ipwl-note">${escapeHTML(e.Note || '')}</td>
      <td class="mono">${escapeHTML(fmtTime(e.CreatedTS))}</td>
      <td><div class="table-actions ipwl-ops">
        <button type="button" class="ipwl-edit" data-id="${e.ID}">编辑</button>
        <button type="button" class="danger ipwl-del" data-id="${e.ID}">删除</button>
      </div></td>
    `;
    tbody.appendChild(tr);
  }
}

$('#ipWLSearch').addEventListener('input', renderIPWhitelist);
// Keep row actions aligned when editing in place.
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
    tr.querySelector('.ipwl-target').innerHTML = `<input class="ipwl-edit-target table-input" aria-label="编辑 IP 或网段" value="${escapeHTML(curTarget)}">`;
    tr.querySelector('.ipwl-note').innerHTML = `<input class="ipwl-edit-note table-input" aria-label="编辑备注" value="${escapeHTML(curNote)}">`;
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

$('#ipWLForm').addEventListener('submit', e => {
  e.preventDefault();
  const target = $('#ipWLTarget').value.trim();
  if (!target) return toast('请输入 IP 或网段', 'error');
  withLoading($('#ipWLAddBtn'), async () => {
    const r = await apiPost('/api/ip-whitelist/add', {target, note: $('#ipWLNote').value.trim()});
    if (r?.ok) { $('#ipWLForm').reset(); toast('已添加白名单', 'success'); await loadIPWhitelist(); }
    else if (r) toast(r.error || '添加失败', 'error');
  });
});

// ---- UA 黑名单 ----
let uaBlacklist = [];
async function loadUABlacklist() {
  const list = await api('/api/ua-blacklist');
  if (!Array.isArray(list)) { $('#uaBlSummary').textContent = '加载失败，请刷新重试。'; return; }
  uaBlacklist = list;
  renderUABlacklist();
}
function renderUABlacklist() {
  const list = filterList(uaBlacklist, $('#uaBlSearch').value, ['Pattern', 'Note'], '#uaBlSummary');
  const tbody = $('#uaBlTbody'); tbody.replaceChildren();
  if (!list.length) { setEmptyRow(tbody, uaBlacklist.length ? '没有匹配的黑名单条目。' : '暂无 UA 黑名单条目。'); return; }
  for (const e of list) {
    const tr = document.createElement('tr');
    tr.innerHTML = `
      <td class="mono">${escapeHTML(e.Pattern)}</td>
      <td>${escapeHTML(e.Note || '')}</td>
      <td class="mono">${escapeHTML(fmtTime(e.CreatedTS))}</td>
      <td><div class="table-actions"><button type="button" class="danger uabl-del" data-id="${e.ID}">删除</button></div></td>
    `;
    tbody.appendChild(tr);
  }
}

$('#uaBlSearch').addEventListener('input', renderUABlacklist);
$('#uaBlTbody').addEventListener('click', async (ev) => {
  if (!ev.target.matches('.uabl-del')) return;
  if (!confirm('删除该 UA 黑名单?')) return;
  const id = parseInt(ev.target.dataset.id, 10);
  const r = await apiPost('/api/ua-blacklist/remove', { id });
  if (r && r.ok) { toast('已删除', 'success'); loadUABlacklist(); }
  else toast((r && r.error) || '失败', 'error');
});

$('#uaBlForm').addEventListener('submit', e => {
  e.preventDefault();
  const pattern = $('#uaBlPattern').value.trim();
  if (!pattern) return toast('请输入 UA 关键词', 'error');
  withLoading($('#uaBlAddBtn'), async () => {
    const r = await apiPost('/api/ua-blacklist/add', {pattern, note: $('#uaBlNote').value.trim()});
    if (r?.ok) { $('#uaBlForm').reset(); toast('已添加 UA 黑名单', 'success'); await loadUABlacklist(); }
    else if (r) toast(r.error || '添加失败', 'error');
  });
});

// ---- 云 IP ----
async function loadGeoIPInfo() {
  const s = await api('/api/geoip');
  if (!s) return;
  const el = $('#geoipStatus');
  if (s.loaded) {
    el.innerHTML = `<span class="pill pass">已加载</span> <span>${escapeHTML(s.version || '')}</span> <code class="breakable">${escapeHTML(s.path || '')}</code>`;
  } else {
    el.innerHTML = '<span class="pill state-warning">未加载</span><span>请到设置 → 日志与 GeoIP 检查路径。</span>';
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
  const fields = rows.filter(([, value]) => value).map(([key, value, suffix]) =>
    `<div><dt>${escapeHTML(key)}</dt><dd>${escapeHTML(value)}${escapeHTML(suffix || '')}</dd></div>`);
  const cloud = info.cloud_provider ? `<p class="status-banner" data-state="pending">云厂商 IP：${escapeHTML(info.cloud_provider)}</p>` : '';
  return `${cloud}<dl class="settings-active">${fields.join('')}</dl>`;
}

$('#geoLookupForm').addEventListener('submit', e => {
  e.preventDefault();
  const ip = $('#cloudCheckIP').value.trim();
  if (!ip) return;
  withLoading($('#cloudCheckBtn'), async () => {
    const r = await api('/api/geoip/lookup?ip=' + encodeURIComponent(ip));
    const el = $('#geoipResult');
    if (!r) { el.textContent = '查询失败，请重试。'; return; }
    if (!r.found) { el.textContent = `未在 GeoIP 数据库中找到 ${ip}。`; return; }
    el.innerHTML = renderGeoInfo(r.info);
  });
});

// ---- SQLite 系统配置 ----
const runtimeForm = $('#runtimeSettingsForm');
const runtimeFields = $('#runtimeFields');
const runtimeStatus = $('#runtimeStatus');
const ingressMode = runtimeForm.elements.namedItem('ingress_mode');
let runtimeBusy = false;
let runtimeSnapshot = null;
let runtimeBaseline = '';
let runtimeError = '';
function updateIngressFields() {
  const chain = ingressMode.value === 'nginx_cloudflare';
  $('#ingressDirectFields').hidden = chain;
  $('#ingressChainFields').hidden = !chain;
  runtimeForm.elements.namedItem('ingress_proxies').required = !chain;
  runtimeForm.elements.namedItem('nginx_egress_ips').required = chain;
}
function writeRuntimeFields(saved) {
  for (const [key, value] of Object.entries(saved)) {
    const field = runtimeForm.elements.namedItem(key);
    if (!field) continue;
    if (field.type === 'checkbox') field.checked = value;
    else field.value = Array.isArray(value) ? value.join('\n') : value;
  }
  updateIngressFields();
}
function readRuntimeFields() {
  const body = {};
  for (const field of runtimeForm.elements) {
    if (!field.name) continue;
    if (field.type === 'checkbox') body[field.name] = field.checked;
    else if (field.type === 'number') body[field.name] = Number(field.value);
    else if (field.tagName === 'TEXTAREA') body[field.name] = field.value.split('\n').map(x => x.trim()).filter(Boolean);
    else body[field.name] = field.value.trim();
  }
  return body;
}
function runtimeDirty() { return runtimeSnapshot !== null && JSON.stringify(readRuntimeFields()) !== runtimeBaseline; }
function updateRuntimeState() {
  const r = runtimeSnapshot;
  const dirty = runtimeDirty();
  const restarting = Boolean(r?.restart_scheduled);
  const pending = Boolean(r?.restart_required);
  const supportsRestart = Boolean(r?.restart_supported);
  const state = runtimeError ? 'error' : runtimeBusy ? 'loading' : restarting || pending || dirty ? 'pending' : 'active';
  const badge = $('#runtimeBadge');
  badge.textContent = runtimeBusy ? '处理中' : restarting ? '正在重启' : dirty ? '未保存' : pending ? '待重启' : r ? '已生效' : '未加载';
  badge.className = 'pill ' + (state === 'pending' ? 'state-warning' : 'state-soft');
  runtimeStatus.dataset.state = state;
  runtimeStatus.textContent = runtimeError || (runtimeBusy ? '正在处理配置…' : restarting ? '配置已保存，服务即将重启。重启后需重新登录；若修改了管理端监听地址，请使用新地址访问。' :
    dirty ? '有未保存的修改。使用面板内的「刷新」不会覆盖草稿。' : pending ? '已保存，仍在使用旧配置。' : r ? '以下表单与当前运行配置一致。' : '配置尚未加载。');
  $('#runtimeSaveMode').textContent = supportsRestart ? '保存实际变更后会自动重启服务。' : '保存后需手动重启服务。';
  $('#runtimeDraftHint').textContent = supportsRestart ? '重启期间订阅与管理面会短暂中断。' : '可从服务管理菜单重启。';
  $('#runtimeReset').disabled = !dirty || runtimeBusy || restarting;
  $('#runtimeSave').disabled = !r || runtimeBusy || restarting || !(dirty || (pending && supportsRestart));
  $('#runtimeSave').textContent = supportsRestart ? (pending && !dirty ? '立即重启' : '保存并重启') : '保存运行配置';
}
function renderRuntimeSettings(r) {
  runtimeError = '';
  runtimeSnapshot = r;
  writeRuntimeFields(r.saved);
  runtimeBaseline = JSON.stringify(readRuntimeFields());
  $('#runtimeActiveListen').textContent = r.active.listen;
  $('#runtimeActiveAdmin').textContent = r.active.admin_listen;
  $('#runtimeActiveIngress').textContent = r.active.ingress_mode === 'nginx_cloudflare' ? 'Nginx → Cloudflare → Sub-Panel' : '直连前置代理';
  runtimeFields.disabled = Boolean(r.restart_scheduled);
  updateRuntimeState();
}
async function loadSettings() {
  if (runtimeBusy || runtimeDirty() || runtimeSnapshot?.restart_scheduled) return;
  runtimeBusy = true;
  runtimeError = '';
  runtimeFields.disabled = true;
  updateRuntimeState();
  const r = await api('/api/settings/runtime');
  runtimeBusy = false;
  if (!r?.saved || !r?.active) {
    runtimeError = runtimeSnapshot ? '刷新失败，仍显示上次读取的配置。' : '加载失败，请刷新重试。';
    runtimeFields.disabled = !runtimeSnapshot;
    updateRuntimeState();
    return;
  }
  renderRuntimeSettings(r);
}
for (const event of ['input', 'change']) runtimeForm.addEventListener(event, () => {
  updateIngressFields(); runtimeError = ''; updateRuntimeState();
});
$('#runtimeReset').addEventListener('click', () => {
  if (!runtimeSnapshot) return;
  runtimeError = '';
  writeRuntimeFields(runtimeSnapshot.saved);
  updateRuntimeState();
});
$$('[data-settings-jump]').forEach(btn => btn.addEventListener('click', () => {
  const target = document.getElementById(btn.dataset.settingsJump);
  target?.focus({preventScroll: true});
  target?.scrollIntoView({block: 'start'});
}));
async function waitForRuntimeRestart() {
  for (let attempt = 0; attempt < 22; attempt++) {
    await new Promise(resolve => setTimeout(resolve, 1200));
    try {
      const r = await fetch('/api/session', {cache: 'no-store', signal: AbortSignal.timeout(2000)});
      if (r.status === 401) { location.replace('/login'); return; }
    } catch { /* Service is temporarily unavailable while systemd restarts it. */ }
  }
  runtimeStatus.textContent = '未能自动确认重启。请检查服务状态，或通过新的管理地址重新登录。';
}
async function saveRuntimeSettings(e) {
  e.preventDefault();
  if (runtimeBusy || !runtimeSnapshot || $('#runtimeSave').disabled) return;
  const body = readRuntimeFields();
  runtimeBusy = true;
  runtimeError = '';
  runtimeFields.disabled = true;
  updateRuntimeState();
  const result = await requestJSON('/api/settings/runtime?restart=1', 'PUT', body);
  runtimeBusy = false;
  if (!result?.saved || result.ok === false) {
    runtimeFields.disabled = false;
    runtimeError = result?.error || '保存失败，请重试。';
    updateRuntimeState();
    return;
  }
  renderRuntimeSettings(result);
  if (result.restart_scheduled) {
    toast('配置已保存，正在重启服务', 'success');
    if (result.active.admin_listen === result.saved.admin_listen) waitForRuntimeRestart();
  } else toast(result.restart_required ? '已保存，请手动重启' : '配置已生效', 'success');
}
runtimeForm.addEventListener('submit', saveRuntimeSettings);

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

const RULE_COUNTERS = [
  ['token_freq', 'Tf', '同一订阅拉取', '次'],
  ['ip_freq', 'If', '同一 IP 拉取', '次'],
  ['token_distinct_ips', 'Td', '同一订阅出现', '个独立 IP'],
  ['ip_distinct_tokens', 'Id', '同一 IP 访问', '个不同订阅'],
];
const RULE_LIST_FIELDS = {
  country_in: ['ruleFormCountryIn', '国家在名单内'], country_not_in: ['ruleFormCountryNotIn', '国家不在名单内'],
  usage_type_in: ['ruleFormUsageIn', 'IP 用途在名单内'], usage_type_not_in: ['ruleFormUsageNotIn', 'IP 用途不在名单内'],
  isp_contains: ['ruleFormISP', '运营商包含'],
};
let ruleView = null;
let ruleRequest = 0;

function readableRuleWindow(seconds) {
  let n = Number(seconds || 0);
  const parts = [];
  for (const [unit, scale] of [['天', 86400], ['小时', 3600], ['分钟', 60], ['秒', 1]]) {
    const value = Math.floor(n / scale);
    if (value > 0) { parts.push(`${value} ${unit}`); n %= scale; }
  }
  return parts.join(' ') || '—';
}
function ruleConditionLabels(r) {
  const labels = [];
  for (const [key,, label, unit] of RULE_COUNTERS) {
    const win = r[`${key}_window_sec`], threshold = r[`${key}_gte`];
    if (win > 0 && threshold > 0) labels.push(`${readableRuleWindow(win)}内，${label} ≥ ${threshold} ${unit}`);
  }
  if (r.from_cloud_ip) labels.push('命中云厂商 IP');
  for (const [key, [, label]] of Object.entries(RULE_LIST_FIELDS)) {
    if (r[key]?.length) labels.push(`${label}：${(key.startsWith('usage_type') ? r[key].map(usageLabel) : r[key]).join('、')}`);
  }
  return labels;
}
function ruleHasGeo(r) { return r.from_cloud_ip || Object.keys(RULE_LIST_FIELDS).some(key => r[key]?.length); }
function ruleIssues(r) {
  const issues = r.issue ? [r.issue] : [];
  if (ruleHasGeo(r) && !ruleView?.geoip_ready) issues.push('GeoIP 数据库未加载，地理、运营商或云厂商条件不会触发。');
  const cap = ruleView?.max_window_sec;
  if (cap && RULE_COUNTERS.some(([key]) => r[`${key}_window_sec`] > cap)) issues.push('计数窗口超过当前运行容量。');
  return issues;
}
function renderRules() {
  const list = $('#rulesList');
  if (!ruleView) return;
  const term = $('#ruleSearch').value.trim().toLowerCase();
  const filter = $('#ruleStatusFilter').value;
  const rows = ruleView.rules.filter(row => {
    if (filter === 'enabled' && !row.enabled || filter === 'disabled' && row.enabled) return false;
    if (filter === 'needs_attention' && !ruleIssues(row).length) return false;
    return !term || [row.name, row.desc, ...ruleConditionLabels(row)].some(x => String(x || '').toLowerCase().includes(term));
  });
  $('#ruleListStatus').textContent = `显示 ${rows.length} / ${ruleView.rules.length} 条规则`;
  list.replaceChildren();
  if (!rows.length) {
    list.innerHTML = `<div class="card empty-state">${ruleView.rules.length ? '没有符合筛选的规则。' : '暂无触发规则。可以导入预设，或新增自定义规则。'}</div>`;
    return;
  }
  for (const x of rows) {
    const card = document.createElement('article');
    card.className = 'card rule-card';
    const conditions = ruleConditionLabels(x);
    const issues = ruleIssues(x);
    const id = escapeHTML(x.name);
    card.innerHTML = `<div class="rule-card-header"><div class="rule-card-title"><h3>${id}</h3>
       <span class="pill ${x.enabled ? 'pass' : 'empty'}">${x.enabled ? '已启用' : '已停用'}</span></div>
       <span class="section-copy">${x.updated_ts > 0 ? '更新于 ' + escapeHTML(fmtTime(x.updated_ts * 1000)) : ''}</span></div>
      ${x.desc ? `<p class="section-copy">${escapeHTML(x.desc)}</p>` : ''}
      <ul class="rule-conditions">${(conditions.length ? conditions : ['暂无有效条件']).map(t => `<li>${escapeHTML(t)}</li>`).join('')}</ul>
      ${issues.length ? `<p class="section-copy rule-warning">${issues.map(escapeHTML).join(' ')}</p>` : ''}
      <div class="table-actions"><button type="button" data-rule-action="edit" data-name="${id}">编辑</button>
      <button type="button" data-rule-action="copy" data-name="${id}">复制为新规则</button>
      <button type="button" data-rule-action="toggle" data-name="${id}">${x.enabled ? '停用' : '启用'}</button>
      <button type="button" data-rule-action="delete" data-name="${id}" class="danger">删除</button></div>`;
    list.append(card);
  }
}
async function loadRulesTable() {
  const request = ++ruleRequest;
  $('#rulesList').setAttribute('aria-busy', 'true');
  $('#ruleListStatus').textContent = '正在读取规则…';
  const r = await api('/api/detect_rules?view=editor');
  if (request !== ruleRequest) return;
  $('#rulesList').setAttribute('aria-busy', 'false');
  if (!Array.isArray(r?.rules)) {
    $('#ruleListStatus').textContent = ruleView ? '刷新失败，正在显示上次读取的规则。' : '读取失败，请点击刷新重试。';
    return;
  }
  ruleView = r;
  const enabled = r.rules.filter(x => x.enabled).length;
  $('#ruleEnabledCount').textContent = enabled;
  $('#ruleDisabledCount').textContent = r.rules.length - enabled;
  $('#ruleCapacity').textContent = readableRuleWindow(r.max_window_sec);
  $('#ruleGeoStatus').textContent = r.geoip_ready ? '已加载' : '未加载';
  renderRules();
}
$('#ruleSearch').addEventListener('input', renderRules);
$('#ruleStatusFilter').addEventListener('change', renderRules);
$('#rulesList').addEventListener('click', e => {
  const btn = e.target.closest('[data-rule-action]');
  if (!btn) return;
  const {ruleAction: action, name} = btn.dataset;
  const item = ruleView?.rules.find(x => x.name === name);
  if (!item) return;
  if (action === 'edit' || action === 'copy') { openRuleModal(item, action === 'copy'); return; }
  if (action === 'delete' && !confirm(`删除「${name}」？删除后不能撤销。`)) return;
  if (action === 'toggle' && !item.enabled && !confirm(`启用「${name}」？启用后，命中请求会返回 HTTP 403。`)) return;
  withLoading(btn, async () => {
    const r = action === 'delete' ? await apiPost('/api/detect_rules/remove', {name}) :
      await apiPost('/api/detect_rules/state', {name, enabled: !item.enabled});
    if (r?.ok) { toast(action === 'delete' ? '已删除' : item.enabled ? '已停用' : '已启用', 'success'); await loadRulesTable(); }
    else if (r) toast(r.error || '规则操作失败', 'error');
  });
});

let ruleEditorRevision = 0;
function csvToList(s) { return [...new Set(String(s || '').split(/[,，\n]+/).map(x => x.trim()).filter(Boolean))]; }
function ruleCounterField(id, suffix) { return $(`#ruleForm${id}${suffix}`); }
function readRuleEditor() {
  const modal = $('#ruleModal');
  const body = {name: $('#ruleFormName').value.trim(), desc: $('#ruleFormDesc').value.trim(),
    enabled: $('#ruleFormEnabled').checked, sort_order: Number(modal.dataset.sortOrder || 0),
    original_name: modal.dataset.originalName || '', from_cloud_ip: $('#ruleFormFromCloud').checked};
  for (const [key, id] of RULE_COUNTERS) {
    body[`${key}_window_sec`] = Number(ruleCounterField(id, 'Win').value);
    body[`${key}_gte`] = Number(ruleCounterField(id, 'Gte').value);
  }
  for (const [field, [id]] of Object.entries(RULE_LIST_FIELDS)) body[field] = csvToList($('#' + id).value);
  return body;
}
function ruleDraftError(r) {
  for (const [key,, label] of RULE_COUNTERS) {
    const a = r[`${key}_window_sec`], b = r[`${key}_gte`];
    if ([a, b].some(x => !Number.isSafeInteger(x) || x < 0)) return `${label}：窗口和阈值必须是整数。`;
    if ((a > 0) !== (b > 0)) return `${label}：窗口和阈值必须同时填写。`;
    if (a > (ruleView?.max_window_sec || 86400)) return `${label}：窗口超过服务当前容量。`;
  }
  if (r.country_in.length && r.country_not_in.length) return '同一条规则不能同时设置两种国家匹配方式。';
  if (r.usage_type_in.length && r.usage_type_not_in.length) return '同一条规则不能同时设置两种 IP 用途匹配方式。';
  if (!ruleConditionLabels(r).length) return '请至少填写一项条件。';
  if (r.enabled && ruleView && !ruleView.geoip_ready && ruleHasGeo(r) && !RULE_COUNTERS.some(([key]) => r[`${key}_window_sec`] > 0)) {
    return 'GeoIP 未加载，纯 GeoIP 规则可以保存为停用，但还不能启用。';
  }
  return '';
}
function renderRulePreview() {
  const r = readRuleEditor();
  const preview = $('#rulePreview');
  const error = ruleDraftError(r);
  preview.classList.toggle('rule-warning', Boolean(error));
  const conditions = ruleConditionLabels(r);
  preview.textContent = error || (r.enabled ? '命中任一条件即拒绝：' : '当前保存为停用，启用后任一条件命中即拒绝：') + conditions.join('；') + '。';
  if (!error && ruleView && !ruleView.geoip_ready && ruleHasGeo(r)) preview.textContent += ' GeoIP 条件在数据库加载前不会触发。';
}
function openRuleModal(r, copy = false) {
  ++ruleEditorRevision;
  const edit = Boolean(r && !copy);
  const name = copy ? `${r.name.slice(0, 116)} 副本` : r?.name || '';
  $('#ruleModalTitle').textContent = edit ? `编辑规则：${r.name}` : copy ? '复制为新规则' : '新增规则';
  $('#ruleFormName').value = name;
  $('#ruleFormDesc').value = r?.desc || '';
  for (const [key, id] of RULE_COUNTERS) {
    ruleCounterField(id, 'Win').value = r?.[`${key}_window_sec`] || '';
    ruleCounterField(id, 'Gte').value = r?.[`${key}_gte`] || '';
  }
  for (const [field, [id]] of Object.entries(RULE_LIST_FIELDS)) $('#' + id).value = r?.[field]?.join(', ') || '';
  $('#ruleFormFromCloud').checked = Boolean(r?.from_cloud_ip);
  $('#ruleFormEnabled').checked = Boolean(edit && r.enabled);
  $('#ruleAdvanced').open = Boolean(r && ruleHasGeo(r));
  $('#ruleModal').dataset.originalName = edit ? r.name : '';
  $('#ruleModal').dataset.sortOrder = edit ? String(r.sort_order || 0) : '0';
  const resolution = readableRuleWindow(ruleView?.resolution_sec || 60);
  $('#ruleWindowHelp').textContent = `同时填写窗口和阈值；两项都留空则忽略。当前按 ${resolution}时间桶近似计数，建议使用整分钟窗口。`;
  renderRulePreview();
  showDialog('ruleModal', '#ruleFormName');
}
function closeRuleModal() { closeActiveDialog('ruleModal'); }
$('#ruleAddBtn').addEventListener('click', () => openRuleModal(null));
$('#ruleModalClose').addEventListener('click', closeRuleModal);
$('#ruleFormCancel').addEventListener('click', closeRuleModal);
$('#ruleModal').addEventListener('click', e => { if (e.target.id === 'ruleModal') closeRuleModal(); });
$('#ruleEditorForm').addEventListener('input', renderRulePreview);
$('#ruleEditorForm').addEventListener('submit', e => {
  e.preventDefault();
  const body = readRuleEditor();
  const error = body.name ? ruleDraftError(body) : '请填写规则名。';
  if (error) { toast(error, 'error'); return; }
  const revision = ruleEditorRevision;
  withLoading($('#ruleFormSave'), async () => {
    const r = await apiPost('/api/detect_rules/save', body);
    if (r?.ok) {
      toast(body.enabled ? '已保存并启用' : '已保存为停用', 'success');
      if (revision === ruleEditorRevision) closeRuleModal();
      await loadRulesTable();
    } else if (r) toast(r.error || '保存失败', 'error');
  });
});

let presetRequest = 0;
let presetImporting = false;
function selectedPresets() { return $$('#rulePresetList input:checked:not(:disabled)').map(x => x.value); }
function updatePresetSelection() {
  const count = selectedPresets().length;
  $('#rulePresetImport').disabled = !count || presetImporting;
  $('#rulePresetImport').textContent = presetImporting ? '导入中…' : count ? `导入 ${count} 条` : '导入所选';
  $('#rulePresetStatus').textContent = count ? `已选 ${count} 条，导入后保持停用。` : '尚未选中可导入的预设。';
}
async function openPresetModal() {
  const request = ++presetRequest;
  $('#rulePresetList').replaceChildren();
  $('#rulePresetImport').disabled = true;
  $('#rulePresetStatus').textContent = '正在读取预设规则…';
  showDialog('rulePresetModal', '#rulePresetClose');
  const items = await api('/api/detect_rules/presets');
  if (request !== presetRequest || $('#rulePresetModal').hidden) return;
  if (!Array.isArray(items)) { $('#rulePresetStatus').textContent = '预设读取失败，关闭后可重新打开。'; return; }
  for (const item of items) {
    const label = document.createElement('label');
    label.className = 'rule-preset-option';
    label.innerHTML = `<input type="checkbox" value="${escapeHTML(item.id)}" ${item.existing ? 'disabled' : ''}>
      <span><strong>${escapeHTML(item.title)}</strong><small>${escapeHTML(item.description)}</small>
      <small>${escapeHTML(item.caution)}</small>${item.existing ? `<span class="pill empty">已存在：${escapeHTML(item.existing)}</span>` : ''}</span>`;
    $('#rulePresetList').append(label);
  }
  updatePresetSelection();
}
function closePresetModal() { closeActiveDialog('rulePresetModal'); }
$('#rulePresetBtn').addEventListener('click', openPresetModal);
$('#rulePresetClose').addEventListener('click', closePresetModal);
$('#rulePresetCancel').addEventListener('click', closePresetModal);
$('#rulePresetModal').addEventListener('click', e => { if (e.target.id === 'rulePresetModal') closePresetModal(); });
$('#rulePresetList').addEventListener('change', updatePresetSelection);
$('#rulePresetForm').addEventListener('submit', async e => {
  e.preventDefault();
  const ids = selectedPresets();
  if (presetImporting || !ids.length) return;
  presetImporting = true;
  const request = presetRequest;
  updatePresetSelection();
  const r = await apiPost('/api/detect_rules/presets/import', {ids});
  presetImporting = false;
  updatePresetSelection();
  if (r?.ok) {
    toast(`导入 ${r.imported.length} 条（停用），跳过 ${r.skipped.length} 条。`, 'success');
    if (request === presetRequest) closePresetModal();
    await loadRulesTable();
  } else if (r) toast(r.error || '导入失败', 'error');
});

// ────────────────────────────────────────────────
// 修改密码 + 一键透传(设置页)
// ────────────────────────────────────────────────
let passthroughBusy = false;
function renderPassthrough(enabled) {
  $('#passthroughToggle').checked = enabled;
  $('#passthroughLabel').textContent = enabled ? '已开启' : '已关闭';
  $('#passthroughStatusPill').hidden = !enabled;
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
let reportSaved = null;
const reportInput = $('#reportSecretInput');
const reportSave = $('#reportSecretSave');
function reportDirty() { return reportSaved !== null && reportInput.value.trim() !== reportSaved; }
function renderReportState() {
  reportInput.disabled = reportBusy || reportSaved === null;
  reportSave.disabled = reportInput.disabled || !reportDirty();
  $('#reportSecretStatus').textContent = reportBusy ? '处理中…' : reportSaved === null ? '未加载，点击刷新重试。' :
    reportDirty() ? '密钥有未保存的修改。' : reportSaved ? '已启用密钥校验。' : '未配置密钥，上报接口不校验。';
}
async function loadReportSecret() {
  if (reportBusy || reportDirty()) return;
  reportBusy = true;
  renderReportState();
  const r = await api('/api/report-info');
  reportBusy = false;
  if (r) { reportSaved = r.report_secret || ''; reportInput.value = reportSaved; }
  renderReportState();
}
reportInput.addEventListener('input', renderReportState);
$('#reportSecretForm').addEventListener('submit', async e => {
  e.preventDefault();
  if (reportBusy || !reportDirty()) return;
  const val = reportInput.value.trim();
  if (!val && !confirm('清除密钥后，上报接口将不再校验密钥。确认清除？')) return;
  reportBusy = true;
  renderReportState();
  const r = await apiPost('/api/report-info/save', {report_secret: val});
  reportBusy = false;
  if (r?.ok) {
    reportSaved = val;
    reportInput.value = val;
    toast(val ? '密钥已保存，请同步更新上报代码。' : '密钥已清除（上报接口不校验）', 'success');
  } else if (r) toast(r.error || '保存失败', 'error');
  renderReportState();
});

$('#adminPasswordForm').addEventListener('submit', async e => {
  e.preventDefault();
  const btn = $('#pwSaveBtn');
  if (btn.disabled) return;
  const oldP = $('#pwOld').value;
  const newP = $('#pwNew').value;
  const newP2 = $('#pwNew2').value;
  if (!oldP || !newP) { toast('请填写原密码和新密码', 'error'); return; }
  const bytes = new TextEncoder().encode(newP).length;
  if (bytes < 8 || bytes > 72) { toast('新密码须为 8–72 字节', 'error'); return; }
  if (newP !== newP2) { toast('两次输入的新密码不一致', 'error'); return; }
  btn.disabled = true;
  $('#passwordStatus').textContent = '正在修改密码…';
  const r = await apiPost('/api/auth/change_password', { old_password: oldP, new_password: newP });
  if (r?.ok) {
    $('#passwordStatus').textContent = '密码已修改，请重新登录。';
    for (const id of ['#pwOld', '#pwNew', '#pwNew2']) $(id).value = '';
    toast('密码已修改，即将退出登录…', 'success');
    setTimeout(() => { location.href = '/login'; }, 1500);
  } else {
    btn.disabled = false;
    $('#passwordStatus').textContent = r?.error || '未修改密码，请重试。';
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

const SUSPECT_PAGE_SIZE = 20;
let suspectsRequest = 0;
let suspectOffset = 0;
let suspectSearchTimer;
async function loadSuspects(offset = 0) {
  clearTimeout(suspectSearchTimer);
  const request = ++suspectsRequest;
  const list = $('#suspectsList');
  const status = $('#suspectResult');
  const range = $('#suspectWindow').value;
  list.replaceChildren();
  list.setAttribute('aria-busy', 'true');
  $('#suspectPager').hidden = true;
  status.textContent = '正在统计订阅活动…';
  const q = new URLSearchParams({view: 'review', tenant: state.tenant, window: range,
    search: $('#suspectSearch').value.trim(), signal: $('#suspectSignal').value, sort: $('#suspectSort').value,
    limit: String(SUSPECT_PAGE_SIZE), offset: String(offset)});
  const result = await api('/api/suspects?' + q);
  if (request !== suspectsRequest) return;
  list.setAttribute('aria-busy', 'false');
  if (!result || !Array.isArray(result.items)) {
    status.textContent = '读取失败，请刷新重试。';
    return;
  }
  if (offset > 0 && result.items.length === 0) { await loadSuspects(0); return; }
  suspectOffset = offset;
  status.textContent = result.total ? `共 ${result.total} 条 · 第 ${offset + 1}–${offset + result.items.length} 条` : '当前筛选没有结果';
  $('#suspectPager').hidden = result.total <= SUSPECT_PAGE_SIZE;
  $('#suspectPrev').disabled = offset === 0;
  $('#suspectNext').disabled = offset + result.items.length >= result.total;
  if (!result.items.length) {
    list.innerHTML = '<div class="card empty-state">没有符合条件的订阅记录。可换时间范围或清除筛选。</div>';
    return;
  }
  for (const r of result.items) list.append(renderSuspectCard(r, range));
  bindCopyHandlers(list);
}

function renderSuspectCard(r, range) {
  const card = document.createElement('article');
  card.className = 'card review-card';
  const id = escapeHTML(r.token);
  const ratio = r.traffic_total > 0 ? ` · ${(r.traffic_used / r.traffic_total * 100).toFixed(0)}%` : '';
  const traffic = r.traffic_total > 0 ? `${fmtBytes(r.traffic_used)} / ${fmtBytes(r.traffic_total)}${ratio}` : '未上报流量额度';
  const metrics = [['成功拉取', r.pull_count], ['独立 IP', r.distinct_ips], ['UA 标识', r.distinct_uas], ['风控拒绝', r.denied]];
  card.innerHTML = `
    <div class="review-card-header">
      <div class="review-identity"><h3>${escapeHTML(r.email || '未上报邮箱')}</h3><span class="pill state-soft">${escapeHTML(r.tenant)}</span>
        ${r.multi_source ? '<span class="pill state-warning">多来源</span>' : ''}</div>
      <button type="button" class="copyable mono" data-copy="${id}" aria-label="复制完整订阅标识">${escapeHTML(tokenShort(r.token))}</button>
    </div>
    <dl class="review-metrics">${metrics.map(([label, value]) => `<div><dt>${label}</dt><dd>${Number(value || 0).toLocaleString('zh-CN')}</dd></div>`).join('')}</dl>
    <div class="review-card-footer">
      <div class="section-copy">最近活动：${escapeHTML(fmtTime(r.last_activity)) || '—'}<br>上报流量：${traffic}</div>
      <div class="table-actions">
        <button type="button" class="sus-detail-toggle" aria-expanded="false">成功拉取明细</button>
        <button type="button" class="sus-event-view">查看请求日志</button>
        <button type="button" class="sus-resolve" data-token="${id}" data-tenant="${escapeHTML(r.tenant)}">标记已处理</button>
      </div>
    </div>
    <div class="suspect-detail" hidden></div>`;
  card.querySelector('.sus-detail-toggle').addEventListener('click', () => toggleSuspectDetail(card, r, range));
  card.querySelector('.sus-event-view').addEventListener('click', () => openRequestView({token: r.token, tenant: r.tenant, window: range}));
  return card;
}

async function toggleSuspectDetail(card, r, range) {
  const box = card.querySelector('.suspect-detail');
  const btn = card.querySelector('.sus-detail-toggle');
  box.hidden = !box.hidden;
  btn.setAttribute('aria-expanded', String(!box.hidden));
  if (box.hidden || box.dataset.loading || box.dataset.loaded) return;
  box.dataset.loading = '1';
  box.textContent = '正在读取成功拉取明细…';
  const q = new URLSearchParams({token: r.token, tenant: r.tenant, window: range});
  const detail = await api('/api/suspect-detail?' + q);
  delete box.dataset.loading;
  if (!card.isConnected) return;
  if (!detail) { box.textContent = '读取失败，收起后可重新展开重试。'; return; }
  box.dataset.loaded = '1';
  if (!detail.ips?.length && !detail.uas?.length) { box.textContent = '当前范围没有成功拉取的来源明细。可在请求日志中查看拒绝记录。'; return; }
  box.innerHTML = `
    <div class="review-results"><p class="section-copy detail-count" role="status"></p><button type="button" class="detail-clear">清除筛选</button></div>
    <div class="review-detail-grid"><div><h4>IP 来源</h4><div class="detail-ips datatable"></div></div><div><h4>客户端 UA</h4><div class="detail-uas datatable"></div></div></div>`;
  const ipsContainer = box.querySelector('.detail-ips');
  const uasContainer = box.querySelector('.detail-uas');
  const countLabel = box.querySelector('.detail-count');
  const clearBtn = box.querySelector('.detail-clear');

  const ipToUAs = new Map(), uaToIPs = new Map();
  for (const b of detail.bindings || []) {
    if (!ipToUAs.has(b.ip)) ipToUAs.set(b.ip, new Set());
    if (!uaToIPs.has(b.ua)) uaToIPs.set(b.ua, new Set());
    ipToUAs.get(b.ip).add(b.ua);
    uaToIPs.get(b.ua).add(b.ip);
  }
  let selectedIP = '', selectedUA = '';

  function renderDetails() {
    const ips = (detail.ips || []).filter(x => !selectedUA || uaToIPs.get(selectedUA)?.has(x.ip));
    const uas = (detail.uas || []).filter(x => !selectedIP || ipToUAs.get(selectedIP)?.has(x.ua));
    const control = (kind, value, selected) => `<button type="button" class="detail-filter mono" data-filter="${kind}" data-value="${escapeHTML(value)}" aria-pressed="${selected}">${escapeHTML(value)}</button>`;
    const table = (headers, rows) => `<table><thead><tr>${headers.map(x => `<th scope="col">${x}</th>`).join('')}</tr></thead><tbody>${rows.length ? rows.join('') : `<tr><td colspan="${headers.length}" class="empty-state">无匹配记录</td></tr>`}</tbody></table>`;
    ipsContainer.innerHTML = table(['IP 地址', '位置 / ISP', '拉取次数', '关联 UA'], ips.map(x => `<tr>
      <td>${control('ip', x.ip, selectedIP === x.ip)}</td><td>${escapeHTML([x.country, x.isp].filter(Boolean).join(' · ') || '—')}</td>
      <td class="numeric">${Number(x.hit_count)}</td><td class="numeric">${ipToUAs.get(x.ip)?.size || 0}</td></tr>`));
    uasContainer.innerHTML = table(['UA', '拉取次数', '关联 IP'], uas.map(x => `<tr>
      <td>${control('ua', x.ua, selectedUA === x.ua)}</td><td class="numeric">${Number(x.hit_count)}</td>
      <td class="numeric">${uaToIPs.get(x.ua)?.size || 0}</td></tr>`));
    countLabel.textContent = `${ips.length} 个 IP · ${uas.length} 种 UA` + (selectedIP || selectedUA ? ' · 已筛选关联项' : ' · 可点 IP 或 UA 交叉筛选');
    clearBtn.disabled = !selectedIP && !selectedUA;
  }
  box.addEventListener('click', e => {
    const filter = e.target.closest('[data-filter]');
    if (!filter) return;
    const {filter: kind, value} = filter.dataset;
    if (kind === 'ip') { selectedIP = selectedIP === value ? '' : value; selectedUA = ''; }
    else { selectedUA = selectedUA === value ? '' : value; selectedIP = ''; }
    renderDetails();
    [...box.querySelectorAll('[data-filter]')].find(x => x.dataset.filter === kind && x.dataset.value === value)?.focus();
  });
  clearBtn.addEventListener('click', () => { selectedIP = selectedUA = ''; renderDetails(); btn.focus(); });
  renderDetails();
}

$('#suspectWindow').addEventListener('change', () => { loadSuspects(); loadDeniedRanking(); });
for (const id of ['#suspectSort', '#suspectSignal']) $(id).addEventListener('change', () => loadSuspects());
$('#suspectSearch').addEventListener('input', () => {
  clearTimeout(suspectSearchTimer);
  ++suspectsRequest;
  suspectSearchTimer = setTimeout(() => loadSuspects(), 250);
});
$('#suspectPrev').addEventListener('click', () => loadSuspects(Math.max(0, suspectOffset - SUSPECT_PAGE_SIZE)));
$('#suspectNext').addEventListener('click', () => loadSuspects(suspectOffset + SUSPECT_PAGE_SIZE));

// 嫌疑卡片"已处理"按钮:事件委托
$('#suspectsList').addEventListener('click', async (e) => {
  const btn = e.target.closest('.sus-resolve');
  if (!btn) return;
  e.stopPropagation();
  const token = btn.dataset.token;
  const tenant = btn.dataset.tenant || '';
  const note = prompt('仅将该机场下的订阅标记为已处理。可填写备注：', '');
  if (note === null) return;
  await withLoading(btn, async () => {
    const r = await apiPost('/api/resolved/add', {token, tenant, note});
    if (r?.ok) { toast('已标记为已处理', 'success'); await loadSuspects(suspectOffset); }
    else if (r) toast(r.error || '标记失败', 'error');
  });
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
let drOriginalReplacements = '';
const DR_MATCH_LABELS = {
  email_suffix: '邮箱后缀', email_exact: '完整邮箱', email_keyword: '邮箱关键词', all: '全部已上报邮箱的订阅',
  ua_contains: 'UA 包含', ua_not_contains: 'UA 不包含',
};
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
      <td class="mono">${Number(r.sort_order)}</td>
      <td>${escapeHTML(r.name)}</td>
      <td>${escapeHTML(r.tenant || '—')}</td>
      <td>${escapeHTML(DR_MATCH_LABELS[r.match_type] || '未知')}${r.match_type === 'all' ? '' : `：${escapeHTML(r.match_value || '—')}`}</td>
      <td>${escapeHTML(r.airport_to || '不改')}</td>
      <td><span class="pill ${r.enabled ? 'pass' : 'empty'}">${r.enabled ? '已启用' : '已停用'}</span></td>
      <td><div class="table-actions">
        <button type="button" class="dr-edit" data-id="${Number(r.id)}">编辑</button>
        <button type="button" class="danger dr-del" data-id="${Number(r.id)}">删除</button>
      </div></td>
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
  return (Array.isArray(reps) ? reps : []).map(p => (p?.from || '') + '=' + (p?.to || '')).join('\n');
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
  const ua = type === 'ua_contains' || type === 'ua_not_contains';
  const input = $('#drMatchValue');
  $('#drMatchRow').hidden = type === 'all';
  input.disabled = type === 'all';
  input.required = type !== 'all';
  $('#drMatchLabel').textContent = ua ? 'UA 关键词' : '邮箱匹配值';
  input.placeholder = ua ? '例如 Clash 或 Shadowrocket' : type === 'email_suffix' ? '例如 example.com' : type === 'email_exact' ? '例如 user@example.com' : '例如 team';
  $('#drMatchHint').textContent = ua ? '只检查当前请求的 User-Agent，忽略大小写，不需要邮箱上报；没有 UA 的请求不匹配。' : '按 V2Board 上报的邮箱判断，未上报邮箱时不匹配。';
}
$('#drMatchType').addEventListener('change', drUpdateMatch);

function drResetForm(r) {
  drEditingId = r ? r.id : 0;
  const last = drRules.reduce((max, row) => Math.max(max, Number(row.sort_order) || 0), -10);
  $('#drSortOrder').value = r ? r.sort_order : Math.min(Number.MAX_SAFE_INTEGER, last + 10);
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
    sort_order: Number($('#drSortOrder').value),
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

$('#drForm').addEventListener('submit', e => {
  e.preventDefault();
  withLoading($('#drSave'), async () => {
  let body;
  try { body = drPayload(); } catch (err) { return toast(err.message, 'error'); }
  if (!body.name) return toast('请填写规则名', 'error');
  if (!body.tenant) return toast('请选择机场', 'error');
  if (body.match_type !== 'all' && !body.match_value) return toast('请填写匹配值', 'error');
  if (!Number.isSafeInteger(body.sort_order)) return toast('优先级必须是整数', 'error');
  if (!body.airport_to && !JSON.parse(body.replacements).length) return toast('请填写新机场名或至少一条关键词替换。', 'error');
  const res = await apiPost('/api/display-rules/save', body);
  if (res && res.ok) {
    toast('已保存', 'success');
    drCloseModal();
    loadDisplayRules();
  } else {
    toast((res && res.error) || '保存失败', 'error');
  }
  });
});
