/* KSR 界面逻辑：串起「扫描 → 分组展示 → 一键优化 → 复检」 */

const TOKEN = new URLSearchParams(location.search).get('t') || '';

const STATE = {
  nav: 'all',
  findings: [],
  passed: [],
  stats: {},
  scanning: false,
  fixing: false,
  lastScanAt: 0,
};

const $ = (s) => document.querySelector(s);
const esc = (s) => String(s == null ? '' : s)
  .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
  .replace(/"/g, '&quot;');

/* ---------------------------------------------------------------- 图标 */
const I = {
  scan: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round"><rect x="2.5" y="4" width="19" height="12.5" rx="1.6"/><path d="M8.5 20h7M12 16.5V20"/><path d="m9 10 2 2 4-4"/></svg>',
  dll: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round"><path d="M5 3.5h9l5 5v12H5z"/><path d="M14 3.5v5h5"/><path d="M8.6 13h1.2a1.4 1.4 0 0 1 0 2.8H8.6zM8.6 13v2.8"/><path d="M12.6 13v3.4M15 13h.9a1.7 1.7 0 0 1 0 3.4H15z"/></svg>',
  runtime: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="3" width="7.5" height="7.5" rx="1.3"/><rect x="13.5" y="3" width="7.5" height="7.5" rx="1.3"/><rect x="3" y="13.5" width="7.5" height="7.5" rx="1.3"/><rect x="13.5" y="13.5" width="7.5" height="7.5" rx="1.3"/></svg>',
  optimize: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round"><path d="M4 7h4M12 7h8M4 12h9M17 12h3M4 17h2M10 17h10"/><circle cx="10" cy="7" r="1.9"/><circle cx="15" cy="12" r="1.9"/><circle cx="8" cy="17" r="1.9"/></svg>',
  audio: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round"><path d="M4 9.5h3.2L12 5.4v13.2L7.2 14.5H4z"/><path d="M15.6 9a4.2 4.2 0 0 1 0 6M18.2 6.6a7.6 7.6 0 0 1 0 10.8"/></svg>',
  game: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round"><path d="M7.4 7h9.2a4.4 4.4 0 0 1 4.3 3.5l.8 4.2a2.6 2.6 0 0 1-4.6 2.2L15.6 15H8.4l-1.5 1.9A2.6 2.6 0 0 1 2.3 14.7l.8-4.2A4.4 4.4 0 0 1 7.4 7z"/><path d="M7.6 10.6v2.6M6.3 11.9h2.6M15.8 11.4h.02M17.8 12.9h.02"/></svg>',
  slow: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round"><path d="M3.6 17a9 9 0 1 1 16.8 0"/><path d="m12 13.6 3.6-3.4"/><circle cx="12" cy="14.4" r="1.5"/></svg>',
  printer: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round"><path d="M7 9V3.8h10V9"/><rect x="3.2" y="9" width="17.6" height="7.6" rx="1.8"/><path d="M7 14h10v6.2H7z"/><path d="M17.4 11.7h.02"/></svg>',
  manual: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round"><path d="M14.7 6.3a3.8 3.8 0 0 0 5 5L20 21l-3-.6-8.2-8.2a3.8 3.8 0 0 1-4.6-5.2l2.7 2.7 2.8-2.8-2.7-2.7a3.8 3.8 0 0 1 4.7.5z"/></svg>',
  chev: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.1" stroke-linecap="round" stroke-linejoin="round"><path d="m5 15 7-7 7 7"/></svg>',
  tick: '<svg viewBox="0 0 24 24" fill="none" stroke="#fff" stroke-width="3.2" stroke-linecap="round" stroke-linejoin="round"><path d="m4 12.5 5 5L20 6.5"/></svg>',
};

/* ---------------------------------------------------------------- 请求 */
async function api(path, opt = {}) {
  const r = await fetch(path, {
    ...opt,
    headers: { 'X-KSR-Token': TOKEN, 'Content-Type': 'application/json', ...(opt.headers || {}) },
  });
  if (!r.ok) throw new Error(`${r.status} ${await r.text()}`);
  return r.json();
}

async function streamNdjson(path, opt, onEvent) {
  const r = await fetch(path, {
    ...opt,
    headers: { 'X-KSR-Token': TOKEN, 'Content-Type': 'application/json', ...(opt.headers || {}) },
  });
  if (!r.ok) throw new Error(`${r.status} ${await r.text()}`);
  const reader = r.body.getReader();
  const dec = new TextDecoder();
  let buf = '';
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    buf += dec.decode(value, { stream: true });
    let nl;
    while ((nl = buf.indexOf('\n')) >= 0) {
      const line = buf.slice(0, nl).trim();
      buf = buf.slice(nl + 1);
      if (line) onEvent(JSON.parse(line));
    }
  }
  if (buf.trim()) onEvent(JSON.parse(buf));
}

/* ---------------------------------------------------------------- 启动 */
let BOOT = null;

async function boot() {
  BOOT = await api('/api/bootstrap');
  setInterval(() => api('/api/heartbeat').catch(() => {}), 5000);
  const want = (location.hash || '').replace('#', '');
  if (want && BOOT.nav.some((n) => n.id === want)) STATE.nav = want;
  renderNav();
  window.addEventListener('hashchange', () => {
    const id = (location.hash || '').replace('#', '');
    if (BOOT.nav.some((n) => n.id === id)) {
      STATE.nav = id;
      document.querySelectorAll('.nav-item').forEach((x) =>
        x.classList.toggle('active', x.dataset.id === id));
      render();
    }
  });
  const env = BOOT.env || {};
  $('#pack-info').textContent =
    `${BOOT.rulepack.scripts} 条脚本 · ${BOOT.rulepack.groups} 个分组`;
  if (env.warnings && env.warnings.length) {
    const s = $('#warn-strip');
    s.hidden = false;
    s.textContent = env.warnings[0];
    s.title = env.warnings.join('\n');
  }
  bindStatic();
  const pre = window.__KSR_PRELOAD__;
  if (pre && pre.findings) {
    STATE.findings = pre.findings;
    STATE.passed = pre.passed || [];
    STATE.lastScanAt = Date.now();
    updateBadges();
    render();
  } else {
    scan();
  }
}

function renderNav() {
  const nav = $('#nav');
  nav.innerHTML = BOOT.nav.map((n) => `
    <div class="nav-item${n.id === STATE.nav ? ' active' : ''}" data-id="${n.id}">
      ${I[n.icon] || I.scan}
      <span class="nav-label">${esc(n.label)}</span>
      <span class="nav-badge" data-badge="${n.id}">${n.items}</span>
    </div>`).join('');
  nav.querySelectorAll('.nav-item').forEach((el) => {
    el.addEventListener('click', () => {
      STATE.nav = el.dataset.id;
      nav.querySelectorAll('.nav-item').forEach((x) => x.classList.toggle('active', x === el));
      history.replaceState(null, '', `#${el.dataset.id}`);
      render();
    });
  });
}

function updateBadges() {
  const counts = {};
  for (const f of STATE.findings) {
    const nav = navOfGroup(f.group);
    if (nav) counts[nav] = (counts[nav] || 0) + 1;
  }
  counts.all = STATE.findings.length;
  BOOT.nav.forEach((n) => {
    const el = document.querySelector(`[data-badge="${n.id}"]`);
    if (!el) return;
    const c = counts[n.id] || 0;
    // 「综合检测」用红标显示待处理项（对应截图里那个红色 1）；
    // 其余分类保持条目数，避免整栏都是红点看不清。
    if (n.id === 'all') {
      el.classList.toggle('hot', c > 0);
      el.textContent = c > 0 ? c : n.items;
    } else {
      el.classList.remove('hot');
      el.textContent = n.items;
    }
    el.title = c > 0 ? `发现 ${c} 项 / 共 ${n.items} 条检测`
                     : `共 ${n.items} 条检测`;
  });
}

function navOfGroup(gid) {
  const n = BOOT.nav.find((x) => x.groups && x.groups.includes(gid));
  return n ? n.id : null;
}

/* ---------------------------------------------------------------- 扫描 */
async function scan() {
  if (STATE.scanning) return;
  STATE.scanning = true;
  const btnFix = $('#btn-fix');
  const btnRescan = $('#btn-rescan');
  btnFix.disabled = true;
  btnRescan.classList.add('busy');
  $('#hero-title').innerHTML = '正在检测中…';
  $('#hero-sub').textContent = '正在逐项检查系统状态，请稍候';
  $('#content').innerHTML = `
    <div class="progress"><i id="pg"></i></div>
    <div class="scanning"><span class="spinner"></span>
      <span id="scan-msg">准备检测…</span></div>`;

  let total = 1;
  let done = 0;
  try {
    await streamNdjson('/api/scan?nav=all', { method: 'GET' }, (ev) => {
      if (ev.type === 'start') {
        total = ev.total || 1;
        $('#scan-msg').textContent = `共 ${total} 条检测脚本，开始扫描…`;
      } else if (ev.type === 'group') {
        done += 1;
        const pg = $('#pg');
        if (pg) pg.style.width = `${Math.min(100, (done / total) * 100).toFixed(1)}%`;
        const msg = $('#scan-msg');
        if (msg) msg.textContent = `已完成 ${ev.title}（${ev.scanned} 条，发现 ${ev.found} 项）`;
      } else if (ev.type === 'done') {
        STATE.findings = ev.findings || [];
        STATE.passed = ev.passed || [];
        STATE.lastScanAt = Date.now();
      }
    });
  } catch (e) {
    $('#content').innerHTML = `<div class="empty">检测失败：${esc(e.message)}</div>`;
    STATE.scanning = false;
    btnRescan.classList.remove('busy');
    return;
  }
  STATE.scanning = false;
  btnRescan.classList.remove('busy');
  updateBadges();
  render();
}

/* ---------------------------------------------------------------- 渲染 */
function visibleFindings() {
  if (STATE.nav === 'all') return STATE.findings;
  const nav = BOOT.nav.find((n) => n.id === STATE.nav);
  const gs = nav && nav.groups ? nav.groups : [];
  return STATE.findings.filter((f) => gs.includes(f.group));
}

function visiblePassed() {
  if (STATE.nav === 'all') return STATE.passed;
  const nav = BOOT.nav.find((n) => n.id === STATE.nav);
  const gs = nav && nav.groups ? nav.groups : [];
  return STATE.passed.filter((f) => gs.includes(f.group));
}

function groupTitle(gid) {
  const n = BOOT.nav.find((x) => x.groups && x.groups.includes(gid));
  return n ? n.label : gid;
}

/* 「系统优化」按原版口径展示：需优化与已达标同列在一个 item 里，
   需优化项勾选并给「优化」按钮，已达标项灰显且不可勾选。
   这正是原版 E_UpAbnormalData 里 level=1/choice=2 与 level=9/choice=3 的差别。

   分组列表 = ksduicfgz.dat 解出的 <solution id="5072"> 的 11 个 item，
   外加 solution 5068「电脑卡慢」里的 7A8F687A（开机时系统服务优化）。 */
const SYSOPT_GROUPS = [
  'sysopt_svc', 'sysopt_sysset', 'sysopt_priv', 'sysopt_taskbar',
  'sysopt_deskicon', 'sysopt_menu', 'sysopt_explorer', 'sysopt_udisk',
  'sysopt_camera', 'sysopt_gpu', 'sysopt_mouse',
  'slow_boot',
];
const isSysopt = (gid) => SYSOPT_GROUPS.indexOf(gid) >= 0;

function secTitleOf(gid) {
  const g = (BOOT.groups || []).find((x) => x.id === gid);
  return g ? g.title : gid;
}

function secDescOf(gid) {
  const g = (BOOT.groups || []).find((x) => x.id === gid);
  return g ? (g.desc || '') : '';
}

function sysoptRow(f) {
  return `
    <div class="row sysopt" data-uuid="${esc(f.uuid)}">
      <label class="chk"><input type="checkbox" class="row-chk" ${!f.fix ? 'disabled' : ''}></label>
      <div class="row-title" title="${esc(f.title)}">${esc(f.title)}</div>
      <div class="row-desc" title="${esc(f.impact || f.detail)}">${esc(f.impact || f.detail)}</div>
      <span class="row-state bad">${f.status === 'unavailable' ? '未完成' : '可选建议'}</span>
      <button class="row-btn primary" data-act="${f.fix ? 'fix' : 'detail'}">${f.fix ? '处理' : '查看'}</button>
    </div>`;
}

function sysoptDoneRow(p) {
  // 用与需优化行相同的 label+input 结构，只把 box 置为未勾选且禁用，
  // 视觉上就是原版 level=9 / choice=3 的「空心框」。
  return `
    <div class="row sysopt is-done" data-uuid="${esc(p.uuid)}">
      <label class="chk"><input type="checkbox" class="row-chk" disabled></label>
      <div class="row-title" title="${esc(p.title)}">${esc(p.title)}</div>
      <div class="row-desc" title="${esc(p.detail)}">${esc(p.detail)}</div>
      <span class="row-state ok">已达标</span>
      <span class="row-btn ghost"></span>
    </div>`;
}

function sysoptSections() {
  const out = [];
  for (const gid of SYSOPT_GROUPS) {
    const need = visibleFindings().filter((f) => f.group === gid);
    const done = visiblePassed().filter((p) => p.group === gid && !p.skip);
    const skip = visiblePassed().filter((p) => p.group === gid && p.skip);
    const total = need.length + done.length;
    if (!total && !skip.length) continue;
    const countText = need.length === 0
      ? `全部达标 · 共 ${total} 项`
      : `${need.length} 项需优化 / 共 ${total} 项`;
    const desc = secDescOf(gid);
    const skipNote = skip.length
      ? `<div class="sec-note">另有 ${skip.length} 项本机不适用（原版在此分支不上报）：` +
        `${skip.map((p) => esc(p.item || p.title)).join('、')}</div>`
      : '';
    out.push(`
      <section class="section" data-sec>
        <div class="sec-head">
          <span class="sec-title">${esc(secTitleOf(gid))}</span>
          <span class="sec-count${need.length === 0 ? ' muted' : ''}">${countText}</span>
          <span class="chev">${I.chev}</span>
        </div>
        ${desc ? `<div class="sec-sub">${esc(desc)}</div>` : ''}
        <div class="sec-body">
          ${need.map(sysoptRow).join('')}
          ${done.map(sysoptDoneRow).join('')}
          ${skipNote}
        </div>
      </section>`);
  }
  return out;
}

function render() {
  const auto = visibleFindings().filter((f) => f.fix && !isSysopt(f.group));
  const manual = visibleFindings().filter((f) => !f.fix && !isSysopt(f.group));
  const passed = visiblePassed().filter((p) => !isSysopt(p.group));

  const total = visibleFindings().length;
  const optCount = visibleFindings().filter((f) => isSysopt(f.group)).length;
  if (total === 0) {
    $('#hero-title').innerHTML = '本轮未发现需要处理的项目';
    const n = visiblePassed().filter((p) => !p.skip).length;
    $('#hero-sub').textContent = `已检查 ${n} 项，未发现异常或可优化项`;
  } else if (auto.length === 0 && optCount === 0) {
    $('#hero-title').innerHTML = `发现 <b>${total}</b> 个需要查看的项目`;
    $('#hero-sub').textContent =
      '以下项目需要手动处理或安装官方组件，程序不会代你改动系统';
  } else {
    $('#hero-title').innerHTML = `发现 <b>${total}</b> 个需要查看的项目`;
    const unavailable = visibleFindings().filter((f) => f.status === 'unavailable').length;
    const optional = visibleFindings().filter((f) => f.optional).length;
    $('#hero-sub').textContent = `${unavailable} 项未能完成检测 · ${optional} 项可选建议；请查看依据后选择`;
  }
  const fixable = visibleFindings().filter((f) => f.fix).length;
  const btn = $('#btn-fix');
  btn.disabled = fixable === 0;
  btn.title = fixable === 0
    ? (total === 0 ? '系统状态良好，无需优化'
       : '当前检出的项目都需要手动处理，详见下方的「请手动修复」')
    : `将修复 ${fixable} 个已勾选的项目`;

  const html = [];

  // 第一段：系统优化（对齐原版分组：需优化 + 已达标同列）
  html.push(...sysoptSections());

  // 第二段：其他可自动修复项，按分组归类
  if (auto.length) {
    const byGroup = {};
    for (const f of auto) (byGroup[f.group] = byGroup[f.group] || []).push(f);
    for (const gid of Object.keys(byGroup)) {
      const items = byGroup[gid];
      html.push(`
        <section class="section" data-sec>
          <div class="sec-head">
            <span class="sec-title">${esc(groupTitle(gid))}</span>
            <span class="sec-count">${items.length} 项</span>
            <span class="chev">${I.chev}</span>
          </div>
          <div class="sec-body">${items.map(autoRow).join('')}</div>
        </section>`);
    }
  }

  // 第三段：需要手动处理
  if (manual.length) {
    html.push(`
      <section class="section" data-sec>
        <div class="sec-head">
          <span class="sec-title">以下项目请手动修复</span>
          <span class="sec-count">${manual.length} 项</span>
          <span class="chev">${I.chev}</span>
        </div>
        <div class="sec-body">${manual.map(manualRow).join('')}</div>
      </section>`);
  }

  // 第四段：未发现问题
  if (passed.length) {
    html.push(`
      <section class="section" data-sec>
        <div class="sec-head">
          <span class="sec-title">以下项目未发现问题</span>
          <span class="sec-count muted">${passed.length} 项</span>
          <span class="chev">${I.chev}</span>
        </div>
        <div class="sec-body">${passed.map(passRow).join('')}</div>
      </section>`);
  }

  if (!html.length) {
    html.push('<div class="empty">未发现问题，系统状态良好</div>');
  }

  $('#content').innerHTML = html.join('');
  bindRows();
}

function rowMeta(f) {
  const d = f.data || {};
  if (Array.isArray(d.missing) && d.missing.length) {
    return `${d.missing.length} 个${d.missing_kind === 'assemblies' ? '组件' : '文件'}`;
  }
  return '';
}

function autoRow(f) {
  const meta = rowMeta(f);
  return `
    <div class="row" data-uuid="${esc(f.uuid)}">
      <label class="chk"><input type="checkbox" class="row-chk" ${f.optional ? '' : 'checked'}></label>
      <div class="row-title" title="${esc(f.title)}">${esc(f.title)}</div>
      <div class="row-desc" title="${esc(f.detail)}">${esc(f.impact || f.detail)}</div>
      ${meta ? `<div class="row-meta">${esc(meta)}</div>` : ''}
      <button class="row-btn" data-act="fix">修复</button>
    </div>`;
}

function manualRow(f) {
  const meta = rowMeta(f);
  const btn = f.data?.action === 'startup_manager'
    ? '<button class="row-btn" data-act="startup">选择停用</button>'
    : f.link
    ? '<button class="row-btn" data-act="open">官网下载</button>'
    : '<button class="row-btn" data-act="detail">查看方法</button>';
  return `
    <div class="row" data-uuid="${esc(f.uuid)}">
      <span class="chk ghost"></span>
      <div class="row-title" title="${esc(f.title)}">${esc(f.title)}</div>
      <div class="row-desc" title="${esc(f.detail)}">${esc(f.status === 'unavailable' ? '检测未完成：' + f.detail : f.impact || f.detail)}</div>
      ${meta ? `<div class="row-meta">${esc(meta)}</div>` : ''}
      ${btn}
    </div>`;
}

const NEGATIVE_TAIL = /(缺失|异常|过多|不可写|未运行|被禁用|损坏|过大|不足|失败)+$/;

function positiveTitle(t) {
  const s = String(t || '').replace(NEGATIVE_TAIL, '').trim();
  return s || t;
}

function passRow(p) {
  return `
    <div class="pass-row" data-uuid="${esc(p.uuid)}">
      <span class="tick">${I.tick}</span>
      <span class="pt">${esc(positiveTitle(p.title))}</span>
      <span class="pd" title="${esc(p.detail)}">${esc(p.detail)}</span>
    </div>`;
}

function bindRows() {
  document.querySelectorAll('[data-act="startup"]').forEach((b) => b.addEventListener('click', showStartup));
  document.querySelectorAll('.sec-head').forEach((h) => {
    h.addEventListener('click', () => h.closest('.section').classList.toggle('collapsed'));
  });
  document.querySelectorAll('.row-chk').forEach((c) => {
    c.addEventListener('change', () => c.closest('.row').classList.toggle('checked', c.checked));
  });
  document.querySelectorAll('[data-act="fix"]').forEach((b) => {
    b.addEventListener('click', () => runFix([b.closest('.row').dataset.uuid]));
  });
  document.querySelectorAll('[data-act="detail"]').forEach((b) => {
    b.addEventListener('click', () => showDetail(b.closest('.row').dataset.uuid));
  });
  document.querySelectorAll('[data-act="open"]').forEach((b) => {
    b.addEventListener('click', () => {
      const f = findFinding(b.closest('.row').dataset.uuid);
      if (f && f.link) api('/api/open', { method: 'POST', body: JSON.stringify({ url: f.link }) });
    });
  });
  document.querySelectorAll('.row-title').forEach((t) => {
    t.addEventListener('click', () => showDetail(t.closest('.row').dataset.uuid));
  });
}

function findFinding(uuid) {
  return STATE.findings.find((f) => f.uuid === uuid);
}

function findPassed(uuid) {
  return STATE.passed.find((p) => p.uuid === uuid);
}

/* 把系统优化项的探针结果拼成「读取位置 / 当前值 / 期望值」三行 */
function probeText(probe) {
  if (!probe) return '';
  if (probe.hive && probe.key) {
    const name = probe.name ? `\\${probe.name}` : '';
    return `${probe.hive}\\${probe.key}${name}`;
  }
  if (probe.service) return `服务 ${probe.service}`;
  if (probe.services) return '服务 ' + probe.services.map((s) => s.name).join('、');
  if (probe.values) return probe.values.map((v) => `${v.hive}\\…\\${v.name}`).join('\n');
  return '';
}

/* ---------------------------------------------------------------- 修复 */
async function runFix(uuids) {
  if (!uuids.length || STATE.fixing) return;
  const selected = uuids.map(findFinding).filter(Boolean);
  if (!confirm('将处理以下项目：\n' + selected.map((f) => '· ' + f.title + (f.optional ? '（可选）' : '')).join('\n') +
    '\n\n会修改对应系统配置或安装官方组件。注册表、服务及受支持的文件变更会保存操作记录；安装包、清理与进程操作不能整体撤销。')) return;
  STATE.fixing = true;
  const btnFix = $('#btn-fix');
  btnFix.disabled = true;
  btnFix.textContent = '优化中…';

  let doneN = 0;
  let okN = 0;
  const failed = [];
  const pendingReboot = [];

  try {
    await streamNdjson('/api/fix', {
      method: 'POST',
      body: JSON.stringify({ uuids }),
    }, (ev) => {
      if (ev.type === 'begin') {
        setRowState(ev.uuid, 'busy', `正在处理（${doneN + 1}/${uuids.length}）`);
      } else if (ev.type === 'item') {
        doneN += 1;
        if (ev.ok) okN += 1;
        else if (ev.status === 'pending_reboot') pendingReboot.push(ev);
        else if (!['pending_reboot', 'not_needed'].includes(ev.status)) failed.push(ev);
        setRowState(ev.uuid, ev.ok ? 'ok' : ev.status === 'pending_reboot' ? 'pending' : 'bad', ev.message || (ev.ok ? '已验证' : '未确认修复'));
      } else if (ev.type === 'done') {
        okN = ev.ok_count;
      }
    });
  } catch (e) {
    alert(`修复请求失败：${e.message}`);
  }

  STATE.fixing = false;
  btnFix.textContent = '修复所选项';

  if (pendingReboot.length) {
    alert(`已验证 ${okN} 项，${pendingReboot.length} 项待重启验证` +
      (failed.length ? `，${failed.length} 项未成功` : '') + '。\n请保存工作并手动重启电脑，然后重新扫描。\n' +
      pendingReboot.map((f) => `· ${f.title}：${f.message}`).join('\n') +
      (failed.length ? '\n未成功项目：\n' + failed.map((f) => `· ${f.title}：${f.message}`).join('\n') : ''));
    return;
  }

  if (doneN > 0) {
    const msg = failed.length
      ? `已修复 ${okN} 项，${failed.length} 项未成功：\n` +
        failed.map((f) => `· ${f.title}：${f.message}`).join('\n')
      : `已修复 ${okN} 项，正在复检…`;
    if (failed.length) alert(msg);
  }
  await scan();
}

function setRowState(uuid, kind, text) {
  const row = document.querySelector(`.row[data-uuid="${uuid}"]`);
  if (!row) return;
  let s = row.querySelector('.row-state');
  if (!s) {
    s = document.createElement('div');
    s.className = 'row-state';
    const btn = row.querySelector('.row-btn');
    if (btn) row.insertBefore(s, btn); else row.appendChild(s);
  }
  s.className = `row-state ${kind === 'ok' ? 'ok' : kind === 'bad' ? 'bad' : ''}`;
  s.textContent = text;
  const btn = row.querySelector('.row-btn');
  if (btn) {
    btn.disabled = kind === 'busy' || kind === 'ok' || kind === 'pending';
    if (kind === 'ok') btn.classList.add('done');
    if (kind === 'bad') btn.classList.add('fail');
  }
  const chk = row.querySelector('.row-chk');
  if (chk && kind !== 'bad') chk.disabled = true;
}

/* ---------------------------------------------------------------- 弹层 */
function openModal(title, bodyHtml) {
  $('#modal-title').textContent = title;
  $('#modal-body').innerHTML = bodyHtml;
  $('#modal').hidden = false;
}
function closeModal() { $('#modal').hidden = true; }

async function showStartup() {
  try {
    const data = await api('/api/startup');
    const rows = data.items || [];
    openModal('启动项管理 · 按需选择停用', `
      <p>仅列出注册表 Run 启动项。请保留需要的输入法、驱动及安全软件；默认不选择任何项。
      不处理服务、驱动、计划任务或启动文件夹。停用不结束当前程序，下次登录生效，可从修复记录撤销。</p>
      <div class="startup-list">${rows.map((row, index) => `
        <label class="startup-item">
          <input type="checkbox" class="startup-choice" value="${index}" ${row.enabled ? '' : 'disabled'}>
          <span><strong>${esc(row.name)}</strong> <small>${esc(row.scope)}${row.enabled ? '' : ' · 已在系统中禁用'}</small>
          <code>${esc(row.command)}</code></span>
        </label>`).join('') || '<p>未发现 Run 启动项。</p>'}</div>
      <button class="btn-primary" id="startup-disable" disabled>停用所选项（可撤销）</button>`);
    const button = $('#startup-disable');
    document.querySelectorAll('.startup-choice').forEach((input) => input.addEventListener('change', () => {
      button.disabled = !document.querySelector('.startup-choice:checked');
    }));
    button.addEventListener('click', async () => {
      const selected = [...document.querySelectorAll('.startup-choice:checked')].map((input) => rows[Number(input.value)]);
      if (!selected.length || !confirm('下次登录时停止自动启动：\n' + selected.map((row) => '· ' + row.name).join('\n') + '\n\n可以在修复记录中撤销。是否继续？')) return;
      button.disabled = true;
      try {
        const result = await api('/api/startup/disable', {method: 'POST', body: JSON.stringify({
          confirm: true, items: selected.map(({id, fingerprint}) => ({id, fingerprint}))})});
        alert(result.message);
        if (result.ok) { closeModal(); await scan(); }
        else await showStartup();
      } catch (error) { alert('停用未完成：' + error.message); button.disabled = false; }
    });
  } catch (error) { alert('读取启动项失败：' + error.message); }
}

function showDetail(uuid) {
  const f = findFinding(uuid);
  if (f) return showFindingDetail(f);
  const p = findPassed(uuid);
  if (p) return showPassedDetail(p);
}

function sysoptExtra(d) {
  const rows = [];
  if (d.why) rows.push(`<h4>这一项检查的是什么</h4><div>${esc(d.why)}</div>`);
  if (d.impact) rows.push(`<h4>不优化会怎样</h4><div>${esc(d.impact)}</div>`);
  const probe = d.probe || {};
  const loc = d.probe_text || probeText(probe);
  if (loc) {
    const actual = probe.actual !== undefined ? `当前值 <code>${esc(String(probe.actual))}</code>` : '';
    const expect = probe.expect !== undefined ? `期望 <code>${esc(String(probe.expect))}</code>` : '';
    let extraLines = '';
    if (Array.isArray(probe.values)) {
      extraLines = probe.values.map((v) =>
        `<div><code>${esc((v.hive ? v.hive + '\\\\' : '') + (v.name || ''))}</code> = ` +
        `<code>${esc(String(v.actual))}</code></div>`).join('');
    }
    rows.push(`<h4>读取位置</h4>
      <div><code>${esc(loc)}</code></div>
      ${actual || expect ? `<div style="margin-top:6px">${actual} ${expect}</div>` : ''}
      ${extraLines}`);
  }
  if (d.src) rows.push(`<h4>对应的原始规则</h4><div><code>${esc(d.src)}</code></div>`);
  if (d.os_gate && d.os_gate.length) {
    rows.push(`<h4>适用系统</h4><div>${esc(d.os_gate.join(' / '))}（当前 ${esc(d.os || '?')}）</div>`);
  }
  return rows;
}

function showPassedDetail(p) {
  const d = p.data || {};
  openModal(p.title, `
    <div>${esc(p.detail)}</div>
    ${sysoptExtra(d).join('')}
    <h4>当前状态</h4><div class="ok-text">已达标，无需处理</div>
    <h4>脚本 UUID</h4><div><code>${esc(p.uuid)}</code></div>`);
}

function showFindingDetail(f) {
  const d = f.data || {};
  const rows = [];
  if (d.missing && d.missing.length) {
    rows.push(`<h4>未检测到的${d.missing_kind === 'assemblies' ? '程序集' : '文件'}（${d.missing.length} 项）</h4>
      <div>${d.missing.map((m) => `<code>${esc(m)}</code>`).join(' ')}</div>`);
  }
  if (d.purpose) rows.push(`<h4>这一项是做什么的</h4><div>${esc(d.purpose)}</div>`);
  if (d.official_url) rows.push(`<h4>安装来源与校验</h4>
    <div>官方来源：<a href="${esc(d.official_url)}" target="_blank" rel="noopener noreferrer">${esc(d.official_url)}</a></div>
    <div>发布者：${esc(d.publisher)}；下载后核对 SHA-256 与 Windows 签名。</div>
    <code>${esc(d.sha256)}</code>`);
  if (d.tier) {
    rows.push(`<h4>判定档位</h4><div>${d.tier === 'core'
      ? '必需项 —— 健康系统上必然存在，缺失属真故障'
      : '兼容项 —— 由可再发行组件包提供，正常系统也可能没有，仅供提示'}</div>`);
  }
  rows.push(...sysoptExtra(d));
  openModal(f.title, `
    <div>${esc(f.detail)}</div>
    ${f.impact ? `<h4>影响</h4><div>${esc(f.impact)}</div>` : ''}
    ${rows.join('')}
    <h4>修复动作</h4>
    <div>${f.fix
      ? `调用 <code>${esc(f.fix.api)}</code> ${f.fix.args ? esc(JSON.stringify(f.fix.args)) : ''}`
      : d.action === 'startup_manager' ? '请点击“启动项管理”，选择需要停用的程序。'
      : '未找到已验证的独立安装包；请使用原应用安装包恢复所需版本，可先通过“诊断应用”检查应用目录。'}</div>
    ${f.needs_admin ? '<h4>权限</h4><div>需要以管理员身份运行才能完成。</div>' : ''}
    <h4>脚本 UUID</h4><div><code>${esc(f.uuid)}</code></div>`);
}

function bindStatic() {
  $('#btn-startup').addEventListener('click', showStartup);
  $('#btn-diagnose').addEventListener('click', async () => {
    const path = prompt('输入需要诊断的 EXE 或 DLL 完整路径（只读分析，不启动程序）');
    if (!path) return;
    openModal('应用诊断', '<p>正在读取 PE 依赖和运行时配置…</p>');
    try {
      const report = await api('/api/diagnose', {method: 'POST', body: JSON.stringify({path: path.replace(/^"|"$/g, '')})});
      const labels = {candidate_found: '找到同架构候选', contract: '系统接口合约', unresolved: '尚未定位', architecture_mismatch: '架构不符', unreadable: '无法读取'};
      const rows = report.dependencies.map((d) => `<tr><td>${esc(d.name)}</td><td>${esc(labels[d.status] || d.status)}</td><td>${esc(d.path)}</td></tr>`).join('');
      openModal('应用诊断', `<p>${esc(report.path)} · ${esc(report.machine)}</p>
        <table><tr><th>依赖</th><th>检查结果</th><th>候选位置</th></tr>${rows}</table>
        ${(report.recommendations || []).map((s) => `<p>${esc(s)}</p>`).join('')}
        ${report.runtime ? `<h4>.NET 运行时</h4><p>${esc(report.runtime.status)} · ${esc(report.runtime.architecture)}</p>` +
          report.runtime.frameworks.map((r) => `<p>${esc(r.name)} ${esc(r.requested_version)}：${esc(r.selected_version || '未找到符合要求的版本')}</p>`).join('') +
          (report.runtime.status === 'missing' ? '<button class="row-btn" id="btn-dotnet-plan">查看 .NET 安装方案</button>' : '') : ''}
        <p>${report.limitations.map(esc).join('<br>')}</p>`);
      const installButton = $('#btn-dotnet-plan');
      if (installButton) installButton.addEventListener('click', () => installDotnetForApp(report.path));
    } catch (error) { openModal('诊断未完成', `<p>${esc(error.message)}</p>`); }
  });
  $('#btn-history').addEventListener('click', async () => {
    try {
      const entries = await api('/api/history');
      openModal('本地修复记录', entries.length ? entries.map((r) => `<p><b>${esc(r.title)}</b> · ${esc(r.status)} · ${r.changes} 个快照
        <br>${esc(r.message)}<br><button class="row-btn" data-undo="${esc(r.id)}" ${!r.changes || r.status === 'undone' ? 'disabled' : ''}>撤销已记录的变更</button></p>`).join('') : '<p>暂无修复记录。</p>');
      document.querySelectorAll('[data-undo]').forEach((button) => button.addEventListener('click', async () => {
        if (!confirm('恢复该记录中的配置？若修复后配置又被修改，将停止撤销。')) return;
        try { const result = await api('/api/undo', {method: 'POST', body: JSON.stringify({id: button.dataset.undo})});
          alert(result.message); closeModal(); await scan();
        } catch (error) { alert(error.message); }
      }));
    } catch (error) { openModal('记录读取失败', `<p>${esc(error.message)}</p>`); }
  });
  $('#btn-rescan').addEventListener('click', (e) => { e.preventDefault(); scan(); });
  $('#btn-fix').addEventListener('click', () => {
    const uuids = [...document.querySelectorAll('.row[data-uuid] input.row-chk:checked')]
      .map((c) => c.closest('.row').dataset.uuid)
      .filter((u) => { const f = findFinding(u); return f && f.fix; });
    runFix(uuids);
  });
  $('#modal-close').addEventListener('click', closeModal);
  $('#modal').addEventListener('click', (e) => { if (e.target.id === 'modal') closeModal(); });

  const about = () => openModal('关于 KSR', `
    <div><b>KSR（系统异常修复）</b>是一个开源免费的系统异常检测与修复工具。</div>
    <h4>它和同类商业工具的区别</h4>
    <ul>
      <li>规则是<b>可读的 JSON</b>，随包发布，任何人都能审计每一条检测在查什么、改什么。</li>
      <li>不内置 VIP、不弹广告、不上传遥测，检测全程只在本机。</li>
      <li>DLL 判定分「必需 / 兼容」两档：只有真正该有的文件缺失才报异常，
          兼容版本缺失只作提示，不会把健康系统报成一片红。</li>
    </ul>
    <h4>技术栈</h4>
    <div>纯 Python 标准库（Win32 走 <code>ctypes</code>），界面为本地页面，
         由系统自带 Edge 以窗口模式承载，无第三方依赖。</div>
    <h4>版本</h4><div>v${esc(BOOT ? BOOT.version : '')} ·
      规则包 ${esc(BOOT ? BOOT.rulepack.scripts : '')} 条</div>`);

  const license = () => openModal('开源许可与数据处理', `
    <h4>许可</h4>
    <div>本项目以 MIT 许可发布，可自由使用、修改、再分发，请保留版权声明。</div>
    <h4>数据</h4>
    <ul>
      <li>检测与修复全部在本机完成，<b>不上传任何数据</b>。</li>
      <li>界面服务只监听 <code>127.0.0.1</code>，并用一次性 token 校验请求。</li>
      <li>安装运行库时会从厂商官方地址下载安装包，这一步需要联网。</li>
    </ul>
    <h4>写系统之前</h4>
    <div>凡涉及服务、注册表、文件覆盖的修复，都会先备份（<code>.ksr.bak</code>），
         并在界面上逐条显示结果。</div>`);

  const usage = () => openModal('使用说明', `
    <h4>三步</h4>
    <ul>
      <li><b>综合检测</b>：启动即自动扫描全部脚本，左栏分类可切换查看。</li>
      <li><b>一键优化</b>：修复所有已勾选的项；单个项目也可点右侧按钮单独修。</li>
      <li><b>重新检测</b>：修复后自动复检，复检不通过的项会标红并给出原因。</li>
    </ul>
    <h4>建议以管理员身份运行</h4>
    <div>服务启动、注册表写入、运行库安装都需要管理员权限；
         标准用户下这些项会直接提示权限不足，不会半途写坏。</div>
    <h4>命令行同样可用</h4>
    <div><code>python -m ksr scan</code> 只读扫描 ·
         <code>python -m ksr fix --dry-run</code> 看修复计划 ·
         <code>python -m ksr fix --yes</code> 真正执行</div>`);

  $('#lnk-issues').addEventListener('click', (e) => { e.preventDefault(); usage(); });
  $('#lnk-repo').addEventListener('click', (e) => { e.preventDefault(); about(); });
  $('#lnk-about').addEventListener('click', (e) => { e.preventDefault(); about(); });
  $('#lnk-license').addEventListener('click', (e) => { e.preventDefault(); license(); });
}

async function installDotnetForApp(path) {
  let installDir = null;
  if (!BOOT.env.admin) {
    installDir = prompt('当前不是管理员。可安装到一个尚不存在的新私有目录，之后使用该目录的 dotnet.exe 启动应用 DLL；不会改变系统运行时。\n若要安装到系统，请取消并以管理员身份重新运行。\n请输入新目录完整路径：');
    if (!installDir) return;
  }
  const request = {path, install_dir: installDir};
  openModal('.NET 安装方案', '<p>正在读取微软发布信息并匹配版本…</p>');
  try {
    const plan = await api('/api/dotnet/plan', {method: 'POST', body: JSON.stringify(request)});
    if (plan.status !== 'ready') {
      openModal('.NET 检查结果', `<p>${esc(plan.status)}</p><p>${esc((plan.issues || []).join('；'))}</p>`);
      return;
    }
    const items = plan.packages.map((p) => `${p.family} ${p.version} (${p.architecture})`);
    openModal('.NET 安装方案', `<p>${esc(installDir ? '安装到私有目录：' + installDir : '安装到系统')}</p>` +
      items.map((s) => `<p>${esc(s)}</p>`).join('') + '<p>从微软官方下载并校验。安装不能整体撤销；不会自动重启，也不会启动目标应用。</p><button class="row-btn" id="btn-dotnet-install">确认安装</button>');
    $('#btn-dotnet-install').addEventListener('click', async () => {
      if (!confirm('确认安装以下官方运行时？\n' + items.join('\n'))) return;
      openModal('正在安装 .NET', '<p>正在下载、校验和安装，请稍候…</p>');
      try {
        const result = await api('/api/dotnet/install', {method: 'POST', body: JSON.stringify({...request, confirm: true, expected_packages: plan.packages})});
        const labels = {verified: '运行时配置复检通过', pending_reboot: '需要重启后重新检测', failed: '安装未完成', blocked: '无法自动安装', not_needed: '已满足要求'};
        openModal('.NET 安装结果', `<h4>${esc(labels[result.status] || result.status)}</h4><p>${esc(result.message)}</p>` +
          (installDir && result.ok ? `<p>私有运行时路径：${esc(installDir)}。请通过该目录的 dotnet.exe 启动应用 DLL。</p>` : ''));
      } catch (error) { openModal('安装未完成', `<p>${esc(error.message)}</p>`); }
    });
  } catch (error) { openModal('无法生成方案', `<p>${esc(error.message)}</p>`); }
}

document.addEventListener('keydown', (e) => { if (e.key === 'Escape') closeModal(); });
boot().catch((e) => {
  document.body.innerHTML =
    `<div style="padding:40px;font:14px/2 'Microsoft YaHei'">
      启动失败：${esc(e.message)}<br>请确认服务仍在运行。</div>`;
});
