"""扫描结果报告：生成自包含 HTML（对应原程序“扫描完成 → 异常项/优化项 → 一键修复”的呈现）。"""

from __future__ import annotations

import datetime
import html

SEV_META = {
    "error": ("异常项", "#e5484d", "#fdecec"),
    "warn": ("优化项", "#e08c00", "#fff6e5"),
    "info": ("可优化项", "#0b7fd4", "#e9f3fd"),
}

CSS = """
*{box-sizing:border-box}
body{margin:0;font:14px/1.6 "Microsoft YaHei","PingFang SC",system-ui,sans-serif;
  color:#1b2430;background:#f2f5f9}
.wrap{max-width:1000px;margin:0 auto;padding:28px 20px 64px}
header{display:flex;align-items:flex-end;gap:16px;margin-bottom:18px}
h1{font-size:22px;margin:0;letter-spacing:.5px}
.sub{color:#6b7a8d;font-size:12px}
.hero{background:linear-gradient(135deg,#1f6feb,#2da4c7);color:#fff;border-radius:16px;
  padding:26px 28px;display:flex;gap:28px;align-items:center;flex-wrap:wrap;
  box-shadow:0 10px 26px rgba(31,111,235,.18)}
.hero .num{font-size:52px;font-weight:700;line-height:1}
.hero .lbl{opacity:.9;font-size:13px}
.hero .bar{flex:1;min-width:220px}
.chips{display:flex;gap:10px;flex-wrap:wrap;margin:22px 0 8px}
.chip{background:#fff;border-radius:12px;padding:12px 16px;flex:1;min-width:150px;
  box-shadow:0 2px 10px rgba(20,40,80,.06);border-left:4px solid var(--c)}
.chip b{display:block;font-size:24px}
.chip span{color:#6b7a8d;font-size:12px}
section{margin-top:26px}
h2{font-size:15px;margin:0 0 10px;color:#33445c;font-weight:600}
.card{background:#fff;border-radius:12px;box-shadow:0 2px 10px rgba(20,40,80,.06);
  overflow:hidden;margin-bottom:12px}
.row{display:flex;gap:12px;padding:14px 16px;border-bottom:1px solid #eef2f7}
.row:last-child{border-bottom:none}
.tag{font-size:11px;padding:2px 8px;border-radius:20px;height:20px;white-space:nowrap}
.t{font-weight:600;margin-bottom:2px}
.d{color:#6b7a8d;font-size:12.5px}
code{background:#f3f6fa;border-radius:4px;padding:1px 5px;font-size:12px;
  font-family:Consolas,monospace;color:#33507a}
.ok{color:#12924f}.fail{color:#e5484d}.plan{color:#8a6d00}
table{width:100%;border-collapse:collapse;font-size:13px}
th,td{text-align:left;padding:8px 10px;border-bottom:1px solid #eef2f7}
th{color:#6b7a8d;font-weight:600;font-size:12px}
footer{margin-top:34px;color:#8c9aad;font-size:12px;text-align:center}
"""


def _esc(s) -> str:
    return html.escape(str(s if s is not None else ""))


def _sev(sev: str) -> tuple:
    return SEV_META.get(sev, SEV_META["info"])


def render(scan: dict, env: dict, cfg, dry_run: bool, title="系统异常修复 · 扫描报告") -> str:
    findings = scan["findings"]
    counts = {"error": 0, "warn": 0, "info": 0}
    for f in findings:
        counts[f.rule.severity] = counts.get(f.rule.severity, 0) + 1
    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    total = len(findings)

    chips = "".join(
        f'<div class="chip" style="--c:{_sev(k)[1]}"><b>{counts.get(k,0)}</b>'
        f'<span>{_sev(k)[0]}</span></div>'
        for k in ("error", "warn", "info")
    )

    by_group: dict[str, list] = {}
    for f in findings:
        by_group.setdefault(f.rule.group, []).append(f)

    secs = []
    for gid in cfg.sequence:
        items = by_group.get(gid)
        if not items:
            continue
        g = cfg.group_of(gid)
        rows = []
        for f in items:
            name, color, bg = _sev(f.sev)
            if f.status == "unavailable":
                name, color, bg = "检测未完成", "#6b7a8d", "#eef2f7"
            imp = (f'<div class="d">影响：{_esc(f.rule.impact)}</div>'
                   if f.rule.impact else "")
            fix_txt = ""
            if f.rule.fix and f.status == "issue":
                state = {"pending_reboot": "待重启验证", "unverified": "尚未验证",
                         "planned": "计划", "not_run": "未执行", "failed": "失败",
                         "verified": "已验证"}.get(f.fix_status, "尚未验证")
                cls = "ok" if state == "已验证" else "fail" if state == "失败" else "plan"
                extra = f" {_esc(f.fix_message)}" if f.fix_message else ""
                fix_txt = (f'<div class="d" style="margin-top:4px">修复动作 '
                           f'<code>{_esc(f.rule.fix["api"])}</code> · '
                           f'<span class="{cls}">{state}</span>{extra}</div>')
            rows.append(
                '<div class="row"><div style="flex:1">'
                f'<div class="t">{_esc(f.rule.title)}</div>'
                f'<div class="d">{_esc(f.detail)}</div>'
                f'{imp}{fix_txt}'
                f'<div class="d" style="margin-top:4px">脚本 UUID '
                f'<code>{_esc(f.rule.uuid[:8])}</code> · 耗时 {f.elapsed_ms} ms</div>'
                '</div>'
                f'<span class="tag" style="background:{bg};color:{color}">{name}</span>'
                '</div>'
            )
        secs.append(
            f'<section><h2>{_esc(g.get("title", gid))} '
            f'<span class="sub">（{gid} · {len(items)} 项）</span></h2>'
            f'<div class="card">{"".join(rows)}</div></section>'
        )

    if not secs:
        secs.append('<section><h2>检测结果</h2><div class="card"><div class="row">'
                    '<div><div class="t ok">以下检测项已最优</div>'
                    '<div class="d">全部规则通过，未发现需要处理的问题。</div>'
                    '</div></div></div></section>')

    gstats = "".join(
        f'<tr><td>{_esc(v["title"])}</td><td>{v["scanned"]}</td>'
        f'<td>{v["found"]}</td><td>{v["elapsed_ms"]} ms</td></tr>'
        for v in scan["groups"].values() if v["scanned"]
    )
    warns = "".join(f"<div class='d'>· {_esc(x)}</div>" for x in env.get("warnings") or [])

    return f"""<!DOCTYPE html><html lang="zh-CN"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{_esc(title)}</title><style>{CSS}</style></head><body><div class="wrap">
<header><div><h1>电脑异常修复</h1>
<div class="sub">KSR 引擎 · 规则包 {_esc(cfg.build)} · {now} · {"只读扫描" if dry_run else "扫描并修复"}</div>
</div></header>
<div class="hero">
  <div><div class="num">{total}</div><div class="lbl">需关注项（含检测未完成）</div></div>
  <div class="bar">
    <div style="font-size:13px;opacity:.92">共执行 {scan["scanned"]} 条脚本 · {len(cfg.groups)} 个分组 · 耗时 {scan["elapsed_ms"]} ms</div>
    {warns or '<div class="d" style="color:#e8f3ff;opacity:.9">· 环境自检通过</div>'}
  </div>
</div>
<div class="chips">{chips}</div>
{''.join(secs)}
<section><h2>执行统计</h2><div class="card"><table>
<tr><th>分组</th><th>执行脚本</th><th>检出</th><th>耗时</th></tr>{gstats}
</table></div></section>
<footer>由 KSR（逆向重实现）生成 · 规则包 schema {_esc(cfg.info.get("schema",""))}</footer>
</div></body></html>"""
