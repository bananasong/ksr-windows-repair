"""扫描/修复引擎。

对应原程序的三段结构：
  ConfigManager::Init            -> ConfigManager.init()      三张表校验
  ScanManage::RunGlobalScript    -> Engine.run_global()       全局准备脚本
  ScanManage::RunOneScriptByUuid -> Engine.run_rule()         按 UUID 跑单条脚本
  ScanMode: run script group / run all scan script -> run_scan(groups=None|[...])

原程序把“扫描脚本”和“修复脚本”做成同一 UUID 命名空间下的两支，日志分别打出
``system repair v3 start to run scan script`` 与 ``... run fix script``；
本实现让一条规则同时持有 check / fix / verify 三段，语义等价。
"""

from __future__ import annotations

import time
import uuid as uuidlib
from dataclasses import dataclass, field

from . import api
from . import pack as packmod
from . import win32api as w
from . import journal

SEVERITY_ORDER = {"error": 0, "warn": 1, "info": 2}


@dataclass
class Rule:
    uuid: str
    group: str
    title: str
    severity: str = "warn"
    impact: str = ""
    description: str = ""
    check: dict = field(default_factory=dict)
    fix: dict | None = None
    verify: dict | None = None
    needs_admin: bool = False
    needs_reboot: bool = False
    tags: list = field(default_factory=list)
    link: str = ""
    optional: bool = False

    @classmethod
    def from_dict(cls, d: dict) -> "Rule":
        return cls(
            uuid=d["uuid"], group=d["group"], title=d["title"],
            severity=d.get("severity", "warn"), impact=d.get("impact", ""),
            description=d.get("description", ""),
            check=d.get("check") or {}, fix=d.get("fix"),
            verify=d.get("verify") or d.get("check"),
            needs_admin=bool(d.get("needs_admin")),
            needs_reboot=bool(d.get("needs_reboot")),
            tags=list(d.get("tags") or []),
            link=d.get("link", ""),
            optional=bool(d.get("optional")),
        )


@dataclass
class Finding:
    rule: Rule
    detail: str
    data: dict
    fixed: bool | None = None
    fix_message: str = ""
    fix_ok: bool | None = None
    verify_detail: str = ""
    elapsed_ms: int = 0
    # 检测结果可以覆盖规则的静态严重级（清单类规则：缺必需项 vs 缺可选项）
    severity: str = ""
    # 检测结果可以覆盖标题：原版同一检查点在「需优化 / 已达标」两态用不同文案
    title: str = ""
    status: str = "issue"
    fix_status: str = "not_run"
    journal_id: str = ""

    @property
    def sev(self) -> str:
        return self.severity or self.rule.severity

    @property
    def display_title(self) -> str:
        return self.title or self.rule.title

    def to_dict(self) -> dict:
        return {
            "uuid": self.rule.uuid,
            "group": self.rule.group,
            "title": self.display_title,
            "severity": self.sev,
            "impact": self.rule.impact,
            "detail": self.detail,
            "data": self.data,
            "fix": self.rule.fix if self.status == "issue" else None,
            "status": self.status,
            "optional": self.rule.optional or self.sev == "info" or bool(self.data.get("optional")),
            "fix_status": self.fix_status,
            "journal_id": self.journal_id,
            "link": self.rule.link,
            "needs_admin": self.rule.needs_admin,
            "needs_reboot": self.rule.needs_reboot,
            "fix_ok": self.fix_ok,
            "fix_message": self.fix_message,
            "verify_detail": self.verify_detail,
            "elapsed_ms": self.elapsed_ms,
        }


class ConfigManager:
    """三张表：script info / script sequence / script group。"""

    def __init__(self, pack: dict):
        self.info = pack.get("info", {})
        self.build = pack.get("build") or self.info.get("build", "")
        self.groups: dict[str, dict] = {}
        self.sequence: list[str] = []
        self.rules: dict[str, Rule] = {}
        self._load(pack["scripts"], self.info.get("groups") or [])

    def _load(self, scripts: list[dict], groups: list[dict]):
        for g in groups:
            gid = g["id"]
            if gid in self.groups:
                raise ValueError(f"script group 表重复: {gid}")
            self.groups[gid] = g
        self.sequence = [g["id"] for g in sorted(groups, key=lambda x: x.get("order", 999))]

        for s in scripts:
            r = Rule.from_dict(s)
            if r.uuid in self.rules:
                raise ValueError(f"script info 表 UUID 重复: {r.uuid}")
            if r.group not in self.groups:
                raise ValueError(f"脚本 {r.uuid} 引用了未定义的组 {r.group}")
            if not r.check.get("api"):
                raise ValueError(f"脚本 {r.uuid} 缺少 check.api")
            if r.check["api"] not in api.CHECKS:
                raise ValueError(f"脚本 {r.uuid} 的 check.api 未注册: {r.check['api']}")
            if r.fix and r.fix.get("api") not in api.FIXES:
                raise ValueError(f"脚本 {r.uuid} 的 fix.api 未注册: {r.fix.get('api')}")
            if r.verify and r.verify.get("api") not in api.CHECKS:
                raise ValueError(f"脚本 {r.uuid} 的 verify.api 未注册")
            self.rules[r.uuid] = r

    def group_of(self, gid: str) -> dict:
        return self.groups.get(gid, {"id": gid, "title": gid, "desc": ""})


class Engine:
    def __init__(self, cfg: ConfigManager, dry_run: bool = True, verbose: bool = False,
                 include_optional: bool = False):
        self.cfg = cfg
        self.dry_run = dry_run
        self.verbose = verbose
        self.telemetry: list[str] = []
        self.passes: list[dict] = []
        self._is_admin = w.is_admin()
        self.include_optional = include_optional

    # ------------------------------------------------------------ 全局脚本
    def run_global(self) -> dict:
        """对应 ScanManage RunGlobalScript：环境自检，决定本次扫描的能力边界。"""
        t0 = time.perf_counter()
        env = {
            "admin": self._is_admin,
            "os": w.system_root(),
            "cpu": w.os.cpu_count(),
            "uptime_h": round(w.uptime_seconds() / 3600, 1),
            "build": self.cfg.build,
            "rules": len(self.cfg.rules),
            "groups": len(self.cfg.groups),
        }
        warn = []
        if not self._is_admin:
            warn.append("非管理员运行：服务/注册表写入类修复会失败，建议以管理员身份重跑")
        self.telemetry.append(
            f"scriptapi=run_global&apiret=0&param1=admin:{int(self._is_admin)}"
            f"&param2=rules:{len(self.cfg.rules)}"
        )
        env["warnings"] = warn
        env["elapsed_ms"] = int((time.perf_counter() - t0) * 1000)
        return env

    # ------------------------------------------------------------ 单条脚本
    def run_rule(self, rule: Rule) -> Finding | None:
        spec = rule.check
        t0 = time.perf_counter()
        try:
            res = api.CHECKS[spec["api"]](spec.get("args") or {})
        except Exception as exc:  # noqa: BLE001
            res = {"ok": False, "detail": f"检测未完成: {exc.__class__.__name__}: {exc}",
                   "data": {}, "status": "unavailable"}
        el = int((time.perf_counter() - t0) * 1000)
        self.telemetry.append(
            f"scriptapi={spec['api']}&apiret={0 if res.get('ok') else 1}"
            f"&param1={rule.uuid}"
        )
        if res.get("ok"):
            d = res.get("data") or {}
            self.passes.append({
                "uuid": rule.uuid, "group": rule.group,
                "title": d.get("title") or rule.title,
                "detail": res.get("detail", ""), "severity": rule.severity,
                # skip=True 表示「本机不适用」，界面不计入检查项也不展示为通过
                "skip": bool(d.get("skip")),
                "data": d,
            })
            return None
        d = res.get("data") or {}
        sev = d.get("severity") or rule.severity
        if rule.optional:
            sev = "info"
        return Finding(rule=rule, detail=res.get("detail", ""),
                       data=d, elapsed_ms=el, severity=sev,
                       title=d.get("title") or "", status=res.get("status", "issue"))

    # ------------------------------------------------------------ 扫描
    def run_scan(self, groups: list[str] | None = None,
                 uuids: list[str] | None = None,
                 on_group=None) -> dict:
        t0 = time.perf_counter()
        self.passes = []
        order = groups if groups else self.cfg.sequence
        if groups and any(g not in self.cfg.groups for g in groups):
            raise ValueError("未知检测分组")
        if uuids:
            resolved = []
            for u in uuids:
                matches = [key for key in self.cfg.rules if key.startswith(u)]
                if len(matches) != 1:
                    raise ValueError(f"规则前缀不存在或不唯一: {u}")
                resolved.append(matches[0])
            uuids = resolved
        if uuids:
            order = [g for g in order
                     if any(self.cfg.rules[u].group == g for u in uuids)]
        findings: list[Finding] = []
        scanned = 0
        by_group: dict[str, dict] = {}
        for gid in order:
            g = self.cfg.group_of(gid)
            stat = {"id": gid, "title": g.get("title", gid), "scanned": 0,
                    "found": 0, "elapsed_ms": 0}
            gt0 = time.perf_counter()
            for rule in self.cfg.rules.values():
                if rule.group != gid:
                    continue
                if uuids and rule.uuid not in uuids:
                    continue
                scanned += 1
                stat["scanned"] += 1
                f = self.run_rule(rule)
                if f:
                    findings.append(f)
                    stat["found"] += 1
            stat["elapsed_ms"] = int((time.perf_counter() - gt0) * 1000)
            by_group[gid] = stat
            if on_group:
                # 界面要按分组推进度，所以每跑完一组就回调一次
                on_group(stat)
        gorder = {g: i for i, g in enumerate(self.cfg.sequence)}
        findings.sort(key=lambda f: (gorder.get(f.rule.group, 999),
                                     SEVERITY_ORDER.get(f.sev, 9)))
        return {
            "scanned": scanned,
            "findings": findings,
            "passed": self.passes,
            "groups": by_group,
            "elapsed_ms": int((time.perf_counter() - t0) * 1000),
        }

    # ------------------------------------------------------------ 修复
    def run_fix(self, findings: list[Finding]) -> list[Finding]:
        for f in findings:
            rule = f.rule
            f.fix_ok = None
            f.fix_status = "not_run"
            if f.status != "issue":
                f.fix_message = "检测未完成，不能据此执行修复"
                continue
            if (rule.optional or f.sev == "info" or f.data.get("optional")) and not self.include_optional:
                f.fix_message = "可选建议，需逐项选择后执行"
                continue
            if not rule.fix:
                f.fix_ok = None
                f.fix_message = "该检测项无自动修复动作，需手动处理"
                continue
            if self.dry_run:
                f.fix_ok = None
                f.fix_status = "planned"
                f.fix_message = f"[计划] 将执行 {rule.fix['api']}({rule.fix.get('args') or {}})"
                continue
            if rule.needs_admin and not self._is_admin:
                f.fix_ok = False
                f.fix_status = "failed"
                f.fix_message = "需要管理员权限"
                continue
            spec = rule.fix
            record = None
            active = None
            try:
                record = journal.Journal(rule.uuid, rule.title)
                f.journal_id = record.id
                active = journal.ACTIVE.set(record)
                good, msg = api.FIXES[spec["api"]](spec.get("args") or {})
            except Exception as exc:  # noqa: BLE001
                good, msg = False, f"修复异常: {exc.__class__.__name__}: {exc}"
            finally:
                if active is not None:
                    journal.ACTIVE.reset(active)
            f.fix_ok = bool(good)
            f.fix_status = "failed" if not good else "unverified"
            f.fix_message = msg
            if good and not rule.verify:
                f.fix_ok = False
                f.fix_message += "（缺少复检，尚未验证）"
            self.telemetry.append(
                f"scriptapi={spec['api']}&apiret={0 if good else 1}&param1={rule.uuid}"
            )
            if good and rule.verify:
                try:
                    v = api.CHECKS[rule.verify["api"]](rule.verify.get("args") or {})
                    f.verify_detail = v.get("detail", "")
                    if not v.get("ok"):
                        f.fix_ok = False
                        f.fix_message += "（修复后复检未通过）"
                        f.fix_status = "failed"
                    elif (v.get("data") or {}).get("skip"):
                        f.fix_ok = False
                        f.fix_status = "unverified"
                        f.fix_message += "（复检不适用，尚未验证）"
                    else:
                        f.fix_status = "verified"
                except Exception as exc:  # noqa: BLE001
                    f.fix_ok = False
                    f.fix_status = "unverified"
                    f.verify_detail = f"复检异常: {exc}"
            if good and rule.needs_reboot:
                f.fix_ok = False
                f.fix_status = "pending_reboot"
                f.fix_message += "（需重启后重新检测，尚未确认修复）"
            if record:
                try:
                    record.finish(f.fix_status, f.fix_message)
                except Exception as exc:
                    f.fix_ok = False
                    f.fix_status = "unverified"
                    f.fix_message += f"（操作记录未能完成: {exc}）"
        return findings


def load(path: str) -> ConfigManager:
    p = packmod.read_pack(path)
    return ConfigManager(p)


def new_uuid() -> str:
    return str(uuidlib.uuid4())
