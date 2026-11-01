"""端到端自测：在临时沙箱里验证 扫描 -> 修复 -> 复检 的闭环。

不触碰真实系统：规则只操作临时目录内的文件，用于证明引擎三张表校验、
RunOneScriptByUuid、fix/verify 与容器读写都能跑通。

    python -m ksr.selftest
"""

from __future__ import annotations

import os
import shutil
import sys
import tempfile
import uuid as uuidlib

from . import engine, pack as packmod


def _mk(sandbox: str) -> dict:
    src = os.path.join(sandbox, "payload")
    dst = os.path.join(sandbox, "target")
    os.makedirs(src, exist_ok=True)
    os.makedirs(dst, exist_ok=True)
    with open(os.path.join(src, "marker.dll"), "wb") as f:
        f.write(b"MZ" + b"\0" * 62)
    uid = str(uuidlib.uuid4())
    return {
        "schema": "ksr.rulepack/1",
        "groups": [{"id": "t", "order": 1, "title": "沙箱测试组", "desc": "selftest"}],
        "scripts": [{
            "uuid": uid,
            "group": "t",
            "title": "沙箱文件缺失",
            "severity": "error",
            "impact": "自测用",
            "check": {"api": "files.present",
                      "args": {"dir": dst, "names": ["marker.dll"]}},
            "fix": {"api": "files.restore",
                    "args": {"src_dir": src, "dst_dir": dst, "names": ["marker.dll"]}},
        }],
    }


def main() -> int:
    sandbox = tempfile.mkdtemp(prefix="ksr_selftest_")
    ok = True
    try:
        p = _mk(sandbox)
        # 1) 容器往返
        kpath = os.path.join(sandbox, "pack.ksrp")
        info = packmod.write_pack(kpath, p, build="20261101120000")
        back = packmod.read_pack(kpath)
        assert back["scripts"][0]["uuid"] == p["scripts"][0]["uuid"]
        print(f"[1] 容器往返     OK  {info['bytes']} 字节，CRC {back['crc']:#010x}")

        # 2) 配置表校验
        cfg = engine.ConfigManager(back)
        assert len(cfg.rules) == 1 and cfg.sequence == ["t"]
        print(f"[2] 三表校验     OK  scripts={len(cfg.rules)} groups={len(cfg.groups)}")

        # 3) 扫描应检出
        eng = engine.Engine(cfg, dry_run=False)
        s1 = eng.run_scan()
        assert len(s1["findings"]) == 1, s1
        print(f"[3] 扫描检出     OK  {s1['findings'][0].detail}")

        # 4) 修复并复检
        eng.run_fix(s1["findings"])
        f = s1["findings"][0]
        assert f.fix_ok, f.fix_message
        assert os.path.isfile(os.path.join(sandbox, "target", "marker.dll"))
        print(f"[4] 修复+复检    OK  {f.fix_message} / {f.verify_detail}")

        # 5) 再扫应为 0
        s2 = engine.Engine(cfg, dry_run=True).run_scan()
        assert not s2["findings"], s2["findings"]
        print(f"[5] 复查清零     OK  {s2['scanned']} 条脚本全部通过")

        # 6) 遥测格式对齐原程序
        tel = [t for t in eng.telemetry if t.startswith("scriptapi=")]
        assert tel and "apiret=0" in tel[-1]
        print(f"[6] 遥测格式     OK  {tel[-1]}")
    except AssertionError as exc:
        ok = False
        print(f"FAIL: {exc}")
    finally:
        shutil.rmtree(sandbox, ignore_errors=True)
    print("\nSELFTEST", "PASS" if ok else "FAIL")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
