"""规则包容器。

原程序的规则以两个容器承载：
  * ``config3a.dat`` —— 脚本配置，头部可见布局为
      u32 header_size(0x78) | char magic[8]="ksystemr" | u32 checksum |
      char build[16]="20120917170317" | u32 pad | u32 count |
      5 × (u32 offset, u32 size, u32 count, u32 aux)  | u32 payload_size | u32 crc
    以 (offset,size) 递推可验证：0x78 + 0x0F50 = 0x0FC8，0x0FC8 + 0x228 = 0x11F0，
    0x11F0 + 0x1EF0 = 0x30E0，0x30E0 + 0x690 = 0x3770 —— 五段依次紧邻，
    每段满足 size == count × item_size（196×20、23×24、198×40、420×4），
    分别对应 ConfigManager 校验的三张表：script info / sequence / group。
  * ``sp3a.nlb`` —— 脚本池，按 UUID 取出单条脚本正文。

本模块按同一思路实现自有容器 .ksrp：同样的头部字段语义（header size、magic、
build stamp、分段表、载荷长度、校验），载荷用 zlib + 滚动异或，属自研格式，
不复用原程序私有密钥。
"""

from __future__ import annotations

import json
import struct
import zlib

MAGIC = b"KSRPK\0\0\0"
HEADER_SIZE = 0x78
SECTIONS = 5


def _roll(data: bytes, seed: int) -> bytes:
    out = bytearray(len(data))
    k = seed & 0xFF
    for i, b in enumerate(data):
        out[i] = b ^ k
        k = (k * 31 + 17) & 0xFF
    return bytes(out)


def _fill_header(entries: list[tuple[int, int, int, int]], build: str,
                 crc: int, payload_size: int, count: int) -> bytes:
    h = bytearray(HEADER_SIZE)
    struct.pack_into("<I", h, 0x00, HEADER_SIZE)
    h[0x04:0x0C] = MAGIC
    struct.pack_into("<I", h, 0x0C, crc)
    stamp = build.encode("ascii", "replace")[:15].ljust(16, b"\0")
    h[0x10:0x20] = stamp
    struct.pack_into("<I", h, 0x20, 1)
    struct.pack_into("<I", h, 0x24, count)
    for i, (off, size, cnt, aux) in enumerate(entries[:SECTIONS]):
        base = 0x28 + i * 16
        struct.pack_into("<IIII", h, base, off, size, cnt, aux)
    struct.pack_into("<I", h, 0x74, payload_size)
    return bytes(h)


def write_pack(path: str, pack: dict, build: str = "20261101000000") -> dict:
    """把规则包写成 .ksrp：info 段为明文 JSON，scripts 段为压缩载荷。"""
    info = {
        "schema": pack.get("schema"),
        "build": build,
        "groups": pack["groups"],
        "count": len(pack["scripts"]),
    }
    info_b = json.dumps(info, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    body_b = json.dumps(pack["scripts"], ensure_ascii=False,
                        separators=(",", ":")).encode("utf-8")
    body_z = zlib.compress(body_b, 9)
    crc = zlib.crc32(body_b) & 0xFFFFFFFF
    body_e = _roll(body_z, crc)

    off1 = HEADER_SIZE
    off2 = off1 + len(info_b)
    entries = [
        (off1, len(info_b), len(info["groups"]), 0),
        (off2, len(body_e), len(pack["scripts"]), crc),
        (0, 0, 0, 0), (0, 0, 0, 0), (0, 0, 0, 0),
    ]
    payload = info_b + body_e
    header = _fill_header(entries, build, crc, len(payload), len(pack["scripts"]))
    with open(path, "wb") as f:
        f.write(header)
        f.write(payload)
    return {
        "path": path,
        "bytes": len(header) + len(payload),
        "scripts": len(pack["scripts"]),
        "groups": len(info["groups"]),
        "raw_body": len(body_b),
        "packed_body": len(body_e),
    }


def read_pack(path: str) -> dict:
    with open(path, "rb") as f:
        blob = f.read()
    if len(blob) < HEADER_SIZE:
        raise ValueError("容器长度不足")
    header_size = struct.unpack_from("<I", blob, 0x00)[0]
    if blob[0x04:0x0C] != MAGIC:
        raise ValueError(f"magic 不匹配: {blob[0x04:0x0C]!r}")
    if header_size != HEADER_SIZE:
        raise ValueError(f"header_size 异常: {header_size:#x}")
    crc = struct.unpack_from("<I", blob, 0x0C)[0]
    build = blob[0x10:0x20].rstrip(b"\0").decode("ascii", "replace")
    count = struct.unpack_from("<I", blob, 0x24)[0]
    entries = []
    for i in range(SECTIONS):
        entries.append(struct.unpack_from("<IIII", blob, 0x28 + i * 16))
    payload_size = struct.unpack_from("<I", blob, 0x74)[0]
    if HEADER_SIZE + payload_size != len(blob):
        raise ValueError("载荷长度与文件大小不一致")

    off1, size1, cnt1, _ = entries[0]
    off2, size2, cnt2, _ = entries[1]
    info = json.loads(blob[off1:off1 + size1].decode("utf-8"))
    body_e = blob[off2:off2 + size2]
    body_b = zlib.decompress(_roll(body_e, crc))
    if zlib.crc32(body_b) & 0xFFFFFFFF != crc:
        raise ValueError("载荷 CRC 校验失败")
    scripts = json.loads(body_b.decode("utf-8"))
    if len(scripts) != cnt2:
        raise ValueError("脚本条数与段头不一致")
    return {"info": info, "scripts": scripts, "build": build,
            "crc": crc, "sections": entries}
