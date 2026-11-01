"""Official-package transport and Windows Authenticode publisher verification."""
from __future__ import annotations
import hashlib
import json
import os
from pathlib import Path
import subprocess
import urllib.parse
import urllib.request

HOSTS = {"aka.ms", "download.microsoft.com", "download.visualstudio.microsoft.com",
         "builds.dotnet.microsoft.com", "dotnetcli.blob.core.windows.net",
         "openal.org", "us.download.nvidia.com"}


def allowed_url(url):
    parsed = urllib.parse.urlsplit(url)
    return (parsed.scheme == "https" and parsed.hostname in HOSTS
            and not parsed.username and not parsed.password and parsed.port in (None, 443))


class OfficialRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, msg, headers, newurl):
        if not allowed_url(newurl):
            raise ValueError("安装包重定向不在官方 HTTPS 来源列表中")
        return super().redirect_request(request, fp, code, msg, headers, newurl)


def download(url, destination, timeout=300, expected_sha256=None, expected_sha512=None):
    target = Path(destination)
    part = target.with_name(target.name + ".part")
    try:
        if not allowed_url(url):
            raise ValueError("只接受配置中的官方 HTTPS 来源")
        digest = hashlib.sha256()
        sha512 = hashlib.sha512()
        size = 0
        opener = urllib.request.build_opener(OfficialRedirect())
        with opener.open(urllib.request.Request(url, headers={"User-Agent": "KSR/1.1"}), timeout=timeout) as response:
            if not allowed_url(response.geturl()):
                raise ValueError("最终下载来源不受信任")
            with part.open("xb") as stream:
                while chunk := response.read(1024 * 1024):
                    size += len(chunk)
                    if size > 256 * 1024 * 1024:
                        raise ValueError("安装包超过大小上限")
                    digest.update(chunk); sha512.update(chunk); stream.write(chunk)
                stream.flush(); os.fsync(stream.fileno())
        if size < 65536:
            raise ValueError("下载内容不是完整安装包")
        if expected_sha256 and digest.hexdigest().lower() != expected_sha256.lower():
            raise ValueError("安装包 SHA-256 不匹配")
        if expected_sha512 and sha512.hexdigest().lower() != expected_sha512.lower():
            raise ValueError("安装包 SHA-512 不匹配")
        os.replace(part, target)
        return True, f"下载 {size} 字节；SHA-256 {digest.hexdigest()}"
    except Exception as exc:
        part.unlink(missing_ok=True)
        return False, f"下载失败: {exc}"


def verify_microsoft(path):
    return verify_publisher(path, "Microsoft Corporation")


def verify_publisher(path, expected_publisher):
    """Use Windows' signature validation; fail closed on invalid/unknown publisher."""
    if expected_publisher not in {"Microsoft Corporation", "Creative Labs Inc", "NVIDIA Corporation"}:
        raise ValueError("发布者未列入支持清单")
    target = Path(path).resolve(strict=True)
    shell = Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32/WindowsPowerShell/v1.0/powershell.exe"
    script = ("$ErrorActionPreference='Stop'; "
              "$s=Get-AuthenticodeSignature -LiteralPath $env:KSR_VERIFY_TARGET; "
              "@{status=[string]$s.Status;subject=[string]$s.SignerCertificate.Subject} | ConvertTo-Json -Compress")
    env = os.environ.copy(); env["KSR_VERIFY_TARGET"] = str(target)
    # A parent PowerShell 7 session can export its module path to Windows PowerShell 5.1.
    # Bind the validation command to the inbox modules rather than the parent's modules.
    env["PSModulePath"] = str(shell.parent / "Modules")
    try:
        result = subprocess.run([str(shell), "-NoProfile", "-NonInteractive", "-Command", script],
                                env=env, capture_output=True, timeout=90, creationflags=0x08000000)
        if result.returncode:
            return False, "Windows 签名校验未完成"
        signature = json.loads(result.stdout.decode("utf-8-sig"))
        import re
        publisher = bool(re.search(r"(?:^|,\s*)O=" + re.escape(expected_publisher) + r"(?:,|$)", signature.get("subject", "")))
        if signature.get("status") != "Valid" or not publisher:
            return False, "安装包签名无效或发布者不符：" + expected_publisher
        return True, "Windows 签名有效；发布者 " + expected_publisher
    except Exception as exc:
        return False, f"无法验证安装包签名: {exc}"
