#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""ZeroAI Agent Client：讓 ZeroAI 在你自己的電腦上做事。

    python zeroai_agent.py pair <配對碼> --server <網址>   用 Discord /agent bind 拿到的碼綁定
    python zeroai_agent.py serve                           保持在線，接 Discord /agent run 的任務
    python zeroai_agent.py run "整理下載資料夾"             直接在這台電腦上跑一個任務
    python zeroai_agent.py status                          額度、可用模型、綁定狀態
    python zeroai_agent.py config show | set <鍵> <值>
    python zeroai_agent.py unpair                          解除綁定並刪除本機金鑰

運作方式：Agent 迴圈在你的電腦上跑——每一步把對話與工具定義送到 ZeroAI，ZeroAI 代為呼叫模型、
依 token 用量扣你的額度後回傳；模型要用工具（跑指令、讀寫檔案……）時在這台電腦上執行。
模型的 API 金鑰永遠在 ZeroAI 那邊，這台電腦只存一把可以隨時在 Discord 撤銷的裝置金鑰。

安全（設計參考 Nous Research 的 Hermes Agent）：
  * 絕對禁止清單：格式化磁碟、刪整個系統或家目錄、fork bomb、讀取本程式的設定檔等，任何模式都擋。
  * 危險操作要核准：刪檔、安裝套件、下載後執行、改系統設定、強制推送……；遠端任務會在 Discord
    跳出按鈕，本機任務在終端機問你。5 分鐘沒回應視為拒絕。
  * 工作區：預設只在工作區（~/ZeroAI-Agent）裡自由讀寫，工作區以外的讀寫都要核准。
  * remote_tasks 設成 false 就完全不接受 Discord 下的任務。

需要 Python 3.10 以上與 aiohttp（pip install aiohttp）。

Copyright (c) 2026 一個團隊網路科技工作室 (anTeam Network Studio). All rights reserved.
依 ZeroAI Agent Client 使用授權條款（同資料夾的 LICENSE）提供：只能連 ZeroAI 官方服務、不得商業使用、
修改版不得分享。使用 ZeroAI 服務另依 https://zeroai.my/terms/ 。
"""

from __future__ import annotations

import argparse
import asyncio
import fnmatch
import ipaddress
import json
import os
import platform
import re
import secrets
import socket
import sys
import time
from datetime import datetime
from pathlib import Path
from urllib.parse import urlparse

try:
    import aiohttp
except ImportError:            # pragma: no cover
    print("需要 aiohttp：pip install aiohttp")
    raise SystemExit(1)

VERSION = "1.0.0"
HOME = Path(os.environ.get("ZEROAI_AGENT_HOME") or (Path.home() / ".zeroai-agent"))
CONFIG_FILE = HOME / "config.json"
MEMORY_FILE = HOME / "memory.md"
SKILLS_DIR = HOME / "skills"
DEFAULTS = {
    "server": "",
    "token": "",
    "device_id": "",
    "name": socket.gethostname()[:40],
    "workspace": str(Path.home() / "ZeroAI-Agent"),
    "allowed_dirs": [],          # 工作區以外也可以自由讀寫的資料夾
    "remote_tasks": True,        # false＝不接受 Discord 下的任務
    "approval": "manual",        # manual：危險操作要核准；off：不問（絕對禁止清單照樣擋）
    "model": "",                 # 本機任務用的模型，空白＝伺服器預設
    "max_steps": 40,
    "command_timeout": 120,
}
MAX_TOOL_OUTPUT = 12_000         # 單次工具輸出最多送回模型的字元數
COMPACT_AT = 300_000             # 對話總字元超過這個數就省略較早的工具輸出（省額度）
APPROVAL_TIMEOUT = 300

if sys.stdout and hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass


# ───────────────────────── 設定 ─────────────────────────

def load_config() -> dict:
    cfg = dict(DEFAULTS)
    if CONFIG_FILE.exists():
        try:
            cfg.update(json.loads(CONFIG_FILE.read_text(encoding="utf-8")))
        except ValueError:
            print(f"⚠️ 設定檔格式錯誤：{CONFIG_FILE}")
    return cfg


def save_config(cfg: dict) -> None:
    HOME.mkdir(parents=True, exist_ok=True)
    CONFIG_FILE.write_text(json.dumps(cfg, ensure_ascii=False, indent=2), encoding="utf-8")
    try:
        os.chmod(CONFIG_FILE, 0o600)           # 只有自己讀得到（Windows 上沒有作用）
    except OSError:
        pass


# ───────────────────────── 安全規則 ─────────────────────────
# 不分大小寫的 regex。HARDLINE 任何模式都擋；DANGEROUS 要核准。

HARDLINE = [
    (r"\brm\s+(-[a-z]*\s+)*-[a-z]*r[a-z]*\s+(-[a-z]*\s+)*(/|/\*|~|~/|\$HOME)\s*($|[;&|])", "刪除整個根目錄或家目錄"),
    (r":\(\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;\s*:", "fork bomb"),
    (r"\bmkfs(\.\w+)?\s+/dev/", "格式化磁碟"),
    (r"\bdd\b[^\n]*\bof=/dev/(sd|nvme|hd|disk)", "直接寫入磁碟裝置"),
    (r"\bformat(\.com)?\s+[a-z]:", "格式化磁碟"),
    (r"\bdiskpart\b", "磁碟分割工具"),
    (r"\b(del|erase)\s+[^\n]*/s[^\n]*\b[a-z]:\\\s*($|\*|[;&|])", "刪除整個磁碟"),
    (r"\b(rd|rmdir)\s+[^\n]*/s[^\n]*\b[a-z]:\\\s*($|[;&|])", "刪除整個磁碟"),
    (r"remove-item\b[^\n]*-recurse[^\n]*\b[a-z]:\\\s*($|\*|[;&|])", "刪除整個磁碟"),
    (r"\.zeroai-agent", "讀取或修改 ZeroAI Agent 自己的設定與金鑰"),
    (r"\bvssadmin\s+delete\b|\bwbadmin\s+delete\b|\bbcdedit\b", "刪除系統還原點或開機設定"),
]
DANGEROUS = [
    (r"\brm\s+(-[a-z]*\s+)*-[a-z]*[rf]", "刪除檔案或資料夾（rm -r／-f）"),
    (r"\b(del|erase)\b|\b(rd|rmdir)\s", "刪除檔案或資料夾"),
    (r"remove-item\b", "刪除檔案或資料夾"),
    (r"\bshred\b|\btruncate\s+-s", "抹除檔案內容"),
    (r"\b(sudo|su|doas|runas)\b", "以系統管理員權限執行"),
    (r"\bchmod\s+(-r\s+)?(777|-r)|\bchown\s+-r|\bicacls\b|\btakeown\b", "大範圍修改檔案權限"),
    (r"\b(shutdown|reboot|halt|poweroff)\b|stop-computer|restart-computer", "關機或重新開機"),
    (r"\b(kill\s+-9|killall|pkill|taskkill)\b|stop-process", "強制結束程式"),
    (r"\bsystemctl\s+(stop|disable|mask|restart)|\bservice\s+\S+\s+stop|\bsc\s+(stop|delete|config)\b", "停止或修改系統服務"),
    (r"\breg\s+(add|delete|import)\b|set-itemproperty\s+-path\s+hk|new-itemproperty", "修改登錄檔"),
    (r"set-executionpolicy|\bnetsh\b|\bnet\s+(user|localgroup|share)\b|\bschtasks\b|\bcrontab\b", "修改系統設定、帳號或排程"),
    (r"\b(pip3?|python3?\s+-m\s+pip)\s+(install|uninstall)\b", "安裝或移除 Python 套件"),
    (r"\b(npm|pnpm|yarn)\s+(install|add|i|uninstall|remove)\b[^\n]*(-g\b|--global)", "全域安裝 Node 套件"),
    (r"\b(apt|apt-get|yum|dnf|pacman|zypper|brew|choco|winget|scoop|snap)\s+(install|remove|purge|uninstall|-s)", "安裝或移除系統軟體"),
    (r"\b(curl|wget|iwr|invoke-webrequest|irm|invoke-restmethod)\b[^\n]*\|\s*(sh|bash|zsh|python3?|iex|invoke-expression)",
     "下載並直接執行網路上的程式"),
    (r"invoke-expression|\biex\b|-encodedcommand|\s-enc\s|certutil\s+-urlcache|bitsadmin", "執行動態或下載的程式碼"),
    (r"\bgit\s+push\b[^\n]*(--force|-f\b)|\bgit\s+reset\s+--hard|\bgit\s+clean\s+-[a-z]*f", "會丟失資料的 git 操作"),
    (r"\b(drop|truncate)\s+(table|database|schema)\b|\bdelete\s+from\s+\w+\s*(;|$)", "刪除資料庫資料"),
    (r">\s*/dev/(sd|nvme|hd)|\bmv\s+[^\n]*\s/dev/null", "覆寫裝置或丟棄檔案"),
    (r"\bdocker\s+(rm|rmi|stop|kill|system\s+prune|volume\s+rm)\b", "刪除或停止 Docker 容器與資料"),
    (r"\bssh\b|\bscp\b|\brsync\b[^\n]*:", "連線到其他主機"),
]


def check_command(cmd: str):
    """(等級, 原因)：等級是 deny／ask／ok。"""
    text = cmd or ""
    for pat, why in HARDLINE:
        if re.search(pat, text, re.IGNORECASE):
            return "deny", why
    for pat, why in DANGEROUS:
        if re.search(pat, text, re.IGNORECASE):
            return "ask", why
    return "ok", ""


def _resolve(path: str, base: Path) -> Path:
    p = Path(os.path.expandvars(os.path.expanduser(str(path or "."))))
    if not p.is_absolute():
        p = base / p
    return p.resolve()


def _inside(p: Path, root: Path) -> bool:
    try:
        p.relative_to(root.resolve())
        return True
    except ValueError:
        return False


def _private_host(url: str) -> bool:
    host = urlparse(url).hostname or ""
    if host in ("localhost",) or host.endswith(".local"):
        return True
    try:
        infos = socket.getaddrinfo(host, None)
    except OSError:
        return False
    for info in infos:
        try:
            ip = ipaddress.ip_address(info[4][0])
        except ValueError:
            continue
        if ip.is_private or ip.is_loopback or ip.is_link_local:
            return True
    return False


# ───────────────────────── 工具 ─────────────────────────

TOOLS = [
    {"type": "function", "function": {
        "name": "terminal",
        "description": "在這台電腦的 shell 執行一行指令（Windows 是 cmd，其他系統是 sh），回傳輸出與結束碼。"
                       "危險的指令（刪檔、安裝、改系統設定…）會先請使用者核准。",
        "parameters": {"type": "object", "properties": {
            "command": {"type": "string", "description": "要執行的指令"},
            "cwd": {"type": "string", "description": "工作目錄，預設是工作區"},
            "timeout": {"type": "integer", "description": "秒數上限，預設 120、最多 600"}},
            "required": ["command"]}}},
    {"type": "function", "function": {
        "name": "read_file",
        "description": "讀文字檔。工作區以外的檔案要使用者核准。",
        "parameters": {"type": "object", "properties": {
            "path": {"type": "string"},
            "offset": {"type": "integer", "description": "從第幾行開始（1 起算）"},
            "limit": {"type": "integer", "description": "最多幾行，預設 400"}}, "required": ["path"]}}},
    {"type": "function", "function": {
        "name": "write_file",
        "description": "寫入文字檔（會建立資料夾）。工作區以外要使用者核准。",
        "parameters": {"type": "object", "properties": {
            "path": {"type": "string"}, "content": {"type": "string"},
            "append": {"type": "boolean", "description": "接在檔尾而不是覆寫"}}, "required": ["path", "content"]}}},
    {"type": "function", "function": {
        "name": "list_dir",
        "description": "列出資料夾內容（名稱、大小、是否為資料夾）。",
        "parameters": {"type": "object", "properties": {"path": {"type": "string"}}, "required": []}}},
    {"type": "function", "function": {
        "name": "search_files",
        "description": "在資料夾裡用 regex 搜尋文字檔內容，回傳檔名、行號與那一行。",
        "parameters": {"type": "object", "properties": {
            "pattern": {"type": "string"}, "path": {"type": "string"},
            "glob": {"type": "string", "description": "只搜這種檔名，例如 *.py"}}, "required": ["pattern"]}}},
    {"type": "function", "function": {
        "name": "fetch_url",
        "description": "用 HTTP GET 讀一個網頁或 API，回傳文字（HTML 會去掉標籤）。",
        "parameters": {"type": "object", "properties": {"url": {"type": "string"}}, "required": ["url"]}}},
    {"type": "function", "function": {
        "name": "memory",
        "description": "長期記憶（跨任務保留）：read 讀出、append 加一條、replace 整份改寫。"
                       "記使用者的偏好、這台電腦的環境、常用路徑等以後用得到的事。",
        "parameters": {"type": "object", "properties": {
            "action": {"type": "string", "enum": ["read", "append", "replace"]},
            "text": {"type": "string"}}, "required": ["action"]}}},
    {"type": "function", "function": {
        "name": "read_skill",
        "description": "讀一份技能說明（系統提示列出的技能名稱），照裡面的步驟做事。",
        "parameters": {"type": "object", "properties": {"name": {"type": "string"}}, "required": ["name"]}}},
]


def list_skills() -> list:
    """~/.zeroai-agent/skills/<名稱>/SKILL.md（與 agentskills.io 相同的資料夾格式）：[(名稱, 說明)]。"""
    out = []
    if not SKILLS_DIR.is_dir():
        return out
    for d in sorted(SKILLS_DIR.iterdir()):
        f = d / "SKILL.md"
        if not f.is_file():
            continue
        desc = ""
        text = f.read_text(encoding="utf-8", errors="replace")[:2000]
        m = re.search(r"^description:\s*(.+)$", text, re.MULTILINE)
        if m:
            desc = m.group(1).strip().strip('"')
        out.append((d.name, desc[:200]))
    return out[:50]


class Tools:
    def __init__(self, cfg: dict, approve, redact):
        self.cfg = cfg
        self.workspace = Path(cfg["workspace"]).expanduser().resolve()
        self.workspace.mkdir(parents=True, exist_ok=True)
        self.allowed = [self.workspace] + [Path(d).expanduser().resolve() for d in cfg.get("allowed_dirs") or []]
        self.approve = approve            # async (action, detail, reason) -> bool
        self.redact = redact

    def _free(self, p: Path) -> bool:
        return any(_inside(p, root) for root in self.allowed)

    async def _guard_path(self, p: Path, action: str) -> str:
        """回傳拒絕原因；可以繼續回傳空字串。"""
        if _inside(p, HOME):
            return "不能存取 ZeroAI Agent 自己的設定與金鑰。"
        if self._free(p):
            return ""
        if self.cfg.get("approval") == "off":
            return ""
        ok = await self.approve(action, str(p), f"{action}的位置在工作區（{self.workspace}）以外")
        return "" if ok else "使用者沒有核准這個操作。"

    async def run(self, name: str, args: dict) -> str:
        fn = getattr(self, "t_" + name, None)
        if fn is None:
            return f"沒有這個工具：{name}"
        try:
            out = await fn(**{k: v for k, v in (args or {}).items() if k in fn.__code__.co_varnames})
        except TypeError as e:
            return f"參數錯誤：{e}"
        except Exception as e:
            return f"工具執行失敗：{type(e).__name__}: {e}"
        out = self.redact(str(out))
        if len(out) > MAX_TOOL_OUTPUT:
            out = out[:MAX_TOOL_OUTPUT // 2] + f"\n…（中間省略 {len(out) - MAX_TOOL_OUTPUT} 字）…\n" + out[-MAX_TOOL_OUTPUT // 2:]
        return out

    async def t_terminal(self, command: str, cwd: str = "", timeout: int = 0) -> str:
        level, why = check_command(command)
        if level == "deny":
            return f"已拒絕：這個指令在絕對禁止清單上（{why}）。"
        if level == "ask" and self.cfg.get("approval") != "off":
            if not await self.approve("執行指令", command, why):
                return "使用者沒有核准這個指令。"
        workdir = _resolve(cwd, self.workspace) if cwd else self.workspace
        if cwd:
            reason = await self._guard_path(workdir, "在這個資料夾執行指令")
            if reason:
                return reason
        limit = max(1, min(int(timeout or self.cfg.get("command_timeout") or 120), 600))
        proc = await asyncio.create_subprocess_shell(
            command, cwd=str(workdir), stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT,
            stdin=asyncio.subprocess.DEVNULL)
        try:
            out, _ = await asyncio.wait_for(proc.communicate(), timeout=limit)
        except asyncio.TimeoutError:
            proc.kill()
            return f"逾時（{limit} 秒），已結束這個指令。"
        text = out.decode("utf-8", errors="replace") if out else ""
        if "�" in text and os.name == "nt":       # Windows 主控台常是系統碼頁
            text = out.decode("mbcs", errors="replace")
        return f"結束碼：{proc.returncode}\n{text}"

    async def t_read_file(self, path: str, offset: int = 1, limit: int = 400) -> str:
        p = _resolve(path, self.workspace)
        reason = await self._guard_path(p, "讀取檔案")
        if reason:
            return reason
        if not p.is_file():
            return f"找不到檔案：{p}"
        if p.stat().st_size > 20 * 1024 * 1024:
            return "檔案超過 20 MB，請用 terminal 搭配 head／findstr 之類的指令讀需要的部分。"
        lines = p.read_text(encoding="utf-8", errors="replace").splitlines()
        start = max(1, int(offset or 1))
        chunk = lines[start - 1:start - 1 + max(1, min(int(limit or 400), 2000))]
        body = "\n".join(f"{i}\t{line}" for i, line in enumerate(chunk, start))
        return f"{p}（共 {len(lines)} 行）\n{body}"

    async def t_write_file(self, path: str, content: str, append: bool = False) -> str:
        p = _resolve(path, self.workspace)
        reason = await self._guard_path(p, "寫入檔案")
        if reason:
            return reason
        p.parent.mkdir(parents=True, exist_ok=True)
        with open(p, "a" if append else "w", encoding="utf-8", newline="") as f:
            f.write(content)
        return f"已{'附加' if append else '寫入'} {p}（{len(content)} 字）"

    async def t_list_dir(self, path: str = "") -> str:
        p = _resolve(path or ".", self.workspace)
        reason = await self._guard_path(p, "列出資料夾")
        if reason:
            return reason
        if not p.is_dir():
            return f"不是資料夾：{p}"
        rows = []
        for child in sorted(p.iterdir(), key=lambda c: (not c.is_dir(), c.name.lower()))[:500]:
            try:
                size = "" if child.is_dir() else f"{child.stat().st_size:,} B"
            except OSError:
                size = "?"
            rows.append(f"{'📁' if child.is_dir() else '📄'} {child.name}  {size}")
        return f"{p}\n" + ("\n".join(rows) or "（空的）")

    async def t_search_files(self, pattern: str, path: str = "", glob: str = "") -> str:
        p = _resolve(path or ".", self.workspace)
        reason = await self._guard_path(p, "搜尋資料夾")
        if reason:
            return reason
        try:
            rx = re.compile(pattern, re.IGNORECASE)
        except re.error as e:
            return f"regex 錯誤：{e}"
        hits, scanned = [], 0
        for root, dirs, files in os.walk(p):
            dirs[:] = [d for d in dirs if d not in (".git", "node_modules", "__pycache__", ".venv", "venv")]
            for name in files:
                if glob and not fnmatch.fnmatch(name, glob):
                    continue
                fp = Path(root) / name
                scanned += 1
                if scanned > 5000 or len(hits) >= 100:
                    break
                try:
                    if fp.stat().st_size > 2 * 1024 * 1024:
                        continue
                    with open(fp, encoding="utf-8", errors="ignore") as f:
                        for no, line in enumerate(f, 1):
                            if rx.search(line):
                                hits.append(f"{fp}:{no}: {line.strip()[:200]}")
                                if len(hits) >= 100:
                                    break
                except OSError:
                    continue
        return "\n".join(hits) or "沒有符合的結果。"

    async def t_fetch_url(self, url: str) -> str:
        if not re.match(r"^https?://", url or "", re.IGNORECASE):
            return "只支援 http／https 網址。"
        if _private_host(url) and self.cfg.get("approval") != "off":
            if not await self.approve("讀取內部網路", url, "這個網址指向本機或區域網路"):
                return "使用者沒有核准這個操作。"
        timeout = aiohttp.ClientTimeout(total=30)
        async with aiohttp.ClientSession(timeout=timeout) as s:
            async with s.get(url, headers={"User-Agent": f"ZeroAI-Agent/{VERSION}"}) as r:
                raw = await r.content.read(400_000)
                text = raw.decode(r.charset or "utf-8", errors="replace")
                if "html" in (r.content_type or ""):
                    text = re.sub(r"(?is)<(script|style).*?</\1>", " ", text)
                    text = re.sub(r"(?s)<[^>]+>", " ", text)
                    text = re.sub(r"[ \t]+", " ", re.sub(r"\n\s*\n+", "\n", text))
                return f"HTTP {r.status}\n{text.strip()}"

    async def t_memory(self, action: str, text: str = "") -> str:
        HOME.mkdir(parents=True, exist_ok=True)
        if action == "read":
            return MEMORY_FILE.read_text(encoding="utf-8") if MEMORY_FILE.exists() else "（還沒有記憶）"
        if action == "append":
            with open(MEMORY_FILE, "a", encoding="utf-8") as f:
                f.write(f"- {text.strip()}\n")
            return "已記下。"
        if action == "replace":
            MEMORY_FILE.write_text(text, encoding="utf-8")
            return "已改寫記憶。"
        return "action 要是 read、append 或 replace。"

    async def t_read_skill(self, name: str) -> str:
        safe = re.sub(r"[^\w.-]", "", name or "")
        f = SKILLS_DIR / safe / "SKILL.md"
        return f.read_text(encoding="utf-8", errors="replace")[:20000] if f.is_file() else f"找不到技能：{name}"


# ───────────────────────── Agent 迴圈 ─────────────────────────

class ServerError(Exception):
    pass


class Api:
    def __init__(self, cfg: dict):
        self.base = cfg["server"].rstrip("/")
        self.token = cfg["token"]
        self.session: aiohttp.ClientSession | None = None

    async def __aenter__(self):
        self.session = aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=300),
                                             headers={"Authorization": f"Bearer {self.token}",
                                                      "User-Agent": f"ZeroAI-Agent/{VERSION}"})
        return self

    async def __aexit__(self, *exc):
        await self.session.close()

    async def get(self, path: str) -> dict:
        async with self.session.get(self.base + path) as r:
            data = await r.json(content_type=None)
            if r.status >= 400:
                raise ServerError(data.get("message") or data.get("error") or f"HTTP {r.status}")
            return data

    async def llm(self, model: str, messages: list, tools: list, task_id: str = None) -> dict:
        body = {"model": model, "messages": messages, "tools": tools, "task_id": task_id}
        async with self.session.post(self.base + "/api/agent/llm", json=body) as r:
            data = await r.json(content_type=None)
            if r.status >= 400 or not data.get("ok"):
                raise ServerError(data.get("message") or data.get("error") or f"HTTP {r.status}")
            return data


def system_prompt(cfg: dict) -> str:
    memory = MEMORY_FILE.read_text(encoding="utf-8")[-4000:] if MEMORY_FILE.exists() else ""
    skills = list_skills()
    shell = "cmd.exe（Windows）" if os.name == "nt" else os.environ.get("SHELL", "/bin/sh")
    parts = [
        "你是 ZeroAI Agent，在使用者自己的電腦上用工具完成任務。",
        f"現在時間：{datetime.now().strftime('%Y-%m-%d %H:%M')}；系統：{platform.system()} {platform.release()}；"
        f"shell：{shell}；工作區：{cfg['workspace']}（預設在這裡讀寫，工作區以外的讀寫會先請使用者核准）。",
        "做法：先想清楚步驟，一次只做必要的事；動手前先查看現況（列資料夾、讀檔），不要猜路徑。"
        "會刪除、覆寫或安裝東西時，先確認那正是使用者要的。工具回報被拒絕時，換別的做法或說明原因，不要一直重試。",
        "結束時用使用者的語言簡短說明做了什麼、結果在哪裡、還有什麼沒完成。",
        "以後用得到的事（使用者偏好、這台電腦的環境）用 memory 工具記下來。",
    ]
    if memory.strip():
        parts.append("【長期記憶】\n" + memory.strip())
    if skills:
        parts.append("【可用技能】需要時用 read_skill 讀完整步驟：\n" +
                     "\n".join(f"- {n}：{d}" for n, d in skills))
    return "\n\n".join(parts)


def compact(messages: list) -> list:
    """對話太長時把較早的工具輸出換成一行說明（最後 8 則保留原樣）。assistant 訊息不動——
    裡面可能有供應商要求原樣送回的思考區塊或簽章。"""
    total = sum(len(json.dumps(m, ensure_ascii=False)) for m in messages)
    if total <= COMPACT_AT:
        return messages
    out = []
    for i, m in enumerate(messages):
        if m.get("role") == "tool" and i < len(messages) - 8 and len(str(m.get("content") or "")) > 300:
            m = dict(m, content="（較早的工具輸出已省略以節省額度）")
        out.append(m)
    return out


async def run_agent(api: Api, cfg: dict, task: str, model: str, approve, progress,
                    cancelled=lambda: False, task_id: str = None, redact=lambda s: s) -> tuple:
    """跑一個任務。回傳 (成功, 最後的文字, 總點數)。"""
    tools = Tools(cfg, approve, redact)
    messages = [{"role": "system", "content": system_prompt(cfg)}, {"role": "user", "content": task}]
    total = 0.0
    steps = max(1, min(int(cfg.get("max_steps") or 40), 200))
    for step in range(1, steps + 1):
        if cancelled():
            return False, "已取消。", total
        try:
            data = await api.llm(model, compact(messages), TOOLS, task_id)
        except ServerError as e:
            return False, f"ZeroAI 回報：{e}", total
        except aiohttp.ClientError as e:
            return False, f"連不上 ZeroAI：{type(e).__name__}", total
        total = round(total + data["usage"]["points"], 2)
        msg = data["message"]
        messages.append(msg)
        calls = msg.get("tool_calls") or []
        if not calls:
            return True, (msg.get("content") or "（完成，沒有文字回覆）"), total
        if msg.get("content"):
            await progress(f"💭 {msg['content'][:200]}")
        for tc in calls:
            fn = tc.get("function") or {}
            name = fn.get("name") or ""
            try:
                args = json.loads(fn.get("arguments") or "{}")
            except ValueError:
                args = {}
            shown = args.get("command") or args.get("path") or args.get("url") or args.get("pattern") or args.get("action") or ""
            await progress(f"[{step}] {name} {str(shown)[:150]}".rstrip())
            if cancelled():
                return False, "已取消。", total
            out = await tools.run(name, args if isinstance(args, dict) else {})
            messages.append({"role": "tool", "tool_call_id": tc.get("id"), "content": out})
    messages.append({"role": "user", "content": "已達步數上限。請不要再呼叫工具，總結目前做到哪裡、還差什麼。"})
    try:
        data = await api.llm(model, compact(messages), TOOLS, task_id)
        total = round(total + data["usage"]["points"], 2)
        return False, data["message"].get("content") or "已達步數上限。", total
    except (ServerError, aiohttp.ClientError) as e:
        return False, f"已達步數上限（{e}）。", total


def make_redactor(cfg: dict):
    token = cfg.get("token") or ""
    return (lambda s: s.replace(token, "[REDACTED]")) if token else (lambda s: s)


# ───────────────────────── 指令 ─────────────────────────

async def cmd_pair(args) -> int:
    cfg = load_config()
    server = (args.server or cfg.get("server") or "").rstrip("/")
    local = (urlparse(server).hostname or "") in ("localhost", "127.0.0.1", "::1")
    if not server.startswith("https://") and not (server.startswith("http://") and local):
        print("請用 --server 指定 ZeroAI Agent 的網址（https://…，Discord /agent bind 會顯示）。")
        return 1
    body = {"code": args.code, "name": args.name or cfg["name"], "os": f"{platform.system()} {platform.release()}",
            "version": VERSION}
    async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=30)) as s:
        async with s.post(server + "/api/agent/pair", json=body) as r:
            data = await r.json(content_type=None)
    if not data.get("ok"):
        print(f"❌ 配對失敗：{data.get('message') or data.get('error')}")
        return 1
    cfg.update(server=server, token=data["token"], device_id=data["device_id"], name=body["name"])
    save_config(cfg)
    Path(cfg["workspace"]).expanduser().mkdir(parents=True, exist_ok=True)
    print(f"✅ 已綁定（裝置 {cfg['name']}）。金鑰存在 {CONFIG_FILE}，不要分享這個檔案。")
    print(f"   工作區：{cfg['workspace']}")
    print("   執行 `python zeroai_agent.py serve` 讓 Discord 的 /agent run 可以把任務送過來。")
    print("   使用本軟體即表示同意 LICENSE（ZeroAI Agent Client 使用授權條款）與 ZeroAI 服務條款。")
    return 0


def _need_token(cfg) -> bool:
    if not cfg.get("token") or not cfg.get("server"):
        print("還沒有綁定。先在 Discord 輸入 /agent bind，再執行 `python zeroai_agent.py pair <配對碼> --server <網址>`。")
        return True
    return False


async def local_approve(action: str, detail: str, reason: str) -> bool:
    print(f"\n⚠️ 需要你核准：{action}（{reason}）\n   {detail}")
    try:
        ans = await asyncio.wait_for(asyncio.to_thread(input, "   允許嗎？[y/N] "), timeout=APPROVAL_TIMEOUT)
    except asyncio.TimeoutError:
        print("   逾時，視為拒絕。")
        return False
    return ans.strip().lower() in ("y", "yes", "是", "好")


async def cmd_run(args) -> int:
    cfg = load_config()
    if _need_token(cfg):
        return 1

    async def progress(text):
        print(f"  {text}")

    async with Api(cfg) as api:
        ok, text, pts = await run_agent(api, cfg, args.task, args.model or cfg.get("model") or "",
                                        local_approve, progress, redact=make_redactor(cfg))
    print(("\n✅ " if ok else "\n⚠️ ") + text)
    print(f"（本次共扣 {pts:g} 點）")
    return 0 if ok else 2


async def cmd_status(args) -> int:
    cfg = load_config()
    if _need_token(cfg):
        return 1
    async with Api(cfg) as api:
        try:
            data = await api.get("/api/agent/me")
        except ServerError as e:
            print(f"❌ {e}")
            return 1
    print(f"裝置：{data['name']}（{data['device_id']}）　伺服器：{cfg['server']}")
    if data.get("access_error"):
        print(f"⚠️ {data['access_error']}")
    print(f"額度：{data.get('quota')}")
    b = data.get("billing") or {}
    print(f"計費：點數 = 模型基準點數 × (輸入 token + 輸出 token × {b.get('output_weight')}) ÷ {b.get('tokens_per_unit'):,}"
          f"（0 點模型至少照 {b.get('min_model_cost')} 計）")
    print("可用模型：")
    for m in data.get("models") or []:
        print(f"  {m['key']:<24} {m['display']}（基準 {m['cost']:g} 點）")
    print(f"遠端任務：{'接受' if cfg.get('remote_tasks') else '不接受'}　核准模式：{cfg.get('approval')}　工作區：{cfg['workspace']}")
    return 0


async def cmd_unpair(args) -> int:
    cfg = load_config()
    if cfg.get("token") and cfg.get("server"):
        try:
            async with Api(cfg) as api:
                async with api.session.post(api.base + "/api/agent/unpair") as r:
                    await r.read()
        except aiohttp.ClientError:
            print("⚠️ 連不上 ZeroAI；本機金鑰照樣刪除，請在 Discord 用 /agent unbind 撤銷。")
    cfg.update(token="", device_id="")
    save_config(cfg)
    print("✅ 已解除綁定。")
    return 0


def cmd_config(args) -> int:
    cfg = load_config()
    if args.action == "show":
        shown = dict(cfg, token=("zag_…" + cfg["token"][-4:]) if cfg.get("token") else "")
        print(json.dumps(shown, ensure_ascii=False, indent=2))
        return 0
    key, value = args.key, args.value
    if key not in DEFAULTS or key in ("token", "device_id"):
        print(f"可以設定的鍵：{', '.join(k for k in DEFAULTS if k not in ('token', 'device_id'))}")
        return 1
    if isinstance(DEFAULTS[key], bool):
        cfg[key] = str(value).lower() in ("1", "true", "yes", "on")
    elif isinstance(DEFAULTS[key], int):
        cfg[key] = int(value)
    elif isinstance(DEFAULTS[key], list):
        cfg[key] = [v.strip() for v in str(value).split(";") if v.strip()]
    else:
        cfg[key] = value
    save_config(cfg)
    print(f"✅ {key} = {cfg[key]}")
    return 0


class Server:
    """serve：用 WebSocket 掛在 ZeroAI 上等任務（連出去的連線，不必開任何埠）。"""

    def __init__(self, cfg: dict):
        self.cfg = cfg
        self.ws = None
        self.approvals: dict = {}
        self.cancelled: set = set()
        self.redact = make_redactor(cfg)

    async def send(self, data: dict):
        if self.ws is not None and not self.ws.closed:
            await self.ws.send_json(data)

    async def run_task(self, api: Api, task_id: str, prompt: str, model: str):
        print(f"\n📥 任務 {task_id}：{prompt[:200]}")

        async def progress(text):
            print(f"  {text}")
            await self.send({"type": "progress", "task_id": task_id, "text": text})

        async def approve(action, detail, reason):
            aid = secrets.token_hex(6)
            fut = asyncio.get_running_loop().create_future()
            self.approvals[aid] = fut
            print(f"  ⚠️ 等待 Discord 核准：{action} {detail[:120]}")
            await self.send({"type": "approval_request", "task_id": task_id, "approval_id": aid,
                             "action": action, "detail": self.redact(detail), "reason": reason})
            try:
                ok = await asyncio.wait_for(fut, timeout=APPROVAL_TIMEOUT)
            except asyncio.TimeoutError:
                ok = False
            finally:
                self.approvals.pop(aid, None)
            print(f"  {'✅ 已核准' if ok else '⛔ 未核准'}")
            return ok

        ok, text, pts = await run_agent(api, self.cfg, prompt, model, approve, progress,
                                        cancelled=lambda: task_id in self.cancelled, task_id=task_id,
                                        redact=self.redact)
        print(("✅ " if ok else "⚠️ ") + f"任務 {task_id} 結束（{pts:g} 點）")
        await self.send({"type": "result", "task_id": task_id, "ok": ok, "text": self.redact(text)})

    async def loop(self) -> int:
        url = self.cfg["server"].rstrip("/").replace("https://", "wss://", 1).replace("http://", "ws://", 1)
        backoff = 2
        async with Api(self.cfg) as api:
            while True:
                try:
                    async with api.session.ws_connect(url + "/api/agent/ws", heartbeat=30,
                                                      timeout=aiohttp.ClientWSTimeout(ws_close=10)) as ws:
                        self.ws = ws
                        backoff = 2
                        await ws.send_json({"type": "hello", "version": VERSION,
                                            "remote_tasks": bool(self.cfg.get("remote_tasks"))})
                        print(f"🟢 已連上 ZeroAI（遠端任務：{'接受' if self.cfg.get('remote_tasks') else '不接受'}）。Ctrl+C 結束。")
                        async for msg in ws:
                            if msg.type != aiohttp.WSMsgType.TEXT:
                                continue
                            data = json.loads(msg.data)
                            kind = data.get("type")
                            if kind == "task":
                                if not self.cfg.get("remote_tasks"):
                                    await self.send({"type": "result", "task_id": data.get("task_id"), "ok": False,
                                                     "text": "這台主機不接受遠端任務。"})
                                    continue
                                asyncio.create_task(self.run_task(api, data["task_id"], data.get("prompt", ""),
                                                                  data.get("model", "")))
                            elif kind == "approval":
                                fut = self.approvals.get(data.get("approval_id"))
                                if fut is not None and not fut.done():
                                    fut.set_result(bool(data.get("approved")))
                            elif kind == "cancel":
                                self.cancelled.add(data.get("task_id"))
                                print(f"🛑 任務 {data.get('task_id')} 已被取消")
                except aiohttp.WSServerHandshakeError as e:
                    if e.status in (401, 403):
                        print("❌ 金鑰無效或沒有使用權限（可能已在 Discord 解除綁定，或方案不是 Pro 以上）。"
                              "請重新 /agent bind 後再 pair。")
                        return 1
                    print(f"⚠️ 連線被拒（HTTP {e.status}），{backoff} 秒後重試…")
                except (aiohttp.ClientError, OSError, asyncio.TimeoutError) as e:
                    print(f"⚠️ 連線中斷（{type(e).__name__}），{backoff} 秒後重試…")
                self.ws = None
                for fut in self.approvals.values():
                    if not fut.done():
                        fut.set_result(False)
                await asyncio.sleep(backoff)
                backoff = min(backoff * 2, 60)


async def cmd_serve(args) -> int:
    cfg = load_config()
    if _need_token(cfg):
        return 1
    return await Server(cfg).loop()


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="zeroai_agent", description="ZeroAI Agent Client")
    sub = p.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("pair", help="用 /agent bind 的配對碼綁定")
    s.add_argument("code")
    s.add_argument("--server", default="")
    s.add_argument("--name", default="")
    sub.add_parser("serve", help="保持在線，接 Discord 的任務")
    s = sub.add_parser("run", help="在這台電腦上跑一個任務")
    s.add_argument("task")
    s.add_argument("--model", default="")
    sub.add_parser("status", help="額度與可用模型")
    sub.add_parser("unpair", help="解除綁定")
    s = sub.add_parser("config", help="設定")
    s.add_argument("action", choices=["show", "set"])
    s.add_argument("key", nargs="?")
    s.add_argument("value", nargs="?")
    args = p.parse_args(argv)
    if args.cmd == "config":
        if args.action == "set" and (args.key is None or args.value is None):
            print("用法：config set <鍵> <值>")
            return 1
        return cmd_config(args)
    handler = {"pair": cmd_pair, "serve": cmd_serve, "run": cmd_run, "status": cmd_status, "unpair": cmd_unpair}[args.cmd]
    try:
        return asyncio.run(handler(args))
    except KeyboardInterrupt:
        print("\n已結束。")
        return 0


if __name__ == "__main__":
    sys.exit(main())
