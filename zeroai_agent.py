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
import inspect
import json
import os
import platform
import re
import secrets
import socket
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path
from urllib.parse import urljoin, urlparse

try:
    import aiohttp
except ImportError:            # pragma: no cover
    print("需要 aiohttp：pip install aiohttp")
    raise SystemExit(1)

VERSION = "1.2.1"
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
# ZeroAI 關閉連線的代碼（與 mods_zeroai/agent_hub.py 相同）：被同一台主機的新連線取代、已解除綁定
CLOSE_REPLACED = 4001
CLOSE_UNBOUND = 4002
# 存活檢查（見 Server._keepalive）：用一般訊息的 ping／pong，不用 WebSocket 內建的 heartbeat
KEEPALIVE_HEADER = "X-Agent-Keepalive"
KEEPALIVE_INTERVAL = 20         # 每隔幾秒送一次 ping
KEEPALIVE_TIMEOUT = 60          # 這麼久沒收到 ZeroAI 任何訊息就重新連線

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
                       "危險的指令（刪檔、安裝、改系統設定…）會先請使用者核准。"
                       "要打開視窗或程式、或啟動會一直執行的東西（開 PowerShell、開瀏覽器、開應用程式、啟動伺服器）"
                       "時把 background 設成 true，否則會一直等到那個程式被關掉；Windows 要開新視窗用 start，例如 start powershell。",
        "parameters": {"type": "object", "properties": {
            "command": {"type": "string", "description": "要執行的指令"},
            "cwd": {"type": "string", "description": "工作目錄，預設是工作區"},
            "timeout": {"type": "integer", "description": "秒數上限，預設 120、最多 600"},
            "background": {"type": "boolean",
                           "description": "啟動後立刻回來，不等它結束、也不回傳輸出（開視窗、開程式用）"}},
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


SEARCH_SKIP_DIRS = {".git", "node_modules", "__pycache__", ".venv", "venv"}


def search_text(root: Path, rx, glob: str = "", max_files: int = 5000, max_hits: int = 100,
                time_limit: float = 30.0) -> str:
    """在 root 底下的文字檔搜 rx。在執行緒裡跑；檔案數、結果數、時間任一到上限就整個停下
    （以前的上限只跳出內層迴圈，os.walk 還是把整顆磁碟走完）。"""
    deadline = time.monotonic() + time_limit
    hits, scanned, stopped = [], 0, ""
    root = root.resolve()

    def permitted(path):
        try:
            resolved = path.resolve()
            return _inside(resolved, root) and not _inside(resolved, HOME)
        except (OSError, RuntimeError):
            return False

    for base, dirs, files in os.walk(root):
        if time.monotonic() > deadline:
            stopped = f"已搜尋 {time_limit:g} 秒"
            break
        if not permitted(Path(base)):
            dirs[:] = []
            continue
        dirs[:] = [d for d in dirs if d not in SEARCH_SKIP_DIRS and permitted(Path(base) / d)]
        for name in files:
            if glob and not fnmatch.fnmatch(name, glob):
                continue
            if scanned >= max_files:
                stopped = f"已掃描 {max_files} 個檔案"
                break
            if time.monotonic() > deadline:
                stopped = f"已搜尋 {time_limit:g} 秒"
                break
            scanned += 1
            fp = Path(base) / name
            try:
                # 核准搜尋父目錄不代表可以讀取 Agent 金鑰，或跟著檔案連結跨出核准範圍。
                if not permitted(fp):
                    continue
                if fp.stat().st_size > 2 * 1024 * 1024:
                    continue
                with open(fp, encoding="utf-8", errors="ignore") as f:
                    for no, line in enumerate(f, 1):
                        if rx.search(line):
                            hits.append(f"{fp}:{no}: {line.strip()[:200]}")
                            if len(hits) >= max_hits:
                                break
            except OSError:
                continue
            if len(hits) >= max_hits:
                stopped = f"已找到 {max_hits} 筆"
                break
        if stopped:
            break
    out = "\n".join(hits) or "沒有符合的結果。"
    if stopped:
        out += f"\n（{stopped}，先停在這裡；結果可能不完整，請縮小資料夾範圍或用 glob 限定檔名）"
    return out


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
            return self.redact(f"沒有這個工具：{name}")
        if not isinstance(args, dict):
            return "參數錯誤：工具參數必須是 JSON 物件。"
        try:
            out = await fn(**{k: v for k, v in args.items() if k in inspect.signature(fn).parameters})
        except TypeError as e:
            out = f"參數錯誤：{e}"
        except Exception as e:
            out = f"工具執行失敗：{type(e).__name__}: {e}"
        out = self.redact(str(out))
        if len(out) > MAX_TOOL_OUTPUT:
            out = out[:MAX_TOOL_OUTPUT // 2] + f"\n…（中間省略 {len(out) - MAX_TOOL_OUTPUT} 字）…\n" + out[-MAX_TOOL_OUTPUT // 2:]
        return out

    async def t_terminal(self, command: str, cwd: str = "", timeout: int = 0, background: bool = False) -> str:
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
        if isinstance(background, str):
            background = background.strip().lower() in ("1", "true", "yes", "on")
        if background:
            # 不接管輸出：開出來的視窗或程式若繼承了輸出管線，這裡會一直等到它被關掉才回來
            extra = ({"creationflags": subprocess.CREATE_NEW_PROCESS_GROUP} if os.name == "nt"
                     else {"start_new_session": True})
            proc = await asyncio.create_subprocess_shell(
                command, cwd=str(workdir), stdin=asyncio.subprocess.DEVNULL,
                stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.DEVNULL, **extra)
            try:
                code = await asyncio.wait_for(proc.wait(), timeout=3)
            except asyncio.TimeoutError:
                return f"已在背景啟動（PID {proc.pid}），不等它結束。"
            return f"已啟動，啟動指令在 3 秒內結束（結束碼 {code}）；開出來的視窗或程式會繼續執行。"
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

    # 檔案類工具的實際讀寫都丟到執行緒：在事件迴圈裡同步走訪大資料夾會卡住 WebSocket 心跳，
    # 超過十幾秒 Gateway 就判定斷線，ZeroAI 那邊看到的就是「主機中途離線」。
    async def t_read_file(self, path: str, offset: int = 1, limit: int = 400) -> str:
        p = _resolve(path, self.workspace)
        reason = await self._guard_path(p, "讀取檔案")
        if reason:
            return reason

        def work():
            if not p.is_file():
                return f"找不到檔案：{p}"
            if p.stat().st_size > 20 * 1024 * 1024:
                return "檔案超過 20 MB，請用 terminal 搭配 head／findstr 之類的指令讀需要的部分。"
            lines = p.read_text(encoding="utf-8", errors="replace").splitlines()
            start = max(1, int(offset or 1))
            chunk = lines[start - 1:start - 1 + max(1, min(int(limit or 400), 2000))]
            body = "\n".join(f"{i}\t{line}" for i, line in enumerate(chunk, start))
            return f"{p}（共 {len(lines)} 行）\n{body}"
        return await asyncio.to_thread(work)

    async def t_write_file(self, path: str, content: str, append: bool = False) -> str:
        p = _resolve(path, self.workspace)
        reason = await self._guard_path(p, "寫入檔案")
        if reason:
            return reason

        def work():
            p.parent.mkdir(parents=True, exist_ok=True)
            with open(p, "a" if append else "w", encoding="utf-8", newline="") as f:
                f.write(content)
            return f"已{'附加' if append else '寫入'} {p}（{len(content)} 字）"
        return await asyncio.to_thread(work)

    async def t_list_dir(self, path: str = "") -> str:
        p = _resolve(path or ".", self.workspace)
        reason = await self._guard_path(p, "列出資料夾")
        if reason:
            return reason

        def work():
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
        return await asyncio.to_thread(work)

    async def t_search_files(self, pattern: str, path: str = "", glob: str = "") -> str:
        p = _resolve(path or ".", self.workspace)
        reason = await self._guard_path(p, "搜尋資料夾")
        if reason:
            return reason
        try:
            rx = re.compile(pattern, re.IGNORECASE)
        except re.error as e:
            return f"regex 錯誤：{e}"
        return await asyncio.to_thread(search_text, p, rx, glob)

    async def t_fetch_url(self, url: str) -> str:
        timeout = aiohttp.ClientTimeout(total=30)
        async with aiohttp.ClientSession(timeout=timeout) as s:
            for hop in range(11):
                if not re.match(r"^https?://", url or "", re.IGNORECASE):
                    return "只支援 http／https 網址。"
                # DNS 解析不阻塞 WebSocket 心跳；重新導向的每個目的地也必須重新檢查。
                if self.cfg.get("approval") != "off" and await asyncio.to_thread(_private_host, url):
                    if not await self.approve("讀取內部網路", url, "這個網址指向本機或區域網路"):
                        return "使用者沒有核准這個操作。"
                async with s.get(url, headers={"User-Agent": f"ZeroAI-Agent/{VERSION}"},
                                 allow_redirects=False) as r:
                    if r.status in (301, 302, 303, 307, 308) and r.headers.get("Location"):
                        if hop == 10:
                            return "重新導向次數過多（最多 10 次）。"
                        url = urljoin(str(r.url), r.headers["Location"])
                        continue
                    # read(n) 可以在第一個網路區塊抵達時就回傳；持續讀到 EOF 或大小上限。
                    raw = bytearray()
                    async for chunk in r.content.iter_chunked(64 * 1024):
                        raw.extend(chunk[:400_000 - len(raw)])
                        if len(raw) >= 400_000:
                            break
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
        except (aiohttp.ClientError, asyncio.TimeoutError) as e:
            return False, f"連不上 ZeroAI：{type(e).__name__}", total
        total = round(total + data["usage"]["points"], 2)
        if cancelled():
            return False, "已取消。", total
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
            except (ValueError, TypeError):
                args = None
            shown = ((args.get("command") or args.get("path") or args.get("url") or args.get("pattern")
                      or args.get("action") or "") if isinstance(args, dict) else "（參數格式錯誤）")
            await progress(redact(f"[{step}] {name} {str(shown)[:150]}".rstrip()))
            if cancelled():
                return False, "已取消。", total
            out = await tools.run(name, args)
            messages.append({"role": "tool", "tool_call_id": tc.get("id"), "content": out})
    if cancelled():
        return False, "已取消。", total
    messages.append({"role": "user", "content": "已達步數上限。請不要再呼叫工具，總結目前做到哪裡、還差什麼。"})
    try:
        data = await api.llm(model, compact(messages), TOOLS, task_id)
        total = round(total + data["usage"]["points"], 2)
        if cancelled():
            return False, "已取消。", total
        return False, data["message"].get("content") or "已達步數上限。", total
    except (ServerError, aiohttp.ClientError, asyncio.TimeoutError) as e:
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
        self.approval_tasks: dict = {}   # approval_id -> task_id（取消任務時立即停止等核准）
        self.cancelled: set = set()
        self.redact = make_redactor(cfg)
        # 斷線期間送不出去、又不能丟的訊息（結果、核准請求）：重新連上後補送。
        # 任務本身不受斷線影響——模型呼叫走 HTTP，ZeroAI 也會保留任務一段時間等主機連回來。
        self.outbox: list = []
        self.running: set = set()
        # 這個 serve 手上還沒回報結果的任務（執行中，或結果還在 outbox）。連上時告訴 ZeroAI，
        # 不在清單上的任務 ZeroAI 就知道已經沒人會回報（例如換了另一個 serve），可以收掉
        self.owned: set = set()
        self.last_seen = 0.0            # 上次收到 ZeroAI 任何訊息的時間
        self.server_keepalive = False   # ZeroAI 是否支援訊息式的存活檢查（welcome 會說）
        self.close_note = ""            # 上一條連線結束的說明（斷線訊息用）

    async def send(self, data: dict):
        if self.ws is not None and not self.ws.closed:
            try:
                await self.ws.send_json(data)
                if data.get("type") == "result":
                    self.owned.discard(data.get("task_id"))
                return
            except (ConnectionError, RuntimeError, aiohttp.ClientError):
                pass
        if data.get("type") in ("result", "approval_request"):
            self.outbox.append(data)

    async def _wait_running_tasks(self, limit: float = 30.0):
        """結束前讓已經在跑的任務做完手上的步驟，不要把正在寫的檔案寫一半就砍掉。
        結果已經送不回去（連線被取代了）；ZeroAI 在新的 serve 連上時就會把這些任務收掉。"""
        running = [t for t in self.running if not t.done()]
        if running:
            print(f"  等 {len(running)} 個執行中的任務結束（最多 {limit:g} 秒）…")
            await asyncio.wait(running, timeout=limit)

    async def _flush_outbox(self):
        pending, self.outbox = self.outbox, []
        for data in pending:
            if data.get("type") == "approval_request" and data.get("approval_id") not in self.approvals:
                continue
            await self.send(data)

    async def run_task(self, api: Api, task_id: str, prompt: str, model: str):
        print(f"\n📥 任務 {task_id}：{prompt[:200]}")
        self.owned.add(task_id)

        async def progress(text):
            text = self.redact(text)
            print(f"  {text}")
            await self.send({"type": "progress", "task_id": task_id, "text": text})

        async def approve(action, detail, reason):
            if task_id in self.cancelled:
                return False
            aid = secrets.token_hex(6)
            fut = asyncio.get_running_loop().create_future()
            self.approvals[aid] = fut
            self.approval_tasks[aid] = task_id
            print(f"  ⚠️ 等待 Discord 核准：{action} {detail[:120]}")
            try:
                await self.send({"type": "approval_request", "task_id": task_id, "approval_id": aid,
                                 "action": action, "detail": self.redact(detail), "reason": reason})
                ok = await asyncio.wait_for(fut, timeout=APPROVAL_TIMEOUT)
            except asyncio.TimeoutError:
                ok = False
            finally:
                self.approvals.pop(aid, None)
                self.approval_tasks.pop(aid, None)
                self.outbox[:] = [m for m in self.outbox if m.get("approval_id") != aid]
            print(f"  {'✅ 已核准' if ok else '⛔ 未核准'}")
            return ok and task_id not in self.cancelled

        try:
            ok, text, pts = await run_agent(api, self.cfg, prompt, model, approve, progress,
                                            cancelled=lambda: task_id in self.cancelled, task_id=task_id,
                                            redact=self.redact)
        except Exception as e:
            ok, text, pts = False, f"任務執行失敗：{type(e).__name__}: {e}", 0.0
        finally:
            self.cancelled.discard(task_id)
        print(("✅ " if ok else "⚠️ ") + f"任務 {task_id} 結束（{pts:g} 點）")
        await self.send({"type": "result", "task_id": task_id, "ok": ok, "text": self.redact(text)})

    async def loop(self) -> int:
        url = self.cfg["server"].rstrip("/").replace("https://", "wss://", 1).replace("http://", "ws://", 1)
        backoff = 2
        async with Api(self.cfg) as api:
            while True:
                try:
                    # 不用 WebSocket 內建的 heartbeat，改由 _keepalive 送一般訊息的 ping（原因見那裡）；
                    # 用標頭告訴 Gateway 與 ZeroAI 這條連線走新的存活檢查。
                    async with api.session.ws_connect(url + "/api/agent/ws", heartbeat=None,
                                                      headers={KEEPALIVE_HEADER: "1"},
                                                      timeout=(aiohttp.ClientWSTimeout(ws_close=10)
                                                               if hasattr(aiohttp, "ClientWSTimeout") else 10.0)) as ws:
                        self.ws = ws
                        backoff = 2
                        connected_at = self.last_seen = time.monotonic()
                        self.server_keepalive = False
                        self.close_note = ""
                        await ws.send_json({"type": "hello", "version": VERSION,
                                            "remote_tasks": bool(self.cfg.get("remote_tasks")),
                                            "tasks": sorted(self.owned),
                                            # 核准模式也告訴 ZeroAI：設成 off 時，對話裡交代任務就不再先私訊確認
                                            "approval": str(self.cfg.get("approval") or "manual")})
                        print(f"🟢 已連上 ZeroAI（遠端任務：{'接受' if self.cfg.get('remote_tasks') else '不接受'}）。Ctrl+C 結束。")
                        if self.outbox:
                            print(f"  補送斷線期間的 {len(self.outbox)} 則訊息")
                            await self._flush_outbox()
                        keeper = asyncio.create_task(self._keepalive(ws))
                        try:
                            await self._receive(api, ws)
                        finally:
                            keeper.cancel()
                            await asyncio.gather(keeper, return_exceptions=True)
                        # 斷線時把關閉代碼與維持了多久印出來：連線一直斷的時候，這兩個數字是判斷原因的依據
                        self.close_note = (f"關閉代碼 {ws.close_code}，維持了 {time.monotonic() - connected_at:.0f} 秒"
                                           + (f"，{self.close_note}" if self.close_note else ""))
                        if ws.close_code == CLOSE_REPLACED:
                            # 同一把金鑰在別的地方連上了。兩個 serve 都自動重連的話會互相擠掉、
                            # 任務送到一半斷線，所以被取代的這一個直接結束
                            print("⛔ 這台主機在別的地方連上了 ZeroAI（可能開了兩個 serve 視窗），這個視窗先結束。"
                                  "只保留一個 serve 即可。")
                            await self._wait_running_tasks()
                            return 2
                        if ws.close_code == CLOSE_UNBOUND:
                            print("⛔ 這台主機已在 Discord 解除綁定，金鑰已失效。要再使用請重新 /agent bind 後 pair。")
                            return 1
                except aiohttp.WSServerHandshakeError as e:
                    if e.status in (401, 403):
                        print("❌ 金鑰無效或沒有使用權限（可能已在 Discord 解除綁定，或方案不是 Pro 以上）。"
                              "請重新 /agent bind 後再 pair。")
                        return 1
                    print(f"⚠️ 連線被拒（HTTP {e.status}），{backoff} 秒後重試…")
                except (aiohttp.ClientError, OSError, asyncio.TimeoutError) as e:
                    print(f"⚠️ 連線中斷（{type(e).__name__}），{backoff} 秒後重試…")
                except Exception as e:                    # 收到看不懂的訊息之類：重連，不要讓 serve 整個結束
                    print(f"⚠️ 連線處理錯誤（{type(e).__name__}: {e}），{backoff} 秒後重試…")
                else:
                    print(f"⚠️ 與 ZeroAI 的連線中斷（{self.close_note}），{backoff} 秒後重新連線…")
                self.ws = None
                # 等核准中的操作不在這裡判拒絕：連回來後使用者在 Discord 按的結果照樣送得到，
                # 真的沒人按就由 APPROVAL_TIMEOUT 收尾
                await asyncio.sleep(backoff)
                backoff = min(backoff * 2, 60)

    async def _keepalive(self, ws):
        """存活檢查：每 KEEPALIVE_INTERVAL 秒送一則一般訊息的 ping，ZeroAI 會回 pong。

        不用 WebSocket 內建的 heartbeat：那是控制訊號，經過某些反向代理（CDN、主機商的代理）不會被轉送，
        兩端各自等不到回應，約 45 秒就判定對方失聯而斷線、不斷重連。一般訊息一定會被轉送。
        ZeroAI 在 welcome 表示支援時，超過 KEEPALIVE_TIMEOUT 秒沒收到任何訊息就主動重連。
        """
        while not ws.closed:
            await asyncio.sleep(KEEPALIVE_INTERVAL)
            if ws.closed:
                return
            silent = time.monotonic() - self.last_seen
            if self.server_keepalive and silent > KEEPALIVE_TIMEOUT:
                self.close_note = f"{silent:.0f} 秒沒有收到 ZeroAI 的任何回應，主動重連"
                await ws.close()
                return
            try:
                await ws.send_json({"type": "ping"})
            except (ConnectionError, RuntimeError, aiohttp.ClientError):
                return

    async def _receive(self, api: Api, ws):
        """收 ZeroAI 送來的訊息，直到連線結束。"""
        async for msg in ws:
            self.last_seen = time.monotonic()
            if msg.type != aiohttp.WSMsgType.TEXT:
                continue
            data = json.loads(msg.data)
            kind = data.get("type")
            if kind == "welcome":
                self.server_keepalive = bool(data.get("keepalive"))
            elif kind == "task":
                task_id = data.get("task_id")
                if not isinstance(task_id, str) or not task_id or task_id in self.owned:
                    continue
                if not self.cfg.get("remote_tasks"):
                    await self.send({"type": "result", "task_id": data.get("task_id"), "ok": False,
                                     "text": "這台主機不接受遠端任務。"})
                    continue
                # 在排程前登記，避免同一批收到兩則 task、協程還沒開始就重複執行。
                self.owned.add(task_id)
                t = asyncio.create_task(self.run_task(api, data["task_id"], data.get("prompt", ""),
                                                      data.get("model", "")))
                self.running.add(t)
                t.add_done_callback(self.running.discard)
            elif kind == "approval":
                fut = self.approvals.get(data.get("approval_id"))
                if fut is not None and not fut.done():
                    fut.set_result(bool(data.get("approved")))
            elif kind == "cancel":
                task_id = data.get("task_id")
                if task_id not in self.owned:
                    continue
                self.cancelled.add(task_id)
                for aid, owner in list(self.approval_tasks.items()):
                    fut = self.approvals.get(aid)
                    if owner == task_id and fut is not None and not fut.done():
                        fut.set_result(False)
                print(f"🛑 任務 {task_id} 已被取消")


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
