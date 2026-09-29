#!/usr/bin/env python3
"""
Antigravity ACP Bridge / Inspector
----------------------------------
Transparent stdio middleware between ACP clients (like Paseo) and agy_acp_server.par.

Transforms and enriches Antigravity tool notifications:
- Injects file content and line metadata into 'read' (view_file) calls so clients
  can see exactly what the agent reads.
- Injects structured diffs and unified diff text into 'edit' (replace_file_content)
  and 'write' (write_to_file) calls so clients render line diffs with syntax highlighting.
- Normalizes tool input and output fields (e.g. AbsolutePath -> filePath, StartLine -> line/offset,
  CommandLine -> command) to standard ACP client schemas.
- Resolves relative file paths against the current workspace directory (cwd) tracked
  from session/new and session/load requests.
"""

import sys
import os
import re
import json
import signal
import difflib
import shutil
import subprocess
import threading
from pathlib import Path
from typing import Dict, Any, Optional, List

BASE_DIR = Path(__file__).resolve().parent
LIB_IPV4_SO = BASE_DIR / "libforce_ipv4.so"
HARNESS_BIN = BASE_DIR / "localharness_external"
LOG_FILE = BASE_DIR / "bridge.log"

# Force UTF-8 IO encoding on Windows
if sys.platform == "win32":
    if hasattr(sys.stdin, "reconfigure"):
        sys.stdin.reconfigure(encoding="utf-8", errors="replace", newline=None)
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace", newline="\n")
    if hasattr(sys.stderr, "reconfigure"):
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")

# Maximum characters of file content to attach to prevent overwhelming stdio
MAX_CONTENT_CHARS = 500_000
MAX_CONTENT_LINES = 5_000
MAX_LOG_SIZE = 5 * 1024 * 1024


def find_server_binary() -> Path:
    """Locates the agy_acp_server binary dynamically on Linux or Windows."""
    env_bin = os.environ.get("AGY_ACP_SERVER_BIN")
    if env_bin and Path(env_bin).exists():
        return Path(env_bin)

    bin_names = ["agy_acp_server.exe", "agy_acp_server.par"]

    # 1. Check BASE_DIR
    for name in bin_names:
        candidate = BASE_DIR / name
        if candidate.exists():
            return candidate

    # 2. Check known standard install locations
    search_dirs = [
        Path(r"C:\antigravity-acp"),
        Path.home() / ".local" / "share" / "antigravity-acp",
        Path.home() / "antigravity-acp",
        Path.home() / ".gemini" / "antigravity-acp",
    ]
    for sdir in search_dirs:
        for name in bin_names:
            candidate = sdir / name
            if candidate.exists():
                return candidate

    # 3. Check PATH
    for name in bin_names:
        which_path = shutil.which(name)
        if which_path and Path(which_path).exists():
            return Path(which_path)

    # 4. Check Zed cache on Windows
    if sys.platform == "win32":
        local_app = os.environ.get("LOCALAPPDATA", r"C:\Users\User\AppData\Local")
        zed_cache = Path(local_app) / "Zed" / "external_agents" / "registry" / "antigravity-acp"
        if zed_cache.exists():
            exes = sorted(zed_cache.glob("*/agy_acp_server.exe"))
            if exes:
                return exes[-1]

    # 5. Check parent directories
    curr = BASE_DIR
    for _ in range(3):
        curr = curr.parent
        for name in bin_names:
            candidate = curr / name
            if candidate.exists():
                return candidate

    return BASE_DIR / ("agy_acp_server.exe" if sys.platform == "win32" else "agy_acp_server.par")


def log_debug(msg: str):
    """Debug logger to inspect bridge communication."""
    try:
        if LOG_FILE.exists() and LOG_FILE.stat().st_size > MAX_LOG_SIZE:
            LOG_FILE.unlink(missing_ok=True)
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(f"[{threading.current_thread().name}] {msg}\n")
    except Exception:
        pass


def read_file_slice(file_path: str, start_line: Optional[int] = None, end_line: Optional[int] = None) -> Optional[str]:
    """Reads specific line slice of a file safely from disk."""
    if not file_path or not os.path.isfile(file_path):
        return None
    try:
        file_size = os.path.getsize(file_path)
        if file_size > 20 * 1024 * 1024:
            # For very large files, stream line by line
            lines: List[str] = []
            with open(file_path, "r", encoding="utf-8", errors="replace") as f:
                for idx, line in enumerate(f, start=1):
                    if start_line and idx < start_line:
                        continue
                    if end_line and idx > end_line:
                        break
                    lines.append(line)
                    if len(lines) >= MAX_CONTENT_LINES:
                        lines.append("\n... [truncated: file slice exceeds limit] ...\n")
                        break
            return "".join(lines)
        else:
            with open(file_path, "r", encoding="utf-8", errors="replace") as f:
                all_lines = f.readlines()
            s_idx = max(0, start_line - 1) if (start_line and start_line > 0) else 0
            e_idx = end_line if (end_line and end_line > 0) else len(all_lines)
            selected = all_lines[s_idx:e_idx]
            if len(selected) > MAX_CONTENT_LINES:
                selected = selected[:MAX_CONTENT_LINES]
                selected.append("\n... [truncated: file slice exceeds limit] ...\n")
            res = "".join(selected)
            if len(res) > MAX_CONTENT_CHARS:
                res = res[:MAX_CONTENT_CHARS] + "\n... [truncated] ...\n"
            return res
    except Exception as e:
        log_debug(f"read_file_slice error for {file_path}: {e}")
        return None


def generate_unified_diff(old_str: Optional[str], new_str: Optional[str], file_path: Optional[str] = None, start_line: Optional[int] = None, base_dir: Optional[str] = None) -> str:
    """Generates standard unified diff string compatible with Paseo parseUnifiedDiff."""
    old_text = old_str or ""
    new_text = new_str or ""
    old_lines = old_text.splitlines() if old_text else []
    new_lines = new_text.splitlines() if new_text else []

    if file_path:
        try:
            if base_dir:
                clean_path = os.path.relpath(file_path, base_dir)
            else:
                clean_path = os.path.basename(file_path)
        except Exception:
            clean_path = os.path.basename(file_path)
        clean_path = clean_path.lstrip("/")
    else:
        clean_path = "file"

    diff = list(difflib.unified_diff(
        old_lines,
        new_lines,
        fromfile=f"a/{clean_path}",
        tofile=f"b/{clean_path}",
        lineterm=""
    ))

    s_line = start_line if (start_line and start_line > 0) else 1
    if not diff:
        return f"--- a/{clean_path}\n+++ b/{clean_path}\n@@ -{s_line},1 +{s_line},1 @@\n {old_text}\n"

    # Ensure header exists
    has_header = any(line.startswith("@@") for line in diff)
    if not has_header:
        diff.insert(2, f"@@ -{s_line},{len(old_lines)} +{s_line},{len(new_lines)} @@")

    return "\n".join(diff) + "\n"


def discover_skills(cwd: Optional[str] = None) -> Dict[str, str]:
    """Discovers workspace and global Antigravity skills from SKILL.md files."""
    skills: Dict[str, str] = {}
    search_dirs: List[Path] = []

    if cwd:
        p_cwd = Path(cwd)
        search_dirs.extend([
            p_cwd / ".agents" / "skills",
            p_cwd / ".agent" / "skills",
            p_cwd / ".gemini" / "skills",
        ])

    candidates: List[Path] = [Path.home() / ".gemini"]

    user_prof = os.environ.get("USERPROFILE")
    if user_prof:
        candidates.append(Path(user_prof) / ".gemini")

    if os.path.isdir("/mnt/c/Users"):
        for u in Path("/mnt/c/Users").iterdir():
            cand = u / ".gemini"
            if cand.is_dir():
                candidates.append(cand)

    for g_dir in candidates:
        if not g_dir.is_dir():
            continue
        search_dirs.extend([
            g_dir / "antigravity-cli" / "builtin" / "skills",
            g_dir / "antigravity-cli" / "skills",
            g_dir / "antigravity" / "builtin" / "skills",
            g_dir / "config" / "skills",
        ])
        for plug_parent in [g_dir / "antigravity-cli" / "plugins", g_dir / "extensions"]:
            if plug_parent.is_dir():
                for p in plug_parent.iterdir():
                    if (p / "skills").is_dir():
                        search_dirs.append(p / "skills")
                    if (p / "workflow-skills").is_dir():
                        search_dirs.append(p / "workflow-skills")

    for sdir in search_dirs:
        if not sdir.is_dir():
            continue
        for skill_md in sdir.glob("**/SKILL.md"):
            try:
                name = skill_md.parent.name
                desc = f"Skill: {name}"
                with open(skill_md, "r", encoding="utf-8", errors="replace") as f:
                    lines = f.readlines()
                in_front = False
                desc_lines = []
                collecting_desc = False
                for line in lines:
                    sline = line.strip()
                    if sline == "---":
                        if in_front:
                            break
                        in_front = True
                        continue
                    if in_front:
                        if sline.startswith("name:"):
                            collecting_desc = False
                            val = sline.split("name:", 1)[1].strip().strip("\"'")
                            if val:
                                name = val
                        elif sline.startswith("description:"):
                            val = sline.split("description:", 1)[1].strip().strip("\"'").lstrip(">-").strip()
                            desc_lines = [val] if val else []
                            collecting_desc = True
                        elif collecting_desc:
                            if line.startswith("  ") or line.startswith("\t"):
                                desc_lines.append(sline)
                            else:
                                collecting_desc = False
                if desc_lines:
                    clean_desc = " ".join(desc_lines).strip()
                    if clean_desc:
                        desc = clean_desc
                safe_name = re.sub(r"[^a-zA-Z0-9_-]", "_", name)
                if safe_name and safe_name not in skills:
                    skills[safe_name] = desc[:150]
            except Exception as e:
                log_debug(f"Error reading skill {skill_md}: {e}")

    return skills


class AcpBridge:
    def __init__(self, server_args):
        self.server_args = server_args
        self.active_tool_calls: Dict[str, Dict[str, Any]] = {}
        self.pending_cwds: Dict[Any, str] = {}  # req_id -> cwd
        self.session_cwds: Dict[str, str] = {}  # sessionId -> cwd
        self.skills_cache: Dict[str, Dict[str, str]] = {}  # cwd -> {name: desc}
        self.active_session_id: Optional[str] = None
        self.default_cwd: str = os.getcwd()
        self.lock = threading.Lock()
        self.proc: Optional[subprocess.Popen] = None

    def get_skills(self, session_id: Optional[str] = None) -> Dict[str, str]:
        """Retrieves or discovers skills available for the session."""
        cwd = self.get_session_cwd(session_id)
        with self.lock:
            if cwd in self.skills_cache:
                return self.skills_cache[cwd]
        skills = discover_skills(cwd)
        with self.lock:
            self.skills_cache[cwd] = skills
        return skills

    def get_session_cwd(self, session_id: Optional[str] = None) -> str:
        """Returns the current working directory associated with the session."""
        with self.lock:
            if session_id and session_id in self.session_cwds:
                return self.session_cwds[session_id]
            if self.active_session_id and self.active_session_id in self.session_cwds:
                return self.session_cwds[self.active_session_id]
            if self.default_cwd:
                return self.default_cwd
            return os.getcwd()

    def resolve_path(self, file_path: Optional[str], session_id: Optional[str] = None) -> Optional[str]:
        """Resolves relative file path against session cwd or working directory."""
        if not file_path:
            return file_path

        # Normalize slashes for current OS
        clean_path = file_path.replace("/", os.sep).replace("\\", os.sep)
        if os.path.isabs(clean_path):
            return clean_path

        session_cwd = self.get_session_cwd(session_id)
        if session_cwd:
            cand = os.path.join(session_cwd, clean_path)
            if os.path.exists(cand):
                return os.path.abspath(cand)

        cwd_cand = os.path.join(os.getcwd(), clean_path)
        if os.path.exists(cwd_cand):
            return os.path.abspath(cwd_cand)

        if session_cwd:
            return os.path.abspath(os.path.join(session_cwd, clean_path))
        return clean_path

    def start_server(self):
        env = os.environ.copy()
        env["PYTHONUNBUFFERED"] = "1"

        if HARNESS_BIN.exists() and not os.access(HARNESS_BIN, os.X_OK):
            try:
                HARNESS_BIN.chmod(0o755)
            except Exception:
                pass

        if LIB_IPV4_SO.exists():
            existing = env.get("LD_PRELOAD", "")
            env["LD_PRELOAD"] = f"{LIB_IPV4_SO}:{existing}" if existing else str(LIB_IPV4_SO)

        server_bin = find_server_binary()
        cmd = [str(server_bin)]
        if str(server_bin).endswith(".par") and "--uid=" not in self.server_args:
            cmd.append("--uid=")
        cmd.extend(self.server_args)

        log_debug(f"Starting server: {' '.join(cmd)}")
        self.proc = subprocess.Popen(
            cmd,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
            bufsize=1,
            env=env,
        )
        log_debug(f"Server process started with PID: {self.proc.pid}")

    def handle_client_line(self, line: str) -> str:
        """Extracts workspace cwd, session info, and transforms skill slash commands."""
        stripped = line.strip()
        if not (stripped.startswith("{") and stripped.endswith("}")):
            return line
        try:
            msg = json.loads(line)
        except Exception:
            return line

        method = msg.get("method")
        req_id = msg.get("id")
        params = msg.get("params") or {}

        if method in ("session/new", "session/load"):
            cwd = params.get("cwd")
            if cwd:
                log_debug(f"Client {method}: cwd={cwd}, id={req_id}")
                with self.lock:
                    if req_id is not None:
                        self.pending_cwds[req_id] = cwd
                    self.default_cwd = cwd
                    sess_id = params.get("sessionId")
                    if sess_id:
                        self.session_cwds[sess_id] = cwd
                        self.active_session_id = sess_id

        elif method == "session/prompt":
            sess_id = params.get("sessionId")
            if sess_id:
                with self.lock:
                    self.active_session_id = sess_id

            prompt_blocks = params.get("prompt")
            if isinstance(prompt_blocks, list):
                skills = self.get_skills(sess_id)
                modified = False
                for block in prompt_blocks:
                    if isinstance(block, dict) and block.get("type") == "text":
                        text = block.get("text", "")
                        match = re.match(r"^/([a-zA-Z0-9_-]+)(?:\s+(.*)|\s*$)", text, re.DOTALL)
                        if match:
                            cmd_name = match.group(1)
                            rest = match.group(2) or ""
                            if cmd_name in skills:
                                block["text"] = f"Activate skill '{cmd_name}' and follow its instructions.\n\n{rest}".strip()
                                modified = True
                                log_debug(f"Transformed client prompt /{cmd_name} -> skill activation")
                if modified:
                    return json.dumps(msg, ensure_ascii=False) + "\n"

        return line

    def forward_stdin(self):
        """Forwards input from ACP client (Paseo) to agy_acp_server."""
        try:
            for line in iter(sys.stdin.readline, ""):
                if not line:
                    break
                log_debug(f">>> CLIENT: {line.strip()[:160]}")
                transformed = self.handle_client_line(line)
                if self.proc and self.proc.stdin:
                    self.proc.stdin.write(transformed)
                    self.proc.stdin.flush()
            log_debug("Client stdin reached EOF")
        except (BrokenPipeError, OSError) as e:
            log_debug(f"forward_stdin error: {e}")
        finally:
            if self.proc and self.proc.stdin:
                try:
                    self.proc.stdin.close()
                except Exception:
                    pass

    def forward_stderr(self):
        """Forwards and logs stderr from agy_acp_server."""
        try:
            if self.proc and self.proc.stderr:
                for line in iter(self.proc.stderr.readline, ""):
                    if not line:
                        break
                    log_debug(f"[SERVER STDERR] {line.strip()}")
        except Exception as e:
            log_debug(f"forward_stderr exception: {e}")

    def transform_server_line(self, line: str) -> str:
        """Inspects and enriches server output lines before passing to client."""
        log_debug(f"<<< SERVER: {line.strip()[:160]}")
        stripped = line.strip()
        if not stripped.startswith("{") or not stripped.endswith("}"):
            return line

        try:
            msg = json.loads(line)
        except Exception:
            return line

        # Check response to session/new to link sessionId with cwd
        req_id = msg.get("id")
        result = msg.get("result")
        if req_id is not None and isinstance(result, dict):
            sess_id = result.get("sessionId")
            if sess_id:
                with self.lock:
                    pending_cwd = self.pending_cwds.pop(req_id, None)
                    if pending_cwd:
                        self.session_cwds[sess_id] = pending_cwd
                        log_debug(f"Linked session {sess_id} -> cwd {pending_cwd}")
                    self.active_session_id = sess_id

        method = msg.get("method")
        if method != "session/update":
            return line

        params = msg.get("params")
        if not isinstance(params, dict):
            return line

        session_id = params.get("sessionId")
        if session_id:
            with self.lock:
                self.active_session_id = session_id

        update = params.get("update")
        if not isinstance(update, dict):
            return line

        update_type = update.get("sessionUpdate")

        # -------------------------------------------------------------
        # 0. Available Commands Update (Slash commands & Skills)
        # -------------------------------------------------------------
        if update_type == "available_commands_update":
            commands = update.get("availableCommands") or []
            existing_names = {c.get("name") for c in commands if isinstance(c, dict)}

            skills = self.get_skills(session_id)
            for skill_name, skill_desc in skills.items():
                if skill_name not in existing_names:
                    commands.append({
                        "name": skill_name,
                        "description": f"Skill: {skill_desc}",
                    })

            update["availableCommands"] = commands
            log_debug(f"Enriched availableCommands with {len(skills)} skills: {list(skills.keys())}")
            return json.dumps(msg, ensure_ascii=False)

        # -------------------------------------------------------------
        # 1. Tool Call Started: sessionUpdate == "tool_call"
        # -------------------------------------------------------------
        if update_type == "tool_call":
            tool_call_id = update.get("toolCallId")
            raw_input = update.get("rawInput")
            kind = update.get("kind")
            title = update.get("title", "")

            if not isinstance(raw_input, dict):
                raw_input = {}
                update["rawInput"] = raw_input

            locations = update.get("locations") or []
            loc_path = locations[0].get("path") if locations and isinstance(locations[0], dict) else None

            # Detection of tool category
            is_read = (
                kind == "read"
                or "view_file" in title.lower()
                or "read" in title.lower()
                or "AbsolutePath" in raw_input
            )
            is_edit = (
                kind == "edit"
                or "replace_file_content" in title.lower()
                or "edit" in title.lower()
                or "TargetContent" in raw_input
                or "ReplacementContent" in raw_input
            )
            is_write = (
                kind == "write"
                or "write_to_file" in title.lower()
                or "CodeContent" in raw_input
            )
            is_search = (
                kind == "search"
                or "grep" in title.lower()
                or "find" in title.lower()
                or "list_dir" in title.lower()
                or "DirectoryPath" in raw_input
                or "SearchPath" in raw_input
                or "SearchDirectory" in raw_input
            )
            is_exec = (
                kind == "execute"
                or "run_command" in title.lower()
                or "CommandLine" in raw_input
            )

            raw_file_path = (
                raw_input.get("AbsolutePath")
                or raw_input.get("TargetFile")
                or raw_input.get("filePath")
                or raw_input.get("path")
                or raw_input.get("file")
                or loc_path
            )

            file_path = self.resolve_path(raw_file_path, session_id) if raw_file_path else None

            start_line = (
                raw_input.get("StartLine")
                or raw_input.get("startLine")
                or raw_input.get("offset")
                or raw_input.get("line")
            )
            end_line = (
                raw_input.get("EndLine")
                or raw_input.get("endLine")
            )

            s_line_int = None
            e_line_int = None
            if start_line is not None:
                try:
                    s_line_int = int(start_line)
                except (ValueError, TypeError):
                    pass
            if end_line is not None:
                try:
                    e_line_int = int(end_line)
                except (ValueError, TypeError):
                    pass

            if is_read:
                update["kind"] = "read"
                if not update.get("name"):
                    update["name"] = "read"

                if file_path:
                    raw_input["filePath"] = file_path
                    raw_input["path"] = file_path
                    raw_input["file"] = file_path

                if s_line_int is not None:
                    raw_input["line"] = s_line_int
                    raw_input["offset"] = s_line_int
                    if e_line_int is not None:
                        raw_input["limit"] = max(1, e_line_int - s_line_int + 1)

                if file_path:
                    update["locations"] = [{"path": file_path, "line": s_line_int or 1}]

                # Try pre-reading file slice immediately so UI has it while running
                slice_text = read_file_slice(file_path, s_line_int, e_line_int) if file_path else None
                if slice_text is not None:
                    raw_input["content"] = slice_text
                    update["content"] = [
                        {
                            "type": "content",
                            "content": {
                                "type": "text",
                                "text": slice_text,
                            },
                        }
                    ]

                # Store for tool_call_update
                if tool_call_id:
                    with self.lock:
                        self.active_tool_calls[tool_call_id] = {
                            "type": "read",
                            "filePath": file_path,
                            "startLine": s_line_int,
                            "endLine": e_line_int,
                        }

            elif is_edit:
                update["kind"] = "edit"
                if not update.get("name"):
                    update["name"] = "edit"
                if file_path:
                    raw_input["filePath"] = file_path
                    raw_input["path"] = file_path
                    raw_input["file"] = file_path

                old_str = raw_input.get("TargetContent") or raw_input.get("oldString") or raw_input.get("oldText") or ""
                new_str = raw_input.get("ReplacementContent") or raw_input.get("newString") or raw_input.get("newText") or ""

                raw_input["oldString"] = old_str
                raw_input["oldText"] = old_str
                raw_input["newString"] = new_str
                raw_input["newText"] = new_str

                session_cwd = self.get_session_cwd(session_id)
                unified_diff = generate_unified_diff(old_str, new_str, file_path, s_line_int, base_dir=session_cwd)
                raw_input["unifiedDiff"] = unified_diff
                raw_input["diff"] = unified_diff
                raw_input["patch"] = unified_diff

                if file_path:
                    update["locations"] = [{"path": file_path, "line": s_line_int or 1}]

                # Provide both diffContent (oldText/newText) and textContent (unifiedDiff)
                update["content"] = [
                    {
                        "type": "diff",
                        "oldText": old_str,
                        "newText": new_str,
                    },
                    {
                        "type": "content",
                        "content": {
                            "type": "text",
                            "text": unified_diff,
                        },
                    },
                ]

                if tool_call_id:
                    with self.lock:
                        self.active_tool_calls[tool_call_id] = {
                            "type": "edit",
                            "filePath": file_path,
                            "oldString": old_str,
                            "newString": new_str,
                            "unifiedDiff": unified_diff,
                            "startLine": s_line_int,
                        }

            elif is_write:
                update["kind"] = "edit"
                if not update.get("name"):
                    update["name"] = "write"
                if file_path:
                    raw_input["filePath"] = file_path
                    raw_input["path"] = file_path
                    raw_input["file"] = file_path

                code = raw_input.get("CodeContent") or raw_input.get("content") or ""
                old_code = ""
                if file_path and os.path.isfile(file_path):
                    old_code = read_file_slice(file_path) or ""

                raw_input["oldString"] = old_code
                raw_input["oldText"] = old_code
                raw_input["newString"] = code
                raw_input["newText"] = code
                raw_input["content"] = code

                session_cwd = self.get_session_cwd(session_id)
                unified_diff = generate_unified_diff(old_code, code, file_path, 1, base_dir=session_cwd)
                raw_input["unifiedDiff"] = unified_diff
                raw_input["diff"] = unified_diff
                raw_input["patch"] = unified_diff

                if file_path:
                    update["locations"] = [{"path": file_path, "line": 1}]

                update["content"] = [
                    {
                        "type": "diff",
                        "oldText": old_code,
                        "newText": code,
                    },
                    {
                        "type": "content",
                        "content": {
                            "type": "text",
                            "text": unified_diff,
                        },
                    },
                ]

                if tool_call_id:
                    with self.lock:
                        self.active_tool_calls[tool_call_id] = {
                            "type": "write",
                            "filePath": file_path,
                            "oldString": old_code,
                            "newString": code,
                            "unifiedDiff": unified_diff,
                        }

            elif is_search:
                update["kind"] = "search"
                if not update.get("name"):
                    update["name"] = "search"
                query = (
                    raw_input.get("Query")
                    or raw_input.get("query")
                    or raw_input.get("Pattern")
                    or raw_input.get("pattern")
                )
                search_dir = (
                    raw_input.get("SearchPath")
                    or raw_input.get("SearchDirectory")
                    or raw_input.get("DirectoryPath")
                    or raw_input.get("directory_path")
                )
                resolved_dir = self.resolve_path(search_dir, session_id) if search_dir else None
                if query:
                    raw_input["query"] = query
                    raw_input["pattern"] = query
                if resolved_dir:
                    raw_input["path"] = resolved_dir

            elif is_exec:
                update["kind"] = "execute"
                if not update.get("name"):
                    update["name"] = "execute"
                cmd = raw_input.get("CommandLine") or raw_input.get("command")
                cwd = raw_input.get("Cwd") or raw_input.get("cwd")
                resolved_cwd = self.resolve_path(cwd, session_id) if cwd else self.get_session_cwd(session_id)
                if cmd:
                    raw_input["command"] = cmd
                if resolved_cwd:
                    raw_input["cwd"] = resolved_cwd

            return json.dumps(msg, ensure_ascii=False)

        # -------------------------------------------------------------
        # 2. Tool Call Finished: sessionUpdate == "tool_call_update"
        # -------------------------------------------------------------
        elif update_type == "tool_call_update":
            tool_call_id = update.get("toolCallId")
            status = update.get("status")

            tool_info = None
            if tool_call_id:
                with self.lock:
                    if status in ("completed", "failed"):
                        tool_info = self.active_tool_calls.pop(tool_call_id, None)
                    else:
                        tool_info = self.active_tool_calls.get(tool_call_id)

            if tool_info and status == "completed":
                tool_type = tool_info.get("type")

                if tool_type == "read":
                    file_path = tool_info.get("filePath")
                    start_l = tool_info.get("startLine")
                    end_l = tool_info.get("endLine")

                    content = read_file_slice(file_path, start_l, end_l)
                    if content is None and file_path:
                        content = f"(File could not be read from disk: {file_path})"

                    if content is not None:
                        raw_out = update.get("rawOutput")
                        if not isinstance(raw_out, dict):
                            raw_out = {}
                        raw_out["content"] = content
                        raw_out["text"] = content
                        raw_out["output"] = content
                        raw_out["description"] = f"Read {file_path}"
                        update["rawOutput"] = raw_out
                        update["content"] = [
                            {
                                "type": "content",
                                "content": {
                                    "type": "text",
                                    "text": content,
                                },
                            }
                        ]

                elif tool_type in ("edit", "write"):
                    old_str = tool_info.get("oldString", "")
                    new_str = tool_info.get("newString", "")
                    diff_text = tool_info.get("unifiedDiff", "")

                    # Always ensure diffContent and unifiedDiff text are preserved
                    update["content"] = [
                        {
                            "type": "diff",
                            "oldText": old_str,
                            "newText": new_str,
                        },
                        {
                            "type": "content",
                            "content": {
                                "type": "text",
                                "text": diff_text,
                            },
                        },
                    ]
                    raw_out = update.get("rawOutput")
                    if not isinstance(raw_out, dict):
                        raw_out = {}
                    raw_out["oldString"] = old_str
                    raw_out["newString"] = new_str
                    raw_out["unifiedDiff"] = diff_text
                    raw_out["diff"] = diff_text
                    raw_out["patch"] = diff_text
                    update["rawOutput"] = raw_out

            return json.dumps(msg, ensure_ascii=False)

        return line

    def run(self) -> int:
        self.start_server()
        if not self.proc:
            return 1

        t_in = threading.Thread(target=self.forward_stdin, daemon=True, name="ClientToBridge")
        t_in.start()

        t_err = threading.Thread(target=self.forward_stderr, daemon=True, name="ServerStderr")
        t_err.start()

        def handle_signal(sig, _frame):
            log_debug(f"Received signal {sig}, terminating server...")
            if self.proc:
                try:
                    self.proc.terminate()
                except Exception:
                    pass
            sys.exit(0)

        try:
            signal.signal(signal.SIGINT, handle_signal)
            if hasattr(signal, "SIGTERM"):
                signal.signal(signal.SIGTERM, handle_signal)
        except Exception:
            pass

        try:
            for line in iter(self.proc.stdout.readline, ""):
                if not line:
                    break
                transformed = self.transform_server_line(line)
                sys.stdout.write(transformed if transformed.endswith("\n") else transformed + "\n")
                sys.stdout.flush()
            log_debug(f"Server stdout reached EOF, returncode={self.proc.poll()}")
        except (BrokenPipeError, OSError) as e:
            log_debug(f"Client stdout pipe error: {e}")
        finally:
            if self.proc:
                try:
                    self.proc.wait(timeout=2)
                except Exception:
                    try:
                        self.proc.kill()
                    except Exception:
                        pass

        return self.proc.returncode if self.proc and self.proc.returncode is not None else 0


def main():
    bridge = AcpBridge(sys.argv[1:])
    sys.exit(bridge.run())


if __name__ == "__main__":
    main()
