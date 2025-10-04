# hp_parent_quarantine.py
# Recebe um PID, resolve os pais (PPID, avôs, etc.), e coloca os executáveis dos pais em quarentena.
# Opcionalmente atua também no próprio PID (--include-self) e pode suspender/kill antes de copiar.
#
# Uso típico:
#   py -3.11 hp_parent_quarantine.py --pid 1234 --depth 3 --suspend --kill
#   py -3.11 hp_parent_quarantine.py --stdin             (lê PIDs de stdin, um por linha ou JSON {"pid": N})
#
# Log: C:\ProgramData\AntiRansom\parent_quarantine.log
# Quarentena: C:\ProgramData\AntiRansom\quarantine

import os, sys, json, time, shutil, ctypes, subprocess, argparse, re
from pathlib import Path
from datetime import datetime
from ctypes import wintypes

APP_DIR      = Path(os.environ.get("PROGRAMDATA", r"C:\ProgramData")) / "AntiRansom"
QUAR_DIR     = APP_DIR / "quarantine"
LOG_PATH     = APP_DIR / "parent_quarantine.log"
POWERSHELL   = "powershell"

# Proteções para evitar dano acidental
DEFAULT_WHITELIST = {
    "system", "system idle process",
    "smss.exe","csrss.exe","wininit.exe","winlogon.exe","services.exe","lsass.exe","svchost.exe",
    "explorer.exe","conhost.exe","taskhostw.exe","sihost.exe",
    "cmd.exe","powershell.exe","pwsh.exe","python.exe","pythonw.exe"
}

# --- infra básica ---
for d in (APP_DIR, QUAR_DIR):
    d.mkdir(parents=True, exist_ok=True)

def log(msg: str):
    ts = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
    line = f"[{ts}] {msg}"
    print(line, flush=True)
    try:
        with open(LOG_PATH, "a", encoding="utf-8") as f:
            f.write(line + "\n")
    except Exception:
        pass

def is_admin():
    try: return ctypes.windll.shell32.IsUserAnAdmin()
    except Exception: return False

# --- WinAPI: suspender/matar (opcional) ---
kernel32 = ctypes.windll.kernel32
ntdll    = ctypes.windll.ntdll

PROCESS_SUSPEND_RESUME = 0x0800
PROCESS_TERMINATE      = 0x0001

OpenProcess = kernel32.OpenProcess
OpenProcess.argtypes = [ctypes.c_uint32, ctypes.c_int, ctypes.c_uint32]
OpenProcess.restype  = ctypes.c_void_p

CloseHandle = kernel32.CloseHandle
CloseHandle.argtypes = [ctypes.c_void_p]
CloseHandle.restype  = ctypes.c_int

NtSuspendProcess = ntdll.NtSuspendProcess
NtSuspendProcess.argtypes = [ctypes.c_void_p]
NtSuspendProcess.restype  = ctypes.c_ulong

NtTerminateProcess = ntdll.NtTerminateProcess
NtTerminateProcess.argtypes = [ctypes.c_void_p, ctypes.c_ulong]
NtTerminateProcess.restype  = ctypes.c_ulong

def suspend_pid(pid: int) -> tuple[bool,str]:
    try:
        h = OpenProcess(PROCESS_SUSPEND_RESUME, False, pid)
        if not h: return False, "OpenProcess falhou"
        try:
            rc = NtSuspendProcess(h)
            return (rc == 0), f"NtSuspend rc={rc}"
        finally:
            CloseHandle(h)
    except Exception as e:
        return False, f"exc:{e}"

def kill_pid(pid: int) -> tuple[bool,str]:
    try:
        h = OpenProcess(PROCESS_TERMINATE, False, pid)
        if not h: return False, "OpenProcess falhou"
        try:
            rc = NtTerminateProcess(h, 1)
            return (rc == 0), f"NtTerminate rc={rc}"
        finally:
            CloseHandle(h)
    except Exception as e:
        return False, f"exc:{e}"

def force_taskkill(pid: int) -> tuple[bool,str]:
    try:
        r = subprocess.run(["taskkill","/PID",str(pid),"/F","/T"],
                           capture_output=True, text=True, timeout=6)
        return (r.returncode == 0), (r.stdout.strip() or r.stderr.strip())
    except Exception as e:
        return False, f"exc:{e}"

# --- Helpers PowerShell ---
def get_process_info(pid: int) -> dict:
    """Retorna dict com Pid, PPid, Path, Cmd, User (via CIM)."""
    ps = f"""
$pid = {pid}
try {{
  $cur = Get-CimInstance Win32_Process -Filter ("ProcessId = " + $pid) -ErrorAction SilentlyContinue
  if (-not $cur) {{ "" | ConvertTo-Json -Compress; exit }}
  $usr = $null
  try {{
    $o = Invoke-CimMethod -InputObject $cur -MethodName GetOwner
    if ($o) {{ $usr = $o.Domain + '\\\\' + $o.User }}
  }} catch {{}}
  [pscustomobject]@{{
    Pid  = $cur.ProcessId
    PPid = $cur.ParentProcessId
    Path = $cur.ExecutablePath
    Cmd  = $cur.CommandLine
    User = $usr
  }} | ConvertTo-Json -Compress
}} catch {{ "" }}
"""
    try:
        r = subprocess.run([POWERSHELL,"-NoProfile","-Command", ps],
                           capture_output=True, text=True, timeout=6)
        if r.returncode != 0 or not r.stdout.strip(): return {}
        d = json.loads(r.stdout)
        if not isinstance(d, dict): return {}
        return {
            "Pid": int(d.get("Pid") or 0),
            "PPid": int(d.get("PPid") or 0),
            "Path": d.get("Path") or "",
            "Cmd": d.get("Cmd") or "",
            "User": d.get("User") or ""
        }
    except Exception:
        return {}

def get_ancestry(pid: int, depth: int) -> list[dict]:
    """Lista [child, parent, grandparent, ...] até 'depth' níveis (inclui o próprio se include_self=True)."""
    chain = []
    cur = get_process_info(pid)
    for _ in range(max(1, depth)):
        if not cur or not cur.get("Pid"): break
        chain.append(cur)
        ppid = int(cur.get("PPid") or 0)
        if ppid <= 0: break
        cur = get_process_info(ppid)
    return chain

def sha256_file(p: Path) -> str:
    import hashlib
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()

def quarantine_file(src: Path, tag_pid: int) -> tuple[bool,str]:
    try:
        ts = datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
        dst = QUAR_DIR / f"{src.name}.parent.pid{tag_pid}.{ts}.copy"
        shutil.copy2(src, dst)
        meta = {
            "src": str(src), "dst": str(dst),
            "sha256": sha256_file(dst),
            "ts": ts, "from_pid": tag_pid
        }
        (QUAR_DIR / (dst.name + ".meta.json")).write_text(json.dumps(meta, indent=2), encoding="utf-8")
        return True, str(dst)
    except Exception as e:
        return False, f"exc:{e}"

# --- política de atuação ---
def should_skip_image(path: str, no_whitelist: bool) -> bool:
    if no_whitelist: return False
    base = (Path(path).name if path else "").lower()
    return base in DEFAULT_WHITELIST

def act_quarantine_chain(root_pid: int, depth: int, include_self: bool,
                         suspend: bool, kill: bool, no_whitelist: bool):
    chain = get_ancestry(root_pid, depth=max(1, depth + (1 if include_self else 0)))
    if not chain:
        log(f"[!] PID {root_pid}: não encontrado")
        return

    # se não incluir self, remove o primeiro (o próprio PID passado)
    targets = chain if include_self else chain[1:]

    log(f"[*] Cadeia até {depth} (include_self={include_self}):")
    for i, p in enumerate(chain):
        log(f"    {'*' if i==0 else ' '} Pid={p['Pid']} PPid={p['PPid']} User={p['User']} Path={p['Path'] or '?'}")
        if p.get("Cmd"): log(f"      Cmd={p['Cmd']}")

    for p in targets:
        pid = int(p.get("Pid") or 0)
        path = p.get("Path") or ""
        base = (Path(path).name if path else "").lower()

        if not pid:
            continue

        if path and should_skip_image(path, no_whitelist):
            log(f"    - SKIP {pid} ({base}) [whitelist]")
            continue

        if suspend:
            ok, msg = suspend_pid(pid)
            log(f"    - suspend({pid}): {ok} ({msg})")
        if kill:
            ok, msg = kill_pid(pid)
            log(f"    - kill({pid}): {ok} ({msg})")
            if not ok:
                ok2, msg2 = force_taskkill(pid)
                log(f"      taskkill({pid}): {ok2} ({msg2})")

        if path:
            okq, msgq = quarantine_file(Path(path), tag_pid=root_pid)
            log(f"    - quarantine({base}): {okq} ({msgq})")
        else:
            log(f"    - quarantine: ignorada (sem caminho) pid={pid}")

# --- CLI / integração ---
def parse_pid_from_line(line: str) -> int|None:
    line = line.strip()
    if not line: return None
    # número puro
    if re.fullmatch(r"\d+", line):
        return int(line)
    # tenta JSON com chave "pid"
    try:
        obj = json.loads(line)
        if isinstance(obj, dict) and "pid" in obj and isinstance(obj["pid"], int):
            return obj["pid"]
    except Exception:
        pass
    return None

def main():
    ap = argparse.ArgumentParser(description="Quarentena dos pais de um PID (e opcionalmente do próprio).")
    ap.add_argument("--pid", type=int, help="PID origem (recebido do hp_blocker)")
    ap.add_argument("--stdin", action="store_true", help="ler PIDs de stdin (linhas: número ou JSON {'pid':N})")
    ap.add_argument("--depth", type=int, default=2, help="níveis de pais (default 2 = pai e avô)")
    ap.add_argument("--include-self", action="store_true", help="também atuar no próprio PID informado")
    ap.add_argument("--suspend", action="store_true", help="suspender antes de quarentenar")
    ap.add_argument("--kill", action="store_true", help="matar o processo (fallback taskkill) antes de quarentenar")
    ap.add_argument("--no-whitelist", action="store_true", help="ignora whitelist (pode impactar processos de sistema)")
    args = ap.parse_args()

    if not is_admin():
        log("[!] Execute como Administrador para suspender/matar/quarentenar com sucesso.")

    if args.stdin:
        log("[*] Lendo PIDs de STDIN… (Ctrl+C para sair)")
        for line in sys.stdin:
            pid = parse_pid_from_line(line)
            if pid is None:
                continue
            log(f"==> PID recebido: {pid}")
            act_quarantine_chain(pid, depth=args.depth, include_self=args.include_self,
                                 suspend=args.suspend, kill=args.kill, no_whitelist=args.no_whitelist)
        return

    if not args.pid:
        log("[!] Forneça --pid N ou use --stdin")
        return

    act_quarantine_chain(args.pid, depth=args.depth, include_self=args.include_self,
                         suspend=args.suspend, kill=args.kill, no_whitelist=args.no_whitelist)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        log("[*] Encerrado pelo usuário.")
    except Exception as e:
        log(f"[!] Erro fatal: {e}")
