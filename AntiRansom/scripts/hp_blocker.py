# hp_block_min.py  (pode salvar como hp_blocker.py)
# Lê NDJSON do detector (kernel/sysmon + security), identifica PID e bloqueia/quarentena.
# Novidade: trata "honeypot_deny" (Security 4656) além de "honeypot_watch".

import os, sys, json, time, shutil, ctypes, subprocess, argparse
from ctypes import wintypes
from pathlib import Path
from datetime import datetime

APP_DIR     = Path(os.environ.get("PROGRAMDATA", r"C:\ProgramData")) / "AntiRansom"
LOG_DIR     = APP_DIR / "logs"
QUAR_DIR    = APP_DIR / "quarantine"
BLOCKER_LOG = APP_DIR / "blocker_min.log"

CHANNEL_SYSMON = "Microsoft-Windows-Sysmon/Operational"
POWERSHELL     = "powershell"
HONEYPOT_PREFIX= "~$sys_"
PARENT_QUAR_SCRIPT = str(Path(__file__).with_name("hp_parent_quarantine.py"))

for d in (APP_DIR, LOG_DIR, QUAR_DIR):
    d.mkdir(parents=True, exist_ok=True)

def log(msg: str):
    ts = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
    line = f"[{ts}] {msg}"
    print(line, flush=True)
    try:
        with open(BLOCKER_LOG, "a", encoding="utf-8") as f:
            f.write(line + "\n")
    except Exception:
        pass

def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except Exception:
        return False

# --- WinAPI suspender/matar ---
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

def suspend_pid(pid: int) -> bool:
    try:
        h = OpenProcess(PROCESS_SUSPEND_RESUME, False, pid)
        if not h: return False
        try: return NtSuspendProcess(h) == 0
        finally: CloseHandle(h)
    except Exception: return False

def kill_pid(pid: int) -> bool:
    try:
        h = OpenProcess(PROCESS_TERMINATE, False, pid)
        if not h: return False
        try: return NtTerminateProcess(h, 1) == 0
        finally: CloseHandle(h)
    except Exception: return False

def force_taskkill(pid: int) -> bool:
    try:
        r = subprocess.run(["taskkill","/PID",str(pid),"/F","/T"], capture_output=True, text=True, timeout=6)
        return r.returncode == 0
    except Exception: return False

def get_process_path(pid: int) -> str|None:
    try:
        ps = f"(Get-Process -Id {pid} -ErrorAction SilentlyContinue).Path"
        r = subprocess.run([POWERSHELL,"-NoProfile","-Command", ps], capture_output=True, text=True, timeout=5)
        s = (r.stdout or "").strip()
        return s if s else None
    except Exception: return None

rstrtmgr = ctypes.WinDLL("rstrtmgr")
CCH_RM_MAX_APP_NAME = 255
CCH_RM_MAX_SVC_NAME = 63
RM_SESSION_KEY_LEN  = 16

class FILETIME(ctypes.Structure):
    _fields_ = [("dwLowDateTime", wintypes.DWORD), ("dwHighDateTime", wintypes.DWORD)]
class RM_UNIQUE_PROCESS(ctypes.Structure):
    _fields_ = [("dwProcessId", wintypes.DWORD), ("ProcessStartTime", FILETIME)]
class RM_PROCESS_INFO(ctypes.Structure):
    _fields_ = [("Process", RM_UNIQUE_PROCESS),
                ("strAppName", wintypes.WCHAR * (CCH_RM_MAX_APP_NAME + 1)),
                ("strServiceShortName", wintypes.WCHAR * (CCH_RM_MAX_SVC_NAME + 1)),
                ("ApplicationType", wintypes.DWORD),
                ("AppStatus", wintypes.DWORD),
                ("TSSessionId", wintypes.DWORD),
                ("bRestartable", wintypes.BOOL)]

RmStartSessionW = rstrtmgr.RmStartSession
RmRegisterResourcesW = rstrtmgr.RmRegisterResources
RmGetListW = rstrtmgr.RmGetList
RmEndSessionW = rstrtmgr.RmEndSession
RmStartSessionW.argtypes = [ctypes.POINTER(wintypes.DWORD), wintypes.DWORD, wintypes.WCHAR * (RM_SESSION_KEY_LEN + 1)]
RmRegisterResourcesW.argtypes = [wintypes.DWORD, wintypes.UINT, ctypes.POINTER(wintypes.LPCWSTR),
                                 wintypes.UINT, ctypes.POINTER(RM_UNIQUE_PROCESS),
                                 wintypes.UINT, ctypes.POINTER(wintypes.LPCWSTR)]
RmGetListW.argtypes = [wintypes.DWORD, ctypes.POINTER(wintypes.UINT), ctypes.POINTER(wintypes.UINT),
                       ctypes.POINTER(RM_PROCESS_INFO), ctypes.POINTER(wintypes.DWORD)]
RmEndSessionW.argtypes = [wintypes.DWORD]

def rm_pids_for_file(path: str, retries=8, delay=0.20) -> list[int]:
    pids: set[int] = set()
    u16_key = (wintypes.WCHAR * (RM_SESSION_KEY_LEN + 1))()
    for _ in range(retries):
        sess = wintypes.DWORD(0); started=False
        try:
            if RmStartSessionW(ctypes.byref(sess), 0, u16_key) != 0:
                time.sleep(delay); continue
            started=True
            arr = (wintypes.LPCWSTR * 1)(); arr[0] = ctypes.c_wchar_p(path)
            if RmRegisterResourcesW(sess, 1, arr, 0, None, 0, None) != 0:
                continue
            needed = wintypes.UINT(0); count = wintypes.UINT(0); rr = wintypes.DWORD(0)
            RmGetListW(sess, ctypes.byref(needed), ctypes.byref(count), None, ctypes.byref(rr))
            n = needed.value
            if n:
                info = (RM_PROCESS_INFO * n)()
                count = wintypes.UINT(n)
                if RmGetListW(sess, ctypes.byref(needed), ctypes.byref(count), info, ctypes.byref(rr)) == 0:
                    for i in range(count.value):
                        pids.add(info[i].Process.dwProcessId)
        finally:
            if started:
                try: RmEndSessionW(sess)
                except Exception: pass
        if pids: break
        time.sleep(delay)
    return sorted(pids)

def _escape_xpath_literal(s: str) -> str:
    if "'" not in s: return f"'{s}'"
    parts = s.split("'")
    return "concat(" + ", ".join([f"'{p}'" for p in parts[:-1]] + ["\"'\"", f"'{parts[-1]}'"]) + ")"

def sysmon_pid_by_file(filepath: str, max_events: int = 80) -> int|None:
    esc = _escape_xpath_literal(filepath)
    xpath = f"*[System[(EventID=11 or EventID=23)]][EventData[Data[@Name='TargetFilename']={esc}]]"
    ps = f"""
$e = Get-WinEvent -LogName '{CHANNEL_SYSMON}' -FilterXPath "{xpath}" -ErrorAction SilentlyContinue `
     -MaxEvents {max_events} | Sort-Object RecordId -Descending | Select-Object -First 1
if ($e) {{
  try {{ $x=[xml]$e.ToXml(); ($x.Event.EventData.Data | Where-Object {{$_.Name -eq 'ProcessId'}}).'#text' }} catch {{ '' }}
}} else {{ '' }}
"""
    try:
        r = subprocess.run([POWERSHELL,"-NoProfile","-Command", ps], capture_output=True, text=True, timeout=8)
        s = (r.stdout or "").strip()
        return int(s) if s.isdigit() else None
    except Exception: return None

def latest_ndjson() -> Path|None:
    try:
        files = sorted(LOG_DIR.glob("events-*.ndjson"))
        return files[-1] if files else None
    except Exception:
        return None

def follow(path: Path):
    with open(path, "r", encoding="utf-8") as f:
        f.seek(0, os.SEEK_END)
        while True:
            line = f.readline()
            if not line: time.sleep(0.20); continue
            yield line

def quarantine_exe(exe: str, pid: int) -> str|None:
    try:
        exe_p = Path(exe)
        dst = QUAR_DIR / f"{exe_p.name}.pid{pid}.{int(time.time())}.copy"
        shutil.copy2(exe_p, dst)
        return str(dst)
    except Exception:
        return None

def act_block_and_quarantine(pid: int, kill: bool):
    ok_s = suspend_pid(pid); log(f"    suspend({pid})={ok_s}")
    if kill:
        ok_k = kill_pid(pid); log(f"    kill({pid})={ok_k}")
        if not ok_k:
            ok_tk = force_taskkill(pid); log(f"    taskkill({pid})={ok_tk}")
    exe = get_process_path(pid)
    if exe:
        q = quarantine_exe(exe, pid)
        log(f"    quarantine: {'OK -> ' + q if q else 'FALHOU'}")
    else:
        log(f"    quarantine: ignorado (exe não encontrado)")

def main():
    ap = argparse.ArgumentParser(description="Bloqueia/quarentena com base no NDJSON dos detectores.")
    ap.add_argument("--kill", action="store_true", help="encerra o processo após suspender")
    ap.add_argument("--log", default="", help="caminho do NDJSON; vazio => último em ProgramData\\AntiRansom\\logs")
    args = ap.parse_args()

    if not is_admin():
        log("[!] Execute como Administrador.")

    nd = Path(args.log) if args.log else latest_ndjson()
    if not nd or not nd.exists():
        log("[!] NDJSON não encontrado. Rode hp_detect_kernel.py e hp_detect_security.py.")
        return

    log(f"[*] Seguindo: {nd}")
    acted_pids: set[int] = set()
    acted_files: set[str] = set()

    for line in follow(nd):
        try:
            evt = json.loads(line)
        except Exception:
            continue

        et = evt.get("type")
        if et not in ("honeypot_watch", "honeypot_deny"):
            continue

        path = evt.get("file") or ""
        kind = (evt.get("event") or "").lower()
        base = os.path.basename(path)

        pid = int(evt.get("pid") or 0)
        if pid and pid not in acted_pids:
            acted_pids.add(pid)
            if path: acted_files.add(path)
            log(f"[!] DENY {kind} {path} -> PID {pid} (Security)")
            act_block_and_quarantine(pid, args.kill)
            try:
                subprocess.Popen([sys.executable, PARENT_QUAR_SCRIPT, "--pid", str(pid), "--depth","2", "--suspend", "--kill"],
                                 creationflags=0x00000008)
                log(f"[i] parent_quarantine disparado para PID {pid}")
            except Exception as e:
                log(f"[!] Falha parent_quarantine: {e}")
            continue

        if et == "honeypot_watch":
            candidates = []
            enc = path + ".encrypted"
            if os.path.exists(enc): candidates.append(enc)
            if kind in ("created","modified") and os.path.exists(path): candidates.append(path)
            if not candidates: candidates = [enc, path]

            pid_found = None
            for t in candidates:
                if not t: continue
                pids = rm_pids_for_file(t, retries=8, delay=0.20)
                if pids:
                    pid_found = next((p for p in pids if p not in acted_pids), None)
                    if pid_found is not None:
                        log(f"[!] RM  {kind} {t} -> PID {pid_found}")
                        break
            if pid_found is None:
                for t in candidates:
                    if not t: continue
                    p = sysmon_pid_by_file(t, max_events=80)
                    if p and p not in acted_pids:
                        pid_found = p
                        log(f"[!] RES {kind} {t} -> PID {pid_found} (Sysmon)")
                        break
            if pid_found is not None:
                acted_pids.add(pid_found)
                if path: acted_files.add(path)
                act_block_and_quarantine(pid_found, args.kill)
                try:
                    subprocess.Popen([sys.executable, PARENT_QUAR_SCRIPT, "--pid", str(pid_found), "--depth","2", "--suspend", "--kill"],
                                     creationflags=0x00000008)
                    log(f"[i] parent_quarantine disparado para PID {pid_found}")
                except Exception as e:
                    log(f"[!] Falha parent_quarantine: {e}")
            else:
                log(f"[i] sem PID: {kind} {path}")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        log("[*] Encerrado pelo usuário.")
    except Exception as e:
        log(f"[!] Erro fatal: {e}")
