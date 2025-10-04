# hp_detect_kernel.py
# Detector leve: Sysmon (ID 11/23) + ReadDirectoryChangesW (nativo)
# Log NDJSON: C:\ProgramData\AntiRansom\logs\events-YYYYMMDD.ndjson

import os, sys, json, time, threading, queue, subprocess, hashlib, ctypes
from ctypes import wintypes
from pathlib import Path
from datetime import datetime

APP_DIR    = Path(os.environ.get("PROGRAMDATA", r"C:\ProgramData")) / "AntiRansom"
LOG_DIR    = APP_DIR / "logs"
HP_DB_PATH = APP_DIR / "honeypots.json"
STATE_PATH = APP_DIR / "sysmon_state.json"
LOG_PATH   = LOG_DIR / f"events-{datetime.now():%Y%m%d}.ndjson"

HONEYPOT_PREFIX = "~$sys_"
SYSLOG_CHANNEL  = "Microsoft-Windows-Sysmon/Operational"
POWERSHELL      = "powershell"

MAX_PULL_PER_TICK = 400
POLL_INTERVAL    = 1.2
Q_MAXSIZE        = 2000
BUFFER_BYTES     = 64 * 1024

# ----------------- básicos -----------------
def ensure_dirs():
    APP_DIR.mkdir(parents=True, exist_ok=True)
    LOG_DIR.mkdir(parents=True, exist_ok=True)

def log_evt(evt: dict):
    evt["ts"] = time.time()
    evt["ts_iso"] = datetime.utcfromtimestamp(evt["ts"]).strftime("%Y-%m-%dT%H:%M:%SZ")
    with open(LOG_PATH, "a", encoding="utf-8") as f:
        f.write(json.dumps(evt, ensure_ascii=False) + "\n")

def load_hp_db():
    if not HP_DB_PATH.exists(): return {}
    try: return json.loads(HP_DB_PATH.read_text(encoding="utf-8"))
    except Exception: return {}

def save_state(state: dict):
    try: STATE_PATH.write_text(json.dumps(state, indent=2), encoding="utf-8")
    except Exception: pass

def load_state():
    if not STATE_PATH.exists(): return {"last_record_id": 0}
    try: return json.loads(STATE_PATH.read_text(encoding="utf-8"))
    except Exception: return {"last_record_id": 0}

def sha256_file(p: Path):
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""): h.update(chunk)
    return h.hexdigest()

# --------- tail seguro do RecordId atual ---------
def _tail_current_record_id():
    ps = f"(Get-WinEvent -LogName '{SYSLOG_CHANNEL}' -MaxEvents 1 | Select-Object -ExpandProperty RecordId)"
    try:
        r = subprocess.run([POWERSHELL,"-NoProfile","-Command", ps],
                           capture_output=True, text=True, timeout=6)
        return int((r.stdout or "0").strip() or "0")
    except Exception:
        return 0

# --------- Sysmon via FilterXPath (preciso) ---------
def sysmon_collect_since(last_record_id: int, limit=MAX_PULL_PER_TICK):
    """
    Busca eventos Sysmon (11/23) com RecordId > last_record_id usando FilterXPath (preciso),
    depois filtra em Python por prefixo dos honeypots (~$sys_).
    """
    xpath = f"*[System[(EventRecordID>{last_record_id}) and (EventID=11 or EventID=23)]]"
    ps = f"""
$evs = Get-WinEvent -LogName '{SYSLOG_CHANNEL}' -FilterXPath "{xpath}" -ErrorAction SilentlyContinue `
       -MaxEvents {limit} | Sort-Object RecordId
$result = @()
foreach($e in $evs){{
  try {{
    $x=[xml]$e.ToXml()
    $d=@{{}}; foreach($n in $x.Event.EventData.Data){{ $d[$n.Name]=$n.'#text' }}
    $result += [PSCustomObject]@{{
      RecordId=$e.RecordId
      Id=$e.Id
      TimeCreated=$e.TimeCreated.ToUniversalTime().ToString("o")
      TargetFilename=$d["TargetFilename"]
      Image=$d["Image"]
      ProcessId=$d["ProcessId"]
    }}
  }} catch {{ }}
}}
$result | ConvertTo-Json -Compress
"""
    try:
        r = subprocess.run([POWERSHELL,"-NoProfile","-Command", ps],
                           capture_output=True, text=True, timeout=12)
        if r.returncode != 0 or not r.stdout.strip():
            return [], last_record_id
        raw = json.loads(r.stdout)
        events = raw if isinstance(raw, list) else [raw]
        keep, high = [], last_record_id
        for e in events:
            rec = int(e.get("RecordId") or 0)
            if rec <= last_record_id: 
                continue
            tf = e.get("TargetFilename") or ""
            if HONEYPOT_PREFIX in os.path.basename(tf):
                keep.append(e)
            if rec > high:
                high = rec
        return keep, high
    except Exception:
        return [], last_record_id

FILE_LIST_DIRECTORY      = 0x0001
FILE_SHARE_READ          = 0x00000001
FILE_SHARE_WRITE         = 0x00000002
FILE_SHARE_DELETE        = 0x00000004
OPEN_EXISTING            = 3
FILE_FLAG_BACKUP_SEMANTICS = 0x02000000

FILE_NOTIFY_CHANGE_FILE_NAME    = 0x00000001
FILE_NOTIFY_CHANGE_DIR_NAME     = 0x00000002
FILE_NOTIFY_CHANGE_ATTRIBUTES   = 0x00000004
FILE_NOTIFY_CHANGE_SIZE         = 0x00000008
FILE_NOTIFY_CHANGE_LAST_WRITE   = 0x00000010
FILE_NOTIFY_CHANGE_SECURITY     = 0x00000100

FILE_ACTION_ADDED               = 0x00000001
FILE_ACTION_REMOVED             = 0x00000002
FILE_ACTION_MODIFIED            = 0x00000003
FILE_ACTION_RENAMED_OLD_NAME    = 0x00000004
FILE_ACTION_RENAMED_NEW_NAME    = 0x00000005

CreateFileW = ctypes.windll.kernel32.CreateFileW
CreateFileW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD,
                        wintypes.LPVOID, wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE]
CreateFileW.restype  = wintypes.HANDLE

ReadDirectoryChangesW = ctypes.windll.kernel32.ReadDirectoryChangesW
ReadDirectoryChangesW.argtypes = [wintypes.HANDLE, wintypes.LPVOID, wintypes.DWORD,
                                  wintypes.BOOL, wintypes.DWORD,
                                  ctypes.POINTER(wintypes.DWORD),
                                  wintypes.LPVOID, wintypes.LPVOID]
ReadDirectoryChangesW.restype  = wintypes.BOOL

CloseHandle = ctypes.windll.kernel32.CloseHandle
CloseHandle.argtypes = [wintypes.HANDLE]
CloseHandle.restype  = wintypes.BOOL

class DirectoryWatcher(threading.Thread):
    def __init__(self, dir_path: Path, hp_db: dict, q: queue.Queue):
        super().__init__(daemon=True)
        self.dir = dir_path
        self.hp_db = hp_db
        self.q = q
        self.stop_evt = threading.Event()
        self.handle = None

    def open_dir(self):
        h = CreateFileW(str(self.dir), FILE_LIST_DIRECTORY,
                        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                        None, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, None)
        if h == wintypes.HANDLE(-1).value:
            raise OSError(f"CreateFileW falhou: {self.dir}")
        return h

    def run(self):
        try:
            self.dir.mkdir(parents=True, exist_ok=True)
            self.handle = self.open_dir()
            buf = (ctypes.c_byte * BUFFER_BYTES)()
            while not self.stop_evt.is_set():
                bytes_ret = wintypes.DWORD(0)
                ok = ReadDirectoryChangesW(
                    self.handle, ctypes.byref(buf), ctypes.sizeof(buf), False,
                    (FILE_NOTIFY_CHANGE_FILE_NAME |
                     FILE_NOTIFY_CHANGE_SIZE |
                     FILE_NOTIFY_CHANGE_LAST_WRITE |
                     FILE_NOTIFY_CHANGE_ATTRIBUTES |
                     FILE_NOTIFY_CHANGE_SECURITY),
                    ctypes.byref(bytes_ret), None, None
                )
                if not ok:
                    time.sleep(0.2); continue

                data = bytes(buf[:bytes_ret.value])
                offset = 0
                while offset < len(data):
                    next_off = int.from_bytes(data[offset:offset+4], "little", signed=False)
                    action   = int.from_bytes(data[offset+4:offset+8], "little", signed=False)
                    name_len = int.from_bytes(data[offset+8:offset+12], "little", signed=False)
                    name_bytes = data[offset+12:offset+12+name_len]
                    try: filename = name_bytes.decode("utf-16le")
                    except Exception: filename = ""
                    fullpath = self.dir / filename

                    base = os.path.basename(str(fullpath))
                    relevant = (str(fullpath) in self.hp_db) or base.startswith(HONEYPOT_PREFIX)
                    if relevant:
                        kind = {
                            FILE_ACTION_ADDED: "created",
                            FILE_ACTION_REMOVED: "deleted",
                            FILE_ACTION_MODIFIED: "modified",
                            FILE_ACTION_RENAMED_OLD_NAME: "renamed_old",
                            FILE_ACTION_RENAMED_NEW_NAME: "renamed_new",
                        }.get(action, f"action_{action}")

                        item = {"type":"honeypot_watch","event":kind,"file":str(fullpath)}
                        if str(fullpath) in self.hp_db and os.path.exists(fullpath):
                            try:
                                h = sha256_file(fullpath)
                                item["sha256_ok"]  = (h == self.hp_db[str(fullpath)]["sha256"])
                                item["sha256_now"] = h
                            except Exception:
                                item["sha256_ok"] = None
                        try: self.q.put_nowait(item)
                        except queue.Full: pass

                    if next_off == 0: break
                    offset += next_off

        except Exception as e:
            log_evt({"type":"error","stage":"DirectoryWatcher", "dir": str(self.dir), "err": str(e)})
        finally:
            if self.handle:
                try: CloseHandle(self.handle)
                except Exception: pass

    def stop(self):
        self.stop_evt.set()

class Engine:
    def __init__(self):
        self.hp_db = load_hp_db()
        self.q = queue.Queue(maxsize=Q_MAXSIZE)
        self.stop_evt = threading.Event()
        self.state = load_state()
        self.last_record_id = int(self.state.get("last_record_id", 0))
        if self.last_record_id == 0:
            self.last_record_id = _tail_current_record_id()
        self.sysmon_thread = threading.Thread(target=self.sysmon_loop, daemon=True)
        self.proc_thread = threading.Thread(target=self.proc_loop, daemon=True)
        self.watchers = []

    def start(self):
        ensure_dirs()
        if self.hp_db:
            dirset = sorted({ Path(k).parent for k in self.hp_db.keys() })
            for d in dirset:
                try:
                    w = DirectoryWatcher(d, self.hp_db, self.q)
                    w.start(); self.watchers.append(w)
                except Exception as e:
                    log_evt({"type":"error","stage":"start_watcher","dir":str(d),"err":str(e)})
            log_evt({"type":"startup","watch_dirs":[str(d) for d in dirset]})
        else:
            log_evt({"type":"startup","warn":"honeypots.json vazio; watchers desativados"})

        self.sysmon_thread.start()
        self.proc_thread.start()
        print("[*] Detector ativo. Log:", LOG_PATH)
        print(f"[*] Sysmon RecordId inicial: {self.last_record_id}")

    def stop_all(self):
        self.stop_evt.set()
        for w in self.watchers:
            try: w.stop()
            except Exception: pass
        for w in self.watchers:
            try: w.join(timeout=1.0)
            except Exception: pass

    def sysmon_loop(self):
        while not self.stop_evt.is_set():
            try:
                batch, high = sysmon_collect_since(self.last_record_id)
                if batch:
                    self.last_record_id = high
                    save_state({"last_record_id": self.last_record_id})
                    for e in batch:
                        evt = {
                            "type":"honeypot_sysmon",
                            "record_id": int(e.get("RecordId") or 0),
                            "event": ("FileCreate" if int(e.get("Id") or 0)==11 else "FileDelete"),
                            "file":  e.get("TargetFilename") or "",
                            "pid":   int(e.get("ProcessId") or 0),
                            "image": e.get("Image") or "",
                            "derived": os.path.basename(e.get("TargetFilename") or "").startswith(HONEYPOT_PREFIX)
                        }
                        try: self.q.put_nowait(evt)
                        except queue.Full: pass
            except Exception as e:
                log_evt({"type":"error","stage":"sysmon_loop","err":str(e)})
            time.sleep(POLL_INTERVAL)

    def proc_loop(self):
        while not self.stop_evt.is_set():
            try:
                evt = self.q.get(timeout=0.5)
            except queue.Empty:
                continue
            try:
                log_evt(evt)
                if evt.get("type") == "honeypot_sysmon":
                    print(f"[SYS] {evt['event']} pid={evt['pid']} img={evt['image']} file={evt['file']}")
                elif evt.get("type") == "honeypot_watch":
                    print(f"[FS ] {evt['event']} {evt['file']} hash_ok={evt.get('sha256_ok')}")
            except Exception as e:
                log_evt({"type":"error","stage":"proc_loop","err":str(e)})

def main():
    eng = Engine()
    eng.start()
    try:
        while True: time.sleep(1)
    except KeyboardInterrupt:
        pass
    finally:
        eng.stop_all()

if __name__ == "__main__":
    main()
