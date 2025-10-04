# hp_detect_security.py
# Detecta negações de acesso (Security 4656 com Status=0xC0000022) aos honeypots/protegidos
# e escreve NDJSON em C:\ProgramData\AntiRansom\logs\events-YYYYMMDD.ndjson
# Requer: Python 3.11+, Windows, permissão p/ ler Security Log (ideal: Admin)

import os, sys, json, time, subprocess, ctypes
from pathlib import Path
from datetime import datetime

APP_DIR   = Path(os.environ.get("PROGRAMDATA", r"C:\ProgramData")) / "AntiRansom"
LOG_DIR   = APP_DIR / "logs"
HP_DB     = APP_DIR / "honeypots.json"
STATE     = APP_DIR / "security_state.json"
LOG_PATH  = LOG_DIR / f"events-{datetime.now():%Y%m%d}.ndjson"
POWERSHELL = "powershell"

HONEYPOT_PREFIX = "~$sys_"
SECURITY_LOG = "Security"
EVENT_ID = 4656  # Handle requested
POLL_INTERVAL = 1.2
MAX_PULL = 400

def ensure_dirs():
    APP_DIR.mkdir(parents=True, exist_ok=True)
    LOG_DIR.mkdir(parents=True, exist_ok=True)

def load_hp_db():
    if HP_DB.exists():
        try: return json.loads(HP_DB.read_text(encoding="utf-8"))
        except Exception: pass
    return {}

def log_evt(evt: dict):
    evt["ts"] = time.time()
    evt["ts_iso"] = datetime.utcfromtimestamp(evt["ts"]).strftime("%Y-%m-%dT%H:%M:%SZ")
    with open(LOG_PATH, "a", encoding="utf-8") as f:
        f.write(json.dumps(evt, ensure_ascii=False) + "\n")

def load_state():
    if STATE.exists():
        try: return json.loads(STATE.read_text(encoding="utf-8"))
        except Exception: pass
    return {"last_record_id": 0}

def save_state(s: dict):
    try: STATE.write_text(json.dumps(s, indent=2), encoding="utf-8")
    except Exception: pass

def _tail_current_record_id():
    ps = f"(Get-WinEvent -LogName '{SECURITY_LOG}' -MaxEvents 1 | Select-Object -ExpandProperty RecordId)"
    try:
        r = subprocess.run([POWERSHELL,"-NoProfile","-Command", ps], capture_output=True, text=True, timeout=6)
        return int((r.stdout or "0").strip() or "0")
    except Exception:
        return 0

def collect_4656_since(last_record_id: int, roots: list[str]):
    xpath = f"*[System[(EventRecordID>{last_record_id}) and (EventID={EVENT_ID})]]"
    ps = f"""
$evs = Get-WinEvent -LogName '{SECURITY_LOG}' -FilterXPath "{xpath}" -ErrorAction SilentlyContinue `
       -MaxEvents {MAX_PULL} | Sort-Object RecordId
$result = @()
foreach($e in $evs){{
  try {{
    $x=[xml]$e.ToXml()
    $d=@{{}}; foreach($n in $x.Event.EventData.Data){{ $d[$n.Name]=$n.'#text' }}
    $result += [PSCustomObject]@{{
      RecordId=$e.RecordId
      TimeCreated=$e.TimeCreated.ToUniversalTime().ToString("o")
      ObjectName=$d["ObjectName"]
      ProcessId=$d["ProcessId"]
      ProcessName=$d["ProcessName"]
      Status=$d["Status"]
      AccessMask=$d["AccessMask"]
    }}
  }} catch {{ }}
}}
$result | ConvertTo-Json -Compress
"""
    try:
        r = subprocess.run([POWERSHELL,"-NoProfile","-Command", ps], capture_output=True, text=True, timeout=12)
        if r.returncode != 0 or not r.stdout.strip(): return [], last_record_id
        raw = json.loads(r.stdout)
        events = raw if isinstance(raw, list) else [raw]
    except Exception:
        return [], last_record_id

    keep, high = [], last_record_id
    for e in events:
        rec = int(e.get("RecordId") or 0)
        if rec <= last_record_id: 
            continue
        obj = (e.get("ObjectName") or "")
        stat= (e.get("Status") or "")
        if not obj: 
            if rec > high: high = rec
            continue
        # Filtro: deny + objeto dentro de honeypot/roots
        in_scope = False
        base = os.path.basename(obj)
        if base.startswith(HONEYPOT_PREFIX):
            in_scope = True
        else:
            for rt in roots:
                try:
                    if obj.lower().startswith(rt.lower()):
                        in_scope = True; break
                except Exception:
                    pass
        if stat.lower() == "0xc0000022" and in_scope:
            keep.append(e)
        if rec > high: high = rec
    return keep, high

def main():
    ensure_dirs()
    db = load_hp_db()
    # roots = pastas onde ficam honeypots
    roots = sorted({ str(Path(p).parent) for p in db.keys() }) if db else []
    st = load_state()
    last = int(st.get("last_record_id") or 0)
    if last == 0:
        last = _tail_current_record_id()
        save_state({"last_record_id": last})

    print("[*] Detector Security 4656 ativo. RecordId inicial:", last)
    while True:
        try:
            batch, high = collect_4656_since(last, roots)
            if batch:
                last = high
                save_state({"last_record_id": last})
                for e in batch:
                    # pid vem em HEX no 4656
                    pid_hex = (e.get("ProcessId") or "").strip()
                    try:
                        pid = int(pid_hex, 16) if pid_hex.lower().startswith("0x") else int(pid_hex or "0")
                    except Exception:
                        pid = 0
                    evt = {
                        "type":"honeypot_deny",
                        "event":"access_denied",
                        "file": e.get("ObjectName") or "",
                        "pid": pid,
                        "image": e.get("ProcessName") or "",
                        "status": e.get("Status") or "",
                        "access": e.get("AccessMask") or ""
                    }
                    log_evt(evt)
                    print(f"[DENY] pid={pid} img={evt['image']} file={evt['file']}")
        except KeyboardInterrupt:
            break
        except Exception:
            pass
        time.sleep(POLL_INTERVAL)

if __name__ == "__main__":
    main()
