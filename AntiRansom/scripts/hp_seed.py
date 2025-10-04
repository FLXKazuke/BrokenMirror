# hp_seed.py
# Cria honeypots (~$sys_*.docx) e registra em C:\ProgramData\AntiRansom\honeypots.json

import os, sys, json, hashlib, ctypes, argparse
from pathlib import Path
from datetime import datetime

APP_DIR    = Path(os.environ.get("PROGRAMDATA", r"C:\ProgramData")) / "AntiRansom"
HP_DB_PATH = APP_DIR / "honeypots.json"
HONEYPOT_PREFIX = "~$sys_"
HONEYPOT_SUFFIX = ".docx"

DEFAULT_DIRS = [
    Path.home()/ "Desktop",
    Path.home()/ "Documents",
    Path.home()/ "Downloads",
    Path.home()/ "Pictures",
    Path.home()/ "Videos",
    Path(os.environ.get("TEMP", str(Path.home() / "AppData/Local/Temp"))),
    Path("C:/Users/Public/Documents"),
    Path("C:/Users/Public/Downloads"),
    Path("C:/Users/Public/Desktop"),
]

FILE_ATTRIBUTE_READONLY=0x1
FILE_ATTRIBUTE_HIDDEN  =0x2
FILE_ATTRIBUTE_SYSTEM  =0x4

def set_rsh(p: Path):
    try:
        ctypes.windll.kernel32.SetFileAttributesW(str(p), FILE_ATTRIBUTE_READONLY|FILE_ATTRIBUTE_HIDDEN|FILE_ATTRIBUTE_SYSTEM)
    except Exception:
        pass

def sha256_file(p: Path):
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""): h.update(chunk)
    return h.hexdigest()

def load_db():
    if HP_DB_PATH.exists():
        try: return json.loads(HP_DB_PATH.read_text(encoding="utf-8"))
        except Exception: pass
    return {}

def save_db(db):
    APP_DIR.mkdir(parents=True, exist_ok=True)
    HP_DB_PATH.write_text(json.dumps(db, indent=2, ensure_ascii=False), encoding="utf-8")

def new_name(d: Path):
    for _ in range(2000):
        p = d / f"{HONEYPOT_PREFIX}{os.urandom(2).hex()}{HONEYPOT_SUFFIX}"
        if not p.exists(): return p
    raise RuntimeError("Não consegui nome único")

def main():
    ap = argparse.ArgumentParser(description="Cria honeypots em várias pastas.")
    ap.add_argument("--per-dir", type=int, default=15, help="quantidade por pasta")
    ap.add_argument("--bytes", type=int, default=1024, help="bytes aleatórios por arquivo")
    ap.add_argument("--dirs", nargs="*", default=[], help="pastas extras (opcional)")
    args = ap.parse_args()

    db = load_db()
    dirs = list(DEFAULT_DIRS) + [Path(d) for d in args.dirs]

    created = 0
    for d in dirs:
        try:
            d.mkdir(parents=True, exist_ok=True)
        except Exception:
            continue
        # quantos já existem nessa pasta
        have = sum(1 for k in db.keys() if Path(k).parent == d and Path(k).exists())
        need = max(0, args.per_dir - have)
        for _ in range(need):
            try:
                p = new_name(d)
                p.write_bytes(os.urandom(args.bytes))
                set_rsh(p)
                db[str(p)] = {"sha256": sha256_file(p), "created": datetime.utcnow().isoformat()+"Z"}
                created += 1
            except Exception:
                continue

    save_db(db)
    print(f"[+] Honeypots criados agora: {created}")
    print(f"[i] Banco: {HP_DB_PATH}")

if __name__ == "__main__":
    main()
