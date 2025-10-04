# slow_trigger_honeypot.py
# Modifica 1 honeypot por ciclo (padrão: a cada 15s) para testar a solução.
 
import os, json, time, argparse, random, ctypes
from pathlib import Path
 
PROGRAMDATA = Path(os.environ.get("PROGRAMDATA", r"C:\ProgramData"))
BASE_DIR    = PROGRAMDATA / "AntiRansom"
HP_DB       = BASE_DIR / "honeypots.json"
 
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
 
PATTERN_PREFIX = "~$sys_"
 
FILE_ATTRIBUTE_READONLY = 0x1
FILE_ATTRIBUTE_HIDDEN   = 0x2
FILE_ATTRIBUTE_SYSTEM   = 0x4
 
def get_attrs(path: Path) -> int:
    return ctypes.windll.kernel32.GetFileAttributesW(str(path))
 
def set_attrs(path: Path, attrs: int):
    ctypes.windll.kernel32.SetFileAttributesW(str(path), attrs)
 
def clear_rsh(path: Path):
    try:
        attrs = get_attrs(path)
        if attrs != -1:
            set_attrs(path, attrs & ~FILE_ATTRIBUTE_READONLY & ~FILE_ATTRIBUTE_SYSTEM & ~FILE_ATTRIBUTE_HIDDEN)
    except Exception:
        pass
 
def add_rsh(path: Path):
    try:
        attrs = get_attrs(path)
        if attrs != -1:
            set_attrs(path, attrs | FILE_ATTRIBUTE_READONLY | FILE_ATTRIBUTE_SYSTEM | FILE_ATTRIBUTE_HIDDEN)
    except Exception:
        pass
 
def load_honeypots_from_db():
    paths = []
    if HP_DB.exists():
        try:
            db = json.loads(HP_DB.read_text(encoding="utf-8"))
            for p in db.keys():
                pp = Path(p)
                if pp.exists():
                    paths.append(pp)
        except Exception:
            pass
    return paths
 
def scan_honeypots(dirs):
    found = []
    for d in dirs:
        d = Path(d)
        if not d.exists(): continue
        try:
            for p in d.iterdir():
                if p.is_file() and p.name.startswith(PATTERN_PREFIX):
                    found.append(p)
        except Exception:
            continue
    return found
 
def pick_one_honeypot():
    hps = load_honeypots_from_db()
    if not hps:
        # fallback: varre pastas padrão
        hps = scan_honeypots(DEFAULT_DIRS)
    hps = [p for p in hps if p.exists()]
    if not hps:
        return None
    random.shuffle(hps)
    return hps[0]
 
def encrypt_new(target: Path, kb: int):
    """Cria <target>.encrypted com dados aleatórios e remove o original."""
    clear_rsh(target)
    new_path = target.with_suffix(target.suffix + ".encrypted")
    with open(new_path, "wb") as wf:
        wf.write(os.urandom(kb*1024))
        wf.flush()
        os.fsync(wf.fileno())
    try:
        target.unlink()
    except Exception:
        pass
    add_rsh(new_path)
    return new_path
 
def main():
    ap = argparse.ArgumentParser(description="Modifica 1 honeypot por ciclo para testes controlados.")
    ap.add_argument("--interval", type=int, default=15, help="segundos entre cada modificação (default 15)")
    ap.add_argument("--kb", type=int, default=32, help="tamanho do .encrypted (KB) em cada ciclo (default 32)")
    ap.add_argument("--cycles", type=int, default=0, help="número de ciclos (0 = infinito até Ctrl+C)")
    ap.add_argument("--hold", type=int, default=3, help="segundos mantendo o handle aberto no novo arquivo (ajuda PID)")
    args = ap.parse_args()
 
    print(f"[*] Iniciando teste: 1 arquivo / {args.interval}s | payload={args.kb}KB | hold={args.hold}s | cycles={'∞' if args.cycles==0 else args.cycles}")
    cycle = 0
    try:
        while True:
            if args.cycles and cycle >= args.cycles:
                print("[*] Ciclos concluídos.")
                break
 
            target = pick_one_honeypot()
            if not target:
                print("[!] Nenhum honeypot encontrado. Crie-os antes de testar.")
                time.sleep(args.interval)
                continue
 
            try:
                print(f"[{time.strftime('%H:%M:%S')}] alvo: {target}")
                newp = encrypt_new(target, args.kb)
                fh = open(newp, "rb")
                print(f"    -> criado {newp.name} (+{args.kb}KB) e removido original | mantendo handle por {args.hold}s")
                time.sleep(args.hold)
                fh.close()
            except Exception as e:
                print(f"[x] falha: {e}")
 
            cycle += 1
            time.sleep(args.interval)
    except KeyboardInterrupt:
        print("\n[*] Encerrado pelo usuário.")
 
if __name__ == "__main__":
    main()