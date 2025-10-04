# hp_enable_audit.py
# Habilita auditoria (categoria/subcategoria) e aplica SACL nos honeypots (~$sys_*).
# - Auto-elevação para Admin
# - Habilita SeSecurity/SeBackup/SeRestore no token
# - Detecta subcategoria no idioma local
# - Confere /get antes de dizer "ok"
# - Usa -LiteralPath e timeouts (sem travar)
 
import os, sys, json, subprocess, ctypes
from ctypes import wintypes
from pathlib import Path
 
APP_DIR    = Path(os.environ.get("PROGRAMDATA", r"C:\ProgramData")) / "AntiRansom"
HP_DB_PATH = APP_DIR / "honeypots.json"
POWERSHELL = "powershell"
 
TIMEOUT_PS = 12
TIMEOUT_EXE= 8
 
# -------- Admin & Elevação --------
def is_admin():
    try: return ctypes.windll.shell32.IsUserAnAdmin()
    except Exception: return False
 
def elevate_and_exit():
    # relança o próprio script com "runas"
    params = " ".join([f'"{a}"' for a in sys.argv])
    ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, params, None, 1)
    sys.exit(0)
 
# -------- Privilégios no token --------
SE_PRIV_NAMES = [
    "SeSecurityPrivilege",
    "SeBackupPrivilege",
    "SeRestorePrivilege",
]
 
def enable_privileges(names=SE_PRIV_NAMES):
    advapi = ctypes.windll.advapi32
    kernel = ctypes.windll.kernel32
 
    TOKEN_ADJUST_PRIVILEGES = 0x20
    TOKEN_QUERY = 0x0008
    SE_PRIVILEGE_ENABLED = 0x00000002
 
    class LUID(ctypes.Structure):
        _fields_ = [("LowPart", wintypes.DWORD), ("HighPart", wintypes.LONG)]
 
    class LUID_AND_ATTRIBUTES(ctypes.Structure):
        _fields_ = [("Luid", LUID), ("Attributes", wintypes.DWORD)]
 
    class TOKEN_PRIVILEGES(ctypes.Structure):
        _fields_ = [("PrivilegeCount", wintypes.DWORD),
                    ("Privileges", LUID_AND_ATTRIBUTES * len(names))]
 
    hProc = kernel.GetCurrentProcess()
    hTok = wintypes.HANDLE()
    if not advapi.OpenProcessToken(hProc, TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, ctypes.byref(hTok)):
        return False
 
    try:
        tp = TOKEN_PRIVILEGES()
        tp.PrivilegeCount = len(names)
        for i, name in enumerate(names):
            luid = LUID()
            # LookupPrivilegeValueW(None, name, &luid)
            if not advapi.LookupPrivilegeValueW(None, name, ctypes.byref(luid)):
                continue
            tp.Privileges[i].Luid = luid
            tp.Privileges[i].Attributes = SE_PRIVILEGE_ENABLED
 
        # AdjustTokenPrivileges(hTok, False, &tp, 0, None, None)
        advapi.AdjustTokenPrivileges(hTok, False, ctypes.byref(tp), 0, None, None)
        # Mesmo que retorne sucesso, precisamos checar GetLastError()==0
        gle = kernel.GetLastError()
        return gle == 0
    finally:
        kernel.CloseHandle(hTok)
 
def run(cmd, shell=False, timeout=TIMEOUT_EXE):
    return subprocess.run(cmd, capture_output=True, text=True, shell=shell, timeout=timeout)
 
def run_ps(ps: str, timeout=TIMEOUT_PS):
    return subprocess.run([POWERSHELL, "-NoProfile", "-Command", ps],
                          capture_output=True, text=True, timeout=timeout)
 
def ps_single_quote(path: str) -> str:
    return "'" + path.replace("'", "''") + "'"
 
def auditpol_list_subcats():
    r = run('auditpol /list /subcategory:*', shell=True)
    return (r.stdout or "") + (r.stderr or "")
 
def find_fs_subcat():
    listing = auditpol_list_subcats()
    lines = [ln.strip() for ln in listing.splitlines() if ln.strip()]
    cands = ["File System", "Sistema de arquivos", "Sistema de ficheiros"]
    for c in cands:
        for ln in lines:
            if ln.lower() == c.lower():
                return ln
    for ln in lines:
        lo = ln.lower()
        if "file" in lo and "system" in lo:
            return ln
        if "sistema" in lo and "arquivo" in lo:
            return ln
    return None
 
def auditpol_set_and_verify(subcat: str):
    ok_any = False
    for mode in ("success:enable", "failure:enable"):
        c = f'auditpol /set /subcategory:"{subcat}" /{mode}'
        r = run(c, shell=True)
        if r.returncode != 0:
            print(f"[!] auditpol falhou: {c}\n{(r.stderr or r.stdout).strip()}")
        else:
            ok_any = True
 
    cg = run(f'auditpol /get /subcategory:"{subcat}"', shell=True)
    out = (cg.stdout or "") + (cg.stderr or "")
    enabled = ("Enabled" in out) or ("Habilitado" in out)
    return ok_any and enabled
 
def auditpol_enable_category_fallback():
    for cat in ('"Object Access"', '"Acesso a objeto"'):
        for mode in ("success:enable", "failure:enable"):
            run(f'auditpol /set /category:{cat} /{mode}', shell=True)
 
def enable_auditing():
    sub = find_fs_subcat()
    if sub:
        ok = auditpol_set_and_verify(sub)
        if ok:
            print(f"[+] Subcategoria habilitada: {sub}")
        else:
            print(f"[!] Não consegui habilitar subcategoria '{sub}'. Tentando categoria…")
            auditpol_enable_category_fallback()
    else:
        print("[!] Subcategoria 'File System' não encontrada. Habilitando categoria…")
        auditpol_enable_category_fallback()
    print("[i] Dica: se ainda vier 0x522, verifique GPO ou execute como SYSTEM (ambiente gerenciado).")
 
# -------- SACL por arquivo --------
FILE_ATTRIBUTE_READONLY=0x1
 
def clr_readonly(p: Path):
    try:
        attrs = ctypes.windll.kernel32.GetFileAttributesW(str(p))
        if attrs != -1 and (attrs & FILE_ATTRIBUTE_READONLY):
            ctypes.windll.kernel32.SetFileAttributesW(str(p), attrs & ~FILE_ATTRIBUTE_READONLY)
    except Exception:
        pass
 
def set_sacl_for(path: Path):
    lit = ps_single_quote(str(path))
    ps = f"""
$path = {lit}
$acl  = Get-Acl -LiteralPath $path
$rule = New-Object System.Security.AccessControl.FileSystemAuditRule(
    'Everyone',
    'WriteData, AppendData, Delete, WriteAttributes, WriteExtendedAttributes',
    'None','None','Success')
$acl.AddAuditRule($rule)
Set-Acl -LiteralPath $path -AclObject $acl
"""
    try:
        r = run_ps(ps, timeout=TIMEOUT_PS)
        if r.returncode != 0:
            print(f"[!] SACL falhou: {path}\n{(r.stderr or r.stdout).strip()}")
            return False
        return True
    except subprocess.TimeoutExpired:
        print(f"[!] SACL TIMEOUT: {path}")
        return False
 
def main():
    if not is_admin():
        print("[!] Precisa rodar como Administrador; tentando elevar…")
        elevate_and_exit()
 
    if not enable_privileges():
        print("[!] Aviso: não consegui habilitar todos os privilégios (SeSecurity/Backup/Restore). Tentando mesmo assim…")
 
    if not HP_DB_PATH.exists():
        print("[!] honeypots.json não encontrado:", HP_DB_PATH)
        sys.exit(1)
 
    try:
        db = json.loads(HP_DB_PATH.read_text(encoding="utf-8"))
    except Exception as e:
        print("[!] Falha lendo JSON:", e); sys.exit(1)
 
    print("[*] Habilitando auditoria (auditpol)…")
    enable_auditing()
 
    print("[*] Aplicando SACL (auditoria) nos honeypots…")
    ok=miss=fail=0
    for p in db.keys():
        path = Path(p)
        if not path.exists():
            miss += 1; continue
        clr_readonly(path)
        if set_sacl_for(path):
            ok += 1
        else:
            fail += 1
    print(f"[=] SACL OK: {ok} | Ausentes: {miss} | Falhas: {fail}")
    print("[i] Depois disso, a Security Log (4656/4663) deve registrar ProcessId/ProcessName quando os honeypots forem tocados.")
 
if __name__ == "__main__":
    main()