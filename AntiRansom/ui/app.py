# -*- coding: utf-8 -*-
# C:\AntiRansom\ui\app.py
import os, sys, subprocess, threading, queue, time, json, csv
import tkinter as tk
from tkinter import ttk, messagebox, filedialog

# ------------------ CONFIG ------------------
ROOT      = r"C:\AntiRansom"
SCRIPTS   = os.path.join(ROOT, "scripts")
DATA      = os.path.join(ROOT, "data")
LOGFILE   = os.path.join(DATA, "events.log")
QUAR      = os.path.join(DATA, "quarantine")
DRIVER    = os.path.join(ROOT, "driver")

INF_PATH  = os.path.join(DRIVER, "passThrough.inf")   # ajuste se mudou
FILTER    = "passThrough"                              # ServiceName do seu INF
# --------------------------------------------

def ensure_dirs():
    for p in (ROOT, SCRIPTS, DATA, QUAR, DRIVER):
        os.makedirs(p, exist_ok=True)
    if not os.path.exists(LOGFILE):
        open(LOGFILE, "a", encoding="utf-8").close()

def run_ps(cmd):
    """Roda PowerShell e retorna (rc, stdout, stderr)."""
    c = subprocess.run(
        ["powershell","-NoProfile","-ExecutionPolicy","Bypass","-Command",cmd],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
    )
    return c.returncode, (c.stdout or "").strip(), (c.stderr or "").strip()

# -------- Driver (minifilter) ----------
def driver_install():
    if not os.path.exists(INF_PATH):
        return False, f"INF não encontrado: {INF_PATH}"
    rc,out,err = run_ps(f'pnputil /add-driver "{INF_PATH}" /install')
    ok = (rc == 0) or ("already" in (out+err).lower())
    return ok, (out or err)

def driver_load():
    rc,out,err = run_ps(f'fltmc load {FILTER}')
    if rc != 0:
        if is_driver_loaded():
            return True, "Já carregado"
        return False, out or err
    return True, out

def driver_unload():
    rc,out,err = run_ps(f'fltmc unload {FILTER}')
    return rc == 0, out or err

def is_driver_loaded():
    rc,out,err = run_ps("fltmc filters")
    return FILTER.lower() in (out or "").lower()

def driver_instances():
    rc,out,err = run_ps("fltmc instances")
    return out or err

# -------- CFA/ASR ----------
def enable_cfa_asr():
    cmds = [
        'Set-MpPreference -EnableControlledFolderAccess Enabled',
        r'Add-MpPreference -ControlledFolderAccessProtectedFolders "$env:USERPROFILE\Documents","$env:USERPROFILE\Desktop","$env:USERPROFILE\Pictures","C:\HoneyNet","C:\Users\Public\Documents\HONEY"',
        '$rules=@('
        '"c1db55ab-c21a-4637-bb3f-a12568109d35",'
        '"d4f940ab-401b-4efc-aadc-ad5f3c50688a",'
        '"3b576869-a4ec-4529-8536-b80a7769e899",'
        '"75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84",'
        '"be9ba2d9-53ea-4cdc-84e5-9b1eeee46550",'
        '"01443614-cd74-433a-b99e-2ecdc07bfc25",'
        '"5beb7efe-fd9a-4556-801d-275e5ffc04cc",'
        '"d3e037e1-3eb8-44c8-a917-57927947596d",'
        '"e6db77e5-3df2-4cf1-b95a-636979351e5b",'
        '"9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2",'
        '"26190899-1602-49e8-8b27-eb1d0a1ce869",'
        '"56a863a9-875e-4185-98a7-b882c64b5ce5"'
        '); foreach($r in $rules){ Add-MpPreference -AttackSurfaceReductionRules_Ids $r -AttackSurfaceReductionRules_Actions Enabled }'
    ]
    for c in cmds:
        rc,out,err = run_ps(c)
        if rc != 0 and "already exists" not in (out+err):
            return False, out or err
    return True, "CFA + ASR habilitados"

def status_cfa():
    rc,out,err = run_ps("(Get-MpPreference).EnableControlledFolderAccess")
    m={"0":"Desativado","1":"Ativado","2":"Audit"}
    return m.get(out.strip(), out.strip() or "?" )

def status_asr():
    rc,out,err = run_ps("$mp=Get-MpPreference; ($mp.AttackSurfaceReductionRules_Ids).Count")
    return out.strip() if out.strip() else "0"

# -------- Guardian (scripts .ps1) ----------
def guardian_start():
    ps1 = os.path.join(SCRIPTS,"02-Start-Guardian.ps1")
    if not os.path.exists(ps1): return False, f"Não achei {ps1}"
    try:
        subprocess.Popen(
            ["powershell","-NoProfile","-ExecutionPolicy","Bypass","-File", ps1],
            creationflags=0x08000000  # CREATE_NO_WINDOW
        )
        return True, "Guardian iniciado"
    except Exception as e:
        return False, str(e)

def guardian_stop():
    ps1 = os.path.join(SCRIPTS,"03-Stop-Guardian.ps1")
    if os.path.exists(ps1):
        rc,out,err = run_ps(f'& "{ps1}"')
        return rc==0, out or err
    rc,out,err = run_ps("Set-NetFirewallProfile -Profile Domain,Public,Private -DefaultOutboundAction Allow -DefaultInboundAction Allow")
    return rc==0, out or err

def guardian_running_guess():
    # 1) runfile criado pelo Start-Guardian
    runfile = os.path.join(DATA, "guardian.run")
    if os.path.exists(runfile):
        return True
    # 2) conferência: há powershell rodando com o script?
    rc, out, err = run_ps("Get-CimInstance Win32_Process | Where-Object { $_.CommandLine -like '*02-Start-Guardian.ps1*' } | Measure-Object | % Count")
    try:
        return int((out or "0").strip()) > 0
    except:
        return False


# -------- Sysmon: últimos processos / arquivos ----------
def sysmon_available():
    rc,out,err = run_ps("(Get-Service -Name sysmon64 -ErrorAction SilentlyContinue).Status")
    return out.strip() != ""

def sysmon_processes_json(max_events=150):
    pwsh = f'''
$ev = Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -FilterXPath "*[System[(EventID=1)]]" -MaxEvents {max_events};
$ev | ForEach-Object {{
  $x=[xml]$_.ToXml();
  [pscustomobject]@{{
    Time=$_.TimeCreated.ToString("s")
    ProcessId=($x.Event.EventData.Data | ? {{ $_.Name -eq 'ProcessId' }}).'#text'
    Image=($x.Event.EventData.Data | ? {{ $_.Name -eq 'Image' }}).'#text'
    CommandLine=($x.Event.EventData.Data | ? {{ $_.Name -eq 'CommandLine' }}).'#text'
    User=($x.Event.EventData.Data | ? {{ $_.Name -eq 'User' }}).'#text'
    ParentImage=($x.Event.EventData.Data | ? {{ $_.Name -eq 'ParentImage' }}).'#text'
    ParentProcessId=($x.Event.EventData.Data | ? {{ $_.Name -eq 'ParentProcessId' }}).'#text'
    Hashes=($x.Event.EventData.Data | ? {{ $_.Name -eq 'Hashes' }}).'#text'
  }}
}} | ConvertTo-Json -Compress
'''
    rc,out,err = run_ps(pwsh)
    if rc!=0 or (not out): return "[]"
    return out

def sysmon_files_json(max_events=150):
    pwsh = f'''
$ev = Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -FilterXPath "*[System[(EventID=11)]]" -MaxEvents {max_events};
$ev | ForEach-Object {{
  $x=[xml]$_.ToXml();
  [pscustomobject]@{{
    Time=$_.TimeCreated.ToString("s")
    ProcessId=($x.Event.EventData.Data | ? {{ $_.Name -eq 'ProcessId' }}).'#text'
    Image=($x.Event.EventData.Data | ? {{ $_.Name -eq 'Image' }}).'#text'
    Target=($x.Event.EventData.Data | ? {{ $_.Name -eq 'TargetFilename' }}).'#text'
  }}
}} | ConvertTo-Json -Compress
'''
    rc,out,err = run_ps(pwsh)
    if rc!=0 or (not out): return "[]"
    return out

# -------- Utilidades ----------
def open_quarantine():
    os.makedirs(QUAR, exist_ok=True)
    os.startfile(QUAR)

def tail_file(path, q):
    with open(path, "a", encoding="utf-8"): pass
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        f.seek(0, os.SEEK_END)
        while True:
            line = f.readline()
            if not line:
                time.sleep(0.25); continue
            q.put(line.rstrip())

def export_csv(rows, headers, out_path):
    with open(out_path, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f); w.writerow(headers)
        for r in rows:
            w.writerow([r.get(h,"") for h in headers])

# ------------------ GUI ------------------
class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("🛡️ Anti-Ransomware — Painel")
        self.geometry("1200x720")
        self.configure(bg="#0b1220")
        ensure_dirs()

        self.q = queue.Queue()
        threading.Thread(target=tail_file, args=(LOGFILE,self.q), daemon=True).start()

        self._build_ui()
        self._refresh_all()
        self.after(250, self._tick_feed)

    # ---- layout
    def _build_ui(self):
        top = tk.Frame(self, bg="#0b1220"); top.pack(fill="x", padx=12, pady=8)
        tk.Label(top, text="Guardian + Kernel Shield", fg="#e3f2fd", bg="#0b1220",
                 font=("Segoe UI", 18, "bold")).pack(side="left")

        nb = ttk.Notebook(self); nb.pack(fill="both", expand=True, padx=12, pady=(0,12))

        # Tab Dashboard
        self.tab_dash = tk.Frame(nb, bg="#0b1220"); nb.add(self.tab_dash, text="Dashboard")
        self._build_dash(self.tab_dash)

        # Tab Processos
        self.tab_proc = tk.Frame(nb, bg="#0b1220"); nb.add(self.tab_proc, text="Processos (Sysmon)")
        self._build_process(self.tab_proc)

        # Tab Arquivos
        self.tab_files = tk.Frame(nb, bg="#0b1220"); nb.add(self.tab_files, text="Arquivos (Sysmon)")
        self._build_files(self.tab_files)

        # Tab Logs
        self.tab_logs = tk.Frame(nb, bg="#0b1220"); nb.add(self.tab_logs, text="Feed/Logs")
        self._build_logs(self.tab_logs)

    def _card(self, parent, title):
        f = tk.Frame(parent, bg="#111827"); f.pack(fill="x", pady=6, ipadx=8, ipady=8)
        tk.Label(f, text=title, fg="#cbd5e1", bg="#111827", font=("Segoe UI", 12, "bold")).pack(anchor="w")
        return f

    def _kv(self, parent, k, v="…"):
        row = tk.Frame(parent, bg="#111827"); row.pack(fill="x", pady=2)
        tk.Label(row, text=k, fg="#94a3b8", bg="#111827", font=("Segoe UI", 10)).pack(side="left")
        lab = tk.Label(row, text=v, fg="#e2e8f0", bg="#111827", font=("Segoe UI", 10, "bold"))
        lab.pack(side="right"); return lab

    def _build_dash(self, root):
        col = tk.Frame(root, bg="#0b1220"); col.pack(side="left", fill="y", padx=(0,12), pady=6)
        col2= tk.Frame(root, bg="#0b1220"); col2.pack(side="left", fill="both", expand=True, pady=6)

        # Status
        st = self._card(col, "Status")
        self.lbl_driver = self._kv(st, "Minifilter")
        self.lbl_cfa    = self._kv(st, "CFA")
        self.lbl_asr    = self._kv(st, "ASR (regras)")
        self.lbl_guard  = self._kv(st, "Guardian")
        ttk.Button(st, text="Atualizar Status", command=self._refresh_all).pack(fill="x", pady=6)

        # Ações rápidas
        ac = self._card(col, "Ações")
        ttk.Button(ac, text="Instalar Driver", command=self._install_driver).pack(fill="x", pady=3)
        ttk.Button(ac, text="Carregar Driver", command=self._load_driver).pack(fill="x", pady=3)
        ttk.Button(ac, text="Descarregar Driver", command=self._unload_driver).pack(fill="x", pady=3)
        ttk.Button(ac, text="Ativar CFA + ASR", command=self._enable_cfa_asr).pack(fill="x", pady=3)
        ttk.Button(ac, text="Iniciar Guardian", command=self._start_guardian).pack(fill="x", pady=3)
        ttk.Button(ac, text="Parar Guardian", command=self._stop_guardian).pack(fill="x", pady=3)
        ttk.Button(ac, text="Abrir Quarentena", command=open_quarantine).pack(fill="x", pady=3)
        ttk.Button(ac, text="Ver Instâncias do Filtro", command=self._show_instances).pack(fill="x", pady=3)
        ttk.Button(ac, text="Exportar Relatório (CSV)", command=self._export_report).pack(fill="x", pady=3)

        # Feed compacto (últimas linhas)
        fc = self._card(col2, "Feed (events.log)")
        self.feed_small = tk.Text(fc, height=18, bg="#0f172a", fg="#e2e8f0", border=0)
        self.feed_small.pack(fill="both", expand=True)

    def _build_process(self, root):
        top = tk.Frame(root, bg="#0b1220"); top.pack(fill="x", pady=6)
        ttk.Button(top, text="Atualizar (Sysmon)", command=self._load_processes).pack(side="left")
        ttk.Button(top, text="Exportar CSV", command=self._export_process_csv).pack(side="left", padx=6)
        self.tv_proc = ttk.Treeview(root,
            columns=("Time","PID","Image","User","ParentPID","ParentImage","CommandLine","Hashes"),
            show="headings"
        )
        for c,w in [("Time",140),("PID",70),("Image",260),("User",180),
                    ("ParentPID",80),("ParentImage",240),("CommandLine",400),("Hashes",280)]:
            self.tv_proc.heading(c, text=c); self.tv_proc.column(c, width=w, anchor="w")
        self.tv_proc.pack(fill="both", expand=True, padx=6, pady=(0,6))

    def _build_files(self, root):
        top = tk.Frame(root, bg="#0b1220"); top.pack(fill="x", pady=6)
        ttk.Button(top, text="Atualizar (Sysmon)", command=self._load_files).pack(side="left")
        ttk.Button(top, text="Exportar CSV", command=self._export_files_csv).pack(side="left", padx=6)
        self.tv_files = ttk.Treeview(root, columns=("Time","PID","Image","Target"), show="headings")
        for c,w in [("Time",140),("PID",70),("Image",360),("Target",520)]:
            self.tv_files.heading(c, text=c); self.tv_files.column(c, width=w, anchor="w")
        self.tv_files.pack(fill="both", expand=True, padx=6, pady=(0,6))

    def _build_logs(self, root):
        top = tk.Frame(root, bg="#0b1220"); top.pack(fill="x", pady=6)
        ttk.Button(top, text="Abrir arquivo de log", command=lambda: os.startfile(LOGFILE)).pack(side="left")
        self.feed = tk.Text(root, bg="#0f172a", fg="#e2e8f0", border=0)
        self.feed.pack(fill="both", expand=True, padx=6, pady=(0,6))
        for t,c in [("error","#ff5c5c"),("det","#ffa726"),("resp","#66bb6a"),("info","#90a4ae")]:
            self.feed.tag_config(t, foreground=c)

    # ---- actions
    def _install_driver(self):
        ok,msg = driver_install()
        messagebox.showinfo("Driver", msg if msg else ("OK" if ok else "Falha"))
        self._refresh_all()

    def _load_driver(self):
        ok,msg = driver_load()
        if not ok: messagebox.showwarning("Driver", msg)
        self._refresh_all()

    def _unload_driver(self):
        ok,msg = driver_unload()
        if not ok: messagebox.showwarning("Driver", msg)
        self._refresh_all()

    def _enable_cfa_asr(self):
        ok,msg = enable_cfa_asr()
        messagebox.showinfo("CFA/ASR", msg)
        self._refresh_all()

    def _start_guardian(self):
        ok,msg = guardian_start()
        if not ok: messagebox.showerror("Guardian", msg)
        self._refresh_all()

    def _stop_guardian(self):
        ok,msg = guardian_stop()
        if not ok: messagebox.showwarning("Guardian", msg)
        self._refresh_all()

    def _show_instances(self):
        info = driver_instances()
        messagebox.showinfo("Instâncias do Filtro", info if info else "N/D")

    def _export_report(self):
        folder = filedialog.askdirectory(title="Escolha a pasta para salvar CSVs")
        if not folder: return
        # Feed: copia
        try:
            dest = os.path.join(folder, "events.log")
            with open(LOGFILE, "rb") as src, open(dest, "wb") as dst: dst.write(src.read())
        except Exception as e:
            messagebox.showwarning("Exportar", f"Falha ao copiar events.log: {e}")
        # Processos / Arquivos
        prows = getattr(self, "_current_process_rows", []) or []
        frows  = getattr(self, "_current_file_rows", []) or []
        export_csv(prows, ["Time","ProcessId","Image","User","ParentProcessId","ParentImage","CommandLine","Hashes"],
                   os.path.join(folder,"sysmon_processes.csv"))
        export_csv(frows,  ["Time","ProcessId","Image","Target"],
                   os.path.join(folder,"sysmon_files.csv"))
        messagebox.showinfo("Exportar", "Relatório exportado.")

    # ---- data loads
    def _refresh_all(self):
        self.lbl_driver.configure(text=("Carregado" if is_driver_loaded() else "Parado"))
        self.lbl_cfa.configure(text=status_cfa())
        self.lbl_asr.configure(text=status_asr())
        self.lbl_guard.configure(text=("Rodando" if guardian_running_guess() else "Parado"))
        self._load_processes()
        self._load_files()

    def _load_processes(self):
        js = sysmon_processes_json(200 if sysmon_available() else 0)
        try: data = json.loads(js) if js else []
        except: data = []
        if isinstance(data, dict): data=[data]
        self._current_process_rows = data
        for i in self.tv_proc.get_children(): self.tv_proc.delete(i)
        for r in data:
            self.tv_proc.insert("", "end", values=(
                r.get("Time",""), r.get("ProcessId",""), r.get("Image",""),
                r.get("User",""), r.get("ParentProcessId",""),
                r.get("ParentImage",""), r.get("CommandLine",""), r.get("Hashes","")
            ))

    def _load_files(self):
        js = sysmon_files_json(200 if sysmon_available() else 0)
        try: data = json.loads(js) if js else []
        except: data = []
        if isinstance(data, dict): data=[data]
        self._current_file_rows = data
        for i in self.tv_files.get_children(): self.tv_files.delete(i)
        for r in data:
            self.tv_files.insert("", "end", values=(
                r.get("Time",""), r.get("ProcessId",""), r.get("Image",""), r.get("Target","")
            ))

    # ---- exportações CSV individuais (processos/arquivos)
    def _export_process_csv(self):
        rows = getattr(self, "_current_process_rows", [])
        if not rows:
            try:
                self._load_processes()
                rows = getattr(self, "_current_process_rows", [])
            except Exception:
                rows = []
        dest = filedialog.asksaveasfilename(
            title="Salvar processos (CSV)",
            defaultextension=".csv",
            filetypes=[("CSV","*.csv")],
            initialfile="sysmon_processes.csv"
        )
        if not dest: return
        headers = ["Time","ProcessId","Image","User","ParentProcessId","ParentImage","CommandLine","Hashes"]
        try:
            export_csv(rows, headers, dest)
            messagebox.showinfo("Exportar", f"Processos exportados para:\n{dest}")
        except Exception as e:
            messagebox.showerror("Exportar", f"Falhou ao exportar:\n{e}")

    def _export_files_csv(self):
        rows = getattr(self, "_current_file_rows", [])
        if not rows:
            try:
                self._load_files()
                rows = getattr(self, "_current_file_rows", [])
            except Exception:
                rows = []
        dest = filedialog.asksaveasfilename(
            title="Salvar arquivos (CSV)",
            defaultextension=".csv",
            filetypes=[("CSV","*.csv")],
            initialfile="sysmon_files.csv"
        )
        if not dest: return
        headers = ["Time","ProcessId","Image","Target"]
        try:
            export_csv(rows, headers, dest)
            messagebox.showinfo("Exportar", f"Arquivos exportados para:\n{dest}")
        except Exception as e:
            messagebox.showerror("Exportar", f"Falhou ao exportar:\n{e}")

    # ---- feed tick
    def _tick_feed(self):
        # consume linhas do log e joga no feed
        while True:
            try: line = self.q.get_nowait()
            except queue.Empty: break
            tag="info"
            if "[ERROR]" in line: tag="error"
            elif "[RESPONSE]" in line or "KILL" in line: tag="resp"
            elif "[DET]" in line or "[SYSMON]" in line: tag="det"
            self.feed.insert("end", line+"\n", tag); self.feed.see("end")
            self.feed_small.insert("end", line+"\n"); self.feed_small.see("end")
        self.after(250, self._tick_feed)

if __name__ == "__main__":
    ensure_dirs()
    app = App()
    app.mainloop()
