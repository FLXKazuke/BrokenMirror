# arq_gui.py
# GUI (Tkinter) para AntiRansom: controla scripts, lê NDJSON/logs em tempo real,
# mostra eventos, processos bloqueados e quarentenas.
# Requisitos: Python 3.11+ em Windows. Execute como Administrador para ações de bloqueio/quarentena.
#
# Scripts esperados no MESMO diretório:
#   - hp_seed.py                 (cria honeypots)
#   - hp_enable_audit.py         (opcional: habilita auditoria SACL/GPO local)
#   - hp_detect_kernel.py        (detector que gera NDJSON em ProgramData\AntiRansom\logs)
#   - hp_blocker.py  (bloqueador)
#   - hp_parent_quarantine.py    (quarentena dos pais)
#   - slow_trigger_honeypot.py   (teste opcional)
#
# Logs monitorados:
#   - ProgramData\AntiRansom\logs\events-*.ndjson  (detector)
#   - ProgramData\AntiRansom\blocker.log 
#   - ProgramData\AntiRansom\parent_quarantine.log
#


import os, sys, json, time, threading, queue, subprocess, ctypes, glob
from pathlib import Path
import tkinter as tk
from tkinter import ttk, messagebox, filedialog

APP_DIR   = Path(os.environ.get("PROGRAMDATA", r"C:\ProgramData")) / "AntiRansom"
LOG_DIR   = APP_DIR / "logs"
QUAR_DIR  = APP_DIR / "quarantine"
APP_DIR.mkdir(parents=True, exist_ok=True); LOG_DIR.mkdir(exist_ok=True); QUAR_DIR.mkdir(exist_ok=True)

# ---- caminhos base ----
HERE = Path(__file__).resolve().parent
PYEXE = sys.executable  # use a mesma versão que abriu a GUI

# nomes dos scripts 
SCRIPT_SEED   = HERE / "hp_seed.py"
SCRIPT_AUDIT  = HERE / "hp_enable_audit.py"
SCRIPT_DETECT = HERE / "hp_detect_kernel.py"
SCRIPT_DETECT_SEC = HERE / "hp_detect_security.py"

for cand in ("hp_blocker.py"):
    if (HERE / cand).exists():
        SCRIPT_BLOCK = HERE / cand
        break
else:
    SCRIPT_BLOCK = HERE / "hp_blocker.py"  
SCRIPT_PARENT = HERE / "hp_parent_quarantine.py"
SCRIPT_TEST   = HERE / "slow_trigger_honeypot.py"

SYSMON_SERVICE = "Sysmon64"
POWERSHELL = "powershell"

def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except Exception:
        return False

def run_ps(cmd: str, timeout=8):
    try:
        r = subprocess.run([POWERSHELL, "-NoProfile", "-Command", cmd],
                           capture_output=True, text=True, timeout=timeout)
        return r.returncode, (r.stdout or "").strip(), (r.stderr or "").strip()
    except Exception as e:
        return 999, "", str(e)

def sysmon_status():
    rc, out, err = run_ps(f"Get-Service {SYSMON_SERVICE} | Select-Object -ExpandProperty Status")
    if rc==0 and out:
        return out.strip()
    return "Unknown"

class TailThread(threading.Thread):
    def __init__(self, path_getter, line_cb, stop_evt, name):
        super().__init__(daemon=True, name=name)
        self.path_getter = path_getter  
        self.line_cb = line_cb          
        self.stop_evt = stop_evt
        self.cur_path = None

    def run(self):
        buf = ""
        f = None
        pos = 0
        while not self.stop_evt.is_set():
            try:
                p = self.path_getter()
                if p and p.exists():
                    if self.cur_path != p:
                        if f: 
                            try: f.close()
                            except Exception: pass
                        f = p.open("r", encoding="utf-8", errors="ignore")
                        f.seek(0, os.SEEK_END)  # tail
                        self.cur_path = p
                        pos = f.tell()
                    line = f.readline()
                    if not line:
                        time.sleep(0.25)
                        continue
                    self.line_cb(line.rstrip("\n"))
                else:
                    time.sleep(0.5)
            except Exception:
                time.sleep(0.5)
        if f:
            try: f.close()
            except Exception: pass

def latest_ndjson():
    files = sorted(LOG_DIR.glob("events-*.ndjson"))
    return files[-1] if files else None

def blocker_log_path():
    p1 = APP_DIR / "blocker.log"
    p2 = APP_DIR / "blocker_min.log"
    return p1 if p1.exists() or not p2.exists() else p2

def parent_log_path():
    return APP_DIR / "parent_quarantine.log"

class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("AntiRansom — Console")
        self.geometry("1150x720")
        self.minsize(1000,650)
        self.configure(bg="#0f1115")

        style = ttk.Style(self)
        try:
            style.theme_use('clam')
        except Exception:
            pass
        style.configure("TFrame", background="#0f1115")
        style.configure("TLabelframe", background="#0f1115", foreground="#e5e7eb")
        style.configure("TLabelframe.Label", background="#0f1115", foreground="#93c5fd", font=("Segoe UI", 10, "bold"))
        style.configure("TLabel", background="#0f1115", foreground="#e5e7eb", font=("Segoe UI", 10))
        style.configure("TButton", font=("Segoe UI", 10, "bold"))
        style.configure("Treeview", background="#0b0d12", fieldbackground="#0b0d12", foreground="#e5e7eb")
        style.configure("Treeview.Heading", background="#111827", foreground="#cbd5e1", font=("Segoe UI", 10, "bold"))
        style.map("TButton", background=[("active","#1f2937")])

        self.proc_detector = None
        self.proc_blocker  = None
        self.stop_tails = threading.Event()

       
        top = ttk.Frame(self); top.pack(fill="x", padx=12, pady=8)
        self.lbl_admin = ttk.Label(top, text="Admin: " + ("SIM" if is_admin() else "NÃO"))
        self.lbl_admin.pack(side="left", padx=(0,16))
        self.lbl_sysmon = ttk.Label(top, text="Sysmon: " + sysmon_status())
        self.lbl_sysmon.pack(side="left", padx=(0,16))
        self.lbl_hp = ttk.Label(top, text="Honeypots: —")
        self.lbl_hp.pack(side="left", padx=(0,16))
        self.lbl_quar = ttk.Label(top, text="Quarentena: —")
        self.lbl_quar.pack(side="left", padx=(0,16))

        actions = ttk.Frame(top); actions.pack(side="right")
        ttk.Button(actions, text="Criar Honeypots", command=self.run_seed).pack(side="left", padx=4)
        ttk.Button(actions, text="Habilitar Auditoria", command=self.run_audit).pack(side="left", padx=4)
        ttk.Button(actions, text="Teste (lento)", command=self.run_test).pack(side="left", padx=4)
        ttk.Button(actions, text="Abrir Quarentena", command=lambda: os.startfile(str(QUAR_DIR))).pack(side="left", padx=4)

        # meio: tabs
        nb = ttk.Notebook(self); nb.pack(fill="both", expand=True, padx=12, pady=8)

        # TAB 1: Painel
        self.tab1 = ttk.Frame(nb); nb.add(self.tab1, text="Painel")
        self.build_tab1()

        # TAB 2: Eventos (NDJSON)
        self.tab2 = ttk.Frame(nb); nb.add(self.tab2, text="Eventos")
        self.build_tab2()

        # TAB 3: Logs
        self.tab3 = ttk.Frame(nb); nb.add(self.tab3, text="Logs")
        self.build_tab3()

        # timers
        self.after(1200, self.refresh_counts)
        self.after(3000, self.refresh_sysmon)

        # tails
        self.start_tailers()

        # fechamento limpo
        self.protocol("WM_DELETE_WINDOW", self.on_close)

    # --------- widgets ---------
    def build_tab1(self):
        # controles
        ctrl = ttk.Labelframe(self.tab1, text="Controle")
        ctrl.pack(fill="x", padx=6, pady=6)

        self.chk_kill = tk.BooleanVar(value=True)
        ttk.Checkbutton(ctrl, text="Kill agressor", variable=self.chk_kill).pack(side="left", padx=(10,6))

        ttk.Button(ctrl, text="Iniciar Detector", command=self.start_detector).pack(side="left", padx=6)
        ttk.Button(ctrl, text="Parar Detector", command=self.stop_detector).pack(side="left", padx=6)
        ttk.Separator(ctrl, orient="vertical").pack(side="left", fill="y", padx=10)
        ttk.Button(ctrl, text="Iniciar Bloqueador", command=self.start_blocker).pack(side="left", padx=6)
        ttk.Button(ctrl, text="Parar Bloqueador", command=self.stop_blocker).pack(side="left", padx=6)

        # resumo
        res = ttk.Labelframe(self.tab1, text="Resumo em tempo real")
        res.pack(fill="both", expand=True, padx=6, pady=6)

        # cards
        cards = ttk.Frame(res); cards.pack(fill="x", pady=10)

        self.var_evt = tk.StringVar(value="0")
        self.card(cards, "Eventos hoje", self.var_evt).pack(side="left", padx=8)
        self.var_blk = tk.StringVar(value="0")
        self.card(cards, "PIDs bloqueados", self.var_blk).pack(side="left", padx=8)
        self.var_qtz = tk.StringVar(value="0")
        self.card(cards, "Arquivos em quarentena", self.var_qtz).pack(side="left", padx=8)

        # última ação
        self.txt_last = tk.Text(res, height=10, bg="#0b0d12", fg="#e5e7eb", insertbackground="#e5e7eb")
        self.txt_last.pack(fill="both", expand=True, padx=6, pady=6)
        self.txt_last.configure(state="disabled")

    def card(self, parent, title, var):
        f = ttk.Frame(parent)
        box = ttk.Frame(f); box.pack(padx=8, pady=8)
        ttk.Label(box, text=title, foreground="#93c5fd", font=("Segoe UI", 10, "bold")).pack(anchor="w")
        ttk.Label(box, textvariable=var, font=("Segoe UI", 22, "bold")).pack(anchor="w")
        return f

    def build_tab2(self):
        # tabela de eventos
        cols = ("ts","tipo","evento","arquivo","pid","extra")
        self.tv_evt = ttk.Treeview(self.tab2, columns=cols, show="headings", height=18)
        for c,w in zip(cols,(160,120,90,460,80,220)):
            self.tv_evt.heading(c, text=c.upper())
            self.tv_evt.column(c, width=w, anchor="w")
        self.tv_evt.pack(fill="both", expand=True, padx=6, pady=6)

    def build_tab3(self):
        paned = ttk.Panedwindow(self.tab3, orient="vertical"); paned.pack(fill="both", expand=True, padx=6, pady=6)

        f1 = ttk.Labelframe(paned, text="Bloqueador"); paned.add(f1, weight=1)
        self.txt_blocker = tk.Text(f1, height=10, bg="#0b0d12", fg="#e5e7eb", insertbackground="#e5e7eb")
        self.txt_blocker.pack(fill="both", expand=True, padx=6, pady=6)

        f2 = ttk.Labelframe(paned, text="Quarentena de Pais"); paned.add(f2, weight=1)
        self.txt_parent = tk.Text(f2, height=10, bg="#0b0d12", fg="#e5e7eb", insertbackground="#e5e7eb")
        self.txt_parent.pack(fill="both", expand=True, padx=6, pady=6)

    # --------- processos externos ---------
    def start_detector(self):
        started = []
        # detector kernel/sysmon
        if self.proc_detector is None or self.proc_detector.poll() is not None:
            if SCRIPT_DETECT.exists():
                self.proc_detector = subprocess.Popen([PYEXE, str(SCRIPT_DETECT)],
                                                      creationflags=0x08000000)
                started.append(f"{SCRIPT_DETECT.name} (pid={self.proc_detector.pid})")
        # detector security (segundo processo)
        if getattr(self, "proc_detector_sec", None) is None or self.proc_detector_sec.poll() is not None:
            if SCRIPT_DETECT_SEC.exists():
                self.proc_detector_sec = subprocess.Popen([PYEXE, str(SCRIPT_DETECT_SEC)],
                                                          creationflags=0x08000000)
                started.append(f"{SCRIPT_DETECT_SEC.name} (pid={self.proc_detector_sec.pid})")

        if started:
            self.append_last("[Detector] iniciado: " + " | ".join(started))
        else:
            messagebox.showinfo("Detector", "Já está em execução ou scripts ausentes.")


    def stop_detector(self):
        self._stop_proc(getattr(self, "proc_detector", None), "Detector(Sysmon/FS)")
        self.proc_detector = None
        self._stop_proc(getattr(self, "proc_detector_sec", None), "Detector(Security)")
        self.proc_detector_sec = None


    def start_blocker(self):
        if self.proc_blocker and self.proc_blocker.poll() is None:
            messagebox.showinfo("Bloqueador", "Já está em execução.")
            return
        if not SCRIPT_BLOCK.exists():
            messagebox.showerror("Bloqueador", f"Não encontrei {SCRIPT_BLOCK.name}")
            return
        args = [PYEXE, str(SCRIPT_BLOCK)]
        if "--kill" not in " ".join(args) and self.chk_kill.get():
            args.append("--kill")
        try:
            self.proc_blocker = subprocess.Popen(args, creationflags=0x08000000)  # CREATE_NO_WINDOW
            self.append_last(f"[Bloqueador] iniciado (pid={self.proc_blocker.pid})")
        except Exception as e:
            messagebox.showerror("Bloqueador", str(e))

    def stop_blocker(self):
        self._stop_proc(self.proc_blocker, "Bloqueador")
        self.proc_blocker = None

    def _stop_proc(self, proc, label):
        try:
            if proc and proc.poll() is None:
                pid = proc.pid
                proc.terminate()
                time.sleep(0.6)
                if proc.poll() is None:
                    subprocess.run(["taskkill","/PID",str(pid),"/F","/T"],
                                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                self.append_last(f"[{label}] parado")
        except Exception as e:
            self.append_last(f"[{label}] erro ao parar: {e}")

    def run_seed(self):
        if not SCRIPT_SEED.exists():
            messagebox.showerror("Honeypots", f"Não encontrei {SCRIPT_SEED.name}")
            return
        try:
            subprocess.run([PYEXE, str(SCRIPT_SEED)], creationflags=0x08000000)
            self.append_last("[Seed] honeypots garantidos")
            self.refresh_counts()
        except Exception as e:
            messagebox.showerror("Honeypots", str(e))

    def run_audit(self):
        if not SCRIPT_AUDIT.exists():
            messagebox.showerror("Auditoria", f"Não encontrei {SCRIPT_AUDIT.name}")
            return
        try:
            subprocess.run([PYEXE, str(SCRIPT_AUDIT)], creationflags=0x08000000)
            self.append_last("[Auditoria] script executado")
        except Exception as e:
            messagebox.showerror("Auditoria", str(e))

    def run_test(self):
        if not SCRIPT_TEST.exists():
            messagebox.showerror("Teste", f"Não encontrei {SCRIPT_TEST.name}")
            return
        # 1 arquivo a cada 15s como você pediu antes
        args = [PYEXE, str(SCRIPT_TEST), "--interval","15","--kb","32","--hold","6","--cycles","6"]
        try:
            subprocess.Popen(args, creationflags=0x00000010)  # CREATE_NEW_CONSOLE (ver saídas)
            self.append_last("[Teste] iniciado (1 hp/15s)")
        except Exception as e:
            messagebox.showerror("Teste", str(e))

    # --------- tails / parsing ---------
    def start_tailers(self):
        self.stop_tails.clear()
        # NDJSON
        self.t1 = TailThread(latest_ndjson, self.on_ndjson_line, self.stop_tails, "ndjson-tail")
        self.t1.start()
        # blocker log
        self.t2 = TailThread(blocker_log_path, self.on_blocker_line, self.stop_tails, "blocker-tail")
        self.t2.start()
        # parent log
        self.t3 = TailThread(parent_log_path, self.on_parent_line, self.stop_tails, "parent-tail")
        self.t3.start()

    def on_ndjson_line(self, line: str):
        try:
            evt = json.loads(line)
        except Exception:
            return
        ts = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(evt.get("ts", time.time())))
        etype = evt.get("type","")
        if etype == "honeypot_watch":
            kind = evt.get("event","")
            path = evt.get("file","")
            extra = ""
            self.add_evt_row(ts, etype, kind, path, "", extra)
            self.bump_counter(self.var_evt)
            self.append_last(f"[EVT] {kind}: {path}")
        elif etype == "honeypot_sysmon":
            path = evt.get("file","")
            pid  = str(evt.get("pid",""))
            self.add_evt_row(ts, etype, evt.get("event",""), path, pid, evt.get("image",""))
            self.bump_counter(self.var_evt)
            self.append_last(f"[SYS] pid={pid} file={path}")
        else:
            # outros tipos (suspicious, alert, etc.)
            why = evt.get("why","")
            pth = evt.get("path","") or evt.get("file","")
            pid = str(evt.get("pid","") or "")
            self.add_evt_row(ts, etype, evt.get("kind",""), pth, pid, why)
            self.bump_counter(self.var_evt)

    def on_blocker_line(self, line: str):
        self.txt_blocker.insert("end", line + "\n")
        self.txt_blocker.see("end")
        # heurística para contar bloqueios
        if " suspend(" in line or " kill(" in line or " RES pid=" in line or " RM  " in line:
            self.bump_counter(self.var_blk)
        if "quarantine:" in line:
            self.bump_counter(self.var_qtz)

    def on_parent_line(self, line: str):
        self.txt_parent.insert("end", line + "\n")
        self.txt_parent.see("end")
        if "quarantine(" in line or "quarentena" in line.lower():
            self.bump_counter(self.var_qtz)

    def add_evt_row(self, ts, tipo, ev, path, pid, extra):
        self.tv_evt.insert("", "end", values=(ts, tipo, ev, path, pid, extra))
        # limitar para não pesar
        if len(self.tv_evt.get_children()) > 1000:
            for i in self.tv_evt.get_children()[:200]:
                self.tv_evt.delete(i)

    def bump_counter(self, var: tk.StringVar, inc=1):
        try:
            cur = int(var.get())
        except Exception:
            cur = 0
        var.set(str(cur + inc))

    def append_last(self, s: str):
        self.txt_last.configure(state="normal")
        self.txt_last.insert("end", s + "\n")
        self.txt_last.see("end")
        self.txt_last.configure(state="disabled")

    # --------- status periódicos ---------
    def refresh_counts(self):
        # honeypots: contar arquivos ~$sys_ nos diretórios comuns
        hp = 0
        for d in ["Desktop","Documents","Downloads","Pictures","Videos","AppData\\Local\\Temp","Public\\Documents","Public\\Downloads","Public\\Desktop"]:
            try:
                p = Path.home() / d
                hp += len(list(p.glob("~$sys_*.docx")))
            except Exception:
                pass
        self.lbl_hp.config(text=f"Honeypots: {hp}")

        q = len(list(QUAR_DIR.glob("*.copy")))
        self.lbl_quar.config(text=f"Quarentena: {q}")

        self.after(3000, self.refresh_counts)

    def refresh_sysmon(self):
        self.lbl_sysmon.config(text="Sysmon: " + sysmon_status())
        self.after(8000, self.refresh_sysmon)

    # --------- fechar ---------
    def on_close(self):
        try:
            self.stop_tails.set()
        except Exception:
            pass
        self.destroy()

if __name__ == "__main__":
    app = App()
    if not is_admin():
        messagebox.showwarning("Permissões", "Ideal rodar como Administrador para suspender/encerrar/quarentenar processos.")
    app.mainloop()
