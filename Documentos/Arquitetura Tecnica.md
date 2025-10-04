# ARQUITETURA_TECNICA.md — BrokenMirror

> Documento de arquitetura técnica do projeto **BrokenMirror** (Sprint 4).  
> Foco: como os módulos se comunicam, principais fluxos, dependências e pontos de operação/observabilidade.

---

## 1. Visão Geral da Arquitetura

A solução combina **defesa no kernel** (MiniFilter) com **detecção e resposta em user‑mode** (Python/PowerShell), exibindo eventos em uma **GUI** simples.

```
            ┌──────────────────────────────┐
            │            Usuário           │
            │        (Operador / GUI)      │
            └──────────────┬───────────────┘
                           │
                           │ eventos/alertas
                           ▼
                   ┌───────────────┐
                   │     GUI       │  arq_gui.py
                   └───────┬───────┘
                           │
          ┌────────────────┼───────────────────┐
          │                │                   │
          ▼                ▼                   ▼
 ┌────────────────┐  ┌───────────────┐  ┌────────────────┐
 │ Detector Sec   │  │ Detector KRN  │  │   Blocker      │
 │ hp_detect_...  │  │ hp_detect_... │  │ hp_blocker.py  │
 └───────┬────────┘  └──────┬────────┘  └────────┬───────┘
         │                  │                    │
  Security EventLog   Sysmon/Operational   Kill/Suspend, Quarentena
 (4656/4663, etc.)    (11, 23, 1, etc.)           │
         │                  │                     │
         └──────────┬───────┴──────────────┬──────┘
                    │                      │
                    ▼                      ▼
            ┌──────────────┐        ┌──────────────┐
            │ Normalizador │        │  Quarentena  │
            │ (NDJSON/log) │        │ Q_*/meta.json│
            └──────┬───────┘        └──────┬───────┘
                   │                       │
                   ▼                       ▼
            C:\AntiRansom\data\events.log  C:\AntiRansom\data\quarantine\
```

Em paralelo, o **MiniFilter** (kernel) intercepta I/O de arquivos e pode negar operações em áreas protegidas:

```
  Processo suspeito ──► MiniFilter (passThrough.sys) ──► [ALLOW/DENY] ──► FS
                                           │
                                           └─► Eventos (STATUS_ACCESS_DENIED) percebidos pelos detectores
```

---

## 2. Componentes Principais

| Componente | Tipo | Caminho (padrão) | Função |
|---|---|---|---|
| MiniFilter `passThrough.sys` | Kernel Driver | `C:\AntiRansom\driver\` | Intercepta I/O e aplica política básica (deny/allow). |
| INF/CAT (`passThrough.inf/.cat`) | Driver Package | `C:\AntiRansom\driver\` | Instalação e assinatura (test/production). |
| `hp_seed.py` | Script | `C:\AntiRansom\scripts\` | Cria honeypots e diretórios de isca. |
| `hp_enable_audit.py` | Script | `C:\AntiRansom\scripts\` | Aplica SACL para eventos 4656/4663 em diretórios/arquivos alvo. |
| `hp_detect_security.py` | Daemon | `C:\AntiRansom\scripts\` | Lê **EventLog Security** (Win32_*) e publica NDJSON. |
| `hp_detect_kernel.py` | Daemon | `C:\AntiRansom\scripts\` | Lê **Sysmon/Operational** (IDs 1/11/23…) e publica NDJSON. |
| `hp_blocker.py` | Daemon | `C:\AntiRansom\scripts\` | Resolve PID/PPID, **suspende/encerra** processo e **quarentena** do binário. |
| `arq_gui.py` | App | `C:\AntiRansom\scripts\` | UI Tkinter exibindo eventos e ações em tempo real. |
| Sysmon + `sysmon.xml` | Ferramenta | `C:\AntiRansom\tools\sysmon\` | Telemetria rica de processos/arquivos/threads. |
| Tarefas Agendadas | Config | Task Scheduler | Persistência de detectores/blocker como **SYSTEM** no boot. |

---

## 3. Fluxos Essenciais

### 3.1 Fluxo A — **Bloqueio no Kernel** (deny imediato)

1. Processo tenta **criar/modificar** arquivo em área protegida.  
2. **MiniFilter** aplica regra e retorna **STATUS_ACCESS_DENIED**.  
3. Auditoria (SACL) provoca **4656/4663** no Security.  
4. `hp_detect_security.py` ingere o evento e publica em `events.log`.  
5. `hp_blocker.py` correlaciona *handle/path → PID* e **finaliza** processo; copia binário para **quarentena**; loga ação.  
6. `arq_gui.py` atualiza a timeline e status.

### 3.2 Fluxo B — **Detecção via Sysmon** (allow + resposta rápida)

1. Processo cria/abre arquivo monitorado.  
2. **Sysmon** emite **EventID 11 (FileCreate)** / **1 (Process Create)** etc.  
3. `hp_detect_kernel.py` ingere, normaliza, grava em NDJSON.  
4. `hp_blocker.py` (regras) detecta padrão malicioso → **kill/quarentena** → log.  
5. GUI reflete o evento e a ação.

### 3.3 Fluxo C — **Inicialização/persistência**

1. No boot, **Task Scheduler** executa detectores e blocker como **SYSTEM**.  
2. Scripts validam diretórios (`data\`, `quarantine\`) e rotação de log.  
3. GUI pode ser aberta on‑demand por operador (não precisa rodar como SYSTEM).

---

## 4. Modelo de Dados e Logs

### 4.1 `events.log` (NDJSON, exemplo)
```json
{"ts":"2025-10-04T14:03:22.318Z","src":"security","eid":4656,"user":"LAB\\user","pid":5120,"op":"WRITE","path":"C:\\HoneyNet\\negado.txt","result":"DENY"}
{"ts":"2025-10-04T14:03:22.539Z","src":"sysmon","eid":11,"pid":5120,"ppid":4980,"sha256":"...","path":"C:\\Users\\user\\AppData\\Local\\Temp\\x.exe"}
{"ts":"2025-10-04T14:03:22.744Z","src":"blocker","action":"kill+quarantine","pid":5120,"exe":"C:\\Users\\user\\AppData\\Local\\Temp\\x.exe","qpath":"C:\\AntiRansom\\data\\quarantine\\Q_20251004_140322"}
```

### 4.2 `quarantine\Q_*/meta.json`
```json
{
  "ts": "2025-10-04T14:03:22.740Z",
  "pid": 5120,
  "ppid": 4980,
  "user": "LAB\\user",
  "exe_src": "C:\\Users\\user\\AppData\\Local\\Temp\\x.exe",
  "sha256": "B2D...",
  "reason": "write to protected path + entropy spike",
  "rules": ["KRN_FILECREATE_HONEY", "SEC_4656_DENY"],
  "sysmon_eid": [1,11],
  "notes": "killed via TerminateProcess; handles closed"
}
```

---

## 5. Interfaces e Integrações

### 5.1 Event Log (Security)
- **EIDs**: 4656 (Handle Request), 4663 (Access Attempted).  
- Requer **SACL** aplicada via `hp_enable_audit.py` nos diretórios monitorados.

### 5.2 Sysmon/Operational
- **EIDs chave**: 1 (ProcessCreate), 11 (FileCreate), 23 (FileDelete), 2 (FileCreateTime).  
- Configuração via `sysmon.xml` (incluir *include* para honeypots e *blocklist heurística*).

### 5.3 Sistema de Arquivos
- **MiniFilter** atua em IRP_MJ_CREATE/WRITE/SET_INFORMATION dependendo da regra.  
- Políticas básicas: **deny list** por caminho/extensão e **honeypots**.

### 5.4 Tarefas Agendadas
- `\AntiRansom\Detect-Security` → `hp_detect_security.py` (SYSTEM).  
- `\AntiRansom\Detect-Kernel` → `hp_detect_kernel.py` (SYSTEM).  
- `\AntiRansom\Blocker` → `hp_blocker.py --kill` (SYSTEM).

---

## 6. Configuração (padrões)

- **Paths**  
  - Base: `C:\AntiRansom\`  
  - Logs: `C:\AntiRansom\data\events.log`  
  - Quarentena: `C:\AntiRansom\data\quarantine\`  
  - Sysmon: `C:\AntiRansom\tools\sysmon\`

- **Políticas**  
  - Lista de diretórios protegidos (ex.: `C:\HoneyNet\`, `C:\Users\*\Documents\*`, `C:\ProgramData\AR_SAFE\*`).  
  - Extensões críticas (`.docx`, `.xlsx`, `.pdf`, `.db`, etc.).  
  - Thresholds heurísticos (ex.: *n* arquivos/minuto, entropia > X, extensão alvo + rename burst).

---

## 7. Segurança e Permissões

- **Driver**: em LAB, **TestSigning**; em produção, **EV/attestation** + **Secure Boot**.  
- **Detectores/Blocker**: executados como **SYSTEM** via Task Scheduler (para kill/quarentena confiável).  
- **GUI**: pode rodar como usuário comum; somente leitura dos logs.  
- **Hardening**:
  - Bloqueio de **Write** em honeypots pelo MiniFilter.  
  - Quarentena com cópia *atomic* + hash (evitar tampering).  
  - Logs **append‑only** e rotação (tamanho/data).

---

## 8. Observabilidade

- **Event Viewer**  
  - Security: 4656/4663/4688 (se habilitado).  
  - Microsoft‑Windows‑Sysmon/Operational: 1/11/23/…
- **Logs**  
  - `events.log` (NDJSON) — ingestão fácil em SIEM.  
  - `quarantine\meta.json` — forense local.  
- **GUI**  
  - Timeline de eventos, status dos serviços, contadores (bloqueios/kill/quarentena).

---

## 9. Desempenho e Resiliência

- **Baixo overhead** do MiniFilter em deny por caminho (match pré‑calculado).  
- Detectores usam **filtros** (XPath/Query) para evitar *busy‑loop*.  
- **Backoff** e retry em operações de quarentena (handle em uso).  
- **Fallback**: se Sysmon ausente, fluxo Security continua válido; se EventLog indisponível, Sysmon cobre criações de arquivo.

---

## 10. Limitações Conhecidas

- TestSigning/driver de LAB pode não carregar com **Secure Boot** ativo.  
- ATAQUES sob **contexto SYSTEM** podem contornar user‑mode (mitigar com MiniFilter e políticas).  
- Quarentena depende de liberação de handle; alguns *kill* podem falhar exigindo **Suspend → Kill** com retry.

---

## 11. Roadmap (Próximos Passos)

- **Assinatura de driver** e *CI pipeline* para build reproduzível.  
- **Lista dinâmica** de diretórios/Ext via arquivo `policy.yaml`.  
- **Mecanismo de isolamento** (AppContainer / Job Object) antes de kill.  
- **Proteção da solução** Proteger a solução em produção de matadores de soluções de proteção
- **Testes automatizados** (pytest) com simulação de eventos.

---

## 12. Anexos (exemplos úteis)

### 12.1 Tarefa agendada (SYSTEM) — Blocker
```powershell
$pyBlock = if (Test-Path "C:\AntiRansom\python\python.exe") { "`"C:\AntiRansom\python\python.exe`" `"`"C:\AntiRansom\scripts\hp_blocker.py`"`" --kill" } else { "py -3 `"`"C:\AntiRansom\scripts\hp_blocker.py`"`" --kill" }
schtasks /Create /TN "\AntiRansom\Blocker" /SC ONSTART /RL HIGHEST /RU SYSTEM /TR $pyBlock /F
```

### 12.2 Estrutura de pastas
```
C:\AntiRansom\
  driver\                  # passThrough.sys/.inf/.cat
  scripts\                 # *.py
  tools\sysmon\            # Sysmon64.exe, sysmon.xml
  data\                    # events.log, quarantine\
  docs\                    # *.md (guia, arquitetura, riscos, testes...)
```

---

**FIM — ARQUITETURA_TECNICA.md**
