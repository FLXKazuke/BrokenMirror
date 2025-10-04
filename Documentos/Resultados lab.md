# RESULTADOS LAB.md — BrokenMirror

> Relatório de execução real em ambiente controlado (LAB AntiRansom FIAP — Sprint 4).  
> Testes realizados entre **28/09 e 03/10/2025**, incluindo amostras conhecidas e variantes controladas de ransomware.

---

## 1. Ambiente de Teste

| Item | Especificação |
|------|----------------|
| **Sistema Base** | Windows 11 Pro x64 (VM isolada) |
| **Hypervisor** | VMware Workstation Pro 17 |
| **CPU/RAM** | 4 vCPU / 6 GB RAM |
| **Modo de Execução** | Snapshot “Pré-ataque” + rollback automático |
| **Sysmon** | v15.11 (config customizada `sysmon.xml`) |
| **Driver** | passThrough.sys compilado em modo **TestSigning** |
| **Ferramentas auxiliares** | Process Explorer, Autoruns, RootkitRevealer, PowerShell Logging |
| **Versão da Solução** | BrokenMirror v1.0.4 (Sprint 4 – entrega final) |

---

## 2. Amostras e Resultados

| Ransomware / Variante | Detecção | Bloqueio | Quarentena | Observações |
|-----------------------|-----------|-----------|-------------|-------------|
| **WannaCry (sample)** | ✅ via Sysmon ID 11 + Security 4656 | ✅ (processo encerrado) | ✅ (`Q_20250928_2235`) | Bloqueado antes de cifrar arquivos honeypot. |
| **Locky (emulado)** | ✅ | ✅ | ✅ | Detectado pelo spike de I/O em honeypots. |
| **CryptoWall 3.0 (simulado)** | ✅ | ✅ | ✅ | Bloqueio kernel negou escrita em diretório protegido. |
| **Ryuk (simulação Python)** | ✅ | ✅ | ✅ | Detectado por Sysmon + bloqueio simultâneo via kernel. |
| **Petya (sample estático)** | ✅ | ⚠️ Parcial | ❌ | Tentou reescrever MBR – fora do escopo de interceptação de arquivo. |
| **RansomEXX (simulado)** | ✅ | ✅ | ✅ | Bloqueio completo + hash de binário armazenado. |
| **_V1 ransomware custom (teste Pride Security)_** | ⚠️ | ❌ | ❌ | Processo encerrou o `hp_blocker.py` e `hp_detect_*` antes de iniciar o ataque. |

---

## 3. Logs Capturados (trechos)

Trecho do `events.log` referente à amostra WannaCry:

```json
{"ts":"2025-09-28T22:35:42.318Z","src":"security","eid":4656,"user":"LAB\\student","pid":6340,"op":"WRITE","path":"C:\\HoneyNet\\test.docx","result":"DENY"}
{"ts":"2025-09-28T22:35:42.339Z","src":"blocker","action":"kill+quarantine","pid":6340,"exe":"C:\\Users\\lab\\AppData\\Roaming\\wannacry.exe","qpath":"C:\\AntiRansom\\data\\quarantine\\Q_20250928_2235"}
```

Trecho da quarentena (`meta.json`):
```json
{
  "pid": 6340,
  "exe_src": "C:\\Users\\lab\\AppData\\Roaming\\wannacry.exe",
  "reason": "write to protected path",
  "action": "terminated",
  "sha256": "3fdfb4a...e1c9b"
}
```

---

## 4. Performance e Impacto

| Métrica | Valor médio | Observação |
|----------|--------------|-------------|
| **Tempo de resposta médio (detecção → kill)** | 1.2 s | Inclui overhead de EventLog + thread blocker |
| **Uso de CPU (idle)** | 1–2% | Detectores em espera |
| **Uso de CPU (durante ataque)** | 10–15% pico | Principalmente pelo `hp_blocker.py` |
| **Memória média dos serviços** | 120 MB | Somando detectores, blocker e GUI |

---

## 5. Falhas e Aprendizados

Durante a apresentação para **Pride Security**, a amostra **_V1 ransomware custom_** não foi bloqueada.  
O agente conseguiu **finalizar nossos processos Python** (`hp_blocker.py`, `hp_detect_security.py`, `hp_detect_kernel.py`) antes de iniciar a criptografia.

### Causa:
- Ausência de mecanismo de **auto-proteção da própria solução** (sem watchdog/serviço protegido).  
- `Task Scheduler` não restarta automaticamente os daemons finalizados.  

### Impacto:
- O ransomware executou sem restrição após encerrar os serviços.  
- Quarentena e logs pararam de ser atualizados.  

### Correção proposta:
- Implementar **módulo watchdog em kernel-mode** ou serviço **Windows Service** com proteção via **SCM lockdown**.  
- Opcionalmente, ativar **WFP (Windows Filtering Platform)** para travar tentativas de `TerminateProcess` direcionadas aos PIDs da solução.

---

## 6. Conclusões Gerais

- A solução demonstrou **eficácia comprovada contra ransomware comum** (WannaCry, Locky, CryptoWall, Ryuk).  
- **Tempo de resposta abaixo de 2 segundos** na maioria dos casos.  
- **Logs detalhados e rastreáveis** (NDJSON + meta.json).  
- Falha pontual com ransomware custom (V1) destacou necessidade de **auto-defesa da própria ferramenta**.  
- Arquitetura modular (driver + user-mode + GUI) facilita expansão e futura integração com SIEM.

---

## 7. Próximos Passos

- Adicionar **serviço watchdog** (reinício automático dos detectores).  
- Proteger processos da solução via ACL (deny TerminateProcess).  
- Integrar logs NDJSON com **Winlogbeat → Elastic SIEM**.  
- Criar **modo “Silent”** para execução totalmente headless em servidores.  
- Implementar **assinatura digital EV** para uso em ambientes com Secure Boot.

---

