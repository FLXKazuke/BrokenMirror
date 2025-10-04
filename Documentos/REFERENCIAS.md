# REFERENCIAS.md — Projeto BrokenMirror

> Compilação das principais **referências técnicas e acadêmicas** utilizadas durante o desenvolvimento, testes e documentação da solução **Anti-Ransomware BrokenMirror** (Sprint 4 — FIAP / Pride Security 2025).

---

## 📚 1. Documentação Técnica da Microsoft

- [Windows Driver Kit (WDK) — File System Minifilter Drivers](https://learn.microsoft.com/en-us/windows-hardware/drivers/ifs/filter-manager-concepts)  
  > Referência base para o desenvolvimento do driver `passThrough.sys`, incluindo estrutura de INF/CAT/SYS, IRP_MJ_CREATE interceptors e políticas de acesso.  
- [Filter Manager — Architecture Overview](https://learn.microsoft.com/en-us/windows-hardware/drivers/ifs/filter-manager-concepts)  
- [Building, Signing, and Deploying Drivers](https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/)  
- [Sysmon — System Monitor (Sysinternals)](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)  
  > Base para coleta de eventos 1, 11 e 23 (ProcessCreate, FileCreate, FileDelete).  
- [Windows Event IDs (Security Log Reference)](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/basic-audit-object-access)  
  > Mapeamento dos eventos 4656/4663 utilizados pelos scripts de detecção.  

---

## ⚙️ 2. Ferramentas Sysinternals e de Laboratório

- **Process Explorer / Autoruns / RootkitRevealer** — análise comportamental e controle de processos.  
- **VMware Workstation / Hyper-V** — ambiente isolado para execução controlada de amostras.  
- **PowerShell Logging** — para coleta detalhada de execução dos scripts e eventos WMI.  
- **Chocolatey / Pandoc / wkhtmltopdf** — empacotamento e geração automática de documentação.  

---

## 🧠 3. Padrões e Frameworks de Segurança

- **NIST SP 800-83r1** — *Guide to Malware Incident Prevention and Handling for Desktops and Laptops*  
  > Referência para o ciclo de resposta a incidentes (detecção → contenção → erradicação → recuperação).  
- **NIST Cybersecurity Framework (CSF 1.1)** — funções *Identify, Protect, Detect, Respond, Recover*.  
- **ISO/IEC 27001:2022** — requisitos para gestão de segurança da informação.  
- **CIS Critical Security Controls v8** — Controles 8 (Malware Defense) e 13 (Network Monitoring).  
- **MITRE ATT&CK Framework** — técnicas *T1486 (Data Encryption)* e *T1059 (Command Execution)* para mapeamento dos eventos simulados.  

---

## 🧪 4. Relatórios e Whitepapers sobre Ransomware

- **Trend Micro Vision One — Ransomware Threat Landscape Report 2024**  
- **Sophos Threat Report 2024** — seções sobre Kill-Process Behavior e Persistência em User-Mode.  
- **Fortinet 2024 Global Threat Landscape Report** — estatísticas de ataque e famílias de ransomware predominantes.  
- **Microsoft Security Intelligence Report — Human-Operated Ransomware (2023)**  
- **Kaspersky Securelist — Ransomware Trends Q1–Q4 2024**  

---

## 🧰 5. Bibliotecas, APIs e Tecnologias Utilizadas

| Tecnologia | Uso | Referência |
|-------------|-----|-------------|
| **Python 3.11+** | Detecção, GUI e automação (Tkinter, os, psutil, json, logging) | https://docs.python.org/3/ |
| **PowerShell 5+** | Criação de SACL, auditoria e automação | https://learn.microsoft.com/en-us/powershell/ |
| **WDK 10 + Visual Studio 2022** | Desenvolvimento do driver kernel | https://learn.microsoft.com/en-us/windows-hardware/drivers/ |
| **Sysmon + Sysinternals Suite** | Telemetria avançada de sistema | https://learn.microsoft.com/en-us/sysinternals/ |
| **Windows EventLog API / WMI** | Captura de eventos de segurança | https://learn.microsoft.com/en-us/windows/win32/eventlog/event-logging-functions |
| **Tkinter** | Interface gráfica do usuário | https://docs.python.org/3/library/tkinter.html |

---

## 🧩 6. Recursos de Apoio e Comunidades

- **GitHub — microsoft/Windows-driver-samples**  
  https://github.com/microsoft/Windows-driver-samples  
- **Sysinternals Community Forum** — https://learn.microsoft.com/en-us/answers/topics/sysinternals.html  
- **Reddit r/blueTeamSec** — discussões sobre defesa ativa e detecção comportamental.  
- **Stack Overflow (tag: winapi, minifilter, sysmon)** — resolução de problemas técnicos.  
- **MDN Docs / Pandoc** — para documentação em Markdown e conversão de formatos.  

---

## 🧾 7. Créditos Educacionais e Parcerias

- **FIAP — Faculdade de Informática e Administração Paulista (1TDCR)**  
  - Coordenação acadêmica e proposta do desafio “Proteja o Futuro — Anti-Ransomware”.  
- **Pride Security (Parceiro FIAP)**  
  - Apoio técnico e ambiente de testes durante a Sprint 4.  
- **Microsoft Learn Student Hub / Sysinternals Live**  
  - Recursos usados na preparação e simulação de cenários reais.

---
