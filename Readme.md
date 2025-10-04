<p align="center">
  <img src="\BrokenMirror\AntiRansom\Documentos\img\BrokenMirror.jpeg" width="800" alt="Logo e Arquitetura do Projeto BrokenMirror">
</p>
# 🧠 BrokenMirror — FIAP | Pride Security

Repositório dedicado à entrega da **Solução Anti-Ransomware (Sprint 4 — Final)**  
Desenvolvido em parceria com a **Pride Security**, o projeto tem como objetivo **bloquear e mitigar ataques de ransomware** de forma global, eficiente e automatizada.

---

## 💡 Visão Geral
O **BrokenMirror** combina camadas de **bloqueio em kernel** (driver MiniFilter) com **detecção e resposta em user-mode** (Python e PowerShell).  
Sua missão é **impedir a criptografia de arquivos** e **interromper processos maliciosos em tempo real**.

### ⚙️ Pré-requisitos
> É necessário permitir que o programa tenha acesso total à máquina (execução como **Administrador**).

- Sistema operacional: **Windows 10/11**
- **Acesso administrativo**
- **Modo Test Signing** habilitado (para o driver de desenvolvimento)
- **Sysmon** e **Python 3.11+** instalados

---

## 🧱 Arquitetura Simplificada
| Camada | Função | Tecnologias |
|:-------|:-------|:-------------|
| **Kernel (Minifilter)** | Intercepta e bloqueia operações suspeitas de escrita/modificação. | C / WDK / INF-SYS-CAT |
| **User-mode** | Detecta eventos via Security/Sysmon e responde (suspende, mata, quarentena). | Python / PowerShell |
| **Honeypots & Auditoria** | Gera arquivos isca e ativa SACL para auditoria de acessos negados. | Python / PowerShell |
| **GUI (Tkinter)** | Exibe logs, quarentenas e status em tempo real. | Python / PowerShell |
| **Sysmon** | Coleta eventos avançados de sistema. | Sysinternals |
