# CREDITOS.md — Equipe BrokenMirror

> Projeto desenvolvido para a disciplina **Cyber Security — FIAP (1TDCR)**  
> Entrega Sprint 4 — Solução Anti-Ransomware "BrokenMirror"  
> Todos os integrantes participaram ativamente da **criação da ideia**, **prototipação** e **implementação final**.

---

## 👥 Equipe de Desenvolvimento

### **Andrey da Silva Feitosa — RM 563533**
**Função:** Apoio em infraestrutura e preparação de ambientes  
- Responsável pela **configuração das VMs de teste**, integração entre redes e sistemas operacionais.  
- Gerenciou os snapshots e isolamento de rede para os testes de ransomware.  
- Auxiliou na coleta de métricas de desempenho e estabilidade durante os experimentos.  
- Garantiu que os ambientes fossem restauráveis e seguros para execução das amostras.

---

### **Felipe Alves Brito — RM 564642**
**Função:** Desenvolvedor Kernel / Produção da solução em nível de driver  
- Responsável pelo **desenvolvimento e compilação do MiniFilter** (`passThrough.sys`).  
- Trabalhou na comunicação entre o **driver kernel** e os scripts em user-mode.  
- Implementou ajustes no **.inf e assinatura de teste (TestSigning)**.  
- Criou documentação de build e auxiliou na depuração via Visual Studio + WDK.  

---

### **Jorge Santos Henriques de Oliveira — RM 561271**
**Função:** Desenvolvedor Principal (User-mode + Integração)  
- Estruturou os módulos **Python e PowerShell** para honeypots, detecção e resposta.  
- Desenvolveu a **interface gráfica (Tkinter)** para monitoramento em tempo real.  
- Coordenou a integração entre **driver**, **Sysmon** e **EventLog Security**.  
- Criou os scripts de automação e o **manual técnico de instalação e execução (`guia.md`)**.  

---

### **Gabriel Costa Barroso — RM 565683**
**Função:** Testador de Ransomwares (Lab / Validação)  
- Responsável pelos **testes práticos de ataque**, utilizando amostras controladas (WannaCry, Locky, Ryuk, etc.).  
- Coletou **logs, prints e evidências** para o relatório de resultados.  
- Ajudou a validar tempo de resposta e eficiência da quarentena.  
- Reproduziu o ataque da versão V1 (custom ransomware) na apresentação para **Pride Security**.  

---

### **Nícola Loreto Cyriaco — RM 562846**
**Função:** Apresentador Geral e Design  
- Responsável pela **apresentação final** da solução, identidade visual e estrutura dos slides.  
- Criou os **materiais gráficos** e diagramas usados na documentação.  
- Contribuiu no refinamento visual da GUI e na padronização dos `.md` do projeto.  
- Atuou como ponte entre equipe técnica e banca avaliadora.  

---

## 🤝 Colaboração e Ideia Coletiva

Todos os membros participaram ativamente:
- **Concepção da ideia inicial do BrokenMirror.**
- **Discussão sobre arquitetura híbrida** (Kernel + User-mode).
- **Implementação conjunta** de honeypots, scripts de auditoria e bloqueio.  
- **Testes em laboratório** e ajuste fino da resposta automática.  

> A solução final representa o esforço conjunto de toda a equipe, com integração constante entre desenvolvimento, testes, design e operação em campo.

---

**FIAP — 1TDCR | Projeto Anti-Ransomware — “BrokenMirror” (Sprint 4)**
