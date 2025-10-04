
---

# Guia de Instalação e Execução — BrokenMirror (Entrega Sprint 4)

## 1. Visão geral
A solução BrokenMirror combina:
- **Driver MiniFilter (kernel)** para negar operações de arquivo em áreas protegidas.
- **User-mode (Python/PowerShell)** para honeypots, auditoria (SACL), detecção (Security/Sysmon), resposta automática (suspender/kill) e quarentena.
- **GUI (Tkinter)** para acompanhar eventos em tempo real.

Fluxo básico: o driver bloqueia → evento 4656 (ACCESS_DENIED) no Security → detector registra → blocker resolve o PID e finaliza o processo → binário em quarentena → GUI exibe.

---

## 2. Pré-requisitos
- Windows 10 ou 11 (VM recomendada para LAB).
- **Administrador** da máquina.
- **Git** instalado.
- **Python 3.11+** instalado 
- **Sysmon** (opcional, recomendado): `tools\sysmon\Sysmon64.exe` + `sysmon.xml`.
- Para driver de desenvolvimento (**test-signed**): habilitar **TestSigning**.

> Produção requer driver assinado com certificado **EV/attestation** e suporte a **Secure Boot**.

---

## 3. Clonar o repositório
Abra **PowerShell (Administrador)** e execute:

```powershell
git clone https://github.com/FLXKazuke/BrokenMirror.git C:\AntiRansom
cd C:\AntiRansom
```

Atualizar depois:

```powershell
git pull origin main
```

---

## 4. Estrutura esperada do projeto

```
C:\AntiRansom\
  driver\                 # passThrough.inf, passThrough.sys, passThrough.cat
  scripts\                # hp_seed.py, hp_enable_audit.py, hp_detect_security.py, hp_detect_kernel.py, hp_blocker.py, arq_gui.py, etc.
  tools\sysmon\          # Sysmon64.exe, sysmon.xml (opcional, recomendado)
  data\                   # events.log e quarantine\ (criados em runtime)
  docs\                   # documentação
  install\                # scripts auxiliares (opcional)
  README.md
```

---

## 5. Instalação e execução (passo a passo)

### 5.1 Preparar o PowerShell e desbloquear arquivos

```powershell
Set-ExecutionPolicy Bypass -Scope Process -Force
Get-ChildItem "C:\AntiRansom" -Recurse | Unblock-File
```

### 5.2 (Opcional) Habilitar TestSigning (driver de desenvolvimento)

> Requer reiniciar 1 vez. Se **Secure Boot** estiver ativo, drivers de teste podem não carregar.

```powershell
bcdedit /set testsigning on
shutdown /r /t 0
```

---

### 5.3 Compilar o driver MiniFilter (Visual Studio e VS Code)

#### 5.3.1 Copiar o sample `passThrough`

Você pode usar o sample oficial da Microsoft (WDK):

```powershell
mkdir C:\src -ea 0
Invoke-WebRequest "https://codeload.github.com/microsoft/Windows-driver-samples/zip/refs/heads/main" -OutFile "C:\src\Windows-driver-samples.zip"
Expand-Archive -Path "C:\src\Windows-driver-samples.zip" -DestinationPath "C:\src" -Force
# Copie o sample para dentro do projeto
Copy-Item "C:\src\Windows-driver-samples-main\filesys\miniFilter\passThrough" `
  -Destination "C:\AntiRansom\driver\source\passThrough" -Recurse -Force
```

> Alternativa: se você já possui seu `passThrough` customizado, apenas **cole a pasta** em `C:\AntiRansom\driver\source\passThrough`.

#### 5.3.2 Compilar no **Visual Studio 2022 + WDK** (recomendado)

1. Abra `C:\AntiRansom\driver\source\passThrough\passThrough.sln` no **Visual Studio 2022**.
2. Selecione **Release** (Config) e **x64** (Platform).
3. Projeto `passThrough` → **Properties**:
   - **Driver Settings → Target OS Version**: Windows 10/11 (a sua versão).
   - **General → Platform Toolset**: `WindowsKernelModeDriver10.0`.
   - **Driver Signing → Sign Mode**: `Test Sign` → **Create Test Certificate…** (aceite o padrão).
4. **Build** → **Build Solution** (`Ctrl+Shift+B`).
5. Saída dos artefatos:
   - `passThrough.sys` e `passThrough.cat` na pasta de saída de **Release (x64)** do projeto.
   - `passThrough.inf` na raiz do projeto (ou em **Release** dependendo do sample).
6. Copie o **trio** para a pasta de driver da solução:

```powershell
Copy-Item ".\x64\Release\passThrough.sys" "C:\AntiRansom\driver\" -Force
Copy-Item ".\x64\Release\passThrough.cat" "C:\AntiRansom\driver\" -Force
Copy-Item ".\passThrough.inf"              "C:\AntiRansom\driver\" -Force
```

> Importante: **não edite** `.inf`/`.sys` após o build, ou o `.cat` perde validade. Se alterar algo, **rebuild** para gerar novo `.cat`.

#### 5.3.3 Compilar via **VS Code** (opcional, usando MSBuild)

> VS Code não compila drivers por si só, mas pode **chamar o MSBuild** (instalado com VS/Build Tools) e o WDK.

1. Instale:
   - **Visual Studio Build Tools 2022** (com **MSVC v143** e **Windows 10/11 SDK**).
   - **WDK 10** correspondente ao SDK.
2. Abra **Developer PowerShell for VS 2022** (ou **x64 Native Tools Command Prompt**), navegue ao projeto e rode:

```powershell
cd C:\AntiRansom\driver\source\passThrough
msbuild passThrough.vcxproj /p:Configuration=Release /p:Platform=x64
```

3. Artefatos saem em **Release (x64)**. Copie o trio para `C:\AntiRansom\driver\` (como no passo 5.3.2).
4. (Opcional) Automatize no VS Code com `tasks.json` (pasta `.vscode`):

```json
{
  "version": "2.0.0",
  "tasks": [
    {
      "label": "Build MiniFilter (Release x64)",
      "type": "shell",
      "command": "msbuild",
      "args": [
        "passThrough.vcxproj",
        "/p:Configuration=Release",
        "/p:Platform=x64"
      ],
      "options": { "cwd": "${workspaceFolder}/driver/source/passThrough" },
      "problemMatcher": []
    }
  ]
}
```

Execute a task no VS Code (**Terminal → Run Task…**).

---

### 5.4 Instalar e carregar o driver

Com o trio na pasta `C:\AntiRansom\driver\`:

```powershell
pnputil /add-driver "C:\AntiRansom\driver\passThrough.inf" /install
fltmc load passThrough
fltmc filters
fltmc instances
```

Se falhar, verifique **TestSigning** e a presença do `.cat` correspondente.

### 5.5 Instalar Sysmon

```powershell
C:\AntiRansom\tools\sysmon\Sysmon64.exe -i C:\AntiRansom\tools\sysmon\sysmon.xml -accepteula
```

### 5.6 Criar honeypots e habilitar auditoria (SACL)

```powershell
$py = if (Test-Path "C:\AntiRansom\python\python.exe") { "C:\AntiRansom\python\python.exe" } else { "py -3" }
& $py "C:\AntiRansom\scripts\hp_seed.py"
& $py "C:\AntiRansom\scripts\hp_enable_audit.py"
```

### 5.7 Iniciar detectores (background)

```powershell
Start-Process -WindowStyle Hidden $py -ArgumentList "C:\AntiRansom\scripts\hp_detect_security.py"
Start-Process -WindowStyle Hidden $py -ArgumentList "C:\AntiRansom\scripts\hp_detect_kernel.py"
```

### 5.8 Iniciar blocker (background) e persistir no boot (SYSTEM)

Iniciar agora:

```powershell
Start-Process -WindowStyle Hidden $py -ArgumentList "C:\AntiRansom\scripts\hp_blocker.py --kill"
```

Criar tarefa agendada (SYSTEM) para iniciar no boot:

```powershell
$pyBlock = if (Test-Path "C:\AntiRansom\python\python.exe") { "`"C:\AntiRansom\python\python.exe`" `"`"C:\AntiRansom\scripts\hp_blocker.py`"`" --kill" } else { "py -3 `"`"C:\AntiRansom\scripts\hp_blocker.py`"`" --kill" }
schtasks /Create /TN "\AntiRansom\Blocker" /SC ONSTART /RL HIGHEST /RU SYSTEM /TR $pyBlock /F
```

(Repita para Detect-Security e Detect-Kernel se quiser persistir ambos como SYSTEM.)

### 5.9 Abrir as GUI

```powershell
& $py "C:\AntiRansom\scripts\arq_gui.py"
& $py "C:\AntiRansom\ui\app.py"
```

---

## 6. Testes de validação

### Cenário A — Bloqueio direto no kernel (deny)

```powershell
cmd /c "echo oi> C:\HoneyNet\negado.txt"
```

Resultado esperado: arquivo **não criado**; Security 4656 registrado; blocker finaliza/quarentena.

### Cenário B — Criação detectada (Sysmon) com resposta

```powershell
mkdir C:\ProgramData\AR_SAFE -ea 0 | Out-Null
cmd /c "echo ok> C:\ProgramData\AR_SAFE\passou.txt"
```

Resultado esperado: arquivo criado; Sysmon registra FileCreate; blocker finaliza/quarentena.

---

## 7. Logs e quarentena (onde verificar)

- `C:\AntiRansom\data\events.log`
- `C:\ProgramData\AntiRansom\logs\` (NDJSON dos detectores)
- `C:\AntiRansom\data\quarantine\Q_*` (binários copiados + `meta.json`)
- Event Viewer:
  - **Security** (4656/4663)
  - **Microsoft-Windows-Sysmon/Operational** (11, 23 etc.)

---

## 8. Desinstalação / rollback

Parar processos Python:

```powershell
Get-Process python,py -ErrorAction SilentlyContinue | Where-Object { $_.CommandLine -match "hp_detect_|hp_blocker|arq_gui" } | Stop-Process -Force
```

Remover tarefas:

```powershell
schtasks /Delete /TN "\AntiRansom\Detect-Security" /F
schtasks /Delete /TN "\AntiRansom\Detect-Kernel" /F
schtasks /Delete /TN "\AntiRansom\Blocker" /F
```

Descarregar e remover driver:

```powershell
fltmc unload passThrough
pnputil /enum-drivers | Select-String -Pattern "Published Name|Original Name|passThrough"
# Identifique o oemXX.inf do passThrough e remova:
pnputil /delete-driver oemXX.inf /uninstall /force
```

Desinstalar Sysmon (opcional):

```powershell
if (Test-Path "C:\AntiRansom\tools\sysmon\Sysmon64.exe") { C:\AntiRansom\tools\sysmon\Sysmon64.exe -u force }
```

Limpar pastas:

```powershell
Remove-Item -Recurse -Force "C:\AntiRansom" -ErrorAction SilentlyContinue
Remove-Item -Recurse -Force "C:\ProgramData\AntiRansom" -ErrorAction SilentlyContinue
```

---


## 10. Considerações de segurança e produção

- **LAB**: use TestSigning; **Produção**: driver assinado EV/attestation + Secure Boot.
- **Privilégios**: bloqueador/detectores devem rodar elevados (SYSTEM para resposta confiável).
- **Amostras reais**: somente em VMs isoladas com snapshots e rede isolada.

---

## 11. Comandos rápidos (resumo)

```powershell
git clone https://github.com/FLXKazuke/BrokenMirror.git C:\AntiRansom
Set-ExecutionPolicy Bypass -Scope Process -Force
Get-ChildItem "C:\AntiRansom" -Recurse | Unblock-File

pnputil /add-driver "C:\AntiRansom\driver\passThrough.inf" /install
fltmc load passThrough

C:\AntiRansom\tools\sysmon\Sysmon64.exe -i C:\AntiRansom\tools\sysmon\sysmon.xml -accepteula

$py = if (Test-Path "C:\AntiRansom\python\python.exe") { "C:\AntiRansom\python\python.exe" } else { "py -3" }
& $py "C:\AntiRansom\scripts\hp_seed.py"
& $py "C:\AntiRansom\scripts\hp_enable_audit.py"

Start-Process -WindowStyle Hidden $py -ArgumentList "C:\AntiRansom\scripts\hp_detect_security.py"
Start-Process -WindowStyle Hidden $py -ArgumentList "C:\AntiRansom\scripts\hp_detect_kernel.py"
Start-Process -WindowStyle Hidden $py -ArgumentList "C:\AntiRansom\scripts\hp_blocker.py --kill"

& $py "C:\AntiRansom\scripts\arq_gui.py"
```
