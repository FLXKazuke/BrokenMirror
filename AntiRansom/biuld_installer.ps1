# C:\AntiRansom\build_installer.ps1 
$ErrorActionPreference = "Stop"

function Require-Admin {
  $wi=[Security.Principal.WindowsIdentity]::GetCurrent()
  $pr=New-Object Security.Principal.WindowsPrincipal($wi)
  if(-not $pr.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){
    throw "Abra o PowerShell como Administrador."
  }
}
Require-Admin

# --- Localizações ---
$SRC      = "C:\AntiRansom"
$STAGE    = Join-Path $env:TEMP "AR_STAGE"
$OUT_EXE  = Join-Path ([Environment]::GetFolderPath('Desktop')) "AntiRansom_Installer.exe"
$PAY7Z    = Join-Path $env:TEMP "AR_payload.7z"
$CFG      = Join-Path $env:TEMP "AR_sfx_config.txt"

# Tente achar 7z.exe e 7zsd.sfx
# --- Tenta localizar 7z.exe e 7zsd.sfx com segurança ---
$SevenZipDirs = @("C:\Program Files\7-Zip","C:\Program Files (x86)\7-Zip")

$gc = Get-Command 7z -ErrorAction SilentlyContinue
if ($gc) {
  $dirFromPath = Split-Path -Parent $gc.Source
  if ($dirFromPath) { $SevenZipDirs += $dirFromPath }
}

$SevenZipDirs = $SevenZipDirs | Where-Object { $_ -and (Test-Path $_) } | Select-Object -Unique

$Z   = $SevenZipDirs | ForEach-Object { Join-Path $_ "7z.exe" }    | Where-Object { Test-Path $_ } | Select-Object -First 1
$SFX = $SevenZipDirs | ForEach-Object { Join-Path $_ "7z.exe" }  | Where-Object { Test-Path $_ } | Select-Object -First 1

if (-not $Z)   { throw "7z.exe não encontrado. Instale o 7-Zip ou ajuste o caminho." }
if (-not $SFX) { throw "7zsd.sfx não encontrado. Verifique a pasta do 7-Zip (geralmente em 'C:\Program Files\7-Zip')." }


Write-Host "Preparando staging…"
Remove-Item -Recurse -Force $STAGE -ErrorAction SilentlyContinue | Out-Null
New-Item -ItemType Directory -Path $STAGE | Out-Null
Copy-Item "$SRC\*" $STAGE -Recurse -Force

$install = @'
# install.ps1 (executa no alvo) — rodar como ADMIN
$ErrorActionPreference = "Stop"
function Require-Admin {
  $wi=[Security.Principal.WindowsIdentity]::GetCurrent()
  $pr=New-Object Security.Principal.WindowsPrincipal($wi)
  if(-not $pr.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){
    throw "Abra o PowerShell como Administrador."
  }
}
Require-Admin

$ROOT="C:\AntiRansom"
$DATA=Join-Path $ROOT "data"
$QUAR=Join-Path $DATA "quarantine"
$SCRIPTS=Join-Path $ROOT "scripts"
$TOOLS=Join-Path $ROOT "tools"
$BIN=Join-Path $ROOT "bin"
@($DATA,$QUAR) | ForEach-Object { New-Item -ItemType Directory -Path $_ -EA 0 | Out-Null }
if(-not (Test-Path (Join-Path $DATA "events.log"))){ New-Item -ItemType File -Path (Join-Path $DATA "events.log") | Out-Null }

function Log($m){ Write-Host "[$(Get-Date -Format s)] $m" }

# (opcional) ativa TestSigning p/ driver teste-signed
try{
  $boot=(bcdedit | Out-String)
  if($boot -notmatch "testsigning\s+Yes"){
    Log "Ativando TestSigning (pode exigir reboot p/ carregar driver pela 1ª vez)…"
    bcdedit /set testsigning on | Out-Null
  }
}catch{}

# Driver
$INF=Join-Path $ROOT "driver\passThrough.inf"
if(Test-Path $INF){
  Log "Instalando driver…"
  pnputil /add-driver "$INF" /install | Out-Null
  Log "Carregando minifilter…"
  fltmc load passThrough | Out-Null
}else{ Log "AVISO: passThrough.inf não encontrado." }

# Sysmon
$SYSMON=Join-Path $TOOLS "sysmon\Sysmon64.exe"
$SYSCFG=Join-Path $TOOLS "sysmon\sysmon.xml"
if(Test-Path $SYSMON){
  if(-not (Get-Service -Name sysmon64 -ErrorAction SilentlyContinue)){
    Log "Instalando Sysmon…"; & $SYSMON -i $SYSCFG -accepteula | Out-Null
  } else { Log "Sysmon já instalado." }
}else{ Log "AVISO: Sysmon não incluso (opcional)." }

# Helpers p/ rodar .py ou .exe
function Invoke-Py { param([string]$script,[string]$args="")
  $pyembed = Join-Path $ROOT "python\python.exe"
  $exe = Join-Path $BIN ([IO.Path]::GetFileNameWithoutExtension($script)+".exe")
  if(Test-Path $exe){ Start-Process -WindowStyle Hidden $exe $args; return }
  if(Test-Path $pyembed){ Start-Process -WindowStyle Hidden $pyembed "`"$SCRIPTS\$script`" $args"; return }
  if(Get-Command py -ErrorAction SilentlyContinue){ Start-Process -WindowStyle Hidden "py" "-3 `"$SCRIPTS\$script`" $args"; return }
  Start-Process -WindowStyle Hidden "python" "`"$SCRIPTS\$script`" $args"
}

# Honeypots + Auditoria
Log "Semeando honeypots…"; Invoke-Py "hp_seed.py"; Start-Sleep -Milliseconds 800
Log "Habilitando auditoria/SACL…"; Invoke-Py "hp_enable_audit.py"

# Detectores + Bloqueador (agora e no boot)
function New-ARTask { param($name,$cmd)
  $tn="\AntiRansom\$name"
  schtasks /Delete /TN $tn /F 2>$null | Out-Null
  schtasks /Create /TN $tn /SC ONSTART /RL HIGHEST /RU SYSTEM /TR $cmd | Out-Null
}
function CmdPy($script,$args){
  $pyembed = Join-Path $ROOT "python\python.exe"
  $exe = Join-Path $BIN ([IO.Path]::GetFileNameWithoutExtension($script)+".exe")
  if(Test-Path $exe){ return "`"$exe`" $args" }
  elseif(Test-Path $pyembed){ return "`"$pyembed`" `"$SCRIPTS\$script`" $args" }
  elseif(Get-Command py -ErrorAction SilentlyContinue){ return "py -3 `"$SCRIPTS\$script`" $args" }
  else{ return "python `"$SCRIPTS\$script`" $args" }
}

New-ARTask "Detect-Security" (CmdPy "hp_detect_security.py" "")
New-ARTask "Detect-Kernel"   (CmdPy "hp_detect_kernel.py"   "")
New-ARTask "Blocker"         (CmdPy "hp_blocker.py"         "--kill")

Log "Iniciando detectores/bloqueador…"
Invoke-Py "hp_detect_security.py"
Invoke-Py "hp_detect_kernel.py"
Invoke-Py "hp_blocker.py" "--kill"

# Atalho GUI (se existir)
$desktop=[Environment]::GetFolderPath("CommonDesktopDirectory")
$lnk=Join-Path $desktop "AntiRansom GUI.lnk"
$W=New-Object -ComObject WScript.Shell
$sc=$W.CreateShortcut($lnk)
if(Test-Path (Join-Path $BIN "arq_gui.exe")){
  $sc.TargetPath = Join-Path $BIN "arq_gui.exe"
}elseif(Test-Path (Join-Path $SCRIPTS "arq_gui.py")){
  $pyembed = Join-Path $ROOT "python\python.exe"
  if(Test-Path $pyembed){ $sc.TargetPath=$pyembed; $sc.Arguments="`"$SCRIPTS\arq_gui.py`"" }
  else { $sc.TargetPath="py"; $sc.Arguments="-3 `"$SCRIPTS\arq_gui.py`"" }
}else{
  $sc.TargetPath="notepad.exe"; $sc.Arguments="`"$DATA\events.log`""
}
$sc.WorkingDirectory=$ROOT; $sc.IconLocation="shell32.dll,167"; $sc.Save()

Write-Host "Instalação concluída. Se TestSigning foi ativado agora, reinicie uma vez para o driver carregar."
'@
Set-Content -Path (Join-Path $STAGE "install.ps1") -Value $install -Encoding UTF8

$uninstall = @'
# uninstall.ps1 (rodar como ADMIN)
$ErrorActionPreference="SilentlyContinue"
Get-Process python,py | Where-Object {
  $_.CommandLine -match "hp_detect_security.py|hp_detect_kernel.py|hp_blocker.py|arq_gui.py"
} | Stop-Process -Force

schtasks /Delete /TN "\AntiRansom\Detect-Security" /F 2>$null | Out-Null
schtasks /Delete /TN "\AntiRansom\Detect-Kernel"   /F 2>$null | Out-Null
schtasks /Delete /TN "\AntiRansom\Blocker"         /F 2>$null | Out-Null
try{ schtasks /Delete /TN "\AntiRansom" /F 2>$null | Out-Null }catch{}

fltmc unload passThrough 2>$null | Out-Null
# remove oem*.inf do driver nosso
$oems = pnputil /enum-drivers | Select-String -Pattern "Published Name|Original Name"
for ($i=0; $i -lt $oems.Count; $i+=2) {
  $pub=($oems[$i].ToString() -replace '.*:\s*','').Trim()
  $org=($oems[$i+1].ToString()-replace '.*:\s*','').Trim()
  if ($org -ieq "passThrough.inf"){ pnputil /delete-driver $pub /uninstall /force | Out-Null }
}
if(Test-Path "C:\AntiRansom\tools\sysmon\Sysmon64.exe"){ "C:\AntiRansom\tools\sysmon\Sysmon64.exe" -u force | Out-Null }
Remove-Item -Recurse -Force "C:\AntiRansom" 2>$null | Out-Null
Write-Host "Remoção concluída."
'@
Set-Content -Path (Join-Path $STAGE "uninstall.ps1") -Value $uninstall -Encoding UTF8

@'
;!@Install@!UTF-8!
Title="AntiRansom Installer"
BeginPrompt="Instalar AntiRansom em C:\AntiRansom?"
; extrai para C:\AntiRansom
Directory="C:\AntiRansom"
GUIMode="2"
RunProgram="hidcon:powershell.exe -NoProfile -ExecutionPolicy Bypass -Command Start-Process PowerShell -Verb RunAs -ArgumentList '-NoProfile -ExecutionPolicy Bypass -File \"install.ps1\"'"
;!@InstallEnd@!
'@ | Set-Content -Path $CFG -Encoding UTF8

Write-Host "Compactando payload…"
if(Test-Path $PAY7Z){ Remove-Item $PAY7Z -Force }
Push-Location $STAGE
& $Z a -t7z -mx=9 $PAY7Z * | Out-Null
Pop-Location

Write-Host "Gerando EXE…"
if(Test-Path $OUT_EXE){ Remove-Item $OUT_EXE -Force }
cmd /c copy /b "`"$SFX`"+"`"$CFG`"+"`"$PAY7Z`"" "`"$OUT_EXE`"" >$null

Write-Host "`n✅ Instalador criado: $OUT_EXE"
Write-Host "Dica: copie esse EXE para a máquina-alvo e execute como Administrador."
