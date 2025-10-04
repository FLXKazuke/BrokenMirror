# C:\AntiRansom\scripts\02-Start-Guardian.ps1
$ErrorActionPreference = "SilentlyContinue"

# --- Paths
$ROOT = "C:\AntiRansom"
$DATA = Join-Path $ROOT "data"
$QUAR = Join-Path $DATA "quarantine"
$LOG  = Join-Path $DATA "events.log"
$RUN  = Join-Path $DATA "guardian.run"
New-Item -ItemType Directory -Path $QUAR -EA 0 | Out-Null
if (-not (Test-Path $LOG)) { New-Item -ItemType File -Path $LOG -EA 0 | Out-Null }

# --- Config
$KillSwitchNetwork = $false
$SysmonLog = "Microsoft-Windows-Sysmon/Operational"
$watchDirs = @(
  "$env:USERPROFILE\Documents",
  "$env:USERPROFILE\Desktop",
  "$env:USERPROFILE\Pictures",
  "C:\HoneyNet",
  "C:\Users\Public\Documents\HONEY",
  "C:\ProgramData\AR_SAFE"

)

function Write-Log([string]$msg,[string]$level="INFO"){
  $ts=(Get-Date).ToString("s")
  Add-Content -Encoding UTF8 -Path $LOG -Value "$ts [$level] $msg"
}

function Kill-Network([switch]$Enable){
  try {
    if($Enable){
      Set-NetFirewallProfile -Profile Domain,Public,Private -DefaultOutboundAction Block -DefaultInboundAction Block | Out-Null
      Write-Log "[RESPONSE] Kill-switch de REDE ATIVADO"
    } else {
      Set-NetFirewallProfile -Profile Domain,Public,Private -DefaultOutboundAction Allow -DefaultInboundAction Allow | Out-Null
      Write-Log "[RESPONSE] Rede restaurada"
    }
  } catch { Write-Log "[ERROR] Kill-Network: $($_.Exception.Message)" }
}

function Quarantine-Process([int]$ProcId,[string]$Reason,[string]$FilePath=""){
  try {
    $p = Get-Process -Id $ProcId -ErrorAction Stop
    $img = $null; try { $img = $p.Path } catch {}
    Write-Log "[RESPONSE] QUARANTINE pid=$ProcId image=$img reason='$Reason' file='$FilePath'"
    try { Stop-Process -Id $ProcId -Force -ErrorAction Stop; Write-Log "[RESPONSE] KILL pid=$ProcId OK" }
    catch { Write-Log "[ERROR] Kill pid=$ProcId : $($_.Exception.Message)" }

    $stamp=(Get-Date).ToString("yyyyMMdd_HHmmss")
    $qdir = Join-Path $QUAR ("Q_"+$stamp+"_PID"+$ProcId)
    New-Item -ItemType Directory -Path $qdir -EA 0 | Out-Null
    if($img -and (Test-Path $img)){ Copy-Item $img -Destination $qdir -Force -EA 0 }
    [pscustomobject]@{Time=(Get-Date).ToString("s");Pid=$ProcId;Image=$img;Reason=$Reason;FileTouched=$FilePath} |
      ConvertTo-Json -Depth 4 | Out-File (Join-Path $qdir "meta.json") -Encoding UTF8

    if($KillSwitchNetwork){ Kill-Network -Enable }
  } catch { Write-Log "[ERROR] Quarantine-Process: $($_.Exception.Message)" }
}

# ---------- Auditoria de "File System" (com fallback de idioma) ----------
function Enable-FileAudit {
  try {
    $ok = $false
    $names = @('File System','Sistema de arquivos','Sistema de Arquivos')
    foreach($n in $names){
      $r = & auditpol /set /subcategory:"$n" /failure:enable /success:enable 2>$null
      if ($LASTEXITCODE -eq 0) { $ok = $true; break }
    }
    if ($ok) { Write-Log "Auditoria de File System habilitada (Security 4656/4663)." }
    else     { Write-Log "[ERROR] auditpol não conseguiu habilitar a auditoria de File System." }
  } catch { Write-Log "[ERROR] auditpol: $($_.Exception.Message)" }
}

function Set-FolderSacl([string]$path){
  try {
    if (-not (Test-Path $path)) { New-Item -ItemType Directory -Path $path -EA 0 | Out-Null }

    # Resolve 'Everyone' via SID para funcionar em qualquer idioma
    $sidWorld  = New-Object System.Security.Principal.SecurityIdentifier `
                   ([System.Security.Principal.WellKnownSidType]::WorldSid, $null)
    $acctWorld = $sidWorld.Translate([System.Security.Principal.NTAccount])

    $acl = Get-Acl $path
    $rule = New-Object System.Security.AccessControl.FileSystemAuditRule(
      $acctWorld.Value,
      "Write,CreateFiles,AppendData,Delete,DeleteSubdirectoriesAndFiles,WriteData,WriteAttributes,WriteExtendedAttributes",
      "ContainerInherit,ObjectInherit",
      "None",
      "Failure"
    )
    $acl.SetAuditRule($rule)
    Set-Acl $path $acl
    Write-Log "SACL (falhas) aplicada em: $path"
  } catch {
    Write-Log "[ERROR] Set-FolderSacl '$path': $($_.Exception.Message)"
  }
}

# ---------- START (daemon) ----------
$subs = @{}
New-Item -ItemType File -Path $RUN -Force | Out-Null

try {
  # habilita auditoria e aplica SACL nas pastas alvo
  Enable-FileAudit
  foreach($d in $watchDirs){ Set-FolderSacl $d }

  # 1) SECURITY 4656 (handle request) — mostra [DENY] quando ACCESS_DENIED
  $pred = $watchDirs | ForEach-Object { "contains(EventData/Data[@Name='ObjectName'], '$_')" }
  $x4656 = "*[System[(EventID=4656)]] and (*[$($pred -join ' or ')])"
  $subs.Sec4656 = Register-WinEvent -LogName "Security" -FilterXPath $x4656 -SourceIdentifier "AR_SEC_4656" -Action {
    try {
      $evt = $Event.SourceEventArgs.NewEvent
      $xml = [xml]$evt.ToXml()
      $obj    = ($xml.Event.EventData.Data | Where-Object { $_.Name -eq 'ObjectName' }).'#text'
      $status = ($xml.Event.EventData.Data | Where-Object { $_.Name -eq 'Status' }).'#text'
      $pidHex = ($xml.Event.EventData.Data | Where-Object { $_.Name -eq 'ProcessId' }).'#text'
      if ($pidHex -and $pidHex.StartsWith("0x")) { $ProcId = [Convert]::ToInt32($pidHex,16) } else { $ProcId = [int]$pidHex }

      if ($status -eq "0xC0000022") {
        Write-Log "[DENY] Acesso negado ao arquivo '$obj' (PID=$ProcId, Security 4656)"
        if ($ProcId -gt 0) { Quarantine-Process -ProcId $ProcId -Reason "Security 4656 - ACCESS_DENIED" -FilePath $obj }
      } else {
        Write-Log "[SEC4656] Handle solicitado (status=$status) PID=$ProcId Obj=$obj"
      }
    } catch { Write-Log "[ERROR] Handler 4656: $($_.Exception.Message)" }
  }
  Write-Log "[DET] Subscrito Security 4656 nas pastas-alvo."

  # 2) SYSMON 11 (FileCreate) — quando a criação passa
  $hpFilters = $watchDirs | ForEach-Object { "contains(EventData/Data[@Name='TargetFilename'], '$_')" }
  $xpath11 = "*[System[(EventID=11)]] and (*[$($hpFilters -join ' or ')])"
  $subs.Sysmon11 = Register-WinEvent -LogName $SysmonLog -FilterXPath $xpath11 -SourceIdentifier "AR_SYSMON_11" -Action {
    try {
      $evt  = $Event.SourceEventArgs.NewEvent
      $xml  = [xml]$evt.ToXml()
      $file   = ($xml.Event.EventData.Data | Where-Object { $_.Name -eq 'TargetFilename' }).'#text'
      $ProcId = [int](($xml.Event.EventData.Data | Where-Object { $_.Name -eq 'ProcessId' }).'#text')
      $img    = ($xml.Event.EventData.Data | Where-Object { $_.Name -eq 'Image' }).'#text'
      Write-Log "[SYSMON] FileCreate PID=$ProcId Image=$img File=$file"
      Quarantine-Process -ProcId $ProcId -Reason "Sysmon(FileCreate) em área protegida" -FilePath $file
    } catch { Write-Log "[ERROR] Handler Sysmon: $($_.Exception.Message)" }
  }
  Write-Log "[DET] Subscrito Sysmon (ID11)."

  # 3) FileSystemWatcher (telemetria)
  $subs.FSW = @()
  foreach($d in $watchDirs){
    if(-not (Test-Path $d)){ New-Item -ItemType Directory -Path $d -EA 0 | Out-Null }
    $w = New-Object System.IO.FileSystemWatcher
    $w.Path = $d; $w.IncludeSubdirectories=$true; $w.EnableRaisingEvents=$true
    $act = { $p=$Event.SourceEventArgs.FullPath; Write-Log "[DET] FSW $($Event.EventName): $p" }
    $subs.FSW += (Register-ObjectEvent $w Created -SourceIdentifier ("AR_FSW_C_"+([guid]::NewGuid())) -Action $act)
    $subs.FSW += (Register-ObjectEvent $w Changed -SourceIdentifier ("AR_FSW_U_"+([guid]::NewGuid())) -Action $act)
    $subs.FSW += (Register-ObjectEvent $w Renamed -SourceIdentifier ("AR_FSW_R_"+([guid]::NewGuid())) -Action $act)
  }
  Write-Log "[DET] FSW ligado."

  Write-Log "Guardian STARTED (Sysmon + Security 4656 + FSW)."
  while(Test-Path $RUN){ Wait-Event -Timeout 2 | Out-Null }

} finally {
  try {
    if($subs.Sysmon11){ Unregister-Event -SourceIdentifier "AR_SYSMON_11" -ErrorAction SilentlyContinue }
    if($subs.Sec4656){  Unregister-Event -SourceIdentifier "AR_SEC_4656"  -ErrorAction SilentlyContinue }
    if($subs.FSW){
      foreach($h in $subs.FSW){ try{ Unregister-Event -SubscriptionId $h.Id -ErrorAction SilentlyContinue } catch{} }
    }
    Get-Event | Remove-Event -ErrorAction SilentlyContinue | Out-Null
  } catch { Write-Log "[ERROR] Cleanup: $($_.Exception.Message)" }

  try { Set-NetFirewallProfile -Profile Domain,Public,Private -DefaultOutboundAction Allow -DefaultInboundAction Allow | Out-Null } catch {}
  Write-Log "Guardian STOPPED."
}
