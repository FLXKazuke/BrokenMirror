# C:\AntiRansom\scripts\00-Prep.ps1
$ErrorActionPreference = "Stop"

# --- Paths
$ROOT = "C:\AntiRansom"
$DATA = Join-Path $ROOT "data"
$QUAR = Join-Path $DATA "quarantine"
$TOOLS = Join-Path $ROOT "tools"
$SYSMON = Join-Path $TOOLS "sysmon\Sysmon64.exe"
$SYSCONF = Join-Path $TOOLS "sysmon\sysmon.xml"
$LOG = Join-Path $DATA "events.log"

# --- Dirs
@($ROOT,$DATA,$QUAR,(Split-Path $SYSCONF -Parent)) | ForEach-Object { New-Item -ItemType Directory -Path $_ -EA 0 | Out-Null }
if (-not (Test-Path $LOG)) { New-Item -ItemType File -Path $LOG -EA 0 | Out-Null }

function Write-Log($msg, $level="INFO"){
  $ts = (Get-Date).ToString("s")
  Add-Content -Encoding UTF8 -Path $LOG -Value "$ts [$level] $msg"
}

# --- Sysmon config
if (-not (Test-Path $SYSCONF)) {
@"
<Sysmon schemaversion="4.82">
  <HashAlgorithms>sha256</HashAlgorithms>
  <EventFiltering>
    <ProcessCreate onmatch="include">
      <Rule groupRelation="or">
        <Image condition="is not">C:\Windows\System32\svchost.exe</Image>
      </Rule>
    </ProcessCreate>
    <FileCreate onmatch="include">
      <Rule groupRelation="or">
        <TargetFilename condition="contains">C:\Users\</TargetFilename>
        <TargetFilename condition="contains">C:\HoneyNet\</TargetFilename>
        <TargetFilename condition="contains">\Documents\</TargetFilename>
        <TargetFilename condition="contains">\Desktop\</TargetFilename>
        <TargetFilename condition="contains">\Pictures\</TargetFilename>
      </Rule>
    </FileCreate>
  </EventFiltering>
</Sysmon>
"@ | Out-File -FilePath $SYSCONF -Encoding UTF8
  Write-Log "Criado sysmon.xml padrão em $SYSCONF"
}

# --- Instalar Sysmon se binário existir e serviço não instalado
$svc = Get-Service -Name sysmon64 -ErrorAction SilentlyContinue
if (-not $svc -and (Test-Path $SYSMON)) {
  & $SYSMON -i $SYSCONF -accepteula | Out-Null
  Start-Sleep -Seconds 2
  $svc = Get-Service -Name sysmon64 -ErrorAction SilentlyContinue
  if ($svc) { Write-Log "Sysmon instalado e em execução." } else { Write-Log "Falha ao instalar Sysmon." "ERROR" }
} elseif ($svc) {
  Write-Log "Sysmon já instalado."
} else {
  Write-Log "Sysmon não encontrado em $SYSMON. (Opcional mas recomendado)"
}

Write-Log "Prep concluído."
"Preparação concluída. Log: $LOG"
