$ROOT = "C:\AntiRansom"
$DATA = Join-Path $ROOT "data"
$LOG  = Join-Path $DATA "events.log"
$RUN  = Join-Path $DATA "guardian.run"

function Write-Log($m){ $ts=(Get-Date).ToString("s"); Add-Content -Encoding UTF8 -Path $LOG -Value "$ts [INFO] $m" }

# Sinaliza para o daemon encerrar
if(Test-Path $RUN){ Remove-Item $RUN -Force -EA 0; Write-Log "Stop signal enviado ao Guardian." }

# Aguarda até 5s o encerramento gracioso
$ok=$false
for($i=0;$i -lt 10;$i++){
  Start-Sleep -Milliseconds 500
  if(-not (Test-Path $RUN)){ $ok=$true; break }
}

# Fallback (último caso): mata processo do Start-Guardian se ainda estiver vivo
if(-not $ok){
  try{
    Get-CimInstance Win32_Process | Where-Object { $_.CommandLine -like '*02-Start-Guardian.ps1*' } |
      ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }
    Write-Log "Fallback: processo do Guardian finalizado à força."
  } catch {}
}

# Garanta rede liberada
try{ Set-NetFirewallProfile -Profile Domain,Public,Private -DefaultOutboundAction Allow -DefaultInboundAction Allow | Out-Null } catch{}
"Guardian parado."
