# C:\AntiRansom\scripts\01-Deploy-Honeypots.ps1
$ErrorActionPreference = "SilentlyContinue"

# ----------------- CONFIG -----------------
$ROOT   = "C:\AntiRansom"
$DATA   = Join-Path $ROOT "data"
$LOG    = Join-Path $DATA "events.log"

$FilterName           = "passThrough"
$AutoToggleMinifilter = $true     # descarrega o filtro durante o deploy e recarrega ao final

# Quantidade e profundidade
$FilesPerFolder = 16             
$Depth          = 2             

# Incluir todos os perfis de C:\Users\* (além do usuário atual)
$IncludeAllUsers = $true
# Incluir OneDrive (se existir)
$IncludeOneDrive = $true
# Outras unidades fixas (D:, E:, …)
$IncludeOtherFixedDisks = $true
# ------------------------------------------

# -------- infra/log --------
New-Item -ItemType Directory -Path $DATA -EA 0 | Out-Null
if (-not (Test-Path $LOG)) { New-Item -ItemType File -Path $LOG -EA 0 | Out-Null }
function Write-Log($msg, $level="INFO"){
  $ts = (Get-Date).ToString("s")
  Add-Content -Encoding UTF8 -Path $LOG -Value "$ts [$level] $msg"
}

function Is-FilterLoaded([string]$name){
  $o = & fltmc filters 2>$null
  return ($o -match ("(?i)^\s*"+[regex]::Escape($name)+"\s"))
}
function Unload-Filter([string]$name){
  try { & fltmc unload $name | Out-Null } catch {}
}
function Load-Filter([string]$name){
  try { & fltmc load $name   | Out-Null } catch {}
}

# -------- coleções de nomes/extensões --------
$Names = @(
  "Relatorio_Financeiro_2024","Contratos_Assinados","Proposta_Comercial",
  "Fotos_Familia_Ferias","Cartao_Corporativo","Extrato_Banco",
  "Planilha_Vendas","Orcamento_Projeto","Clientes_Prioritarios",
  "Senha_WiFi","Chaves_API","SSH_Config","Credenciais_VPN",
  "Notas_Reuniao","Apresentacao_Final","Roadmap_Produto",
  "Licencas_Software","Backup_DB","Dump_SQL","Curriculo",
  "Faturas_Emitidas","Comprovantes","Documentos_Pessoais",
  "Relatorio_Auditoria","Dados_Sensiveis","Impostos_2024"
)

$ExtsDocs   = @("docx","xlsx","pptx","pdf","txt","rtf","csv","json","xml")
$ExtsMedia  = @("jpg","jpeg","png","mp4","mp3","wav","raw")
$ExtsDevSec = @("ps1","py","sql","pem","ppk","rdp","ini","cfg","env")
$ExtsMisc   = @("zip","7z","rar","bak","pst","mdb","accdb")
$AllExts    = $ExtsDocs + $ExtsMedia + $ExtsDevSec + $ExtsMisc

$Subdirs = @(
  "Projetos","Financeiro","Contratos","Fotos","Videos","Musicas","Backups",
  "Clientes","Docs","Notas","Impostos","Propostas","Relatorios","Admin","TI"
)

# -------- helpers de criação --------
function New-RandomBytes([int]$kb=8){
  $len = [Math]::Max(1,$kb) * 1024
  $bytes = New-Object byte[] $len
  [System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($bytes)
  return ,$bytes
}
function New-RandomFile([string]$path,[int]$minKB=4,[int]$maxKB=64){
  $kb = Get-Random -Minimum $minKB -Maximum $maxKB
  try {
    [IO.File]::WriteAllBytes($path, (New-RandomBytes $kb))
  } catch {
    # fallback texto
    ("{0} - {1}" -f (Get-Date), (Get-Random)) | Out-File -FilePath $path -Encoding UTF8 -Force
  }
  # envelhece metadados (realismo)
  $days = Get-Random -Minimum 30 -Maximum 720
  try {
    (Get-Item $path).CreationTime  = (Get-Date).AddDays(-$days)
    (Get-Item $path).LastWriteTime = (Get-Date).AddDays(-$days + (Get-Random -Minimum -5 -Maximum 5))
  } catch {}
}

function Ensure-Folder([string]$path){
  try { New-Item -ItemType Directory -Path $path -EA 0 | Out-Null } catch {}
  return (Test-Path $path)
}

function Deploy-In-Folder([string]$base){
  if (-not (Ensure-Folder $base)) { return 0 }
  $created = 0

  # subpastas
  $targets = @($base)
  if ($Depth -ge 1){
    foreach($sd in ($Subdirs | Get-Random -Count ([Math]::Min(6,$Subdirs.Count)))){
      $p = Join-Path $base $sd; if (Ensure-Folder $p) { $targets += $p }
      if ($Depth -ge 2){
        foreach($sd2 in ($Subdirs | Get-Random -Count 3)){
          $p2 = Join-Path $p $sd2; if (Ensure-Folder $p2) { $targets += $p2 }
        }
      }
    }
  }

  foreach($t in $targets){
    # set de arquivos variados
    for($i=0; $i -lt $FilesPerFolder; $i++){
      $name = ($Names | Get-Random)
      $ext  = ($AllExts | Get-Random)
      $file = Join-Path $t ("{0}.{1}" -f $name,$ext)
      if (-not (Test-Path $file)) {
        New-RandomFile -path $file -minKB 4 -maxKB 128
        $created++
      }
    }
  }
  return $created
}

# -------- montagem de destinos --------
$Targets = @()

# usuário atual
$Targets += @(
  "$env:USERPROFILE\Documents",
  "$env:USERPROFILE\Desktop",
  "$env:USERPROFILE\Downloads",
  "$env:USERPROFILE\Pictures",
  "$env:USERPROFILE\Videos",
  "$env:USERPROFILE\Music"
)

# OneDrive (usuário atual)
if ($IncludeOneDrive -and $env:OneDrive){
  $Targets += @(
    Join-Path $env:OneDrive "Documents",
    Join-Path $env:OneDrive "Desktop",
    Join-Path $env:OneDrive "Pictures"
  )
}

# Public / nossas pastas canário
$Targets += @("C:\HoneyNet","C:\Users\Public\Documents\HONEY")

# todos os perfis de C:\Users 
if ($IncludeAllUsers) {
  Get-ChildItem "C:\Users" -Directory -ErrorAction SilentlyContinue | Where-Object {
    $_.Name -notin @("Public","Default","Default User","DefaultAppPool","All Users")
  } | ForEach-Object {
    $Targets += @(
      Join-Path $_.FullName "Documents",
      Join-Path $_.FullName "Desktop",
      Join-Path $_.FullName "Downloads",
      Join-Path $_.FullName "Pictures"
    )
    if ($IncludeOneDrive) {
      $od = Join-Path $_.FullName "OneDrive"
      $Targets += @(
        Join-Path $od "Documents",
        Join-Path $od "Desktop",
        Join-Path $od "Pictures"
      )
    }
  }
}

# Outras unidades fixas (D:, E:, …)
if ($IncludeOtherFixedDisks){
  $fixed = Get-Volume -ErrorAction SilentlyContinue | Where-Object { $_.DriveType -eq 'Fixed' -and $_.DriveLetter -and $_.DriveLetter -ne 'C' }
  foreach($v in $fixed){
    $root = ($v.DriveLetter + ":\")
    $Targets += @(
      (Join-Path $root "HoneyNet"),
      (Join-Path $root "Users\Public\Documents\HONEY"),
      (Join-Path $root "Dados"),
      (Join-Path $root "Projetos")
    )
  }
}

# remove duplicados e nulos
$Targets = $Targets | Where-Object { $_ } | Select-Object -Unique

# -------- execução --------
Write-Log "Deploy de honeypots INICIADO. Pastas alvo: $($Targets -join '; ')"

$filterWasLoaded = $false
if ($AutoToggleMinifilter -and (Is-FilterLoaded $FilterName)) {
  $filterWasLoaded = $true
  Write-Log "Minifilter '$FilterName' está carregado. Descarregando temporariamente para criar honeypots…"
  Unload-Filter $FilterName
  Start-Sleep -Seconds 1
}

$total = 0
foreach($t in $Targets){
  $count = Deploy-In-Folder $t
  if ($count -gt 0) {
    Write-Log "Honeypots criados em '$t' : $count arquivos"
    $total += $count
  } else {
    Write-Log "Pasta inacessível/não criada: '$t'" "WARN"
  }
}

if ($filterWasLoaded) {
  Write-Log "Recarregando minifilter '$FilterName'…"
  Load-Filter $FilterName
}

Write-Log "Deploy de honeypots CONCLUÍDO. Total de arquivos: $total"
"OK: Honeypots implantados. Total: $total (veja $LOG)"
