# ==============================================================================
# Skulls & Bones Sovereign Suite - 2-Node Mesh & E2E Pairing Drill
# ==============================================================================
$ErrorActionPreference = "Stop"

$Root = (Get-Location).Path
$SbBin = Join-Path $Root "target\debug\sb.exe"
$SbCodeBin = Join-Path $Root "target\debug\sb-code.exe"

$NodeADir = "c:\Users\leonf\.sb-node-a"
$NodeBDir = "c:\Users\leonf\.sb-node-b"

Write-Host "=================================================================" -ForegroundColor Cyan
Write-Host "[DRILL SETUP] Initialisiere isolierte Knotenverzeichnisse..." -ForegroundColor Cyan
Write-Host "  Node A: $NodeADir"
Write-Host "  Node B: $NodeBDir"
Write-Host "=================================================================" -ForegroundColor Cyan

if (Test-Path $NodeADir) { Remove-Item -Recurse -Force $NodeADir }
if (Test-Path $NodeBDir) { Remove-Item -Recurse -Force $NodeBDir }

New-Item -ItemType Directory -Force $NodeADir | Out-Null
New-Item -ItemType Directory -Force $NodeBDir | Out-Null

# ------------------------------------------------------------------------------
# 1. Node A: Admin Swarm mit 4-Augen-Quorum (2 Admins: Alice & Bob)
# ------------------------------------------------------------------------------
Write-Host "`n[SCHRITT 1] Konfiguriere Node A (Admin-Swarm mit 2 Admins: Alice & Bob)..." -ForegroundColor Yellow
'[{"name": "admin-alice", "role": "admin", "added_at": "2026-10-09T00:00:00Z"}, {"name": "co-admin-bob", "role": "admin", "added_at": "2026-10-09T00:00:00Z"}]' | Set-Content (Join-Path $NodeADir "team_members.json") -Encoding UTF8

$env:SB_HOME = $NodeADir
$env:SB_MESH_HOME = Join-Path $NodeADir ".mesh"
$env:SB_SSH_HOME = Join-Path $NodeADir ".ssh"
$env:SB_CALLSIGN = "admin-alice"

Write-Host "[SCHRITT 2] Alice laedt Dev-Client 'dev-charlie' ein (erfordert 4-Augen-Freigabe)..." -ForegroundColor Yellow
$InviteOutput = & $SbBin invite client dev-charlie
$InviteOutput | ForEach-Object { Write-Host "  [Node A] $_" }

# Extrahiere Antrags-ID
$ReqMatch = ($InviteOutput | Select-String "req-[0-9a-fA-F]+")
if (-not $ReqMatch) {
    throw "Antrags-ID konnte nicht in Einladungs-Ausgabe gefunden werden!"
}
$ReqId = $ReqMatch.Matches[0].Value
Write-Host "`n  -> Gefundene Antrags-ID: $ReqId (Status: PENDING - Quorum 1/2)" -ForegroundColor Green

# Zeige offene Antraege
Write-Host "`n[SCHRITT 3] Offene Antraege via 'sb invite list' pruefen..." -ForegroundColor Yellow
& $SbBin invite list | ForEach-Object { Write-Host "  [Node A] $_" }

# Co-Admin Bob genehmigt die Anfrage (4-Augen-Prinzip erfuellt)
Write-Host "`n[SCHRITT 4] Co-Admin Bob genehmigt Antrag $ReqId..." -ForegroundColor Yellow
$ApproveOutput = & $SbBin approve $ReqId --approver co-admin-bob
$ApproveOutput | ForEach-Object { Write-Host "  [Node A] $_" }

# Extrahiere Token
$TokenMatch = ($ApproveOutput | Select-String "sbm-pair://[a-zA-Z0-9+/=]+")
if (-not $TokenMatch) {
    throw "Pairing-Token konnte nach Genehmigung nicht extrahiert werden!"
}
$PairToken = $TokenMatch.Matches[0].Value
Write-Host "`n  -> Freigeschaltetes Pairing-Token: $PairToken" -ForegroundColor Green

# ------------------------------------------------------------------------------
# 2. Node B: Beitritt als Dev-Client 'dev-charlie'
# ------------------------------------------------------------------------------
Write-Host "`n[SCHRITT 5] Node B (Entwickler 'dev-charlie') tritt dem Mesh via 'sb join' bei..." -ForegroundColor Yellow
$env:SB_HOME = $NodeBDir
$env:SB_MESH_HOME = Join-Path $NodeBDir ".mesh"
$env:SB_SSH_HOME = Join-Path $NodeBDir ".ssh"
$env:SB_CALLSIGN = "dev-charlie"

$JoinOutput = & $SbBin join $PairToken --name dev-charlie
$JoinOutput | ForEach-Object { Write-Host "  [Node B] $_" }

# Verifiziere CA-Verankerung in Node B
$NodeBCaTrust = Join-Path (Join-Path $NodeBDir ".ssh") "swarm_ca.pub"
if (Test-Path $NodeBCaTrust) {
    $CaContent = Get-Content $NodeBCaTrust -Raw
    Write-Host "`n  -> Node B Swarm CA erfolgreich verankert: $CaContent" -ForegroundColor Green
} else {
    throw "Swarm-CA wurde in Node B nicht gefunden!"
}

# ------------------------------------------------------------------------------
# 3. Workspace-Replikation & Code Sync (sb-code)
# ------------------------------------------------------------------------------
Write-Host "`n[SCHRITT 6] Code-Synchronisation via Merkle-VCS (sb-code)..." -ForegroundColor Yellow
$DevWorkspace = Join-Path $NodeBDir "workspace\sovereign-drill-app"
$AdminWorkspace = Join-Path $NodeADir "workspace\sovereign-drill-app"
New-Item -ItemType Directory -Force $DevWorkspace | Out-Null
New-Item -ItemType Directory -Force $AdminWorkspace | Out-Null

# In Dev Workspace: Repo initialisieren, Datei anlegen & signiert committen
Push-Location $DevWorkspace
try {
    Write-Host "  -> Initialisiere Dev-Workspace auf Node B..."
    & $SbCodeBin init | Out-Null
    
    'fn main() { println!("Sovereign 2-Node Mesh Drill successfully verified!"); }' | Set-Content (Join-Path $DevWorkspace "main.rs") -Encoding UTF8
    
    Write-Host "  -> Erstelle signierten Commit auf Node B (dev-charlie)..."
    & $SbCodeBin commit -m "feat: initial commit from dev-charlie via sovereign mesh"
    
    $BundlePath = Join-Path $NodeBDir "workspace\app-replication.sbbundle"
    Write-Host "  -> Exportiere Workspace-Bundle nach $BundlePath..."
    & $SbCodeBin bundle export -o $BundlePath
} finally {
    Pop-Location
}

# In Admin Workspace: Repo initialisieren & Bundle importieren
Push-Location $AdminWorkspace
try {
    Write-Host "  -> Initialisiere Admin-Workspace auf Node A..."
    & $SbCodeBin init | Out-Null
    
    Write-Host "  -> Importiere Replikations-Bundle auf Node A..."
    & $SbCodeBin bundle import $BundlePath --checkout
    
    Write-Host "  -> Pruefe importierten Commit-Log auf Node A..."
    & $SbCodeBin log
} finally {
    Pop-Location
}

# Verifiziere Dateiinhalt in Node A
$AdminMainRs = Join-Path $AdminWorkspace "main.rs"
if (Test-Path $AdminMainRs) {
    Write-Host "`n[OK] MAIN.RS AUF NODE A ERFOLGREICH REPLIZIERT:" -ForegroundColor Green
    Get-Content $AdminMainRs | ForEach-Object { Write-Host "    $_" -ForegroundColor Cyan }
} else {
    throw "Replikation fehlgeschlagen: main.rs existiert nicht auf Node A!"
}

Write-Host "`n=================================================================" -ForegroundColor Green
Write-Host "[ERFOLG] 2-Node Mesh-Drill & E2E-Pairing vollstaendig bestanden!" -ForegroundColor Green
Write-Host "=================================================================" -ForegroundColor Green
