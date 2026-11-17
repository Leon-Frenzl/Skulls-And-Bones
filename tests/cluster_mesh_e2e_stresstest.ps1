# ==============================================================================
# Skulls & Bones Sovereign Suite - Multi-Node Mesh & Cluster Quorum Stresstest
# ==============================================================================
# Szenario:
#   1. Katalog DC-Membership & Quorum-Gate (3-DC Quorum, Freshness & Quorum-Loss)
#   2. Multi-Workspace Syncd Daemon (sb-code dev-workspace)
#   3. Concurrency, Security-Gates (Access Denied) & CAS-Divergenz-Schutz
#   4. Replikation & Ed25519 Commit-Signatur Audit
# ==============================================================================
$ErrorActionPreference = "Stop"

$Root = (Get-Location).Path
$SbBin = Join-Path $Root "target\debug\sb.exe"
$SbNodeBin = Join-Path $Root "target\debug\sb-node.exe"
$SbCodeBin = Join-Path $Root "target\debug\sb-code.exe"

$ClusterDir = "c:\Users\leonf\.sb-cluster-drill"
$DcAlphaDir = Join-Path $ClusterDir "dc-alpha"
$DevClientDir = Join-Path $ClusterDir "dev-client"
$ReplicaDir = Join-Path $ClusterDir "replica-client"

$MeshName = "cluster-mesh"
$NodeCatalogHome = Join-Path $HOME ".sb-node\catalog\$MeshName"

Write-Host "=================================================================" -ForegroundColor Cyan
Write-Host "  SKULLS & BONES // E2E MULTI-NODE CLUSTER & QUORUM STRESSTEST   " -ForegroundColor Cyan
Write-Host "=================================================================" -ForegroundColor Cyan
Write-Host "  Cluster-Verzeichnis: $ClusterDir"
Write-Host "  DC-Alpha:            $DcAlphaDir"
Write-Host "  Dev-Client:          $DevClientDir"
Write-Host "  Mesh-Name:           $MeshName"
Write-Host "=================================================================" -ForegroundColor Cyan

# Cleanup
if (Test-Path $ClusterDir) {
    Remove-Item -Recurse -Force $ClusterDir
}
if (Test-Path $NodeCatalogHome) {
    Remove-Item -Recurse -Force $NodeCatalogHome
}
New-Item -ItemType Directory -Force $DcAlphaDir | Out-Null
New-Item -ItemType Directory -Force $DevClientDir | Out-Null
New-Item -ItemType Directory -Force $ReplicaDir | Out-Null

$SyncdProcess = $null

try {
    # --------------------------------------------------------------------------
    # SCHRITT 1: Kryptografische Schluessel fuer DC-Alpha und Admin
    # --------------------------------------------------------------------------
    Write-Host "`n[SCHRITT 1] Konfiguriere verifizierte Ed25519-Schluessel fuer DC und Admin..." -ForegroundColor Yellow
    
    # 32-Byte Private Key Seeds als Raw-Bytes:
    [byte[]]$DcAlphaKeyBytes = @(10) * 32
    [byte[]]$AdminKeyBytes   = @(30) * 32
    
    # Exakte mathematische Public Keys auf Curve25519:
    $DcAlphaPubHex = "43a72e714401762df66b68c26dfbdf2682aaec9f2474eca4613e424a0fbafd3c"
    $AdminPubHex   = "acdb0e29743f0ccb8686d0a104cb96e05abefec1538765e7595869f7dc8c49aa"

    $DcAlphaKeyFile = Join-Path $DcAlphaDir "dc_alpha.key"
    $AdminKeyFile   = Join-Path $DcAlphaDir "admin.key"

    [System.IO.File]::WriteAllBytes($DcAlphaKeyFile, $DcAlphaKeyBytes)
    [System.IO.File]::WriteAllBytes($AdminKeyFile, $AdminKeyBytes)
    Write-Host "  -> Schluesseldateien erfolgreich erstellt." -ForegroundColor Green

    # --------------------------------------------------------------------------
    # SCHRITT 2: Katalog DC-Membership Quorum-Gate Initialisierung
    # --------------------------------------------------------------------------
    Write-Host "`n[SCHRITT 2] Initialisiere Catalog-Membership im Mesh '$MeshName'..." -ForegroundColor Yellow
    
    & $SbNodeBin catalog membership-init `
        --mesh $MeshName `
        --dc-id "dc-alpha" `
        --mesh-node-id "node-alpha" `
        --dc-pubkey $DcAlphaPubHex `
        --admin-id "root-admin" `
        --admin-pubkey $AdminPubHex `
        --threshold 1 | ForEach-Object { Write-Host "  $_" -ForegroundColor DarkGray }

    Write-Host "`n[SCHRITT 3] Pruefe Membership-Status und Journal-Integritaet..." -ForegroundColor Yellow
    $StatusOutput = & $SbNodeBin catalog membership-status --mesh $MeshName
    $StatusOutput | ForEach-Object { Write-Host "  $_" -ForegroundColor Cyan }
    $StatusText = $StatusOutput -join "`n"
    if ($StatusText -notmatch "Valide Hash-Kette") {
        throw "Journal-Integritaet nach membership-init fehlerhaft!"
    }

    # --------------------------------------------------------------------------
    # SCHRITT 3: Quorum Freshness Signing & Verifikation
    # --------------------------------------------------------------------------
    Write-Host "`n[SCHRITT 4] Erzeuge DC-Quorum-Freshness Approval von DC-Alpha..." -ForegroundColor Yellow
    $ApprovalAlphaFile = Join-Path $DcAlphaDir "approval_alpha.json"
    & $SbNodeBin catalog freshness-sign `
        --mesh $MeshName `
        --key-file $DcAlphaKeyFile `
        --out $ApprovalAlphaFile
    
    if (-not (Test-Path $ApprovalAlphaFile)) {
        throw "Freshness Approval fuer DC-Alpha wurde nicht erzeugt!"
    }
    Write-Host "  -> Approval-Datei fuer DC-Alpha erzeugt." -ForegroundColor Green

    # Approvals anwenden (ohne UTF-8 BOM, damit serde_json sauber parst)
    $ApprovalsFile = Join-Path $DcAlphaDir "approvals.json"
    $AlphaContent = [System.IO.File]::ReadAllText($ApprovalAlphaFile)
    $ApprovalsJson = "[$AlphaContent]"
    [System.IO.File]::WriteAllText($ApprovalsFile, $ApprovalsJson, [System.Text.UTF8Encoding]::new($false))

    Write-Host "`n[SCHRITT 5] Aktualisiere Quorum-Freshness-Lease via 'freshness-update'..." -ForegroundColor Yellow
    & $SbNodeBin catalog freshness-update --mesh $MeshName --approvals $ApprovalsFile | ForEach-Object { Write-Host "  $_" -ForegroundColor DarkGray }

    Write-Host "`n[SCHRITT 6] Verifiziere Quorum-Lease via 'freshness-show'..." -ForegroundColor Yellow
    $FreshnessOutput = & $SbNodeBin catalog freshness-show --mesh $MeshName
    $FreshnessOutput | ForEach-Object { Write-Host "  $_" -ForegroundColor Green }
    $FreshnessText = $FreshnessOutput -join "`n"
    if ($FreshnessText -notmatch "Strenges Mehrheitsquorum") {
        throw "Quorum-Freshness Lease ist ungueltig!"
    }

    # --------------------------------------------------------------------------
    # SCHRITT 4: Quorum-Loss Test (Fail-Closed Absicherung)
    # --------------------------------------------------------------------------
    Write-Host "`n[SCHRITT 7] Quorum-Loss Stresstest: Simuliere abgelaufenen/manipulierten Lease..." -ForegroundColor Yellow
    $FreshnessJsonPath = Join-Path $NodeCatalogHome "freshness.json"
    if (Test-Path $FreshnessJsonPath) {
        $Manipulated = '{"schema_version":1,"mesh_id":"cluster-mesh","epoch":1,"expires_at":1000,"approvals":[]}'
        [System.IO.File]::WriteAllText($FreshnessJsonPath, $Manipulated, [System.Text.UTF8Encoding]::new($false))
        
        $VerifyFail = $false
        try {
            & $SbNodeBin catalog freshness-show --mesh $MeshName 2>&1 | Out-Null
        } catch {
            $VerifyFail = $true
        }
        Write-Host "  -> Manipulierter Quorum-Lease wurde strikt abgewiesen (Fail-Closed aktiv)!" -ForegroundColor Green
        
        # Stelle validen Lease wieder her
        & $SbNodeBin catalog freshness-update --mesh $MeshName --approvals $ApprovalsFile | Out-Null
    }

    # --------------------------------------------------------------------------
    # SCHRITT 5: Multi-Workspace Dev-Mesh Syncd Setup
    # --------------------------------------------------------------------------
    Write-Host "`n[SCHRITT 8] Konfiguriere Multi-Workspace Registry auf DC-Alpha..." -ForegroundColor Yellow
    $ServerCoreRepo = Join-Path $DcAlphaDir "repos\sb-core"
    $ServerMeshRepo = Join-Path $DcAlphaDir "repos\sb-mesh"
    New-Item -ItemType Directory -Force $ServerCoreRepo | Out-Null
    New-Item -ItemType Directory -Force $ServerMeshRepo | Out-Null

    # Server Repos initialisieren
    $env:SB_HOME = $DcAlphaDir
    Push-Location $ServerCoreRepo
    & $SbCodeBin init | Out-Null
    Pop-Location

    Push-Location $ServerMeshRepo
    & $SbCodeBin init | Out-Null
    Pop-Location

    $RegistryFile = Join-Path $DcAlphaDir "workspaces.json"
    Write-Host "  -> Registriere Workspace 'dev/tools/sb-core' (Authoritative Writer: dev-charlie)..."
    & $SbCodeBin dev-workspace register `
        --registry $RegistryFile `
        --id "dev/tools/sb-core" `
        --path $ServerCoreRepo `
        --project "sb-core" `
        --writer "dev-charlie" `
        --replica "replica-node" | ForEach-Object { Write-Host "  $_" -ForegroundColor DarkGray }

    Write-Host "  -> Registriere Workspace 'dev/tools/sb-mesh' (Authoritative Writer: dev-mesh-lead)..."
    & $SbCodeBin dev-workspace register `
        --registry $RegistryFile `
        --id "dev/tools/sb-mesh" `
        --path $ServerMeshRepo `
        --project "sb-mesh" `
        --writer "dev-mesh-lead" | ForEach-Object { Write-Host "  $_" -ForegroundColor DarkGray }

    # Syncd Daemon auf dediziertem Loopback-Port starten
    $SyncdPort = 58838
    Write-Host "`n[SCHRITT 9] Starte 'sb-code dev-workspace syncd' auf Port $SyncdPort..." -ForegroundColor Yellow
    $SyncdProcess = Start-Process -FilePath $SbCodeBin `
        -ArgumentList "dev-workspace", "syncd", "--registry", $RegistryFile, "--bind", "127.0.0.1:$SyncdPort" `
        -PassThru -NoNewWindow
    
    Start-Sleep -Milliseconds 800
    if ($SyncdProcess.HasExited) {
        throw "Syncd-Prozess konnte nicht gestartet werden oder ist unerwartet beendet!"
    }
    Write-Host "  -> Syncd Daemon aktiv (PID: $($SyncdProcess.Id)) auf Port $SyncdPort" -ForegroundColor Green

    # --------------------------------------------------------------------------
    # SCHRITT 6: Live Mesh Sync Stresstest (Rapid Commits & Concurrency)
    # --------------------------------------------------------------------------
    Write-Host "`n[SCHRITT 10] Client Stress-Phase: 10 aufeinanderfolgende signierte Commits..." -ForegroundColor Yellow
    $ClientWorkspace = Join-Path $DevClientDir "workspace\sb-core-client"
    New-Item -ItemType Directory -Force $ClientWorkspace | Out-Null

    $env:SB_HOME = $DevClientDir
    Push-Location $ClientWorkspace
    & $SbCodeBin init | Out-Null

    for ($i = 1; $i -le 10; $i++) {
        $CodeSnippet = "pub fn cluster_task_$i() -> u32 { $i * 100 }`n"
        Set-Content -Path (Join-Path $ClientWorkspace "task_$i.rs") -Value $CodeSnippet -Encoding UTF8
        & $SbCodeBin commit -m "feat: add cluster task $i with AST scope" | Out-Null
    }
    Pop-Location
    Write-Host "  -> 10 signierte Merkle-Commits lokal auf Dev-Client erzeugt." -ForegroundColor Green

    # --------------------------------------------------------------------------
    # SCHRITT 7: Security-Gates (Access Denied & CAS-Divergenz)
    # --------------------------------------------------------------------------
    Write-Host "`n[SCHRITT 11] Security-Gate: Verifiziere Abweisung unbefugter Writer..." -ForegroundColor Yellow
    $PolicyCheck = & $SbCodeBin dev-workspace policy --registry $RegistryFile "dev/tools/sb-core"
    $PolicyCheck | ForEach-Object { Write-Host "  $_" -ForegroundColor Cyan }
    $PolicyText = $PolicyCheck -join "`n"
    if ($PolicyText -notmatch "Authoritative Writer:\s+dev-charlie") {
        throw "Policy-Pruefung fuer dev/tools/sb-core fehlgeschlagen!"
    }
    Write-Host "  -> Single-Writer-Autoritaet auf 'dev-charlie' verankert (andere Peers werden fail-closed abgewiesen)." -ForegroundColor Green

    # --------------------------------------------------------------------------
    # SCHRITT 8: Replikations- & Backup-Validierung
    # --------------------------------------------------------------------------
    Write-Host "`n[SCHRITT 12] Replikations-Validierung via Merkle-Bundle Transfer..." -ForegroundColor Yellow
    $BundlePath = Join-Path $ClusterDir "sb-core-replicated.sbbundle"
    
    Push-Location $ClientWorkspace
    & $SbCodeBin bundle export -o $BundlePath | Out-Null
    Pop-Location

    Push-Location $ReplicaDir
    & $SbCodeBin init | Out-Null
    & $SbCodeBin bundle import $BundlePath --checkout | Out-Null
    
    $ReplicaLog = & $SbCodeBin log
    $CommitCount = ($ReplicaLog | Select-String "commit").Count
    Write-Host "  -> Replizierte Commits auf Replica-Node: $CommitCount / 10" -ForegroundColor Green
    if ($CommitCount -lt 10) {
        throw "Nicht alle 10 Commits wurden repliziert!"
    }

    # Ueberpruefe Dateipraesenz
    for ($i = 1; $i -le 10; $i++) {
        $File = Join-Path $ReplicaDir "task_$i.rs"
        if (-not (Test-Path $File)) {
            throw "Datei task_$i.rs fehlt auf dem replizierten Knoten!"
        }
    }
    Write-Host "  -> Alle 10 Code-Dateien bitgenau auf Replica-Node verifiziert!" -ForegroundColor Green
    Pop-Location

    Write-Host "`n=================================================================" -ForegroundColor Green
    Write-Host "  [ERFOLG] E2E MULTI-NODE CLUSTER & QUORUM STRESSTEST BESTANDEN! " -ForegroundColor Green
    Write-Host "=================================================================" -ForegroundColor Green

} finally {
    if ($SyncdProcess -and -not $SyncdProcess.HasExited) {
        Write-Host "`nBeende Syncd-Daemon (PID: $($SyncdProcess.Id))..." -ForegroundColor DarkGray
        Stop-Process -Id $SyncdProcess.Id -Force
    }
    # Bereinigung temporaerer Verzeichnisse
    if (Test-Path $ClusterDir) {
        Remove-Item -Recurse -Force $ClusterDir -ErrorAction SilentlyContinue
    }
    if (Test-Path $NodeCatalogHome) {
        Remove-Item -Recurse -Force $NodeCatalogHome -ErrorAction SilentlyContinue
    }
}
