<#
.SYNOPSIS
Automatise la preparation dun master avant execution de sysprep_cleaner.ps1.

.DESCRIPTION
Enchaine les prerequis critiques (disque, reboot en attente, services Windows Update),
suspend BitLocker, effectue une hygiene rapide puis lance sysprep_cleaner.ps1
avec les parametres souhaites (optionnellement enchainer Sysprep).

.NOTES
A lancer dans une console PowerShell **elevee** (Administrateur).
#>
[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [string]$SysprepCleanerPath = '.\sysprep_cleaner.ps1',
    [string]$SysprepLogPath = 'C:\Windows\System32\Sysprep\Panther\setupact.log',
    [string]$SysprepTranscriptPath = '.\logs\sysprep_cleaner-{0:yyyyMMdd-HHmmss}.log',
    [switch]$RunSysprepAfterCleaner = $true,
    [switch]$SysprepCleanerAutoYes,
    [ValidateSet('shutdown','reboot','quit')]
    [string]$SysprepAction = 'shutdown',
    [ValidateSet('oobe','audit')]
    [string]$SysprepMode = 'oobe',
    [switch]$NoGeneralize,
    [string]$SysprepUnattend,
    [switch]$SkipBitLockerSuspend,
    [switch]$SkipNetworkToggle,
    [switch]$ClearEventLogs,
    [switch]$SkipPendingRebootCheck,
    [ValidateSet('1','2')]
    [string]$Phase = '1',
[string]$TranscriptPath = '.\logs\prepare-master-{0:yyyyMMdd-HHmmss}.log'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$script:BitLockerOverridePreviouslyAllowed = $false

$scriptDir = if ($PSScriptRoot) { $PSScriptRoot } else { Split-Path -Path $MyInvocation.MyCommand.Path -Parent }
if (-not $scriptDir) { $scriptDir = (Get-Location).Path }
$logsRoot = Join-Path $scriptDir 'logs'
if (-not (Test-Path -LiteralPath $logsRoot)) { New-Item -ItemType Directory -Path $logsRoot -Force | Out-Null }

$stateFilePath = Join-Path $scriptDir 'state.json'
$serviceStatePath = Join-Path $scriptDir 'service-states.json'
$phase2TaskName = 'SysprepFix-Phase2'

$script:BitLockerRebootRequired = $false
$script:BitLockerOffRequested = $false

function Resolve-ScriptRelativePath {
    param([string]$Path)
    if ([string]::IsNullOrWhiteSpace($Path)) { return $Path }
    if ([System.IO.Path]::IsPathRooted($Path)) { return $Path }
    return Join-Path -Path $scriptDir -ChildPath $Path
}

function Set-ConsoleTheme {
    param(
        [ConsoleColor]$Foreground = [ConsoleColor]::Gray,
        [ConsoleColor]$Background = [ConsoleColor]::Black
    )
    try {
        if (-not ($Host.UI -and $Host.UI.RawUI)) { return }
        $raw = $Host.UI.RawUI
        $raw.ForegroundColor = $Foreground
        $raw.BackgroundColor = $Background
        Clear-Host
    } catch {
        # Ignore theme errors (non-interactive host)
    }
}

function Show-RestartPromptAnimation {
    param(
        [string]$Message = 'Préparation du redémarrage Phase 2',
        [int]$Cycles = 12,
        [int]$DelayMilliseconds = 90
    )
    try {
        $frames = @('|','/','-','\')
        for ($i = 0; $i -lt $Cycles; $i++) {
            $frame = $frames[$i % $frames.Count]
            Write-Host ("{0} {1}`r" -f $frame, $Message) -ForegroundColor Cyan -NoNewline
            Start-Sleep -Milliseconds $DelayMilliseconds
        }
        $clear = ' ' * ($Message.Length + 4)
        Write-Host ("$clear`r") -NoNewline
    } catch {
        # Non interactive host, ignore animation
    }
}

Set-ConsoleTheme -Foreground ([ConsoleColor]::Gray) -Background ([ConsoleColor]::Black)

function Write-Log {
    param(
        [object]$Message,
        [ConsoleColor]$ForegroundColor = [ConsoleColor]::White
    )
    $text = if ($Message -is [string]) { $Message } else { $Message | Out-String }
    if (-not $text) { $text = '' }
    Write-Host $text -ForegroundColor $ForegroundColor
}

function Assert-Admin {
    if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)) {
        throw 'Ce script doit etre lance dans PowerShell Administrateur.'
    }
}

function Test-DiskSpace {
    param([int]$MinimumGB = 20)
    $drive = Get-PSDrive -Name C -ErrorAction Stop
    $freeGB = [math]::Round($drive.Free / 1GB, 2)
    if ($freeGB -lt $MinimumGB) {
        throw "Espace disque insuffisant sur C: ($freeGB Go libres, minimum requis $MinimumGB Go)."
    }
    Write-Log "Espace disque C: OK ($freeGB Go libres)." -ForegroundColor Green
}

function Test-PendingReboot {
    $pending = $false
    $regPaths = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending',
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired'
    )
    foreach ($path in $regPaths) {
        if (Test-Path $path) {
            $pending = $true
            Write-Log "Reboot en attente detecte via $path." -ForegroundColor Red
        }
    }
    $renameOps = Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' -Name PendingFileRenameOperations -ErrorAction SilentlyContinue
    if ($renameOps -and $renameOps.PendingFileRenameOperations) {
        $pending = $true
        Write-Log 'Reboot en attente (PendingFileRenameOperations).' -ForegroundColor Red
    }
    if ($pending) {
        Write-Log 'Redemarrage en attente detecte. Souhaitez-vous redemarrer maintenant ? (O/N)' -ForegroundColor Yellow
        $answer = Read-Host 'Reboot requis avant de continuer'
        if ($answer -in @('O','o','Y','y')) {
            Write-Log 'Redemarrage immediat...' -ForegroundColor Cyan
            Restart-Computer -Force
            Start-Sleep -Seconds 1
            exit
        } else {
            throw 'Annulez/terminez les redemarrages en attente avant de relancer ce script.'
        }
    }
    Write-Log 'Aucun reboot en attente detecte.' -ForegroundColor Green
}

function Test-DomainMembership {
    $cs = Get-CimInstance -ClassName Win32_ComputerSystem
    if ($cs.DomainRole -notin @(0, 2)) {
        Write-Log "Attention : machine rattachee au domaine ($($cs.Domain))." -ForegroundColor Yellow
    } else {
        Write-Log 'Machine autonome : OK.' -ForegroundColor Green
    }
}

function Disable-UpdateServices {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param()

    $services = @('wuauserv','bits','UsoSvc','dosvc','TrustedInstaller')
    $states = @()
    $serviceInfo = @{}

    $doKey = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization'
    $doAction = 'Configurer Delivery Optimization en mode 99 (bypass)'
    if ($PSCmdlet.ShouldProcess($doKey, $doAction)) {
        try {
            New-Item -Path $doKey -Force | Out-Null
            New-ItemProperty -Path $doKey -Name 'DODownloadMode' -PropertyType DWord -Value 99 -Force | Out-Null
            Write-Log 'Delivery Optimization configuree en mode 99 (bypass).' -ForegroundColor Cyan
        } catch {
            Write-Log "Impossible de definir la strategie Delivery Optimization : $($_.Exception.Message)" -ForegroundColor DarkRed
        }
    } else {
        Write-Log "(WhatIf) Delivery Optimization conserverait sa configuration actuelle." -ForegroundColor DarkCyan
    }

    foreach ($name in $services) {
        $svc = Get-CimInstance Win32_Service -Filter "Name='$name'" -ErrorAction SilentlyContinue
        if (-not $svc) {
            Write-Log "Service $name introuvable (ignore)." -ForegroundColor DarkYellow
            continue
        }
        $serviceInfo[$name] = $svc
        $states += [pscustomobject]@{
            Name      = $svc.Name
            StartMode = $svc.StartMode
            State     = $svc.State
        }
    }

    $stopOrder = @('wuauserv','bits','UsoSvc')
    foreach ($name in $stopOrder) {
        if (-not $serviceInfo.ContainsKey($name)) { continue }
        $targetLabel = "Service $name"
        if ($PSCmdlet.ShouldProcess($targetLabel, 'Arret + desactivation (Startup=Disabled)')) {
            Write-Log "Arret de $name..." -ForegroundColor Cyan
            try {
                Stop-Service -Name $name -Force -ErrorAction Stop
            } catch {
                Write-Log "Echec de l'arret de $name : $($_.Exception.Message)" -ForegroundColor DarkRed
            }
            try {
                Write-Log "Desactivation de $name (Start=Disabled)." -ForegroundColor Cyan
                Set-Service -Name $name -StartupType Disabled -ErrorAction Stop
            } catch {
                Write-Log "Echec de la desactivation de $name : $($_.Exception.Message)" -ForegroundColor DarkRed
            }
        } else {
            Write-Log "(WhatIf) $name resterait dans son etat actuel (aucun Stop/Disable)." -ForegroundColor DarkCyan
        }
    }

    if ($serviceInfo.ContainsKey('dosvc')) {
        $dosvcLabel = 'Service dosvc'
        if ($PSCmdlet.ShouldProcess($dosvcLabel, 'Arret temporaire (mode DO bypass)')) {
            Write-Log 'Arret de dosvc...' -ForegroundColor Cyan
            try {
                Stop-Service -Name 'dosvc' -Force -ErrorAction Stop
            } catch {
                Write-Log "Echec de l'arret de dosvc : $($_.Exception.Message)" -ForegroundColor DarkRed
            }
            Write-Log 'Start de dosvc conserve (bypass via strategie DO).' -ForegroundColor Yellow
        } else {
            Write-Log "(WhatIf) dosvc ne serait pas arrete (bypass via DO seulement)." -ForegroundColor DarkCyan
        }
    }

    return $states
}

function Disable-TrustedInstallerService {
    Write-Log 'Gel du service TrustedInstaller...' -ForegroundColor Cyan
    try {
        Stop-Service -Name 'TrustedInstaller' -Force -ErrorAction Stop
    } catch {
        Write-Log ("Arrêt TrustedInstaller : {0}" -f $_.Exception.Message) -ForegroundColor DarkYellow
    }
    try {
        Set-Service -Name 'TrustedInstaller' -StartupType Disabled -ErrorAction Stop
        Write-Log 'TrustedInstaller configuré sur Disabled.' -ForegroundColor Cyan
    } catch {
        Write-Log ("Impossible de désactiver TrustedInstaller : {0}" -f $_.Exception.Message) -ForegroundColor DarkRed
    }
}

function Invoke-DismComponentCleanup {
    Write-Log 'Nettoyage du magasin de composants (DISM /resetbase)...' -ForegroundColor Cyan
    try {
        Set-Service -Name 'TrustedInstaller' -StartupType Manual -ErrorAction Stop
    } catch {}
    try {
        Start-Service -Name 'TrustedInstaller' -ErrorAction SilentlyContinue
    } catch {
        Write-Log ("Impossible de lancer TrustedInstaller avant DISM : {0}" -f $_.Exception.Message) -ForegroundColor DarkYellow
    }

    $dismCommands = @(
        [pscustomobject]@{
            Description = '/StartComponentCleanup /ResetBase'
            Arguments   = @('/online','/cleanup-image','/startcomponentcleanup','/resetbase')
            ContinueOn  = @(87) # option inconnue -> tenter sans /resetbase
        },
        [pscustomobject]@{
            Description = '/StartComponentCleanup'
            Arguments   = @('/online','/cleanup-image','/startcomponentcleanup')
            ContinueOn  = @(87)
        }
    )

    foreach ($cmd in $dismCommands) {
        Write-Log ("DISM : tentative {0}..." -f $cmd.Description) -ForegroundColor DarkGray
        try {
            $proc = Start-Process -FilePath 'dism.exe' -ArgumentList $cmd.Arguments -NoNewWindow -Wait -PassThru -ErrorAction Stop
        } catch {
            Write-Log ("DISM {0} a généré une exception : {1}" -f $cmd.Description, $_.Exception.Message) -ForegroundColor DarkYellow
            continue
        }

        if ($proc.ExitCode -eq 0) {
            Write-Log ("DISM {0} terminé avec succès." -f $cmd.Description) -ForegroundColor Green
            return
        }

        if ($cmd.ContinueOn -contains $proc.ExitCode) {
            Write-Log ("DISM {0} a retourné le code {1}, tentative suivante..." -f $cmd.Description, $proc.ExitCode) -ForegroundColor Yellow
            continue
        }

        Write-Log ("DISM {0} a échoué (code {1})." -f $cmd.Description, $proc.ExitCode) -ForegroundColor DarkRed
        return
    }

    Write-Log "DISM : aucune des tentatives n'a abouti (options non prises en charge sur ce build)." -ForegroundColor DarkYellow
}

function Get-ServiceStartupTypeValue {
    param([string]$StartMode)
    switch ($StartMode.ToLower()) {
        'auto'                  { 'Automatic' }
        'automatic'             { 'Automatic' }
        'manual'                { 'Manual' }
        'demand'                { 'Manual' }
        'disabled'              { 'Disabled' }
        'delayed-auto'          { 'AutomaticDelayedStart' }
        'automaticdelayedstart' { 'AutomaticDelayedStart' }
        default                 { 'Manual' }
    }
}

function Export-ServiceRestoreScript {
    param(
        [Parameter(Mandatory)]
        [array]$ServiceStates,
        [string]$OutputPath
    )
    if (-not $ServiceStates) { return }
    $lines = @(
        '@echo off',
        'setlocal',
        'set "PS=%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe"',
        'if not exist "%PS%" set "PS=powershell.exe"',
        'echo Restauration des services Windows Update...'
    )
    foreach ($svc in $ServiceStates) {
        $startup = Get-ServiceStartupTypeValue -StartMode $svc.StartMode
        $lines += ('"%PS%" -NoLogo -NoProfile -Command "Try {{ Set-Service -Name ''{0}'' -StartupType {1} -ErrorAction Stop }} Catch {{}}" >nul 2>&1' -f $svc.Name, $startup)
        if ($svc.State -eq 'Running') {
            $lines += ('"%PS%" -NoLogo -NoProfile -Command "Try {{ Start-Service -Name ''{0}'' -ErrorAction SilentlyContinue }} Catch {{}}" >nul 2>&1' -f $svc.Name)
        }
    }
    $lines += 'echo Termine. Redemarrer la machine si necessaire.'
    $lines += 'endlocal'
    $lines += 'pause'
    Set-Content -Path $OutputPath -Value $lines -Encoding ASCII
}

function Save-ServiceStatesToFile {
    param(
        [array]$ServiceStates,
        [string]$Path
    )
    if (-not $ServiceStates) { return }
    $json = $ServiceStates | ConvertTo-Json -Depth 5
    Set-Content -Path $Path -Value $json -Encoding UTF8
}

function Load-ServiceStatesFromFile {
    param([string]$Path)
    if (-not $Path -or -not (Test-Path -LiteralPath $Path)) { return @() }
    try {
        $raw = Get-Content -LiteralPath $Path -Raw -ErrorAction Stop
        if (-not $raw) { return @() }
        $data = $raw | ConvertFrom-Json -ErrorAction Stop
        if ($data -is [System.Collections.IEnumerable] -and -not ($data -is [string])) {
            return @($data)
        }
        return @($data)
    } catch {
        Write-Log ("Impossible de charger l'etat des services depuis {0} : {1}" -f $Path, $_.Exception.Message) -ForegroundColor DarkYellow
        return @()
    }
}

function Restore-UpdateServicesState {
    param(
        [array]$ServiceStates,
        [System.Management.Automation.PSCmdlet]$Cmdlet
    )
    if (-not $ServiceStates) {
        Write-Log 'Aucun etat des services a restaurer.' -ForegroundColor Yellow
        return
    }
    foreach ($svc in $ServiceStates) {
        if (-not $svc.Name) { continue }
        if ($svc.Name -eq 'dosvc') {
            Write-Log "Ignorer la restauration de dosvc (sealed par le systeme)." -ForegroundColor Yellow
            continue
        }
        if ($svc.Name -eq 'CryptSvc') { continue }
        $targetLabel = "Service $($svc.Name)"
        $desiredStartup = Get-ServiceStartupTypeValue -StartMode $svc.StartMode
        $shouldProcess = $true
        if ($Cmdlet) { $shouldProcess = $Cmdlet.ShouldProcess($targetLabel, 'Restauration StartType/Status') }
        if (-not $shouldProcess) { continue }
        try {
            Set-Service -Name $svc.Name -StartupType $desiredStartup -ErrorAction Stop
        } catch {
            Write-Log ("Impossible de restaurer le StartupType de {0} : {1}" -f $svc.Name, $_.Exception.Message) -ForegroundColor DarkRed
        }
        if ($svc.State -eq 'Running') {
            try {
                Start-Service -Name $svc.Name -ErrorAction SilentlyContinue
            } catch {
                Write-Log ("Impossible de redemarrer le service {0} : {1}" -f $svc.Name, $_.Exception.Message) -ForegroundColor DarkYellow
            }
        }
    }
}

# Assure les services critiques nécessaires à Sysprep
function Assert-PreSysprepServicesReady {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param()

    $errors = @()

    function Start-ServiceIfRequired {
        param([string]$Name, [switch]$BlockIfFail)
        try {
            $svc = Get-Service -Name $Name -ErrorAction Stop
        } catch {
            $msg = "Service $Name introuvable: $($_.Exception.Message)"
            if ($BlockIfFail) { $errors += $msg } else { Write-Log $msg -ForegroundColor DarkYellow }
            return
        }
        # StartType via CIM
        $startMode = $null
        try { $startMode = (Get-CimInstance Win32_Service -Filter "Name='$Name'" -ErrorAction Stop).StartMode } catch {}

        # Si Disabled et blocant, tenter Manual
        if ($BlockIfFail -and $startMode -and $startMode.Equals('Disabled',[System.StringComparison]::OrdinalIgnoreCase)) {
            try { Set-Service -Name $Name -StartupType Manual -ErrorAction Stop } catch {
                $errors += "Impossible de mettre $Name en Manual: $($_.Exception.Message)"
            }
        }

        # Démarrer si non Running
        if ($svc.Status -ne [System.ServiceProcess.ServiceControllerStatus]::Running) {
            try { Start-Service -Name $Name -ErrorAction Stop } catch {
                $msg = "Impossible de démarrer $($Name): $($_.Exception.Message)"
                if ($BlockIfFail) { $errors += $msg } else { Write-Log $msg -ForegroundColor DarkYellow }
            }
        }
    }

    # Bloquants pour Sysprep
    Start-ServiceIfRequired -Name 'TrustedInstaller' -BlockIfFail
    Start-ServiceIfRequired -Name 'wuauserv' -BlockIfFail

    # Recommandés (non bloquants)
    Start-ServiceIfRequired -Name 'bits'
    Start-ServiceIfRequired -Name 'UsoSvc'
    # DoSvc: on tente mais non bloquant, le StartType peut être protégé
    Start-ServiceIfRequired -Name 'DoSvc'

    if ($errors.Count -gt 0) {
        $errors | ForEach-Object { Write-Log $_ -ForegroundColor DarkRed }
        throw "Services critiques non prêts pour Sysprep (corrigez puis relancez)."
    }
    Write-Log 'Services critiques prêts pour Sysprep.' -ForegroundColor Green
}

function New-Phase2StateFile {
    param(
        [string]$Path,
        [string]$Phase,
        [string]$Reason,
        [System.Management.Automation.PSCmdlet]$Cmdlet
    )
    if (-not $Path) { return }
    $shouldProcess = $true
    if ($Cmdlet) { $shouldProcess = $Cmdlet.ShouldProcess($Path, "Creation de l'initiateur Phase $Phase") }
    if (-not $shouldProcess) { return }
    $payload = [ordered]@{
        phase   = $Phase
        created = (Get-Date).ToString('o')
        reason  = $Reason
    } | ConvertTo-Json -Depth 3
    Set-Content -Path $Path -Value $payload -Encoding UTF8
    Write-Log ("Init phase file ecrit : {0}" -f $Path) -ForegroundColor Green
}

function Register-Phase2ResumeTask {
    param(
        [string]$TaskName,
        [string]$ScriptPath,
        [string]$UserId,
        [System.Management.Automation.PSCmdlet]$Cmdlet
    )
    if (-not $TaskName -or -not $ScriptPath) { return }
    $psExe = Join-Path $PSHOME 'powershell.exe'
    if (-not (Test-Path -LiteralPath $psExe)) {
        $psExe = 'powershell.exe'
    }
    $shouldProcess = $true
    if ($Cmdlet) { $shouldProcess = $Cmdlet.ShouldProcess($TaskName, 'Enregistrement de la reprise automatique Phase 2') }
    if (-not $shouldProcess) { return }
    if (-not $UserId) {
        $UserId = ([System.Security.Principal.WindowsIdentity]::GetCurrent()).Name
    }
    $escapedPsExe = $psExe.Replace('"','\"')
    $escapedScript = $ScriptPath.Replace('"','\"')
    $cmdBody = "`"$escapedPsExe`" -NoProfile -ExecutionPolicy Bypass -File `"$escapedScript`" -Phase 2"
    $runLine = "`"$($cmdBody.Replace('"','\"'))`""
    $schtasksArgs = @(
        '/Create',
        '/TN', $TaskName,
        '/SC', 'ONLOGON',
        '/RL', 'HIGHEST',
        '/TR', $runLine,
        '/F',
        '/IT'
    )
    if ($UserId) {
        $schtasksArgs += @('/RU', $UserId)
    }
    $proc = Start-Process -FilePath 'schtasks.exe' -ArgumentList $schtasksArgs -Wait -NoNewWindow -PassThru -ErrorAction Stop
    if ($proc.ExitCode -ne 0) {
        throw "schtasks.exe a retourne le code $($proc.ExitCode) lors de la creation de $TaskName."
    }
    Write-Log "Tache planifiee Phase 2 enregistree : $TaskName (AtLogon interactif -> $UserId)." -ForegroundColor Green
}

function Remove-Phase2ResumeTask {
    param(
        [string]$TaskName,
        [System.Management.Automation.PSCmdlet]$Cmdlet
    )
    if (-not $TaskName) { return }
    $existing = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
    if (-not $existing) { return }
    $shouldProcess = $true
    if ($Cmdlet) { $shouldProcess = $Cmdlet.ShouldProcess($TaskName, 'Suppression de la tache planifiee Phase 2') }
    if (-not $shouldProcess) { return }
    Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue
}

function Remove-Phase2StartupEntries {
    param(
        [string]$ScriptPath,
        [string[]]$AdditionalNames = @()
    )

    $resolvedScriptPath = $null
    if ($ScriptPath) {
        try { $resolvedScriptPath = (Resolve-Path -LiteralPath $ScriptPath -ErrorAction Stop).Path } catch { $resolvedScriptPath = $ScriptPath }
    }

    $candidateNames = @()
    if ($resolvedScriptPath) {
        $scriptLeaf = Split-Path -Path $resolvedScriptPath -Leaf
        if ($scriptLeaf) { $candidateNames += $scriptLeaf }
    }
    foreach ($extraName in $AdditionalNames) {
        if ($extraName) { $candidateNames += $extraName }
    }
    if ($candidateNames) { $candidateNames = $candidateNames | Sort-Object -Unique }

    $normalizedScript = $null
    if ($resolvedScriptPath) {
        try { $normalizedScript = [System.IO.Path]::GetFullPath($resolvedScriptPath).ToLowerInvariant() } catch { $normalizedScript = $resolvedScriptPath.ToLowerInvariant() }
    }

    $runKeys = @(
        'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run',
        'HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce',
        'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run',
        'HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce'
    )

    foreach ($key in $runKeys) {
        try { $item = Get-Item -LiteralPath $key -ErrorAction Stop } catch { continue }
        foreach ($valueName in $item.GetValueNames()) {
            $raw = $item.GetValue($valueName)
            if (-not $raw) { continue }
            $text = [string]$raw
            $match = $false
            if ($normalizedScript -and $text.ToLowerInvariant().Contains($normalizedScript)) {
                $match = $true
            } elseif ($candidateNames) {
                foreach ($candidate in $candidateNames) {
                    if ($text.IndexOf($candidate, [System.StringComparison]::OrdinalIgnoreCase) -ge 0) { $match = $true; break }
                }
            }
            if (-not $match) { continue }
            try {
                Remove-ItemProperty -LiteralPath $key -Name $valueName -ErrorAction Stop
                Write-Log ("Entree demarrage supprimee : {0}\{1}" -f $key, $valueName) -ForegroundColor Yellow
            } catch {
                Write-Log ("Impossible de supprimer l'entree de demarrage {0}\{1} : {2}" -f $key, $valueName, $_.Exception.Message) -ForegroundColor DarkYellow
            }
        }
    }

    $startupFolders = @()
    $userStartup = [Environment]::GetFolderPath('Startup')
    if ($userStartup -and (Test-Path -LiteralPath $userStartup)) { $startupFolders += $userStartup }
    $commonStartup = [Environment]::GetFolderPath('CommonStartup')
    if ($commonStartup -and (Test-Path -LiteralPath $commonStartup)) { $startupFolders += $commonStartup }

    if (-not $startupFolders) { return }

    $shell = $null
    foreach ($folder in $startupFolders) {
        try { $entries = Get-ChildItem -LiteralPath $folder -File -ErrorAction Stop } catch { continue }
        foreach ($entry in $entries) {
            $shouldRemove = $false
            if ($candidateNames -and ($candidateNames -contains $entry.Name)) {
                $shouldRemove = $true
            } elseif ($entry.Extension -eq '.lnk' -and $normalizedScript) {
                if (-not $shell) {
                    try { $shell = New-Object -ComObject WScript.Shell } catch {}
                }
                if ($shell) {
                    try {
                        $shortcut = $shell.CreateShortcut($entry.FullName)
                        $target = $shortcut.TargetPath
                        if ($target) {
                            $targetFull = [System.IO.Path]::GetFullPath($target)
                            if ($targetFull) { $targetFull = $targetFull.ToLowerInvariant() }
                            if ($targetFull -and $targetFull -eq $normalizedScript) {
                                $shouldRemove = $true
                            } else {
                                $targetLeaf = Split-Path -Path $target -Leaf
                                if ($targetLeaf -and $candidateNames -contains $targetLeaf) { $shouldRemove = $true }
                            }
                        }
                    } catch {
                        Write-Log ("Impossible d'analyser le raccourci {0} : {1}" -f $entry.FullName, $_.Exception.Message) -ForegroundColor DarkYellow
                    }
                }
            }
            if (-not $shouldRemove) { continue }
            try {
                Remove-Item -LiteralPath $entry.FullName -Force -ErrorAction Stop
                Write-Log ("Element demarrage supprime : {0}" -f $entry.FullName) -ForegroundColor Yellow
            } catch {
                Write-Log ("Impossible de supprimer {0} : {1}" -f $entry.FullName, $_.Exception.Message) -ForegroundColor DarkYellow
            }
        }
    }

    if ($shell) {
        try { [System.Runtime.InteropServices.Marshal]::ReleaseComObject($shell) | Out-Null } catch {}
    }
}
function Get-BitLockerVolumeInfo {
    param(
        [string]$MountPoint = 'C:'
    )

    if (-not (Get-Command Get-BitLockerVolume -ErrorAction SilentlyContinue)) {
        return $null
    }

    try {
        return Get-BitLockerVolume -MountPoint $MountPoint -ErrorAction SilentlyContinue
    } catch {
        return $null
    }
}

function Convert-BitLockerString {
    param([string]$Value)

    if ([string]::IsNullOrWhiteSpace($Value)) { return '' }
    try {
        $trimmed = $Value.Trim()
        $normalized = $trimmed.Normalize([System.Text.NormalizationForm]::FormD)
        $stripped = [System.Text.RegularExpressions.Regex]::Replace($normalized, '\p{Mn}', '')
        return $stripped.ToLowerInvariant()
    } catch {
        return $Value.ToLowerInvariant().Trim()
    }
}

function Test-BitLockerKeyword {
    param(
        [string]$Value,
        [string[]]$Keywords,
        [bool]$Default = $true
    )

    if ([string]::IsNullOrWhiteSpace($Value)) {
        return $Default
    }
    $normalized = Convert-BitLockerString -Value $Value
    $normalizedNoSpace = $normalized.Replace(' ','')
    foreach ($keyword in $Keywords) {
        $normKeyword = $keyword.ToLowerInvariant()
        $normKeywordNoSpace = $normKeyword.Replace(' ','')
        if ($normalized.Contains($normKeyword) -or $normalizedNoSpace.Contains($normKeywordNoSpace)) {
            return $true
        }
    }
    return $false
}

function Get-BitLockerStatusInfo {
    param(
        [string]$MountPoint = 'C:'
    )

    $manageBde = Join-Path $env:WINDIR 'System32\manage-bde.exe'
    if (-not (Test-Path -LiteralPath $manageBde)) {
        return $null
    }

    try {
        $output = & $manageBde -status $MountPoint 2>$null
    } catch {
        return $null
    }

    if (-not $output) {
        return $null
    }

    $info = @{
        Version    = $null
        Protection = $null
        Conversion = $null
        Lock       = $null
        Percentage = $null
    }

    foreach ($line in $output) {
        $trimmed = $line.Trim()
        if (-not $trimmed) { continue }

        if ($trimmed -match '^(?:Version de BitLocker|BitLocker\s+Version)\s*:\s*(?<val>.+)$') {
            $info.Version = $matches['val'].Trim()
            continue
        }
        if ($trimmed -match '^(?:Etat de la protection|Protection Status)\s*:\s*(?<val>.+)$') {
            $info.Protection = $matches['val'].Trim()
            continue
        }
        if ($trimmed -match '^(?:Etat de la conversion|Conversion Status)\s*:\s*(?<val>.+)$') {
            $info.Conversion = $matches['val'].Trim()
            continue
        }
        if ($trimmed -match '^(?:Etat du verrouillage|Lock Status)\s*:\s*(?<val>.+)$') {
            $info.Lock = $matches['val'].Trim()
            continue
        }
        if ($trimmed -match '^(?:Pourcentage chiffr[eé]|Percentage Encrypted)\s*:\s*(?<val>.+)$') {
            $raw = ($matches['val'] -replace '%','').Trim()
            $raw = $raw -replace ',', '.'
            $parsed = 0.0
            if ([double]::TryParse($raw, [System.Globalization.NumberStyles]::Float, [System.Globalization.CultureInfo]::InvariantCulture, [ref]$parsed)) {
                $info.Percentage = $parsed
            }
            continue
        }
    }

    return [pscustomobject]@{
        Version    = $info.Version
        Protection = $info.Protection
        Conversion = $info.Conversion
        Lock       = $info.Lock
        Percentage = $info.Percentage
        Raw        = ($output -join "`n")
    }
}

function Get-BitLockerVersionString {
    param(
        [string]$MountPoint = 'C:'
    )

    $status = Get-BitLockerStatusInfo -MountPoint $MountPoint
    if ($status) { return $status.Version }
    return $null
}

function Invoke-BitLockerDisable {
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
    param(
        [string]$MountPoint = 'C:',
        $CmdletContext
    )

    $manageBde = Join-Path $env:WINDIR 'System32\manage-bde.exe'
    if (-not (Test-Path -LiteralPath $manageBde)) {
        Write-Log "manage-bde.exe introuvable : impossible de lancer automatiquement la commande -off." -ForegroundColor DarkRed
        return $false
    }

    $shouldRun = $true
    if ($CmdletContext -and $CmdletContext -is [System.Management.Automation.PSCmdlet]) {
        $shouldRun = $CmdletContext.ShouldProcess($MountPoint, 'manage-bde -off (dechiffrement complet)')
    }
    if (-not $shouldRun) {
        Write-Log "(WhatIf) manage-bde -off $MountPoint" -ForegroundColor DarkCyan
        return $false
    }

    Write-Log ("Lancement manage-bde -off {0} (dechiffrement du volume)." -f $MountPoint) -ForegroundColor Yellow
    try {
        & $manageBde -off $MountPoint 2>&1 | ForEach-Object {
            if ($_ -is [string]) {
                if ($_) { Write-Log "  $($_)" -ForegroundColor DarkCyan }
            } elseif ($_ -ne $null) {
                Write-Log ("  {0}" -f $_) -ForegroundColor DarkCyan
            }
        }
        Write-Log ("Commande manage-bde -off initiee pour {0}. Surveillez 'manage-bde -status {0}' jusqu'a ce que le pourcentage chiffre atteigne 0 et que la version soit 'Aucun'." -f $MountPoint) -ForegroundColor Yellow
        return $true
    } catch {
        Write-Log ("Echec manage-bde -off {0} : {1}" -f $MountPoint, $_.Exception.Message) -ForegroundColor DarkRed
        return $false
    }
}

function Test-BitLockerReady {
    param(
        [string]$MountPoint = 'C:',
        $Volume
    )

    $status = Get-BitLockerStatusInfo -MountPoint $MountPoint
    $statusVersion = if ($status) { $status.Version } else { $null }
    $statusProtection = if ($status) { $status.Protection } else { $null }
    $statusConversion = if ($status) { $status.Conversion } else { $null }
    $statusPercentage = if ($status) { $status.Percentage } else { $null }

    $versionReady = Test-BitLockerKeyword -Value $statusVersion -Keywords @('aucun','aucune','none','pas trouve','not found','sans','n/a','na','absent','no protectors','no protecteur')
    $percentageReady = $true
    if ($null -ne $statusPercentage) {
        $percentageReady = ([math]::Abs([double]$statusPercentage) -lt 0.01)
    }
    $protectionReady = Test-BitLockerKeyword -Value $statusProtection -Keywords @('off','0','none','desactive','desactivee','deactive','deactivated','disabled','arrete','arret','stoppe','inactive','suspendu','not protected','aucune protection')
    $conversionReady = Test-BitLockerKeyword -Value $statusConversion -Keywords @('integralement dechiffre','integralement decrypte','fully decrypted','fully decrypte','fullydecrypted','fullydecrypte','dechiffre','decrypte','not encrypted','non chiffre','pas chiffre','decrypted')

    $volume = $null
    if ($PSBoundParameters.ContainsKey('Volume') -and $null -ne $Volume) {
        $volume = $Volume
    } else {
        $volume = Get-BitLockerVolumeInfo -MountPoint $MountPoint
    }

    if ($volume) {
        $volProtection = $null
        if ($volume.PSObject.Properties.Match('ProtectionStatus').Count -gt 0) {
            $volProtection = [string]$volume.ProtectionStatus
        }
        if ($volProtection) {
            $protectionReady = $protectionReady -and (Test-BitLockerKeyword -Value $volProtection -Keywords @('off','0','none','desactive','desactivee','deactive','deactivated','disabled','arrete','stoppe','inactive','suspendu','not protected','aucune protection','off(0)'))
        }

        $volPercent = $null
        if ($volume.PSObject.Properties.Match('EncryptionPercentage').Count -gt 0 -and $null -ne $volume.EncryptionPercentage) {
            try {
                $volPercent = [double]$volume.EncryptionPercentage
            } catch {
                $volPercent = $null
            }
        }
        if ($null -ne $volPercent) {
            $percentageReady = $percentageReady -and ([math]::Abs($volPercent) -lt 0.01)
        }

        $volStatus = $null
        if ($volume.PSObject.Properties.Match('VolumeStatus').Count -gt 0) {
            $volStatus = [string]$volume.VolumeStatus
        }
    if ($volStatus) {
        $conversionReady = $conversionReady -and (Test-BitLockerKeyword -Value $volStatus -Keywords @('integralement dechiffre','integralement decrypte','fully decrypted','fully decrypte','fullydecrypted','fullydecrypte','dechiffre','decrypte','not encrypted','non chiffre','pas chiffre','decrypted'))
    }
}

$allReady = ($versionReady -and $percentageReady -and $protectionReady -and $conversionReady)
if ($allReady) {
    $script:BitLockerOverridePreviouslyAllowed = $true
}

return $allReady
}

function Suspend-SystemBitLocker {
    if (-not (Get-Command Suspend-BitLocker -ErrorAction SilentlyContinue)) {
        Write-Log 'Suspend-BitLocker indisponible (module BitLocker non present).' -ForegroundColor Yellow
        return
    }
    $volumes = Get-BitLockerVolume -ErrorAction SilentlyContinue
    if (-not $volumes) {
        Write-Log 'BitLocker non detecte sur ce systeme.' -ForegroundColor Green
        return
    }
    foreach ($vol in $volumes) {
        $mountPoints = @($vol.MountPoint) | Where-Object { $_ }
        $target = if ($mountPoints) { $mountPoints[0] } else { $vol.VolumeId }
        if (-not $target) { continue }

        $label = if ($mountPoints -and $mountPoints[0]) { $mountPoints[0] } elseif ($vol.VolumeType) { $vol.VolumeType } else { $target }
        $statusMsg = if ($vol.ProtectionStatus -eq 'On') { 'actif' } else { 'deja suspendu' }
        Write-Log ("Suspension de BitLocker sur {0} (etat actuel : {1}, suspension indefinie demandee)." -f $label, $statusMsg) -ForegroundColor Cyan
        try {
            Suspend-BitLocker -MountPoint $target -RebootCount 0 -Confirm:$false -ErrorAction Stop
        } catch {
            Write-Log ("Suspend-BitLocker a retourne une erreur sur {0} : {1}" -f $label, $_.Exception.Message) -ForegroundColor DarkRed
        }
        try {
            Write-Log ("manage-bde -protectors -disable {0}" -f $target) -ForegroundColor Cyan
            & manage-bde -protectors -disable $target 2>$null | Out-Null
        } catch {
            Write-Log ("Echec manage-bde -protectors -disable {0} : {1}" -f $target, $_.Exception.Message) -ForegroundColor DarkRed
        }
        Start-Sleep -Seconds 2
        $check = Get-BitLockerVolume -MountPoint $target -ErrorAction SilentlyContinue
        if ($check -and $check.ProtectionStatus -eq 'On') {
            Write-Log ("ALERTE : BitLocker sur {0} reste actif. Tentative de dechiffrement complet." -f $label) -ForegroundColor Red
            if (-not $script:BitLockerOffRequested) {
                if (Invoke-BitLockerDisable -MountPoint $target -CmdletContext $PSCmdlet) {
                    $script:BitLockerOffRequested = $true
                }
            }
        } else {
            Write-Log ("BitLocker sur {0} suspendu confirme." -f $label) -ForegroundColor Green
        }

        try {
            $statusLines = (& manage-bde -status $target 2>$null) -join "`n"
            if ($statusLines -match '(?i)red.marrage.*restant' -or $statusLines -match '(?i)restart.*remaining') {
                Write-Log ("Attention : un redemarrage est requis pour finaliser la suspension de BitLocker sur {0}." -f $label) -ForegroundColor Yellow
                $script:BitLockerRebootRequired = $true
            }
        } catch {}

        if ($check -and $check.ProtectionStatus -eq 'On') {
            Write-Log ("BitLocker sur {0} n'a pas pu etre suspendu automatiquement." -f $label) -ForegroundColor Red
            if (-not $script:BitLockerOffRequested) {
                if (Invoke-BitLockerDisable -MountPoint $target -CmdletContext $PSCmdlet) {
                    $script:BitLockerOffRequested = $true
                }
            }
            Write-Log "Veuillez suspendre BitLocker manuellement (manage-bde -protectors -disable $target) puis confirmez pour continuer." -ForegroundColor Yellow
            $userOk = Read-Host "BitLocker est-il maintenant suspendu ? (O/N)"
            if ($userOk -notin @('O','o','Y','y')) {
                throw ("Suspension BitLocker non validee pour {0}. Abandon." -f $label)
            }
            $verify = Get-BitLockerVolume -MountPoint $target -ErrorAction SilentlyContinue
            if ($verify -and $verify.ProtectionStatus -eq 'On') {
                throw ("BitLocker reste actif sur {0} malgre la confirmation manuelle." -f $label)
            }
            Write-Log ("BitLocker sur {0} confirme suspendu manuellement." -f $label) -ForegroundColor Green
        }
    }
}

function Assert-BitLockerGeneralizeReady {
    if (-not (Get-Command Get-BitLockerVolume -ErrorAction SilentlyContinue)) {
        return
    }

    $volumes = Get-BitLockerVolume -ErrorAction SilentlyContinue
    if (-not $volumes) { return }

    foreach ($vol in $volumes) {
        $mountPoints = @($vol.MountPoint) | Where-Object { $_ }
        $target = if ($mountPoints) { $mountPoints[0] } else { $vol.VolumeId }
        if (-not $target) { continue }

        $label = if ($mountPoints -and $mountPoints[0]) { $mountPoints[0] } elseif ($vol.VolumeType) { $vol.VolumeType } else { $target }
        if (Test-BitLockerReady -Volume $vol -MountPoint $target) {
            $script:BitLockerOverridePreviouslyAllowed = $true
            continue
        } else {
            $statusInfo = Get-BitLockerStatusInfo -MountPoint $target
            $protectionStatus = if ($statusInfo -and $statusInfo.Protection) { $statusInfo.Protection } elseif ($vol.PSObject.Properties.Match('ProtectionStatus').Count -gt 0) { [string]$vol.ProtectionStatus } else { 'Inconnu' }
            $encryptionPercentage = if ($statusInfo -and $null -ne $statusInfo.Percentage) { [double]$statusInfo.Percentage } else { 0.0 }
            if ($encryptionPercentage -eq 0.0 -and $vol.PSObject.Properties.Match('EncryptionPercentage').Count -gt 0 -and $null -ne $vol.EncryptionPercentage) {
                try { $encryptionPercentage = [double]$vol.EncryptionPercentage } catch { $encryptionPercentage = 0.0 }
            }
            $volumeStatus = if ($statusInfo -and $statusInfo.Conversion) { $statusInfo.Conversion } elseif ($vol.PSObject.Properties.Match('VolumeStatus').Count -gt 0) { [string]$vol.VolumeStatus } else { 'Inconnu' }
            $pctText = [System.String]::Format([System.Globalization.CultureInfo]::InvariantCulture, '{0:0.##}', $encryptionPercentage)
            $versionString = if ($statusInfo -and $statusInfo.Version) { $statusInfo.Version } else { (Get-BitLockerVersionString -MountPoint $target) }
            if (-not $versionString) { $versionString = 'Inconnu' }
            $versionReady = Test-BitLockerKeyword -Value $versionString -Keywords @('aucun','aucune','none','pas trouve','not found','sans','n/a','na','absent','no protectors','no protecteur')
            $protectionReady = Test-BitLockerKeyword -Value $protectionStatus -Keywords @('off','0','none','desactive','desactivee','deactive','deactivated','disabled','arrete','arret','stoppe','inactive','suspendu','not protected','aucune protection','off(0)')
            $conversionReady = Test-BitLockerKeyword -Value $volumeStatus -Keywords @('integralement dechiffre','integralement decrypte','fully decrypted','fully decrypte','fullydecrypted','fullydecrypte','dechiffre','decrypte','not encrypted','non chiffre','pas chiffre','decrypted')
            $percentageReady = ([math]::Abs($encryptionPercentage) -lt 0.01)
            if ($statusInfo -and $statusInfo.Raw) {
                Write-Log "Detail manage-bde -status :" -ForegroundColor DarkYellow
                $statusInfo.Raw.Split("`n") | ForEach-Object { Write-Log ("  {0}" -f $_) -ForegroundColor DarkYellow }
            }
            if ($versionReady -and $protectionReady -and $conversionReady -and $percentageReady) {
                Write-Log ("BitLocker deja confirme comme off sur {0} (Protection={1}, Chiffrement={2}%, Etat={3}, Version={4})." -f $label, $protectionStatus, $pctText, $volumeStatus, $versionString) -ForegroundColor Green
                $script:BitLockerOverridePreviouslyAllowed = $true
                continue
            }
            Write-Log ("BitLocker reste actif sur {0} (Protection={1}, Chiffrement={2}%, Etat={3}, Version={4})." -f $label, $protectionStatus, $pctText, $volumeStatus, $versionString) -ForegroundColor Red
            if (-not $script:BitLockerOffRequested) {
                if (Invoke-BitLockerDisable -MountPoint $target -CmdletContext $PSCmdlet) {
                    $script:BitLockerOffRequested = $true
                }
            }
            Write-Log ("Desactivez ou dechiffrez completement ce volume (ex : manage-bde -off {0}) avant de relancer ce script. Sysprep echouera sinon avec le code 0x80310039." -f $label) -ForegroundColor Yellow
            throw 'BitLocker toujours actif : Sysprep refuse de continuer.'
        }

        if ($script:BitLockerOverridePreviouslyAllowed) {
            continue
        }
    }
}

function Clear-TempFolders {
    Write-Log 'Nettoyage de %TEMP% et C:\Windows\Temp...' -ForegroundColor Cyan
    foreach ($path in @([IO.Path]::GetTempPath(), 'C:\Windows\Temp')) {
        if (-not (Test-Path $path)) { continue }
        Get-ChildItem -Path $path -Force -ErrorAction SilentlyContinue | ForEach-Object {
            try { Remove-Item -Path $_.FullName -Recurse -Force -ErrorAction Stop } catch {}
        }
    }
    Write-Log 'Nettoyage des dossiers temporaires termine.' -ForegroundColor Green
}

function Clear-AllEventLogs {
    Write-Log 'Purge des journaux devenements...' -ForegroundColor Cyan
    $logs = wevtutil el
    foreach ($log in $logs) {
        try { wevtutil cl "$log" } catch {}
    }
    Write-Log 'Purge des journaux effectuee.' -ForegroundColor Green
}

function Toggle-Network {
    param([int]$Seconds = 10)
    $adapters = Get-NetAdapter -Physical | Where-Object { $_.Status -eq 'Up' }
    if (-not $adapters) {
        Write-Log 'Aucun adaptateur reseau actif detecte, aucune action.' -ForegroundColor Yellow
        return
    }
    Write-Log 'Desactivation temporaire des adaptateurs reseau physiques...' -ForegroundColor Cyan
    $adapters | ForEach-Object { Disable-NetAdapter -Name $_.Name -Confirm:$false -ErrorAction SilentlyContinue }
    Start-Sleep -Seconds $Seconds
    Write-Log 'Reactivation des adaptateurs reseau.' -ForegroundColor Cyan
    $adapters | ForEach-Object { Enable-NetAdapter -Name $_.Name -Confirm:$false -ErrorAction SilentlyContinue }
}

function Remove-SysprepTag {
    $tag = Join-Path $env:WINDIR 'System32\Sysprep\Sysprep_succeeded.tag'
    if (Test-Path $tag) {
        Write-Log 'Suppression de Sysprep_succeeded.tag.' -ForegroundColor Cyan
        Remove-Item -Path $tag -Force -ErrorAction SilentlyContinue
    }
}

Assert-Admin

$timestamp = Get-Date
try { $TranscriptPath = [string]::Format($TranscriptPath, $timestamp) } catch {}
if (-not [System.IO.Path]::IsPathRooted($TranscriptPath)) {
    $TranscriptPath = Join-Path $logsRoot $TranscriptPath
}
$transcriptDir = Split-Path -Path $TranscriptPath -Parent
if ($transcriptDir -and -not (Test-Path -LiteralPath $transcriptDir)) {
    New-Item -ItemType Directory -Path $transcriptDir -Force | Out-Null
}
Start-Transcript -Path $TranscriptPath -ErrorAction SilentlyContinue | Out-Null
Write-Log "Transcript principal : $TranscriptPath" -ForegroundColor Cyan

$phaseWasExplicit = $PSBoundParameters.ContainsKey('Phase')
$phase2InitiatorDetected = $false
$phase2StateData = $null
if (Test-Path -LiteralPath $stateFilePath) {
    try {
        $rawState = Get-Content -LiteralPath $stateFilePath -Raw -ErrorAction Stop
        if ($rawState) {
            $phase2StateData = $rawState | ConvertFrom-Json -ErrorAction Stop
        }
    } catch {
        Write-Log ("Impossible de lire l'initiateur de Phase 2 ({0}) : {1}" -f $stateFilePath, $_.Exception.Message) -ForegroundColor DarkYellow
    }
    if ($phase2StateData -and $phase2StateData.phase -eq '2') {
        $phase2InitiatorDetected = $true
        if (-not $phaseWasExplicit) {
            Write-Log 'Initiateur Phase 2 detecte : reprise automatique en Phase 2.' -ForegroundColor Yellow
            $Phase = '2'
        } elseif ($Phase -eq '1') {
            Write-Log 'Initiateur Phase 2 detecte mais Phase 1 demande explicitement. Suppression de l''initiateur existant.' -ForegroundColor Yellow
            try { Remove-Item -LiteralPath $stateFilePath -Force -ErrorAction Stop } catch {}
            try { if (Test-Path -LiteralPath $serviceStatePath) { Remove-Item -LiteralPath $serviceStatePath -Force -ErrorAction Stop } } catch {}
            try { Remove-Phase2ResumeTask -TaskName $phase2TaskName -Cmdlet $PSCmdlet } catch {}
            $phase2InitiatorDetected = $false
            $phase2StateData = $null
        }
    }
}

$phaseServiceStates = @()

try {
    if ($Phase -eq '1') {
        Write-Log '=== Phase 1 : preparation avant Sysprep ===' -ForegroundColor Green
        Test-DiskSpace -MinimumGB 20
        if ($SkipPendingRebootCheck) {
            Write-Log 'Controle des redemarrages en attente ignore (SkipPendingRebootCheck).' -ForegroundColor Yellow
        } else {
            Test-PendingReboot
        }
        Test-DomainMembership

        Write-Log '=== Gel de Windows Update & Delivery Optimization ===' -ForegroundColor Green
        $phaseServiceStates = Disable-UpdateServices
        Invoke-DismComponentCleanup
        Disable-TrustedInstallerService
        Get-ChildItem -Path $scriptDir -Filter 'restore-update-services-*.bat' -ErrorAction SilentlyContinue | Remove-Item -Force
        $restoreScript = Join-Path $scriptDir ("restore-update-services-{0:yyyyMMdd-HHmmss}.bat" -f (Get-Date))
        Export-ServiceRestoreScript -ServiceStates $phaseServiceStates -OutputPath $restoreScript
        Write-Log "Script de restauration des services : $restoreScript" -ForegroundColor Yellow
        try { Save-ServiceStatesToFile -ServiceStates $phaseServiceStates -Path $serviceStatePath } catch {
            Write-Log ("Impossible d'enregistrer l'etat des services : {0}" -f $_.Exception.Message) -ForegroundColor DarkYellow
        }

        if (-not $SkipBitLockerSuspend) {
            Write-Log '=== Suspension BitLocker (C:) ===' -ForegroundColor Green
            Suspend-SystemBitLocker
            Assert-BitLockerGeneralizeReady
            if ($script:BitLockerRebootRequired) {
                Write-Log 'Un redemarrage est necessaire pour finaliser la suspension BitLocker. Souhaitez-vous redemarrer maintenant ? (O/N)' -ForegroundColor Yellow
                $confirmReboot = Read-Host 'Redemarrer requis'
                if ($confirmReboot -in @('O','o','Y','y')) {
                    Write-Log 'Redemarrage immediat pour finaliser la suspension BitLocker...' -ForegroundColor Cyan
                    Restart-Computer -Force
                    Start-Sleep -Seconds 1
                    exit
                } else {
                    throw 'Redemarrage BitLocker requis. Relancez le script apres avoir redemarre.'
                }
            }
        } else {
            Write-Log 'Suspension BitLocker ignoree (parametre SkipBitLockerSuspend).' -ForegroundColor Yellow
        }

        Write-Log '=== Hygiene rapide ===' -ForegroundColor Green
        Clear-TempFolders
        if ($ClearEventLogs) { Clear-AllEventLogs }

        Write-Log 'Verification Unattend ignoree (genere ulterieurement).' -ForegroundColor Yellow

        Write-Log '=== Pre-lancement Sysprep ===' -ForegroundColor Green
        Remove-SysprepTag

        if (-not $SkipNetworkToggle) {
            Toggle-Network -Seconds 10
        } else {
            Write-Log 'desactivation reseau ignoree (SkipNetworkToggle).' -ForegroundColor Yellow
        }

        Write-Log 'Phase 1 terminee. Souhaitez-vous redemarrer pour lancer automatiquement la Phase 2 ? (O/N)' -ForegroundColor Cyan
        Show-RestartPromptAnimation -Message 'Synchronisation avant redemarrage...'
        $phase2Reply = Read-Host 'Redemarrer pour Phase 2'
        if ($phase2Reply -in @('O','o','Y','y')) {
            $scriptPath = $PSCommandPath
            if (-not $scriptPath -and $MyInvocation.MyCommand.Path) {
                $scriptPath = $MyInvocation.MyCommand.Path
            }
            if (-not $scriptPath) {
                $scriptPath = Join-Path $scriptDir 'prepare_master.ps1'
            }
            $resolvedScriptPath = $scriptPath
            try {
                $resolvedScriptPath = (Resolve-Path -LiteralPath $scriptPath).Path
            } catch {}
            $currentPrincipal = [System.Security.Principal.WindowsIdentity]::GetCurrent()
            $currentUserName = if ($currentPrincipal) { $currentPrincipal.Name } else { $env:USERNAME }
            try {
                New-Phase2StateFile -Path $stateFilePath -Phase '2' -Reason 'RebootBeforeSysprep' -Cmdlet $PSCmdlet
            } catch {
                Write-Log ("Impossible de creer l'initiateur Phase 2 : {0}" -f $_.Exception.Message) -ForegroundColor DarkRed
                throw
            }
            try {
                Register-Phase2ResumeTask -TaskName $phase2TaskName -ScriptPath $resolvedScriptPath -UserId $currentUserName -Cmdlet $PSCmdlet
            } catch {
                Write-Log ("Impossible d'enregistrer la tache planifiee Phase 2 : {0}" -f $_.Exception.Message) -ForegroundColor DarkRed
                throw
            }
            Write-Log 'Redemarrage immediat pour lancer la Phase 2 apres demarrage.' -ForegroundColor Cyan
            Restart-Computer -Force
            Start-Sleep -Seconds 1
            exit
        } else {
            Write-Log "Phase 1 finalisee sans redemarrage. Lancez la Phase 2 manuellement via `".\prepare_master.ps1 -Phase 2`" lorsque vous serez pret." -ForegroundColor Yellow
        }
    } elseif ($Phase -eq '2') {
        Write-Log '=== Phase 2 : execution Sysprep & nettoyage AppX ===' -ForegroundColor Green
        try {
            Remove-Phase2ResumeTask -TaskName $phase2TaskName -Cmdlet $PSCmdlet
        } catch {
            Write-Log ("Impossible de supprimer la tache planifiee Phase 2 avant execution : {0}" -f $_.Exception.Message) -ForegroundColor DarkYellow
        }
        $phase2ScriptPath = $PSCommandPath
        if (-not $phase2ScriptPath -and $MyInvocation.MyCommand.Path) {
            $phase2ScriptPath = $MyInvocation.MyCommand.Path
        }
        Remove-Phase2StartupEntries -ScriptPath $phase2ScriptPath -AdditionalNames @('PrepareMaster_Launcher.bat','PrepareMaster_Launcher.lnk')
        if (-not $phase2InitiatorDetected -and -not $phaseWasExplicit) {
            Write-Log 'Phase 2 demarree manuellement.' -ForegroundColor Yellow
        }
        try {
            $phaseServiceStates = Load-ServiceStatesFromFile -Path $serviceStatePath
        } catch {
            Write-Log ("Impossible de charger l'etat des services : {0}" -f $_.Exception.Message) -ForegroundColor DarkYellow
            $phaseServiceStates = @()
        }
        if (-not $phaseServiceStates) {
            Write-Log 'Aucun etat enregistre pour les services Windows Update (restauration impossible).' -ForegroundColor Yellow
        } else {
            Write-Log 'Etat des services Windows Update charge (restauration en fin de Phase 2).' -ForegroundColor Green
            Write-Log 'Restauration des services critiques avant lancement de Sysprep...' -ForegroundColor Cyan
            try {
                Restore-UpdateServicesState -ServiceStates $phaseServiceStates -Cmdlet $PSCmdlet
            } catch {
                Write-Log ("Erreur lors de la restauration pre-Sysprep des services : {0}" -f $_.Exception.Message) -ForegroundColor DarkRed
            }
        }

        Write-Log '=== Pre-lancement Sysprep (Phase 2) ===' -ForegroundColor Green
        # Vérification bloquante: services critiques prêts
        try {
            Assert-PreSysprepServicesReady
        } catch {
            Write-Log ("Blocage: services non prêts pour Sysprep : {0}" -f $_.Exception.Message) -ForegroundColor Red
            throw
        }
        Remove-SysprepTag
        if (-not $SkipNetworkToggle) {
            Toggle-Network -Seconds 10
        } else {
            Write-Log 'desactivation reseau ignoree (SkipNetworkToggle).' -ForegroundColor Yellow
        }

        Write-Log '=== Lancement sysprep_cleaner ===' -ForegroundColor Green
        $sysprepCleanerCandidate = Resolve-ScriptRelativePath -Path $SysprepCleanerPath
        if (-not (Test-Path -LiteralPath $sysprepCleanerCandidate)) {
            throw "sysprep_cleaner.ps1 introuvable : $sysprepCleanerCandidate"
        }
        $sysprepCleanerFull = (Resolve-Path -LiteralPath $sysprepCleanerCandidate).Path
        try { $SysprepTranscriptPath = [string]::Format($SysprepTranscriptPath, (Get-Date)) } catch {}
        if (-not [System.IO.Path]::IsPathRooted($SysprepTranscriptPath)) {
            $SysprepTranscriptPath = Join-Path $logsRoot $SysprepTranscriptPath
        }
        $sysprepTranscriptDir = Split-Path -Path $SysprepTranscriptPath -Parent
        if ($sysprepTranscriptDir -and -not (Test-Path -LiteralPath $sysprepTranscriptDir)) {
            New-Item -ItemType Directory -Path $sysprepTranscriptDir -Force | Out-Null
        }

        $cleanerParams = [ordered]@{
            LogPath        = $SysprepLogPath
            TranscriptPath = $SysprepTranscriptPath
        }
        if ($SysprepCleanerAutoYes) {
            $cleanerParams['Yes'] = $true
        }
        if ($RunSysprepAfterCleaner) {
            $cleanerParams['RunSysprep'] = $true
            $cleanerParams['SysprepAction'] = $SysprepAction
            $cleanerParams['SysprepMode'] = $SysprepMode
            if ($NoGeneralize) { $cleanerParams['NoGeneralize'] = $true }
            if ($SysprepUnattend) { $cleanerParams['Unattend'] = $SysprepUnattend }
        }

        $cmdPreview = foreach ($entry in $cleanerParams.GetEnumerator()) {
            $name = "-$($entry.Key)"
            $value = $entry.Value
            if ($value -is [bool]) {
                if ($value) { $name }
            } else {
                $needsQuotes = ($value -is [string]) -and $value.Contains(' ')
                $formatted = if ($needsQuotes) { '"{0}"' -f $value } else { $value }
                "$name $formatted"
            }
        }
        Write-Log ("Commande : `"{0}`" {1}" -f $sysprepCleanerFull, ($cmdPreview -join ' ')) -ForegroundColor Cyan

        & $sysprepCleanerFull @cleanerParams
        $exitCode = $LASTEXITCODE
        Write-Log "sysprep_cleaner termine (ExitCode=$exitCode)." -ForegroundColor Cyan
        Write-Log "Transcript sysprep_cleaner : $SysprepTranscriptPath" -ForegroundColor Yellow
    } else {
        throw "Phase non supportee : $Phase"
    }
} catch {
    Write-Log "ERREUR : $_" -ForegroundColor Red
    throw
} finally {
    if ($Phase -eq '2') {
        try {
            Restore-UpdateServicesState -ServiceStates $phaseServiceStates -Cmdlet $PSCmdlet
        } catch {
            Write-Log ("Echec de la restauration automatique des services : {0}" -f $_.Exception.Message) -ForegroundColor DarkYellow
        }
        try {
            Remove-Phase2ResumeTask -TaskName $phase2TaskName -Cmdlet $PSCmdlet
        } catch {
            Write-Log ("Impossible de supprimer la tache planifiee Phase 2 : {0}" -f $_.Exception.Message) -ForegroundColor DarkYellow
        }
        try {
            if (Test-Path -LiteralPath $stateFilePath) {
                Remove-Item -LiteralPath $stateFilePath -Force -ErrorAction Stop
            }
        } catch {
            Write-Log ("Impossible de supprimer le fichier d'etat Phase 2 : {0}" -f $_.Exception.Message) -ForegroundColor DarkYellow
        }
        try {
            if (Test-Path -LiteralPath $serviceStatePath) {
                Remove-Item -LiteralPath $serviceStatePath -Force -ErrorAction Stop
            }
        } catch {
            Write-Log ("Impossible de supprimer le fichier d'etat des services : {0}" -f $_.Exception.Message) -ForegroundColor DarkYellow
        }
    }
    if ($TranscriptPath) {
        try { Stop-Transcript | Out-Null } catch {}
    }
}

Write-Log 'Script parent termine.' -ForegroundColor Green

