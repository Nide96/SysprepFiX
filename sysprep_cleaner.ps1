<#
.SYNOPSIS
Detecte et supprime automatiquement les packages AppX qui bloquent Sysprep.

.DESCRIPTION
Analyse le fichier setupact.log de Sysprep pour identifier les packages AppX
installes pour un utilisateur mais non provisionnes au niveau systeme.
Supprime ensuite ces packages pour tous les utilisateurs ET du provisioning.

.PARAMETER LogPath
Chemin du journal Sysprep a analyser (setupact.log par defaut).

.PARAMETER Yes
Execute sans demander de confirmation (mode non interactif).

.PARAMETER Exclude
Liste de noms courts d'apps a ne pas supprimer (ex: Microsoft.BingNews).

.PARAMETER TranscriptPath
Chemin d'un fichier transcript pour journaliser l'execution.

.PARAMETER RunSysprep
Lance Sysprep automatiquement apres le nettoyage.

.PARAMETER SysprepAction
Action apres Sysprep: shutdown, reboot ou quit (shutdown par defaut).

.PARAMETER SysprepMode
Mode Sysprep: oobe ou audit (oobe par defaut).

.PARAMETER NoGeneralize
N'ajoute pas le commutateur /generalize (par defaut, /generalize est utilise).

.PARAMETER Unattend
Chemin vers un fichier Unattend XML a passer a Sysprep.

.PARAMETER PreSysprepRestoreScript
Script optionnel a executer avec elevation avant chaque lancement de Sysprep.

.EXAMPLE
.\n+  .\sysprep_cleaner.ps1 -Yes -WhatIf
Dry run complet (sans suppression) avec confirmation bypass.

.EXAMPLE
.
  .\sysprep_cleaner.ps1 -Exclude Microsoft.WindowsStore,Microsoft.SkypeApp
Exclut certaines apps de la suppression.
#>

[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
    [string]$LogPath = 'C:\Windows\System32\Sysprep\Panther\setupact.log',
    [switch]$Yes,
    [string[]]$Exclude,
    [string]$TranscriptPath,
    [switch]$RunSysprep,
    [ValidateSet('shutdown','reboot','quit')][string]$SysprepAction = 'shutdown',
    [ValidateSet('oobe','audit')][string]$SysprepMode = 'oobe',
    [switch]$NoGeneralize,
    [string]$Unattend,
    [string]$PreSysprepRestoreScript
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$script:EXIT_SUCCESS = 0
$script:EXIT_GENERAL_FAILURE = 1
$script:EXIT_BITLOCKER_BLOCKED = 2
$script:EXIT_APPX_STUBBORN = 3
$script:EXIT_RESERVED_STORAGE = 4
$script:BitLockerOffRequested = $false
$script:BitLockerOverridePreviouslyAllowed = $false

# Sortie console en UTF-8 pour eviter les caracteres "?"
try {
    $OutputEncoding = [Console]::OutputEncoding = [System.Text.UTF8Encoding]::new()
} catch {}

$script:ScriptDir = if ($PSScriptRoot) { $PSScriptRoot } else { Split-Path -Parent $MyInvocation.MyCommand.Path }
$script:DefaultServiceSnapshot = if ($script:ScriptDir) { Join-Path -Path $script:ScriptDir -ChildPath 'service-states.json' } else { 'service-states.json' }

function Write-Log {
    param(
        [Parameter(Position = 0)]
        [object]$Message,
        [ConsoleColor]$ForegroundColor = [ConsoleColor]::White
    )

    $msgText = if ($Message -is [string]) { $Message } else { $Message | Out-String }
    if (-not $msgText) { $msgText = '' }
    Write-Host $msgText -ForegroundColor $ForegroundColor
}

function Convert-ServiceStartMode {
    param([string]$StartMode)

    if (-not $StartMode) { return 'Manual' }
    switch -Regex ($StartMode) {
        '^auto$'              { return 'Automatic' }
        '^automatic$'         { return 'Automatic' }
        '^delayed-auto$'      { return 'AutomaticDelayedStart' }
        '^automaticdelayed'   { return 'AutomaticDelayedStart' }
        '^manual$'            { return 'Manual' }
        '^demand$'            { return 'Manual' }
        '^disabled$'          { return 'Disabled' }
        default               { return 'Manual' }
    }
}

function Restore-ServiceStates {
    param(
        [string]$Path = $script:DefaultServiceSnapshot
    )

    if (-not $Path -or -not (Test-Path -LiteralPath $Path)) {
        Write-Log ("Aucun snapshot de services trouve a '{0}'." -f $Path) -ForegroundColor Yellow
        return @()
    }

    try {
        $raw = Get-Content -LiteralPath $Path -Raw -ErrorAction Stop
        if (-not $raw) {
            Write-Log ("Snapshot de services vide : {0}" -f $Path) -ForegroundColor Yellow
            return @()
        }
        $data = $raw | ConvertFrom-Json -ErrorAction Stop
    } catch {
        Write-Log ("Lecture du snapshot services impossible ({0}) : {1}" -f $Path, $_.Exception.Message) -ForegroundColor DarkYellow
        return @()
    }

    $serviceStates = @($data | Where-Object { $_ -and $_.Name })
    if ($serviceStates.Count -eq 0) {
        Write-Log ("Snapshot de services sans entrees exploitables ({0})." -f $Path) -ForegroundColor Yellow
        return @()
    }

    $restored = New-Object 'System.Collections.Generic.List[string]'

    foreach ($svc in $serviceStates) {
        if ($svc.Name -eq 'dosvc') {
            Write-Log "Ignorer la restauration de dosvc (sealed par le systeme)." -ForegroundColor Yellow
            continue
        }
        if ($svc.Name -eq 'CryptSvc') {
            Write-Log "Ignorer la restauration de CryptSvc (mode de service conserve)." -ForegroundColor Yellow
            continue
        }
        $serviceName = $svc.Name
        $desiredMode = Convert-ServiceStartMode -StartMode $svc.StartMode
        try {
            switch ($desiredMode) {
                'AutomaticDelayedStart' {
                    & sc.exe config $serviceName start= delayed-auto | Out-Null
                    if ($LASTEXITCODE -ne 0) { throw "sc.exe a retourne le code $LASTEXITCODE" }
                }
                'Automatic' {
                    Set-Service -Name $serviceName -StartupType Automatic -ErrorAction Stop
                }
                'Disabled' {
                    Set-Service -Name $serviceName -StartupType Disabled -ErrorAction Stop
                }
                default {
                    Set-Service -Name $serviceName -StartupType Manual -ErrorAction Stop
                }
            }
        } catch {
            Write-Log ("Impossible de restaurer le StartupType de {0} : {1}" -f $serviceName, $_.Exception.Message) -ForegroundColor DarkYellow
            continue
        }

        if ($serviceName -eq 'wuauserv') {
            $delayedProp = $svc.PSObject.Properties['Delayed']
            if ($delayedProp) {
                $delayedValue = $delayedProp.Value
                if ($delayedValue -isnot [int]) {
                    try { $delayedValue = [int]$delayedValue } catch { $delayedValue = 0 }
                }
                try {
                    New-Item -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\wuauserv' -Force | Out-Null
                    Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\wuauserv' -Name 'DelayedAutostart' -Type DWord -Value $delayedValue -ErrorAction Stop
                } catch {
                    Write-Log ("Impossible de positionner DelayedAutostart pour wuauserv : {0}" -f $_.Exception.Message) -ForegroundColor DarkYellow
                }
            }
        }

        if ($svc.State -and $svc.State.ToString().Equals('Running',[System.StringComparison]::OrdinalIgnoreCase)) {
            try {
                Start-Service -Name $serviceName -ErrorAction SilentlyContinue
            } catch {
                Write-Log ("Impossible de demarrer le service {0} : {1}" -f $serviceName, $_.Exception.Message) -ForegroundColor DarkYellow
            }
        }

        $restored.Add($serviceName) | Out-Null
    }

    if ($restored.Count -gt 0) {
        Write-Log ("Services restaures avant Sysprep : {0}" -f ($restored -join ', ')) -ForegroundColor Green
    } else {
        Write-Log "Aucun service n'a ete restaure (aucune entree exploitable)." -ForegroundColor Yellow
    }

    return @($restored.ToArray())
}

function Get-SysprepLineTimestamp {
    param(
        [string]$Line
    )

    if (-not $Line) { return $null }
    if ($Line -notmatch '^(?<date>\d{4}-\d{2}-\d{2})\s+(?<time>\d{2}:\d{2}:\d{2})') {
        return $null
    }
    $datePart = $matches['date']
    $timePart = $matches['time']
    if (-not $datePart -or -not $timePart) { return $null }
    $stamp = '{0} {1}' -f $datePart, $timePart
    try {
        return [datetime]::ParseExact($stamp, 'yyyy-MM-dd HH:mm:ss', [System.Globalization.CultureInfo]::InvariantCulture)
    } catch {
        return $null
    }
}

function Get-ProblematicAppNames {
    param(
        [string]$LogPath,
        [string[]]$Exclude,
        [datetime]$Since
    )

    if (-not $LogPath) {
        return [pscustomobject]@{
            All      = @()
            Filtered = @()
            Excluded = @()
        }
    }
    if (-not (Test-Path -LiteralPath $LogPath)) {
        return [pscustomobject]@{
            All      = @()
            Filtered = @()
            Excluded = @()
        }
    }

    $sinceCutoff = $null
    if ($PSBoundParameters.ContainsKey('Since') -and $Since) {
        $sinceCutoff = $Since
    }

    $pattern = 'SYSPRP\s+Package\s+([^\s]+)\s+was installed for a user'
    try {
        $lines = Select-String -Path $LogPath -Pattern $pattern -AllMatches -ErrorAction Stop
    } catch {
        Write-Verbose $_
        return [pscustomobject]@{
            All      = @()
            Filtered = @()
            Excluded = @()
        }
    }

    $allApps = $lines | ForEach-Object {
        foreach ($m in $_.Matches) {
            $fullName = $m.Groups[1].Value
            if (-not $fullName) { continue }
            if ($sinceCutoff) {
                $lineStamp = Get-SysprepLineTimestamp -Line $_.Line
                if ($lineStamp -and $lineStamp -lt $sinceCutoff) { continue }
            }
            $shortName = $fullName.Split('_')[0]
            if ($shortName) { $shortName }
        }
    } | Where-Object { $_ } | Sort-Object -Unique

    $filtered = $allApps
    $excluded = @()
    if ($Exclude -and $Exclude.Count -gt 0) {
        $filtered = $allApps | Where-Object { $_ -notin $Exclude }
        $excluded = $allApps | Where-Object { $_ -in $Exclude }
    }

    return [pscustomobject]@{
        All      = @($allApps)
        Filtered = @($filtered)
        Excluded = @($excluded)
    }
}

function Get-RecentSysprepLogLines {
    param(
        [string]$LogPath,
        [int]$Tail = 400,
        [int]$LookbackMinutes = 2
    )

    $logsToCheck = @()
    if ($LogPath -and (Test-Path -LiteralPath $LogPath)) {
        $logsToCheck += $LogPath
    }
    if ($LogPath) {
        try {
            $errLog = Join-Path -Path ([System.IO.Path]::GetDirectoryName($LogPath)) -ChildPath 'setuperr.log'
            if (Test-Path -LiteralPath $errLog) {
                $logsToCheck += $errLog
            }
        } catch {}
    }
    if (-not $logsToCheck) {
        return @()
    }

    $timestampRegex = '^(?<date>\d{4}-\d{2}-\d{2})\s+(?<time>\d{2}:\d{2}:\d{2})'
    $culture = [System.Globalization.CultureInfo]::InvariantCulture
    $collected = @()

    foreach ($path in $logsToCheck) {
        try {
            $tail = Get-Content -LiteralPath $path -Tail $Tail -ErrorAction Stop
        } catch {
            continue
        }

        if (-not $tail) { continue }

        $entries = @()
        $currentTs = $null
        foreach ($line in $tail) {
            if ($line -match $timestampRegex) {
                $tsString = '{0} {1}' -f $matches['date'], $matches['time']
                try {
                    $currentTs = [datetime]::ParseExact($tsString, 'yyyy-MM-dd HH:mm:ss', $culture)
                } catch {
                    $currentTs = $null
                }
            }
            $entries += [pscustomobject]@{
                Timestamp = $currentTs
                Line      = $line
            }
        }

        if (@($entries).Count -eq 0) { continue }

        $latestTs = $entries | Where-Object { $_.Timestamp } | Sort-Object -Property Timestamp -Descending | Select-Object -First 1 -ExpandProperty Timestamp
        if ($latestTs) {
            $windowStart = $latestTs.AddMinutes(-[double]$LookbackMinutes)
            $recentLines = @($entries | Where-Object { $_.Timestamp -and $_.Timestamp -ge $windowStart })
            if ($recentLines.Count -gt 0) {
                $collected += $recentLines.Line
                continue
            }
        }

        $collected += $entries.Line
    }

    return $collected
}

function Test-BitLockerErrorInSysprepLogs {
    param(
        [string]$LogPath
    )

    $patterns = @(
        '(?i)Error.*BitLocker-Sysprep',
        '(?i)Error.*ValidateBitLockerState',
        '(?i)Error.*0x80310039'
    )

    $linesToScan = Get-RecentSysprepLogLines -LogPath $LogPath
    if (-not $linesToScan -or @($linesToScan).Count -eq 0) {
        return $false
    }

    foreach ($pattern in $patterns) {
        if ($linesToScan | Where-Object { $_ -match $pattern }) {
            return $true
        }
    }

    return $false
}

function Test-ReservedStorageBusyInSysprepLogs {
    param(
        [string]$LogPath
    )

    $patterns = @(
        '(?i)reserved storage is in use',
        '(?i)Audit mode cannot be turned on if reserved storage is in use',
        '(?i)0x800f0975',
        '(?i)0x80070975'
    )

    $linesToScan = Get-RecentSysprepLogLines -LogPath $LogPath
    if (-not $linesToScan -or @($linesToScan).Count -eq 0) {
        return $false
    }

    foreach ($pattern in $patterns) {
        if ($linesToScan | Where-Object { $_ -match $pattern }) {
            return $true
        }
    }

    return $false
}

function Get-ReservedStorageActiveScenarioState {
    param(
        [string]$RegistryPath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\ReserveManager',
        [string]$ValueName = 'ActiveScenario'
    )

    $state = [pscustomobject]@{
        Exists   = $false
        Value    = $null
        IsActive = $false
    }

    if (-not (Test-Path -LiteralPath $RegistryPath)) {
        Write-Verbose ("Cle ReserveManager introuvable ({0})." -f $RegistryPath)
        return $state
    }

    try {
        $props = Get-ItemProperty -LiteralPath $RegistryPath -Name $ValueName -ErrorAction Stop
        if ($null -eq $props) { return $state }
        $value = $props.$ValueName
        $state.Exists = $true
        $state.Value = $value
        if ($null -eq $value) { return $state }

        $numericValue = $null
        if ($value -is [ValueType]) {
            try { $numericValue = [long]$value } catch { $numericValue = $null }
        }
        if ($null -eq $numericValue) {
            $stringValue = [string]$value
            if (-not [string]::IsNullOrWhiteSpace($stringValue)) {
                $trimmed = $stringValue.Trim()
                if ($trimmed -match '^0x[0-9a-fA-F]+$') {
                    try { $numericValue = [Convert]::ToInt64($trimmed,16) } catch { $numericValue = $null }
                } else {
                    [long]::TryParse($trimmed, [ref]$numericValue) | Out-Null
                }
            }
        }

        if ($null -ne $numericValue) {
            $state.IsActive = ($numericValue -ne 0)
        } else {
            $stringEval = [string]$value
            $state.IsActive = -not [string]::IsNullOrWhiteSpace($stringEval) -and -not $stringEval.Trim().Equals('0',[System.StringComparison]::OrdinalIgnoreCase)
        }
    } catch {
        Write-Verbose ("Lecture de ActiveScenario impossible ({0}\\{1}) : {2}" -f $RegistryPath, $ValueName, $_.Exception.Message)
    }

    return $state
}

function Reset-ReservedStorageActiveScenario {
    param(
        [string]$RegistryPath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\ReserveManager',
        [string]$ValueName = 'ActiveScenario'
    )

    try {
        if (-not (Test-Path -LiteralPath $RegistryPath)) {
            return $false
        }
        Set-ItemProperty -LiteralPath $RegistryPath -Name $ValueName -Value 0 -ErrorAction Stop
        return $true
    } catch {
        Write-Verbose ("Impossible de positionner ActiveScenario a 0 ({0}\\{1}) : {2}" -f $RegistryPath, $ValueName, $_.Exception.Message)
        return $false
    }
}

function Ensure-ReservedStorageScenarioClear {
    param(
        [switch]$Yes,
        [string]$RegistryPath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\ReserveManager',
        [string]$ValueName = 'ActiveScenario'
    )

    $state = Get-ReservedStorageActiveScenarioState -RegistryPath $RegistryPath -ValueName $ValueName
    if (-not $state.IsActive) {
        return $true
    }

    $displayValue = if ($null -eq $state.Value) { '(null)' } else { $state.Value }
    Write-Log ("Erreur : Reserved Storage signale un scenario actif (ActiveScenario={0})." -f $displayValue) -ForegroundColor Red
    Write-Log "Windows Update/servicing monopolise encore l'espace reserve. Sysprep echouera tant que cette valeur reste differente de 0." -ForegroundColor Yellow

    $shouldForce = $false
    if ($Yes) {
        $shouldForce = $true
        Write-Log "Mode -Yes : tentative automatique de forcer ActiveScenario a 0." -ForegroundColor DarkYellow
    } else {
        $response = Read-Host "Forcer maintenant ActiveScenario a 0 ? (O/N)"
        if ($response -in @('O','o','Y','y')) {
            $shouldForce = $true
        }
    }

    if ($shouldForce) {
        Write-Log "Tentative de remise a zero de Reserved Storage ActiveScenario..." -ForegroundColor DarkYellow
        if (Reset-ReservedStorageActiveScenario -RegistryPath $RegistryPath -ValueName $ValueName) {
            $state = Get-ReservedStorageActiveScenarioState -RegistryPath $RegistryPath -ValueName $ValueName
            if (-not $state.IsActive) {
                Write-Log "ActiveScenario force a 0 avec succes." -ForegroundColor Green
                return $true
            }
            $displayValue = if ($null -eq $state.Value) { '(null)' } else { $state.Value }
            Write-Log ("ActiveScenario reste non nul ({0}) malgre la tentative de correction." -f $displayValue) -ForegroundColor Red
        } else {
            Write-Log "Impossible de modifier la valeur ActiveScenario automatiquement." -ForegroundColor Red
        }

        Write-Log "Corrigez manuellement via : Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\ReserveManager' -Name 'ActiveScenario' -Value 0" -ForegroundColor Yellow
        return $false
    }

    Write-Log "Operation interrompue tant que Reserved Storage reste actif." -ForegroundColor Yellow
    Write-Log "Commande proposee : Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\ReserveManager' -Name 'ActiveScenario' -Value 0" -ForegroundColor Yellow
    return $false
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

function Normalize-BitLockerString {
    param(
        [string]$Value
    )

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
    $normalized = Normalize-BitLockerString -Value $Value
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

function Get-DismInstallPendingReport {
    Write-Log 'Vérification des paquets "Install Pending" via DISM...' -ForegroundColor Cyan

    $trustedInstaller = $null
    $tiWasRunning = $false
    $tiOriginalMode = $null

    try {
        $trustedInstaller = Get-Service -Name 'TrustedInstaller' -ErrorAction Stop
        $tiWasRunning = ($trustedInstaller.Status -eq [System.ServiceProcess.ServiceControllerStatus]::Running)
        try {
            $tiOriginalMode = (Get-CimInstance Win32_Service -Filter "Name='TrustedInstaller'" -ErrorAction Stop).StartMode
        } catch {
            $tiOriginalMode = $trustedInstaller.StartType.ToString()
        }

        if ($trustedInstaller.StartType -eq [System.ServiceProcess.ServiceStartMode]::Disabled) {
            try {
                Set-Service -Name 'TrustedInstaller' -StartupType Manual -ErrorAction Stop
            } catch {
                Write-Log ("Impossible de positionner TrustedInstaller en mode Manual : {0}" -f $_.Exception.Message) -ForegroundColor DarkYellow
            }
        }
        if (-not $tiWasRunning) {
            try {
                Start-Service -Name 'TrustedInstaller' -ErrorAction Stop
            } catch {
                Write-Log ("Impossible de démarrer TrustedInstaller avant DISM : {0}" -f $_.Exception.Message) -ForegroundColor DarkYellow
            }
        }
    } catch {
        Write-Log ("Avertissement : accès au service TrustedInstaller impossible ({0})." -f $_.Exception.Message) -ForegroundColor DarkYellow
    }

    try {
        $output = (& dism.exe /online /get-packages 2>&1)
    } catch {
        Write-Log ("DISM /Get-Packages a échoué : {0}" -f $_.Exception.Message) -ForegroundColor DarkRed
        $output = $null
    }

    if ($trustedInstaller) {
        try {
            if (-not $tiWasRunning) {
                Stop-Service -Name 'TrustedInstaller' -Force -ErrorAction SilentlyContinue
            }
        } catch {}
        try {
            if ($tiOriginalMode -and $tiOriginalMode.Equals('Disabled',[System.StringComparison]::OrdinalIgnoreCase)) {
                Set-Service -Name 'TrustedInstaller' -StartupType Disabled -ErrorAction SilentlyContinue
            }
        } catch {}
    }

    if ($null -eq $output) { return $null }

    if ($LASTEXITCODE -ne 0) {
        Write-Log ("DISM /Get-Packages a retourné le code {0}." -f $LASTEXITCODE) -ForegroundColor DarkRed
    }

    $pending = $output | Where-Object { $_ -match 'Install Pending' }
    if ($pending -and $pending.Count -gt 0) {
        Write-Log 'Paquets en état "Install Pending" détectés :' -ForegroundColor Yellow
        $pending | ForEach-Object { Write-Log ("  {0}" -f $_.Trim()) -ForegroundColor Yellow }
    } else {
        Write-Log 'Aucun paquet en état "Install Pending".' -ForegroundColor Green
    }

    return $pending
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

function Ensure-BitLockerReady {
    param(
        [string]$MountPoint = 'C:'
    )

    $volume = Get-BitLockerVolumeInfo -MountPoint $MountPoint
    if (-not $volume) {
        return $true
    }

    if (Test-BitLockerReady -Volume $volume -MountPoint $MountPoint) {
        $script:BitLockerOverridePreviouslyAllowed = $true
        return $true
    }

    if (-not $script:BitLockerOffRequested) {
        if (Invoke-BitLockerDisable -MountPoint $MountPoint -CmdletContext $PSCmdlet) {
            $script:BitLockerOffRequested = $true
        }
    }

    $statusInfo = Get-BitLockerStatusInfo -MountPoint $MountPoint

    $protectionStatus = if ($statusInfo -and $statusInfo.Protection) { $statusInfo.Protection } elseif ($volume.PSObject.Properties.Match('ProtectionStatus').Count -gt 0) { [string]$volume.ProtectionStatus } else { 'Inconnu' }
    $encryptionPercentage = if ($statusInfo -and $null -ne $statusInfo.Percentage) { [double]$statusInfo.Percentage } else { 0.0 }
    if ($encryptionPercentage -eq 0.0 -and $volume.PSObject.Properties.Match('EncryptionPercentage').Count -gt 0 -and $null -ne $volume.EncryptionPercentage) {
        try { $encryptionPercentage = [double]$volume.EncryptionPercentage } catch { $encryptionPercentage = 0.0 }
    }
    $volumeStatus = if ($statusInfo -and $statusInfo.Conversion) { $statusInfo.Conversion } elseif ($volume.PSObject.Properties.Match('VolumeStatus').Count -gt 0) { [string]$volume.VolumeStatus } else { 'Inconnu' }
    $pctText = [System.String]::Format([System.Globalization.CultureInfo]::InvariantCulture, '{0:0.##}', $encryptionPercentage)
    $versionString = if ($statusInfo -and $statusInfo.Version) { $statusInfo.Version } else { (Get-BitLockerVersionString -MountPoint $MountPoint) }
    if (-not $versionString) { $versionString = 'Inconnu' }

    $versionReady = Test-BitLockerKeyword -Value $versionString -Keywords @('aucun','aucune','none','pas trouve','not found','sans','n/a','na','absent','no protectors','no protecteur')
    $protectionReady = Test-BitLockerKeyword -Value $protectionStatus -Keywords @('off','0','none','desactive','desactivee','deactive','deactivated','disabled','arrete','arret','stoppe','inactive','suspendu','not protected','aucune protection','off(0)')
    $conversionReady = Test-BitLockerKeyword -Value $volumeStatus -Keywords @('integralement dechiffre','integralement decrypte','fully decrypted','fully decrypte','fullydecrypted','fullydecrypte','dechiffre','decrypte','not encrypted','non chiffre','pas chiffre','decrypted')
    $percentageReady = ([math]::Abs($encryptionPercentage) -lt 0.01)

    if ($statusInfo -and $statusInfo.Raw) {
        Write-Log "Detail manage-bde -status :" -ForegroundColor DarkYellow
        $statusInfo.Raw.Split("`n") | ForEach-Object { Write-Log ("  {0}" -f $_) -ForegroundColor DarkYellow }
    }

    if ($versionReady -and $percentageReady -and $protectionReady -and $conversionReady) {
        Write-Log ("BitLocker a deja ete confirme comme off (Protection={1}, Chiffrement={2}%, Etat={3}, Version={4})." -f $MountPoint, $protectionStatus, $pctText, $volumeStatus, $versionString) -ForegroundColor Green
        $script:BitLockerOverridePreviouslyAllowed = $true
        return $true
    }

    Write-Log ("BitLocker reste actif sur {0} (Protection={1}, Chiffrement={2}%, Etat={3}, Version={4})." -f $MountPoint, $protectionStatus, $pctText, $volumeStatus, $versionString) -ForegroundColor Red
    Write-Log ("Desactivez ou dechiffrez completement ce volume (ex : manage-bde -off {0}) avant de relancer. Sysprep echoue sinon avec l'erreur 0x80310039." -f $MountPoint) -ForegroundColor Yellow
    return $false
}

function Invoke-AppxRemoval {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [string[]]$AppNames,
        [switch]$Yes
    )

    if (-not $AppNames -or $AppNames.Count -eq 0) {
        Write-Log "Aucun package AppX a supprimer." -ForegroundColor Green
        return [pscustomobject]@{
            UserRemovals        = 0
            ProvisionedRemovals = 0
        }
    }

    $userRemovals = 0
    $provRemovals = 0

    foreach ($app in $AppNames) {
        Write-Host ""
        Write-Log "=== Traitement de : $app ===" -ForegroundColor Yellow

        if (-not $Yes) {
            $prompt = Read-Host "Supprimer le package $app pour tous les utilisateurs ET du provisioning ? (O/N)"
            if ($prompt -notin @('O','o','Y','y')) {
                Write-Log "Suppression du package $app annulee par l'utilisateur." -ForegroundColor Yellow
                continue
            }
        } else {
            Write-Verbose "Suppression $app confirme via -Yes"
        }

        $pkgs = Get-AppxPackage -AllUsers -Name $app -ErrorAction SilentlyContinue
        if ($pkgs) {
            foreach ($pkg in $pkgs) {
                $removedAllUsers = $false
                try {
                    if ($PSCmdlet.ShouldProcess($pkg.PackageFullName, "Remove-AppxPackage -AllUsers")) {
                        Remove-AppxPackage -AllUsers -Package $pkg.PackageFullName -ErrorAction Stop
                        $userRemovals++
                        $removedAllUsers = $true
                        Write-Log "  V Suppression utilisateur : $($pkg.PackageFullName)" -ForegroundColor Green
                    } else {
                        Write-Log "  (WhatIf) Suppression utilisateur : $($pkg.PackageFullName)" -ForegroundColor DarkCyan
                    }
                } catch {
                    Write-Log "  ? Erreur suppression utilisateur : $($pkg.PackageFullName)" -ForegroundColor Red
                    Write-Log "    $_" -ForegroundColor DarkRed
                }

                if (-not $removedAllUsers) {
                    $userInfos = @()
                    if ($pkg.PSObject.Properties.Match('PackageUserInformation').Count -gt 0) {
                        $userInfos = @($pkg.PackageUserInformation)
                    }
                    if ($userInfos.Count -eq 0) {
                        $stringInfo = $pkg | Select-Object -ExpandProperty PackageUserInformation -ErrorAction SilentlyContinue
                        if ($stringInfo) { $userInfos = @($stringInfo) }
                    }

                    foreach ($info in $userInfos) {
                        $userState = $null
                        $sid = $null
                        if ($info -is [string]) {
                            if ($info -match '^(?<sid>S-[0-9\-]+)\s*\[(?<state>[^\]]+)\]') {
                                $sid = $matches['sid']
                                $userState = $matches['state']
                            } else {
                                $userState = $info
                            }
                        } else {
                            if ($info.PSObject.Properties.Match('InstallState').Count -gt 0) {
                                $userState = $info.InstallState
                            }
                            if ($info.PSObject.Properties.Match('UserSecurityId').Count -gt 0) {
                                $sid = $info.UserSecurityId
                            } elseif ($info.PSObject.Properties.Match('UserSid').Count -gt 0 -and $info.UserSid) {
                                try { $sid = $info.UserSid.Value } catch { $sid = $info.UserSid.ToString() }
                            }
                        }

                        if ($userState -and $userState.ToString() -notmatch 'Installed') { continue }
                        if (-not $sid) { continue }

                        try {
                            if ($PSCmdlet.ShouldProcess("$($pkg.PackageFullName) @ $sid", "Remove-AppxPackage -User")) {
                                Remove-AppxPackage -Package $pkg.PackageFullName -User $sid -ErrorAction Stop
                                $userRemovals++
                                Write-Log "  V Suppression utilisateur ($sid) : $($pkg.PackageFullName)" -ForegroundColor Green
                            } else {
                                Write-Log "  (WhatIf) Suppression utilisateur ($sid) : $($pkg.PackageFullName)" -ForegroundColor DarkCyan
                            }
                        } catch {
                            Write-Log "  ? Erreur suppression utilisateur ($sid) : $($pkg.PackageFullName)" -ForegroundColor Red
                            Write-Log "    $_" -ForegroundColor DarkRed
                        }
                    }
                }
            }
        } else {
            Write-Log "  (Deja absent des profils utilisateurs)" -ForegroundColor DarkYellow
        }

        $provPkgs = Get-AppxProvisionedPackage -Online -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName -eq $app }
        if ($provPkgs) {
            foreach ($prov in $provPkgs) {
                try {
                    if ($PSCmdlet.ShouldProcess($prov.PackageName, "Remove-AppxProvisionedPackage -Online")) {
                        Remove-AppxProvisionedPackage -Online -PackageName $prov.PackageName -ErrorAction Stop | Out-Null
                        $provRemovals++
                        Write-Log "  V Suppression provisioning : $($prov.PackageName)" -ForegroundColor Green
                    } else {
                        Write-Log "  (WhatIf) Suppression provisioning : $($prov.PackageName)" -ForegroundColor DarkCyan
                    }
                } catch {
                    Write-Log "  ? Erreur suppression provisioning : $($prov.PackageName)" -ForegroundColor Red
                    Write-Log "    $_" -ForegroundColor DarkRed
                }
            }
        } else {
            Write-Log "  (Pas provisionne, rien a retirer du store d'image)" -ForegroundColor DarkYellow
        }

        $stillUsers = Get-AppxPackage -AllUsers -Name $app -ErrorAction SilentlyContinue
        if ($stillUsers) {
            Write-Log "  ! Le package est encore present pour au moins un utilisateur." -ForegroundColor DarkRed
        } else {
            Write-Log "   Verification: plus aucune instance installee pour les utilisateurs." -ForegroundColor Green
        }
        $stillProv = Get-AppxProvisionedPackage -Online -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName -eq $app }
        if ($stillProv) {
            Write-Log "  ! Le package est toujours provisionne dans l'image (nouveaux profils)." -ForegroundColor DarkRed
        } else {
            Write-Log "   Verification: plus aucune entree provisionnee." -ForegroundColor Green
        }
    }

    Write-Host ""
    Write-Log "=== Nettoyage termine ===" -ForegroundColor Green
    Write-Log ("Resume: {0} suppression(s) cote utilisateurs, {1} suppression(s) cote provisioning." -f $userRemovals, $provRemovals) -ForegroundColor Green

    return [pscustomobject]@{
        UserRemovals        = $userRemovals
        ProvisionedRemovals = $provRemovals
    }
}

function Invoke-AppxCleanupOnce {
    param(
        [string]$LogPath,
        [string[]]$Exclude,
        [switch]$Yes,
        [datetime]$LogSince
    )

    $logExists = Test-Path -LiteralPath $LogPath
    $logEmpty = $false
    if ($logExists) {
        try { $logEmpty = ((Get-Item -LiteralPath $LogPath).Length -eq 0) } catch { $logEmpty = $false }
    }
    if (-not $logExists -or $logEmpty) {
        $why = if (-not $logExists) { 'introuvable' } else { 'vide' }
        Write-Log "Avertissement : Le fichier setupact.log est $why." -ForegroundColor DarkYellow
        Write-Log "Chemin attendu : $LogPath"
        Write-Log "Astuce : lancez au moins une fois Sysprep pour generer le log, ou corrigez le chemin." -ForegroundColor Yellow
        return $script:EXIT_GENERAL_FAILURE
    }

    if (-not $script:BitLockerOverridePreviouslyAllowed) {
        if (Test-BitLockerErrorInSysprepLogs -LogPath $LogPath) {
            Write-Log "Erreur BitLocker detectee dans les journaux Sysprep (0x80310039). Corrigez l'etat BitLocker avant de relancer." -ForegroundColor Red
            if (-not $script:BitLockerOffRequested) {
                if (Invoke-BitLockerDisable -MountPoint 'C:' -CmdletContext $PSCmdlet) {
                    $script:BitLockerOffRequested = $true
                }
            }
            return $script:EXIT_BITLOCKER_BLOCKED
        }
    } else {
        Write-Log "Skipping BitLocker error check because the system is flagged as already confirmed safe." -ForegroundColor DarkYellow
    }

    if (Test-ReservedStorageBusyInSysprepLogs -LogPath $LogPath) {
        Write-Log "Erreur : Reserved Storage est en cours d'utilisation (0x800F0975/0x80070975)." -ForegroundColor Red
        Write-Log "Un servicing Windows Update monopolise l'espace reserve. Terminez les operations en cours, redemarrez, puis relancez Sysprep." -ForegroundColor Yellow
        Write-Log "Astuce : executez 'dism.exe /Online /Cleanup-Image /StartComponentCleanup' puis 'dism.exe /Online /Set-ReservedStorageState /State:Disabled' dans PowerShell Administrateur pour liberer l'espace reserve." -ForegroundColor Yellow
        return $script:EXIT_RESERVED_STORAGE
    }

    if (-not (Ensure-ReservedStorageScenarioClear -Yes:$Yes)) {
        return $script:EXIT_RESERVED_STORAGE
    }

    $getParams = @{
        LogPath = $LogPath
        Exclude = $Exclude
    }
    if ($PSBoundParameters.ContainsKey('LogSince') -and $LogSince) {
        $getParams['Since'] = $LogSince
    }

    $appInfo = Get-ProblematicAppNames @getParams
    $badApps = @($appInfo.Filtered | Where-Object { $_ })
    $excludedApps = @($appInfo.Excluded | Where-Object { $_ })
    if ($excludedApps.Count -gt 0) {
        Write-Log ("({0} element(s) exclu(s) via -Exclude)" -f $excludedApps.Count) -ForegroundColor DarkYellow
    }
    if ($badApps.Count -eq 0) {
        Write-Log "Aucun package AppX problematique detecte dans le log Sysprep." -ForegroundColor Green
        Write-Log "Soit l'image est propre, soit l'echec Sysprep a une autre cause." -ForegroundColor Yellow
        return $script:EXIT_SUCCESS
    }

    Write-Host ""
    Write-Log "=== Packages AppX problematiques detectes ===" -ForegroundColor Yellow
    $badApps | ForEach-Object { Write-Log " - $_" -ForegroundColor Cyan }

    if (-not $Yes) {
        $confirmation = Read-Host "Voulez-vous supprimer ces packages pour tous les utilisateurs ET du provisioning ? (O/N)"
        if ($confirmation -notin @('O','o','Y','y')) {
            Write-Log "Operation annulee." -ForegroundColor Yellow
            return $script:EXIT_SUCCESS
        }
    } else {
        Write-Verbose "Confirmation bypass via -Yes"
    }

    Invoke-AppxRemoval -AppNames $badApps -Yes:$Yes | Out-Null
    Write-Log "Vous pouvez maintenant relancer Sysprep (ex : /generalize /oobe /shutdown)." -ForegroundColor Green
    return $script:EXIT_SUCCESS
}

function Invoke-SysprepCleanupLoop {
    param(
        [string]$LogPath,
        [string[]]$Exclude,
        [switch]$Yes,
        [ValidateSet('shutdown','reboot','quit')][string]$Action,
        [ValidateSet('oobe','audit')][string]$Mode,
        [switch]$NoGeneralize,
        [string]$Unattend,
        [string]$PreSysprepRestoreScript,
        [int]$MaxIterations = 5
    )

    $sysprepExe = Get-SysprepExecutable
    if (-not $sysprepExe) {
        Write-Log "Erreur : Sysprep.exe introuvable (System32/Sysnative/SysWOW64)." -ForegroundColor Red
        return $script:EXIT_GENERAL_FAILURE
    }
    $sysprepArgs = Get-SysprepArguments -Action $Action -Mode $Mode -NoGeneralize:$NoGeneralize -Unattend $Unattend

    $resolvedPreSysprepScript = $null
    if ($PreSysprepRestoreScript) {
        try {
            $resolvedPreSysprepScript = (Resolve-Path -LiteralPath $PreSysprepRestoreScript -ErrorAction Stop).ProviderPath
            Write-Verbose ("Script de restauration pre-Sysprep resolu vers '{0}'." -f $resolvedPreSysprepScript)
        } catch {
            Write-Log ("Erreur : impossible de localiser le script pre-Sysprep '{0}'." -f $PreSysprepRestoreScript) -ForegroundColor Red
            Write-Log $_ -ForegroundColor DarkRed
            return $script:EXIT_GENERAL_FAILURE
        }
    }

    if (-not $Yes) {
        Write-Log "Ce mode lancera Sysprep puis proposera la suppression des AppX detectes, jusqu'a disparition des erreurs." -ForegroundColor Yellow
        $answer = Read-Host "Confirmez-vous ce mode boucle ? (O/N)"
        if ($answer -notin @('O','o','Y','y')) {
            Write-Log "Operation annulee." -ForegroundColor Yellow
            return $script:EXIT_SUCCESS
        }
    }

    $seenSets = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)

    for ($iteration = 1; $iteration -le $MaxIterations; $iteration++) {
        Write-Host ""
        Write-Log ("=== Iteration Sysprep/AppX #{0} ===" -f $iteration) -ForegroundColor Green

        if (-not (Ensure-BitLockerReady -MountPoint 'C:')) {
            return $script:EXIT_BITLOCKER_BLOCKED
        }

        Get-DismInstallPendingReport | Out-Null

        $iterationStart = (Get-Date).AddSeconds(-1)

        if (-not $Yes) {
            $confirmSysprep = Read-Host ("Lancer Sysprep pour l'iteration #{0} ? (O/N)" -f $iteration)
            if ($confirmSysprep -notin @('O','o','Y','y')) {
                Write-Log ("Boucle interrompue avant lancement de Sysprep (iteration #{0})." -f $iteration) -ForegroundColor Yellow
                return $script:EXIT_SUCCESS
            }
        }

        if (-not (Ensure-ReservedStorageScenarioClear -Yes:$Yes)) {
            return $script:EXIT_RESERVED_STORAGE
        }

        $exitCode = Invoke-SysprepProcess -Executable $sysprepExe -Arguments $sysprepArgs -PreSysprepRestoreScript $resolvedPreSysprepScript
        if ($null -ne $exitCode) {
            Write-Log ("Sysprep (iteration #{0}) s'est termine avec le code {1}." -f $iteration, $exitCode) -ForegroundColor Cyan
            if ($exitCode -ne 0) {
                Write-Log "Code retour non nul detecte, interruption de la boucle Sysprep/AppX." -ForegroundColor Red
                return $exitCode
            }
        }

        if (-not $Yes) {
            Write-Log "Si une fenetre Sysprep est encore ouverte (erreur), fermez-la avant de continuer." -ForegroundColor Yellow
            $ack = Read-Host "Continuer l'analyse du journal Sysprep ? (O/N)"
            if ($ack -notin @('O','o','Y','y')) {
                Write-Log "Boucle interrompue a la demande de l'utilisateur apres Sysprep." -ForegroundColor Yellow
                return $script:EXIT_SUCCESS
            }
        }

        $logReady = $false
        for ($retry = 0; $retry -lt 5; $retry++) {
            if (Test-Path -LiteralPath $LogPath) {
                $logReady = $true
                break
            }
            Start-Sleep -Seconds 2
        }
        if (-not $logReady) {
            Write-Log "Erreur : setupact.log n'a pas ete trouve apres l'execution de Sysprep." -ForegroundColor Red
            return $script:EXIT_GENERAL_FAILURE
        }

        Start-Sleep -Seconds 2

        if (Test-BitLockerErrorInSysprepLogs -LogPath $LogPath) {
            Write-Log "Erreur BitLocker detectee dans les journaux Sysprep (0x80310039). Arret de la boucle : desactivez BitLocker puis relancez." -ForegroundColor Red
            return $script:EXIT_BITLOCKER_BLOCKED
        }

        if (Test-ReservedStorageBusyInSysprepLogs -LogPath $LogPath) {
            Write-Log "Erreur : Reserved Storage est en cours d'utilisation (0x800F0975/0x80070975). Boucle interrompue." -ForegroundColor Red
            Write-Log "Solution : laissez les operations Windows Update se terminer, redemarrez, puis relancez Sysprep." -ForegroundColor Yellow
            Write-Log "Astuce : 'dism.exe /Online /Cleanup-Image /StartComponentCleanup' et 'dism.exe /Online /Set-ReservedStorageState /State:Disabled' peuvent aider a liberer l'espace reserve." -ForegroundColor Yellow
            return $script:EXIT_RESERVED_STORAGE
        }

        $appInfoParams = @{
            LogPath = $LogPath
            Exclude = $Exclude
        }
        if ($iterationStart) {
            $appInfoParams['Since'] = $iterationStart
        }

        $appInfo = Get-ProblematicAppNames @appInfoParams
        $badApps = @($appInfo.Filtered | Where-Object { $_ })
        $excludedApps = @($appInfo.Excluded | Where-Object { $_ })
        if ($excludedApps.Count -gt 0) {
            Write-Log ("({0} element(s) exclu(s) via -Exclude)" -f $excludedApps.Count) -ForegroundColor DarkYellow
        }
        if ($badApps.Count -eq 0) {
            Write-Log "Aucune erreur AppX detectee apres cette execution de Sysprep." -ForegroundColor Green
            return $script:EXIT_SUCCESS
        }

        Write-Host ""
        Write-Log ("Packages AppX problematiques detectes apres Sysprep #{0} :" -f $iteration) -ForegroundColor Yellow
        $badApps | ForEach-Object { Write-Log " - $_" -ForegroundColor Cyan }

        $signature = ($badApps | Sort-Object) -join ';'
        if ($seenSets.Contains($signature)) {
            Write-Log "Les memes packages reviennent malgre les suppressions precedentes. Interruption de la boucle." -ForegroundColor Red
            Write-Log "Conseil : l'application est probablement reinstallee automatiquement. Ajoutez-la a -Exclude ou desinstallez-la definitivement avant de relancer Sysprep." -ForegroundColor Yellow
            return $script:EXIT_APPX_STUBBORN
        }
        $seenSets.Add($signature) | Out-Null

        if (-not $Yes) {
            $confirmCleanup = Read-Host "Supprimer ces packages maintenant ? (O/N)"
            if ($confirmCleanup -notin @('O','o','Y','y')) {
                Write-Log "Boucle interrompue a la demande de l'utilisateur." -ForegroundColor Yellow
                return $script:EXIT_SUCCESS
            }
        } else {
            Write-Verbose "Confirmation suppression bypass via -Yes"
        }

        Invoke-AppxRemoval -AppNames $badApps -Yes:$Yes | Out-Null

        if ($iteration -eq $MaxIterations) {
            if ($Yes) {
                $MaxIterations += 5
                Write-Log ("Nombre maximal de tentatives initial ({0}) atteint, extension automatique a {1} (mode -Yes)." -f ($iteration), $MaxIterations) -ForegroundColor Yellow
            } else {
                $prompt = Read-Host ("Nombre maximal de tentatives atteint ({0}). Continuer avec 5 iterations supplementaires ? (O/N)" -f $MaxIterations)
                if ($prompt -in @('O','o','Y','y')) {
                    $MaxIterations += 5
                    Write-Log ("Nouvelle limite d'iterations : {0}." -f $MaxIterations) -ForegroundColor Yellow
                } else {
                    Write-Log ("Nombre maximal de tentatives atteint ({0}). Arret a la demande." -f $MaxIterations) -ForegroundColor Red
                    return $script:EXIT_APPX_STUBBORN
                }
            }
        }

        if (-not $Yes) {
            $rerun = Read-Host "Relancer Sysprep pour une nouvelle verification ? (O/N)"
            if ($rerun -notin @('O','o','Y','y')) {
                Write-Log "Boucle interrompue avant relance de Sysprep." -ForegroundColor Yellow
                return $script:EXIT_SUCCESS
            }
        } else {
            Write-Verbose "Relance Sysprep automatique (mode -Yes)."
        }

        Write-Log "Nouvelle execution de Sysprep requise pour verifier les erreurs restantes..." -ForegroundColor Yellow
    }

    return $script:EXIT_SUCCESS
}

function Get-SysprepExecutable {
    $candidates = @(
        (Join-Path -Path $env:WINDIR -ChildPath 'System32\Sysprep\sysprep.exe'),
        (Join-Path -Path $env:WINDIR -ChildPath 'Sysnative\Sysprep\sysprep.exe'),
        (Join-Path -Path $env:WINDIR -ChildPath 'SysWOW64\Sysprep\sysprep.exe')
    )
    foreach ($candidate in $candidates) {
        if (Test-Path -LiteralPath $candidate) { return $candidate }
    }
    return $null
}

function Get-SysprepArguments {
    param(
        [ValidateSet('shutdown','reboot','quit')]
        [string]$Action,
        [ValidateSet('oobe','audit')]
        [string]$Mode,
        [switch]$NoGeneralize,
        [string]$Unattend
    )

    $args = @()
    if (-not $NoGeneralize) { $args += '/generalize' }
    if ($Mode -eq 'audit') { $args += '/audit' } else { $args += '/oobe' }
    switch ($Action) {
        'reboot' { $args += '/reboot' }
        'quit'   { $args += '/quit' }
        default  { $args += '/shutdown' }
    }
    if ($Unattend) {
        if (Test-Path -LiteralPath $Unattend) {
            $args += ('/unattend:"{0}"' -f (Resolve-Path -LiteralPath $Unattend))
        } else {
            Write-Log "Avertissement : fichier Unattend introuvable ($Unattend). Argument ignore." -ForegroundColor DarkYellow
        }
    }
    return $args
}

function Invoke-SysprepProcess {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [string]$Executable,
        [string[]]$Arguments,
        [string]$PreSysprepRestoreScript,
        [string]$ServiceSnapshotPath = $script:DefaultServiceSnapshot
    )

    $preview = ('"{0}" {1}' -f $Executable, ($Arguments -join ' ')).Trim()
    Write-Log "Preparation de Sysprep: $preview" -ForegroundColor Cyan

    if (-not $PSCmdlet.ShouldProcess($Executable,'Lancer Sysprep')) {
        Write-Log "(WhatIf) Sysprep ne sera pas lance." -ForegroundColor DarkCyan
        return $null
    }

    try {
        if ($PSCmdlet.ShouldProcess('Services','Restaurer etats precedents avant Sysprep')) {
            Restore-ServiceStates -Path $ServiceSnapshotPath | Out-Null
        }

        if ($PreSysprepRestoreScript) {
            if (-not (Test-Path -LiteralPath $PreSysprepRestoreScript)) {
                Write-Log ("Erreur : script pre-Sysprep introuvable ('{0}')." -f $PreSysprepRestoreScript) -ForegroundColor Red
                return $script:EXIT_GENERAL_FAILURE
            }

            if ($PSCmdlet.ShouldProcess($PreSysprepRestoreScript,'Executer script pre-Sysprep')) {
                Write-Log ("Execution du script pre-Sysprep '{0}'..." -f $PreSysprepRestoreScript) -ForegroundColor Cyan
                $preScriptWorkingDir = Split-Path -Path $PreSysprepRestoreScript -Parent
                if (-not $preScriptWorkingDir) {
                    $preScriptWorkingDir = (Get-Location).Path
                }

                $preScriptParams = @{
                    WorkingDirectory = $preScriptWorkingDir
                    Verb             = 'runas'
                    Wait             = $true
                    PassThru         = $true
                    WindowStyle      = 'Normal'
                    ErrorAction      = 'Stop'
                }

                $extension = [System.IO.Path]::GetExtension($PreSysprepRestoreScript)
                if ($extension -and $extension.Equals('.ps1', [System.StringComparison]::OrdinalIgnoreCase)) {
                    try {
                        $powershellExe = (Get-Command -Name 'powershell.exe' -ErrorAction Stop).Source
                    } catch {
                        Write-Log "Erreur : impossible de localiser powershell.exe pour executer le script pre-Sysprep." -ForegroundColor Red
                        Write-Log $_ -ForegroundColor DarkRed
                        return $script:EXIT_GENERAL_FAILURE
                    }
                    $preScriptParams['FilePath'] = $powershellExe
                    $preScriptParams['ArgumentList'] = @('-NoProfile','-ExecutionPolicy','Bypass','-File',$PreSysprepRestoreScript)
                } else {
                    $preScriptParams['FilePath'] = $PreSysprepRestoreScript
                }

                try {
                    $preProc = Start-Process @preScriptParams
                    $preExitCode = $null
                    try { $preExitCode = $preProc.ExitCode } catch { $preExitCode = $null }
                    if ($null -ne $preExitCode) {
                        Write-Log ("Script pre-Sysprep termine (ExitCode={0})." -f $preExitCode) -ForegroundColor Cyan
                        if ($preExitCode -ne 0) {
                            Write-Log "Execution du script pre-Sysprep en echec, abandon du lancement de Sysprep." -ForegroundColor Red
                            return $preExitCode
                        }
                    } else {
                        Write-Log "Script pre-Sysprep termine (code retour indisponible)." -ForegroundColor Yellow
                    }
                } catch {
                    Write-Log "Erreur lors de l'execution du script pre-Sysprep." -ForegroundColor Red
                    Write-Log $_ -ForegroundColor DarkRed
                    return $script:EXIT_GENERAL_FAILURE
                }
            }
        }

        $wd = Split-Path -Path $Executable -Parent
        $proc = Start-Process -FilePath $Executable -ArgumentList $Arguments -WorkingDirectory $wd -Wait -PassThru -WindowStyle Normal -ErrorAction Stop
        Write-Log "Sysprep lance (PID: $($proc.Id))." -ForegroundColor Green
        $exitCode = $null
        try { $exitCode = $proc.ExitCode } catch { $exitCode = $null }
        if ($null -ne $exitCode) {
            $msgColor = if ($exitCode -eq 0) { 'Green' } else { 'Red' }
            Write-Log ("Sysprep termine (ExitCode={0})." -f $exitCode) -ForegroundColor $msgColor
        } else {
            Write-Log "Sysprep termine (code retour indisponible)." -ForegroundColor Green
        }
        return $exitCode
    } catch {
        Write-Log "Erreur lors du lancement direct de Sysprep." -ForegroundColor Red
        Write-Log $_ -ForegroundColor DarkRed
        return $script:EXIT_GENERAL_FAILURE
    }
}

if ($Yes) {
    try { $PSDefaultParameterValues['Remove-AppxPackage:Confirm'] = $false } catch {}
    try { $PSDefaultParameterValues['Remove-AppxProvisionedPackage:Confirm'] = $false } catch {}
    $ConfirmPreference = 'None'
}

# ==============================
# 1) Prerequis: execution en Admin
# ==============================
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltinRole] "Administrator")) {
    Write-Log "Erreur : execute ce script en PowerShell Administrateur, sinon rien ne sera supprime." -ForegroundColor Red
    exit 1
}

# ==============================
# 2) Localisation du log Sysprep
# ==============================
$logPath = $LogPath

if ($TranscriptPath) {
    try {
        $now = Get-Date
        try { $TranscriptPath = [string]::Format($TranscriptPath, $now) } catch {}
        if (-not [System.IO.Path]::IsPathRooted($TranscriptPath)) {
            $TranscriptPath = Join-Path -Path (Get-Location) -ChildPath $TranscriptPath
        }
        $transcriptDir = Split-Path -Path $TranscriptPath -Parent
        if ($transcriptDir -and -not (Test-Path -LiteralPath $transcriptDir)) {
            New-Item -ItemType Directory -Path $transcriptDir -Force | Out-Null
        }
        Start-Transcript -Path $TranscriptPath -ErrorAction Stop | Out-Null
        Write-Verbose "Transcript demarre: $TranscriptPath"
    } catch {
        Write-Log "Avertissement: impossible de demarrer le transcript a '$TranscriptPath'" -ForegroundColor DarkYellow
        Write-Verbose $_
    }
}

$exitCode = $script:EXIT_SUCCESS
try {
    if ($RunSysprep) {
        $exitCode = Invoke-SysprepCleanupLoop -LogPath $logPath -Exclude $Exclude -Yes:$Yes -Action $SysprepAction -Mode $SysprepMode -NoGeneralize:$NoGeneralize -Unattend $Unattend -PreSysprepRestoreScript $PreSysprepRestoreScript
    } else {
        $exitCode = Invoke-AppxCleanupOnce -LogPath $logPath -Exclude $Exclude -Yes:$Yes
    }
} catch {
    Write-Log "ERREUR : $_" -ForegroundColor Red
    $exitCode = $script:EXIT_GENERAL_FAILURE
} finally {
    if ($TranscriptPath) {
        try { Stop-Transcript | Out-Null } catch {}
    }
}

exit $exitCode


