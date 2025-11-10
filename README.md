# SysprepFiX

Ensemble d'outils PowerShell pour preparer un master Windows avant generalisation : verifications critiques (BitLocker, AppX), nettoyage des applications UWP problematiques et orchestration complete avec reprise automatique.

## Contenu du depot

- `prepare_master.ps1` : chef d'orchestre en deux phases (preparation, redemarrage, lancement sysprep_cleaner).
- `sysprep_cleaner.ps1` : analyse `setupact.log`, suppression des paquets AppX bloquants, boucle Sysprep jusqu'au succes.
- `PrepareMaster_Launcher.bat` : lance `prepare_master.ps1` avec transcript automatique.
- `SysprepCleaner_RunAndLog.bat` : lance `sysprep_cleaner.ps1 -Yes -RunSysprep` et journalise l'execution.
- `logs\` : dossier cible pour les transcripts generes.
- `state.json` (genere) : fichier d'etat temporaire pour la reprise de phase.

## Prerequis

- Console PowerShell demarree en Administrateur (elevation obligatoire).
- Windows 10 ou 11 avec Sysprep, BitLocker et les cmdlets AppX disponibles.
- ExecutionPolicy autorisant les scripts (les lanceurs .bat passent en Bypass).
- Minimum 20 Go libres sur `C:` pour DISM et Sysprep.

## Vue d'ensemble

| Etape | Phase | Description |
| --- | --- | --- |
| Pre-checks | Phase 1 (`-Phase 1`) | Verifie espace disque, reboot en attente, appartenance domaine, lance le transcript principal. |
| Services Windows Update | Phase 1 | Aucun gel automatique : le script consigne simplement que les services restent actifs. |
| BitLocker | Phase 1 | Suspend BitLocker (cmdlet et manage-bde), confirme que Sysprep pourra generaliser. |
| Hygiene rapide | Phase 1 | Nettoie `%TEMP%` et `C:\Windows\Temp`, purge optionnelle des journaux. |
| Preparation Sysprep | Phase 1 | Supprime `Sysprep_succeeded.tag`, alterne les cartes reseau et propose le redemarrage pour Phase 2. |
| Reprise automatique | Transition | Cree `state.json`, enregistre une tache `SysprepFix-Phase2` qui relance le script en Phase 2 apres reboot. |
| Lancement Sysprep | Phase 2 (`-Phase 2`) | Restaure les services critiques, controle leur statut, relance sysprep_cleaner avec transcript dedie. |
| Restauration finale | Phase 2 | Restaure les services d'origine, supprime les fichiers d'etat et arrete le transcript.

## Details sur `prepare_master.ps1`

### Phase 1

1. `Assert-Admin`, `Test-DiskSpace`, `Test-PendingReboot`, `Test-DomainMembership`.
2. `Disable-UpdateServices` journalise que le gel est desactive, `Invoke-DismComponentCleanup` reste actif, `Disable-TrustedInstallerService` se contente d'un log.
3. `Suspend-SystemBitLocker` puis `Assert-BitLockerGeneralizeReady` valident l'absence de verrouillage BitLocker.
4. `Clear-TempFolders` et `Clear-AllEventLogs` (optionnel).
5. `Remove-SysprepTag`, `Toggle-Network`.
6. Invite a redemarrer pour Phase 2 : `New-Phase2StateFile` et `Register-Phase2ResumeTask` preparent la reprise automatique.

### Phase 2

1. Supprime la tache planifiee et les entrees Run/RunOnce associees (`Remove-Phase2StartupEntries`).
2. Passe directement aux controles `Assert-PreSysprepServicesReady` (TrustedInstaller, wuauserv) sans tenter de restaurer un snapshot de services.
3. Rafraichit reseau et tag Sysprep, puis construit les arguments pour `sysprep_cleaner.ps1`.
4. Lance `sysprep_cleaner` avec transcript horodate, propage les parametres (`-RunSysprepAfterCleaner`, `-SysprepAction`, `-SysprepMode`, `-NoGeneralize`, `-SysprepUnattend`, `-SysprepCleanerAutoYes`).
5. Bloc `finally` : supprime `state.json` et ferme le transcript.

### Artefacts generes

- `logs\prepare-master-YYYYMMDD-HHMMSS.log` : transcript principal.
- `logs\sysprep_cleaner-YYYYMMDD-HHMMSS.log` : transcript sysprep_cleaner.
- `state.json` : drapeau Phase 2 (supprime automatiquement).

## Details sur `sysprep_cleaner.ps1`

- Analyse `setupact.log` (et `setuperr.log`) pour reperer les lignes `SYSPRP Package ... was installed for a user`.
- `Invoke-AppxCleanupOnce` combine `Remove-AppxPackage` et `Remove-AppxProvisionedPackage`; `-Exclude` permet de conserver certaines apps.
- `Invoke-SysprepCleanupLoop` relance Sysprep jusqu'a disparition des erreurs ou blocage critique.
- Detection des erreurs 0x80310039 (BitLocker), 0x80073CF2 (AppX obstinee) et Reserved Storage occupe (0x800F0975 / 0x80070975).
- Tentative de desactivation BitLocker : essaie `Disable-BitLocker -MountPoint C:` (PowerShell) si disponible, sinon bascule automatiquement sur `manage-bde -off`.
- Lorsque le dechiffrement est lance, le script rappelle que l'operation peut prendre longtemps et conseille de suivre `manage-bde -status C:` jusqu'a Protection=Off et Pourcentage=0%.
- Avant chaque nettoyage/Sysprep, `Ensure-ReservedStorageScenarioClear` lit `HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\ReserveManager\ActiveScenario`; si la valeur est differente de 0, le script explique le probleme et propose (auto en `-Yes`) de la forcer a 0 via `Set-ItemProperty`.
- `Ensure-BitLockerReady` appelle `manage-bde -off` si necessaire et relaye les informations a l'utilisateur.
- Possibilite d'executer un script de restauration personnalise avant chaque Sysprep (`-PreSysprepRestoreScript`).
- Codes de sortie : 0 succes, 1 echec generique, 2 BitLocker actif, 3 AppX resistant, 4 Reserved Storage.

## Parametres principaux

### prepare_master.ps1

| Parametre | Defaut | Effet |
| --- | --- | --- |
| `-Phase` | `1` | Phase a executer (`1` ou `2`). |
| `-SysprepCleanerPath` | `.\sysprep_cleaner.ps1` | Chemin du script de nettoyage. |
| `-SysprepLogPath` | `C:\Windows\System32\Sysprep\Panther\setupact.log` | Journal Sysprep analyse. |
| `-SysprepTranscriptPath` | `.\logs\sysprep_cleaner-{timestamp}.log` | Transcript passe a sysprep_cleaner. |
| `-RunSysprepAfterCleaner` | `$true` | Chaine nettoyage + Sysprep. Mettre `:$false` pour nettoyage seul. |
| `-SysprepCleanerAutoYes` | `$false` | Force `-Yes` cote sysprep_cleaner. |
| `-SysprepAction` | `shutdown` | Action finale (shutdown, reboot, quit). |
| `-SysprepMode` | `oobe` | Mode Sysprep (oobe ou audit). |
| `-NoGeneralize` | `$false` | Retire l'option `/generalize`. |
| `-SysprepUnattend` | `null` | Fichier unattend a transmettre. |
| `-SkipBitLockerSuspend` | `$false` | Ignore la suspension BitLocker. |
| `-SkipNetworkToggle` | `$false` | N'alterne pas les cartes reseau. |
| `-ClearEventLogs` | `$false` | Purge tous les journaux d'evenements. |
| `-SkipPendingRebootCheck` | `$false` | Ignore la detection de reboot en attente. |
| `-TranscriptPath` | `.\logs\prepare-master-{timestamp}.log` | Transcript principal. |

### sysprep_cleaner.ps1

| Parametre | Defaut | Effet |
| --- | --- | --- |
| `-LogPath` | `C:\Windows\System32\Sysprep\Panther\setupact.log` | Journal Sysprep analyse. |
| `-Yes` | `$false` | Suppression AppX sans confirmation. |
| `-Exclude` | `[]` | Liste d'apps a conserver. |
| `-TranscriptPath` | `null` | Transcript de run. |
| `-RunSysprep` | `$false` | Enchaine les relances Sysprep. |
| `-SysprepAction` | `shutdown` | Action finale Sysprep. |
| `-SysprepMode` | `oobe` | Mode Sysprep. |
| `-NoGeneralize` | `$false` | Omet `/generalize`. |
| `-Unattend` | `null` | Fichier unattend optionnel. |
| `-PreSysprepRestoreScript` | `null` | Script externe execute avant Sysprep (restauration custom). |

## Journaux et artefacts

- `logs\prepare-master-*.log` : transcript global.
- `logs\sysprep_cleaner-*.log` : journal detaille des suppressions et tentatives Sysprep.
- `logs\run-*.log` : transcript genere par `SysprepCleaner_RunAndLog.bat`.
- `state.json` : drapeau de reprise Phase 2.

## Depannage

- **0x80310039 BitLocker** : verifier `manage-bde -status`, suspendre ou desactiver, puis relancer Phase 2.
- **0x80073CF2 AppX** : supprimer manuellement le package resilient, relancer sysprep_cleaner.
- **Reserved Storage** : suivre les commandes suggerees (DISM StartComponentCleanup puis Set-ReservedStorageState). Le script controle aussi `HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\ReserveManager\ActiveScenario`; forcer `Set-ItemProperty -Path ... -Name ActiveScenario -Value 0` s'il reste bloque.
- **Phase 2 non relancee** : supprimer `state.json`, la tache `SysprepFix-Phase2`, puis executer `prepare_master.ps1 -Phase 2`.
- **Boucle sur les memes erreurs** : purger `setupact.log` et `setuperr.log`, verifier les transcripts dans `logs\`.

## Utilisation conseillee

1. Lancer `PrepareMaster_Launcher.bat` en Administrateur (ou `prepare_master.ps1` manuellement).
2. Suivre les invites Phase 1, accepter le redemarrage si BitLocker l'exige.
3. Laisser la machine redemarrer, la Phase 2 reprend automatiquement; sinon lancer `.\prepare_master.ps1 -Phase 2`.
4. En mode interactif, confirmer les suppressions AppX (ou fournir `-SysprepCleanerAutoYes`).
5. Apres succes, conserver les transcripts jusqu'a validation du master puis les archiver/supprimer selon vos procedures.

## Bonnes pratiques

- Tester Phase 1 sur une VM snapshottee avant de l'appliquer sur un master de reference.
- S'assurer que BitLocker est suspendu durablement avant de lancer Sysprep.
- Utiliser `-WhatIf` pour valider les actions prevues sans modification.
- Verifier les transcripts pour toute investigation (toutes les commandes y sont journalisees).
- Supprimer les artefacts sensibles (transcripts) une fois le master valide.
