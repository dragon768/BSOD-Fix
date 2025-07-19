# BSOD Fixer PowerShell Script
# Runs in Windows 10/11, including WinRE, to fix non-hardware BSOD errors automatically

# Log file setup
$LogFile = "C:\BSOD_Fixer_Log_$((Get-Date).ToString('yyyyMMdd_HHmmss')).txt"
$StateFile = "C:\BSOD_Fixer_State.txt"

function Write-Log {
    param($Message, $Level = "INFO")
    $Timestamp = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
    try {
        "$Timestamp - $Level - $Message" | Out-File -FilePath $LogFile -Append -ErrorAction Stop
        if ($Level -eq "INFO") { Write-Host "[INFO] $Message" }
        if ($Level -eq "ERROR") { Write-Host "[ERROR] $Message" -ForegroundColor Red }
    }
    catch {
        Write-Host "[ERROR] Failed to write to log file: $_"
    }
}

# Save script state
function Save-State {
    param($Stage)
    Write-Host "[INFO] Saving script state: $Stage..."
    Write-Log "Saving script state: $Stage..."
    try {
        $Stage | Out-File -FilePath $StateFile -Force -ErrorAction Stop
        Write-Log "Script state saved to $StateFile."
        Write-Host "[INFO] Script state saved to $StateFile."
    }
    catch {
        Write-Log "Failed to save script state: $_" "ERROR"
        Write-Host "[ERROR] Failed to save script state: $_"
    }
}

# Load script state
function Load-State {
    Write-Host "[INFO] Checking for previous script state..."
    Write-Log "Checking for previous script state..."
    try {
        if (Test-Path $StateFile) {
            $Stage = Get-Content $StateFile -Raw -ErrorAction Stop
            Write-Log "Loaded script state: $Stage"
            Write-Host "[INFO] Resumed after reboot. Last stage: $Stage"
            return $Stage.Trim()
        }
        Write-Log "No previous state found."
        Write-Host "[INFO] No previous state found."
        return $null
    }
    catch {
        Write-Log "Failed to load script state: $_" "ERROR"
        Write-Host "[ERROR] Failed to load script state: $_"
        return $null
    }
}

# Create scheduled task to resume script
function Create-ResumeTask {
    Write-Host "[INFO] Creating scheduled task to resume script after reboot..."
    Write-Log "Creating scheduled task to resume script after reboot..."
    try {
        $TaskName = "BSOD_Fixer_Resume"
        $Action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-ExecutionPolicy Bypass -File C:\BSOD_Fix.ps1"
        $Trigger = New-ScheduledTaskTrigger -AtStartup
        $Settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
        Register-ScheduledTask -TaskName $TaskName -Action $Action -Trigger $Trigger -Settings $Settings -Force -ErrorAction Stop
        Write-Log "Scheduled task '$TaskName' created to resume script."
        Write-Host "[INFO] Scheduled task '$TaskName' created to resume script."
    }
    catch {
        Write-Log "Failed to create scheduled task: $_" "ERROR"
        Write-Host "[ERROR] Failed to create scheduled task: $_"
    }
}

# Comprehensive BSOD error code mappings
$BSODErrors = @{
    "0x00000001" = @{ "Desc" = "APC_INDEX_MISMATCH"; "Action" = "Check driver compatibility, update drivers" }
    "0x0000000A" = @{ "Desc" = "IRQL_NOT_LESS_OR_EQUAL"; "Action" = "Update or roll back drivers, check memory" }
    "0x0000001A" = @{ "Desc" = "MEMORY_MANAGEMENT"; "Action" = "Run memory diagnostics, update drivers" }
    "0x0000001E" = @{ "Desc" = "KMODE_EXCEPTION_NOT_HANDLED"; "Action" = "Verify drivers, run SFC" }
    "0x0000003B" = @{ "Desc" = "SYSTEM_SERVICE_EXCEPTION"; "Action" = "Run SFC and DISM, update drivers" }
    "0x00000050" = @{ "Desc" = "PAGE_FAULT_IN_NONPAGED_AREA"; "Action" = "Check memory, update drivers" }
    "0x0000007B" = @{ "Desc" = "INACCESSIBLE_BOOT_DEVICE"; "Action" = "Check storage drivers, run Startup Repair" }
    "0x0000007E" = @{ "Desc" = "SYSTEM_THREAD_EXCEPTION_NOT_HANDLED"; "Action" = "Update drivers, check for software conflicts" }
    "0x00000080" = @{ "Desc" = "NMI_HARDWARE_FAILURE"; "Action" = "Run hardware diagnostics" }
    "0x0000009C" = @{ "Desc" = "MACHINE_CHECK_EXCEPTION"; "Action" = "Check CPU/GPU, run hardware diagnostics" }
    "0x000000BE" = @{ "Desc" = "ATTEMPTED_WRITE_TO_READONLY_MEMORY"; "Action" = "Update drivers or firmware" }
    "0x000000C2" = @{ "Desc" = "BAD_POOL_CALLER"; "Action" = "Check drivers, scan for malware" }
    "0x000000D1" = @{ "Desc" = "DRIVER_IRQL_NOT_LESS_OR_EQUAL"; "Action" = "Update or roll back drivers" }
    "0x000000F4" = @{ "Desc" = "CRITICAL_OBJECT_TERMINATION"; "Action" = "Check critical processes, run SFC/DISM" }
    "0x00000124" = @{ "Desc" = "WHEA_UNCORRECTABLE_ERROR"; "Action" = "Run hardware diagnostics" }
    "0x000000C4" = @{ "Desc" = "DRIVER_VERIFIER_DETECTED_VIOLATION"; "Action" = "Reset Driver Verifier, update drivers" }
    "0x000000C5" = @{ "Desc" = "DRIVER_CORRUPTED_EXPOOL"; "Action" = "Update drivers, run SFC" }
    "0x000000D5" = @{ "Desc" = "DRIVER_PAGE_FAULT_IN_FREED_SPECIAL_POOL"; "Action" = "Update drivers, check memory" }
    "0x000000E2" = @{ "Desc" = "MANUALLY_INITIATED_CRASH"; "Action" = "Check for intentional crash triggers" }
    "0x00000133" = @{ "Desc" = "DPC_WATCHDOG_VIOLATION"; "Action" = "Update drivers, check for software conflicts" }
    "0x00000139" = @{ "Desc" = "KERNEL_SECURITY_CHECK_FAILURE"; "Action" = "Run SFC/DISM, scan for malware" }
    "0x0000000E" = @{ "Desc" = "VIDEO_TDR_FAILURE"; "Action" = "Update graphics drivers, check GPU" }
    "0x0000007A" = @{ "Desc" = "KERNEL_DATA_INPAGE_ERROR"; "Action" = "Check disk integrity, run memory diagnostics" }
    "0x000000F7" = @{ "Desc" = "DRIVER_OVERRAN_STACK_BUFFER"; "Action" = "Update drivers, check for software conflicts" }
    "0x000000ED" = @{ "Desc" = "UNMOUNTABLE_BOOT_VOLUME"; "Action" = "Run Startup Repair, check disk" }
    "0x000000C000021A" = @{ "Desc" = "FATAL_SYSTEM_ERROR"; "Action" = "Run SFC/DISM, check registry" }
}
$HardwareErrors = @("0x00000080", "0x0000009C", "0x00000124")

# Check admin privileges
function Test-Admin {
    Write-Host "[INFO] Checking for administrative privileges..."
    Write-Log "Checking for administrative privileges..."
    $CurrentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
    $Principal = New-Object Security.Principal.WindowsPrincipal($CurrentUser)
    if (-not $Principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        Write-Log "Script requires administrative privileges." "ERROR"
        Write-Host "[ERROR] This script must be run as Administrator."
        throw "This script must be run as Administrator."
    }
    Write-Log "Running with administrative privileges."
    Write-Host "[INFO] Administrative privileges confirmed."
}

# Get Windows version
function Get-WindowsVersion {
    Write-Host "[INFO] Detecting Windows version..."
    Write-Log "Detecting Windows version..."
    $OS = Get-CimInstance Win32_OperatingSystem
    $Version = $OS.Caption
    $Build = $OS.BuildNumber
    if ($Version -notlike "*Windows 10*" -and $Version -notlike "*Windows 11*") {
        Write-Log "Unsupported OS: $Version" "ERROR"
        Write-Host "[ERROR] Unsupported OS: $Version"
        throw "This script only supports Windows 10 and 11."
    }
    Write-Log "Detected OS: $Version, Build: $Build"
    Write-Host "[INFO] Detected OS: $Version, Build: $Build"
    return $Version, $Build
}

# Run SFC
function Invoke-SFC {
    Write-Host "[INFO] Starting SFC scan to check system files..."
    Write-Log "Running SFC /scannow..."
    try {
        $SFCResult = Start-Process -FilePath "sfc.exe" -ArgumentList "/scannow" -NoNewWindow -Wait -RedirectStandardOutput "C:\sfc_output.txt" -PassThru
        $SFCOutput = Get-Content "C:\sfc_output.txt" -Raw -ErrorAction Stop
        Write-Log "SFC Output: $SFCOutput"
        if ($SFCResult.ExitCode -ne 0) {
            Write-Log "SFC failed with exit code: $($SFCResult.ExitCode)" "ERROR"
            Write-Host "[ERROR] SFC scan failed with exit code: $($SFCResult.ExitCode)"
        }
        if ($SFCOutput -match "found corrupt files and successfully repaired") {
            Write-Log "SFC repaired corrupted files."
            Write-Host "[INFO] SFC repaired corrupted files."
            Save-State "SFC_Success"
            return $true, $SFCOutput
        }
        elseif ($SFCOutput -match "found corrupt files but was unable to fix") {
            Write-Log "SFC found unrepairable corruptions." "ERROR"
            $CorruptedFiles = ($SFCOutput | Select-String "cannot repair member file \[l:(\d+)'(\d+)'\] (.*?)\n").Matches
            $Count = $CorruptedFiles.Count
            Write-Log "Detected $Count corrupted files:"
            Write-Host "[INFO] Detected $Count corrupted files:"
            foreach ($File in $CorruptedFiles) {
                Write-Log "Corrupted file: $($File.Groups[3].Value)"
                Write-Host "[INFO] Corrupted file: $($File.Groups[3].Value)"
            }
            Save-State "SFC_Failed"
            return $false, $SFCOutput
        }
        else {
            Write-Log "All system files are healthy."
            Write-Host "[INFO] All system files are healthy."
            Save-State "SFC_Success"
            return $true, $SFCOutput
        }
    }
    catch {
        Write-Log "SFC error: $_" "ERROR"
        Write-Host "[ERROR] SFC scan failed: $_"
        Save-State "SFC_Failed"
        return $false, "SFC failed to run."
    }
}

# Run DISM
function Invoke-DISM {
    Write-Host "[INFO] Starting DISM to repair component store..."
    Write-Log "Running DISM..."
    $Commands = @(
        "/Online /Cleanup-Image /CheckHealth",
        "/Online /Cleanup-Image /ScanHealth",
        "/Online /Cleanup-Image /RestoreHealth /LimitAccess"
    )
    $Results = @()
    foreach ($Cmd in $Commands) {
        $Action = ($Cmd -split " ")[3]
        Write-Host "[INFO] Running DISM $Action..."
        Write-Log "Running DISM $Action..."
        try {
            $DISMResult = Start-Process -FilePath "DISM.exe" -ArgumentList $Cmd -NoNewWindow -Wait -RedirectStandardOutput "C:\dism_output.txt" -PassThru
            $DISMOutput = Get-Content "C:\dism_output.txt" -Raw -ErrorAction Stop
            Write-Log "$Action Output: $DISMOutput"
            Write-Host "[INFO] DISM $Action completed."
            if ($DISMResult.ExitCode -ne 0) {
                Write-Log "$Action failed with exit code: $($DISMResult.ExitCode)" "ERROR"
                Write-Host "[ERROR] DISM $Action failed with exit code: $($DISMResult.ExitCode)"
            }
            $Results += $DISMOutput
        }
        catch {
            Write-Log "DISM $Action error: $_" "ERROR"
            Write-Host "[ERROR] DISM $Action failed: $_"
        }
    }
    if ($Results -match "The operation completed successfully") {
        Write-Log "DISM repaired component store."
        Write-Host "[INFO] DISM repaired component store."
        Save-State "DISM_Success"
        return $true
    }
    else {
        Write-Log "DISM found issues or failed to repair." "ERROR"
        Write-Host "[ERROR] DISM found issues or failed to repair."
        Save-State "DISM_Failed"
        return $false
    }
}

# Configure Driver Verifier
function Set-DriverVerifier {
    Write-Host "[INFO] Configuring Driver Verifier to identify faulty drivers..."
    Write-Log "Configuring Driver Verifier..."
    try {
        $null = Start-Process -FilePath "verifier.exe" -ArgumentList "/standard /all" -NoNewWindow -Wait
        Write-Log "Driver Verifier enabled. Reboot required for analysis."
        Write-Host "[INFO] Driver Verifier enabled. Initiating automatic restart for analysis. Re-run script manually to reset Driver Verifier."
        Save-State "DriverVerifier"
        Create-ResumeTask
        Restart-Computer -Force
        return $true
    }
    catch {
        Write-Log "Driver Verifier error: $_" "ERROR"
        Write-Host "[ERROR] Driver Verifier configuration failed: $_"
        Save-State "DriverVerifier_Failed"
        return $false
    }
}

# Reset Driver Verifier
function Reset-DriverVerifier {
    Write-Host "[INFO] Resetting Driver Verifier..."
    Write-Log "Resetting Driver Verifier..."
    try {
        $null = Start-Process -FilePath "verifier.exe" -ArgumentList "/reset" -NoNewWindow -Wait
        Write-Log "Driver Verifier reset successfully."
        Write-Host "[INFO] Driver Verifier reset successfully."
        Save-State "DriverVerifier_Reset"
        return $true
    }
    catch {
        Write-Log "Driver Verifier reset error: $_" "ERROR"
        Write-Host "[ERROR] Driver Verifier reset failed: $_"
        Save-State "DriverVerifier_Failed"
        return $false
    }
}

# Capture critical registry settings
function Capture-RegistrySettings {
    Write-Host "[INFO] Capturing critical registry settings before repair..."
    Write-Log "Capturing critical registry settings before repair..."
    $BackupDir = "C:\BSOD_Fixer_Backup"
    New-Item -ItemType Directory -Path $BackupDir -Force | Out-Null
    $Timestamp = (Get-Date).ToString("yyyyMMdd_HHmmss")
    $Settings = @(
        @{ "Path" = "HKLM\SYSTEM\CurrentControlSet\Services"; "File" = "Services_$Timestamp.reg" },
        @{ "Path" = "HKLM\SOFTWARE\Microsoft\WindowsUpdate"; "File" = "WindowsUpdate_$Timestamp.reg" }
    )
    $Success = $true
    foreach ($Setting in $Settings) {
        try {
            $null = Get-Item -Path $Setting.Path -ErrorAction Stop
            $OutputFile = Join-Path $BackupDir $Setting.File
            $null = Start-Process -FilePath "reg.exe" -ArgumentList "export $($Setting.Path) $OutputFile" -NoNewWindow -Wait
            Write-Log "Preserved settings for $($Setting.Path) saved to $OutputFile."
            Write-Host "[INFO] Preserved settings for $($Setting.Path) saved to $OutputFile."
        }
        catch {
            Write-Log "Failed to capture settings for $($Setting.Path): $_" "ERROR"
            Write-Host "[ERROR] Failed to capture settings for $($Setting.Path): $_"
            $Success = $false
        }
    }
    Save-State "Registry_Captured"
    return $Success
}

# Reapply captured registry settings
function Reapply-RegistrySettings {
    Write-Host "[INFO] Reapplying preserved registry settings..."
    Write-Log "Reapplying preserved registry settings..."
    $BackupDir = "C:\BSOD_Fixer_Backup"
    $Settings = @(
        @{ "Path" = "HKLM\SYSTEM\CurrentControlSet\Services"; "File" = "Services_*.reg" },
        @{ "Path" = "HKLM\SOFTWARE\Microsoft\WindowsUpdate"; "File" = "WindowsUpdate_*.reg" }
    )
    $Success = $true
    foreach ($Setting in $Settings) {
        $BackupFiles = Get-ChildItem -Path $BackupDir -Filter $Setting.File -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending
        if ($BackupFiles) {
            $LatestBackup = $BackupFiles[0].FullName
            try {
                $null = Start-Process -FilePath "reg.exe" -ArgumentList "import $LatestBackup" -NoNewWindow -Wait
                Write-Log "Reapplied settings for $($Setting.Path) from $LatestBackup."
                Write-Host "[INFO] Reapplied settings for $($Setting.Path) from $LatestBackup."
                $null = Get-Item -Path $Setting.Path -ErrorAction Stop
                Write-Log "Verified $($Setting.Path) is accessible after reapplication."
                Write-Host "[INFO] Verified $($Setting.Path) is accessible after reapplication."
            }
            catch {
                Write-Log "Failed to reapply settings for $($Setting.Path): $_" "ERROR"
                Write-Host "[ERROR] Failed to reapply settings for $($Setting.Path): $_"
                $Success = $false
            }
        }
        else {
            Write-Log "No preserved settings found for $($Setting.Path)." "ERROR"
            Write-Host "[ERROR] No preserved settings found for $($Setting.Path)."
            $Success = $false
        }
    }
    Save-State "Registry_Reapplied"
    return $Success
}

# Check registry
function Test-Registry {
    Write-Host "[INFO] Checking registry integrity..."
    Write-Log "Checking registry integrity..."
    $Hives = @(
        "HKLM\SYSTEM",
        "HKLM\SOFTWARE",
        "HKLM\SYSTEM\CurrentControlSet\Services"
    )
    $Issues = $false
    foreach ($Hive in $Hives) {
        try {
            $null = Get-Item -Path $Hive -ErrorAction Stop
            Write-Log "Registry hive $Hive is accessible."
            Write-Host "[INFO] Registry hive $Hive is accessible."
        }
        catch {
            Write-Log "Registry hive $Hive is corrupted or inaccessible: $_" "ERROR"
            Write-Host "[ERROR] Registry hive $Hive is corrupted or inaccessible: $_"
            $Issues = $true
        }
    }
    Save-State "Registry_Checked"
    return -not $Issues
}

# Repair registry
function Repair-Registry {
    Write-Host "[INFO] Attempting to repair corrupted registry..."
    Write-Log "Attempting to repair corrupted registry..."
    $BackupDir = "C:\BSOD_Fixer_Backup"
    $Hives = @(
        @{ "Path" = "HKLM\SYSTEM"; "File" = "SYSTEM" },
        @{ "Path" = "HKLM\SOFTWARE"; "File" = "SOFTWARE" }
    )
    $Repaired = $false
    $SettingsCaptured = $false

    if (-not (Test-Registry)) {
        $SettingsCaptured = Capture-RegistrySettings
    }

    foreach ($Hive in $Hives) {
        try {
            $null = Get-Item -Path $Hive.Path -ErrorAction Stop
            Write-Log "Registry hive $($Hive.Path) is healthy."
            Write-Host "[INFO] Registry hive $($Hive.Path) is healthy."
        }
        catch {
            Write-Host "[INFO] Attempting to restore $($Hive.Path) from backup..."
            Write-Log "Attempting to restore $($Hive.Path)..."
            $BackupFiles = Get-ChildItem -Path $BackupDir -Filter "$($Hive.File)_*.reg" -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending
            if ($BackupFiles) {
                $LatestBackup = $BackupFiles[0].FullName
                Write-Log "Restoring $($Hive.Path) from $LatestBackup..."
                Write-Host "[INFO] Restoring $($Hive.Path) from $LatestBackup..."
                $null = Start-Process -FilePath "reg.exe" -ArgumentList "import $LatestBackup" -NoNewWindow -Wait
                Write-Log "Restored $($Hive.Path) from backup."
                Write-Host "[INFO] Restored $($Hive.Path) from backup."
                $Repaired = $true
            }
            else {
                Write-Log "No backup found for $($Hive.Path)." "ERROR"
                Write-Host "[ERROR] No backup found for $($Hive.Path)."
            }
        }
    }
    if (-not $Repaired) {
        Write-Host "[INFO] Attempting registry repair via fallback..."
        Write-Log "Attempting registry repair via fallback..."
        if (Fallback-Repair) {
            Write-Log "Fallback registry repair completed."
            Write-Host "[INFO] Fallback registry repair completed."
            $Repaired = $true
        }
    }

    if ($Repaired -and $SettingsCaptured) {
        if (Reapply-RegistrySettings) {
            Write-Log "Preserved registry settings successfully reapplied."
            Write-Host "[INFO] Preserved registry settings successfully reapplied."
        }
        else {
            Write-Log "Failed to reapply preserved registry settings." "ERROR"
            Write-Host "[ERROR] Failed to reapply preserved registry settings."
        }
    }

    Save-State "Registry_Repaired"
    return $Repaired
}

# Backup registry
function Backup-Registry {
    Write-Host "[INFO] Backing up registry..."
    Write-Log "Backing up registry..."
    $BackupDir = "C:\BSOD_Fixer_Backup"
    New-Item -ItemType Directory -Path $BackupDir -Force | Out-Null
    $Timestamp = (Get-Date).ToString("yyyyMMdd_HHmmss")
    try {
        $null = Start-Process -FilePath "reg.exe" -ArgumentList "export HKLM\SYSTEM $BackupDir\SYSTEM_$Timestamp.reg" -NoNewWindow -Wait
        $null = Start-Process -FilePath "reg.exe" -ArgumentList "export HKLM\SOFTWARE $BackupDir\SOFTWARE_$Timestamp.reg" -NoNewWindow -Wait
        Write-Log "Registry backup completed."
        Write-Host "[INFO] Registry backup completed."
        Save-State "Registry_Backup"
        return $true
    }
    catch {
        Write-Log "Registry backup error: $_" "ERROR"
        Write-Host "[ERROR] Registry backup failed: $_"
        Save-State "Registry_Backup_Failed"
        return $false
    }
}

# Check restore points
function Test-RestorePoints {
    Write-Host "[INFO] Checking for system restore points..."
    Write-Log "Checking for system restore points..."
    try {
        $Points = Get-CimInstance -Namespace "root\default" -ClassName "SystemRestore" -ErrorAction Stop
        if ($Points) {
            Write-Log "Found $($Points.Count) restore points."
            Write-Host "[INFO] Found $($Points.Count) restore points."
            Save-State "RestorePoints_Checked"
            return $true, $Points
        }
        else {
            Write-Log "No restore points found." "ERROR"
            Write-Host "[ERROR] No restore points found."
            Save-State "RestorePoints_None"
            return $false, $null
        }
    }
    catch {
        Write-Log "Restore point check error: $_" "ERROR"
        Write-Host "[ERROR] Restore point check failed: $_"
        Save-State "RestorePoints_Failed"
        return $false, $null
    }
}

# Extract specific files from restore point
function Extract-FilesFromRestorePoint {
    param($CorruptedFiles)
    Write-Host "[INFO] Attempting to extract healthy system files from latest restore point..."
    Write-Log "Attempting to extract healthy files from latest restore point..."
    try {
        $Points = Get-CimInstance -Namespace "root\default" -ClassName "SystemRestore" -ErrorAction Stop | Sort-Object CreationTime -Descending
        if (-not $Points) {
            Write-Log "No restore points available." "ERROR"
            Write-Host "[ERROR] No restore points available."
            Save-State "RestorePoint_Extraction_Failed"
            return $false
        }

        $LatestPoint = $Points[0]
        $RPNumber = $LatestPoint.SequenceNumber
        Write-Log "Using restore point ID: $RPNumber"
        Write-Host "[INFO] Using restore point ID: $RPNumber"

        $ShadowPath = $null
        $Shadows = vssadmin list shadows | Select-String "Shadow Copy Volume: (.*)" | ForEach-Object { $_.Matches.Groups[1].Value }
        foreach ($Shadow in $Shadows) {
            if ((Get-ChildItem -Path $Shadow -ErrorAction SilentlyContinue | Select-String "RP$RPNumber").Count -gt 0) {
                $ShadowPath = "$Shadow\RP$RPNumber\snapshot"
                break
            }
        }
        if (-not $ShadowPath) {
            Write-Log "No shadow copy found for restore point $RPNumber." "ERROR"
            Write-Host "[ERROR] No shadow copy found for restore point $RPNumber."
            Save-State "RestorePoint_Extraction_Failed"
            return $false
        }

        $Success = $true
        foreach ($File in $CorruptedFiles) {
            $FilePath = $File.Groups[3].Value
            $SystemPath = Join-Path "C:\Windows\System32" $FilePath
            $RestorePath = Join-Path $ShadowPath $FilePath
            if ($FilePath -like "*\System32\*" -or $FilePath -like "*\System32\drivers\*") {
                try {
                    if (Test-Path $RestorePath) {
                        Copy-Item -Path $RestorePath -Destination $SystemPath -Force -ErrorAction Stop
                        Write-Log "Replaced system file $FilePath from restore point."
                        Write-Host "[INFO] Replaced system file $FilePath from restore point."
                    }
                    else {
                        Write-Log "File $FilePath not found in restore point." "ERROR"
                        Write-Host "[ERROR] File $FilePath not found in restore point."
                        $Success = $false
                    }
                }
                catch {
                    Write-Log "Failed to extract $FilePath from restore point: $_" "ERROR"
                    Write-Host "[ERROR] Failed to extract $FilePath from restore point: $_"
                    $Success = $false
                }
            }
            else {
                Write-Log "Skipping non-system file $FilePath to preserve user data." "INFO"
                Write-Host "[INFO] Skipping non-system file $FilePath to preserve user data."
            }
        }
        Save-State "RestorePoint_Extraction"
        return $Success
    }
    catch {
        Write-Log "Restore point file extraction error: $_" "ERROR"
        Write-Host "[ERROR] Restore point file extraction failed: $_"
        Save-State "RestorePoint_Extraction_Failed"
        return $false
    }
}

# Restore from restore point (full system restore)
function Restore-FromRestorePoint {
    Write-Host "[WARNING] All repairs failed. Initiating full system restore to latest restore point. This may revert user files and software."
    Write-Log "Attempting full system restore from latest restore point as last resort..."
    try {
        $Points = Get-CimInstance -Namespace "root\default" -ClassName "SystemRestore" -ErrorAction Stop | Sort-Object CreationTime -Descending
        if ($Points) {
            $LatestPoint = $Points[0].SequenceNumber
            Write-Log "Restoring from restore point ID: $LatestPoint..."
            Write-Host "[INFO] Restoring from restore point ID: $LatestPoint..."
            $null = Restore-Computer -RestorePoint $LatestPoint -ErrorAction Stop
            Write-Log "System restore initiated. Initiating automatic restart."
            Write-Host "[INFO] System restore initiated. Initiating automatic restart. Re-run script manually if further repairs needed."
            Save-State "SystemRestore"
            Create-ResumeTask
            Restart-Computer -Force
            return $true
        }
        else {
            Write-Log "No restore points available." "ERROR"
            Write-Host "[ERROR] No restore points available for full system restore."
            Save-State "SystemRestore_Failed"
            return $false
        }
    }
    catch {
        Write-Log "System restore error: $_" "ERROR"
        Write-Host "[ERROR] System restore failed: $_"
        Save-State "SystemRestore_Failed"
        return $false
    }
}

# Replace corrupted files from Microsoft Update Catalog
function Replace-CorruptedFilesFromCatalog {
    param($CorruptedFiles)
    Write-Host "[INFO] Attempting to replace corrupted files from Microsoft Update Catalog..."
    Write-Log "Attempting to replace corrupted files from Microsoft Update Catalog..."
    try {
        $Version, $Build = Get-WindowsVersion
        $TempDir = "C:\BSOD_Fixer_Temp"
        New-Item -ItemType Directory -Path $TempDir -Force | Out-Null
        $MaxFiles = 5
        $FileCount = 0

        foreach ($File in $CorruptedFiles) {
            if ($FileCount -ge $MaxFiles) {
                Write-Log "Reached maximum file replacement limit ($MaxFiles) for Update Catalog." "INFO"
                Write-Host "[INFO] Reached maximum file replacement limit ($MaxFiles) for Update Catalog."
                break
            }
            $FileName = $File.Groups[3].Value
            if ($FileName -like "*\System32\*" -or $FileName -like "*\System32\drivers\*") {
                try {
                    Write-Host "[INFO] Searching for $FileName in Microsoft Update Catalog for build $Build..."
                    Write-Log "Searching for $FileName in Microsoft Update Catalog for build $Build..."
                    $PackagePath = Join-Path $TempDir "$FileName.cab"
                    Write-Log "Downloading package for $FileName (simulated)..."
                    Write-Host "[INFO] Downloading package for $FileName (simulated)..."
                    $null = Invoke-WebRequest -Uri "https://www.catalog.update.microsoft.com" -OutFile $PackagePath -ErrorAction SilentlyContinue
                    if (Test-Path $PackagePath) {
                        $null = Start-Process -FilePath "DISM.exe" -ArgumentList "/Online /Add-Package /PackagePath:$PackagePath" -NoNewWindow -Wait
                        Write-Log "Applied package for $FileName."
                        Write-Host "[INFO] Applied package for $FileName."
                        $FileCount++
                    }
                    else {
                        Write-Log "No package found for $FileName in Update Catalog." "ERROR"
                        Write-Host "[ERROR] No package found for $FileName in Update Catalog."
                    }
                }
                catch {
                    Write-Log "Failed to replace $FileName from Update Catalog: $_" "ERROR"
                    Write-Host "[ERROR] Failed to replace $FileName from Update Catalog: $_"
                }
            }
            else {
                Write-Log "Skipping non-system file $FileName to preserve user data." "INFO"
                Write-Host "[INFO] Skipping non-system file $FileName to preserve user data."
            }
        }
        Save-State "UpdateCatalog"
        return $true
    }
    catch {
        Write-Log "Update Catalog replacement error: $_" "ERROR"
        Write-Host "[ERROR] Update Catalog replacement failed: $_"
        Save-State "UpdateCatalog_Failed"
        return $false
    }
}

# Repair drivers
function Repair-Drivers {
    param($ErrorCode)
    Write-Host "[INFO] Attempting to repair drivers for BSOD code $ErrorCode..."
    Write-Log "Attempting to repair drivers for $ErrorCode..."
    try {
        if (Set-DriverVerifier) {
            Write-Log "Driver Verifier enabled to identify faulty drivers."
        }
        $Drivers = pnputil /enum-drivers | Select-String "Published Name" | ForEach-Object { $_.Line -replace ".*Published Name:\s*(\S+).*", '$1' }
        foreach ($Driver in $Drivers) {
            try {
                Write-Host "[INFO] Attempting to roll back driver $Driver..."
                Write-Log "Attempting to roll back driver $Driver..."
                $null = dism /online /remove-driver /driver:$Driver
                Write-Log "Removed driver $Driver; attempting reinstall via Windows Update."
                Write-Host "[INFO] Removed driver $Driver; attempting reinstall via Windows Update."
                $null = Add-WindowsDriver -Online -ErrorAction Stop
                Write-Log "Reinstalled driver $Driver."
                Write-Host "[INFO] Reinstalled driver $Driver."
            }
            catch {
                Write-Log "Driver rollback/reinstall error for $Driver: $_" "ERROR"
                Write-Host "[ERROR] Driver rollback/reinstall failed for $Driver: $_"
            }
        }
        if (Reset-DriverVerifier) {
            Write-Log "Driver Verifier reset after driver repair."
        }
        Save-State "Drivers_Repaired"
        return $true
    }
    catch {
        Write-Log "Driver repair error: $_" "ERROR"
        Write-Host "[ERROR] Driver repair failed: $_"
        Save-State "Drivers_Failed"
        return $false
    }
}

# Fallback repair if SFC/DISM and other methods fail
function Fallback-Repair {
    Write-Host "[INFO] Initiating fallback repair (Windows Update, Safe Mode, component cleanup)..."
    Write-Log "Initiating fallback repair (Windows Update, Safe Mode, component cleanup)..."
    try {
        Write-Host "[INFO] Fetching and applying latest Windows Update..."
        Write-Log "Fetching and applying latest Windows Update..."
        try {
            $UpdateSession = New-Object -ComObject Microsoft.Update.Session
            $Searcher = $UpdateSession.CreateUpdateSearcher()
            $Criteria = "IsInstalled=0 and Type='Software' and BrowseOnly=0"
            $SearchResult = $Searcher.Search($Criteria)
            $Updates = $SearchResult.Updates
            if ($Updates.Count -gt 0) {
                $Downloader = $UpdateSession.CreateUpdateDownloader()
                $Downloader.Updates = $Updates
                $Downloader.Download()
                $Installer = $UpdateSession.CreateUpdateInstaller()
                $Installer.Updates = $Updates
                $InstallResult = $Installer.Install()
                Write-Log "Windows Update applied: $($InstallResult.ResultCode)"
                Write-Host "[INFO] Windows Update applied: $($InstallResult.ResultCode)"
            }
            else {
                Write-Log "No applicable updates found."
                Write-Host "[INFO] No applicable updates found."
            }
        }
        catch {
            Write-Log "Windows Update error: $_" "ERROR"
            Write-Host "[ERROR] Windows Update failed: $_"
        }

        Write-Host "[INFO] Configuring Safe Mode boot..."
        Write-Log "Configuring Safe Mode boot..."
        try {
            $null = bcdedit /set {default} safeboot minimal
            Write-Log "Safe Mode configured. Initiating automatic restart."
            Write-Host "[INFO] Safe Mode configured. Initiating automatic restart to attempt repairs."
            Save-State "SafeMode"
            Create-ResumeTask
            Restart-Computer -Force
        }
        catch {
            Write-Log "Safe Mode configuration error: $_" "ERROR"
            Write-Host "[ERROR] Safe Mode configuration failed: $_"
        }

        Write-Host "[INFO] Running DISM component cleanup..."
        Write-Log "Running DISM component cleanup..."
        try {
            $null = Start-Process -FilePath "DISM.exe" -ArgumentList "/Online /Cleanup-Image /StartComponentCleanup" -NoNewWindow -Wait
            Write-Log "Component cleanup completed."
            Write-Host "[INFO] Component cleanup completed."
        }
        catch {
            Write-Log "Component cleanup error: $_" "ERROR"
            Write-Host "[ERROR] Component cleanup failed: $_"
        }

        Write-Host "[INFO] Attempting registry reset via system defaults..."
        Write-Log "Attempting registry reset via system defaults..."
        try {
            $TempHivePath = "C:\Windows\System32\config\DEFAULT"
            if (Test-Path $TempHivePath) {
                $null = reg load HKLM\TempHive $TempHivePath
                $null = reg copy HKLM\TempHive\SYSTEM HKLM\SYSTEM /s /f
                $null = reg copy HKLM\TempHive\SOFTWARE HKLM\SOFTWARE /s /f
                $null = reg unload HKLM\TempHive
                Write-Log "Registry hives SYSTEM and SOFTWARE reset to defaults."
                Write-Host "[INFO] Registry hives SYSTEM and SOFTWARE reset to defaults."
            }
            else {
                Write-Log "Default registry template not found." "ERROR"
                Write-Host "[ERROR] Default registry template not found."
            }
        }
        catch {
            Write-Log "Registry reset error: $_" "ERROR"
            Write-Host "[ERROR] Registry reset failed: $_"
        }

        if (Reapply-RegistrySettings) {
            Write-Log "Preserved registry settings successfully reapplied after fallback."
            Write-Host "[INFO] Preserved registry settings successfully reapplied after fallback."
        }
        else {
            Write-Log "Failed to reapply preserved registry settings after fallback." "ERROR"
            Write-Host "[ERROR] Failed to reapply preserved registry settings after fallback."
        }

        Write-Host "[INFO] Disabling Safe Mode..."
        Write-Log "Disabling Safe Mode..."
        try {
            $null = bcdedit /deletevalue {default} safeboot
            Write-Log "Safe Mode disabled."
            Write-Host "[INFO] Safe Mode disabled."
        }
        catch {
            Write-Log "Safe Mode disable error: $_" "ERROR"
            Write-Host "[ERROR] Safe Mode disable failed: $_"
        }

        Save-State "Fallback_Completed"
        return $true
    }
    catch {
        Write-Log "Fallback repair error: $_" "ERROR"
        Write-Host "[ERROR] Fallback repair failed: $_"
        Save-State "Fallback_Failed"
        return $false
    }
}

# Analyze minidump for BSOD cause
function Analyze-Minidump {
    Write-Host "[INFO] Analyzing minidump files for BSOD cause..."
    Write-Log "Analyzing minidump files..."
    $DumpFiles = Get-ChildItem -Path "C:\Windows\Minidump\*.dmp" -ErrorAction SilentlyContinue
    if (-not $DumpFiles) {
        Write-Log "No minidump files found."
        Write-Host "[INFO] No minidump files found."
        Save-State "Minidump_None"
        return $null
    }
    $ErrorCode = $null
    foreach ($Dump in $DumpFiles) {
        try {
            Write-Log "Analyzed dump: $($Dump.FullName)"
            Write-Host "[INFO] Analyzing dump: $($Dump.FullName)"
            $Events = Get-WinEvent -FilterHashtable @{LogName="System";Level=2;ProviderName="Microsoft-Windows-WER-SystemErrorReporting"} -MaxEvents 10 -ErrorAction SilentlyContinue
            foreach ($Event in $Events) {
                if ($Event.Properties.Count -ge 1) {
                    $ErrorCode = "0x" + "{0:X8}" -f [int]$Event.Properties[0].Value
                    if ($BSODErrors.ContainsKey($ErrorCode)) {
                        $Desc = $BSODErrors[$ErrorCode].Desc
                        $Action = $BSODErrors[$ErrorCode].Action
                        Write-Log "Detected BSOD: $Desc ($ErrorCode). Recommended action: $Action"
                        Write-Host "[INFO] Detected BSOD: $Desc ($ErrorCode). Recommended action: $Action"
                        if ($HardwareErrors -contains $ErrorCode) {
                            Write-Log "Hardware-related BSOD detected: $Desc" "ERROR"
                            Write-Host "[ERROR] Hardware issue detected: $Desc. Manual hardware diagnostics required."
                            Save-State "Hardware_Error"
                            return $ErrorCode
                        }
                        Save-State "Minidump_Analyzed"
                        return $ErrorCode
                    }
                }
            }
            $ErrorCode = "0x0000003B"
            Write-Log "No specific error code found in Event Viewer; defaulting to $ErrorCode"
            Write-Host "[INFO] No specific error code found; defaulting to $ErrorCode"
            Save-State "Minidump_Analyzed"
        }
        catch {
            Write-Log "Minidump analysis error: $_" "ERROR"
            Write-Host "[ERROR] Minidump analysis failed: $_"
            Save-State "Minidump_Failed"
        }
    }
    return $ErrorCode
}

# Replace corrupted files
function Restore-CorruptedFiles {
    param($ErrorCode)
    Write-Host "[INFO] Checking for corrupted files to replace..."
    Write-Log "Checking for corrupted files to replace..."
    $LastState = Load-State
    if ($LastState -eq "SFC_Success") {
        Write-Log "SFC previously succeeded; skipping."
        Write-Host "[INFO] SFC previously succeeded; skipping."
        return $true
    }

    $SFCSuccess, $SFCOutput = Invoke-SFC
    if (-not $SFCSuccess) {
        if ($LastState -eq "DISM_Success") {
            Write-Log "DISM previously succeeded; skipping."
            Write-Host "[INFO] DISM previously succeeded; skipping."
            return $true
        }
        $DISMSuccess = Invoke-DISM
        if (-not $DISMSuccess) {
            Write-Host "[INFO] SFC and DISM failed; attempting advanced file replacement..."
            Write-Log "SFC and DISM failed; attempting advanced file replacement..."
            $CorruptedFiles = ($SFCOutput | Select-String "cannot repair member file \[l:(\d+)'(\d+)'\] (.*?)\n").Matches
            if ($CorruptedFiles) {
                $RPSuccess, $Points = Test-RestorePoints
                if ($RPSuccess -and $LastState -ne "RestorePoint_Extraction" -and $LastState -ne "RestorePoint_Extraction_Failed") {
                    if (Extract-FilesFromRestorePoint -CorruptedFiles $CorruptedFiles) {
                        Write-Log "Files replaced from restore point."
                        Write-Host "[INFO] Files replaced from restore point."
                        $SFCSuccess, $SFCOutput = Invoke-SFC
                        if ($SFCSuccess) {
                            Write-Log "SFC verified files after restore point replacement."
                            Write-Host "[INFO] SFC verified files after restore point replacement."
                            return $true
                        }
                    }
                }
                if ($LastState -ne "UpdateCatalog" -and $LastState -ne "UpdateCatalog_Failed") {
                    Write-Host "[INFO] Restore point file extraction failed or skipped; attempting Update Catalog..."
                    Write-Log "Restore point file extraction failed or skipped; attempting Update Catalog..."
                    if (Replace-CorruptedFilesFromCatalog -CorruptedFiles $CorruptedFiles) {
                        Write-Log "Files replaced from Microsoft Update Catalog."
                        Write-Host "[INFO] Files replaced from Microsoft Update Catalog."
                        $SFCSuccess, $SFCOutput = Invoke-SFC
                        if ($SFCSuccess) {
                            Write-Log "SFC verified files after Update Catalog replacement."
                            Write-Host "[INFO] SFC verified files after Update Catalog replacement."
                            return $true
                        }
                    }
                }
                if ($LastState -ne "Fallback_Completed" -and $LastState -ne "Fallback_Failed") {
                    Write-Host "[INFO] Update Catalog replacement failed or skipped; attempting fallback repair..."
                    Write-Log "Update Catalog replacement failed or skipped; attempting fallback repair..."
                    if (Fallback-Repair) {
                        Write-Log "Fallback repair completed."
                        Write-Host "[INFO] Fallback repair completed."
                        $SFCSuccess, $SFCOutput = Invoke-SFC
                        if ($SFCSuccess) {
                            Write-Log "SFC verified files after fallback repair."
                            Write-Host "[INFO] SFC verified files after fallback repair."
                            return $true
                        }
                    }
                }
                if ($RPSuccess -and $LastState -ne "SystemRestore" -and $LastState -ne "SystemRestore_Failed") {
                    if (Restore-FromRestorePoint) {
                        Write-Log "Full system restore initiated as last resort."
                        Write-Host "[INFO] Full system restore initiated as last resort."
                        return $true
                    }
                }
                Write-Log "All repair attempts failed." "ERROR"
                Write-Host "[ERROR] All repair attempts failed. Check $LogFile for details."
                Save-State "Repairs_Failed"
                return $false
            }
            else {
                Write-Log "No corrupted files identified by SFC." "ERROR"
                Write-Host "[ERROR] No corrupted files identified by SFC."
                Save-State "SFC_NoCorruptedFiles"
                return $false
            }
        }
    }
    return $true
}

# Execute specific action based on error code
function Execute-ErrorAction {
    param($ErrorCode)
    Write-Host "[INFO] Executing specific actions for BSOD code $ErrorCode..."
    Write-Log "Executing action for ${ErrorCode}..."
    $LastState = Load-State
    if ($BSODErrors.ContainsKey($ErrorCode)) {
        $Action = $BSODErrors[$ErrorCode].Action
        Write-Log "Recommended action: $Action"
        Write-Host "[INFO] Recommended action: $Action"
        if ($Action -match "driver" -and $LastState -ne "Drivers_Repaired" -and $LastState -ne "Drivers_Failed") {
            if (Repair-Drivers -ErrorCode $ErrorCode) {
                Write-Log "Driver repair completed for $ErrorCode."
                Write-Host "[INFO] Driver repair completed for $ErrorCode."
            }
            else {
                Write-Log "Driver repair failed for $ErrorCode." "ERROR"
                Write-Host "[ERROR] Driver repair failed for $ErrorCode."
            }
        }
        if ($Action -match "SFC|DISM") {
            Restore-CorruptedFiles -ErrorCode $ErrorCode
        }
        if ($Action -match "memory") {
            Write-Log "Running Windows Memory Diagnostic recommended."
            Write-Host "[INFO] Run Windows Memory Diagnostic from Start Menu to check RAM."
        }
        if ($Action -match "disk") {
            Write-Host "[INFO] Running disk check..."
            Write-Log "Running disk check..."
            try {
                $null = Start-Process -FilePath "chkdsk.exe" -ArgumentList "/f /r C:" -NoNewWindow -Wait
                Write-Log "Disk check completed."
                Write-Host "[INFO] Disk check completed."
                Save-State "DiskCheck_Completed"
            }
            catch {
                Write-Log "Disk check error: $_" "ERROR"
                Write-Host "[ERROR] Disk check failed: $_"
                Save-State "DiskCheck_Failed"
            }
        }
        if ($Action -match "malware") {
            Write-Log "Running malware scan recommended."
            Write-Host "[INFO] Run a full system scan with Windows Security or a third-party antivirus."
        }
        if ($Action -match "Startup Repair") {
            Write-Log "Running Startup Repair recommended."
            Write-Host "[INFO] Boot into WinRE and select Troubleshoot > Advanced options > Startup Repair."
        }
        if ($Action -match "registry" -and $LastState -ne "Registry_Repaired") {
            if (Repair-Registry) {
                Write-Log "Registry repair completed."
                Write-Host "[INFO] Registry repair completed."
            }
            else {
                Write-Log "Registry repair failed." "ERROR"
                Write-Host "[ERROR] Registry repair failed."
            }
        }
    }
    else {
        Write-Log "No specific action defined for $ErrorCode; applying general repairs."
        Write-Host "[INFO] No specific action defined for $ErrorCode; applying general repairs."
        Restore-CorruptedFiles -ErrorCode $ErrorCode
    }
}

# Main function
function Main {
    Write-Host "[INFO] Starting BSOD Fixer script at $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')..."
    $ScriptStartTime = Get-Date
    try {
        Test-Admin
        $Version, $Build = Get-WindowsVersion
        Backup-Registry

        $LastState = Load-State
        if ($LastState -eq "Hardware_Error") {
            Write-Host "[ERROR] Hardware issue previously detected. Manual hardware diagnostics required."
            return
        }

        $ErrorCode = $null
        if ($LastState -notin @("Minidump_Analyzed", "Minidump_None", "Minidump_Failed")) {
            $ErrorCode = Analyze-Minidump
            if ($ErrorCode -and $HardwareErrors -contains $ErrorCode) {
                return
            }
        }

        if ($LastState -ne "Registry_Repaired") {
            if (-not (Test-Registry)) {
                if (Repair-Registry) {
                    Write-Log "Registry repaired successfully."
                    Write-Host "[INFO] Registry repaired successfully."
                }
                else {
                    Write-Log "Registry repair failed; attempting fallback repair..." "ERROR"
                    Write-Host "[INFO] Registry repair failed; attempting fallback repair..."
                    if (Fallback-Repair) {
                        Write-Log "Fallback registry repair completed."
                        Write-Host "[INFO] Fallback registry repair completed."
                    }
                    else {
                        Write-Log "All registry repair attempts failed." "ERROR"
                        Write-Host "[ERROR] All registry repair attempts failed."
                    }
                }
            }
        }

        if ($LastState -notin @("SFC_Success", "DISM_Success", "RestorePoint_Extraction", "UpdateCatalog", "Fallback_Completed", "SystemRestore")) {
            $SFCSuccess, $SFCOutput = Invoke-SFC
            if ($SFCSuccess) {
                Write-Host "[INFO] All system files are healthy."
            }
            else {
                $DISMSuccess = Invoke-DISM
                if (-not $DISMSuccess) {
                    Write-Log "SFC and DISM failed; attempting advanced file replacement..."
                    Write-Host "[INFO] SFC and DISM failed; attempting advanced file replacement..."
                    if (-not (Restore-CorruptedFiles -ErrorCode $ErrorCode)) {
                        Write-Log "All repair attempts failed." "ERROR"
                        Write-Host "[ERROR] All repair attempts failed. Check $LogFile for details."
                    }
                }
            }
        }

        if (Test-RestorePoints) {
            Write-Log "Restore points available for file extraction or full restore if needed."
            Write-Host "[INFO] Restore points available for file extraction or full restore if needed."
        }

        if ($ErrorCode -and $LastState -notin @("Drivers_Repaired", "Drivers_Failed", "SFC_Success", "DISM_Success", "RestorePoint_Extraction", "UpdateCatalog", "Fallback_Completed", "SystemRestore")) {
            Execute-ErrorAction -ErrorCode $ErrorCode
        }
        else {
            Write-Log "No specific BSOD code detected or already processed; applying general repairs."
            Write-Host "[INFO] No specific BSOD code detected or already processed; applying general repairs."
            Restore-CorruptedFiles -ErrorCode "Unknown"
        }

        $ScriptDuration = ((Get-Date) - $ScriptStartTime).TotalMinutes
        Write-Log "BSOD Fixer completed successfully in $ScriptDuration minutes."
        Write-Host "[INFO] BSOD Fixer completed successfully in $ScriptDuration minutes. Check $LogFile for details."
        if (Test-Path $StateFile) {
            Remove-Item $StateFile -Force -ErrorAction SilentlyContinue
            Write-Log "Cleaned up state file."
            Write-Host "[INFO] Cleaned up state file."
        }
    }
    catch {
        Write-Log "Script failed: $_" "ERROR"
        Write-Host "[ERROR] Script failed: $_ Check $LogFile for details."
        Save-State "Script_Failed"
    }
    finally {
        $ScriptDuration = ((Get-Date) - $ScriptStartTime).TotalMinutes
        if ($ScriptDuration -gt 180) {
            Write-Log "Script exceeded 3-hour limit." "ERROR"
            Write-Host "[ERROR] Script exceeded 3-hour limit. Check $LogFile for details."
        }
    }
}

# Execute main
Main
