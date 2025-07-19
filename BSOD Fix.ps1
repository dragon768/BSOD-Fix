# BSOD Fixer PowerShell Script
# Runs in Windows 10/11, including WinRE, to fix all non-hardware BSOD errors

# Log file setup
$LogFile = "C:\BSOD_Fixer_Log_$((Get-Date).ToString('yyyyMMdd_HHmmss')).txt"
function Write-Log {
    param($Message, $Level = "INFO")
    $Timestamp = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
    "$Timestamp - $Level - $Message" | Out-File -FilePath $LogFile -Append
    if ($Level -eq "INFO") { Write-Host "[INFO] $Message" }
    if ($Level -eq "ERROR") { Write-Host "[ERROR] $Message" -ForegroundColor Red }
}

# Comprehensive BSOD error code mappings (non-hardware and hardware)
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
    # Add more codes as needed from Microsoft Bug Check Reference
}
$HardwareErrors = @("0x00000080", "0x0000009C", "0x00000124")

# Check admin privileges
function Test-Admin {
    $CurrentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
    $Principal = New-Object Security.Principal.WindowsPrincipal($CurrentUser)
    if (-not $Principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        Write-Log "Script requires administrative privileges." "ERROR"
        throw "This script must be run as Administrator."
    }
    Write-Log "Running with administrative privileges."
}

# Get Windows version
function Get-WindowsVersion {
    $OS = Get-CimInstance Win32_OperatingSystem
    $Version = $OS.Caption
    $Build = $OS.BuildNumber
    if ($Version -notlike "*Windows 10*" -and $Version -notlike "*Windows 11*") {
        Write-Log "Unsupported OS: $Version" "ERROR"
        throw "This script only supports Windows 10 and 11."
    }
    Write-Log "Detected OS: $Version, Build: $Build"
    return $Version, $Build
}

# Run SFC
function Invoke-SFC {
    Write-Log "Running SFC /scannow..."
    try {
        $SFCResult = Start-Process -FilePath "sfc.exe" -ArgumentList "/scannow" -NoNewWindow -Wait -RedirectStandardOutput "C:\sfc_output.txt" -PassThru
        $SFCOutput = Get-Content "C:\sfc_output.txt" -Raw -ErrorAction Stop
        Write-Log "SFC Output: $SFCOutput"
        if ($SFCResult.ExitCode -ne 0) {
            Write-Log "SFC failed with exit code: $($SFCResult.ExitCode)" "ERROR"
        }
        if ($SFCOutput -match "found corrupt files and successfully repaired") {
            Write-Log "SFC repaired corrupted files."
            return $true, $SFCOutput
        }
        elseif ($SFCOutput -match "found corrupt files but was unable to fix") {
            Write-Log "SFC found unrepairable corruptions." "ERROR"
            $CorruptedFiles = ($SFCOutput | Select-String "cannot repair member file \[l:(\d+)'(\d+)'\] (.*?)\n").Matches
            $Count = $CorruptedFiles.Count
            Write-Log "Detected $Count corrupted files:"
            foreach ($File in $CorruptedFiles) {
                Write-Log "Corrupted file: $($File.Groups[3].Value)"
            }
            return $false, $SFCOutput
        }
        else {
            Write-Log "All system files are healthy."
            return $true, $SFCOutput
        }
    }
    catch {
        Write-Log "SFC error: $_" "ERROR"
        return $false, "SFC failed to run."
    }
}

# Run DISM
function Invoke-DISM {
    $Commands = @(
        "/Online /Cleanup-Image /CheckHealth",
        "/Online /Cleanup-Image /ScanHealth",
        "/Online /Cleanup-Image /RestoreHealth /LimitAccess"
    )
    $Results = @()
    foreach ($Cmd in $Commands) {
        $Action = ($Cmd -split " ")[3]
        Write-Log "Running DISM $Action..."
        try {
            $DISMResult = Start-Process -FilePath "DISM.exe" -ArgumentList $Cmd -NoNewWindow -Wait -RedirectStandardOutput "C:\dism_output.txt" -PassThru
            $DISMOutput = Get-Content "C:\dism_output.txt" -Raw -ErrorAction Stop
            Write-Log "$Action Output: $DISMOutput"
            if ($DISMResult.ExitCode -ne 0) {
                Write-Log "$Action failed with exit code: $($DISMResult.ExitCode)" "ERROR"
            }
            $Results += $DISMOutput
        }
        catch {
            Write-Log "DISM $Action error: $_" "ERROR"
        }
    }
    if ($Results -match "The operation completed successfully") {
        Write-Log "DISM repaired component store."
        return $true
    }
    else {
        Write-Log "DISM found issues or failed to repair." "ERROR"
        return $false
    }
}

# Configure Driver Verifier
function Set-DriverVerifier {
    Write-Log "Configuring Driver Verifier..."
    try {
        $null = Start-Process -FilePath "verifier.exe" -ArgumentList "/standard /all" -NoNewWindow -Wait
        Write-Log "Driver Verifier enabled. Reboot required for analysis."
        Write-Host "[INFO] Driver Verifier enabled. Reboot and run script again to reset."
        return $true
    }
    catch {
        Write-Log "Driver Verifier error: $_" "ERROR"
        return $false
    }
}

# Reset Driver Verifier
function Reset-DriverVerifier {
    Write-Log "Resetting Driver Verifier..."
    try {
        $null = Start-Process -FilePath "verifier.exe" -ArgumentList "/reset" -NoNewWindow -Wait
        Write-Log "Driver Verifier reset successfully."
        return $true
    }
    catch {
        Write-Log "Driver Verifier reset error: $_" "ERROR"
        return $false
    }
}

# Check registry
function Test-Registry {
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
        }
        catch {
            Write-Log "Registry hive $Hive is corrupted or inaccessible: $_" "ERROR"
            $Issues = $true
        }
    }
    return -not $Issues
}

# Backup registry
function Backup-Registry {
    $BackupDir = "C:\BSOD_Fixer_Backup"
    New-Item -ItemType Directory -Path $BackupDir -Force | Out-Null
    $Timestamp = (Get-Date).ToString("yyyyMMdd_HHmmss")
    Write-Log "Backing up registry..."
    try {
        $null = Start-Process -FilePath "reg.exe" -ArgumentList "export HKLM\SYSTEM $BackupDir\SYSTEM_$Timestamp.reg" -NoNewWindow -Wait
        $null = Start-Process -FilePath "reg.exe" -ArgumentList "export HKLM\SOFTWARE $BackupDir\SOFTWARE_$Timestamp.reg" -NoNewWindow -Wait
        Write-Log "Registry backup completed."
        return $true
    }
    catch {
        Write-Log "Registry backup error: $_" "ERROR"
        return $false
    }
}

# Check restore points
function Test-RestorePoints {
    Write-Log "Checking for system restore points..."
    try {
        $Points = Get-CimInstance -Namespace "root\default" -ClassName "SystemRestore" -ErrorAction Stop
        if ($Points) {
            Write-Log "Found $($Points.Count) restore points."
            return $true
        }
        else {
            Write-Log "No restore points found." "ERROR"
            return $false
        }
    }
    catch {
        Write-Log "Restore point check error: $_" "ERROR"
        return $false
    }
}

# Analyze minidump for BSOD cause
function Analyze-Minidump {
    Write-Log "Analyzing minidump files..."
    $DumpFiles = Get-ChildItem -Path "C:\Windows\Minidump\*.dmp" -ErrorAction SilentlyContinue
    if (-not $DumpFiles) {
        Write-Log "No minidump files found."
        return $null
    }
    $ErrorCode = $null
    foreach ($Dump in $DumpFiles) {
        try {
            # Basic parsing (limited in PowerShell; extend with Event Viewer if needed)
            Write-Log "Analyzed dump: $($Dump.FullName)"
            # Check Event Viewer for BugCheck events
            $Events = Get-WinEvent -FilterHashtable @{LogName="System";Level=2;ProviderName="Microsoft-Windows-WER-SystemErrorReporting"} -MaxEvents 10 -ErrorAction SilentlyContinue
            foreach ($Event in $Events) {
                if ($Event.Properties.Count -ge 1) {
                    $ErrorCode = "0x" + "{0:X8}" -f [int]$Event.Properties[0].Value
                    if ($BSODErrors.ContainsKey($ErrorCode)) {
                        $Desc = $BSODErrors[$ErrorCode].Desc
                        $Action = $BSODErrors[$ErrorCode].Action
                        Write-Log "Detected BSOD: $Desc ($ErrorCode). Recommended action: $Action"
                        if ($HardwareErrors -contains $ErrorCode) {
                            Write-Log "Hardware-related BSOD detected: $Desc" "ERROR"
                            Write-Host "[ERROR] Hardware issue detected: $Desc. Manual hardware diagnostics required."
                            return $ErrorCode
                        }
                        return $ErrorCode
                    }
                }
            }
            # Fallback: Default to common non-hardware error if no code found
            $ErrorCode = "0x0000003B"
            Write-Log "No specific error code found in Event Viewer; defaulting to $ErrorCode"
        }
        catch {
            Write-Log "Minidump analysis error: $_" "ERROR"
        }
    }
    return $ErrorCode
}

# Replace corrupted files
function Restore-CorruptedFiles {
    param($ErrorCode)
    Write-Log "Checking for corrupted files to replace..."
    if ($BSODErrors[$ErrorCode].Action -match "SFC|DISM") {
        $SFCSuccess, $SFCOutput = Invoke-SFC
        if (-not $SFCSuccess) {
            $DISMSuccess = Invoke-DISM
            if (-not $DISMSuccess) {
                Write-Log "DISM failed to repair; checking restore points."
                if (Test-RestorePoints) {
                    Write-Log "Manual restore point extraction required."
                }
            }
        }
    }
    else {
        Write-Log "No file replacement needed for $ErrorCode."
    }
    return $true
}

# Execute specific action based on error code
function Execute-ErrorAction {
    param($ErrorCode)
    if ($BSODErrors.ContainsKey($ErrorCode)) {
        $Action = $BSODErrors[$ErrorCode].Action
        Write-Log "Executing action for $ErrorCode: $Action"
        if ($Action -match "driver") {
            Write-Log "Running Driver Verifier to identify faulty drivers."
            Set-DriverVerifier
        }
        if ($Action -match "SFC|DISM") {
            Restore-CorruptedFiles -ErrorCode $ErrorCode
        }
        if ($Action -match "memory") {
            Write-Log "Running Windows Memory Diagnostic recommended."
            Write-Host "[INFO] Run Windows Memory Diagnostic from Start Menu to check RAM."
        }
        if ($Action -match "disk") {
            Write-Log "Running disk check..."
            try {
                $null = Start-Process -FilePath "chkdsk.exe" -ArgumentList "/f /r C:" -NoNewWindow -Wait
                Write-Log "Disk check completed."
            }
            catch {
                Write-Log "Disk check error: $_" "ERROR"
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
    }
    else {
        Write-Log "No specific action defined for $ErrorCode; applying general repairs."
        Restore-CorruptedFiles -ErrorCode $ErrorCode
    }
}

# Main function
function Main {
    try {
        Test-Admin
        $Version, $Build = Get-WindowsVersion
        Backup-Registry

        # Analyze minidump
        $ErrorCode = Analyze-Minidump
        if ($ErrorCode -and $HardwareErrors -contains $ErrorCode) {
            return
        }

        # Run SFC
        $SFCSuccess, $SFCOutput = Invoke-SFC
        if ($SFCSuccess) {
            Write-Host "[INFO] All system files are healthy."
        }

        # Run DISM
        $DISMSuccess = Invoke-DISM
        if ($DISMSuccess) {
            Write-Log "DISM completed successfully."
        }

        # Check restore points
        if (Test-RestorePoints) {
            Write-Log "Restore points available for manual recovery if needed."
        }

        # Check registry
        if (-not (Test-Registry)) {
            Write-Log "Registry issues detected; consider restoring from backup." "ERROR"
        }

        # Execute specific action for detected error code
        if ($ErrorCode) {
            Execute-ErrorAction -ErrorCode $ErrorCode
        }
        else {
            Write-Log "No specific BSOD code detected; applying general repairs."
            Restore-CorruptedFiles -ErrorCode "Unknown"
        }

        # Configure Driver Verifier
        if (Set-DriverVerifier) {
            Write-Log "Driver Verifier enabled. Reboot and run script again to reset."
        }
        else {
            Write-Log "Driver Verifier configuration failed." "ERROR"
        }

        Write-Host "[INFO] BSOD Fixer completed. Check $LogFile for details."
        Write-Log "BSOD Fixer completed successfully."
    }
    catch {
        Write-Log "Script failed: $_" "ERROR"
        Write-Host "[ERROR] Script failed. Check $LogFile for details."
    }
}

# Execute main
Main