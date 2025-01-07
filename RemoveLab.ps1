<#
.SYNOPSIS
Cleans up a Hyper-V lab environment by removing specified VMs, their configurations, checkpoints, VHDs, and associated files.

.DESCRIPTION
This script systematically dismantles a Hyper-V lab setup by:
- Checking if specified VMs exist
- Shutting down running VMs
- Removing VM checkpoints (snapshots)
- Removing VHD files associated with VMs
- Removing VM configurations
- Removing additional VM-related files
- Removing unused virtual switches
- Clearing out VM groups

The script logs all actions and stops execution on critical errors.

.PARAMETER VMDirectory
The path to the directory where VM files are stored. This must be a valid directory path.

.PARAMETER VMNames
An array of VM names to be removed from the lab. Each name should correspond to an existing VM in Hyper-V.

.EXAMPLE
.\RemoveLab.ps1 -VMDirectory "C:\Hyper-V" -VMNames "DC01", "SQL01", "SQL02", "SQL03"

.LINK
[Link to any related documentation or GitHub repo]

.NOTES
File Name      : InitialiseLab.ps1
Author         : <Add the author's name here>
Github         : <Add the author's Github profile here>
Prerequisites  : Hyper-V module, Administrator rightsy.
Warning        : Be cautious as this script performs destructive actions; ensure you have backups.
Logging        : Script logs are written to a file named with a timestamp in the directory as defined by the VMDirectory parameter value.
AI Use         : This script was prepared, largely, by an iterative approach leaning heavily on Grok AI.
#>

#requires -module Hyper-V

param (
    [Parameter(Mandatory=$true)]
    [ValidateScript({Test-Path $_ -PathType Container -IsValid})]
    [string]$VMDirectory = "C:\Hyper-V",

    [Parameter(Mandatory=$true)]
    [string[]]$VMNames = @("DC01", "SQL01", "SQL02", "SQL03")
)

# Validate VMNames
if ($VMNames.Length -eq 0) {
    Write-Log "Error: No VM names specified." -Level "FATAL"
    throw "No VM names were provided in the VMNames parameter."
}

foreach ($VMName in $VMNames) {
    if ([string]::IsNullOrWhiteSpace($VMName)) {
        Write-Log "Error: One or more VM names are invalid or empty." -Level "FATAL"
        throw "Invalid VM name detected in VMNames: '$VMName'."
    }
}

# Generate log file name with datetime stamp
$logFileName = Join-Path -Path $VMDirectory -ChildPath "LabCleanupLog_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt"

# Define the function to write to the log file
function Write-Log {
    param (
        [Parameter(Mandatory=$true)]
        [string]$Message,

        [Parameter(Mandatory=$false)]
        [ValidateSet("INFO", "WARNING", "ERROR", "SUCCESS", "DEBUG", "VERBOSE", "FATAL")]
        [string]$Level = "INFO"
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logMessage = "$timestamp [$Level] $Message"
    
    # Append to the log file
    $logMessage | Out-File -FilePath $logFileName -Append
}

# Warning prompt, before proceeding
if (-not $PSCmdlet.ShouldContinue("This script will remove the specified VM lab setup. Are you sure you want to proceed?", "Warning")) {
    Write-Log "Script execution cancelled by user." -Level "INFO"
    exit
}

# Define the function to check the existence of the required VMs
function CheckVMExistence {
    param (
        [Parameter(Mandatory=$true)]
        [string[]]$VMNames
    )
    Write-Log "Checking if specified VMs exist." -Level "INFO"
    try {
        $existingVMs = Get-VM -Name $VMNames -ErrorAction SilentlyContinue
        if ($existingVMs.Count -ne $VMNames.Count) {
            $missingVMs = $VMNames | Where-Object { $_ -notin $existingVMs.Name }
            Write-Log "Warning: Some VMs do not exist or could not be retrieved: $($missingVMs -join ', ')." -Level "WARNING"
            if ($existingVMs.Count -eq 0) {
                throw "No VMs found matching the specified names."
            }
        }
        return $existingVMs
    } catch {
        Write-Log "Error checking VM existence: $_" -Level "FATAL"
        throw $_  # Re-throw the error to indicate script should stop
    }
}

# Define the list of VMs
$VMs = CheckVMExistence -VMNames $VMNames

# Define the function to shutdown the VMs
function ShutdownVMs {
    param (
        [Parameter(Mandatory=$true)]
        [Microsoft.HyperV.PowerShell.VirtualMachine[]]$VMs
    )
    Write-Log "Shutting down any VMs still running." -Level "INFO"
    try {
        foreach ($VM in $VMs) {
            try {
                if ($VM.State -eq "Running") {
                    Stop-VM -VM $VM -Force -ErrorAction Stop
                    Write-Log "The $($VM.Name) VM has been shut down." -Level "SUCCESS"
                } else {
                    Write-Log "The $($VM.Name) VM is not running, so no action taken." -Level "INFO"
                }
            } catch {
                Write-Log "Failed to shut down the $($VM.Name) VM: $_" -Level "ERROR"
            }
        }
    } catch {
        Write-Log "Error in the ShutdownVMs function. Some or all VMs have not been shut down: $_" -Level "FATAL"
        throw $_  # Stop script if there's a critical error affecting all VMs
    } finally {
        Write-Log "Shutdown process completed." -Level "INFO"
    }
}

# Define the function to remove any checkpoints (snapshots)
function RemoveVMCheckpoints {
    param (
        [Parameter(Mandatory=$true)]
        [Microsoft.HyperV.PowerShell.VirtualMachine[]]$VMs
    )
    Write-Log "Starting VM checkpoint removal process." -Level "INFO"
    try {
        foreach ($VM in $VMs) {
            try {
                $snapshots = Get-VMSnapshot -VM $VM -ErrorAction Stop
                if ($snapshots) {
                    Write-Log "Removing checkpoints for $($VM.Name)." -Level "INFO"
                    $snapshots | Remove-VMSnapshot -IncludeAllChildSnapshots -ErrorAction Stop
                }
            } catch {
                Write-Log "Failed to remove checkpoints for $($VM.Name) VM: $_" -Level "ERROR"
            }
        }
    } catch {
        Write-Log "Error in the RemoveVMCheckpoints function: $_" -Level "FATAL"
        throw $_  # Stop script if there's a critical error affecting all VMs
    } finally {
        Write-Log "VM checkpoint removal process completed." -Level "INFO"
    }
}

# Define the function to delete the VHD files
function DeleteVHDs {
    param (
        [Parameter(Mandatory=$true)]
        [string[]]$VMNames
    )
    Write-Log "Starting VHD removal process." -Level "INFO"
    try {
        foreach ($VMName in $VMNames) {
            try {
                Write-Log "Processing VHDs for VM: $VMName" -Level "INFO"
                
                # Get the paths of VHD files associated with the VM4
                $vhdPaths = Get-VMHardDiskDrive -VMName $VMName -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Path
                
                if ($vhdPaths) {
                    foreach ($vhdPath in $vhdPaths) {
                        if (Test-Path $vhdPath) {
                            Write-Log "Removing VHD file: $vhdPath" -Level "INFO"
                            Remove-Item -Path $vhdPath -Force -ErrorAction Stop
                            Write-Log "Successfully removed VHD file: $vhdPath" -Level "SUCCESS"
                        } else {
                            Write-Log "VHD file not found: $vhdPath" -Level "WARNING"
                        }
                    }
                } else {
                    Write-Log "No VHD files found for $VMName." -Level "WARNING"
                }
            } catch {
                Write-Log "Failed to remove VHD files for $($VMName): $_" -Level "ERROR"
            }
        }
    } catch {
        Write-Log "Error in the RemoveVHDs function: $_" -Level "FATAL"
        throw $_  # Stop script if there's a critical error affecting all VMs
    } finally {
        Write-Log "VHD removal process completed." -Level "INFO"
    }
}

# Define the function to remove the VM configurations
function RemoveVMConfigurations {
    param (
        [Parameter(Mandatory=$true)]
        [Microsoft.HyperV.PowerShell.VirtualMachine[]]$VMs
    )
    Write-Log "Starting VM removal process." -Level "INFO"
    try {
        foreach ($VM in $VMs) {
            try {
                Write-Log "Removing VM configuration for $($VM.Name)." -Level "INFO"
                Remove-VM -VM $VM -Force -ErrorAction Stop
                Write-Log "The $($VM.Name) VM configuration has been removed." -Level "SUCCESS"
            } catch {
                Write-Log "Failed to remove the $($VM.Name) VM: $_" -Level "ERROR"
            }
        }
    } catch {
        Write-Log "Error in the RemoveVMConfigurations function: $_" -Level "FATAL"
        throw $_  # Stop script if there's a critical error affecting all VMs
    } finally {
        Write-Log "VM removal process completed." -Level "INFO"
    }
}

# Define the function to check for any other files that need to be deleted
function RemoveAdditionalVMFiles {
    param (
        [Parameter(Mandatory=$true)]
        [string[]]$VMNames,

        [Parameter(Mandatory=$true)]
        [string]$VMDirectory
    )
    Write-Log "Starting process to remove additional VM files." -Level "INFO"
    try {
        foreach ($VMName in $VMNames) {
            try {
                Write-Log "Processing additional files for VM: $VMName" -Level "INFO"
                
                # Define directories and file patterns to look for
                $vmDirectory = Join-Path -Path $VMDirectory -ChildPath $VMName
                $filePatterns = "*.vhdx", "*.vmcx", "*.vmrs", "*.avhd", "*.avhdx", "*.vsv", "*.xml", "log_*.txt", "Export*"
                
                if (Test-Path $vmDirectory) {
                    foreach ($pattern in $filePatterns) {
                        $files = Get-ChildItem -Path $vmDirectory -Filter $pattern -Recurse -ErrorAction SilentlyContinue
                        if ($files) {
                            foreach ($file in $files) {
                                Write-Log "Removing file: $($file.FullName)" -Level "INFO"
                                Remove-Item -Path $file.FullName -Force -ErrorAction Stop
                                Write-Log "Successfully removed file: $($file.FullName)" -Level "SUCCESS"
                            }
                        } else {
                            Write-Log "No files matching pattern $pattern found for $VMName." -Level "INFO"
                        }
                    }
                } else {
                    Write-Log "Directory for VM $VMName not found." -Level "WARNING"
                }
            } catch {
                Write-Log "Failed to remove additional files for $($VMName): $_" -Level "ERROR"
            }
        }
    } catch {
        Write-Log "Error in the RemoveAdditionalVMFiles function: $_" -Level "FATAL"
        throw $_
    } finally {
        Write-Log "Process to remove additional VM files completed." -Level "INFO"
    }
}

# Define the function to remove the virtual switches
function RemoveVirtualSwitches {
    Write-Log "Checking for unused virtual switches to remove." -Level "INFO"
    try {
        $switches = Get-VMSwitch | Where-Object { $_.SwitchType -eq "External" -and ($_.NetAdapterInterfaceDescription -notmatch "Microsoft Hyper-V Network Adapter") }
        foreach ($switch in $switches) {
            Write-Log "Removing virtual switch: $($switch.Name)" -Level "INFO"
            Remove-VMSwitch -Name $switch.Name -Force -ErrorAction Stop
            Write-Log "Successfully removed virtual switch: $($switch.Name)" -Level "SUCCESS"
        }
    } catch {
        Write-Log "Error removing virtual switch: $_" -Level "FATAL"
        throw $_
    } finally {
        Write-Log "Virtual switch removal process completed." -Level "INFO"
    }
}

# Define the function to check for any VM groups and remove them
function RemoveVMGroups {
    Write-Log "Checking for VM groups to remove." -Level "INFO"
    try {
        $vmGroups = Get-VMGroup -ErrorAction SilentlyContinue
        if ($vmGroups) {
            Write-Log "VM groups found. Removing them." -Level "INFO"
            foreach ($group in $vmGroups) {
                try {
                    # Remove-VMGroup requires the group to be empty, so we'll remove members first
                    $group | Get-VMGroupMember | ForEach-Object {
                        Remove-VMGroupMember -VMGroup $group -VM $_ -Force -ErrorAction Stop
                    }
                    Remove-VMGroup -VMGroup $group -Force -ErrorAction Stop
                    Write-Log "Successfully removed VM group: $($group.Name)" -Level "SUCCESS"
                } catch {
                    Write-Log "Error removing VM group $($group.Name): $_" -Level "ERROR"
                }
            }
        } else {
            Write-Log "No VM groups found to remove." -Level "INFO"
        }
    } catch {
        Write-Log "Error checking for or removing VM groups: $_" -Level "FATAL"
        throw $_
    } finally {
        Write-Log "VM groups removal process completed." -Level "INFO"
    }
}

# Main execution block
try {
    ShutdownVMs -VMs $VMs
    RemoveVMCheckpoints -VMs $VMs
    DeleteVHDs -VMNames $VMNames
    RemoveVMConfigurations -VMs $VMs
    RemoveAdditionalVMFiles -VMNames $VMNames -VMDirectory $VMDirectory
    RemoveVirtualSwitches
    RemoveVMGroups
    Write-Log "Lab cleanup completed successfully." -Level "SUCCESS"
} catch {
    Write-Log "An unexpected error occurred during lab cleanup: $_" -Level "FATAL"
}
