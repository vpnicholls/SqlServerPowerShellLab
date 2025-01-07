<#
.SYNOPSIS
Automates the setup of a Hyper-V lab environment with Domain Controller and SQL Server VMs.

.DESCRIPTION
This script systematically creates a lab environment setup by:
- configuring Hyper-V
- creating VMs
- installing operating systems
- setting up network configurations
- joining VMs to a domain. 
It includes error handling and logging for troubleshooting.

.PARAMETER DomainName
The domain name for the Active Directory forest. This parameter is mandatory.

.PARAMETER SwitchName
The name of the virtual switch to be created or used. This parameter is mandatory.

.PARAMETER VMDirectory
The directory where ISO, *.vhdx, log, and answer files will be saved (in sub-directories, in some cases). This parameter is mandatory.

.PARAMETER DCName
The name of the domain controller to be created. This parameter is mandatory.

.PARAMETER SQLHosts
An array of SQL Server VM names to be created. This parameter is mandatory.

.PARAMETER DCIPAddress
The IP address for the Domain Controller. This parameter is mandatory.

.PARAMETER DCGateway
The gateway IP address for the Domain Controller network. This parameter is mandatory.

.PARAMETER DNSServer
The DNS server IP address for the Domain Controller. This parameter is mandatory.

.PARAMETER SQLIPAddresses
A hashtable mapping SQL VM names to their IP addresses. This parameter is mandatory.

.PARAMETER SubnetMask
The subnet mask for the network. Default is "255.255.255.0".

.PARAMETER VMGeneration
The VM generation number. Default is 1.

.PARAMETER VHDType
The type of VHD to create. Default is "DynamicallyExpanding".

.PARAMETER DCMemory
Memory allocation for the Domain Controller. This parameter is mandatory. Accepts MB or GB.

.PARAMETER DCVHDSize
VHD size for the Domain Controller. This parameter is mandatory. Accepts MB or GB.

.PARAMETER SQLMemory
Memory allocation for SQL Server VMs. This parameter is mandatory. Accepts MB or GB.

.PARAMETER SQLVHDSize
VHD size for SQL Server VMs. This parameter is mandatory. Accepts MB or GB.

.PARAMETER SQLExpectedServices
Services expected to be running on SQL Server VMs after setup. Default is @("WinRM").

.PARAMETER DCExpectedFeatures
Windows features expected on the Domain Controller. Default is @("AD-Domain-Services").

.PARAMETER DCExpectedServices
Services expected to be running on the Domain Controller after setup. Default is @("ADWS", "DNS").

.PARAMETER TestNetworkIP
The IP address to use for network connectivity checks. Default is "8.8.8.8".

.PARAMETER CheckDomainMembership
Flag to check if SQL Servers are in the domain. Default is $true.

.PARAMETER ISOPath
Optional path to an ISO file for OS installation.

.PARAMETER UnattendFilePath
Optional full file path and name for the unattended OS installation file. Default is answer.xml in the $VMDirectory directory.

.PARAMETER GlobalTimeout
Optional timeout setting (in seconds). Default is 300 (5 minutes).

.PARAMETER GlobalMaxRetries
Optional setting for maximum number of retry attempts. Default is 5.

.PARAMETER GlobalRetryInterval
Optional setting for the retry interval (in seconds). Default is 60 (1 minute).

.EXAMPLE
$params = @{
    DomainName = "mylab.local"
    SwitchName = "myLabSwitch"
    VMDirectory = "C:\Hyper-V"
    DCName = "DC01"
    SQLHosts = @("SQL01","SQL02","SQL03")
    DCIPAddress = "192.168.1.10"
    DCGateway = "192.168.1.1"
    DNSServer = "192.168.1.10"
    SQLIPAddresses = @{SQL01="192.168.1.20"; SQL02="192.168.1.21"; SQL03="192.168.1.22"}
    DCMemory = "2GB"
    DCVHDSize = "50GB"
    SQLMemory = "4GB"
    SQLVHDSize = "60GB"
    ISOPath = "C:\Hyper-V\ISOs\SERVER_EVAL_x64FRE_en-us.iso"
    GlobalRetryInterval = 600
}
.\InitialiseLab.ps1 @params

.TESTING
Ensure all VMs are running, joined to the domain, and that network settings are correct by manually checking or using the provided PostInstallationChecks function.

.LINK
https://github.com/vpnicholls

.NOTES
File Name      : InitialiseLab.ps1
Author         : <Add the author's name here>
Prerequisites  : Hyper-V module, Administrator rights, Windows Server ISO, unattend file in VMDirectory.
Logging        : Script logs are written to a file named with a timestamp in the directory as defined by the VMDirectory parameter value.
AI Use         : This script was prepared, largely, by an iterative approach leaning heavily on Grok AI.
#>

#requires -module Hyper-V

param (
    [Parameter(Mandatory=$true)]
    [ValidatePattern("^[a-zA-Z0-9-]+\.[a-zA-Z]{2,}$")]
    [string]$DomainName,

    [Parameter(Mandatory=$true)]
    [ValidatePattern("^[a-zA-Z0-9-]+$")]
    [string]$SwitchName,

    [Parameter(Mandatory=$true)]
    [ValidateScript({Test-Path $_ -PathType Container -IsValid})]
    [string]$VMDirectory,

    [Parameter(Mandatory=$true)]
    [ValidatePattern("^[a-zA-Z0-9-]+$")]
    [string]$DCName,

    [Parameter(Mandatory=$true)]
    [ValidatePattern("^[a-zA-Z0-9-]+$")]
    [string[]]$SQLHosts,

    [Parameter(Mandatory=$true)]
    [ValidatePattern("^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$")]
    [string]$DCIPAddress,

    [Parameter(Mandatory=$true)]
    [ValidatePattern("^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$")]
    [string]$DCGateway,

    [Parameter(Mandatory=$true)]
    [ValidatePattern("^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$")]
    [string]$DNSServer,

    [Parameter(Mandatory=$true)]
    [hashtable]$SQLIPAddresses,

    [Parameter(Mandatory=$false)]
    [ValidatePattern("^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$")]
    [string]$SubnetMask = "255.255.255.0",

    [Parameter(Mandatory=$false)]
    [ValidateSet(1, 2)]
    [int]$VMGeneration = 1,

    [Parameter(Mandatory=$false)]
    [ValidateSet("Fixed","DynamicallyExpanding")]
    [string]$VHDType = "DynamicallyExpanding",

    [Parameter(Mandatory=$true)]
    [ValidatePattern("^\d+\s*(GB|MB)$")]
    [string]$DCMemory,

    [Parameter(Mandatory=$true)]
    [ValidatePattern("^\d+\s*(GB|MB)$")]
    [string]$DCVHDSize,

    [Parameter(Mandatory=$true)]
    [ValidatePattern("^\d+\s*(GB|MB)$")]
    [string]$SQLMemory,

    [Parameter(Mandatory=$true)]
    [ValidatePattern("^\d+\s*(GB|MB)$")]
    [string]$SQLVHDSize,

    [Parameter(Mandatory=$false)]
    [string[]]$SQLExpectedServices = @("WinRM"),

    [Parameter(Mandatory=$false)]
    [string[]]$DCExpectedFeatures = @("AD-Domain-Services"),
    
    [Parameter(Mandatory=$false)]
    [string[]]$DCExpectedServices = @("ADWS", "DNS", "NetLogon", "NTDS", "Kdc", "WinRM", "PlugPlay"),

    [Parameter(Mandatory=$false)]
    [ValidatePattern("^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$")]
    [string]$TestNetworkIP = "8.8.8.8",

    [Parameter(Mandatory=$false)]
    [bool]$CheckDomainMembership = $true,

    [Parameter(Mandatory=$false)]
    [ValidateScript({Test-Path $_ -PathType Leaf})]
    [string]$ISOPath = "",

    [Parameter(Mandatory=$false)]
    [ValidateScript({Test-Path $_ -PathType Leaf})]
    [string]$UnattendFilePath = (Join-Path -Path $VMDirectory -ChildPath "answerfile.xml"),

    [Parameter(Mandatory=$false)]
    [ValidateRange(1, [int]::MaxValue)]
    [int]$GlobalTimeout = 300,  # Default to 5 minutes

    [Parameter(Mandatory=$false)]
    [ValidateRange(1, [int]::MaxValue)]
    [int]$GlobalMaxRetries = 5,

    [Parameter(Mandatory=$false)]
    [ValidateRange(1, [int]::MaxValue)]
    [int]$GlobalRetryInterval = 60  # Default to 1 minute
)

Set-StrictMode -Version Latest

# Generate log file name with datetime stamp
$logFileName = Join-Path -Path $VMDirectory -ChildPath "LabSetupLog_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt"

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

# Define the function to ensure script runs with admin privileges
function EnsureAdminPrivileges {
    [CmdletBinding()]
    param()
    if (-Not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
        Write-Log "Script requires admin privileges. Attempting to restart with elevated privileges." -Level "WARNING"
        $arguments = "& '" + $myinvocation.mycommand.definition + "'"
        Start-Process powershell -Verb runAs -ArgumentList $arguments
        exit
    }
}

# Call this function immediately to ensure admin privileges early
EnsureAdminPrivileges

# Function to get administrator credentials
function GetAdminCredentials {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$false)]
        [string]$DefaultUsername = "administrator"
    )

    try {
        $credential = Get-Credential -UserName $DefaultUsername -Message "Enter the administrator password you'll use for the new VMs." -ErrorAction Stop
        Write-Log "Administrator credentials collected." -Level "INFO"
        return $credential
    } catch {
        Write-Log "Error collecting administrator credentials: $_" -Level "ERROR"
        throw
    }
}

# Define the function to get Domain Controller safe mode password
function GetSafeModePassword {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$false)]
        [int]$MinLength = 8
    )

    try {
        $password = Read-Host "Enter the safe mode administrator password for the Domain Controller." -AsSecureString
        Write-Log "Safe mode password collected." -Level "INFO"
        if ($password.Length -lt $MinLength) { 
            Write-Log "Warning: Safe mode password might be too short. Ensure it meets complexity requirements." -Level "WARNING"
        }
        return $password
    } catch {
        Write-Log "Error collecting safe mode password: $_" -Level "ERROR"
        throw
    }
}

# Define the function to conver GB or MB to B
function ConvertToBytes {
    param (
        [string]$SizeString
    )
    $multiplier = switch -Regex ($SizeString) {
        'GB' { 1GB }
        'MB' { 1MB }
        default { throw "Invalid size unit in $SizeString" }
    }
    return [int]($SizeString -replace '\D') * $multiplier
}

# Define function to clean up sessions
function CleanUpSessions {
    param (
        [string]$VMName
    )
    $sessionsToClean = Get-PSSession | Where-Object { $_.ComputerName -eq $VMName }
    foreach ($session in $sessionsToClean) {
        Write-Log "Cleaning up session for VM: $VMName" -Level "INFO"
        Remove-PSSession -Session $session -ErrorAction SilentlyContinue
    }
}

# Define the function to validate that IP addresses are within the network
function ValidateIPWithinNetwork {
    [CmdletBinding()]
    param (
        [string]$NetworkIP,
        [string]$SubnetMask,
        [string]$IPAddressToCheck
    )

    # Convert IP addresses to integers for comparison
    $networkIPInt = [IPAddress]::Parse($NetworkIP).GetAddressBytes() -join ""
    $ipToCheckInt = [IPAddress]::Parse($IPAddressToCheck).GetAddressBytes() -join ""
    $subnetMaskInt = [IPAddress]::Parse($SubnetMask).GetAddressBytes() -join ""

    # Perform bitwise AND with subnet mask
    $networkStart = $networkIPInt -band $subnetMaskInt
    $ipCheckStart = $ipToCheckInt -band $subnetMaskInt

    return $networkStart -eq $ipCheckStart
}

# Define the function to wait until a new VM is operational
function WaitForVMOperational {
    param (
        [string]$VMName,
        [string[]]$RequiredServices = @("WinRM"),
        [Parameter(Mandatory=$true)]
        [System.Management.Automation.PSCredential]$Credential
    )
    $retries = 0
    while ($retries -lt $GlobalMaxRetries) {
        $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
        while ($true) {
            $percentComplete = ($retries / $GlobalMaxRetries) * 100
            Write-Progress -Activity "Waiting for $VMName to become operational" -Status "Retry attempt $retries of $GlobalMaxRetries" -PercentComplete $percentComplete
            
            if (Test-Connection -ComputerName $VMName -Count 1 -Quiet) {
                try {
                    $session = New-PSSession -VMName $VMName -Credential $Credential -ErrorAction Stop
                    if ($session) {
                        $allServicesRunning = $true
                        foreach ($service in $RequiredServices) {
                            $serviceStatus = Invoke-Command -Session $session -ScriptBlock {
                                Get-Service -Name $using:service | Select-Object -ExpandProperty Status
                            }
                            Write-Log "Checking status of service $service on $VMName. Status: $serviceStatus" -Level "INFO"
                            if ($serviceStatus -ne "Running") {
                                $allServicesRunning = $false
                                break
                            }
                        }
                        if ($allServicesRunning) {
                            Write-Log "VM $VMName is fully operational with all required services running."
                            Remove-PSSession -Session $session
                            Write-Progress -Activity "Waiting for $VMName to become operational" -Completed
                            return $true
                        }
                    }
                } catch {
                    Write-Log "WinRM or other services not yet accessible on $VMName, continuing to wait..." -Level "INFO"
                } finally {
                    CleanUpSessions
                }
            }
            if ($stopwatch.Elapsed.TotalSeconds -ge $GlobalTimeout) {
                Write-Progress -Activity "Waiting for $VMName to become operational" -Completed
                Write-Log "Timeout waiting for $VMName to become fully operational." -Level "ERROR"
                break 
            }
            Start-Sleep -Seconds $GlobalRetryInterval
        }
        $retries++
        Write-Progress -Activity "Waiting for $VMName to become operational" -Status "Retry attempt $retries of $GlobalMaxRetries" -PercentComplete ($retries / $GlobalMaxRetries * 100)
    }
    Write-Progress -Activity "Waiting for $VMName to become operational" -Completed
    Write-Log "Failed to make VM $VMName operational after $GlobalMaxRetries attempts." -Level "ERROR"
    CleanUpSessions
    return $false
}

# Define the function to check and enable Hyper-V if necessary
function EnsureHyperVIsEnabled {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$false)]
        [string[]]$FeatureNames = @("Microsoft-Hyper-V-All"),

        [Parameter(Mandatory=$false)]
        [switch]$RestartIfNeeded = $false
    )

    try {
        foreach ($featureName in $FeatureNames) {
            Write-Log "Checking if $featureName is enabled..."
            $feature = Get-WindowsOptionalFeature -Online -FeatureName $featureName -ErrorAction Stop
            if ($feature.State -ne "Enabled") {
                Write-Log "$featureName is not enabled. Attempting to enable..."
                Enable-WindowsOptionalFeature -Online -FeatureName $featureName -All -NoRestart -ErrorAction Stop
                Write-Log "$featureName has been enabled. Restart might be required for changes to take effect."

                if ($RestartIfNeeded) {
                    Write-Log "Restarting the system to ensure changes take effect..."
                    Restart-Computer -Force
                }
            } else {
                Write-Log "$featureName is already enabled."
            }
        }
    } catch {
        Write-Log "Error occurred in EnsureHyperVIsEnabled function. Failed to check or enable Hyper-V: $_" -Level "ERROR"
        throw
    }
}

# Define the function to create necessary directories
function CreateDirectories {
    [CmdletBinding()]
    param (
        [string]$DirectoryPath
    )

    try {
        if (-not (Test-Path -Path $DirectoryPath -ErrorAction Stop)) {
            New-Item -ItemType Directory -Path $DirectoryPath -ErrorAction Stop
            Write-Log "Directory $DirectoryPath created."
        } else {
            Write-Log "Directory $DirectoryPath already exists."
        }
    } catch {
        Write-Log "An error occurred in the CreateDirectories function. Error creating directory $($DirectoryPath): $_" -Level "ERROR"
        throw
    }
}

# Define the function to handle ISO selection
function GetISOToUse {
    try {
        $ISODirectory = Join-Path -Path $VMDirectory -ChildPath "ISOs"
        if (-not (Test-Path -Path $ISODirectory -ErrorAction Stop)) {
            Write-Log "Creating ISOs directory..."
            New-Item -ItemType Directory -Path $ISODirectory -ErrorAction Stop
        }

        $isos = Get-ChildItem -Path $ISODirectory -Filter "*.iso" -ErrorAction Stop
        if ($isos.Count -eq 0) {
            Write-Log "No ISO file found in $ISODirectory."
            $isoPath = Read-Host "Please move the ISO to $ISODirectory or enter the path to an ISO"
            if (-not (Test-Path $isoPath -ErrorAction Stop)) {
                Write-Log "Invalid path for ISO. Please correct and run the script again." -Level "ERROR"
                exit
            }
            $isoToUse = Get-Item $isoPath -ErrorAction Stop
        } elseif ($isos.Count -eq 1) {
            Write-Log "Found one ISO file in $ISODirectory."
            $isoToUse = $isos[0]
        } else {
            Write-Log "Multiple ISO files found in $ISODirectory. Prompting user to select one."
            $isoToUse = $isos | Out-GridView -Title "Select an ISO file" -PassThru -ErrorAction Stop
        }

        if (-not $isoToUse) {
            Write-Log "No ISO file selected. Exiting script." -Level "ERROR"
            exit
        }
        return $isoToUse
    } catch {
        Write-Log "Error occurred in GetISOToUse function. Error during ISO selection: $_" -Level "ERROR"
        throw
    }
}

# Define the function to mount ISO and start VM for OS installation
function InstallOS {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [string]$VMName,
        
        [Parameter(Mandatory=$true)]
        [ValidateScript({Test-Path $_ -PathType Leaf})]
        [string]$ISOPath,
        
        [Parameter(Mandatory=$true)]
        [ValidateScript({Test-Path $_ -PathType Leaf})]
        [string]$UnattendFilePath,
        
        [Parameter(Mandatory=$true)]
        [System.Management.Automation.PSCredential]$Credential
    )
    try {
        Write-Log "Mounting ISO $ISOPath to VM $VMName..." -Level "INFO"

        # Remove any existing ISO mounts
        $existingDrives = Get-VMDvdDrive -VMName $VMName
        foreach ($drive in $existingDrives) {
            if ($drive.Path) {
                Write-Log "Removing existing ISO mount from $VMName..." -Level "INFO"
                Set-VMDvdDrive -VMName $VMName -ControllerNumber $drive.ControllerNumber -ControllerLocation $drive.ControllerLocation -Path $null -ErrorAction SilentlyContinue
            }
        }

        # Now mount the ISO
        $isoMountPath = Get-VMDvdDrive -VMName $VMName | Where-Object { -not $_.Path } | Select-Object -First 1 -ErrorAction Stop
        if ($isoMountPath) {
            Write-Log "Setting DVD drive for VM $VMName..." -Level "INFO"
            Set-VMDvdDrive -VMName $VMName -Path $ISOPath -ControllerNumber $isoMountPath.ControllerNumber -ControllerLocation $isoMountPath.ControllerLocation -ErrorAction Stop
        } else {
            Write-Log "Adding new DVD drive to VM $VMName..." -Level "INFO"
            Add-VMDvdDrive -VMName $VMName -Path $ISOPath -ErrorAction Stop
        }

        Write-Log "Checking for unattend file at $UnattendFilePath..." -Level "INFO"
        if (-not (Test-Path -Path $UnattendFilePath -ErrorAction Stop)) {
            Write-Log "Unattend file not found at $UnattendFilePath. Please ensure the file exists or update the script path." -Level "ERROR"
            throw "Unattend file missing. Aborting OS installation."
        } else {
            Write-Log "Unattend file found at $UnattendFilePath." -Level "INFO"
        }

        Write-Log "Attempting to automate OS installation on $VMName..." -Level "INFO"
        Start-VM -Name $VMName -ErrorAction Stop
        Write-Log "Waiting for $VMName to start..." -Level "INFO"

        $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
        $maxRetries = $GlobalMaxRetries
        $retryCount = 0
        $retryInterval = $GlobalRetryInterval
        
        # Give VM initial chance to get up and running
        Start-Sleep -Seconds $retryInterval

        while ($retryCount -lt $maxRetries) {
            $vmState = (Get-VM -Name $VMName).State
            $isResponsive = Test-Connection -ComputerName $VMName -Count 1 -Quiet

            if ($vmState -eq 'Running' -and $isResponsive) {
                Write-Log "VM $VMName is running and responsive." -Level "INFO"

                # Additional check for PowerShell Remoting
                try {
                    # Use or create session from cache
                    if (-not $Global:SessionCache) {
                        $Global:SessionCache = @{}
                    }
                    if (-not $Global:SessionCache.ContainsKey($VMName)) {
                        $Global:SessionCache[$VMName] = New-PSSession -VMName $VMName -Credential $Credential -ErrorAction Stop
                    }
                    $pssess = $Global:SessionCache[$VMName]
                    
                    Write-Log "PowerShell Remoting is working on $VMName." -Level "INFO"
                    break
                } catch {
                    Write-Log "PowerShell Remoting test failed on $VMName. Attempting to enable remoting." -Level "WARNING"
                    # Try to enable remoting remotely (this might not work if remoting isn't already enabled, but worth a try)
                    Invoke-Command -VMName $VMName -Credential $Credential -ScriptBlock { Enable-PSRemoting -Force } -ErrorAction SilentlyContinue
                }
            }
            
            if ($stopwatch.Elapsed.TotalSeconds -ge $GlobalTimeout) {
                Write-Log "Timeout waiting for $VMName to become responsive." -Level "ERROR"
                throw "VM did not become responsive within the allotted time."
            }
            
            Write-Log "VM $VMName not yet responsive, retrying in $retryInterval seconds..." -Level "INFO"
            Start-Sleep -Seconds $retryInterval
            $retryCount++
        }

        # Check if we've exhausted retries
        if ($retryCount -eq $maxRetries) {
            throw "Failed to establish connection to VM after $maxRetries retries."
        }

        try {
            $loginRetries = 0
            $loginMaxRetries = 5
            while ($loginRetries -lt $loginMaxRetries) {
                $logonCheck = Invoke-Command -Session $pssess -ScriptBlock {
                    Get-Process | Where-Object { $_.Name -eq "LogonUI" }
                }
                if ($logonCheck) {
                    Write-Log "VM $VMName has reached the login screen, proceeding with setup." -Level "INFO"
                    Write-Log "Starting OS setup on $VMName..." -Level "INFO"
                    Write-Log "Attempting to run setup.exe on $VMName. Time: $(Get-Date)" -Level "INFO"
                    Invoke-Command -Session $pssess -ScriptBlock {
                        Start-Process -FilePath "setup.exe" -ArgumentList "/unattend:$using:UnattendFilePath" -Wait -ErrorAction Stop
                    } -ErrorAction Stop
                    Write-Log "setup.exe was called on $VMName. Time: $(Get-Date)" -Level "INFO"
                    break
                } else {
                    Write-Log "VM $VMName still not at login screen, retrying in 60 seconds..." -Level "WARNING"
                    Start-Sleep -Seconds 60
                    $loginRetries++
                }
            }
            if ($loginRetries -eq $loginMaxRetries) {
                Write-Log "Failed to reach login screen on $VMName after $loginMaxRetries attempts." -Level "ERROR"
                throw "Login screen not detected after multiple retries."
            }
        } finally {
            Write-Log "Removing PowerShell session for $VMName..." -Level "INFO"
            Remove-PSSession -Session $pssess -ErrorAction Stop
            $Global:SessionCache.Remove($VMName)
        }

        Write-Log "OS installation initiated on $VMName. Waiting for installation to complete..." -Level "INFO"

        if (-not (WaitForVMOperational -VMName $VMName -Credential $Credential)) {
            Write-Log "Failed to wait for $VMName to become operational. Exiting script." -Level "ERROR"
            throw "VM did not become operational after OS installation."
        }
    } catch {
        Write-Log "Error occurred in InstallOS function. Error while installing OS on $($VMName): $_" -Level "ERROR"
        throw
    } finally {
        CleanUpSessions
    }
}

# Define the function to setup Network Adapter
function SetupNetworkAdapter {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [string]$SwitchName,

        [Parameter(Mandatory=$false)]
        [string]$AdapterPattern = "notmatch Loopback|Tunnel|Virtual|VMware",

        [Parameter(Mandatory=$false)]
        [switch]$AllowManagementOS = $true
    )

    try {
        Write-Log "Gathering physical network adapter..."
        $physicalAdapter = Get-NetAdapter | Where-Object {
            $_.Status -eq "Up" -and 
            $_.InterfaceDescription -notmatch $AdapterPattern
        } | Select-Object -First 1 -ExpandProperty Name -ErrorAction Stop

        if (-not $physicalAdapter) {
            throw "Could not find a suitable physical network adapter."
        }

        Write-Log "Checking for existing virtual switch..."
        $existingSwitch = Get-VMSwitch -Name $SwitchName -ErrorAction SilentlyContinue
        if (-not $existingSwitch) {
            Write-Log "Creating virtual switch '$SwitchName'..."
            New-VMSwitch -Name $SwitchName -NetAdapterName $physicalAdapter -AllowManagementOS:$AllowManagementOS.IsPresent -ErrorAction Stop
            Write-Log "Virtual switch $SwitchName created successfully using adapter '$physicalAdapter'."
        } else {
            Write-Log "Virtual switch '$SwitchName' already exists."
        }
    }
    catch {
        Write-Log "An error occurred in the SetupNetworkAdapter function. Error while setting up the virtual switch: $_" -Level "ERROR"
        throw
    }
}

# Define the function to handle VHD creation or usage
function HandleVHD {
    [CmdletBinding()]
    param (
        [string]$VMName,
        
        [string]$VHDPath,
        
        [string]$VHDSize,
        
        [string]$Memory,
        
        [string]$SwitchName,
        
        [Parameter(Mandatory=$false)]
        [int]$VMGeneration = 2,
        
        [Parameter(Mandatory=$false)]
        [ValidateSet("Fixed","DynamicallyExpanding")]
        [string]$VHDType = "DynamicallyExpanding"
    )

    try {
        # Convert memory and size strings to bytes
        $memoryBytes = ConvertToBytes -SizeString $Memory
        $vhdSizeBytes = ConvertToBytes -SizeString $VHDSize

        $existingVHD = Get-ChildItem -Path $VHDPath -ErrorAction SilentlyContinue
        if ($existingVHD) {
            Write-Log "Existing VHD found at $VHDPath for $VMName. Removing to create new VHD." -Level "INFO"
            Remove-Item -Path $VHDPath -Force -ErrorAction Stop
        }

        # Create new VHD with specified type
        Write-Log "Creating new VHD for $VMName at $VHDPath." -Level "INFO"
        New-VHD -Path $VHDPath -SizeBytes $vhdSizeBytes -Fixed:$($VHDType -eq "Fixed") -ErrorAction Stop
        
        # Now create VM with the new VHD
        Write-Log "Creating VM $VMName with new VHD." -Level "INFO"
        New-VM -Name $VMName -MemoryStartupBytes $memoryBytes -VHDPath $VHDPath -SwitchName $SwitchName -Generation $VMGeneration -ErrorAction Stop
    } catch {
        Write-Log "Error occurred in HandleVHD function. Error handling VHD for $($VMName): $_" -Level "ERROR"
        throw
    }
}

# Define the function to configure the VM Network
function ConfigureVMNetwork {
    param (
        [string]$VMName,
        [string]$IPAddress,
        [string]$Gateway,
        [string[]]$DNSServers,
        [string]$Netmask = $SubnetMask,
        [System.Management.Automation.PSCredential]$Credential
    )
    try {
        Write-Log "Attempting to configure static network settings for $VMName..." -Level "INFO"
        
        # Create a new PowerShell session to the VM
        $session = New-PSSession -VMName $VMName -Credential $Credential -ErrorAction Stop
        
        # Script block to be executed on the VM
        $scriptBlock = {
            param($ip, $gateway, $dns, $netmask)
            
            # Get the first network adapter that's up
            $interface = Get-NetAdapter | Where-Object { $_.Status -eq 'Up' } | Select-Object -First 1
            if ($interface) {
                # Remove any existing IP configuration for the interface
                Remove-NetIPAddress -InterfaceAlias $interface.Name -Confirm:$false -ErrorAction SilentlyContinue
                Remove-DnsClientServerAddress -InterfaceAlias $interface.Name -Confirm:$false -ErrorAction SilentlyContinue
                
                # Add static IP configuration
                New-NetIPAddress -InterfaceAlias $interface.Name -IPAddress $ip -PrefixLength (ConvertMaskToCIDR $netmask) -DefaultGateway $gateway -ErrorAction Stop
                
                # Set DNS servers
                Set-DnsClientServerAddress -InterfaceAlias $interface.Name -ServerAddresses $dns -ErrorAction Stop
                Write-Log "Successfully configured static IP for $using:VMName" -Level "SUCCESS"
            } else {
                throw "No network adapter found in an 'Up' state."
            }
        }
        
        # Helper function to convert subnet mask to CIDR notation
        function ConvertMaskToCIDR {
            param([string]$Mask)
            $bits = ([IPAddress]$Mask).GetAddressBytes() | ForEach-Object { [Convert]::ToString($_, 2) } | ForEach-Object { $_.PadLeft(8, '0') }
            return ($bits -join '') -replace '1', '' | Measure-Object -Character | Select-Object -ExpandProperty Characters
        }
        
        # Execute the script block on the remote session
        Invoke-Command -Session $session -ScriptBlock $scriptBlock -ArgumentList $IPAddress, $Gateway, $DNSServers, $Netmask -ErrorAction Stop
    } catch {
        Write-Log "Failed to configure network for $($VMName): $_" -Level "ERROR"
        throw
    } finally {
        if ($session) {
            Remove-PSSession -Session $session
        }
    }
}

# Define the function to configure Domain Controller
function ConfigureDomainController {
    [CmdletBinding()]
    param (
        [string]$DCIPAddress,
        [string]$DCGateway,
        [string[]]$DCDNSServers
    )
    try {
        $pssess = New-PSSession -VMName $DCName -Credential $Credential
        try {
            Invoke-Command -Session $pssess -ScriptBlock {
                $SecurePassword = $using:SecurePassword
                Write-Log "Installing Active Directory Domain Services on $using:DCName..." -Level "INFO"
                Install-WindowsFeature AD-Domain-Services -IncludeManagementTools -ErrorAction Stop

                Write-Log "Configuring network settings for Domain Controller..." -Level "INFO"
                #Dynamically select an interface:
                $interfaceAlias = (Get-NetAdapter | Where-Object { $_.Status -eq "Up" } | Select-Object -First 1 -ExpandProperty Name)
                
                $ipAddress = $using:DCIPAddress
                $gateway = $using:DCGateway
                $dnsServers = $using:DCDNSServers

                New-NetIPAddress -InterfaceAlias $interfaceAlias -IPAddress $ipAddress -PrefixLength 24 -DefaultGateway $gateway -ErrorAction Stop
                Set-DnsClientServerAddress -InterfaceAlias $interfaceAlias -ServerAddresses $dnsServers -ErrorAction Stop
                
                Write-Log "Installing new Active Directory forest..." -Level "INFO"
                Install-ADDSForest -DomainName $using:DomainName -InstallDNS:$true -SafeModeAdministratorPassword $SecurePassword -ErrorAction Stop
                Write-Log "Domain Controller configuration completed successfully." -Level "SUCCESS"
            }
        } catch {
            Write-Log "Error occurred within Invoke-Command block for Domain Controller configuration: $_" -Level "ERROR"
            throw
        }
    } finally {
        if ($pssess) {
            Remove-PSSession -Session $pssess -ErrorAction Stop
        }
    }
}

# Define the function to join VM to domain and configure network settings
function JoinToDomainAndConfigure {
    [CmdletBinding()]
    param (
        [string]$VMName,
        
        [string]$IPAddress,
        
        [string]$DomainName,
        
        $Credential
    )

    try {
        Write-Log "Attempting to create PowerShell session for $VMName to join domain..." -Level "INFO"
        $pssess = New-PSSession -VMName $VMName -Credential $Credential
        try {
            Write-Log "Configuring network settings for $VMName..." -Level "INFO"
            Invoke-Command -Session $pssess -ScriptBlock {
                param($ipAddress, $gateway, $dnsServers, $domainName, $credential)
            
                $interfaceAlias = (Get-NetAdapter | Where-Object { $_.Status -eq "Up" } | Select-Object -First 1 -ExpandProperty Name)
            
                # Set static IP
                New-NetIPAddress -InterfaceAlias $interfaceAlias -IPAddress $ipAddress -PrefixLength 24 -DefaultGateway $gateway -ErrorAction Stop
                Write-Log "IP address configuration successful." -Level "SUCCESS"
                Set-DnsClientServerAddress -InterfaceAlias $interfaceAlias -ServerAddresses $dnsServers -ErrorAction Stop
                Write-Log "DNS server configuration successful." -Level "SUCCESS"
            
                Write-Log "Attempting to join $VMName to domain $domainName..." -Level "INFO"
                Add-Computer -DomainName $domainName -Credential $credential -Restart -Force -ErrorAction Stop
                Write-Log "$VMName has been added to the domain $domainName." -Level "SUCCESS"
            } -ArgumentList $IPAddress, $gateway, $dnsServers, $DomainName, $Credential
            Write-Log "Configuration for $VMName initiated."

            Write-Log "Waiting for $VMName to restart after domain join..."
            $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()

            # Check the VM state after the session is closed
            while ((Get-VM -Name $VMName).State -ne 'Running' -and $stopwatch.Elapsed.TotalSeconds -lt $GlobalTimeout) {
                Start-Sleep -Seconds 10
            }

            if ($stopwatch.Elapsed.TotalSeconds -ge $GlobalTimeout) {
                Write-Log "Timeout waiting for $VMName to start after domain join and IP configuration." -Level "ERROR"
                return $false
            }

            Write-Log "$VMName has restarted, after domain join and IP configuration."

            # Check VM is fully operational after reboot
            if (-not (WaitForVMOperational -VMName $VMName -RequiredServices @("Netlogon"))) {
                Write-Log "VM $VMName did not become fully operational after reboot." -Level "ERROR"
                return $false
            }

            Write-Log "Checking domain membership for $VMName..." -Level "INFO"
            $domainCheckSession = New-PSSession -VMName $VMName -Credential $Credential
            try {
                $domainStatus = Invoke-Command -Session $domainCheckSession -ScriptBlock {
                    if ((Get-WmiObject -Class Win32_ComputerSystem).PartOfDomain) {
                        return $true
                    } else {
                        return $false
                    }
                }
                if ($domainStatus) {
                    Write-Log "$VMName successfully joined the domain." -Level "SUCCESS"
                } else {
                    Write-Log "$VMName failed to join the domain." -Level "ERROR"
                    return $false
                }

                Write-Log "Checking network configuration for $VMName..." -Level "INFO"
                $networkStatus = Invoke-Command -Session $domainCheckSession -ScriptBlock {
                    $interface = Get-NetIPInterface | Where-Object { $_.ConnectionState -eq "Connected" }
                    if ($interface -and $interface.IPv4DefaultGateway) {
                        return $true
                    } else {
                        return $false
                    }
                }
                if ($networkStatus) {
                    Write-Log "$VMName has proper network configuration." -Level "SUCCESS"
                } else {
                    Write-Log "$VMName has incorrect network configuration." -Level "WARNING"
                }
            } finally {
                Write-Log "Closing domain check session for $VMName..." -Level "INFO"
                Remove-PSSession -Session $domainCheckSession
            }
    
            return $true
        } catch {
            Write-Log "An error occurred during network configuration or joining $VMName to the domain: $_" -Level "ERROR"
            return $false
        } finally {
            if ($pssess) {
                Write-Log "Closing PowerShell session for $VMName..." -Level "INFO"
                Remove-PSSession -Session $pssess
            }
        }
    } catch {
        Write-Log "An error occurred in JoinToDomainAndConfigure function: $_" -Level "ERROR"
        return $false
    }
}

# Define the function to perform post-installation checks
function PostInstallationChecks {
    [CmdletBinding()]
    param (
        [string]$VMName,

        [string[]]$ExpectedServices = $DCExpectedServices,

        [Parameter(Mandatory=$false)]
        [string[]]$ExpectedFeatures,

        [Parameter(Mandatory=$false)]
        [string]$TestNetworkIP,

        [Parameter(Mandatory=$false)]
        [bool]$CheckDomainMembership = $true
    )

    Write-Log "Performing post-installation checks on $VMName..."

    if (-not (WaitForVMOperational -VMName $VMName -RequiredServices $ExpectedServices)) {
        Write-Log "VM $VMName is not fully operational, skipping checks." -Level "WARNING"
        return $false
    }

$pssess = New-PSSession -VMName $VMName -Credential $Credential
try {
    # Check if the service is running
    $serviceStatus = Invoke-Command -Session $pssess -ScriptBlock {
        $servicesStatus = @()
        foreach ($service in $using:ExpectedServices) {
            $status = Get-Service -Name $service | Select-Object -ExpandProperty Status -ErrorAction Stop
            $servicesStatus += @{Name=$service; Status=$status}
        }
        $servicesStatus
    }

    foreach ($serviceCheck in $serviceStatus) {
        if ($serviceCheck.Status -ne "Running") {
            Write-Log "Service $($serviceCheck.Name) on $VMName is not running. Status: $($serviceCheck.Status)" -Level "WARNING"
            return $false
        }
    }
    Write-Log "All expected services on $VMName are running."

    # Check domain membership if applicable (for SQL Servers)
    if ($CheckDomainMembership -and $VMName -ne $DCName) {
        $domainMembership = Invoke-Command -Session $pssess -ScriptBlock {
            (Get-WmiObject -Class Win32_ComputerSystem -ErrorAction Stop).PartOfDomain
        }
        if ($domainMembership) {
            Write-Log "$VMName is part of the domain."
        } else {
            Write-Log "$VMName is not part of the domain." -Level "WARNING"
            return $false
        }
    }

    # Additional checks, like verifying installed features or network connectivity
    $featureCheck = Invoke-Command -Session $pssess -ScriptBlock {
        # Example: Check if a specific feature is installed
        Get-WindowsFeature | Where-Object { $_.Name -in $using:ExpectedFeatures } | Select-Object -ExpandProperty Installed -ErrorAction Stop
    }
    if ($featureCheck -contains $true) {
        Write-Log "Expected features are installed on $VMName."
    } else {
        Write-Log "Some expected features are not installed on $VMName." -Level "WARNING"
    }

    # Network connectivity check
    $networkCheck = Invoke-Command -Session $pssess -ScriptBlock {
        Test-Connection -ComputerName $TestNetworkIP -Count 1 -Quiet -ErrorAction Stop # Check internet connectivity
    }
    if ($networkCheck) {
        Write-Log "$VMName has external network connectivity."
    } else {
        Write-Log "$VMName does not have external network connectivity." -Level "WARNING"
    }

} catch {
    Write-Log "Error occurred in PostInstallationChecks function. Failed to check status on $($VMName): $_" -Level "ERROR"
    throw
} finally {
    Remove-PSSession -Session $pssess
}

return $true
}

#Main script execution
try {
    Write-Log "Starting initial setup..." -Level "INFO"
    EnsureHyperVIsEnabled
    Write-Log "Collecting credentials..." -Level "INFO"
    $Credential = GetAdminCredentials -DefaultUsername "administrator"  # or any custom username
    $SecurePassword = GetSafeModePassword -MinLength 8  # or any custom length

    Write-Log "Setting up environment variables..." -Level "INFO"
    $global:timeout = $GlobalTimeout

    Write-Log "Creating directories..." -Level "INFO"
    CreateDirectories -DirectoryPath $VMDirectory
    CreateDirectories -DirectoryPath "$($VMDirectory)\$($DCName)"
    foreach ($SQLHost in $SQLHosts) {
        CreateDirectories -DirectoryPath "$($VMDirectory)\$($SQLHost)"
    }

    Write-Log "Selecting ISO..." -Level "INFO"
    if ([string]::IsNullOrEmpty($ISOPath)) {
        $isoToUse = GetISOToUse
        $isoPathForInstall = $isoToUse.FullName
    } else {
        $isoToUse = Get-Item $ISOPath -ErrorAction Stop
        if ($isoToUse.Extension -ne ".iso") {
            Write-Log "The file specified in ISOPath is not an ISO file." -Level "ERROR"
            exit
        }
        $isoPathForInstall = $ISOPath
    }

    # Define the path to the unattend file
    if (-not (Test-Path -Path $unattendFilePath -ErrorAction Stop)) {
        Write-Log "Unattend file not found at $unattendFilePath. Please place the file there or update the script." -Level "ERROR"
        exit
    }

    Write-Log "Setting up network..." -Level "INFO"
    SetupNetworkAdapter -SwitchName $SwitchName

    # Domain Controller setup
    Write-Log "Configuring Domain Controller..." -Level "INFO"
    $vhdPath = "$($VMDirectory)\$($DCName)\$($DCName).vhdx"
    HandleVHD -VMName $DCName -VHDPath $vhdPath -VHDSize $DCVHDSize -Memory $DCMemory -SwitchName $SwitchName -VMGeneration $VMGeneration -VHDType $VHDType
    InstallOS -VMName $DCName -ISOPath $isoPathForInstall -UnattendFilePath $unattendFilePath -Credential $Credential
    ConfigureVMNetwork -VMName $DCName -IPAddress $DCIPAddress -Gateway $DCGateway -DNSServers @($DNSServer) -Credential $Credential
    ConfigureDomainController -DCIPAddress $DCIPAddress -DCGateway $DCGateway -DCDNSServers @($DNSServer)
    if (-not (PostInstallationChecks -VMName $DCName -ExpectedServices $DCExpectedServices -ExpectedFeatures $DCExpectedFeatures -CheckDomainMembership $false)) {
        Write-Log "Post-installation checks failed for Domain Controller. Aborting script."
        exit
    }

    # SQL Server VMs setup
    $totalSQLHosts = $SQLHosts.Count
    for ($i = 0; $i -lt $totalSQLHosts; $i++) {
        $SQLHost = $SQLHosts[$i]
        Write-Progress -Activity "Setting up SQL Servers" -Status "Configuring $SQLHost" -PercentComplete (($i / $totalSQLHosts) * 100)
        
        if (-not $SQLIPAddresses.ContainsKey($SQLHost)) {
            Write-Log "No IP address specified for $SQLHost. Aborting script."
            exit
        }

        $SQLIPAddress = $SQLIPAddresses[$SQLHost]
        if (-not (ValidateIPWithinNetwork -NetworkIP $DCIPAddress -SubnetMask $SubnetMask -IPAddressToCheck $SQLIPAddress)) {
            Write-Log "IP address for $SQLHost ($SQLIPAddress) does not match the network defined by the Domain Controller ($DCIPAddress/$SubnetMask). Aborting script."
            exit
        }

        $sqlVhdPath = "$($VMDirectory)\$($SQLHost)\$($SQLHost).vhdx"
        HandleVHD -VMName $SQLHost -VHDPath $sqlVhdPath -VHDSize $SQLVHDSize -Memory $SQLMemory -SwitchName $SwitchName -VMGeneration $VMGeneration -VHDType $VHDType
        InstallOS -VMName $SQLHost -ISOPath $isoPathForInstall -UnattendFilePath $unattendFilePath -Credential $Credential
        if (-not (JoinToDomainAndConfigure -VMName $SQLHost -IPAddress $SQLIPAddress -DomainName $DomainName -Credential $Credential)) {
            Write-Log "Failed to join $SQLHost to the domain or configure network settings. Aborting script."
            exit
        }
        if (-not (PostInstallationChecks -VMName $SQLHost -ExpectedServices $SQLExpectedServices -CheckDomainMembership $true)) {
            Write-Log "Post-installation checks failed for $SQLHost. Aborting script."
            exit
        }
    }
    Write-Progress -Activity "Setting up SQL Servers" -Completed
} catch {
    Write-Log "An error occurred during the setup process: $_" -Level "ERROR"
    Write-Log "Script terminated at line $($_.InvocationInfo.ScriptLineNumber)" -Level "ERROR"
} finally {
    Write-Log "Script execution completed or terminated. Cleaning up..." -Level "INFO"
    CleanUpSessions
    # Placeholder, in case there is any future need identified to remove any temporary files, close connections, or clean up resources, etc.
}