# ================================
# SailPoint IdentityIQ 8.5 - Full Auto Installer
# Windows Server + SQL Server + Tomcat 9 + JDK 17
# ================================

# ----- Configurations -----
$InstallerPath = "C:\InstallerFiles"
$JavaPath      = "C:\Program Files\Java\jdk-17"
$TomcatRoot    = "C:\SailPoint"
$TomcatPath    = "$TomcatRoot\tomcat"
$IiqVersion    = "8.5"
$IiqWar        = "$InstallerPath\identityiq-$IiqVersion\identityiq.war"
$BrandingPath  = "$InstallerPath\Branding"
$JdbcDriver    = "$InstallerPath\mssql-jdbc-9.4.1.jre16.jar"
$EncPasswords  = @{}
$SqlExe        = "SQL2022-SSEI-Expr.exe"   # Online installer
$SqlSetupExe   = "SQLEXPR_x64_ENU.exe"     # Offline installer
$SsmsExe       = "vs_SSMS.exe"
$SqlSaPassword = "P@ssw0rd@#123"

# Tomcat Memory Configuration
$InitialMemory = "4096"
$MaximumMemory = "6000"

# ------------------------------
# 0. Pre-configuration
# ------------------------------

# Record installation start time
$InstallStartTime = Get-Date
Write-Host "Starting installation at: $InstallStartTime" -ForegroundColor Cyan

# ----- Enhanced Logging Functions -----
function Write-LogMessage {
    param(
        [string]$Message,
        [ValidateSet("INFO", "WARN", "ERROR", "SUCCESS")]
        [string]$Level = "INFO"
    )
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $colorMap = @{
        "INFO" = "White"
        "WARN" = "Yellow" 
        "ERROR" = "Red"
        "SUCCESS" = "Green"
    }
    
    $logEntry = "[$timestamp] [$Level] $Message"
    Write-Host $logEntry -ForegroundColor $colorMap[$Level]
    
    # Also write to transcript if active
    if ($global:TranscriptActive) {
        Write-Output $logEntry
    }
}

function Test-PreRequisites {
    Write-LogMessage "Checking prerequisites..." "INFO"
    
    # Check if running as Administrator
    if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
        throw "You must run this script as Administrator!"
    }
    
    # Check PowerShell version
    if ($PSVersionTable.PSVersion.Major -lt 5) {
        throw "PowerShell 5.0 or higher is required!"
    }
    
    # Check available disk space (minimum 10GB)
    $systemDrive = Get-WmiObject -Class Win32_LogicalDisk | Where-Object { $_.DeviceID -eq $env:SystemDrive }
    $freeSpaceGB = [math]::Round($systemDrive.FreeSpace / 1GB, 2)
    if ($freeSpaceGB -lt 10) {
        throw "Insufficient disk space. At least 10GB free space required. Current: ${freeSpaceGB}GB"
    }
    
    Write-LogMessage "Prerequisites check passed. Free disk space: ${freeSpaceGB}GB" "SUCCESS"
}

function Test-FileExists {
    param([string]$FilePath, [string]$Description)
    
    if (!(Test-Path $FilePath)) {
        throw "$Description missing at: $FilePath"
    }
    Write-LogMessage "$Description found: $FilePath" "SUCCESS"
}

function Wait-ForService {
    param(
        [string]$ServiceName,
        [int]$TimeoutSeconds = 60
    )
    
    Write-LogMessage "Waiting for service '$ServiceName' to start..." "INFO"
    
    $timeout = (Get-Date).AddSeconds($TimeoutSeconds)
    do {
        $service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
        if ($service -and $service.Status -eq "Running") {
            Write-LogMessage "Service '$ServiceName' is running" "SUCCESS"
            return $true
        }
        Start-Sleep -Seconds 2
    } while ((Get-Date) -lt $timeout)
    
    throw "Service '$ServiceName' failed to start within $TimeoutSeconds seconds"
}

function Test-SqlConnection {
    param(
        [string]$ServerInstance,
        [string]$Username = $null,
        [string]$Password = $null,
        [switch]$WindowsAuth
    )
    
    $connectionString = if ($WindowsAuth) {
        "sqlcmd -S `"$ServerInstance`" -E -Q `"SELECT @@VERSION`" -b"
    } else {
        "sqlcmd -S `"$ServerInstance`" -U `"$Username`" -P `"$Password`" -Q `"SELECT @@VERSION`" -b"
    }
    
    try {
        if ($WindowsAuth) {
            & sqlcmd -S $ServerInstance -E -Q "SELECT @@VERSION" -b | Out-Null
        } else {
            & sqlcmd -S $ServerInstance -U $Username -P $Password -Q "SELECT @@VERSION" -b | Out-Null
        }
        return $true
    }
    catch {
        return $false
    }
}

# Start enhanced logging
$LogFile = "$InstallerPath\IIQ_Install_$(Get-Date -Format 'yyyyMMdd-HHmmss').log"

if (!(Test-Path $InstallerPath)) { 
    New-Item -Path $InstallerPath -ItemType Directory -Force | Out-Null 
}
Start-Transcript -Path $LogFile -Append
$global:TranscriptActive = $true

Write-LogMessage "=== SailPoint IdentityIQ $IiqVersion - Auto Installer ===" "INFO"
Write-LogMessage "Log file: $LogFile" "INFO"

# Pre-configuration checks
Test-PreRequisites
Test-FileExists $InstallerPath "Installer directory"

# Ensure have admin rights
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    throw "You must run this script as Administrator!"
}

# ------------------------------
# 1. Install JDK 17
# ------------------------------
Write-LogMessage "Installing JDK 17..." "INFO"
$JdkInstaller = Join-Path $InstallerPath "jdk-17.0.15_windows-x64_bin.exe"
Test-FileExists $JdkInstaller "JDK installer"

Start-Process -FilePath $JdkInstaller -ArgumentList "/s" -Wait -NoNewWindow

# Set JAVA_HOME and PATH (permanent)
$envPath = [System.Environment]::GetEnvironmentVariable("Path", "Machine")
if ($envPath -notlike "*$JavaPath\bin*") {
    [System.Environment]::SetEnvironmentVariable("JAVA_HOME", $JavaPath, "Machine")
    [System.Environment]::SetEnvironmentVariable("Path", $envPath + ";$JavaPath\bin", "Machine")
    Write-LogMessage "JAVA_HOME and PATH updated" "SUCCESS"
}
$env:JAVA_HOME = $JavaPath
$env:Path += ";$JavaPath\bin"

# ------------------------------
# 2. Install Tomcat
# ------------------------------
Write-LogMessage "Installing Apache Tomcat..." "INFO"
$TomcatZip = Join-Path $InstallerPath "apache-tomcat-9.0.109-windows-x64.zip"

Test-FileExists $TomcatZip "Tomcat ZIP"

# Clean old Tomcat if exists
if (Test-Path "$TomcatRoot\tomcat") {
    Write-LogMessage "Removing old Tomcat installation..." "WARN"
    
    $tomcatService = Get-Service -Name "Tomcat9" -ErrorAction SilentlyContinue
    if ($tomcatService) {
        Stop-Service -Name "Tomcat9" -Force -ErrorAction SilentlyContinue
    }
    
    Remove-Item -Recurse -Force "$TomcatRoot\tomcat" -ErrorAction SilentlyContinue
}

Expand-Archive -Path $TomcatZip -DestinationPath $TomcatRoot -Force
Rename-Item "$TomcatRoot\apache-tomcat-9.0.109" "tomcat" -Force

# Set Env Vars
[System.Environment]::SetEnvironmentVariable("CATALINA_HOME", $TomcatPath, "Machine")
[System.Environment]::SetEnvironmentVariable("JAVA_HOME", $JavaPath, "Machine")
$env:CATALINA_HOME = $TomcatPath
$env:JAVA_HOME = $JavaPath

# Install Tomcat as Windows service (via CMD) only if not exists
if (-not (Get-Service -Name "Tomcat9" -ErrorAction SilentlyContinue)) {
    Write-LogMessage "Installing Tomcat service..." "INFO"
    cmd.exe /c "cd /d `"$TomcatPath\bin`" && service.bat install Tomcat9"
    Start-Sleep -Seconds 5
} else {
    Write-LogMessage "Tomcat9 service already exists" "INFO"
}

# Configure JVM Memory Settings for Tomcat Service
Write-LogMessage "Configuring JVM memory settings (Initial: ${InitialMemory}MB, Maximum: ${MaximumMemory}MB)..." "INFO"
$TomcatExe = "$TomcatPath\bin\tomcat9.exe"

if (Test-Path $TomcatExe) {
    # Stop the service if running
    $service = Get-Service -Name "Tomcat9" -ErrorAction SilentlyContinue
    if ($service -and $service.Status -eq "Running") {
        Stop-Service -Name "Tomcat9" -Force
        Start-Sleep -Seconds 3
    }

    # Configure JVM options using tomcat9w.exe (GUI configuration tool via command line)
    try {
        # Configure memory settings
        & "$TomcatPath\bin\tomcat9.exe" //US//Tomcat9 --JvmMs=$InitialMemory     
        & "$TomcatPath\bin\tomcat9.exe" //US//Tomcat9 --JvmMx=$MaximumMemory            
    }
    catch {
        Write-LogMessage "Primary memory configuration failed: $($_.Exception.Message)" "WARN"
        Write-LogMessage "Attempting registry-based memory configuration..." "INFO"
        
        # Fallback to registry configuration if tomcat9.exe method failed
        $TomcatRegistryPath = "HKLM:\SOFTWARE\Apache Software Foundation\Procrun 2.0\Tomcat9\Parameters\Java"
        if (Test-Path $TomcatRegistryPath) {
            try {
                Set-ItemProperty -Path $TomcatRegistryPath -Name "JvmMs" -Value $InitialMemory
                Set-ItemProperty -Path $TomcatRegistryPath -Name "JvmMx" -Value $MaximumMemory
                Write-LogMessage "Memory settings configured via registry!" "SUCCESS"
            }
            catch {
                Write-LogMessage "Registry configuration also failed: $($_.Exception.Message)" "ERROR"
            }
        }
    }
} else {
    Write-LogMessage "Memory configuration failed - may need manual configuration" "WARN"
}

# Configure and start Tomcat service
Set-Service -Name "Tomcat9" -StartupType Automatic
Start-Service -Name "Tomcat9"
Wait-ForService -ServiceName "Tomcat9" -TimeoutSeconds 30

Write-LogMessage "Tomcat9 service started successfully!" "SUCCESS"

Start-Process "http://localhost:8080"

# ------------------------------
# 3. Install SQL Server
# ------------------------------
Write-LogMessage "Installing SQL Server Express..." "INFO"
$SqlInstaller = Join-Path $InstallerPath $SqlExe
Test-FileExists $SqlInstaller "SQL Server installer"

# Check if SQL Server is already installed
$existingSqlService = Get-Service | Where-Object { $_.Name -like "MSSQL*" } | Select-Object -First 1
if ($existingSqlService) {
    Write-LogMessage "SQL Server service already exists: $($existingSqlService.Name)" "INFO"
} else {
    Write-LogMessage "Installing SQL Server Express..." "INFO"
    Start-Process -FilePath $SqlInstaller -ArgumentList "/qs /x:$InstallerPath\SQLSetup" -Wait -NoNewWindow

    $newSqlService = Get-Service | Where-Object { $_.Name -like "MSSQL*" } | Select-Object -First 1
    if ($newSqlService) {
        Write-LogMessage "SQL Server service detected: $($newSqlService.Name)" "SUCCESS"
    }

    if (-not $newSqlService) {
            throw "SQL Server installation failed - no SQL service found after installation"
    }
}

# ------------------------------
# 3.0 Ensure SQLCMD is available (MOVED UP)
# ------------------------------
Write-LogMessage "Setting up SQLCMD tools..." "INFO"

# Common paths where sqlcmd might be installed
$SqlCmdPaths = @(
    "C:\Program Files\Microsoft SQL Server\Client SDK\ODBC\170\Tools\Binn",
    "C:\Program Files\Microsoft SQL Server\Client SDK\ODBC\130\Tools\Binn",
    "C:\Program Files\Microsoft SQL Server\140\Tools\Binn",
    "C:\Program Files\Microsoft SQL Server\150\Tools\Binn",
    "C:\Program Files\Microsoft SQL Server\160\Tools\Binn"
)

$SqlCmdFound = $false
foreach ($path in $SqlCmdPaths) {
    if (Test-Path "$path\sqlcmd.exe") {
        Write-LogMessage "Found SQLCMD at: $path" "SUCCESS"
        
        # Add to PATH if not already there
        $envPath = [System.Environment]::GetEnvironmentVariable("Path", "Machine")
        if ($envPath -notlike "*$path*") {
            [System.Environment]::SetEnvironmentVariable("Path", $envPath + ";$path", "Machine")
        }
        $env:Path += ";$path"
        $SqlCmdFound = $true
        break
    }
}

if (-not $SqlCmdFound) {
    Write-LogMessage "SQLCMD not found. Installing SQL Server Command Line Utilities..." "WARN"
    
    # Download and install SQL Server Command Line Utilities if not found
    $SqlCmdInstaller = "https://go.microsoft.com/fwlink/?linkid=2230791"
    $SqlCmdInstallerPath = "$InstallerPath\MsSqlCmdLnUtils.msi"
    
    try {
        Invoke-WebRequest -Uri $SqlCmdInstaller -OutFile $SqlCmdInstallerPath
        Start-Process -FilePath "msiexec.exe" -ArgumentList "/i `"$SqlCmdInstallerPath`" /quiet IACCEPTMSSQLCMDLNUTILSLICENSETERMS=YES" -Wait
        
        # Re-check for sqlcmd after installation
        foreach ($path in $SqlCmdPaths) {
            if (Test-Path "$path\sqlcmd.exe") {
                $envPath = [System.Environment]::GetEnvironmentVariable("Path", "Machine")
                if ($envPath -notlike "*$path*") {
                    [System.Environment]::SetEnvironmentVariable("Path", $envPath + ";$path", "Machine")
                }
                $env:Path += ";$path"
                $SqlCmdFound = $true
                Write-LogMessage "SQLCMD installed and configured" "SUCCESS"
                break
            }
        }
    }
    catch {
        throw "Failed to download/install SQL Server Command Line Utilities: $($_.Exception.Message)"
    }
}

if (-not $SqlCmdFound) {
    throw "SQLCMD could not be found or installed"
}

# Test sqlcmd availability
try {
    $null = & sqlcmd -?
    Write-LogMessage "SQLCMD is operational" "SUCCESS"
}
catch {
    throw "SQLCMD installation verification failed"
}

# ------------------------------
# 3.1 Enable sa login + set password
# ------------------------------

# Detect SQL Server service dynamically
$SqlService = Get-Service | Where-Object { $_.Name -like "MSSQL*" } | Select-Object -First 1
if (-not $SqlService) {
    throw "No SQL Server service found after installation"
}

Write-LogMessage "Configuring SQL Server service: $($SqlService.Name)" "INFO"

# Ensure service is running
if ($SqlService.Status -ne "Running") {
    Write-LogMessage "Starting SQL Server service: $($SqlService.Name)" "INFO"
    Start-Service -Name $SqlService.Name
    Wait-ForService -ServiceName $SqlService.Name -TimeoutSeconds 60
}

# Build instance connection string
$SqlInstance = if ($SqlService.Name -like "MSSQLSERVER") { "localhost" } else { "localhost\$($SqlService.Name -replace 'MSSQL\$', '')" }
Write-LogMessage "SQL Server instance: $SqlInstance" "INFO"

# Enable sa login + set password using Windows Authentication (-E)
$EnableSaQuery = @"
ALTER LOGIN [sa] ENABLE;
ALTER LOGIN [sa] WITH PASSWORD = N'$SqlSaPassword' UNLOCK;
"@
& sqlcmd -S $SqlInstance -E -Q "$EnableSaQuery"

# ------------------------------
# 3.2 Enable Mixed Mode Authentication
# ------------------------------
Write-LogMessage "Enabling Mixed Mode Authentication..." "INFO"
$SqlInstanceName = if ($SqlService.Name -like "MSSQLSERVER") { "MSSQLSERVER" } else { ($SqlService.Name -replace 'MSSQL\$', '') }

# Try SQL 2022 (MSSQL16) and SQL 2019 (MSSQL15) registry paths
$AuthRegPaths = @(
    "HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server\MSSQL16.$SqlInstanceName\MSSQLServer",
    "HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server\MSSQL15.$SqlInstanceName\MSSQLServer",
    "HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server\MSSQL14.$SqlInstanceName\MSSQLServer"
)

$FoundAuthPath = $null
foreach ($p in $AuthRegPaths) {
    if (Test-Path $p) {
        $FoundAuthPath = $p
        break
    }
}

if ($FoundAuthPath) {
    Set-ItemProperty -Path $FoundAuthPath -Name "LoginMode" -Value 2
    Write-LogMessage ">>> Mixed Mode Authentication enabled" "SUCCESS"
} else {
    Write-LogMessage "Failed to set registry at $regPath : $($_.Exception.Message)" "WARN"
}

if (-not $FoundAuthPath) {
    Write-LogMessage "Could not set Mixed Mode Authentication via registry" "WARN"
}
# ------------------------------
# 3.3 Enable TCP/IP and configure port 1433
# ------------------------------
Write-LogMessage "Configuring TCP/IP and port 1433..." "INFO"

$TcpRegPaths = @(
    "HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server\MSSQL16.$SqlInstanceName\MSSQLServer\SuperSocketNetLib\Tcp", # SQL 2022
    "HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server\MSSQL15.$SqlInstanceName\MSSQLServer\SuperSocketNetLib\Tcp", # SQL 2019
    "HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server\MSSQL14.$SqlInstanceName\MSSQLServer\SuperSocketNetLib\Tcp"  # SQL 2016
)

$FoundPath = $null
foreach ($p in $TcpRegPaths) {
    if (Test-Path $p) {
        $FoundPath = $p
        break
    }
}

if ($FoundPath) {
    # Enable TCP/IP globally
    Set-ItemProperty -Path $FoundPath -Name Enabled -Value 1

    # Configure IPAll
    $IpAllPath = "$FoundPath\IPAll"
    Set-ItemProperty -Path $IpAllPath -Name TcpDynamicPorts -Value ""
    Set-ItemProperty -Path $IpAllPath -Name TcpPort -Value "1433"

    Write-LogMessage "TCP/IP enabled and port 1433 configured: $regPath" "SUCCESS"
} else {
    Write-LogMessage "Failed to configure TCP/IP at $regPath : $($_.Exception.Message)" "WARN"
}

if (-not $FoundPath) {
        Write-LogMessage "Could not configure TCP/IP via registry" "WARN"
}

# ------------------------------
# 3.4 Configure SQL Server Service
# ------------------------------
try {
    Set-Service -Name $SqlService.Name -StartupType Automatic

    # Disable delayed auto-start (set to 0)
    $regKey = "HKLM:\SYSTEM\CurrentControlSet\Services\$($SqlService.Name)"
    if (Test-Path $regKey) {
        Set-ItemProperty -Path $regKey -Name "DelayedAutoStart" -Value 0
    }
    Write-LogMessage "SQL Service configured for automatic startup" "SUCCESS"

    if ($SqlService.Status -ne "Running") {
        Write-Output ">>> Starting SQL Server service: $SqlService"
        Start-Service -Name $SqlService.Name
        Wait-ForService -ServiceName $SqlService.Name -TimeoutSeconds 60
    }
} catch {
    Write-LogMessage "Failed to configure service startup: $($_.Exception.Message)" "WARN"
}

# Restart SQL Server service to apply changes
Write-LogMessage "Restarting SQL Server to apply configuration changes..." "INFO"
Restart-Service -Name $SqlService.Name -Force
Wait-ForService -ServiceName $SqlService.Name -TimeoutSeconds 60

# ------------------------------
# 4. Install SSMS
# ------------------------------
Write-LogMessage "Checking if SQL Server Management Studio (SSMS) is installed..." "INFO"

$possiblePaths = @(
    "C:\Program Files\Microsoft SQL Server Management Studio*",
    "C:\Program Files (x86)\Microsoft SQL Server Management Studio*",
    "C:\Program Files\Microsoft SQL Server\*\Tools\Binn\ManagementStudio",
    "C:\Program Files (x86)\Microsoft SQL Server\*\Tools\Binn\ManagementStudio"
)

$ssmsExe = Get-ChildItem $possiblePaths -Recurse -Include "ssms.exe" -ErrorAction SilentlyContinue | 
            Select-Object -First 1

if ($ssmsExe) {
    # Write-LogMessage "SSMS is already installed at: $($ssmsExe.FullName)" "SUCCESS"
    Write-LogMessage "SSMS is already installed" "SUCCESS"
}
else {
    Write-LogMessage "SSMS not found, attempting installation..." "INFO"

    $SsmsInstaller = Join-Path $InstallerPath $SsmsExe
    if (!(Test-Path $SsmsInstaller)) { 
        Write-LogMessage "SSMS installer not found, skipping: $SsmsInstaller" "WARN"
    } else {
        Start-Process -FilePath $SsmsInstaller -ArgumentList "/install /quiet /norestart" -Wait
        Write-LogMessage "SSMS installation completed." "SUCCESS"
    }
}

# ------------------------------
# 4.1 Ensure SQLCMD is in PATH
# ------------------------------
# $SqlCmdPath = "C:\Program Files\Microsoft SQL Server\Client SDK\ODBC\170\Tools\Binn"
# if (Test-Path $SqlCmdPath) {
#     $envPath = [System.Environment]::GetEnvironmentVariable("Path", "Machine")
#     if ($envPath -notlike "*$SqlCmdPath*") {
#         [System.Environment]::SetEnvironmentVariable("Path", $envPath + ";$SqlCmdPath", "Machine")
#     }
#     $env:Path += ";$SqlCmdPath"
# } else {
#     Write-Warning "SQLCMD tools not found. Ensure SQL Server Client Tools installed!"
# }

# ------------------------------
# 5. Deploy SailPoint IIQ
# ------------------------------
Write-LogMessage "Deploying IdentityIQ WAR..." "INFO"

$IIQZip = Join-Path $InstallerPath "identityiq-$IiqVersion.zip"
Test-FileExists $IIQZip "IdentityIQ ZIP"

$IIQPath = Join-Path $InstallerPath "identityiq-$IiqVersion"

# Clean extraction
if (Test-Path $IIQPath) {
    Remove-Item -Recurse -Force $IIQPath
}

# Extract ZIP
Expand-Archive -Path $IIQZip -DestinationPath $IIQPath -Force
Test-FileExists $IiqWar "IdentityIQ WAR"

# Clean previous deployment
$webappsPath = "$TomcatPath\webapps"
$iiqWebappPath = "$webappsPath\identityiq"

if (Test-Path "$webappsPath\identityiq.war") {
    Remove-Item "$webappsPath\identityiq.war" -Force
}
if (Test-Path $iiqWebappPath) {
    Remove-Item -Recurse -Force $iiqWebappPath
}

# Deploy WAR
$deployedWar = "$webappsPath\identityiq.war"
Copy-Item $IiqWar $deployedWar -Force
Write-LogMessage "WAR file deployed to Tomcat" "SUCCESS"

# Extract WAR
New-Item -Path $iiqWebappPath -ItemType Directory -Force | Out-Null
Push-Location $iiqWebappPath
try {
    & "$JavaPath\bin\jar.exe" -xf $deployedWar
    Write-LogMessage "WAR file extracted for configuration" "SUCCESS"
}
finally {
    Pop-Location
}

# Delete WAR after extraction
if (Test-Path $deployedWar) {
    Remove-Item $deployedWar -Force
    Write-LogMessage "WAR file removed after extraction" "INFO"
}

# ------------------------------
# 5.1 Add SQL Server JDBC Driver
# ------------------------------
Write-LogMessage "Adding SQL Server JDBC Driver..." "INFO"
Test-FileExists $JdbcDriver "SQL Server JDBC Driver"

$LibPath = "$iiqWebappPath\WEB-INF\lib"
Copy-Item $JdbcDriver $LibPath -Force
Write-LogMessage "JDBC driver copied to application lib directory" "SUCCESS"

# ------------------------------
# 5.2 Modify IdentityExtended.hbm.xml
# ------------------------------
Write-LogMessage "Modifying IdentityExtended.hbm.xml..." "INFO"

$IdentityExtendedHbmPath = "$iiqWebappPath\WEB-INF\classes\sailpoint\object\IdentityExtended.hbm.xml"
Test-FileExists $IdentityExtendedHbmPath "IdentityExtended.hbm.xml"

try {
    $fileContent = Get-Content $IdentityExtendedHbmPath -Raw
    $modified = $false

    # Define the properly formatted extended properties (what we want as final result)
    $extendedProperties = @"
    <property name="extended11" type="string" length="450"/>
    <property name="extended12" type="string" length="450"/>
    <property name="extended13" type="string" length="450"/>
    <property name="extended14" type="string" length="450"/>
    <property name="extended15" type="string" length="450"/>
    <property name="extended16" type="string" length="450"/>
    <property name="extended17" type="string" length="450"/>
    <property name="extended18" type="string" length="450"/>
    <property name="extended19" type="string" length="450"/>
    <property name="extended20" type="string" length="450"/>
"@

    # Regex to catch multi-line comment block that starts with <!-- and ends with -->
    $pattern = '(?s)<!--\s*\r?\n\s*<property name="extended11".*?<property name="extended20".*?\r?\n\s*-->'

    if ($fileContent -match $pattern) {
        Write-LogMessage "Found commented extended11–20 block. Replacing..." "INFO"

        $newContent = [regex]::Replace($fileContent, $pattern, $extendedProperties)

        $Utf8NoBomEncoding = New-Object System.Text.UTF8Encoding($false)
        [System.IO.File]::WriteAllText($IdentityExtendedHbmPath, $newContent, $Utf8NoBomEncoding)

        Write-LogMessage "Extended properties 11-20 successfully uncommented and formatted" "SUCCESS"
        $modified = $true
    }

    if (-not $modified) {
        if ($hasExtended11to20) {
            Write-LogMessage "Extended properties 11-20 already uncommented" "INFO"
        } else {
            Write-LogMessage "No commented extended properties block found to modify" "WARN"
        }
    }
}
catch {
    Write-LogMessage "Failed to modify IdentityExtended.hbm.xml: $($_.Exception.Message)" "ERROR"
    if ($backupPath) {
        Copy-Item $backupPath $IdentityExtendedHbmPath -Force
        Write-LogMessage "Restored from backup: $backupPath" "INFO"
    }
    throw
}

# ------------------------------
# 6. Create IIQ Database Schema
# ------------------------------
Write-LogMessage "Creating IdentityIQ Database Schema..." "INFO"

# Ensure SQL Server is ready
if ($SqlService.Status -ne "Running") {
    Start-Service -Name $SqlService.Name
    Wait-ForService -ServiceName $SqlService.Name -TimeoutSeconds 60
}

# Pre-cleanup with enhanced error handling
Write-LogMessage "Cleaning up existing IdentityIQ databases..." "INFO"

# Pre-cleanup: Drop old DBs + logins if they exist
$CleanupSql = @"
-- Set databases to single user mode and drop them
DECLARE @DatabaseName NVARCHAR(128)
DECLARE @SQL NVARCHAR(MAX)

-- List of databases to clean up
DECLARE db_cursor CURSOR FOR 
SELECT name FROM sys.databases WHERE name IN ('identityiq', 'identityiqah', 'identityiqPlugin')

OPEN db_cursor
FETCH NEXT FROM db_cursor INTO @DatabaseName

WHILE @@FETCH_STATUS = 0
BEGIN
    BEGIN TRY
        SET @SQL = 'ALTER DATABASE [' + @DatabaseName + '] SET SINGLE_USER WITH ROLLBACK IMMEDIATE'
        EXEC sp_executesql @SQL
        
        SET @SQL = 'DROP DATABASE [' + @DatabaseName + ']'
        EXEC sp_executesql @SQL
        
        PRINT 'Successfully dropped database: ' + @DatabaseName
    END TRY
    BEGIN CATCH
        PRINT 'Error dropping database ' + @DatabaseName + ': ' + ERROR_MESSAGE()
    END CATCH
    
    FETCH NEXT FROM db_cursor INTO @DatabaseName
END

CLOSE db_cursor
DEALLOCATE db_cursor

-- Clean up logins
IF EXISTS (SELECT name FROM sys.sql_logins WHERE name = N'identityiq')
    DROP LOGIN [identityiq];
IF EXISTS (SELECT name FROM sys.sql_logins WHERE name = N'identityiqah')
    DROP LOGIN [identityiqah];
IF EXISTS (SELECT name FROM sys.sql_logins WHERE name = N'identityiqPlugin')
    DROP LOGIN [identityiqPlugin];

PRINT 'Database cleanup completed successfully'
"@

$CleanupFile = "$InstallerPath\cleanup_identityiq.sql"
Set-Content -Path $CleanupFile -Value $CleanupSql -Encoding UTF8

# Execute cleanup with connection preference
$cleanupSuccess = $false
try {
    & sqlcmd -S $SqlInstance -U sa -P $SqlSaPassword -i $CleanupFile -b
    if ($LASTEXITCODE -eq 0) {
        Write-LogMessage "Database cleanup completed with sa login" "SUCCESS"
        $cleanupSuccess = $true
    }
}
catch {
    Write-LogMessage "Cleanup with sa failed: $($_.Exception.Message)" "WARN"
}

if (-not $cleanupSuccess) {
    try {
        & sqlcmd -S $SqlInstance -E -i $CleanupFile -b
        if ($LASTEXITCODE -eq 0) {
            Write-LogMessage "Database cleanup completed with Windows Authentication" "SUCCESS"
            $cleanupSuccess = $true
        }
    }
    catch {
        Write-LogMessage "Cleanup with Windows Auth failed: $($_.Exception.Message)" "WARN"
    }
}

if (-not $cleanupSuccess) {
    Write-LogMessage "Database cleanup failed - proceeding with schema creation anyway" "WARN"
}

# Generate IdentityIQ schema
Write-LogMessage "Generating IdentityIQ database schema..." "INFO"

Push-Location "$iiqWebappPath\WEB-INF\bin"
try {
    & ".\iiq.bat" schema
    
    $SQLScript = "$iiqWebappPath\WEB-INF\database\create_identityiq_tables.sqlserver"
    Test-FileExists $SQLScript "Generated SQL schema file"
    
    # Enhanced password patching with validation
    $originalScript = Get-Content $SQLScript -Raw
    $patchedScript = $originalScript -replace "PASSWORD='identityiq'", "PASSWORD='$SqlSaPassword'" `
                                      -replace "PASSWORD='identityiqah'", "PASSWORD='$SqlSaPassword'" `
                                      -replace "PASSWORD='identityiqPlugin'", "PASSWORD='$SqlSaPassword'"
    
    # Verify patches were applied
    $passwordCount = ($patchedScript | Select-String "PASSWORD='$SqlSaPassword'" -AllMatches).Matches.Count
    Write-LogMessage "Applied password patches to $passwordCount locations in schema script" "INFO"
    
    $TempScript = "$InstallerPath\create_identityiq_tables_patched.sql"
    Set-Content -Path $TempScript -Value $patchedScript -Encoding UTF8
    
    Write-LogMessage "Enhanced schema script created: $TempScript" "SUCCESS"
    
    # Execute schema creation with retry logic
    $schemaSuccess = $false
    $maxRetries = 2

    for ($retry = 1; $retry -le $maxRetries; $retry++) {
        Write-LogMessage "Executing schema creation (attempt $retry/$maxRetries)..." "INFO"
        
        # Try sa first if available
        if (Test-SqlConnection -ServerInstance $SqlInstance -Username "sa" -Password $SqlSaPassword) {
            try {
                & sqlcmd -S $SqlInstance -U sa -P $SqlSaPassword -i $TempScript -b -t 300
                if ($LASTEXITCODE -eq 0) {
                    Write-LogMessage "Schema created successfully with sa authentication" "SUCCESS"
                    $schemaSuccess = $true
                    break
                } else {
                    throw "sqlcmd exited with code: $LASTEXITCODE"
                }
            }
            catch {
                Write-LogMessage "Schema creation with sa failed (attempt $retry): $($_.Exception.Message)" "WARN"
            }
        }
        
        # Fallback to Windows Authentication
        if (-not $schemaSuccess -and (Test-SqlConnection -ServerInstance $SqlInstance -WindowsAuth)) {
            try {
                & sqlcmd -S $SqlInstance -E -i $TempScript -b -t 300
                if ($LASTEXITCODE -eq 0) {
                    Write-LogMessage "Schema created successfully with Windows Authentication" "SUCCESS"
                    $schemaSuccess = $true
                    break
                } else {
                    throw "sqlcmd exited with code: $LASTEXITCODE"
                }
            }
            catch {
                Write-LogMessage "Schema creation with Windows Auth failed (attempt $retry): $($_.Exception.Message)" "WARN"
            }
        }
        
        if ($retry -lt $maxRetries) {
            Write-LogMessage "Waiting before retry..." "INFO"
            Start-Sleep -Seconds 10
        }
    }
    
    if (-not $schemaSuccess) {
        throw "Failed to create database schema after $maxRetries attempts"
    }
    
    # Verify database creation
    $verificationQuery = "SELECT name FROM sys.databases WHERE name IN ('identityiq', 'identityiqah', 'identityiqPlugin')"
    
    if (Test-SqlConnection -ServerInstance $SqlInstance -Username "sa" -Password $SqlSaPassword) {
        $databases = & sqlcmd -S $SqlInstance -U sa -P $SqlSaPassword -Q $verificationQuery -h -1 -W
    } else {
        $databases = & sqlcmd -S $SqlInstance -E -Q $verificationQuery -h -1 -W
    }
    
    $dbCount = ($databases | Where-Object { $_.Trim() -in @('identityiq', 'identityiqah', 'identityiqPlugin') }).Count
    Write-LogMessage "Verified $dbCount IdentityIQ databases created successfully" "SUCCESS"
}
finally {
    Pop-Location
}

# ------------------------------
# 7. Encrypt Passwords
# ------------------------------
Write-LogMessage "Encrypting database passwords..." "INFO"

Push-Location "$iiqWebappPath\WEB-INF\bin"
try {    
    # Run encryption with detailed logging
    $process = Start-Process -FilePath "$iiqWebappPath\WEB-INF\bin\iiq.bat" `
        -ArgumentList "encrypt $SqlSaPassword" -NoNewWindow -RedirectStandardOutput "$InstallerPath\identityiq.enc" -PassThru -Wait
    
    if ($process.ExitCode -ne 0) {
        throw "Password encryption process failed with exit code: $($process.ExitCode)"
    }
    
    # Extract encrypted value with better error handling
    $encOutput = Get-Content "$InstallerPath\identityiq.enc" -ErrorAction Stop
    $encryptedLine = $encOutput | Where-Object { $_ -like "*1:ACP:*" } | Select-Object -First 1
    
    if (-not $encryptedLine) {
        Write-LogMessage "Encryption output for debugging:" "WARN"
        $encOutput | ForEach-Object { Write-LogMessage $_ "INFO" }
        throw "Could not find encrypted password in output"
    }
    
    $EncryptedPassword = $encryptedLine.Trim()
    Write-LogMessage "Password encrypted successfully" "SUCCESS"
    
    # Store encrypted passwords for all databases
    $EncPasswords = @{
        "identityiq" = $EncryptedPassword
        "identityiqah" = $EncryptedPassword  
        "identityiqPlugin" = $EncryptedPassword
    }
    
}
catch {
    Write-LogMessage "Password encryption failed: $($_.Exception.Message)" "ERROR"
    throw
}
finally {
    Pop-Location
}

# ------------------------------
# 8. iiq.properties Configuration
# ------------------------------
Write-LogMessage "Configuring iiq.properties..." "INFO"

$IiqProps = "$iiqWebappPath\WEB-INF\classes\iiq.properties"
Test-FileExists $IiqProps "iiq.properties file"

# Load file content
$props = Get-Content $IiqProps

# 1. Update encrypted passwords
$props = $props | ForEach-Object {
    $_ -replace "dataSource.password=.*", "dataSource.password=$($EncPasswords['identityiq'])" `
       -replace "pluginsDataSource.password=.*", "pluginsDataSource.password=$($EncPasswords['identityiqPlugin'])" `
       -replace "dataSourceAccessHistory.password=.*", "dataSourceAccessHistory.password=$($EncPasswords['identityiqah'])"
}

# 2. Comment out unwanted MySQL
$patternsToComment = @(
    "dataSource.url=jdbc:mysql://localhost/identityiq?useServerPrepStmts=true&tinyInt1isBit=true&useSSL=false&characterEncoding=UTF-8&serverTimezone=UTC",
    "dataSource.driverClassName=com.mysql.cj.jdbc.Driver",
    "sessionFactory.hibernateProperties.hibernate.dialect=org.hibernate.dialect.MySQL57Dialect",
    "activeMQMessageServiceManager.activemqJdbcAdapter=org.apache.activemq.store.jdbc.adapter.MySqlJDBCAdapter",
    "pluginsDataSource.url=jdbc:mysql://localhost/identityiqPlugin?useServerPrepStmts=true&tinyInt1isBit=true&useSSL=false&characterEncoding=UTF-8&serverTimezone=UTC",
    "pluginsDataSource.driverClassName=com.mysql.cj.jdbc.Driver",
    "dataSourceAccessHistory.url=jdbc:mysql://localhost/identityiqah?useServerPrepStmts=true&tinyInt1isBit=true&useSSL=false&characterEncoding=UTF-8&serverTimezone=UTC",
    "dataSourceAccessHistory.driverClassName=com.mysql.cj.jdbc.Driver",
    "sessionFactoryAccessHistory.hibernateProperties.hibernate.dialect=org.hibernate.dialect.MySQL57Dialect"
)

$props = $props | ForEach-Object {
    $line = $_
    foreach ($pat in $patternsToComment) {
        if ($line -match [regex]::Escape($pat)) {
            if ($line -notmatch "^\s*#") { $line = "#" + $line.TrimStart() }
        }
    }
    $line
}

# 3. Uncomment specific SQL Server lines
$patternsToUncomment = @(
    "#dataSourceAccessHistory.url=jdbc:sqlserver://localhost:1433;databaseName=identityiqah;",
    "#dataSourceAccessHistory.driverClassName=com.microsoft.sqlserver.jdbc.SQLServerDriver",
    "#sessionFactoryAccessHistory.hibernateProperties.hibernate.dialect=sailpoint.persistence.SQLServerUnicodeDialect",
    "#pluginsDataSource.url=jdbc:sqlserver://localhost:1433;databaseName=identityiqPlugin",
    "#pluginsdataSource.driverClassName=com.microsoft.sqlserver.jdbc.SQLServerDriver",
    "#dataSource.url=jdbc:sqlserver://localhost:1433;databaseName=identityiq;",
    "#dataSource.driverClassName=com.microsoft.sqlserver.jdbc.SQLServerDriver",
    "#sessionFactory.hibernateProperties.hibernate.dialect=sailpoint.persistence.SQLServerUnicodeDialect",
    "#scheduler.quartzProperties.org.quartz.jobStore.driverDelegateClass=org.quartz.impl.jdbcjobstore.MSSQLDelegate",
    "#scheduler.quartzProperties.org.quartz.jobStore.selectWithLockSQL=SELECT * FROM {0}LOCKS UPDLOCK WHERE LOCK_NAME = ?",
    "#activeMQMessageServiceManager.activemqJdbcAdapter=org.apache.activemq.store.jdbc.adapter.TransactJDBCAdapter"
)

$props = $props | ForEach-Object {
    $line = $_
    foreach ($pat in $patternsToUncomment) {
        if ($line -match "^$([Regex]::Escape($pat))") {
            $line = $line.TrimStart("#")
        }
    }
    $line
}

# 4. Save back
$Utf8NoBomEncoding = New-Object System.Text.UTF8Encoding($false)
[System.IO.File]::WriteAllLines($IiqProps, $props, $Utf8NoBomEncoding)

Write-LogMessage "iiq.properties updated successfully" "SUCCESS"

# ------------------------------
# 9. Apply Branding Application
# ------------------------------
Write-LogMessage "Applying SailPoint IIQ branding customizations..." "INFO"

if (Test-Path $BrandingPath) {
    try {
        # 1. Copy ui-custom.css
        $UiCssSource = Join-Path $BrandingPath "Style\ui-custom.css"
        $UiCssTarget = "$iiqWebappPath\ui\css\ui-custom.css"
        if (Test-Path $UiCssSource) {
            Copy-Item $UiCssSource $UiCssTarget -Force
            Write-LogMessage "ui-custom.css applied" "SUCCESS"
        } else {
            Write-LogMessage "ui-custom.css not found at: $UiCssSource" "WARN"
        }

        # 2. Copy iiq-custom.css
        $IiqCssSource = Join-Path $BrandingPath "Style\iiq-custom.css"
        $IiqCssTarget = "$iiqWebappPath\css\iiq-custom.css"
        if (Test-Path $IiqCssSource) {
            Copy-Item $IiqCssSource $IiqCssTarget -Force
            Write-LogMessage "iiq-custom.css applied" "SUCCESS"
        } else {
            Write-LogMessage "iiq-custom.css not found at: $IiqCssSource" "WARN"
        }

        # 3. Copy icons with verification
        $IconsSource = Join-Path $BrandingPath "Icons"
        $IconsTarget = "$iiqWebappPath\ui\images"
        if (Test-Path $IconsSource) {
            $iconFiles = Get-ChildItem $IconsSource -File
            foreach ($icon in $iconFiles) {
                Copy-Item $icon.FullName $IconsTarget -Force
            }
            Write-LogMessage "Applied $($iconFiles.Count) branding icons" "SUCCESS"
        } else {
            Write-LogMessage "Icons directory not found at: $IconsSource" "WARN"
        }

        Write-LogMessage "Branding application completed" "SUCCESS"
    }
    catch {
        Write-LogMessage "Branding application failed: $($_.Exception.Message)" "WARN"
    }
} else {
    Write-LogMessage "Branding path not found: $BrandingPath" "WARN"
}

# ------------------------------
# 10. Auto Import Core XMLs
# ------------------------------
Write-LogMessage "Importing IdentityIQ core XML files..." "INFO"

$ConsoleCommands = @"
import init.xml
import init-lcm.xml
import rapidsetup.xml
quit
"@
$ConsoleFile = "$InstallerPath\console.txt"
$ConsoleCommands | Out-File $ConsoleFile -Encoding ASCII

# Full path to iiq.bat
$iiqBat = "$iiqWebappPath\WEB-INF\bin\iiq.bat"

if (Test-Path $iiqBat) {
    cmd.exe /c "`"$iiqBat`" console < `"$ConsoleFile`""
    Write-LogMessage "XML import process completed" "SUCCESS"
}
else {
    Write-LogMessage "iiq.bat not found at $iiqBat" "ERROR"
}

# ------------------------------
# 11. Final System Restart and Validation
# ------------------------------
Write-LogMessage "Performing final system restart and validation..." "INFO"
    
Restart-Service -Name "Tomcat9" -Force
Wait-ForService -ServiceName "Tomcat9" -TimeoutSeconds 60

# Final application health check
$healthCheckPassed = $false
$maxHealthCheckWait = 180 # 3 minutes
$healthCheckWaited = 0

Write-LogMessage "Performing application health check..." "INFO"

while (-not $healthCheckPassed -and $healthCheckWaited -lt $maxHealthCheckWait) {
    Start-Sleep -Seconds 10
    $healthCheckWaited += 10
    
    try {
        $response = Invoke-WebRequest -Uri "http://localhost:8080/identityiq" -TimeoutSec 15 -UseBasicParsing
        if ($response.StatusCode -eq 200) {
            Write-LogMessage "IdentityIQ application health check passed" "SUCCESS"
            $healthCheckPassed = $true
        } elseif ($response.StatusCode -eq 302) {
            Write-LogMessage "IdentityIQ application is redirecting (likely to login) - this is normal" "SUCCESS"
            $healthCheckPassed = $true
        }
    }
    catch {
        Write-LogMessage "Health check in progress... ($healthCheckWaited/$maxHealthCheckWait seconds)" "INFO"
    }
}

if (-not $healthCheckPassed) {
    Write-LogMessage "Application health check did not pass within timeout - manual verification recommended" "WARN"
}

# ------------------------------
# 12. Browser Cache Cleanup
# ------------------------------
Write-LogMessage "Clearing browser caches..." "INFO"

# Google Chrome
$ChromeCache = "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Cache"
if (Test-Path $ChromeCache) {
    Remove-Item -Recurse -Force -ErrorAction SilentlyContinue $ChromeCache
    Write-LogMessage ">>> Chrome cache cleared." "INFO"
}

# Microsoft Edge
$EdgeCache = "$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default\Cache"
if (Test-Path $EdgeCache) {
    Remove-Item -Recurse -Force -ErrorAction SilentlyContinue $EdgeCache
    Write-LogMessage ">>> Edge cache cleared." "INFO"
}

# Mozilla Firefox
$FirefoxProfiles = Get-ChildItem "$env:APPDATA\Mozilla\Firefox\Profiles" -Directory -ErrorAction SilentlyContinue
foreach ($Profile in $FirefoxProfiles) {
    $FirefoxCache = Join-Path $Profile.FullName "cache2"
    if (Test-Path $FirefoxCache) {
        Remove-Item -Recurse -Force -ErrorAction SilentlyContinue $FirefoxCache
        Write-LogMessage ">>> Firefox cache cleared for profile $($Profile.Name)." "INFO"
    }
}

Write-LogMessage ">>> Browser cache cleanup completed." "SUCCESS"

# ------------------------------
# 13. Installation Summary and Completion
# ------------------------------
Write-LogMessage "Installation Completed" "SUCCESS"
Write-Output ">>> Opening: http://localhost:8080/identityiq"
Write-Output ">>> Default Login: spadmin / admin"

# Launch browser based on default browser
try {
    $url = "http://localhost:8080/identityiq"
    $defaultBrowserProgId = (Get-ItemProperty "HKCU:\Software\Microsoft\Windows\Shell\Associations\UrlAssociations\http\UserChoice" -ErrorAction SilentlyContinue).ProgId
    
    if ($defaultBrowserProgId) {
        switch -Wildcard ($defaultBrowserProgId) {
            "*Chrome*" {
                Start-Process "chrome.exe" -ArgumentList "--incognito $url"
                Write-LogMessage "Launched Chrome in incognito mode" "SUCCESS"
            }
            "*Edge*" {
                Start-Process "msedge.exe" -ArgumentList "--inprivate $url"
                Write-LogMessage "Launched Edge in private mode" "SUCCESS"
            }
            "*Firefox*" {
                Start-Process "firefox.exe" -ArgumentList "-private-window $url"
                Write-LogMessage "Launched Firefox in private mode" "SUCCESS"
            }
            default {
                Start-Process $url
                Write-LogMessage "Launched default browser" "SUCCESS"
            }
        }
    } else {
        Start-Process $url
        Write-LogMessage "Launched default browser" "SUCCESS"
    }
}
catch {
    Write-LogMessage "Could not automatically launch browser: $($_.Exception.Message)" "WARN"
    Write-LogMessage "Please manually navigate to: http://localhost:8080/identityiq" "INFO"
}

Write-LogMessage "=== IdentityIQ $IiqVersion Installation Completed Successfully! ===" "SUCCESS"
Write-LogMessage "Installation completed in $([math]::Round((Get-Date).Subtract($InstallStartTime).TotalMinutes, 2)) minutes" "INFO"

# Stop Logging
Stop-Transcript
Write-LogMessage ">>> Full log saved to $LogFile" "INFO"