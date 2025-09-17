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
$SqlExe        = "SQL2022-SSEI-Expr.exe"   # Online installer (small EXE ~ 7MB)
$SqlSetupExe   = "SQLEXPR_x64_ENU.exe"     # Offline installer main setup file
$SsmsExe       = "vs_SSMS.exe"
$SqlSaPassword = "P@ssw0rd@#123"

# Tomcat Memory Configuration
$InitialMemory = "4096"   # Initial memory pool in MB
$MaximumMemory = "6000"   # Maximum memory pool in MB

# ------------------------------
# 0. Pre-configuration
# ------------------------------

# Ensure installer path exists
if (!(Test-Path $InstallerPath)) {
    Write-Error "Installer path $InstallerPath not found. Please place installers first."
    exit 1
}

# Ensure have admin rights
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Error "You must run this script as Administrator!"
    exit 1
}

# Centralized Logging
$LogFile = "$InstallerPath\IIQ_Install.log"
Start-Transcript -Path $LogFile -Append
# (all script output will now be logged until Stop-Transcript)

# ------------------------------
# 1. Install JDK 17
# ------------------------------
Write-Output ">>> Installing JDK..."
$JdkInstaller = Join-Path $InstallerPath "jdk-17.0.15_windows-x64_bin.exe"
if (!(Test-Path $JdkInstaller)) {
    Write-Error "JDK installer missing!";
    exit 1
}

Start-Process -FilePath $JdkInstaller -ArgumentList "/s" -Wait

# Set JAVA_HOME and PATH (permanent)
$envPath = [System.Environment]::GetEnvironmentVariable("Path", "Machine")
if ($envPath -notlike "*$JavaPath\bin*") {
    [System.Environment]::SetEnvironmentVariable("JAVA_HOME", $JavaPath, "Machine")
    [System.Environment]::SetEnvironmentVariable("Path", $envPath + ";$JavaPath\bin", "Machine")
}
$env:JAVA_HOME = $JavaPath
$env:Path += ";$JavaPath\bin"

# ------------------------------
# 2. Install Tomcat
# ------------------------------
Write-Output ">>> Installing Tomcat..."
$TomcatZip = Join-Path $InstallerPath "apache-tomcat-9.0.109-windows-x64.zip"
if (!(Test-Path $TomcatZip)) {
    Write-Error "Tomcat ZIP missing!"; 
    exit 1 
}

# Clean old Tomcat if exists
if (Test-Path "$TomcatRoot\tomcat") {
    Write-Output ">>> Removing old Tomcat installation..."
    if (Get-Service -Name "Tomcat9" -ErrorAction SilentlyContinue) {
        Stop-Service -Name "Tomcat9" -Force
    }
    Remove-Item -Recurse -Force "$TomcatRoot\tomcat"
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
    cmd.exe /c "cd /d `"$TomcatPath\bin`" && service.bat install Tomcat9"
    Start-Sleep -Seconds 5
} else {
    Write-Output ">>> Tomcat9 service already exists. Skipping installation."
}

# Configure JVM Memory Settings for Tomcat Service
Write-Output ">>> Configuring JVM memory settings (Initial: ${InitialMemory}MB, Maximum: ${MaximumMemory}MB)..."
$TomcatExe = "$TomcatPath\bin\tomcat9.exe"

if (Test-Path $TomcatExe) {
    # Stop the service if running
    if (Get-Service -Name "Tomcat9" -ErrorAction SilentlyContinue) {
        Stop-Service -Name "Tomcat9" -Force -ErrorAction SilentlyContinue
        Start-Sleep -Seconds 3
    }
    
    # Configure JVM options using tomcat9w.exe (GUI configuration tool via command line)
    try {
        # Set Initial Memory Pool (Xms)
        & "$TomcatPath\bin\tomcat9.exe" //US//Tomcat9 --JvmMs=$InitialMemory
        
        # Set Maximum Memory Pool (Xmx)
        & "$TomcatPath\bin\tomcat9.exe" //US//Tomcat9 --JvmMx=$MaximumMemory      
        
        Write-Output ">>> JVM memory settings configured successfully!"
        Write-Output "    Initial Memory: ${InitialMemory}MB"
        Write-Output "    Maximum Memory: ${MaximumMemory}MB"
    }
    catch {
        Write-Warning "Failed to configure JVM settings via tomcat9.exe: $($_.Exception.Message)"
        Write-Output ">>> Attempting alternative configuration method..."
        
        # Alternative method: Modify registry directly
        $TomcatRegistryPath = "HKLM:\SOFTWARE\Apache Software Foundation\Procrun 2.0\Tomcat9\Parameters\Java"
        if (Test-Path $TomcatRegistryPath) {
            try {
                Set-ItemProperty -Path $TomcatRegistryPath -Name "JvmMs" -Value $InitialMemory
                Set-ItemProperty -Path $TomcatRegistryPath -Name "JvmMx" -Value $MaximumMemory
                Write-Output ">>> JVM memory settings configured via registry!"
            }
            catch {
                Write-Error "Failed to configure JVM settings via registry: $($_.Exception.Message)"
            }
        }
    }
} else {
    Write-Warning "tomcat9.exe not found. Memory settings may need to be configured manually."
}

# Start Tomcat service if installed
if (Get-Service -Name "Tomcat9" -ErrorAction SilentlyContinue) {
    Set-Service -Name "Tomcat9" -StartupType Automatic
    Start-Service -Name "Tomcat9"
    Write-Output ">>> Tomcat9 service started successfully!"
} else {
    Write-Error "Tomcat9 service was not created. Check JAVA_HOME / CATALINA_HOME."
    exit 1
}

Start-Process "http://localhost:8080"

# ------------------------------
# 3. Install SQL Server
# ------------------------------
Write-Output ">>> Installing SQL Server..."
$SqlInstaller = Join-Path $InstallerPath $SqlExe
if (!(Test-Path $SqlInstaller)) { 
    Write-Error "SQL Server installer missing!"; 
    exit 1 
}

Start-Process -FilePath $SqlInstaller -ArgumentList "/qs /x:$InstallerPath\SQLSetup" -Wait

# ------------------------------
# 3.0 Ensure SQLCMD is available (MOVED UP)
# ------------------------------
Write-Output ">>> Setting up SQLCMD tools..."

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
        Write-Output ">>> Found SQLCMD at: $path"
        
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
    Write-Warning ">>> SQLCMD not found. Installing SQL Server Command Line Utilities..."
    
    # Download and install SQL Server Command Line Utilities if not found
    $SqlCmdInstaller = "https://go.microsoft.com/fwlink/?linkid=2230791"  # SQL Server 2022 Command Line Utilities
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
                break
            }
        }
    }
    catch {
        Write-Error "Failed to download/install SQL Server Command Line Utilities: $($_.Exception.Message)"
    }
}

if (-not $SqlCmdFound) {
    Write-Error "SQLCMD could not be found or installed. Please install SQL Server Command Line Utilities manually."
    exit 1
}

# Test sqlcmd availability
try {
    $null = & sqlcmd -?
    Write-Output ">>> SQLCMD is now available"
}
catch {
    Write-Error "SQLCMD still not accessible. Please check installation."
    exit 1
}

# ------------------------------
# 3.1 Enable sa login + set password
# ------------------------------

# Detect SQL Server service dynamically
$SqlService = Get-Service | Where-Object { $_.Name -like "MSSQL*" } | Select-Object -First 1
if (-not $SqlService) {
    Write-Error "No SQL Server service found! Did SQL Server install correctly?"
    exit 1
}

# Ensure service is running
if ($SqlService.Status -ne "Running") {
    Write-Output ">>> Starting SQL Server service: $($SqlService.Name)"
    Start-Service -Name $SqlService.Name
    Start-Sleep -Seconds 15
}

# Build instance connection string
$SqlInstance = if ($SqlService.Name -like "MSSQLSERVER") { "localhost" } else { "localhost\$($SqlService.Name -replace 'MSSQL\$', '')" }
Write-Output ">>> Using SQL Instance for sa enable: $SqlInstance"

# Enable sa login + set password using Windows Authentication (-E)
$EnableSaQuery = @"
ALTER LOGIN [sa] ENABLE;
ALTER LOGIN [sa] WITH PASSWORD = N'$SqlSaPassword' UNLOCK;
"@
& sqlcmd -S $SqlInstance -E -Q "$EnableSaQuery"

# ------------------------------
# 3.1.1 Enable Mixed Mode Authentication
# ------------------------------
Write-Output ">>> Enabling SQL Authentication (Mixed Mode)..."

# SQL instance name (from service name)
$SqlInstanceName = if ($SqlService.Name -like "MSSQLSERVER") { "MSSQLSERVER" } else { ($SqlService.Name -replace 'MSSQL\$', '') }

# Try SQL 2022 (MSSQL16) and SQL 2019 (MSSQL15) registry paths
$AuthRegPaths = @(
    "HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server\MSSQL16.$SqlInstanceName\MSSQLServer",
    "HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server\MSSQL15.$SqlInstanceName\MSSQLServer"
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
    Write-Output ">>> Mixed Mode Authentication enabled"
} else {
    Write-Warning ">>> Could not locate registry path to enable Mixed Mode. Check SQL version/instance."
}


# ------------------------------
# 3.2 Configure SQL Server Service
# ------------------------------
$ServiceName = 'MSSQL$SQLEXPRESS'

try {
    $svc = Get-Service -Name $ServiceName -ErrorAction Stop
    Write-Output ">>> Found service: $ServiceName"
    Set-Service -Name $ServiceName -StartupType Automatic

    # Disable delayed auto-start (set to 0)
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\$ServiceName" -Name DelayedAutoStart -Value 0

    Write-Output ">>> Changed $ServiceName to Automatic (not Delayed Start)."

    if ($svc.Status -ne "Running") {
        Write-Output ">>> Starting SQL Server service: $ServiceName"
        Start-Service -Name $ServiceName
        Start-Sleep -Seconds 10
    }
} catch {
    Write-Warning ">>> SQL Server service $ServiceName not found. Check if SQL Express installed."
}

# ------------------------------
# 3.3 Enable TCP/IP and configure port 1433
# ------------------------------
Write-Output ">>> Enabling TCP/IP and setting port 1433 for SQL Server..."

# SQL instance name (from service name)
$SqlInstanceName = if ($SqlService.Name -like "MSSQLSERVER") { "MSSQLSERVER" } else { ($SqlService.Name -replace 'MSSQL\$', '') }

# Try both SQL 2022 (MSSQL16) and SQL 2019 (MSSQL15) registry paths
$TcpRegPaths = @(
    "HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server\MSSQL16.$SqlInstanceName\MSSQLServer\SuperSocketNetLib\Tcp", # SQL 2022
    "HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server\MSSQL15.$SqlInstanceName\MSSQLServer\SuperSocketNetLib\Tcp"  # SQL 2019
)

$FoundPath = $null
foreach ($p in $TcpRegPaths) {
    if (Test-Path $p) {
        $FoundPath = $p
        break
    }
}

if ($FoundPath) {
    Write-Output ">>> Enabling TCP/IP..."

    # Enable TCP/IP globally
    Set-ItemProperty -Path $FoundPath -Name Enabled -Value 1

    # Configure IPAll
    $IpAllPath = "$FoundPath\IPAll"
    Set-ItemProperty -Path $IpAllPath -Name TcpDynamicPorts -Value ""
    Set-ItemProperty -Path $IpAllPath -Name TcpPort -Value "1433"

    Write-Output ">>> TCP/IP enabled and port 1433 set for IPAll."
} else {
    Write-Warning ">>> Could not find registry path for SQL TCP settings. Check SQL version/install."
}

# Restart SQL Server service to apply changes
Write-Output ">>> Restarting SQL Server service: $ServiceName"
Restart-Service -Name $ServiceName -Force
Start-Sleep -Seconds 10

# ------------------------------
# 4. Install SSMS
# ------------------------------
Write-Output ">>> Installing SQL Server Management Studio..."
$SsmsInstaller = Join-Path $InstallerPath $SsmsExe
if (!(Test-Path $SsmsInstaller)) { 
    Write-Warning "SSMS installer missing! Skipping..." 
}
else {
    Start-Process -FilePath $SsmsInstaller -ArgumentList "/install /quiet /norestart" -Wait
}

# ------------------------------
# 4.1 Ensure SQLCMD is in PATH
# ------------------------------
$SqlCmdPath = "C:\Program Files\Microsoft SQL Server\Client SDK\ODBC\170\Tools\Binn"
if (Test-Path $SqlCmdPath) {
    $envPath = [System.Environment]::GetEnvironmentVariable("Path", "Machine")
    if ($envPath -notlike "*$SqlCmdPath*") {
        [System.Environment]::SetEnvironmentVariable("Path", $envPath + ";$SqlCmdPath", "Machine")
    }
    $env:Path += ";$SqlCmdPath"
} else {
    Write-Warning "SQLCMD tools not found. Ensure SQL Server Client Tools installed!"
}

# ------------------------------
# 5. Deploy SailPoint IIQ
# ------------------------------
Write-Output ">>> Deploying IdentityIQ WAR..."

$IIQZip = Join-Path $InstallerPath "identityiq-$IiqVersion.zip"

if (!(Test-Path $IIQZip)) {
    Write-Error "IdentityIQ ZIP missing!"
    exit 1
}

$IIQPath = Join-Path $InstallerPath "identityiq-$IiqVersion"

# Extract ZIP
Expand-Archive -Path $IIQZip -DestinationPath $IIQPath -Force

if (!(Test-Path $IiqWar)) { 
    Write-Error "IdentityIQ WAR file missing!"; 
    exit 1 
}

# Deploy WAR
Copy-Item $IiqWar "$TomcatPath\webapps\identityiq.war" -Force

# Extract WAR
New-Item -Path "$TomcatPath\webapps\identityiq" -ItemType Directory -Force | Out-Null
cd "$TomcatPath\webapps\identityiq"
& "$JavaPath\bin\jar.exe" -xvf "$IiqWar" | Out-Null

# ------------------------------
# 5.1 Add SQL Server JDBC Driver
# ------------------------------
Write-Output ">>> Adding SQL Server JDBC Driver..."
if (!(Test-Path $JdbcDriver)) { 
    Write-Error "JDBC driver not found in $InstallerPath"; 
    exit 1 
}

$LibPath = "$TomcatPath\webapps\identityiq\WEB-INF\lib"
Copy-Item $JdbcDriver $LibPath -Force

# ------------------------------
# 6. Create IIQ Database Schema
# ------------------------------
Write-Output ">>> Creating IIQ Database Schema..."

# Detect SQL Server service
$SqlService = Get-Service | Where-Object { $_.Name -like "MSSQL*" } | Select-Object -First 1
if (-not $SqlService) {
    Write-Error "No SQL Server service found! Did SQL Server install correctly?"
    exit 1
}

# Start service if not running
if ($SqlService.Status -ne "Running") {
    Write-Output ">>> Starting SQL Server service: $($SqlService.Name)"
    Start-Service -Name $SqlService.Name
    Start-Sleep -Seconds 15
}

# Set instance connection string
$SqlInstance = if ($SqlService.Name -like "MSSQLSERVER") { "localhost" } else { "localhost\$($SqlService.Name -replace 'MSSQL\$', '')" }
Write-Output ">>> Using SQL Instance: $SqlInstance"

# Pre-cleanup: Drop old DBs + logins if they exist
$CleanupSql = @"
IF EXISTS (SELECT name FROM sys.databases WHERE name = N'identityiq')
BEGIN
    ALTER DATABASE [identityiq] SET SINGLE_USER WITH ROLLBACK IMMEDIATE;
    DROP DATABASE [identityiq];
END

IF EXISTS (SELECT name FROM sys.databases WHERE name = N'identityiqah')
BEGIN
    ALTER DATABASE [identityiqah] SET SINGLE_USER WITH ROLLBACK IMMEDIATE;
    DROP DATABASE [identityiqah];
END

IF EXISTS (SELECT name FROM sys.databases WHERE name = N'identityiqPlugin')
BEGIN
    ALTER DATABASE [identityiqPlugin] SET SINGLE_USER WITH ROLLBACK IMMEDIATE;
    DROP DATABASE [identityiqPlugin];
END

IF EXISTS (SELECT name FROM sys.sql_logins WHERE name = N'identityiq')
    DROP LOGIN [identityiq];
IF EXISTS (SELECT name FROM sys.sql_logins WHERE name = N'identityiqah')
    DROP LOGIN [identityiqah];
IF EXISTS (SELECT name FROM sys.sql_logins WHERE name = N'identityiqPlugin')
    DROP LOGIN [identityiqPlugin];
"@

$CleanupFile = "$InstallerPath\cleanup_identityiq.sql"
Set-Content -Path $CleanupFile -Value $CleanupSql -Encoding UTF8

Write-Output ">>> Dropping old IdentityIQ databases/logins if they exist..."
& sqlcmd -S $SqlInstance -U sa -P $SqlSaPassword -i $CleanupFile -b
if ($LASTEXITCODE -ne 0) {
    Write-Warning ">>> 'sa' login failed for cleanup. Retrying with Windows Authentication..."
    & sqlcmd -S $SqlInstance -E -i $CleanupFile -b
    if ($LASTEXITCODE -ne 0) {
        Write-Error "Cleanup failed with both 'sa' and Windows Authentication."
        exit 1
    }
}
Write-Output ">>> Cleanup completed."

# Run schema creation
Set-Location "$TomcatPath\webapps\identityiq\WEB-INF\bin"
& "$TomcatPath\webapps\identityiq\WEB-INF\bin\iiq.bat" schema

$SQLScript = "$TomcatPath\webapps\identityiq\WEB-INF\database\create_identityiq_tables.sqlserver"
$TempScript = "$InstallerPath\create_identityiq_tables_patched.sqlserver"

(Get-Content $SQLScript) |
ForEach-Object {
    $_ -replace "PASSWORD='identityiq'", "PASSWORD='$SqlSaPassword'" `
       -replace "PASSWORD='identityiqah'", "PASSWORD='$SqlSaPassword'" `
       -replace "PASSWORD='identityiqPlugin'", "PASSWORD='$SqlSaPassword'"
} | Set-Content $TempScript

Write-Output ">>> Patched schema script saved to $TempScript"

# Run patched schema creation script
Write-Output ">>> Running IIQ schema creation script with updated passwords..."
try {
    & sqlcmd -S $SqlInstance -U sa -P $SqlSaPassword -i $TempScript -b
    if ($LASTEXITCODE -eq 0) {
        Write-Output ">>> Schema created successfully with 'sa'."
    } else {
        throw "SA login failed."
    }
}
catch {
    Write-Warning ">>> 'sa' login failed. Retrying with Windows Authentication..."
    & sqlcmd -S $SqlInstance -E -i $TempScript -b
    if ($LASTEXITCODE -ne 0) {
        Write-Error "Schema creation failed with both 'sa' and Windows Authentication."
        exit 1
    }
    Write-Output ">>> Schema created successfully with Windows Authentication."
}

# ------------------------------
# 7. Encrypt Passwords
# ------------------------------
Write-Output ">>> Encrypting password..."
$Proc = Start-Process -FilePath "$TomcatPath\webapps\identityiq\WEB-INF\bin\iiq.bat" `
    -ArgumentList "encrypt $SqlSaPassword" -NoNewWindow -RedirectStandardOutput "$InstallerPath\identityiq.enc" -PassThru -Wait
$EncValue = Get-Content "$InstallerPath\identityiq.enc" | Select-String "1:ACP:" | ForEach-Object { $_.ToString().Trim() }
foreach ($db in @("identityiq","identityiqah","identityiqPlugin")) {
    $EncPasswords[$db] = $EncValue
}

# ------------------------------
# 8. Update iiq.properties
# ------------------------------
Write-Output ">>> Updating iiq.properties..."
$IiqProps = "$TomcatPath\webapps\identityiq\WEB-INF\classes\iiq.properties"

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
Write-Output ">>> iiq.properties updated successfully."

# ------------------------------
# 9. Apply Branding Customizations
# ------------------------------
Write-Output ">>> Applying SailPoint IIQ Branding..."

# 1. Copy ui-custom.css -> IIQ ui\css folder
$UiCssSource = Join-Path $BrandingPath "Style\ui-custom.css"
$UiCssTarget = "C:\SailPoint\tomcat\webapps\identityiq\ui\css\ui-custom.css"
if (Test-Path $UiCssSource) {
    Copy-Item $UiCssSource $UiCssTarget -Force
} else {
    Write-Warning "ui-custom.css not found at $UiCssSource"
}

# 2. Copy iiq-custom.css -> IIQ css folder
$IiqCssSource = Join-Path $BrandingPath "Style\iiq-custom.css"
$IiqCssTarget = "C:\SailPoint\tomcat\webapps\identityiq\css\iiq-custom.css"
if (Test-Path $IiqCssSource) {
    Copy-Item $IiqCssSource $IiqCssTarget -Force
} else {
    Write-Warning "iiq-custom.css not found at $IiqCssSource"
}

# 3. Copy all icons -> IIQ ui\images folder
$IconsSource = Join-Path $BrandingPath "Icons\*"
$IconsTarget = "C:\SailPoint\tomcat\webapps\identityiq\ui\images"
if (Test-Path (Join-Path $BrandingPath "Icons")) {
    Copy-Item $IconsSource $IconsTarget -Force -Recurse
} else {
    Write-Warning "Icons folder not found at $($BrandingPath)\Icons"
}

Write-Output ">>> Branding applied successfully."

# ------------------------------
# 10. Auto Import Core XMLs
# ------------------------------
Write-Output ">>> Importing IIQ Core XMLs..."
$ConsoleCommands = @"
import init.xml
import init-lcm.xml
import rapidsetup.xml
quit
"@
$ConsoleFile = "$InstallerPath\console.txt"
$ConsoleCommands | Out-File $ConsoleFile -Encoding ASCII
cmd.exe /c ".\iiq.bat console < `"$ConsoleFile`""

# ------------------------------
# 11. Restart Tomcat + Clear Browser Cache (Chrome, Edge, Firefox)
# ------------------------------
Restart-Service Tomcat9

Write-Output ">>> Clearing browser cache..."

# Google Chrome
$ChromeCache = "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Cache"
if (Test-Path $ChromeCache) {
    Remove-Item -Recurse -Force -ErrorAction SilentlyContinue $ChromeCache
    Write-Output ">>> Chrome cache cleared."
}

# Microsoft Edge
$EdgeCache = "$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default\Cache"
if (Test-Path $EdgeCache) {
    Remove-Item -Recurse -Force -ErrorAction SilentlyContinue $EdgeCache
    Write-Output ">>> Edge cache cleared."
}

# Mozilla Firefox
$FirefoxProfiles = Get-ChildItem "$env:APPDATA\Mozilla\Firefox\Profiles" -Directory -ErrorAction SilentlyContinue
foreach ($Profile in $FirefoxProfiles) {
    $FirefoxCache = Join-Path $Profile.FullName "cache2"
    if (Test-Path $FirefoxCache) {
        Remove-Item -Recurse -Force -ErrorAction SilentlyContinue $FirefoxCache
        Write-Output ">>> Firefox cache cleared for profile $($Profile.Name)."
    }
}

Write-Output ">>> Browser cache cleanup completed."

#------------------------------
# Launch IIQ in Browser
#------------------------------
Write-Output ">>> Installation Completed!"
Write-Output ">>> Opening: http://localhost:8080/identityiq"
Write-Output ">>> Default Login: spadmin / admin"

# Stop Logging
Stop-Transcript
Write-Output ">>> Full log saved to $LogFile"

# Start-Process "http://localhost:8080/identityiq"
# Start-Process "msedge.exe" -ArgumentList "--inprivate http://localhost:8080/identityiq"

# Target URL
$url = "http://localhost:8080/identityiq"

$defaultBrowserProgId = (Get-ItemProperty "HKCU:\Software\Microsoft\Windows\Shell\Associations\UrlAssociations\http\UserChoice").ProgId

switch -Wildcard ($defaultBrowserProgId) {
    "*Chrome*" {
        Start-Process "chrome.exe" -ArgumentList "--incognito $url"
    }
    "*Edge*" {
        Start-Process "msedge.exe" -ArgumentList "--inprivate $url"
    }
    "*Firefox*" {
        Start-Process "firefox.exe" -ArgumentList "-private-window $url"
    }
    default {
        Start-Process $url
    }
}