# 🚀 SailPoint IdentityIQ 8.5 – Automated Installer

This repository provides a **PowerShell automation script** that fully installs and configures **SailPoint IdentityIQ 8.5** on Windows Server with the following stack:

- **JDK 17**
- **Apache Tomcat 9**
- **Microsoft SQL Server 2022 Express** (with Mixed Mode Authentication)
- **SQL Server Management Studio (SSMS)**
- **SQLCMD Tools**
- **IdentityIQ WAR deployment** (with JDBC driver and extended property configuration)

The script is designed for **one-click deployment**, ensuring consistent setup for development, testing, or training environments.

---

## 📂 Project Structure
     
      SailPoint-IIQ---Automated-Installer/
      │
      ├── README.md                                   # Documentation
      └── InstallerFiles/                             # Expected local folder containing installers
          ├── jdk-17.0.xx_windows-x64_bin.exe
          ├── apache-tomcat-9.x.xxx-windows-x64.zip
          ├── identityiq-x.x.zip
          ├── install-iiq-full.ps1                    # Main PowerShell automation script
          ├── mssql-jdbc-9.4.1.jre16.jar
          ├── SQL20xx-SSEI-Expr.exe
          ├── SQLEXPR_x64_ENU.exe                     # (optional offline installer)
          └── vs_SSMS.exe                             # SQL Server Management Studio installer

---

## ⚙️ Features

- ✅ Pre-checks for prerequisites (admin rights, PowerShell version, disk space)  
- ✅ Automated installation of JDK 17 and environment variables setup  
- ✅ Apache Tomcat 9 installation and Windows service configuration  
- ✅ SQL Server 2022 Express installation with:
  - SA account enablement + secure password  
  - Mixed Mode Authentication  
  - TCP/IP enabled on port 1433  
- ✅ SQLCMD installation and path configuration  
- ✅ SQL Server Management Studio (SSMS) installation  
- ✅ Deployment of **IdentityIQ WAR** into Tomcat  
- ✅ Automatic addition of SQL Server JDBC driver  
- ✅ Customization of `IdentityExtended.hbm.xml` (extended11–20)  
- ✅ Creation of IdentityIQ database schema  
- ✅ Full logging to timestamped log file  

---

## 📋 Requirements

- **Windows Server 2016+ / Windows 10+**  
- **Administrator privileges**  
- **PowerShell 5.0+**  
- Minimum **10 GB free disk space**  
- Internet connection (for online SQL installer) or offline installers in `InstallerFiles`  

---

## 🚀 Installation Steps

1. **Clone the Repository**
   ```powershell
   git clone https://github.com/Mahmooooud33/SailPoint-IIQ---Automated-Installer.git
   cd SailPoint-IIQ---Automated-Installer
   
2. **Prepare Installers**
Place the following files in the C:\InstallerFiles directory (default path):
  - jdk-17.0.xx_windows-x64_bin.exe
  - apache-tomcat-9.x.xxx-windows-x64.zip
  - identityiq-x.x.zip
  - mssql-jdbc-9.4.1.jre16.jar
  - SQL20xx-SSEI-Expr.exe (or SQLEXPR_x64_ENU.exe for offline)
  - vs_SSMS.exe

3. **Run the Installer**
Open PowerShell as Administrator and run:
   ```powershell
    Set-ExecutionPolicy Bypass -Scope Process -Force
    .\install-iiq-full.ps1

4. **Follow Logs**
Installation logs are stored in:
   ```bash
    C:\InstallerFiles\IIQ_Install_yyyyMMdd-HHmmss.log
