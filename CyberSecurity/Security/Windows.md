# Windows OS

## Windows Editions

Windows Home edition is designed for consumers (PC and tablet).  
Windows Pro edition is designed for businesses, adding Active Directory, BitLocker, Hyper-V...

Home/Pro Edition :
- Windows 2000 (2000)
- Windows XP (2001)
- Windows Vista (2006)
- Windows 7 (2009)
- Windows 8 (2012)
- Windows 10 (2017)
- Windows 11 (2021)

Windows Server :
- Windows Server 2012
- Windows Server 2016
- Windows Server 2019
- Windows Server 2022


## File System

Old Windows machines used **FAT32** (File Allocation Table) and **HPFS** (High Performance FS).  
FAT is still used for USB devices or MicroSD cards, but not for Windows computers or servers.

Modern Windows machines use **NTFS** (New Technology File System).  
NTFS supports files larger than 4GB, file/folder level permission, compression and encryption.


## Windows Command Line

### Command Prompt

The command prompt is a terminal that can be started with `Run > cmd.exe`.  
It offers a command-line interface to interact with the machine :

```shell
whoami                 # current username
hostname               # machine name
ver                    # display the version of the Windows OS
systeminfo             # display system details (OS name, version, system model, locale, memory...)
set                    # display, set or remove env variables
cls                    # clear the screen

help set               # provide manual for the set command
ipconfig /?            # the /? option provides the help
net help               # help for the "net" command to monitor network resources

# networking
ipconfig               # display network configuration (IP address, default gateway...)
ipconfig /all          # display more network configuration (MAC address, DHCP info, DNS server ...)
ping <HOSTNAME>        # send an ICMP package to a host and listen for a response to test connectivity
tracert <HOSTNAME>     # traceroute
nslookup example.com   # DNS record lookup
netstat                # monitor active TCP/IP connections

# file management
cd                     # display the current directory (pwd in Linux)
dir                    # display content of the current directory (ls in Linux)
tree                   # display the content of current directory as a tree
more a.txt             # display the content of a file
copy a.txt b.txt       # copy a file (cp in Linux)
move a.txt ..          # move a file (mv in Linux)
del a.txt              # remove a file (rm in Linux)

# tasks and processes
tasklist               # list running processes
taskkill /PID 1234     # kill a running process by PID
shutdown /s            # shutdown the machine (/r to reboot)

# other
chkdsk                 # check the file system and disk volumes
driverquery            # list all installed drivers
sfc /verifyonly        # scan integrity of protected system files (use /scannow to fix errors)
```

### PowerShell

**PowerShell** is a task automation and configuration management program developed by Microsoft.  
It consists of a command-line shell and the associated scripting language built on the .NET framework.  
It is open-source and available on Windows / Linux / MacOS.  
PowerShell scripts have the extension `.ps1`.

Windows uses structured data and API, while Unix represents everything as files, which made it difficult to use Unix tools in Windows.  
Therefore, Microsoft developed an object-oriented approach, allowing administrators to automate tasks by manipulating objects.

Commands in Powershell are called **cmdlets** and return object instances, allowing more advanced data manipulation.  
Powershell cmdlets follow a Verb-Noun naming convention, like `Get-Content` or `Set-Location`.

```shell
Get-Command                                     # list all available Powershell cmdlets
Get-Command -Name Copy*                         # list all available Powershell cmdlets starting with "Copy"
Get-Date                                        # display the current date and time
Get-Culture                                     # display the current culture settings on the computer (for ex en-US)
Get-Help Get-Date                               # display help about a specific Powershell cmdlet
Get-Help Get-Date -examples                     # display examples of the Get-Date cmdlet
Get-Alias                                       # display all cmdlet aliases (for example ls, cd, mv, cp...)

Get-ChildItem -Path ..                          # display the content of a directory (ls in Linux)
Set-Location -Path ..                           # change the current working directory (cd in Linux)
New-Item -Path ".\mydir" -ItemType "Directory"  # create a directory
New-Item -Path ".\a.txt" -ItemType "File"       # create a file
Remove-Item -Path ".\a.txt"                     # remove a file or a directory (both rm and rmdir in Linux)
Copy-Item -Path ".\aaa" -Destination ".\bbb"    # copy a file or directory
Move-Item -Path ".\aaa" -Destination ".\bbb"    # move a file or directory
Get-Content -Path ".\a.txt"                     # display the content of a file (cat in Linux)

Select-String -Path ".\a.txt" -Pattern "aa"     # find a string in a file (grep in Linux)

# System config and Networking
Get-ComputerInfo                                # display system information (OS, hardware, BIOS...)
Get-LocalUser                                   # list all local user accounts
Get-NetIPConfiguration                          # display info about the network interfaces (IP, DNS server, default gateway)
Get-NetIPAddress                                # display detailed info for all IP addresses on the system

# Process / Service / Connections monitoring
Get-Process                                     # list all running processes
Get-Service                                     # list all services and their status
Get-NetTCPConnection                            # list all TCP connections (local and remote address/port, state)
Get-FileHash -Path .\a.txt                      # calculate the hash of a file (SHA256 by default) 

Invoke-Command -ComputerName ServerA -FilePath ./test.ps1           # execute a Powershell script on a remote server
Invoke-Command -ComputerName ServerA -ScriptBlock { Get-Culture }   # execute some Powershell cmdlets on a remote server

Invoke-WebRequest -uri 
```

Piping is even more powerful in PowerShell than in Bash, because it passes objects to the next command (not strings).  
This allows the next command to use the properties and methods of the input data :
```shell
Get Child-Item | Sort-Object Length                              # sort input of the 1st cmdlet
Get Child-Item | Where-Object -Property "Extension" -eq ".txt"   # filter input of the 1st cmdlet by extension
Get Child-Item | Where-Object -Property "Name" -like "test*"     # filter input of the 1st cmdlet by name
Get Child-Item | Select-Object Length,Name                       # select specific properties of the input
```

Additional cmdlets can be downloaded online to enrich the capabilities of the Powershell.  
We can search for modules with the `Find-Module` cmdlet, and install them with the `Install-Module` cmdlet.

Just like Bash, Powershell supports script files that can contain cmdlets, define variables and use them in later instructions.  
For example, to fetch a JSON file from a URL and save its content to a file :
```shell
$url = "https://httpbin.org/get" 
$response = Invoke-WebRequest -Uri $url
$json = $response.Content
$outputFile = "response.txt"
Set-Content -Path $outputFile -Value $json
Write-Output "JSON result written to file $outputFile"
```

Some common features of the PowerShell language are :
```shell
# set a constant variable
Set-Variable Pi -Option ReadOnly -Value 3.14

# define an array
$array1 = @()                       # empty array
$array2 = @('A', 'B', 'C')          # initialized array
$array2[1]                          # read an element of the array

# define a map
$map1 = @{}                         # empty map
$map2 = @{'A': '1', 'B': '2'}       # initialized map
$map2.name = 'Bob'                  # add a value in the map
$map2.number = '00-11-22-33'
$map2.number                        # read a value from the map

# if conditions use C-style syntax
# comparison operators are similar to Bash
if ($a -eq $b) {
  # do something  
} elseif ($a -gt $b) {
  # do something
} else {
  # do something
}

# for loop
for ($i=1; $i -lt 10; $i++) {
  Write-Host $i
}

# do-while loop
Do {
  # do something
}
While ($a -lt $b)

# read and write from/to the host
Write-Host "Enter your name : "
Read-Host $Name
Write-Host "Hi " + $Name

# read from a file
$FileContent = Get-Content -Path C:\flag.txt
```

To execute a Powershell script, we need to update the execution policy to allow it :
```shell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy ByPass
./script.ps1
```

Powershell keeps an history of commands executed in a session in `%APPDATA%\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt`.  
This can be a valuable resource when investigating a cybersecurity incident.


## Windows Folders

The Windows OS is usually contained in the `C:/Windows` folder.  
It can be installed in a different location, defined by the `%windir%` env var.   

The `C:/Windows/System32` folder contains many `.dll` and `.exe` files required by Windows (like the task manager).  
It should not be modified manually, or we would break the OS and require a Windows re-installation.

Each user has a profile created for him, under `C:/Users/<USERNAME>`.  
This folder contains standard folders : Desktop, Downloads, Documents, Pictures, Music...


## User Accounts and Groups

User accounts can be either `Administrator` or `Standard`.  
The account created at the Windows installation is an Administrator account.  
Only Administrator accounts can add/delete users, edit groups, modify Windows settings, install applications...

**User Account Control** is a feature that improves security of Administrator accounts.  
By default, they run with a standard account permissions, and when an operation requires Administrator privilege,
a pop-up asks to confirm.  

When running an operation that requires Administrator privilege from a standard account, the username and password of
an Administrator must be entered.

Users can be created in the `Settings > Accounts > Family and other users` menu.

User accounts and groups can be configured from the **Local User and Groups** screen accessed with : `Run > lusrmgr.msc`.  
This can also be configured from the Control Panel : `Control Panel > User Accounts`.  


## Configuration and Monitoring tools


### Settings and Control Panel

Originally all Windows configuration was performed from the Control Panel window.  
Windows 8 introduced the Settings window that became the primary location for Windows configuration.  
Some operations in the Settings window redirect to the Control Panel for more detailed configuration.

The Settings window include among others :
- Network & Internet
  - Network status and properties
  - Wifi and Ethernet monitoring
  - Proxy configuration
- Account
  - Current user info
  - Creation and management of other users
- Update and Security
  - Windows Update : manage update patches
  - Windows Security : quick access to Windows Security window
    - Virus and Threat Protection (Windows Defender antivirus + External vendor Antivirus if any)
    - Firewall and network protection (allow app, Firewall config in Windows Defender Firewall window)
    - App & browser control (Microsoft Defender SmartScreen to identify malicious apps and downloads)


### Task Manager

The task manager provides a monitoring dashboard for system resources usage and process statistics.  
It can be open with the `Ctrl+Shift+Esc` shortcut.

In the `Processes` tab, we can monitor and stop running processes and applications.  
Processes are sorted into 3 groups : Applications, Background Processes and Windows Processes.  
We can create a dump file of a running process to capture a snapshot of the program's memory.

The `Performance` tab lets us monitor in real-time some metrics like CPU, RAM, GPU, Wifi/Ethernet throughput...  
We can click the "Open Resource Monitor" link at the bottom for process-level info.  
It also shows :
- CPU info : speed, cores, virtualization, uptime
- RAM info : total RAM, number of used RAM slots
- Storage info : Disk name, capacity, HDD/SSD

The `Startup` tab lists all startup programs (automatically started when we sign in to the user account).  
Startup programs can be disabled from here, as well as in `Settings > Apps > Startup`.

The `Service` tab lets us start and stop Windows services.  
This contains the same information as `services.msc`, the services management console.  

The `Users` tab shows all users connected to the machine, and the processes they are running.  
We can disconnect a user (lock the session) or sign off a user (close the session).


### Resource Monitor

Resource Monitor is a window that displays per-process and aggregate CPU, memory, disk usage and network usage.  
It also provides information about which process uses which file handles and modules.  
It allows stopping or suspending specific running processes.  
It shows a graphical representation of the CPU, memory, disk usage and network activity.


### Computer Management

The Computer Management window has 3 main sections :

- System Tools
  - Task Scheduler : configure some tasks that run on a specified schedule (login, logout, every X min...)  
  - Event Viewer : view events that have occurred on the machine per log provider, used for diagnostic and incident investigation  
  - Shared Folders : list folders shared with others across the network, and sessions of users connected to these shares  
  - Local Users and Groups : manage users and groups on the machine (same as `lusrmgr.msc`)  
  - Performance : show a performance monitor tool
  - Device Manager : list and configure the hardware devices attached to the machine
- Storage
  - Windows Server Backup (only available on Windows Server)
  - Disk Management : perform storage tasks like setup a drive, extend/shrink a partition, change drive letter...
- Services and Applications
  - Services : start, stop or view properties of services
  - WMI Control : configure the Windows Management Instrumentation service (WMI)


### System Information

System Information is a window open with `Msinfo32.exe`, or accessed via the Start menu or the System Configuration.  
It gathers information about the computer and displays a view of the hardware, system components and software environment.

It splits its info between 3 sections :
- Hardware Resources
- Components (Display, Keyboard, Modem, USB, Storage...)
- Software Environment (drivers, env vars, services, network connections...)


### Registry Editor

The Windows Registry is a central hierarchical database used to store information to configure the system.  
It contains info that Windows continually references during operations (user profiles, hardware, ports, application info...).  
The Registry Editor window lets us browser through the registry values and edit them.


### System Configuration

System Configuration is a configuration window with several tabs :
- **General** : Select the type of boot (normal, diagnostic or selective)
- **Boot** : options for the boot of the Windows OS
- **Services** : list all configured services (running and stopped)
- **Tools** : list utilities that can be run to configure the Windows OS further
  - About Windows : display the Windows version and license
  - Change UAC Settings : choose when to get notified when Administrative privileges are used
  - System Information : Open the System information window (OS name and version, processor, RAM, Timezone...)
  - Computer Management : open the Computer management window
  - Resource Monitor : Open the Resource Monitor window
  - Task Manager : open the Task Manager window
  - Command Prompt : open a windows command promp (terminal)
  - Internet Protocol Configuration : Run the ipconfig command in a command prompt


## Security in Windows


### Windows Updates

Windows Updates is a service providing security updates, feature enhancements and patches for the Windows OS and Windows products.  
Updates are released on **Patch Tuesday** (2nd Tuesday each month), unless it is critical and released immediately.  

Windows Update is available in the Settings window under _Update & Security_.  
We can manually download and install the updates, or make it automatic.  
We can decide on the best time to reboot the machine when needed, but if we keep postponing it will automatically reboot.


### Windows Security

Windows Security is the section in the Settings window to view and manage several aspects of the security of the machine :

- Virus & threat protection
  - scan the device for threats
  - activate the real-time protection
  - create exception that Windows Defender will not scan

- Firewall & Network Protection
  - activate Windows Defender firewall for domain / private / public networks
  - manage apps allowed through the Windows Defender firewall
  - access the Windows Defender firewall window for more advanced settings (same as `WF.msc`)

- App & Browser Control
  - change settings for SmartScreen (protection against unrecognized apps and files from the web)
  - built-in Windows exploit protection

- Device Security
  - Security Processor (TPM details)
  - Secure Boot


### Windows Defender

Windows Defender is the built-in Windows firewall.  
It can define customized rules to allow or deny incoming and outgoing network traffic.

Windows Defender can set a different configuration for 2 network profiles : private network and guest or public network.  


### BitLocker

BitLocker is a data protection feature to encrypt entire volumes.  
It prevents data theft or exposure from lost/stolen computer.  

BitLocker provides a great protection when used with a TPM (Trusted Platform Module).  
On devices that do not have a TPM, BitLocker requires either a startup key (file on a removable drive) or a password.


## AD (Active Directory)

A **Windows domain** is a group of users and Windows computers under the administration of a single business.  
The administration of common components of a Windows domain is centralised in a single repository called **Active Directory**.  
The server running the Active Directory service is called the **Domain Controller** (DC).

All users and machines are configured from AD.  
Security policies can be configured in AD and applied to users and computers across the Windows domain.

AD is used in companies or in universities, to allow for example to provide our user and password on any computer of the network.  
The authentication process is handled by AD, that checks the credentials.  
AD can also restrict what users can do on the machines, for example prevent the access to the Control Panel.  

The core of AD is the **Active Directory Domain Service** (AD DS), a catalog holding all objects on the Windows domain.  
It contains users, groups, machines, printers, shares ...

### AD Objects

#### AD Users

Users are the most common objects in AD.  
They are **security principals**, meaning that they can be authenticated by the domain and assigned privileges over resources (files, printers...).  
Users can represent either people (employees of a company) or services (database server...).

#### AD Machines

Machines in AD represent computers joining the AD domain.  
Machines are also **security principals** and are assigned an account just like regular users, with limited permissions.  

Machine accounts are local administrators on the assigned computer, and are usually not accessed except by this computer.  
Machine accounts are easy to recognize because they follow a naming scheme, it is the machine name followed by the '$' sign. 

#### AD Security Groups

Security groups allow to assign access rights to entire groups of users instead of individual users.  
Security groups are also **security principals** and can have permissions over resources in the AD network.  
Groups can contain both users and machines as members, as well as other groups.

Some groups are created by default in an AD domain, the most important are :
- **Domain Admins** : grant administrative privileges over the entire domain, can administer any computer including the DC
- **Server Operators** : grant permission to administer the Domain Controllers, but not group membership
- **Backup Operators** : grant permission to access any file (ignoring their permission), used to perform backups
- **Account Operators** : grant permission to create and modify other accounts in the domain
- **Domain Users** : include all existing accounts in the domain
- **Domain Computers** : include all existing machines in the domain
- **Domain Controllers** : include all existing DCs on in the domain


### AD Configuration

To configure AD, we need to log in to the DC and run **Active Directory Users and Computers** from the start menu.  
It opens a window with the hierarchy of users, groups and machines in AD.  
Each level in the hierarchy is an **Organizational Unit** (OU), which usually mimic the business structure (Sales, IT, HR...).  
Those OUs are used to deploy policies to entire departments.
A user can only belong to one OU (and any levels of sub-OUs).  
By selecting the user in its OU, we can modify (rename, edit, reset password, add to group, disable account...).  

Users are protected against accidental deletion, to delete them we need to :
- enable advanced features : View > Advanced Features
- disable the protection against accidental deletion : right-click on the user > Object > untick the protection checkbox
- delete the user : right-click on the user > Delete

Apart from the OUs we create, the hierarchy contains several default containers :
- **Builtin** : list of all default groups
- **Computers** : contains every machine joining the network (they can then be moved to another folder if needed)
- **Domain Controllers** : contains the DCs of the AD network
- **Users** : default users and groups
- **Managed Service Accounts** : contains accounts used by services

By default, all computers added to the AD network appear under the _Computers_ container.  
It is a better practice to split them into multiple OUs to assign different policies.  
A common setup is to divide them by their use :
- **Workstations** : computers used by users for their daily work, should not have privileged users accessing them.  
- **Servers** : computers used to run services for users or other servers
- **Domain Controllers** : computers used to manage the AD domain, very sensitive because they contain the hashed passwords for all users

#### Delegation

We can delegate some control over specific OUs to specific users, this is called delegation.  
A common example is to give IT Support the permission to reset low-privilege users passwords.  
This is performed by right-clicking the OU and selecting _Delegate Control_.  

We can select which actions a user or group can perform on this OU, for example password reset.  
To test it, we can RDP to the machine as the modified user (we need his password).  
The user may not have permission to open the **Active Directory Users and Computers** window,  so we use the AD CLI in Powershell :
```shell
# rest the password to a password asked in a prompt
Set-ADAccountPassword <USER_NAME> -Reset -NewPassword (Read-Host -AsSecureString -Prompt 'New Password') -Verbose

# force a password reset on first login
Set-ADUser -ChangePasswordAtLogon $true -Identity <USER_NAME> -Verbose
```

#### Group Policies

In AD, we can create some **Group Policy Objects** that are collections of settings that can be applied to an OU.  
GPOs can be applied to users or computers.  
GPOs are created from the Group Policy Management window in the start menu under the _Group Policy Objects_ folder.  
In the GPO edition screen, we can dig down to each policy, and double-click and go to the _Explain_ tab to understand the policy.

When editing a GPO, we have multiple tabs :
- **Scope** : shows the OUs where this GPO is applied, as well as an optional filter to limit the resources that this policy applies to
- **Details** : general info about the GPO (owner, creation time, status...)
- **Settings** : the actual content of the GPO 
  - configuration that applies only to computers (password, account lockout, kerberos, ...)
  - configuration that applies only the users

GPOs are distributed to the network via the network share called **SYSVOL** stored in the DC.  
All users in the AD domain have access to this network share.

```shell
# list all GPOs in the AD domain controller
Get-GPO -All                       

# generate an HTML report with the details of a GPO
Get-GPOReport -Name "SetWallpaper" -ReportType HTML -Path ".\report.html" 
```

#### Authentication

Every authentication request in an AD domain is sent to the domain controller.  
The authentication protocol used by AD can be either **Kerberos** or **NetNTLM**.

##### Kerberos

Kerberos is the default authentication protocol used by AD in every recent version of Windows.  
It uses a mechanism based on tickets as a proof of a previous authentication.  

A user sends their username and a timestamp encrypted with a key derived from their password to the **Key Distribution Center (KDC)**.  
The KDC is in charge of creating all the Kerberos tickets to grant service access.  
On successful authentication, the KDC sends back : 
- a session key, encrypted with the user password hash
- a **Ticket Granting Ticket (TGT)** that allows the user to request service access tickets, encrypted with the **krbtgt** account's password hash   
The TGT contains the session key, so the KDC does not need to store the session key locally, it can retrieve it from the TGT.  

When a user wants to connect to a service on the network (share, website, database...), he needs to request a **Ticket Granting Service (TGS)**.  
He will send their username, a timestamp encrypted with their session key, their TGT and a Service Principal Name (SPN) telling the target service and server name.  
The KDC will validate the TGT and return a TGS and a Service Session Key.  
The TGS is encrypted with the service owner hash, so the user running the service can decrypt it.  
The TGS can then be sent to the service to authenticate.

##### NetNTLM

NetNTLM is a legacy authentication protocol, kept only for compatibility purpose.  
It uses a challenge-response mechanism.  

When a user wants to access a server, it sends an authentication request, and the server replies with a random number as a challenge.  
The user combine the challenge with its password hash to generate a challenge to send back to the server.  
The server sends this challenge and the response to the domain controller for verification.  
The domain controller knows the user password hash, so he checks the challenge response and returns a success or failure.

#### Trees and Forests

When the AD network grows, it can be better to split it into multiple AD domains.  
Multiple domains sharing the same namespace can be joined into an **AD Tree**.  
For example, the root domain `example.local` could contain domains `uk.example.local` and `us.example.local`.  
This allows IT teams in the UK to manage UK users without having any control over US users.  

We can also need to manage domains in multiple namespaces, for example after a company is acquired.  
In that case, the union of the several AD trees on multiple namespaces is called an **AD Forest**.

Domains arranged in trees and forests are linked with **trust relationship**.  
This allows users in a domain to access some files on a server of another domain if needed, for example.  
If domain A trusts domain B, then users in domain B can access resources in domain A.  
When a trust relationship is configured, it means that the resources from one domain are visible to the other domain when creating access rules.