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


## Command Prompt / PowerShell

The command prompt is a terminal that can be started with `Run > cmd.exe`.  
It offers a command-line interface to interact with the machine :

```commandline
whoami                 // current username
hostname               // machine name
ipconfig /?            // the /? option provides the help
cls                    // clears the screen
netstat                // monitor active TCP/IP connections
net help               // help for the "net" command to monitor network resources
```

**PowerShell** is a task automation and configuration management program developed by Microsoft.  
It consists of a command-line shell and the associated scripting language.  
It is open-source and available on Windows / Linux / MacOS.  
PowerShell scripts have the extension `.ps1`.



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


## BitLocker

BitLocker is a data protection feature to encrypt entire volumes.  
It prevents data theft or exposure from lost/stolen computer.  

BitLocker provides a great protection when used with a TPM (Trusted Platform Module).  
On devices that do not have a TPM, BitLocker requires either a startup key (file on a removable drive) or a password.
