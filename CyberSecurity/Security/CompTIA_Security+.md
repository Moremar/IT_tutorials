# CompTIA Security+


## Hacking Methodology

### DAD Triad

Cyber-security aims at protecting the CIA Triad.  
Hacking aims at breaking it, making the DAD Triad :

- **Disclosure** : break confidentiality by gaining accessed to resources that should not be accessed
- **Alteration** : break integrity by modifying the content or behavior of resources
- **Denial** : break availability by preventing legitimate users to access resources


### Hacking steps

- **Reconnaissance / Fingerprinting** : Gather info about the target, can be either passive or active  
- **Exploitation** : Take advantage of vulnerabilities to gain access via phishing, social engineering, weak passwords, unpatched softwares...  
- **Privilege escalation** : Use the gained access to get higher permission (create accounts, get admin access...)  
- **Establish persistence** : create a backdoor for later remote access control
- **Attack** : data extraction, data corruption, malware injection
- **Avoid detection** : ICMP tunnels, delete logs, erase command history


### Attack frameworks

- **Cyber Kill Chain** : linear framework in 7 steps :  
  - Reconnaissance
  - Weaponization
  - Delivery
  - Exploitation
  - Installation
  - Command and Control
  - Actions

- **MITR pre-ATT&CK and ATT&CK matrices** : free framework using matrices showing different tactics for reconnaissance and attack

- **Diamond model** : model using relations between 4 core features :
  - Victim
  - Capacity
  - Adversary
  - Infrastructure


## Malwares

### Virus

A virus infects a computer and can replicate and spread to other computers.  
It attaches its code to legitimate programs or files.    
It gets executed when the infected program is run or the infected file is opened.

Main types of viruses :
- **boot-sector** : stored in first sector of hard drive and loaded in memory at boot (before OS startup)
- **macro** : virus code embedded inside another document started at document open (Word, Excel, Powerpoint)
- **program** : infects an executable or application and load the virus when the program runs
- **multi-partite** : combination of boot-sector and program virus, it is attached to a system file and recreated at boot
- **encrypted** : virus encrypting its content to avoid detection by signature-based antivirus
- **polymorphic** : virus altering its content to avoid detection by signature-based antivirus
- **metamorphic** : advanced version of polymorphic virus rewriting itself entirely before propagation
- **stealth** : category of viruses hiding themselves to avoid detection
- **armored** : virus with mechanism to make detection by antivirus harder
- **hoax** : virus that propagates by making user believe they need to install it to cleanup their machine

### Worm

A Worm is similar to a virus, it infects a computer and spread to others, but it is self-replicating.  
It does not need a host program or file, nor human interaction to replicate and propagate.  
It is used to create botnets, due to its capacity to propagate very quickly.

### Trojan

A Trojan is a malware disguised as a legitimate and useful software.  
A **RAT** (Remote Access Trojan) opens a backdoor for hackers to remotely access and control the machine.  
An **info-stealer trojan** steals user data, for example with the use of a keylogger.  
A **trojan downloader** downloads new versions of malwares.  

**ProRat** is an example of RAT that allows an attacker to create a "server" (an infected file) that gives remote 
control when executed on the victim's machine.  
The attacker can take many actions from the ProRat GUI (see system info, send message, take screenshot, keylogger ...).

A **banking trojan** is a popular attack on Android devices.  
A trojan app is installed (a game for instance) and runs in the background.  
It detects when a real banking app is open on the phone, and adds an overlay above it that the user cannot see.  
When the user enters his credentials, it is captured by the trojan app and sent to the criminal.  
The **AceCard** banking trojan was able to overlay over 30 banking apps.

### Adware

An adware is a software displaying ads, and can also hijack the browser search page.

### Spyware

A spyware is a software tracking the activity on a victim's machine.  
It can monitor web usage for targeting ads, or use a keylogger to steal credentials.

### Ransomware

A ransomware is a software encrypting data on the victim's machine and selling the decryption key against a ransom (usually in crypto-money).  
**Doxing** is a special ransomware type, where the victim should pay a ransom, or their stolen info will be disclosed to the public (customer data, salaries, secret documents...).

### Rootkit

A rootkit is a malware hiding its presence and providing unauthorized access to a computer.  
It is activated before the machine boots.  
It usually requires to wipe the hard disk to get rid of it.

A rootkit can act at multiple levels :
- **kernel level** : highest privilege, can inject code in the OS
- **application level** : can modify the behavior of applications
- **library level** : can hook system calls with malicious code
- **hypervisor level** : load itself in a hypervisor
- **firmware level** : override the BIOS of the machine

Rootkits make use of **DLL injection** and/or **driver manipulation**.

### Spam

Spam is the abuse of electronic messaging systems to send unsolicited emails, usually containing ads.  
Most spammers make use of **email relays** from other organizations to send emails anonymously. 

### Malware Delivery Methods

Malwares can be delivered to the victim in multiple ways :
- **autorun** on external media mount : USB / CD / Floppy Disk
- **phishing link** : drive-by installation, download links...
- **auto-execution** of downloaded executables : (py, vbs, bat, exe)
- **VBA macro** triggered when a Word/Excel document is open

Many modern malwares are fileless : they either attach to an existing executable, or store their file in a 
temporary directory and them remove the files.  
This makes it harder for antivirus to detect them by signature.

## Attack Types

### Web Attacks

#### Directory Traversal

Attack trying to access unauthorized files by manually setting a parameter of a URL to a specific file path.  
Web servers that can serve user-specified files must validate and restrict the user input to protect from it. 

#### Buffer Overflow

A buffer overflow is the allocation of memory exceeding the size of the buffer used to receive it.  
It is used by attackers to override the return pointer in the execution stack.  
For example, they can redirect to a malicious code that runs a shell, so they have a remote code execution.

#### SQL injection

SQL injection is the execution of custom SQL commands by using un-sanitized user input in SQL query.  
It is one of the most common attacks on websites and is part of the OWASP 10.  

**Havij** is a tool that can detect SQL injection vulnerabilities of a website.

**SQLmap** is another penetration tool that detects SQL injections in web applications.  
It can infer the DB version and exploit the SQL injection vulnerabilities to list databases, tables, columns and rows.

#### Cross-Site scripting (XSS)

XSS is another OWASP 10 attack on websites.  
It exploits the trust that a user has in the web server.  
The hacker executes malicious JS code on the browser of the victim by including it inside the code that is dynamically 
served to the victim (for ex in a post comment).  

The 3 types of XSS attacks are :
- Stored and Persistent : get the malicious code saved in the DB by the web server
- Reflected : malicious code executed when the victim clicks on a link on the site
- DOM-based : exploit the victim's web browser

#### XSRF (Cross-Site Request Forgery)

Unlike XSS, XSRF exploits the trust that the web server has in his user.  
The attacker forces a user to execute actions on the website for which he is already authenticated.  
This is done by making the user click on a URL to that site, so his session cookie will be attached to the request.  

XSRF can be avoided by using XSRF tokens in the HTML templates.  
The token is sent with each request and validated on receive, so the forged URL would not have it.

### RCE (Remote Code Execution)

Attack that allows the attacker to run any arbitrary command on a system from a remote location.  
That is one of the most dangerous types of security issue, and the goal of any attacker.  

### Wireless attacks

#### Wardriving

Wardriving is the act of searching for Wifi networks, usually from a moving vehicle (car with antenna).  
It usually uses a smartphone or a laptop, looking for weakly protected networks to crack.

#### De-authentication attack

If we know the wireless network SSID and the MAC address of a machine connected to it, we can send to the Wifi AP 
a **de-authentication frame** with the spoofed MAC address of the victim to force the disconnection of the machine.  
This can be used to crack WEP or WPA passwords, as we need to sniff some connection traffic to infer the password.  
De-authentication lets us force the user to reconnect while we sniff the traffic.

#### Evil Twin

An evil twin is a fraudulent Wifi AP that appears legitimate but is setup to eavesdrop on wireless communications.  
It is an AP setup with a name similar to an existing valid one.  

Once the evil twin is setup, the attacker de-authenticates all connected clients to force them to reconnect.  
When they connect again, they may use the rogue AP instead, and the attacker has a man-in-the-middle attack giving 
access to all the victim's traffic.  
It is often used in places offering a public Wifi (cafés, airports...).

#### Bluetooth Attacks

**Bluejacking** is the action of sending unsolicited messages to Bluetooth enabled devices.

**Bluesnarfing** is the unauthorized access of information from a wireless device over a Bluetooth connection.

### Phishing

Phishing is a social engineering technique to lure someone into willingly providing critical information (credentials, credit card numbers...).    
It is often using fake URLs in phishing emails redirecting to fake login pages :
- **Vishing** : phishing by phone
- **Smishing** : physhing by SMS 
- **Sextortion** : obtain compromising pictures/videos, then used to blackmail the victim
- **Insider** : the attacker applies for a job in the target company and get hired to gain access to the internal network

### Botnet

A botnet is a group of computers (bots) controlled remotely by the attacker.  
The attacker issues commands to the C&C server (Control and Command), that gives instructions to the bots.  
A victim machine becomes a bot usually after installing a trojan horse.

### DoS / DDoS (Distributed Denial of Service)

DoS is an attack aiming at preventing a system to perform its task.  
DDoS is identical, but performed by multiple machines at the same time (usually a botnet) for higher impact.

#### Flood Attack

Flood attack is a common form of DoS, trying to overwhelm a network or machine.  
It consists in sending a heavy load of traffic to a victim to prevent it to serve regular users.  

Multiple types of flood can be used :
- **ICMP flood** (ping)
- **Smurf attack** : similar to ICMP flood but send the pings to a network's broadcast address spoofed with the victim IP as source to amplify the traffic
- **SYN flood** : initiate many TCP sessions with different spoofed source IPs and never send the ACKs
- **XMAS attack** : messages have FIN, URG and PSH flags set, which is an unexpected combination that made many servers crash
- **HTTP flood** (for web servers)

#### Ping of Death

Send a malformed and oversized packet to a victim server, causing some machines to crash on reception.  
It was one of the first DoS attacks, but modern OSs are no longer vulnerable to this attack.

#### Teardrop attack

Attack breaking an IP packet into fragments and modifying them so they overlap and go beyond the max size.  
Some machines crash or reboot when trying to re-assemble these fragments.

#### Fork Bomb

Attack creating a large number of processes on the victim machine to use up all available processing power.

#### DNS Amplification

Common DDoS attack sending a very small request to a DNS server with the spoofed source IP of the victim.  
The DNS server responds with a large message to the spoofed IP, amplifying the quantity of data received by the victim.

### Hijacking

Hijacking is the exploitation of a computer session in an attempt to gain unauthorized access to data, services or other resources.  

- **Session Theft** : the attacker steals or guesses the session ID of a web session, and takes over the already authorized session.


- **TCP/IP Hijacking** : the attacker takes over an ongoing TCP/IP session between 2 computers without the need of cookies.  
TCP/IP sessions authenticate only in the TCP 3-way handshake, so the attacker can control the session if he guesses the sequence IDs.


- **Blind Hijacking** : the attacker blindly injects data into a communication stream without knowing if successful or not.


- **Clickjacking** : use multiple transparent layers to trick a user to click on a button or link when they believe they clicked on the page.


- **Man in the Middle** : the attacker intercepts the network traffic between 2 machines and impersonates both sides.  
It is a very common attack on unsecure wireless networks.
  - **email hijacking** : the hacker gets control over an email account
  - **wifi eavesdropping** : hijacking a wifi connection
  - **man in the browser** : MitM attack limited to a client browser (trojan infecting the browser) 


- **Watering Hole** : the attacker puts a malware on a website that he knows the victim often uses.

### Null Sessions

A null session is an unauthenticated network connection to a Windows-based machine's **IPC$** (Inter-Process Communication Share).  
The connecting entity does not need to provide valid credentials but can still establish a limited form of access to the system.  

Null sessions are normally used with the SMB or NetBIOS protocols for machines to share with each other info about files
and printers on Windows networks. 

It may be used by an attacker as part of information gathering by :
```commandline
net use \<TARGET_IP>\ipc$ "" /u:""
```

To protect against it, we should block ports 445 (SMB) and 139 (netBIOS).  
It can also be prevented with an IPS or a Firewall blocking external requests on these ports.

### Supply-Chain attack

This is the attack of an external service provider of the victim, that has access to the victim's network.  
This is used when the victim has a strong defense, but the external service provider is easier to compromise.

### DNS Attacks

#### DNS Poisoning

Attack modifying the name resolution information in the cache of a DNS server.  
It causes the redirection of users to fraudulent websites.  
Targets of DNS poisoning are internal DNS servers inside a network (not public DNS servers).

#### Unauthorized Zone Transfer

The attacker requests replication of the DNS information to his system for use in a future attack.  
It provides a list of all internal server names and IP addresses.

#### Altered Host Files

The host file is a text file on each machine containing a mapping of IP addresses and names.  
It is first checked when a DNS resolution is required, and the corresponding IP is used if found.  
If not found, the machine will request a DNS resolution from a DNS server.  

By poisoning this host file, the attacker can force a specific machine to redirect to a malicious site.  
This redirection to a malicious site is called **pharming**.

The host file on Windows is located under : `%systemroot%/system 32/drivers/etc`

#### Domain Name Kiting

This is not really an attack, more an abuse of the domain name registration process.  
When registering a domain name, some providers offer a 5-days grace period, and we can delete it for free.  
If we re-register it right after, we can block a domain name from real users without paying for it.

### ARP Poisoning (or ARP Spoofing)

Attack modifying the mapping between IP address and MAC address inside a local network to steal, modify or redirect frames.    
ARP Poisoning can be avoided by VLAN segmentation and DHCP Snooping.

### SIM Swap Fraud

The SIM card (Subscriber Identity Module) of a mobile phone gives access to the network of the carrier and provides the phone number.  
An attacker calls the carrier of the victim pretending to be the victim, saying that he lost his phone and asking to 
transfer the phone number to a new SIM card.  
That gives the attacker access to the victim's phone number and all SMS (including codes for 2FA).  
This access allows to reset the password from GMail for example and take control over the victim's email address.

### Virtualization attacks

- **VM Escape** : attack allowing an attacker to break out of a normally isolated VM by interacting directly with the hypervisor
- **Data Remnant** : data left on a cloud server after the shutdown of the virtual machine, which could be stolen by an attacker
- **Privilege Elevation** : user grants himself the ability to run functions as higher-level user
- **Unencrypted VDI file** : A virtual machine is saved on the host as a VDI file that is not encrypted by default, so 
an attacker stealing the file can start the same virtual machine and access its content.  
To prevent it, we can encrypt the VM (in Virtual Box Settings > Disk Encryption).

### War Dialing

War dialing is an attack to automatically dial many phone numbers in order to identify numbers connecting to modems and other devices of interest.  
Hackers often use war dialing software, sometimes called "war dialers" to look for unprotected modems.  

War dialing is used to identify all phone numbers from a company, or identify potential vulnerable modems.   
Phone numbers can be dialed sequentially or randomly and notes.  
The response shows if the number is connected to a modem, a fax machine, an internal phone system, a home, or a business.

Many phone companies have systems that are designed to detect war dialing.  
These systems will lock a user out of the phone system if he is attempting to war dial.

Networks that still use modems can protect against war dialing by setting a callback feature.  
Instead of opening a connection on a call, the modem hangs up and calls back to initiate a connection only if the caller ID is identified.  
The best remediation is still to get rid of modems and use SSH access for remote connection instead.

## Emails

### Protocols

**IMAP** (Internet Message Access Protocol) is an email reception protocol.  
IMAP clients can sync their emails from the mail sever.  
Every action on a mail from a client (read/delete a mail) is performed on the server, and other clients will sync.  
It allows to use multiple clients (phone and laptop for example) and to see a common state on all of them.  
It is more recent and more convenient than POP3 for users that check emails on multiple devices.  
IMAP uses ports **143** (unencrypted) and **993** (SSL encrypted).

**POP3** (Post Office Protocol) is also an email reception protocol.  
Unlike IMAP, there is no sync process between the POP3 clients and the mail server.  
When an email is fetched from the mail server, it is deleted from the mail server (so other clients will not see it).  
POP3 uses ports **110** (unencrypted) and **995** (SSL encrypted).

**SMTP** (Simple Message Transfer Protocol) is a protocol to send emails from a web server to another.  
It uses ports **25** (unencrypted) and **465** (SMTPS - SSL encrypted).

**STARTTLS** is a protocol extension that can be used above SMTP to add SSL/TLS encryption.  
It is an optimistic encryption method : it starts with a plaintext SMTP connection, and then upgrades to a secure TLS 
or SSL encrypted connection if both the sending and receiving email servers support STARTTLS.  
It is more flexible than SMTPS and is slowly replacing it.  
If a secure connection is established, it uses port **587**.

### Email tools

**Email Tracker** is a Chrome plugin to know if the recipient has opened our email.  
It integrates with most email service providers (Gmail, Outlook, Yahoo Mail...). 

**Ugly Email** is a Chrome and Firefox plugin to detect and prevent tracking on our emails.  
An eye icon appears on tracked emails, and it shows on hover the tracker type (SendGrid, Salesforce...).  
It blocks the "tracking pixel" so the tracking is prevented.   
Note that messages tracked with the Email Tracker plugin are not detected.

**guerillamail.com** is a website that lets us create a temporary disposable email address.  
It is useful for registration on random websites requiring an email address to activate the account.


## Network Scanning 

Network scanning can provide information on live devices (OS, IP address, open ports...).  
It is used to detect vulnerabilities in the target network.  

Scanning live devices can be done with a **ping sweep**, sending a ICMP echo request to all IPs in the network.  
It is also possible to use ARP requests instead of ICMP to trick machines configured to not respond to ICMP.

Port discovery helps understand what services are running on each machine (database, web server, FTP server...).

**Fingerprinting** is the identification of the OS and application versions.  
It can be either active (sending requests to the network) or passive (eavesdropping the traffic).  

**Banner Grabbing** is a popular fingerprinting technique to find the version of running web servers.

```commandline
telnet 192.168.1.212 80       // use telnet on open port 80 (instead of usual 23)
HEAD / HTTP/1.0               // send a HEAD HTTP request
```
The response often contains server info like `Microsoft-IIS/8.5` or `Apache/2.0.46`.  

**netcat** is another tool that can help with banner grabbing, used just like telnet :
```commandline
nc 192.168.1.212 80
HEAD / HTTP/1.0
```

The **nmap** program can be used for network scanning, ports discovery and banner grabbing (see the Tools page).   
It is a command-line tool, and it offers the **Zenmap** GUI in KaliLinux.


## Vulnerability Scanning

**Nessus** is the most popular tool to detect vulnerabilities on running machines.  
- can create custom policies and finetune a lot of parameters for host discovery, port scanning, services discovery...
- can run scan using custom policies of default scan types
- detailled report on all vulnerabilities found and how to solve them
- uses plugin regularly updated to detect vulnerabilities




## Security Applications and Devices

### Host-based Firewall

A host-based firewall is a firewall protecting an individual host.  
Most OS have one by default :
- **Windows Defender Firewall** for Windows
- **PF** (Packet Filter) for MacOS managed with the `pfctl` command
- **iptables** or **nftables** for Linux distributions

Many third-party anti-malware suites also offer a software host-based firewall, like Symantec (Norton), McAfee or Zone Alarm.

### Antivirus

An antivirus is a software protecting a computer from malwares.  
The most popular antivirus solutions are **Kaspersky**, **BitDefender**, **Avast**, **Norton**, **McAfee**...  

Malwares can be identified by 2 main methods :
 - **by signature** : trying to match a malware signature (unique binary pattern for a known malware)
 - **by heuristic method** : sandbox testing of a file and determine if it is a virus from its behavior (risk of false positive)
            
An antivirus can scan the system on demand or on a schedule.  
Some polymorphic viruses change their code, making it hard to detect their signature.

### EPP (Endpoint Protection Platform)

An EPP is a software agent and monitoring system performing multiple security tasks at host-level.  
It can include an anti-virus, data encryption, DLP, firewalls, HIDS/HIPS...  
There are many on the market, and every year Gartner makes a list of the best EPPs.  
Leaders are the solutions offered by Microsoft, CrowdStrike and Symantec.


### EDR (Endpoint Detection and Response)

An EDR is a software agent collecting system data and logs for analysis to provide threat detection.  
It can work together with an EPP to find existing threats on the host.  

### UEBA (User and Entity Behavior Analytics)

UEBA is an approach that focuses on monitoring and analyzing the behavior of users and entities (devices, applications,
and systems) within an organization's network to detect and respond to security threats.  
It is often used together with SIEM solutions to enhance threat detection and incident response capabilities.  
It makes use of ML and AI.  
Leader UEBA solutions are **Microsoft Advanced Threat Analytics** and **Splunk User Behavior Analytics**.

### UTM (Unified Threat Management)

A UTM system is also called a next-gen firewall (NGFW).  
It is a comprehensive security solution that integrates multiple security features and functions into a single
appliance or software platform.  
UTM systems are designed to protect computer networks from a wide range of security threats and vulnerabilities.  
UTM may include a firewall, a NIDS/NIPS, content filter, anti-malware, DLP, VPN...  

UTM solutions are commonly used in both small and medium-sized businesses (SMBs) and larger enterprises to simplify 
network security management and enhance protection. 

Unlike an EPP, a UTM system protect an entire network, not a specific machine.


### Honeypot and Honeynet

Those are decoy servers and networks with intentional security flaws to attract attacks.  
They keep attackers away from the real routers and servers, and allow to analyze the attacks (types, IPs, ...)



## Cloud Security


### SECaaS (Security As A Service)

SECaaS encompasses a wide range of security services hosted in the cloud and delivered to users over the internet.  
They can include anti-malware, firewall, IDS/IPS, identity and access management (IAM), email security, encryption...  
SECaaS follows a subscription model, so clients pay a monthly fee and do not need to buy any hardware. 

### CASB (Cloud Access Security Broker)

A CASB is an enterprise management solution designed to mediate access to cloud services by users across all devices.  
CASB offer visibility on how cloud services are used within the organization.

It can provide many functionalities :
- SSO (single sign-on) for cloud services
- malware and rogue device detection
- monitor and audit user activity
- mitigate data exfiltration (DLP system)

### FaaS (Function as a Service)

FaaS is a cloud service model supporting **serverless** software architecture, provisioning a runtime container
where client code can be executed.

FaaS eliminates the need to maintain physical or virtual servers to run our code.  
It also saves cost, since we pay for the server only for the time the function has been running on the cloud.

The underlying architecture is entirely managed by the cloud provider (AWS when using AWS Lambda).

### Major cloud threats

- **Insecure API**
  - all APIs should communicate via an encrypted channel (HTTPS)
  - server-side request input validation
  - error messages not revealing internal details
  - throttling to prevent DoS (block IPs that send too many requests)
- **Improper key management**
  - all API calls should use secure authentication/authorization (like SAML or OAuth)
  - never hardcode keys in source code
  - delete unnecessary keys
- **Logging and monitoring**
  - SaaS does not let clients access logs, so logging should be done by clients
  - logs must be copied to long-term storage
- **Unprotected storage**
  - storage is usually in AWS buckets or Azure blobs
  - access control should use IAM, container policies and ACL
  - specify permissions to each storage (usually too permissive by default)


## Automation

### CI/CD

**Continuous Integration** is a software development method where code updates are tested and committed to a build server.  
It avoids merge conflicts and ensure that the latest code passes unit tests.

**Continuous Delivery** is a software development method where application is frequently tested and validated for availability.  
It ensures that the code passes all integration tests and is ready for release. 

**Continuous Deployment** is a software development method where application is frequently sent to production.


### DevOps / DevSecOps

**DevOps** is the merge of development and system integration team to work on the automation of CI/CD and smoothen the development cycle. 

**DevSecOps** adds security operations into DevOps so the security is taken into account at every step of the development cycle.

DevSecOps teams leverage **Infrastructure as Code**, they deploy resources in the cloud using deployment scripts.  
They generate consistent builds using orchestration runbooks.

## AI (Artificial Intelligence)

**AI** is the science of creating machines with the ability to develop problem-solving and analysis strategies without 
significant human intervention.

**ML** (Machine Learning) is a component of AI that enables a machine to develop a strategy for solving a task given a labeled dataset where 
features have been identified, but without further explicit instruction.  
It is very efficient for labeling and categorization when provided with a good training dataset.  

**Deep learning** is a refinement of ML where the training dataset has results but not features.  
The features need to be determined by the algorithm.



## Defence Solutions


### Password Management

Different passwords should be used for all important accounts, so one account can be compromised without impacting the others.

A **password manager** can be used to generate and manage strong passwords.  
Only the master password must be remembered, and other passwords are handled by the password manager.  
Popular password manager solutions are **LastPass**, **Dashlane**, **OnePassword**, **PasswordSafe**...

### Backup

All important data must be saved in a backup (for example Windows 10 full system backup).   
A files backup can be either on external drive or on the cloud (Google Drive, DropBox). 


### MFA (Multi-Factor Authentication)

MFA is an authentication technique that requires multiple types of identity proofs :
- **what we know** : password, PIN
- **what we have** : token, access card
- **what we are** : biometrics (fingerprints, DNA, voice, gait, retina)



### Encryption

#### Encryption in transit

Communication sent over an insecure network must be encrypted.  
Encryption in transit usually involves a key-based encryption/decryption to turn clear text into encrypted ciphers.  
The encryption can be **symmetric** (same key for encryption/decryption) or **asymmetric** (different keys). 

**RSA** is an asymmetric encryption algorithm.  
**DES** (Data Encryption Standard) and its successor **AES** (Advanced Encryption Standard) are symmetric encryption algorithms.

#### Encryption at rest

Data encryption at rest protects data on the disk in case of theft, seize, repair.  

On Windows machines, **BitLocker** is a volume encryption feature built-in with Windows Vista and above.  
BitLocker uses AES as a symmetric key encryption mechanism, and **TPM** (Trusted Platform Module) for the key generation.  
TPM is a module inside the motherboard so the disk is readable only from this motherboard.  
For motherboards that do not support TPM, we can use a USB drive to store the encryption key, and it should always be 
plugged to read the encrypted disk.

On MacOS machines, **FileVault** is the built-in disk encryption feature, using the login password to encrypt the entire disk.

**Veracrypt** is a software available on Windows / MacOS / Linux to create an encrypted volume.  
It can encrypt a folder, an entire non-system disk (for ex a flash drive) or the entire system drive.  
When creating the volume, we set an encryption algo (AES) and a password.  
Then we can mount the volume (password required), so it appears as all other volumes.  
When we no longer need to use its content, we should unmount the volume so its content is not readable.  
If we create an encrypted volume on an external drive, it can be mounted from any other machine that has Veracrypt installed.  

A **Self-Encrypted Drive** (SED) is an external drive with built-in encryption.  
When we first use it, we need to set a password.  
When we mount it, we need to provide the password, then it can be used normally.  
When we no longer need to use it, we should unmount or eject the drive.  

There is also hardware-level encryption with **HSM** (Hardware Security Module).  
It is a hardware device providing a high level of security for cryptographic operations and key management.  
HSM are expensive and less used than software-level encryption. 


### Device Hardening

Hardening is the action to take some common sense security measures to protect a device, including :  
- change credentials
- password policy
- upgrade firmwares
- patch/update libraries and softwares
- use secure protocols
- disable unused ports
- use key rotation
- kill unnecessary services (ie. Telnet)
- least privilege for each user

For example on a Windows server, we can go to "Services" and stop/disable all Remote Desktop services.

A good hardening practice is to use a **TOS** (Trusted OS).  
Multiple governments (US, Canada, France...) maintain a list together of trusted OS regarded as secured enough for government critical operations.  
These TOS include Windows 8+, MacOS 10.6+, FreeBSD, Red Hat Enterprise Server...

#### Windows 10 Hardening

- Settings > Privacy > General : Set all privacy settings to off to prevent Microsoft to use ads and track our application use
- Connect to our Microsoft account > Privacy Dashboard > Personalized Ad Settings > Off
- Turn off Cortana if it is active and all data it is allowed to access
- Settings > Privacy > Location > Turn off location tracking
- Settings > Update & Security > Advanced Options > Delivery Optimization > turn off downloads from other PCs
- Settings > Network & Internet > Windows Firewall > Ensure the firewall is on
- Settings > Network & Internet > Wifi > Use random hardware address (if supported by the network adapter)


### CWE / CVE / NVD

**CWE** (Common Weakness Enumeration) is a community-developed list of software and hardware weakness types that can 
lead to vulnerabilities in computer systems and software applications.  
CWE is maintained by the MITRE Corporation and is used as a classification system for vulnerabilities in software and hardware.

**CVE** (Common Vulnerabilities and Exposures) is a database of known vulnerabilities maintained by the MITRE corporation.  
It is used by security professionals to keep up to date with the latest securities issues.  
Hackers use these CVEs to craft exploits that use the vulnerability to attack a system.  
Keeping softwares patched prevents all these attacks.

**NVD** (National Vulnerability Database) is a publicly accessible database listing CVEs and their remediation.  
It feeds from the CVE database and exposes a better navigation for the vulnerabilities.


## Supply Chain Management

Hardening the network implies making sure all suppliers can be trusted.  

To choose suppliers, we must apply **due diligence**, and check that they have :
- cyber-security programs
- security assurance and risk management processes
- a clear product support lifecycle
- security controls for confidential data
- incident response and forensics assistance
- historical information (to be sure they won't go out of business)

### Trusted Foundry Program

As part of the supply chain management, the supply of hardware must be also be reviewed.  
The **DoD** (US Department of Defense) created the **Trusted Foundry Program** for their micro-processor supply.  
It is a micro-processor manufacturing utility operated by the DoD and part of a validated supply chain.

### Hardware Root of Trust (ROT)

The Root of Trust is a cryptographic module embedded within a computer system that enables a secure boot process (for example TPM).  
It scans the boot metrics and OS files to verify their signature.  
It is a digital certificate embedded inside the hardware.  

### Trusted Firmwares

Trusted firmwares are validated to be secured, reliable and resistant to threat to prevent being compromised by firmware exploits.  
They use multiple techniques to prevent to be tampered with :
- **UEFI** (Unified Extensible Firmware Interface) : alternative to BIOS, it is a type of system firmware providing support for 64-bit CPU operations at boot.   
It has full GUI and mouse operation at boot and better boot security.  
All modern machines use UEFI and not BIOS.
- **Secure Boot** : UEFI feature that prevents unwanted processes from executing during the boot operation
- **Measured Boot** : UEFI feature gathering secure metrics to validate the boot process in an attestation report
- **Attestation** : Claim that the data presented in a report is valid by digitally signing it using the TPM's private key
- **eFUSE** (electrically programmable fuse) : type of semiconductor component used in integrated circuits for one-time programmable memory.  
They mimic traditional fuses and can be programmed or blown electronically (rather than physically).
- **Trusted Firmware Updates** : firmware update that is digitally signed by the vendor and trusted by the system before installation.


## SDLC (Software Developement Life Cycle)

SDLC is an organized process to develop secure software application.  
The software goes through multiple steps in a waterfall model.  

Different companies may have different steps, the official SDLC steps for Security+ are :
- **Planning and Analysis**
- **Software and System Design**
- **Implementation**
- **Testing**
  - System testing (black-box, gray-box, white-box)
  - Static analysis (full review of the source code)
  - Dynamic analysis (testing on running system)
- **Integration**
- **Deployment**
- **Maintenance** (Versioning, Patches, Retirement...)

**Agile development** is an alternative development method based on small increments to add flexibility.  
The development is split into **sprints**, short periods of 2 or 4 weeks that focus on specific features. 


## eDiscovery

eDiscovery is the electronic aspect of identifying, collecting, and preserving ESI (Electronically Stored Info) for legal purpose.  
This info must be presented in case of an investigation or a lawsuit.

## Jailbreaking

Jailbreaking an iPhone or an iPad is the process of hacking its software to remove restriction.  
The kernel is the core program controlling everything in the system, it is one of the first programs to load when the device is powered.  
Jailbreaking is performed by applying patches on the kernel to modify the way it operates.  
It is technically legal to jailbreak our device.  
However it implies the loss of the warranty and customer support, and official updates would break the device.


## Wireless Security

Wireless access must encrypt its data and require authentication to access a network.  
The successive protocols to encrypt data over a wireless connection are :
- **WEP** (Wired Equivalent Privacy) : approved in 1999, very vulnerable and abandoned in 2004
- **WPA** (Wifi Protected Access) : improvement of WEP but still exploitable
- **WPA2** : Uses AES for encryption
- **WPA3** launched in 2018 and supported by Wifi 6 compatible routers


## Domain Name Registrar

A domain name registrar is a company that allows to purchase and register domain names.   

All domain name registrars are accredited by **ICANN** (Internet Corporation for Assigned Names and Numbers), a 
non-profit organization responsible for managing domain names.

A domain name is registered for a given duration, up to 10 years.  
If it is not renewed before expiration, the domain name expires and anyone can register it.

It is possible to transfer the management of a domain name to another registrar if unhappy with the current registrar.  
This transfer cannot be done within the first 60 days after the domain name purchase.

A domain in `.com` costs around 15$ a year.

Some popular domain name registrars are :
- **Domain.com** : licensed for all top-level and many country-level extensions
- **Bluehost** : web hosting provider and WordPress partner, they offer free domain name registration when hosting a site with them
- **GoDaddy** : major registrar offering many extensions and an easy-to-use interface for domain name management


## 5 Eyes (FVEY)

5 Eyes is an intelligence alliance between Australia, Canada, New Zealand, the UK and the US, collaborating on 
intelligence gathering, surveillance and data collection.  
The exact scope of their activities is confidential and not disclosed.  

Extended alliance including more countries were formed :
- **9 Eyes** : 5 Eyes + France + Denmark + Norway + Netherlands
- **14 Eyes** : 9 Eyes + Sweden + Germany + Belgium + Italy + Spain


## File Systems

A file system (FS) is a method used by an OS to store, organize, and manage files and directories on a storage device.  
Most popular file systems are :

- **FAT32** (File Allocation Table) : old FS used by previous versions of Windows, with a 4GB file size limit  
- **exFAT** (Extended FAT) : portable Microsoft FS building on FAT32 and improving file size limit 
- **NTFS** (New Technology FS) : modern FS used by Windows, supporting file/folder permissions, compression, encryption...
- **ext4** (Extended FS) : FS commonly used on Linux and other Unix-based OS
- **HFS+** (Hierarchical FS) : old FS used by macOS
- **APFS** (Apple FS) : modern FS introduced by Apple for MacOS and iOS devices

It is possible to convert a drive using FAT32 to NTFS without data loss.  

Every FS is not supported natively with every OS.  
MacOS can read but not write to NTFS disks, and Windows does not even recognize HFS+ or APFS disks.  
When a disk is formatted, the chosen FS governs which devices can read or write to the disk.  

FAT32 and exFAT are a good choice when compatibility between OS is needed (flash drives, memory cards...). 