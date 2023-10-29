# Cyber-Security Tools


## NMAP (Network Mapper)

NMAP is a network scanner used to discover machines on a network.  
NMAP can scan them for open ports and detect the version of programs running on these ports.

NMAP's default port scan sends packets to the target machines on every port, which can be intrusive.  
It may be detected by the IDS of the target, and further requests may be blocked by their firewall.  
NMAP comes with various options to customize the type of scan, with different stealth levels.

NMAP also comes with a collection of scripts used to detect vulnerabilities on the target network.

```commandline
nmap                                 # display the help
nmap 192.168.0.1 -v                  # increase logging level of the result (-vv for even more logging)

# TARGET SPECIFICATION
nmap 192.168.0.1                     # scan a machine by IP (machine discovery + port scan)
nmap scanme.nmap.org                 # scan a machine by hostname
nmap microsoft.com/24                # scan a network by domain name
nmap -iR 10                          # scan 10 random targets on the internet

# HOST DISCOVERY
nmap facebook.com/24 -sL             # List scan, only list machines but no port scan (stealth scan - no package sent)
nmap facebook.com/24 -sn             # Ping scan, only sending a ICMP echo request to each host to know which are up (no port scan)
nmap facebook.com/24 -Pn             # Skip host discovery (ping) and launch port scan assuming all targets are up
nmap 192.168.1.130 -PS80             # Host discovery using TCP SYN packet to given port(s)
                                     #   -PA[portlist]    alternative using TCP ACK
                                     #   -PU[portlist]    alternative using UDP

# SCAN TECHNIQUES
nmap 192.168.1.123 -sS               # TCP SYN port scan (default)
nmap 192.168.1.123 -sT               # TCP Connect port scan (very slow, more detectable, but no admin right required on source machine)
nmap 192.168.1.123 -sU               # UDP port scan
nmap 192.168.0.123 -F                # limit the scan to the top 100 ports
nmap 192.168.0.123 -p68-150          # limit the scan to the specified ports
nmap 192.168.1.123 -O                # enable OS detection
nmap 192.168.1.123 -sV               # enable service detection on each scanned port
nmap 192.168.0.123 -sC               # Script Scan, running default NSE (NMAP Script Engine) scripts for more info gathering
nmap 192.168.0.123 --script vuln     # Run a bunch of scripts to detect vulnerabilties on a target system
nmap 192.168.0.123 -A                # Aggressive scan (full port scan, OS and service detection, script scanning, traceroute)

# FIREWALL EVASION
nmap 192.168.0.123 -f                # fragment packets so firewalls don't know it comes from NMAP by the packet size
nmap 192.168.0.123 --mtu 16          # force a max packet size (multiple of 8) so firewalls don't know it comes from NMAP by the packet size
nmap 192.168.0.123 -D 192.168.0.1,192.168.0.3   # use decoys to spoof the source IP address
                                     # the scan appears to come from multiple sources (including us)
                                     # should use live decoys that do not look suspicious to the target
nmap 192.168.0.123 -g 53             # use a specific source port, should use trusted port numbers like 53 (DNS), 20 (FTP), 67 (DHCP) or 88 (Kerberos)
```

## Nessus

Nessus is a commercial vulnerability scanning tool.  
It identifies vulnerabilities on a network, classifies them and assigns a severity to each of them.  
It also keeps track of past vulnerabilities and reports.

Nessus lets us create **scan policies**, that are definitions to describe the vulnerability tests to run.  
We can provide some credentials to a Nessus policy to perform a credentials scan (and detect vulnerabilities when logged in).  
Nessus offers many **plugins** that are all potential vulnerabilities to check for.  

To start a scan, we must specify which scan policy to apply, and the targets of the scan.  
Once completed, the scan generates a report of all detected vulnerabilities for each target server.  
It provides details on each vulnerability, like the description, the severity, the CWE, the tools that can exploit it...


## WireShark

WireShark is an open-source network packet analyzer offering a GUI to capture, analyze and load network packets.  

WireShark was first released in 1998 under the name "Ethereal" and renamed to "WireShark" in 2006.  
Many people contributed to it to add support for more protocols.  
In 2023, it moved to the WireShark Foundation non-profit corporation that promotes network education and hosts SharkFest (WireShark developer and user conferences). 


## Hashcat

Hashcat is a password recovery and cracking tool.  
It is free and accessible online as a zip folder.

It takes as input a target hash, a hashing method and a list of passwords, and it tries to find one password in the list that generates this hash.

Hashcat can also perform mask attacks, similar to brute force attacks with constraints (password length, only alpha-numeric, ...).

All hashes found by Hashcat are stored in a _hashcat.potfile_ file.

Hashcat shows a status of `Cracked` if a match was found, `Exhausted` otherwise.  

```commandline
hashcat -h                                         # display help
hashcat -a 0 -m 0 hash.txt dict.txt                # try to find a password in a dict that generates a given hash
                                                   #   -m to specify the hashing method (0 : MD5)
                                                   #   -a to specify the attack mode (0 : straight, 1 : combination, 3 : mask)
hashcat -a 1 -m 0 hash.txt dict.txt rockyou.txt    # try to find a password in multiple dicts
hashcat -a 3 -m 0 hash.txt ?l?l?l?l?l?l            # try to find a password of 6 lower letters
```

Note : to get the hash for a given string, we can use an online hash tool or the `Get-FileHash` command from Powershell :
```commandline
Get-FileHash movie.mp4 | format-List                              # SHA256 hash (default)
Get-FileHash movie.mp4 -Algorithm MD5 | format-List               # MD5 hash
```


## John the Ripper

John the Ripper is another password cracking tool, offering similar functionalities as HashCat.  
It comes with a free community edition.

John the Ripper is pre-installed on KaliLinux, and accessible with the `john` command.  

For example, to crack the password of a ZIP or RAR archive, we can run :
```commandline
zip2john Test.zip > hash.txt        // create a file with the target hash
john --format=zip hash.txt          // find the password of the ZIP
```

John the Ripper can also crack the password from Linux users.  
The password hashes are stored under `/etc/shadow` and can be cracked with :
```commandline
useradd -r user2        // create a user
passwd user2            // set a password for user2
john /etc/shadow        // crack the password for user2
```


## Recon-ng

Recon-ng is a terminal reconnaissance tool shipped with Kali Linux.  
It is similar to Maltego, but offering a custom DSL in the terminal instead of a GUI.

```commandline
recon-ng                          # start the Recon-ng DSL
help                              # show all available commands of the DSL
back                              # quit the loaded module or workspace, or exit Recon-ng
exit                              # quit Recon-ng

marketplace install all           # install all available modules
workspaces list                   # show all workspaces
workspaces create google          # create a workspace called "google" for a reconnaissance on google.com
workspaces load google            # enter inside the "google" workspace
show                              # list all available item types (company, email, ...) in the loaded workspace
show companies                    # list all companies registered in the workspace
show contacts                     # list all contacts registered in the workspace
db insert companies               # insert a new company item in the workspace (prompt for company details)
db insert domains                 # insert a new domain name in the workspace (prompt for domain details)

marketplace search whois          # search all existing modules for "whois"
modules load recon/domains-contacts/whois-pocs     # load a module listed by the above command
info                              # show how to use the currently loaded module
options set SOURCE google.com     # set the SOURCE option of the module to "google.com"
run                               # find the point of contact (poc) of the SOURCE domain and add it to the contacts table

marketplace search brute
modules load recon/domains-hosts/brute_hosts       # load a module listed by the above command
info                              # show how to use the currently loaded module
run                               # try to check subdomain existence using a brute-force from a text file

marketplace search interesting
module load discovery/info_disclosure/interesting_files
info                              # show how to use the currently loaded module
run

marketplace search reporting
modules load reporting/html       # load a module to report all findings of the workspace
info
options set CREATOR Bob
options set CUSTOMER Google
run
```

## Havij

Havij is an automated SQL Injection tool that helps penetration testers to find and exploit SQL Injection vulnerabilities on a web page.  
It is developed by ITSecTeam, an Iranian security organization.  
The name Havij means "carrot" in Persian language.


## BlackEye

BlackEye is an application on KaliLinux to create a fake login page for popular websites (Facebook, LinkedIn, Paypal...).  
It generates a URL to send to the victim that looks like the original login page.  
When accessed, info about the victim (IP and browser) get displayed in the KaliLinux console running BlackEye.  
When the victim enters his username and password, they are displayed to the console, and the victim is redirected to the real site.


## Brave / Ghostery

**Brave** is a Chromium-based web browser focusing on privacy.  
It blocks fingerprinting, ads and ad-trackers by default.

**Ghostery** is a privacy suite offering ads and trackers blocker, a search engine and a web browser.  
It can be installed as a plugin on most popular browsers (Chrome, Firefox, Edge, Safari, Opera).


## Tor browser

Tor is a web browser transferring the incoming traffic through a network of computers to provide anonymity and untraceability.  
Requests sent to Tor go to 3 Tor relays before being sent to the target website.  
The communication is encrypted between all Tor relays.  

Files downloaded with Tor should NEVER be open while online as they can reveal the user's real IP.  

Tor is not useful to download torrents, since they tend to ignore proxy settings and make direct transfer, use a VPN instead.

Since Tor provides good anonymity, it is used by many cyber-criminals, and Tor users can be flagged as "extremists" 
and "persons of interest" by the NSA, which cannot distinguish good and bad Tor users.  
Many Websites (Nike, Expedia, ...) block all connections from Tor machines.  

The main attack on Tor is called the "end-to-end correlation attack" : it consists in monitoring the requests entering 
the Tor network and the requests getting out of the Tor network, and try to correlate them to deduce the user that sent the request.  
This can be made harder when using HTTPS (so the request is encrypted even before and after the Tor network) but it is 
still possible to correlate the timing between entering and exiting requests in the Tor network.

Users of Tor can access the darkweb (websites that are not referenced by search engines).  
Accessing the darkweb is legal, but a lot of the services offered on darkweb sites are illegal.  
All transactions on the darkweb are settled in bitcoin.

We can use a VPN to connect to Tor, it hides to the ISP that we access Tor, and it prevents the Tor network entry point
to see our real IP (but the VPN provider knows it).


## Holehe

Holehe is a Python script testing the registration of an email address against over 120 services (Amazon, GitHub...).  
The target email address is not alerted (no mail sent to the address to reset a password for example).  

It is a useful tool for **OSINT** (Open-Source INTelligence) to gather information on people.  
It can be integrated with Maltego for automatic social networks reconnaissance in GUI.


## ProtonMail

ProtonMail is an email service provider focused on privacy and security based in Switzerland.  
The free version offers 1 address (xxx@protonmail.com) and 500Mb of storage.  
The paid version allows to use a custom domain and get rid of the ProtonMail signature.


## CCleaner and BleachBit

CCleaner and BleachBit are two cleaner programs for Windows.  
They can help to remove useless files, clear caches, remove cookies and free up disk space.


## NordVPN / TunnelBear / CyberGhost

NordVPN, TunnelBear and CyberGhost are 3 popular VPN services that offer secure and private internet connections.

NordVPN offers strong security features and commitment to user privacy.  
TunnelBear has less features but has a more intuitive GUI that makes it a good choice for beginners.  
CyberGhost is an intermediate solution balancing a good range of feature with an intuitive GUI. 


## Burp Suite

The Burp suite is a web application security testing software.  
It is configured as a proxy that intercepts and forwards the traffic between a local browser and a target website.  
It analyzes the traffic, sends its own requests to the website, and reports all found security vulnerabilities.

The Burp suite comes with a Community, a Professional and an Enterprise edition.  
The Community edition only includes a proxy and requests history, but a free trial of the Pro edition is available.


## Altoro Mutual

Altoro Mutual is a fake banking website with intentional security flaws.  
It is developed by IBM to demonstrate the efficiency of their security products.  

The application code is open source and available on GitHub : [https://github.com/HCL-TECH-SOFTWARE/AltoroJ](https://github.com/HCL-TECH-SOFTWARE/AltoroJ)


## The WayBack Machine

The WayBack Machine is a website that takes snapshot of websites and allow to see a website as it used to be in the past.  
This can be used to see the content of previous versions of websites.

## ICANN Lookup

ICANN Lookup is a website giving public info on registered domain names.  
This info can be hidden by the domain name registrar (like GoDaddy) when requested.  
