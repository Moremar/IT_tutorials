# Cyber-Security Tools


## Networking Tools


### NetSpot

NetSpot is a software tool for wireless network assessment, scanning and survey.  
It can analyze Wi-fi coverage and performance.  
It runs on Windows and MacOS.  
It is used to analyze radio signal leaks, map channel use, optimize wireless AP locations...


### WireShark

WireShark is an open-source network packet analyzer offering a GUI to capture, analyze and load network packets.  

WireShark was first released in 1998 under the name "Ethereal" and renamed to "WireShark" in 2006.  
Many people contributed to it to add support for more protocols.  
In 2023, it moved to the WireShark Foundation non-profit corporation that promotes network education and hosts SharkFest
(WireShark developer and user conferences). 

WireShark can also load packets captured with `tcpdump`.


### NetCat

NetCat is a command-line utility available on Windows and Linux to read from and write to network connections.  
It offers a backend for other machines to connect to a machine.  
It is often used to create a backdoor to access a machine remotely.

NetCat can be used in multiple ways :
- data transfer
- relay
- port scanning
- reverse shell / bakdoor
- chat

```shell
# start NetCat in listening mode on port 1234
nc -l -p 1234

# from another machine, open a connection to it (for chat for example)
nc <TARGET_IP> 1234

# start NetCat as a proxy listening on port 1234 and redirecting a a target host/port
nc -l -p 1234 | nc <TARGET_HOST> <TARGET_PORT>

# use NetCat for scanning ports on a target machine
# -v is for verbose mode and -z for scanning mode (without sending data)
nc -v -z <TARGET_HOST> <START_PORT>-<END_PORT>
```

### OpenSSL

[OpenSSL](https://www.openssl.org/) is an open-source command-line tool for cryptography and secure communications.  
It is commonly used to generate private keys, create CSRs, install an SSL/TLS certificate, and identify certificate information.


### CyberDuck

[CyberDuck](https://cyberduck.io/) is a free server and cloud storage browser on Mac and Windows.  
It supports many storage technologies, including FTP, SFTP, AWS S3, MS Azure, Google Drive, OneDrive, DropBox... 


## Privacy Tools


### NordVPN / TunnelBear / CyberGhost

NordVPN, TunnelBear and CyberGhost are 3 popular VPN services that offer secure and private internet connections.

NordVPN offers strong security features and commitment to user privacy.  
TunnelBear has less features but has a more intuitive GUI that makes it a good choice for beginners.  
CyberGhost is an intermediate solution balancing a good range of features with an intuitive GUI. 


### Brave / Ghostery

**Brave** is a Chromium-based web browser focusing on privacy.  
It blocks fingerprinting, ads and ad-trackers by default.

**Ghostery** is a privacy suite offering ads and trackers blocker, a search engine and a web browser.  
It can be installed as a plugin on most popular browsers (Chrome, Firefox, Edge, Safari, Opera).


### Tor browser

Tor is a web browser transferring the incoming traffic through a network of computers to provide anonymity and untraceability.  
Requests sent to Tor go to 3 Tor relays before being sent to the target website.  
The communication is encrypted between all Tor relays.  

Files downloaded with Tor should NEVER be open while online as they can reveal the user's real IP.  

Tor is not useful to download torrents, since they tend to ignore proxy settings and make direct transfer, use a VPN instead.

Since Tor provides good anonymity, it is used by many cyber-criminals.  
Tor users can be flagged as "extremists" and "persons of interest" by the NSA, which cannot distinguish good and bad Tor users.  
Many websites (Nike, Expedia, ...) block all connections from Tor machines.  

The main attack on Tor is called the **end-to-end correlation attack**.  
It consists in monitoring the requests entering the Tor network and the requests getting out of the Tor network, and try to correlate them to deduce the user that sent the request.  
This can be made harder when using HTTPS (so the request is encrypted even before and after the Tor network) but it is 
still possible to correlate the timing between entering and exiting requests in the Tor network.

Users of Tor can access the darkweb (websites that are not referenced by search engines).  
Accessing the darkweb is legal, but a lot of the services offered on darkweb sites are illegal.  
All transactions on the darkweb are settled in bitcoin.

We can use a VPN to connect to Tor, it hides to the ISP that we access Tor, and it prevents the Tor network entry point
to see our real IP (but the VPN provider knows it).


### ProtonMail

ProtonMail is an email service provider focused on privacy and security based in Switzerland.  
The free version offers 1 address (xxx@protonmail.com) and 500Mb of storage.  
The paid version allows to use a custom domain and get rid of the ProtonMail signature.


### CCleaner and BleachBit

CCleaner and BleachBit are two cleaner programs for Windows.  
They can help to remove useless files, clear caches, remove cookies and free up disk space.



## Reconnaissance Tools


### OSINT

OSINT tools provide information from free public resources on the Internet.  
It is the main element of passive reconnaissance.  

Many OSINT resources are categorized in the OSINT framework website : [https://osintframework.com/](https://osintframework.com/)

### NMap (Network Mapper)

NMap is a network scanner used to discover machines on a network.  
NMap can scan a machine for open ports and detect the version of programs running on these ports.

NMap's default port scan sends packets to the target machines on every port, which can be intrusive.  
It may be detected by the IDS of the target, and further requests may be blocked by their firewall.  
NMap comes with various options to customize the type of scan, with different stealth levels.

NMap also comes with a collection of scripts used to detect vulnerabilities on the target network.

```shell
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
nmap 192.168.0.123 -sC               # Script Scan, running default NSE (NMap Script Engine) scripts for more info gathering
nmap 192.168.0.123 --script vuln     # Run a bunch of scripts to detect vulnerabilties on a target system
nmap 192.168.0.123 -A                # Aggressive scan (full port scan, OS and service detection, script scanning, traceroute)

# FIREWALL EVASION
nmap 192.168.0.123 -f                # fragment packets so firewalls don't know it comes from NMap by the packet size
nmap 192.168.0.123 --mtu 16          # force a max packet size (multiple of 8) so firewalls don't know it comes from NMap by the packet size
nmap 192.168.0.123 -D 192.168.0.1,192.168.0.3   # use decoys to spoof the source IP address
                                     # the scan appears to come from multiple sources (including us)
                                     # should use live decoys that do not look suspicious to the target
nmap 192.168.0.123 -g 53             # use a specific source port, should use trusted port numbers like 53 (DNS), 20 (FTP), 67 (DHCP) or 88 (Kerberos)
```


### Recon-ng

Recon-ng is a terminal reconnaissance tool shipped with Kali Linux.  
It is similar to Maltego, but offering a custom DSL in the terminal instead of a GUI.

```shell
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


### scanless

scanless is a utility to create an exploitation web server that can perform open port scans in a stealthier manner.  
If the target notices the scan, it appears as being performed by this web server instead of the actual host.


### dnsenum

dnsenum is a DNS reconnaissance tool.  
It is used to enumerate all DNS servers and DNS entries for a given organization.


### The Harvester

The harvester is a Python script used by red teams during penetration tests to perform OSINT reconnaissance.  
It can gather emails, subdomains, hosts, employee names, open ports, IPs...  
It retrieves its information from public sources, like search engines, PGP key servers, the Shodan database...


### ICANN Lookup

ICANN Lookup is a website giving public info on registered domain names.  
This info can be hidden by the domain name registrar (like GoDaddy) when requested.  


### Holehe

Holehe is a Python script testing the registration of an email address against over 120 services (Amazon, GitHub...).  
The target email address is not alerted (no mail sent to the address to reset a password for example).  

It is a useful tool for **OSINT** (Open-Source INTelligence) to gather information on people.  
It can be integrated with Maltego for automatic social networks reconnaissance in GUI.


### Shodan Database

The Shodan database is a search engine use to search for various types of devices (webcam, router, server)...


### The WayBack Machine

The WayBack Machine is a website that takes snapshot of websites and allows to see a website as it used to be in the past.  
This can be used to see the content of previous versions of websites.



## Vulnerability Scanning Tools


### Nessus

Nessus is a commercial vulnerability scanning tool.  
It identifies vulnerabilities on a network, classifies them and assigns a severity to each of them.  
It also keeps track of past vulnerabilities and reports.

Nessus lets us create **scan policies**, that are definitions to describe the vulnerability tests to run.  
We can provide some credentials to a Nessus policy to perform a credentials scan (and detect vulnerabilities when logged in).  
Nessus offers many **plugins** that are all potential vulnerabilities to check for.  

To start a scan, we must specify which scan policy to apply, and the targets of the scan.  
Once completed, the scan generates a report of all detected vulnerabilities for each target server.  
It provides details on each vulnerability, like the description, the severity, the CWE, the tools that can exploit it...


### sn1per

sn1per is an automated scanner used during a penetration test to enumerate and scan vulnerabilities on the network.  
It combines in a single tools several reconnaissance and exploit tools (Nmap, Metasploit, theHarvester...).  
It is an alternative to Nessus.


### Burp Suite

The Burp suite is a Java-based web application security testing software.  
It is the industry standard tool for web application and mobile application penetration testing.

Burp is configured as a web proxy : it captures and enables manipulation of HTTP/HTTPS traffic between a browser and a web server.  
It analyzes the traffic, sends its own requests to the web server, and reports all found security vulnerabilities.

The Burp suite comes with a Community, a Professional and an Enterprise edition.  
The Community edition only includes a proxy and requests history, but a free trial of the Pro edition is available.

Burp Suite Professional comes with an automated vulnerability scanner, a fuzzer with no rate limit, access to Burp extensions...

Burp Suite Enterprise is mostly used for continuous scanning.  
It is installed on a server and constantly scans the target web application for potential vulnerabilities.


### ffuf - Fuzz Faster U Fool

fuff is a fast web fuzzer written in Go.  
It accepts a list of words, and sends many requests to a web server replacing a placeholder by the words in the list.  
It can detect which requests were successful and which were not and report its findings.  
This is used for discovery of hidden files or pages in a website.

Some good word lists are publicly available :
- [https://github.com/danielmiessler/SecLists](https://github.com/danielmiessler/SecLists)
- [https://github.com/six2dez/OneListForAll](https://github.com/six2dez/OneListForAll) 

```shell
# simple example with a FUZZ placeholder in the URL
ffuf -w wordlist.txt -u 'https://ffuf.io.fi/FUZZ'

# same but with a custom placeholder name
ffuf -w wordlist.txt:FOO -u 'https://ffuf.io.fi/FOO'

# multiple word lists
# by default it tries every combination of words (n*m combinations)
# use "-mode pitchwork" to use the 1st word of each list, then the 2nd of each list... (n combinations)
ffuf -w wordlist1.txt:FOO -w wordlist2.txt:BAR -u 'https://ffuf.io.fi/FOO/BAR'

# list all valid usernames in a website among a list of usernames
# we use the POST method (GET by default)
# we provide the POST body with -d parameter, as url-encoded, so we add the corresponding header
# -mr lets us match the positive results on a regex (by default it matches on non-error response codes)
ffuf -w SecLists/Usernames/Names/names.txt
     -X POST
     -d "username=FUZZ&email=x&password=x&cpassword=x" 
     -H "Content-Type: application/x-www-form-urlencoded"
     -u http://10.10.1.80/customers/signup
     -mr "user already exists"

# brute-force password by using a list of valid usernames and a list of potential passwords
# use -fc 200 to filter out the 200 status code (considered as failed)
ffuf -w valid_usernames.txt:W1
     -w SecLists/Passwords/Common-Credentials/10-million-password-list-top-100.txt:W2
     -X POST
     -d "username=W1&password=W2" 
     -H "Content-Type: application/x-www-form-urlencoded"
     -u http://10.10.1.80/customers/login
     -fc 200
```


## Exploiting Tools


### Metasploit

Metasploit (or MSF for MetaSploit Framework) is a command-line security tool improving penetration testing.  
It offers information about software vulnerabilities and IDS signature development.

If a vulnerability was discovered (with Nessus or sn1per for example), we can check if Metasploit has an exploit for it.  
If it does, we can execute the exploit, and Metasploit can provide a command shell on this victim machine.  

It is a script-kiddie friendly framework to attack machines without understanding the actual vulnerabilities.  
It also offers more advanced capabilities, like the creation of custom plugins to exploit new vulnerabilities.


### BeEF (Browser Exploitation Framework)

BeEF is an open-source penetration testing tool designed to focus on the exploitation of web browsers.  
It is used by ethical hackers, security professionals, and penetration testers to assess the security of web applications and web browsers.  
It can be used to demonstrate various types of attacks that can be carried out through a web browser.


### Havij

Havij is an automated SQL Injection tool that helps penetration testers to find and exploit SQL Injection vulnerabilities on a web page.  
It is developed by ITSecTeam, an Iranian security organization.  
The name Havij means "carrot" in Persian language.


### BlackEye

BlackEye is an application on Kali Linux to create a fake login page for popular websites (Facebook, LinkedIn, Paypal...).  
It generates a URL to send to the victim that looks like the original login page.  
When accessed, info about the victim (IP and browser) get displayed in the Kali Linux console running BlackEye.  
When the victim enters his username and password, they are displayed to the console, and the victim is redirected to the real site.



## Password Cracking and Recovery


### Cain and Abel

Cain and Abel is a password recovery tool for Windows that can :
- sniff the network
- crack encrypted passwords (brute-force, dictionary attack)
- record VoIP conversations
- decode scrambled passwords
- reveal password boxes
- analyze routing protocols...


### Hashcat

Hashcat is an offline password recovery and cracking tool.  
It is free and accessible online as a zip folder.

It takes as input a target hash, a hashing method and a list of passwords, and it tries to find one password in the
list that generates this hash.

Hashcat can also perform mask attacks, similar to brute force attacks with constraints (password length, only alpha-numeric, ...).

All hashes found by Hashcat are stored in a _hashcat.potfile_ file.

Hashcat shows a status of `Cracked` if a match was found, `Exhausted` otherwise.  

```shell
hashcat -h                                         # display help
hashcat -a 0 -m 0 hash.txt dict.txt                # try to find a password in a dict that generates a given hash
                                                   #   -m to specify the hashing method (0 : MD5)
                                                   #   -a to specify the attack mode (0 : straight, 1 : combination, 3 : mask)
hashcat -a 1 -m 0 hash.txt dict.txt rockyou.txt    # try to find a password in multiple dicts
hashcat -a 3 -m 0 hash.txt ?l?l?l?l?l?l            # try to find a password of 6 lower letters
```

Note : to get the hash for a given string, we can use an online hash tool or the `Get-FileHash` command from Powershell :
```shell
Get-FileHash movie.mp4 | Format-List                              # SHA-256 hash (default)
Get-FileHash movie.mp4 -Algorithm MD5 | Format-List               # MD5 hash
```


### John the Ripper

John the Ripper is another password cracking tool, offering similar functionalities as HashCat.  
It comes with a free community edition.

John the Ripper is pre-installed on Kali Linux, and accessible with the `john` command.  

For example, to crack the password of a ZIP or RAR archive, we can run :
```shell
zip2john Test.zip > hash.txt        # create a file with the target hash
john --format=zip hash.txt          # find the password of the ZIP
```

John the Ripper can also crack the password from Linux users.  
The password hashes are stored under `/etc/shadow` and can be cracked with :
```shell
useradd -r user2        # create a user
passwd user2            # set a password for user2
john /etc/shadow        # crack the password for user2
```


### CrackStation.net

[https://crackstation.net](https://crackstation.net) is a website for cracking unsalted hashes.  
It keeps a database of billions of hashes and their original values for common hashing methods (MD5, SHA1, SHA-256, ...).  
It can detect automatically the hashing method used and give the original value for up to 20 hashes at a time.


### Crunch

Crunch is a utility that generates a custom word list to provide to a password cracker.  
We can specify the password min and max size and the allowed characters, and Crunch generates all possibilities.  
Crunch is available by default in Kali Linux.

```shell
# generate the pins.txt file containing all possible PIN numbers of 4 to 6 digits
crunch 4 6 0123456789 -o pins.txt
```


### CeWL (Custom Word List)

CeWL is another custom word list generator that uses the content of a website to create its word list.  
It is a Ruby app that spiders a given URL up to a specific depth to capture the words for its list.  
Its generated file can then be used with password crackers like **John the Ripper** or **Wfuzz**.

```shell
# generate a word list and an emails list from a website with depth 2 and min word length 5
cewl -d 2 -m 5 -w passwords.txt http://10.10.131.23 --email --email_file emails.txt
```


### Hydra

Hydra is an open-source password brute-forcing tool for online brute-force attacks.  
It is designed to operate via network protocols like SSH, RDP, HTTP and HTML forms.  
It is sending the login attempt one-by-one to the target and checks the response for success.

Unlike Hashcat or John the Ripper, it is not an offline password cracking tool.  
It does not check passwords against a target hash, but against a target network system (so it can be detected).

```shell
# try all passwords in a word list to access the target IP in SSH with a given user (login)
# -f to stop when a valid password is found
# -v for verbose logging
hydra -l testuser -P rockyou.txt -f -v <TARGET_IP> ssh

# try all passwords in a word list to access the target IP on a given HTML form
# no user is needed to access, only a password
# we specify the login PHP page, the field to use for the password, and the message on error (separated with ":")
hydra -l '' -P pins.txt -f -v 10.10.131.34 http-post-form "/login.php:pin=^PASS^:Access Denied" -s 8000
```

### Aircrack-ng

Aircrack-ng is an open-source suite of software tools used for assessing and testing the security of Wifi networks.  
It can capture packets on a wireless network and crack poorly secured Wifi passwords.  
It is available by default in the Kali Linux distribution.

For example, Aircrack-ng can crack a WEP password in a few minutes by IV attack.    

```shell
# list wireless networks and their encryption, find one using WEP
# Note down its channel and BSSID
airodump-ng wlan0mon

# Start scanning the target wireless network
airodump-ng --channel <CHANNEL> --bssid <BSSID> --write MyHackedTraffic wlan0mon

# Keep above command running and in another terminal send an auth request
aireplay-ng --fakeauth 0 -a <BSSID> -h <wlan0mon MAC ADDRESS> wlan0mon

# Get some ARP messages
aireplay-ng --arpreplay -b <BSSID> -h <wlan0mon MAC ADDRESS> wlan0mon 

# Crack the network using the IVs from the captured traffic
# It will try to infer the WEP key from all captured IVs
# It may fail if not enough data, it reruns every 5000 data captured by the scan 
aircrack-ng MyHackedTraffic.cap
```


## Forensics Tools


### FTK Imager (Forensic Tool Kit Imager)

FTK Imager is used to create a copy of a hard drive or a USB thumbdrive as a sequence of files.  
It is a GUI-based program for Windows.  
These files have the `.dd` extension, a format compatible with multiple forensic tools.

FTK Imager can then open the drive copy and analyze it.  
It shows all the files of the drive, even the deleted ones, which can sometimes be recovered.


### Autopsy

Autopsy is an open-source digital forensics platform.  
It offers a graphical interface to the Sleuth toolkit, and adds other digital forensics tools.  

Its imaging function relies on `dd`, and its analysis function relies on the Sleuth toolkit.


### Volatility

Volatility is a command-line tool used by digital forensics and incident response teams to analyze a memory dump.  
It is a Python program called `vol.py` that can analyze memory snapshots from Linux, MacOS and Windows.

Its main functions are :
- list active and closed network connections
- list running processes
- list command line history
- extract malicious processes for later analysis

It needs to be provided with the profile of the machine from which the memory dump was generated.  
It is required to know the memory structure of the OS, so Volatility can make sense of the dump.  
Windows profiles are available by default (see list with `vol.py --info`).  
Linux profiles must be created by the user and added to the local Volatililty Linux profiles folder.

```shell
vol.py -h                   # display help
vol.py --info               # display all profiles, commands, plugins...

vol.py -f linux.mem --profile="VistaSP0x64" linux_bash     # check command history file
vol.py -f linux.mem --profile="VistaSP0x64" linux_pslist   # check running processes
vol.py -f linux.mem --profile="VistaSP0x64" linux_procdump -D <OUTPUT_FOLDER> -p <PID>  # extract binary of a process
```


### Cuckoo

Cuckoo is an open-source software to automate the analysis of suspicious files.  
It is basically a sandbox where we can put a suspicious file and observe its behavior.


### WinHex

WinHex is a commercial disk editor and universal hexadecimal editor for Windows.  
It is used for digital forensics and data recovery.

WinHex allows users to view, edit, and analyze binary data on various types of storage media, including hard drives, USB drives, memory cards...  
It offers a wide range of features for examining and manipulating data at a low level.


### DNSpy (DotNet Spy)

DNSpy is an open-source tool designed for the analysis and editing of .NET assemblies.  
It is commonly used for reverse engineering, debugging, and modifying .NET applications. 



## Educational Tools


### Oxford Journal of Cyber-Security

Academic Journal from Oxford university offering free articles about Cyber-Security threats, attacks and latest defenses :

[https://academic.oup.com/cybersecurity](https://academic.oup.com/cybersecurity)


### Hacksplaining

[Hacksplaining](https://www.hacksplaining.com/) is a security training website.  
It explains and gives examples of most common web security issues, especially the OWASP Top 10 issues.


### OWASP Juice Shop

OWASP Juice Shop is a fake e-commerce web application designed with intentional security flaws.  
It can be deployed locally in a container, and its aim is to teach web vulnerabilities.  
It contains a score dashboard with a lot of challenges to break the website.


### OWASP WebGoat

WebGoat is a security testing software developed by OWASP written on the J2EE (Java 2 Enterprise Edition).  
It is an intentionally flawed web application containing hundreds of vulnerabilities.  
It offers courses to understand and exploit all these vulnerabilities.


### Altoro Mutual

Altoro Mutual is a fake banking website with intentional security flaws.  
It is developed by IBM to demonstrate the efficiency of their security products.  

The application code is open source and available on [GitHub](https://github.com/HCL-TECH-SOFTWARE/AltoroJ).
