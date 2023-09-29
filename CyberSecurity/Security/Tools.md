# Cyber-Security Tools


## NMAP (Network Mapper)

NMAP is a network scanner used to discover machines on a network, scan them for open ports and detect the version of programs running on these ports.

NMAP default port scan sends packets to the target machines on every port, which can be intrusive.  
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
