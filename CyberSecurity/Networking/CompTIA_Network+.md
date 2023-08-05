# CompTIA Network+

## Network Models

### OSI Model (Open System Interconnection)

The OSI model was adopted in 1984 as the first standard model.  
It is made of 7 layers describing how computers communicate over a network.

| Layer |     Name     | Role                                                                                                                                                                         |
|:-----:|:------------:|------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
|   7   | Application  | Human/Computer interaction layer where applications can access the network services (web browser, mail client...).<br/>Protocols : HTTP, HTTPS, SMTP, POP3, IMAP, DNS, FTP... |
|   6   | Presentation | Translate data into a format that can be understood by the receiving system (encryption, compression, encoding...)                                                           |
|   5   |   Session    | Create communication channels (sessions) between devices.<br/>Can create checkpoints during data transfer for example.                                                       |
|   4   |  Transport   | Break messages into segments, flow control, error control, adapt send rate to target's connection speed.<br/>Protocols: TCP, UDP                                             |
|   3   |   Network    | Break segments into network packets, and route the packets by discovering the best path across the network using the target IP address.<br/>Protocols: IP, ICMP, ARP...      |
|   2   |  Data Link   | Break network packets into frames and establish/terminate the connection between 2 nodes.<br/>Protocols: Ethernet, TokenRing...                                              |
|   1   |   Physical   | Physical connector sending a series of 1 and 0 signals (cable or wireless connection)                                                                                        |


The Data Link layer is further split into 2 sub-layers :
- LLC layer : logical link control, identify network layer protocols and encapsulate them + flow control
- MAC layer : define how packets are placed on the media + error detection (CRC) + physical address

A **PDU** (Protocol Data Unit) is a single unit of information managed by a protocol.  
At application level, a PDU is **a payload**.  
In TCP, a PDU is **a segment**.  
In UDP, a PDU is **a datagram**.  
In IP, a PDU is **a packet**.  
In Ethernet, a PDU is **a frame**.  
At physical level, a PDU is **a bit**.


### TCP/IP Model

The TCP model was designed by the Department of Defence (DoD) in 1960.  
It is a concise version of the OSI model with only 4 layers.

| Layer |    Name     | Role                                                                                                                        |
|:-----:|:-----------:|-----------------------------------------------------------------------------------------------------------------------------|
|   4   | Application | Group layers 7, 6 and 5 of the OSI model.<br/>Protocols : HTTP, HTTPS, SMTP, POP3, IMAP, DNS, FTP...                        |
|   3   |  Transport  | Layer 4 of the OSI model, manage end-to-end communication and reliable data delivery between hosts.<br/>Protocols: TCP, UDP |
|   3   |  Internet   | Layer 3 of the OSI model, handle packet forwarding and routing to deliver data across interconnected networks.              |
|   2   |    Link     | Layers 2 and 1 of the OSI model, control the hardware-level communication between devices on the same network segment       |


## Protocols

|  Protocol  |   Port(s)   |                 Name                  | Layer | Role                                                                                                                                                                                                                                                |
|:----------:|:-----------:|:-------------------------------------:|:-----:|-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
|    STP     |      -      |        Spanning Tree Protocol         |   2   | Build a loop-free logical topology of an Ethernet network to decide switch ports to set to active                                                                                                                                                   |
|     IP     |      -      |           Internet Protocol           |   3   | Use an IP address (IPv4 or IPv6) for the source and destination of each packet to decide the best route through the networks.                                                                                                                       |
|    ICMP    |      -      |   Internet Control Message Protocol   |   3   | Transmission error control, sent by a host when a transmission error occurred.<br/>An ICMP packet is wrapped in an IP packet (it has an IP header).                                                                                                 |
|    TCP     |      -      |     Transmission Control Protocol     |   4   | Connection oriented reliable transport protocol that guarantees reception.<br/> It waits for a reception ACK of each segment and resends them if no ACK is received.<br/>It is reliable but has an overhead due to the connection and ACK mechanism. |
|    UDP     |      -      |        User Datagram Protocol         |   4   | Connection-less transport protocol with no ACK and no guarantee of reception.<br/>It is less reliable than TCP but has no overhead (used for streaming, video games...).                                                                            |
|    HTTP    |     80      |     Hyper Text Transfer Protocol      |   7   | Client/server communication between web browsers and web servers on the Internet.                                                                                                                                                                   |
|   HTTPS    |     443     |              HTTP Secure              |   7   | HTTP variant with SSL/TLS encryption of the communication between the browser and the server.                                                                                                                                                       |
|    DNS     |     53      |          Domain Name System           |   7   | Get the IP for a given hostname.<br/>It uses UDP for its transport layer so DNS servers do not need to keep connections.                                                                                                                            |
|   Telnet   |     23      |           Teletype Network            |   7   | Open a virtual terminal TCP connection to a remote machine.<br/>Developed in 1969 and deprecated for security reasons, replaced by SSH.                                                                                                             |
|    SSH     |     22      |             Secure Shell              |   7   | Open a secure channel to a remote host over an unsecure network.<br/>The traffic is encrypted, and SSH supports authentication with a password or with public/private keys.                                                                         |
|    FTP     |   20 / 21   |        File Transfer Protocol         |   7   | Transfer files from a server to a client on a network.<br/>Port 20 is used for data transfer (upload or download).<br/>Port 21 is used for control (commands and responses).                                                                        |
|    TFTP    |     69      |              Trivial FTP              |   7   | Simpler version of FTP with no authentication, no connection and basic error handling.<br/>Convenient for simple file transfer with no security concern.                                                                                            |
|    SFTP    |     22      |                SSH FTP                |   7   | Secure variant of FTP using SSH for encryption (so the traffic goes to SSH port 22)                                                                                                                                                                 |
|    FTPS    |  989 / 990  |           FTP over SSL/TLS            |   7   | Secure variant of FTP using a SSL/TLS encryption layer above normal FTP.<br/>Port 989 is used for data transfer.<br/>Port 990 is used for control.                                                                                                  |
|    DHCP    |   67 / 68   |  Dynamic Host Configuration Protocol  |   7   | Automatically assign an available IP to machines joining a network.<br/>Port 67 is used by the DHCP server.<br/>Port 68 is used by DHCP clients.                                                                                                    |
|    SMTP    |  25 / 587   |     Simple Mail Transfer Protocol     |   7   | Send emails to a mail server.<br/>The secure version using TLS encryption uses port 587.                                                                                                                                                            |
|    IMAP    |  143 / 993  |   Internet Message Access Protocol    |   7   | Used by a mail client to retrieve messages from a mail server, replacing POP3.<br/>The secure version using SSL uses port 993.                                                                                                                      |
|    POP3    |     110     |         Post Office Protocol          |   7   | Alternative to IMAP to retrieve messages from a mail server.<br/>The secure version using SSL uses port 995.                                                                                                                                        |
|    RDP     |    3389     |        Remote Desktop Protocol        |   7   | Microsoft-proprietary protocol to provide a GUI to connect to a remote machine.</br>Client and server exist for Linux and MacOS as well.                                                                                                            |
|    NTP     |     123     |         Network Time Protocol         |   7   | Use UDP for clock synchronization between machines over a network.                                                                                                                                                                                  |
|    SIP     | 5060 / 5061 |      Session Initiation Protocol      |   7   | Voice + messaging + video real-time sessions.                                                                                                                                                                                                       |
|    LDAP    |  389 / 636  | Lightweight Directory Access Protocol |   7   | Access and maintain distributed directory information services.<br/>The secure version LDAPS with SSL encryption uses port 636.                                                                                                                     |
|    SNMP    |  161 / 162  |  Simple Network Management Protocol   |   7   | Collect and organize info about managed devices on the network (watchdog of the network).                                                                                                                                                           |
|   Syslog   | 514 / 6514  |        System Logging Protocol        |   7   | Centralize, persist and manage logs of networking devices in a central place                                                                                                                                                                        |
|   MySQL    |    3306     |            MySQL Database             |   7   | MySQL database                                                                                                                                                                                                                                      |
| SQL Server |    1433     |          SQL Server database          |   7   | Microsoft SQL server database                                                                                                                                                                                                                       |
|   SQLnet   |    1521     |            Oracle database            |   7   | Oracle database                                                                                                                                                                                                                                     |
|  NetBIOS   |     139     |   Network Basic Input/Output System   |   7   | Old protocol for Windows-based networks for file and printer sharing.                                                                                                                                                                               |
|    SMB     |     445     |         Server Message Block          |   7   | Protocol used for file and printer sharing in modern Windows networks (better security and encryption than NetBIOS)                                                                                                                                 |


### Syslog

Syslog is a protocol used to gather all logs from network devices into one centralized Syslog server (on port UDP 514).  
Logs can be monitored, searched and archived from this Syslog server.  
It simplifies troubleshooting network issues on network devices.  
It also allows data retention of the logs (otherwise not persisted by Cisco devices storing logs in RAM).  
Syslog messages have a timestamp, a facility (message domain), a severity, a mnemonic (message type) and a description.

There are 8 different severity level for Syslog messages.  
They can be remembered with the sentence : _Every Awesome Cisco Engineer Will Need Ice-cream Daily_.

| ID  |   Severity    | Usage                            |
|:----|:-------------:|:---------------------------------|
| 0   |   Emergency   | System is unusable               |
| 1   |     Alert     | Immediate Action required        |
| 2   |   Critical    | Critical condition               |
| 3   |     Error     | An error occurred                |
| 4   |    Warning    | A Warning was generated          |
| 5   |    Notice     | Expected but significant message |
| 6   | Informational | An informative message           |
| 7   |     Debug     | Debug-level message              |


### DHCP

DHCP is a network management protocol used to automate the configuration of devices on IP networks.  
A DHCP server automatically assigns an IP address and other network configuration to each new device on the network.  

The steps of the DHCP workflow is **DORA** (Discover - Offer - Request - Ack) :
- a device joins the network and broadcasts a DISCOVER request to identify DHCP servers
- the DHCP server responds with an available IP address OFFER
- the device responds with a REQUEST for this IP
- the DHCP server responds with a ACK

The provided IP is available for a limited amount of time (DHCP lease).  
To keep its IP address, the device must send a renewal request before the end of the lease to extend the lease duration.

The OFFER message contains options with network information to use : default gateway, lease time, DNS server...

A **DHCP relay** can be setup to allow the DHCP server broadcasts to cross a router (usually setup in the router itself) so several networks can use the same DHCP server.


### DNS

DNS is responsible for the resolution of domain names into IP addresses.  

When a browser needs to access _www.mysite.com_, it queries the DNS server to know the corresponding IP address.    
If the DNS server does not have it configured or in cache, it will ask the **root DNS server**.  
The root DNS server replies with the IP of the **top-level DNS server** in charge of the `com` domain.  
The DNS server will ask the top-level DNS server, that will provide the IP of the **authoritative DNS server** in charge of `mysite.com`.  
The DNS server will ask the authoritative DNS server, that will provide the IP of `www.mysite.com`.  
The DNS server will cache this IP address and return it to the browser.

#### Types of DNS Records

- **A / AAAA** : convert a domain name into an IPv4 or IPv6 address
- **CNAME** (Canonical Name) : define an alias for a domain name
- **NS** (Name Server) : identifies the IP of the authoritative DNS server for a domain
- **PTR** (Pointer) : reverse DNS lookup, it maps an IP to a domain name
- **MX** (Mail Exchange) : IP of the mail server responsible for receiving emails on behalf of a domain
- **SOA** (Start of Authority) : administrative info about the zone (name, TTL, administrator...)

#### nslookup

`nslookup` is a command-line tool used to query a DNS server for DNS records.  
It is the main tool to troubleshoot DNS related issues and verifying the DNS configuration.

```commandline
nslookup facebook.com                # query the IPv4 and IPv6 addresses for a domain name
nslookup 142.250.196.132             # reverse lookup, query the domain name for an IP address
nslookup -type=MX facebook.com       # query the hostname of the mail server for a domain name
nslookup -type=SOA facebook.com      # query the SOA data for a domain name (name server, admin email, TTL...)
nslookup facebook.com 8.8.8.8        # use a custom DNS server (8.8.8.8 is Google's public DNS server) 
```


## TCP 3-ways Handshake

TCP guarantees reception and integrity of messages by establishing a connection and sending segments until it gets a reception ACK, called a PAR (Positive Acknowledgment with Retransmission).  
The connection is established by 3 segments exchanged between the client and the server, sending to each other their sequence ID :
- The client sends a SYN segment including its sequence ID seq=X
- The server sends a ACK-SYN segment including its sequence ID : seq=Y, ack=X+1
- The client sends a ACK : ack=Y+1



## Layer 1 and Cables


### Ethernet Cable Categories

- **Category 3** (obsolete) : Original Ethernet standard  
  10-BASE-T over 100m (10 Mbps)  


- **Category 5** (obsolete) : 10x and 100x faster than the original Ethernet standard  
100-BASE-TX over 100m (100 Mbps)  :   **Fast Ethernet**   
1000-BASE-T over 100m (1 Gbps) :  **Gigabit Ethernet**
 

- **Category 5e** : Enhancement of Cat5 cables, most common cable for home networks   
1000-BASE-T over 100m (1 Gbps) **Gigabit Ethernet**  
   

- **Category 6** :  Cable connecting floors together in buildings  
10G-BASE-T over 37 to 55m (10Gbps)


- **Category 6A** :  Improvement of Cat6 cables with thicker copper conductors and jackets  
10G-BASE-T over 100m (10Gbps)


- **Category 7** :  Similar specs as Cat6A, only exists in shielded version and mostly used in data centers  
10G-BASE-T over 100m (10Gbps)


- **Category 8** : Thicker and more expensive than Cat7, used in data centers  
40G-BASE-T over 30m (40Gbps)

  
### Twisted-Pair Cables

Cables with twisted pairs contain multiple pairs of smaller copper cables twisted together to prevent interference and sending opposite signals.  
Each pair is twisted with a different twist rate (distance between two twists).  
Almost all twisted cables have 4 pairs of cables inside.

All Ethernet cables (Cat5e, Cat6, Cat7, Cat8...) are twisted-pair cables.

Twisted pair cables can be either unshielded (UTP) or shielded (STP).  
**UTP cables** only contain the twisted pairs inside the outer PVC jacket of the cable.  
**STP cables** have an additional shield around the twisted pairs, and sometimes even around each individual pair, and a ground wire.  
STP cables provide an extra protection against electro-magnetic interferences (EMI) and are used in manufacturing environments.


### T568A and T568B

T568A and T568B are two different standards for connecting the wires inside the RJ-45 connector of an Ethernet cable.  
They define the order in which the individual 8 wires are arranged and connected to the pins of the connector.  
Both standard are widely used, and they are compatible with each other as long as both ends of the cable follow the same standard.

<p align="center">
<img alt="T568A and T568B" src="../images/T568A_T568B.jpg" width="350">
</p>

Between a computer and a switch, we need a **straight-through cable**, with the same standard at both ends.  
Between 2 computers or 2 switches, we need a **cross-over cable**, with a different standard at both ends.

**Auto-MDX** is a technology supported by most recent machines that automatically detects if the cable used is straight-through or cross-over, and adapts at software level, so it no longer matters which type of cable is used.


### Coaxial cables

Coaxial cables are still in use sometimes, for example for old TVs or to bring internet to a modem.  
They contain a wire covered by an insulated layer, covered by a metal layer, and finally the plastic jacket.  
Coaxial cables use the **BNC connector**.  

Some common standards are **RG59** (low-cost, short-distance, for cable TV) and **RG6** (cable TV or modem).


### Fiber Optic Cables

Unlike copper cables using electrical signals to transmit data, fiber optic cables use pulses of light.  
This allows the data to travel further than with copper cables before fading, and it is easy to regenerate.  

There are 2 types of fiber optic cables :
- **Single Mode Fiber** (SMF) : small, using glass core, long distance, expensive, high bandwidth (yellow cable)  
- **Multi-Mode Fiber** (MMF) : thick, using plastic core, shorter distance, cheaper, lower bandwidth (orange or aqua cable)  

All fiber optic cables have 2 lines : one receive connector (Rx) and one transmit connector (Tx).  
Fiber cables are used to connect buildings, campuses, even countries (like under the Atlantic ocean).  

There are many connector standards for fiber cables, many vendors have their own connectors, some try to group the 2 lines together :  
- **ST** (Straight Tip) : Round bayonet-style connector, relatively large, used in older networks
- **LC** (Lucent Connector) : Small, square-shaped with a short latch mechanism, popular in modern networks
- **SC** (Subscriber Connector) : square-shaped push-pull design, popular in modern networks
- **FC** (Ferrule Connector) : threaded screw-on design with a metal ferrule at the end, mostly used with single-mode fiber for industrial applications
- **MT-RJ** (Mechanical Transfer Registered Jack) : group both Rx and Tx lines in a single small cable

<p align="center">
<img alt="Fiber Connectors" src="../images/fiber_connector.jpg" width="500">
</p>

A **fiber splicer** is a box used to extend a fiber cable (repeating the signal).  

A **fiber optic transceiver** (transmitter-receiver) is a device plugged to a switch / firewall / router to convert the electrical signal into light pulses.  
It contains a light source for transmission and a photo-diode semiconductor for reception.  
- **SFP** (Small Form-factor Pluggable) : used for 1 Gbps Ethernet
- **SFP+** (Enhanced SFP) : used for 10 Gbps Ethernet, backward compatible with SFP slots
- **QSFP** (Quad SFP) : for 40 and 100 Gbps Ethernet


### Plenum space

A plenum is the part of a building that facilitates air circulation for heating and air conditioning systems, providing pathways for heated/conditioned air flow.   
It is a space between the structural ceiling and the drop ceiling.  
If instead there is a dedicated duct work for the forced air return flow as well, then there is no plenum. 

<div style="display: flex;">
    <img src="../images/plenum.png" alt="Plenum" style="width: 45%;" />
    <img src="../images/no_plenum.png" alt="No plenum" style="width: 45%;" />
</div>

Building with a plenum have the network cables in the plenum, along with potential water pipes and the forced-air return inside the open space above the ceiling.  
This raises concerns in case of fire, so network cables must not be toxic to human beings when they burn.  
To limit the toxicity, a special material can be used (FEP, or "low-smoke PVC") which is not as flexible as normal cables.

### Power over Ethernet (PoE)

PoE is a way to power devices connected with Ethernet cables without an additional power source.  
The same cable is used for network and for power (it requires a Cat5 cable or higher).  
It is used for IP video cameras, wireless APs, IoT devices, Cisco phones...  
Many recent switches support PoE, otherwise we can use a **power injector** to inject power in the Ethernet cables. 

PoE (2003) is defined by **IEEE 802.3af** standard and allows 15.4W and a current of 350mA.   
PoE+ (2009) is defined by **IEEE 802.3at** standard and allows 25.5W and a current of 600mA.


### CSMA/CD and CSMA/CA (Carrier-Sense Media Access with Collision Detection/Avoidance)

CSMA/CD is a medium access control method used in local networking to let several machines in the same broadcast domain communicate with each other without speaking at the same time.  
If a machine detects that another machine speaks at the same time, it stops sending and waits for a random time before sending again.  
It was used with bus topology or with hubs, but it is no longer needed now that we use switches instead.

CSMA/CA is an alternative to CSMA/CD that determines first if the channel is idle before emitting.  
It is used mostly for wireless networks where CSMA/CD is not possible.



## Layer 2, Switch and MAC Address


### Media Access Control (MAC) Address

The MAC address is also called physical address, Ethernet address, layer 2 address or hardware address.  
It is a unique identifier assigned to each network interface cards (NIC) and uniquely identifies a machine on a local network.  
It is made of 48 bits (6 bytes) and represented as a sequence of 12 hexa digits, for example _00:0c:29:17:1b:27_   
The first 3 bytes of the MAC address represent the Organization Unique Identifier (OUI).   
It can be displayed with `ifconfig` on Linux and `ipconfig` on Windows. 


### Switch

A switch is a layer 2 device to route traffic within a local network.  
It listens to incoming traffic, and at each received message it uses the source MAC address in the message to update its MAC table, to associate that MAC address to the receiving port of the switch.  
When a message is received, if the destination MAC address is in its MAC table, the switch sends the message only to that port.  
Otherwise, it broadcasts the message on all ports except the receiving port.


### Port mirroring

Some managed switches allow to configure port mirroring.  
All dataframes sent to a given port of the switch will also be sent to another port, usually for monitoring purpose.


### Virtual LAN (VLAN)

A VLAN is a logical separation of the ports of one or more switches into groups that cannot communicate with each other.  
If we have machines M1, M2, M3 and M4 on ports 1 to 4 of a switch, we can create a VLAN with M1 and M2, and another VLAN with M3 and M4 by specifying on the switch that ports 1 and 2 are in a VLAN and 3 and 4 in another.  
A broadcast message is limited to the VLAN of the port it was received from, so a VLAN defines a layer 2 broadcast domain.  
VLANs can be created in **managed switches** only (unmanaged switches do not have a management interface).


### Access Port VS Trunk Port

Each port on a managed switch is either an access port or a trunk port.  
An access port is connected to a machine and can be part of a VLAN.  
A trunk port is connected to a switch and can be used by multiple VLANs to reach other machines of that VLAN.  

<p align="center">
<img alt="Access Trunk Ports" src="../images/access_trunk_ports.png">
</p>


If we want M1, M2 and M4 in the same VLAN 1 and M3 and M5 in the VLAN 2, ports 4 of switch 1 and port 3 of switch 2 are trunk ports.  
Both VLANs need to use these ports to reach other machines of the VLAN.   
Protocol **802.1q** is used to add a tag with the VLAN ID to each message going through the trunk port.  
The receiving switch will remove the tag and send the message only to ports in the target VLAN.  


### Spanning Tree Protocol (STP)

STP is a layer 2 network protocol used to build a loop-free logical topology on an Ethernet network.  
It prevents bridge loops in a network that has redundant paths (physical loops).  
It selects a root node and builds a spanning tree connecting all nodes with no loop, and all switch ports out of this spanning tree are disabled.  
If the network changes (a segment fails or a new machine joins), the spanning tree is recalculated.  
STP is defined by the **IEEE 802.1d** standard.


## Layer 3, Router and IP address


### Routing Types

Routers forward traffic to a next node based on the target IP of each packet.  
To decide where to forward each packet, there are 3 possible types of routing :

- **static routing** : every reachable network has an explicit routing rule.  
  This is the most secure option, but it is not scalable to big networks, as the admin must set all rules in every router.  


- **default routing** : configure a default route for packets which target IP is not part of a directly connected network.  
  This is used for stub routers that route all outside traffic to the same target.


- **dynamic routing** : routers communicate with each other to find the optimal path through the network for each packet.  
  This is used for large interior networks and on the Internet.


### Dynamic Routing Protocols

- **RIPv2** (Routing Information Protocol 2) : interior distance vector protocol used on old networks


- **EIGRP** (Enhanced Interior Gateway Routing Protocol) : better than RIPv2, it used to be Cisco-proprietary, now it is still used and easy to setup.


- **OSPF** (Open Shortest Path First) : most popular interior gateway protocol and main alternative to EIGRP.  
  It has always been open and is available on any router hardware in the market. 


- **BGP** (Border Gateway Protocol) : main routing protocol of the Internet.  
  Unlike RIPv2, OSPF and EIGRP, BGP is an exterior gateway protocol to exchange routes between separate networks that we have no control over.  
  It can be used by enterprises on the Internet edge connecting to the ISP to allow fail-over if an ISP is down (which is not possible with a static default route to the ISP).

In networks with dynamic routing protocol configured, there are 2 types of packets sent by routers :
- data packets (IP, IPv6) for user data
- route updates packets (RIP, EIGRP, OSPF) to build and maintain routing tables on each router


### Private IP Address Ranges

Private IP addresses are a set of reserved IP address ranges that are not routable on the public Internet.  
They enable devices on a private network to communicate with each other without requiring a unique public IP addresses for each device.  
Devices using a private IP address can communicate with the Internet by using a NAT.

|     Network     |  Class  | # Addresses | Broadcast Address | Usage                    |
|:---------------:|:-------:|:------------|:-----------------:|:-------------------------|
|   10.0.0.0/8    |  A x 1  | 16M         |  10.255.255.255   | Large networks           | 
|  172.16.0.0/12  | B x 16  | 1M          |  172.31.255.255   | Medium networks          | 
| 192.168.0.0/16  | C x 256 | 65025       |  192.168.255.255  | Home and office networks |


### Subnets

Subnetting is the division of one big network in multiple smaller networks.  
For example, network 10.0.0.0/8 contains 2^24 addresses (-2 for network and broadcast addresses).  
To create multiple subnets, we sacrifice N bits of the host section to create 2^N subnets.   
Each subnet has 2^k-2 host addresses, where k is the number of 0 in the mask.

If we need 12 subnets, we sacrifice 4 bits (2^4 = 16 is the min power of 2 bigger than 12).  
The network masks of the subnets is 255.240.0.0.  
The subnets are 10.0.0.0/12, 10.16.0.0/12, ..., 10.240.0.0/12.  


### NAT and PAT (Network / Port Address Translation)

NAT/PAT is a mechanism to hide the local IP address of a machine behind a public IP.  
It is usually performed by a router or a firewall.  
Traffic from private IPs for the outside go through the NAT device, that replaces the source IP by its public one.  
PAT is used to allow several machines with private IPs to request some resources on the same port through the same NAT.  
The NAT device replaces the IP with its public one, and the port with any unused one, and keeps the mapping in a table to send the response coming to that port to the right private machine.  
The private IPs of machines behind a NAT are not visible from outside the network, and can be in the private IP address ranges.  

NAT is a 1-to-1 mapping, for example for a publicly accessible web server in a DMZ.  
PAT is a N-to-1 mapping between private IPs and one public IP.  
Routers can do both NAT and PAT for different machines in the local network.


### Router Access Control List (ACL)

ACLs are a set of rules to control network traffic going through the router and mitigate attacks :
- stateless decision to PERMIT / DENY (does not know previous traffic)
- can use fields from the packets for the decision : source/destination IPs, protocol, ...
- can filter incoming and outgoing traffic
- ACLs are applied at the router interfaces (can have different ACLs for each interface)


### Firewall

A firewall is a network security device that monitors and controls incoming and outgoing network traffic.  
It is often used between a trusted network and an untrusted network (the Internet).  
It serves a similar purpose as the router ACLs but offers more control on the filtering.  
Some firewalls also provide more features like intrusion detection, anti-virus...

- **Packet filtering firewall** : similar to router ACLs, filter based on source/dest IP, port, protocol...
- **Circuit-level gateway** : monitor TCP handshake, act as a proxy for the internal machine and allow only legitimate session traffic
- **stateful inspection firewall** : examine data inside the packets and remember if the packet is part of a session (uses network performance)
- **application-level firewall** : check data validity at application layer (for ex WAF for HTTP)
- **host-based firewall** : software firewall installed on a computer to protect this computer only, for example Windows 10 built-in host-based firewall, or the "Zone Alarm" 3rd party firewall 


### IP Address Management (IPAM)

IPAM is a method of IP scanning, IP address tracking and managing information associated with a network's IP address space.  
An IPAM software avoids using spreadsheets to keep track of the IP address of each machine.

- track free and assigned IP addresses
- monitor the size and the users of subnets
- monitor the status, the hostname and the hardware for each IP address
- integrate with DHCP to show DHCP reservations
- integrate with DNS, creating A records so machines can be accessed by their hostname

There are free and paid IPAM softwares.  
A popular one is **SolarWinds IP Address Manager**, and its free version **IP Address Tracker**.


### Layer 3 Switch

A Layer 3 switch has all functionalities of a layer 2 switch, but also offers routing capabilities.  
Its main purpose is to allow communication between different VLANs without the need of a router.  

With a standard layer 2 switch with 2 VLANs, machines from one VLAN cannot communicate with machines from another VLAN directly.  
We need a router connected to both VLANs on the switch to pass the traffic from a VLAN to the other.  

A variant is the **router on a stick** configuration, where a router is connected to the layer 2 switch with a single trunk port used by both VLANs, using the 802.1q standard.

With a layer 3 switch, the switch itself can route traffic from a VLAN to the other by IP.

A layer 3 switch is more expensive than a layer 2 switch but is easier to setup than a switch and a router for multi-VLAN networks.



## Wireless Networks


### Wireless Service Sets

**IEEE 802.11** is the set of standards for wireless LAN commonly called Wi-Fi.

A **service set** is a group of wireless network devices communicating with each other on a same LAN using the same AP.  
A service set as a unique identifier called the SSID.

There are multiple types of service sets :

- **IBSS** (Independent Basic Service Set) : created by peer-to-peer devices connected with each other without network infrastructure.  
  An example is a temporary network to share a laptop's connection with a smartphone.   
  An IBSS is also called an "adhoc network".

- **BSS** (Basic Service Set) : created by an infrastructure device called Access Point (AP) for other devices to join.  
  A BSS is also called "infrastructure mode".

- **ESS** (Extended Service Set) : physical subnet containing multiple APs communicating with each other to allow authenticated users to roam between them (for example in a hotel or an airport). 


### Types of Networks

- **PAN** (Personal Area Network) : very small network, usually a single room (USB, Bluetooth devices, IR, NFC...)

- **LAN** (Local Area Network) : uses switches and routers, usually connected with Ethernet

- **SAN** (Storage Area Network) : dedicated high-speed network of storage devices providing access to large amount of data and allowing sharing data as if it were a drive attached to a server.

- **WLAN** (Wireless LAN) : LAN with wireless access points and devices connecting to it.

- **CAN** (Campus Area Network) : network connecting some LANs together, covering several buildings.

- **MAN** (Metropolitan Area Network) : covering an entire city.

- **WAN** (Wide Area Network) : global network connecting multiple location in the world, like the Internet.


### WLC (Wireless LAN Controller)

A WLC is a network device controlling multiple wireless APs of the network.  
It allows centralized management and configuration of multiple APs.

A WLC is used for seamless connectivity when moving from one AP to another (roaming).  
It provides statistics and performance information on each AP's usage.  

To communicate with the APs, a WLC uses one of :
- Cisco-proprietary protocol **LWAPP** (Light-Weight AP Protocol)
- non-proprietary protocol **CAPWAP** (Control And Provisioning of Wireless AP) for modern controllers 


### Internet of Things (IoT)

System of mechanical or digital divices that have a unique ID and the ability to transfer data over a network without the need for human intervention.  
This includes smart homes, heart monitor implants, animal bio-chip transponders, car sensors, drones...  
IoT devices are used increasingly in enterprises to generate data and monitor the business more efficiently.  
Usually IoT devices send data to an **IoT Gateway** (or "IoT Hub") that will send the data for processing to the cloud.

IoT raises some challenges, like security concerns, management of large amount of data and numerous IoT standards.

IoT technologies include :

- **Wifi** : IEE 802.11 standard

- **IR** (Infrared) : TV remote controllers for example, require direct line of sight

- **Bluetooth** : headphones, health trackers, wireless speakers...

- **NFC** (Near-Field Communication) : very close wireless communication (up to 10cm), used by Apple Pay, contactless payment cards, commuter pass...

- **RFID** (Radio-Frequency Identification) : method to store and retrieve data by using RFID tags.  
   RFID tags are microchips with an antenna to reply to RFID readers.  
   RFID can be used for theft protection, pet identification, warehouse logistics improvement, barcode replacement...  

- **Z-Wave** : Radio protocol created for home automation, mesh network using low-energy radio-waves to communicate between devices.  
  It is used for lightning control, security systems, swimming pools, garage doors...

- **Zigbee** : low power and low data rate short-range wireless ad-hoc networks (competitor of Z-Wave)

- **ANT+** : wireless sensor network technology mainly used for health and activity trackers


### Wifi 2.4GHz and 5GHz Bands

Old routers use Wifi in the 2.4GHz frequency band, which covers a large range (entire house).  
It causes interferences with other devices also using the same frequencies, like microwaves, cordless phones, Bluetooth devices...  
It only offers 11 channels, and only 3 non-overlapping channels.

Most modern routers are dual-band, so they can transmit and receive both in the 2.4GHz and in the 5GHz bands.  
The 5GHz band is twice quicker (frequencies are twice higher) but it has shorter range and does not go through walls.  
No other device uses these frequencies, so it  usually doesn't cause interferences.  
It contains 25 non-overlapping channels.

A channel is a band of frequencies (usually around 20MHz wide) used for wireless communication.    
2.4GHz routers have 11 channels, centered from 2412MHz (channel 1) to 2462MHz (channel 11).  
When using the 2.4GHz, we should use a different band from our neighbor to minimize interferences.  
The router can usually assign automatically the optimal channel.



## Network Configuration Steps

- If we want to use VLANs, define the VLANs on the switches and define which port is in which VLAN.
- Configure IP addresses for layer 3+ devices (routers, firewalls, layer 3 switches, PCs, L2 managed switches...)
- Configure routing in each router, either manually or dynamically (with RIPv2 for ex).
- Configure the DHCP server to allow machines to dynamically receive an IP address if needed
- Configure a NAT instance (dedicated NAT instance or router)


## IDS / IPS (Intrusion Detection/Prevention System)

Both IDS and IPS monitor the traffic on the network against a database of known attacks.

IDS only observe the traffic and alert in case an attack is detected.  
They are usually connected to a switch and get a copy of the traffic on another port using port mirroring.  
They alert the administrator when an anomaly is detected.  
**Snort** is a popular open-source IDS.

IPS can prevent attacks to reach the network.  
They are placed between the network to protect and the outside, and block suspicious packets.  

Both IDS and IPS can use 2 types of monitoring techniques :

- **Signature-based** : check traffic against the fingerprints of known attacks
- **Behavior-based** : establish a baseline of the normal behavior on the network and detect deviations from this baseline 

There are **host-based IDS and IPS** (HIDS and HIPS) that monitor and analyze the activity of individual hosts.


## Proxy Server

A **forward proxy server** is a device that sends queries on behalf of its client machines.  
Instead of sending their traffic to the Internet, clients send the traffic to the proxy server.  

Proxy servers have multiple benefits :
- **anonymity** : the IP of the client is no longer in the queries on the Internet, only the proxy knows it
- **content filtering** : can prevent employees or children to access specific sites
- **speed** : the frequently accessed resources can be cached to speed up retrieval
- **activity logging** : allows to keep track of what websites were visited

A proxy server does not encrypt the data sent to the Internet, this is done by a VPN.

A **reverse proxy server** intercepts traffic coming into the network.  
It forwards the traffic from the Internet to specific servers inside the network.  
A reverse proxy increases security on a private network by hiding the IP addresses of the internal servers.  
It also allows load-balancing to distribute incoming traffic across multiple servers.  
A reverse proxy can be equipped with WAF capabilities to inspect incoming traffic for security threats.   
**Nginx** is a popular open-source reverse proxy.


## VPN Concentrator

A VPN Concentrator is a specialized networking hardware device that aggregates multiple VPN connections from remote clients.  
It simplifies and centralizes the management of VPN connections, to allow access from remote users or branch offices to the main network.

It is placed at the forefront of the network, next to the firewall.  
It comes with dedicated software to support VPN connections.


## RADIUS (Remote Access Dial-In User Service)

RADIUS is a client-server networking protocol to centralize user access authorization.  
It is part of the **802.1x** standard.  

RADIUS clients are networking devices that need to authenticate users (VPN concentrator, router, switch...).  
A RADIUS server is a process running on a UNIX or Windows server that maintains user profiles in a central database.  

RADIUS clients contact the RADIUS server using the RADIUS protocol everytime they need to authenticate a user.  
All RADIUS servers have **AAA capabilities** (Authentication / Authorization / Accounting).


## VoIP (Voice over IP)

VoIP is a technology to transmit voice calls using the IP network instead of the traditional phone network.  
VoIP does not use dedicated physical lines, but breaks the voice into IP packets to transmit via Internet.  
It is much cheaper than the traditional phone lines and usable anywhere with Internet access.

A **PBX** (Private Branch Exchange) is a hardware used in a private network to provide phone connectivity to the users of the network.  
Machines connect to the IP-PBX via the LAN, it allows multiple call functionalities : extension dialing, business hours settings to route calls off-hours, customer waiting queues, conference calls...

VoIP can be used by IP phones (like Cisco) or by phone softwares or computers.  

VoIP service providers perform routing of outgoing and incoming calls.  
If the recipient also uses VoIP, the call stays entirely on the IP network, it is an **on-net call**.  
Otherwise it is an **off-net call**, the IP packets are converted to a regular voice call and sent to the **PSTN** (Public Switched Telephone Network).  
A **VoIP gateway** is used to connect the internal VoIP network (with the PBX) with the outside PSTN.  


## Hypervisor

An hypervisor is a software for the creation and management of virtual machines running an OS.  
The hypervisor runs on the **host machine** and each VM it manages  is a **guest machine**.

There are 2 types of hypervisor :
- **Type 1 - Bare Metal** : the hypervisor runs directly on the hardware (no OS)  
  &rarr; Microsoft Hyper-V, Oracle VM Server, VMware vSphere...
- **Type 2 - Hosted** : the hypervisor is an application running on the OS of the host machine  
  &rarr; Oracle VirtualBox, VMware Workstation...

With the hypervisor, we can create virtual machines, virtual hard disks, virtual switches...







