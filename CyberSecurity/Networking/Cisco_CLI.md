
# Cisco CLI Introduction

Most Cisco devices use the same Cisco CLI for management.  
To access the CLI, we can use either a console cable (in the device's console port), Telnet or SSH.  
In all 3 cases, Putty can be used to open a terminal (for console port, use the "Serial" connection type in Putty).

There are several modes that we can enter to have access to different commands :
- **Exec Mode** or **User Mode** : default mode when logging to the device, can show device info (`>` prompt)
- **Privileged Mode** or **Enabled Mode** : require a password, allow write action on the device (`#` prompt)
- **Global Configuration Mode** : accessed from privileged mode, allow to edit the entire device config
- **Granular Configuration Mode** : access from global config mode, allow to edit a sub-section of the config (interface, CLI, vlan...)


## CLI Basic Commands

```commandline
enable / disable                 // enter / exit privileged mode

// device cleanup
erase startup-config             // delete the previous device configuration
delete flash:vlan.dat            // delete VLAN config (for a switch)
reload                           // reboot the device

show version                     // show general info (model, IOS, uptime ...)
do show version                  // use "do" to run it outside of enabled mode (global config mode for ex)
show mac address-table dynamic   // show all learned MAC addresses (for a switch)
show running-config              // show the entire device config
show vlan brief                  // show info on existing VLANs and ports in each VLAN
show ip interface brief          // list all IP networks associated to all interfaces
show ip interface gig 1/0        // more IP-related details on Gigabit interface 1/0
show interface gig 1/0           // more all info on Gigabit interface 1/0 (not only IP related)
show ip route                    // show all routing info for a router device
show ip dhcp pool                // show info on all DHCP IP address pools on the DHCP server

// set clock
clock set 14:05:00 November 8 2023

// global device configuration
configure terminal               // enter configuration mode (must be in enabled mode)
hostname MySwitch                // set the hostname (must be in configuration mode)

// CLI configuration
line console 0                   // enter granular config mode of the console port number 0
password mypassword777           // set a password for this console port
login                            // require login to access the console port (with the password)
exit                             // back to global config mode

// Interface configuration
interface FastEthernet 0/1       // enter granular config mode of the FastEthernet interface number 0/1
description CONNECTION_DESKTOP   // set a description for the interface
duplex full                      // force full-duplex for this interface
speed 100                        // set the speed to 100Mbs
exit                             // back to global config mode
```

All the config we change on the device is applied to the running configuration, and is lost after reboot.  
We can save the running config (RAM) to the startup config (NVRAM) to persist the changes :

```commandline
copy running-config startup-config
wr                                       // alternative to above command (old write command)
```

We can use `?` to get help on available commands and sub-commands :

```commandline
?                   // show top-level commands
cl?                 // show top-level commands starting with "cl"
clock ?             // show parameters of the "clock" command
clock set ?         // show parameters of the "clock set" command
```

## CLI Use cases

### VLAN Creation

```commandline
configure terminal        // enter global config mode
vlan 100                  // enter granular config mode for VLAN 100 (create it if not existing)
name accounting           // optionally give a name to the VLAN
end                       // go back to enabled mode

show vlan                 // display all VLAN infos, the new VLAN should be listed with no port
```

### Set a port in a VLAN

```commandline
configure terminal           // enter global config mode
interface gig 0/0            // enter granular config for Gigabit interface number 0/0
switchport mode access       // set port to access mode (not trunk)
switchport access vlan 100   // add the interface to VLAN 100
end                          // go back to enabled mode
```

### Assign 2 ports of a router to different networks

```commandline
configure terminal                   // enter global config mode

interface gig 1/0                    // enter granular config for Gigabit interface number 1/0
no shutdown                          // specify to not shutdown the interface (down by default)
ip address 10.23.0.3 255.255.255.0   // set network 10.23.0.3/24 to that interface

interface gig 2/0                    // same for interface 2/0
no shutdown
ip address 67.83.0.1 255.255.255.0   // set network 67.83.0.1/24 to that interface

end                                  // go back to enabled mode
show ip interface                    // check if the IP config was updated correctly
```

### Assign a default route on a router

```commandline
configure terminal                   // enter global config mode
ip route 0.0.0.0 0.0.0.0 10.12.0.9   // set 10.12.0.9 as the next hop for unknown routes 
end                                  // go back to enabled mode
```

### Set a router to use RIPv2 for dynamic routing

```commandline
configure terminal                   // enter global config mode
router rip                           // enter router config mode for RIP dynamic routing
version 2                            // use RIPv2
network 10.0.0.0                     // apply to network 10.0.0.0/8 (10.0.0.0 is class A so default to /8)
no auto-summary                      // disable auto-summary feature
end                                  // go back to enabled mode
show ip route                        // ensure the indirectly connected networks were discovered
```

### Set a router to act as DHCP server

```commandline
configure terminal                   // enter global config mode
ip dhcp pool pool1                   // create a pool of IP addresses for the DHCP server
network 10.1.0.0 255.255.255.0       // specify the IP network for that pool
default-router 10.1.0.1              // set the default gateway for the DHCP clients
dns-server 1.1.1.1                   // set the DNS server for the DHCP clients
ip dhcp excluded-address 10.1.0.1 10.1.0.20  // exclude a range of IPs (10.1.0.1-20)
end                                  // go back to enabled mode
```

### Setup a router for NAT

```commandline
configure terminal                                 // enter global config mode
access-list 1 permit 10.0.0.0 255.255.255.0        // create a list of internal IPs to use NAT for
ip nat pool MYPOOL 203.0.113.1 203.0.113.5 netmask 255.255.255.0   // define the public IPs for the NAT
ip nat inside source list 1 pool MYPOOL overload   // create a NAT translation rule
                                                   // overload allows multiple internal IPs to use the same public IP (PAT)

interface gig 1/0               // enter granular config mode for an interface
ip nat inside                   // specify that the interface is inside (eligible for NAT)

interface gig 2/0               // enter granular config mode for another interface
ip nat outside                  // specify that the interface is outside (not eligible for NAT)

end                             // go back to enabled mode
show ip nat translations        // verify the NAT configuration
```

### Setup a layer 3 switch to route traffic between 2 VLANs

```commandline
configure terminal                    // enter global config mode

interface vlan 100                    // create logical interface for vlan 100
ip address 10.100.0.1 255.255.255.0   // assign an IP address to this logical interface
no shutdown                           // make the interface active

interface vlan 200                    // create logical interface for vlan 200
ip address 10.200.0.1 255.255.255.0   // assign an IP address to this logical interface
no shutdown                           // make the interface active

exit                                  // back to global config mode
ip routing                            // allow IP routing at the multi-layer switch level

end                                   // go back to enabled mode
show ip interface brief               // check that the 2 logical interfaces were created
show ip route                         // ensure the switch can route from 10.100.0.0/24 to 10.200.0.0/24
```

### Setup port security on a switch

```commandline
configure terminal                            // enter global config mode
interface gig 0/0                             // enter granular config mode for an interface
switchport port-security maximum 5            // limit number of MAC addresses to 5 on that port
switchport port-security violation shutdown   // if breached, shutdown that switch port
end                                           // go back to enabled mode
```
