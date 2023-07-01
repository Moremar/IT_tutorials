# Famous Cyber Attacks

## 2013-2014 : Yahoo! Data Breaches

<p align="center">
<img alt="Yahoo Data Breaches" src="./images/yahoo_data_breaches.jpg" width=400>
</p>

In 2016, Yahoo! revealed that some data breaches were detected, that exposed all 3 billion user accounts in 2013, and another 500 million user accounts in 2014.  
Compromised data include user names, dates of birth, emails, phone numbers, security questions and hashed passwords and "Nonce" values.  
This is regarded as the largest data breach in cybercrime hystory. 

Hackers managed to access the network by using spear fishing, getting some Yahoo! employees to click a link and execute a malware.  
They got access to the user database content, and used the "Nonce" value (number used to create user session cookies) to access user accounts without the need of the password.

The US Intelligence suspects Russians to be the perpetrators of the attack, due to some similarities with previous data breaches.  
4 men were charged for the 2014 breach, 2 of them working for the FSB (Russian Federal Security Service).


## November 2014 : Sony Pictures Hack

<p align="center">
<img alt="Sony Pictures hack" src="./images/sony_hack.jpg" width=400>
</p>

On November 24th 2014, the Lazarus Group (calling themselves the "Guardians of Peace") hacked into Sony Pictures's internal network.  
Sony's network was down for several days, then the attackers leaked to the public and to journalists some internal emails, employees personal information, salaries, unreleased movies...

The motive of the hack was the release on December 25th of "The Interview", a comedy about 2 American journalists who assassinate North Korean leader Kim Jong Un.  
North Korea government contacted the US governement to ask for the ban of this release, judged as sponsoring terrorism, but the US did not ban it.  

The attackers threatened to commit terrorist attacks against movie theaters that would show the film.  
Following the threat, many theater owners decided to drop the release of the movie.

The Interview was only shown in 331 independent movie theaters, and released to online video on-demand platforms. 

The NSA announced that it has evidence that the attack was orchestrated by North Korea, but those evidence were not made public for security reasons.  
North Korea declined any responsibility in the attack, but considered the attack righteous.


## May 2017 : WannaCry

<p align="center">
<img alt="WannaCry" src="./images/wannacry.png" width=400>
</p>

WannaCry is a ransomware launched on May 12th, 2017.  
It propagated very quickly and affected over 230,000 Windows machines over 150 countries.  
It affected all sectors of the economy : companies, banks, schools, hospitals, ISPs...

WannaCry encrypted most files on the victim machines.  
Victims were requested to pay $300 in bitcoin for the decryption key.  
If not paid within 3 days, the price doubled to $600.  
If not paid within 7 days, the files would be lost.  

The 2 exploits behind WannaCry are "EternalBlue" and "DoublePulsar".  
They were both originally found by the NSA, and leaked in 2017 by a group of hackers called the Shadow Brokers.  

EternalBlue (CVE-2017-0144) exploits a vulnerability in the SMBv1 network protocol on Windows machines (Vista, XP, Windows 7, 8 and 10).  
It allows remote code execution on the victim machine.  

DoublePulsar is an exploit to implant a backdoor in victim machines for later code execution.

Microsoft released a security patch to fix the vulnerability, but many machines were still running an unpatched Windows version.

WannaCry was sent to the victim machines using the DoublePulsar backdoor.  
When WannaCry executed, it propagated to all machines reachable via SMBv1 using EternalBlue, and installed a copy of itself to these machines using DoublePulsar.  
It then ran the ransomware program to encrypt victim files. 

Researcher Marcus Hutchins discovered a kill switch domain by running the malware in a sandbox.  
WannaCry tries to connect to a hardcoded unregistered domain name, and executes the ransomware only if the connexion fails.  
Marcus Hutchins registered the domain, which stopped the malware for all victims.  
The domain was attacked by DDoS to resume WannaCry's attack, but Hutchins managed to increase
its availability by using a cached version of the site to protect the domain from the DDoS attack.

The perpetrators of the WannaCry attack are not clearly identified.  
The main suspect is the Lazarus Group, a cybercrime group from North Korea.  
Some code similarities were found with previous of their malwares, and the analysis of the WannaCry language file revealed that the machine that created it had Hangul installed and was on timezone UTC+09:00.
