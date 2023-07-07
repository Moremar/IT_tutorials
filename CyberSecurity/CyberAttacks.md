# Famous Cyber Attacks


## March 1999 : The Melissa Virus

<p align="center">
<img alt="Melissa Virus" src="./images/melissa.jpg" width=400  style="border:1px solid black">
</p>

On 26th March 1999, David Lee Smith launched Melissa, one of the fastest-spreading mass-mailing macro virus.  
It was designed to target systems running Microsoft Word and Outlook.

The Melissa virus was a Visual-Basic macro included in a Word file called List.doc, and executed when the file is open.  
It was attached to a social engineering email with title `Important message from [sender]` and body `Here is that document you asked for... don't show anyone else ;)`  
When a user opened it, the VB macro executed, deactivating some safeguards in Microsoft Word 97 and 2000, and sent itself to the first 50 contacts in the Outlook address book.

The virus did not destroy any file or steal any data, but it caused an email flood that crippled many networks, causing an estimated $80M of damage.  
According to the FBI, it overloaded email servers in over 300 corporations, and infected thousands of computers.

David Lee Smith was arrested on April 1st 1999, cooperating with authorities and claiming it was intended as a joke.  
He was sentenced to 20 months in federal prison and a $5000 fine.


## 2013-2014 : Yahoo! Data Breaches

<p align="center">
<img alt="Yahoo Data Breaches" src="./images/yahoo_data_breaches.jpg" width=400  style="border:1px solid black">
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
<img alt="Sony Pictures hack" src="./images/sony_hack.jpg" width=400  style="border:1px solid black">
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


## 2014-2018 : Carbanak Money Heist

<p align="center">
<img alt="Carbanak Money Heist" src="./images/carbanak.jpg" width=400  style="border:1px solid black">
</p>

In 2014, the "Carbanak" hacker group coordinated the biggest cyber-heist in cyber-crime history, stealing over $1B from financial institutions.   
The main targeted bank was the Kaspersky Russian bank, but it was discovered later that over 200 institutions were victim of the same attack.  
Many intelligence organizations teamed up to track the hackers (FBI, CIA, JCAT, FSB...).

**Phase 1**  
The hackers sent a spear fishing email to a bank employee.  
When the malicious attachment was open, a malware installed a VNC backdoor (Virtual Network Computing) on the machine.  
From this infected machine, the hackers infected other machines on the network and looked for the admin machine.  

**Phase 2**  
They slowed down the admin machine by running as many programs as possible, so someone calls IT support to check it.  
When IT support came, they entered the admin password on the machine, which was recorded by a keylogger.  
The hackers just gained access to the admin machine of the bank.

**Phase 3**  
They spied on employees for months to know exactly how they operated daily.  
Once they got a perfect knowledge of how they operated, the robbery started.  
They impersonated high-level banking employees and sent money transfer SWIFT requests.  
They used the bank e-payment system to transfer this money to some other accounts in the US and in China.  
Then some "Money Mules" were hired to withdraw the money from ATMs.  
They got remote control over the ATMs and were able to make them spit out cash when they wanted.

**Investigation**  
In the Kaspersky bank, an employee noticed an unusual behavior of the domain server.  
After a security audit, the bank realized that the VNC screen sharing software was installed on multiple machines.  
An employee opened a text file and typed "Hello", and the computer replied "Hello, you won't catch us.", confirming that they were being hacked.  

In 2016, the Carbanak group made an important mistake in Taipei.  
2 money mules were withdrawing money from an ATM.  
As a Taiwanese man approached, they left in a hurry and forgot over $2M in the ATM.  
The Taiwanese man alerted the police, who identified them and tracked them using CCTV footage, which led to the identification of 22 suspects from Russia and Eastern Europe.  
3 of them were still in Taipei and were arrested by the local police.

In 2018, an investigation on a criminal money laundering organization in Spain led to the identification of Denis K, a Ukrainian computer specialist, as one of their client.   
He is believed to be the mastermind of the operation, he was involved with the Russian and Moldavian mafias and coordinated some cyberattacks for them.  
He was arrested, and the Spanish police found at his place several boxes of jewellery and over 15.000 bitcoins.


## Avril 2015 : TV5 Monde 

<p align="center">
<img alt="TV5 Monde" src="./images/tv5_monde.png" width=400 style="border:1px solid black">
</p>

TV5 Monde is the biggest French public TV network, broadcasting 11 channels in French in over 200 countries.

On April 8th 2015, the hacker group called "CyberCaliphate" attacked the headquarters of TV5 Monde TV Network in Paris.  
All 11 channels were interrupted for over 20 hours, showing a black screen.  
The hackers published on the social medias of TV5 Monde some messages from IS.

The attack was started on January 23rd, only 2 weeks after the Charlie Hebdo terrorist attack in Paris.  
Hackers scanned TV5 Monde public IP addresses, and gained access to the live-stage cameras (using default credentials).  
For months, they discovered the internal network, and gained access to more and more machines and accounts.  
Finally, they gained access to the 2 main multiplexers in charge of broadcasting all 11 channels (main one and backup one).

<table>
<tr>
  <td><b>19:57</b></td>
  <td>Multiplexers parameters changed to make them impossible to reboot.</td>
</tr>
<tr>
  <td><b>20:58</b></td>
  <td>TV5 Monde social network accounts show some messages from IS.</td>
</tr>
<tr>
  <td><b>21:48</b></td>
  <td>The 2 multiplexers are down, causing all 11 channels to stop broadcasting.</td>
</tr>
<tr>
  <td><b>22:40</b></td>
  <td>The internal messaging system is down.</td>
</tr>
<tr>
  <td><b>Night</b></td>
  <td>TV5 Monde disconnects their entire network from the public internet.<br/>
They calls the ANSII (Agence Nationale de la Sécurité des Systèmes d'Information) for help.<br/>
The ANSII tracks the hackers operation and rebuilds a network by changing all the machines.</td>
</tr>
<tr>
  <td><b>10:00</b></td>
  <td>Channels can broadcast pre-recorded programs (not live yet)<br/>
Broadcast on all channels of a speech from Yves Bigot (TV5 Monde CEO) to explain the attack.</td>
</tr>
<tr>
  <td><b>18:00</b></td>
  <td>First live broadcast.</td>
</tr>
</table>

The attack has taken down all 11 channels for 22 hours, and costed over 10M€ to TV5 Monde.

The investigation led to the suspicion of a russian hackers group called "APT 28".  
They possibly worked for IS, or were using IS as a cover to collect data for the Russian government.  
The Ministry of Foreign Affairs took over the investigation, and there were no later official update. 


## May 2017 : WannaCry

<p align="center">
<img alt="WannaCry" src="./images/wannacry.png" width=400  style="border:1px solid black">
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
