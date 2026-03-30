
---

```bash
zs1n@ptw ~> feroxbuster -u https://api.robinhood.com/ -w /usr/share/seclists/Discovery/Web-Content/common.txt -r -t 20 -o recursive_results.txt

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.13.1
───────────────────────────┬──────────────────────
 🎯  Target Url            │ https://api.robinhood.com/
 🚩  In-Scope Url          │ api.robinhood.com
 🚀  Threads               │ 20
 📖  Wordlist              │ /usr/share/seclists/Discovery/Web-Content/common.txt
 👌  Status Codes          │ All Status Codes!
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.13.1
 💉  Config File           │ /etc/feroxbuster/ferox-config.toml
 🔎  Extract Links         │ true
 💾  Output File           │ recursive_results.txt
 🏁  HTTP methods          │ [GET]
 📍  Follow Redirects      │ true
 🔃  Recursion Depth       │ 4
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
404      GET        0l        0w        0c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
401      GET        1l        5w       58c https://api.robinhood.com/documents/
404      GET       10l       21w      179c https://api.robinhood.com/mfa/challenge
[####################] - 41s     4751/4751    0s      found:2       errors:0
[####################] - 40s     4751/4751    119/s   https://api.robinhood.com/ 
```

![[Pasted image 20260325115338.png]]

```json
POST / HTTP/2

Host: graphql.tradepmr.com

User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0

Accept: */*

Accept-Language: en-US,en;q=0.5

Accept-Encoding: gzip, deflate, br

Access-Control-Request-Method: POST

Access-Control-Request-Headers: content-type,fweb_client_version,loggedin

Referer: https://fusion.tradepmr.com/

Origin: https://fusion.tradepmr.com/

Sec-Fetch-Dest: empty

Sec-Fetch-Mode: cors

Sec-Fetch-Site: same-site

Priority: u=4

Te: trailers

Content-Type: application/json

Content-Length: 83

Fweb_client_version: 1.0.0

Loggedin: true

Tpmr_log_emulated_by: admin@tradepmr.com

Temporaryaccesstoken: any_string_here



{"query": "mutation { login(username: \"admin\", password: \"admin\") { token } }"}
```

![[Pasted image 20260325123745.png]]

