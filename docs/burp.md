# Proxying lab targets through Burp Suite

Burp Suite (Community Edition ships with Kali — free) lets you intercept,
inspect, and tamper with HTTP(S) between you and the vulnerable targets. This is
the core loop for working the OWASP Top 10 in Juice Shop and DVWA.

## 1. Start Burp on the attacker

```bash
vagrant ssh attacker           # or the GUI window
burpsuite &                    # "Temporary project" → "Use Burp defaults"
```

Burp's default proxy listener is `127.0.0.1:8080`. That's fine when the browser
and Burp are on the same Kali box (the usual setup).

## 2. Point a browser at Burp

Use the pre-configured Firefox on Kali, or set any browser's HTTP/HTTPS proxy to
`127.0.0.1:8080`, then browse to a target:

- Juice Shop: <http://10.20.0.31:3000>
- DVWA:       <http://10.20.0.32/>  (login `admin` / `password`)

In **Proxy → Intercept**, toggle *Intercept is on* to pause and edit requests.
Send interesting requests to **Repeater** (Ctrl-R) to iterate on payloads.

## 3. Proxying tooling instead of a browser

To route command-line tools through Burp (great for watching what `sqlmap` or a
script actually sends):

```bash
# curl through Burp
curl -x http://127.0.0.1:8080 http://10.20.0.32/vulnerabilities/sqli/

# sqlmap through Burp
sqlmap -u "http://10.20.0.32/vulnerabilities/sqli/?id=1&Submit=Submit" \
       --proxy=http://127.0.0.1:8080 --cookie="security=low; PHPSESSID=..."
```

## 4. HTTPS interception

The lab targets are HTTP, so you usually don't need Burp's CA. If you add TLS to
a target, install Burp's CA cert (`http://burp/cert` while proxied) into the
browser/system trust store so interception doesn't throw cert warnings.

## Suggested exercises

| Target     | Burp workflow |
|------------|---------------|
| Juice Shop | Intercept the login, tamper the SQL in `email` to bypass auth. |
| Juice Shop | Use Repeater to fuzz the product-search `q` param for injection. |
| DVWA (low) | Intercept the SQLi form, then bump `security` cookie to *high* and compare. |
| DVWA       | Use Intruder (Community: rate-limited) on the brute-force page. |

Everything you do here is logged centrally — open the [SIEM](siem.md) and search
for your requests to practice detection.
