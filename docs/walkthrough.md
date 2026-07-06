# A first walkthrough

A guided hour in the lab that touches recon, web exploitation, traffic capture,
proxying, and blue-team detection. **Isolated lab you own only** — see
[ETHICS.md](../ETHICS.md).

## 0. Bring it up and confirm isolation

```bash
scripts/lab-up.sh --minimal      # attacker + siem + juice, fastest start
scripts/verify-isolation.sh      # MUST report every box isolated
```

## 1. Recon (attacker box)

```bash
vagrant ssh attacker
cd ~/labforge
./scan-lab.sh                    # ping sweep + service/version scan
msfconsole -q -r recon.rc        # same, stored in the msf database
```

You should see Juice Shop on `10.20.0.31:3000` and (in the full lab) DVWA on
`10.20.0.32:80`.

## 2. Web exploitation — Juice Shop (OWASP Top 10)

1. Start Burp (`burpsuite &`) and point Firefox at `127.0.0.1:8080`.
2. Browse to <http://10.20.0.31:3000>.
3. Try the classic SQLi auth bypass at login: intercept the request and set the
   email to `' OR 1=1--`. You're in as the first user.
4. Work through the built-in **Score Board** (Juice Shop hides it — finding it
   is challenge #1). Each challenge maps to an OWASP category.

See [docs/burp.md](burp.md) for the proxy details.

## 3. Web exploitation — DVWA (progressive difficulty)

1. Login `admin` / `password` at <http://10.20.0.32/>.
2. Set **DVWA Security** to *low*. Exploit the **SQL Injection** page:
   `1' UNION SELECT user, password FROM users-- -`.
3. Bump security to *medium*, then *high*, and watch the same payload fail —
   read the source diff on each page to learn the mitigation.

## 4. Capture the traffic

In another terminal on the attacker:

```bash
sudo tshark -i eth1 -f "host 10.20.0.32" -w ~/labforge/dvwa.pcap
# ...run your DVWA attacks...
# Ctrl-C, then inspect:
tshark -r ~/labforge/dvwa.pcap -Y http.request \
       -T fields -e ip.dst -e http.request.uri
```

More filters in [docs/wireshark.md](wireshark.md).

## 5. Blue-team: find yourself in the SIEM

Open <http://10.20.0.20:8000> and search:

- `sqlmap` if you used it,
- `POST` around the DVWA login time,
- `nikto` if you scanned.

Note what each attack looks like in the logs. That signature knowledge is the
point — offense to understand defense. Details in [docs/siem.md](siem.md).

## 6. (Optional) Windows victim

```bash
vagrant destroy -f
scripts/lab-up.sh --windows
```

Then from Kali, enumerate SMB and try a password attack against the deliberately
weak `labuser` / `svc_backup` accounts:

```bash
smbclient -L //10.20.0.40 -N
hydra -l labuser -P /usr/share/wordlists/rockyou.txt rdp://10.20.0.40
```

Watch the failed logons (`EventID=4625`) show up in the SIEM.

## 7. Tear down

```bash
vagrant destroy -f
```

Everything is throwaway. Rebuild any time with one command.
