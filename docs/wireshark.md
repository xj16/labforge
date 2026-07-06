# Capturing lab traffic in Wireshark

The Kali attacker box is set up to sniff the **entire** lab segment. The
Vagrantfile enables promiscuous mode (`--nicpromisc2 allow-all`) on the
host-only adapter, and the `kali` role gives the `vagrant` user non-root
capture rights via the `wireshark` group + `dumpcap` capabilities.

## From the attacker VM (GUI)

```bash
vagrant ssh attacker          # or use the GUI window Vagrant opened
sudo wireshark -i eth1 &      # eth1 is the 10.20.0.0/24 host-only NIC
```

Useful display filters once you're capturing:

| Goal                         | Filter |
|------------------------------|--------|
| Only Juice Shop HTTP         | `ip.addr == 10.20.0.31 && http` |
| Only DVWA HTTP               | `ip.addr == 10.20.0.32 && http` |
| Credentials in the clear     | `http.request.method == "POST"` |
| Syslog to the SIEM           | `ip.addr == 10.20.0.20 && (tcp.port == 5514 || udp.port == 5514)` |
| SMB to the Windows victim    | `ip.addr == 10.20.0.40 && smb2` |
| Your own nmap sweep          | `tcp.flags.syn == 1 && tcp.flags.ack == 0` |

## Headless capture with tshark

Great for saving a pcap while you run an attack in another terminal:

```bash
# capture DVWA login traffic to a file for later analysis
sudo tshark -i eth1 -f "host 10.20.0.32" -w ~/labforge/dvwa-login.pcap

# then, offline:
tshark -r ~/labforge/dvwa-login.pcap -Y "http.request" \
       -T fields -e http.host -e http.request.uri -e urlencoded-form
```

## Which NIC is which?

VirtualBox host-only NICs usually enumerate as the **second** interface
(`eth1` on Debian/Kali). Confirm with:

```bash
ip -brief addr | grep 10.20.0
```

## Blue-team follow-up

After you capture an attack, jump to the [SIEM guide](siem.md) and search the
central log viewer for the same event — seeing the packet *and* the resulting
log entry is the whole point of pairing Wireshark with the SIEM.
