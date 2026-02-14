# ASTRA User Guide (for non‑developers)

This guide is for users who want to run ASTRA on a Linux server.

## 1) Download
You will receive an archive from the release page, for example:
```
astra-0.1.0-linux-amd64.tar.gz
```

## 2) Install
Unpack:
```
tar -xzf astra-0.1.0-linux-amd64.tar.gz
cd astra-0.1.0-linux-amd64
```

Copy configs:
```
sudo mkdir -p /etc/astra
sudo cp configs/*.json /etc/astra/
```

Copy systemd units:
```
sudo cp systemd/*.service /etc/systemd/system/
```

Copy binaries:
```
sudo mkdir -p /opt/astra/bin
sudo cp bin/* /opt/astra/bin/
```

Enable services:
```
sudo systemctl daemon-reload
sudo systemctl enable --now astra-entry astra-relay astra-exit astra-client
```

## 3) Basic configuration
Edit configs in:
```
/etc/astra/
```

Most common settings:
- `ENTRY_ADDR` — address for entry node
- `ENTRY_TRANSPORT` — `tls`, `rudp`, or `tcp`
- `ENTRY_TLS_ALPN` — `h2,http/1.1`
- `EXIT_ALLOW_PORTS` — allowed ports for exit

## 4) Full VPN mode (TUN)
ASTRA supports TUN mode to route all traffic through the tunnel.

Server (Exit):
```
sudo cp configs/astra-tun-exit.json /etc/astra/astra-exit.json
```

Client (Windows/Linux):
```
astra-tun-client -config configs/astra-tun-client.json
```

Linux routing example:
```
sudo ip addr add 10.10.0.2/24 dev astra0
sudo ip link set astra0 up
sudo ip route add default dev astra0
```

Server NAT example (Exit side):
```
sudo sysctl -w net.ipv4.ip_forward=1
sudo iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
```

Windows note:
- Install WireGuard (Wintun driver) so TUN device can be created.

## 5) Proxy mode (no TUN)
If you cannot use TUN on Windows, use the local HTTP CONNECT proxy.

Server (Exit):
```
# in /etc/astra/astra-exit.json
"EXIT_PROXY_MODE": true
```

Client (Windows):
```
astra-proxy-client -config configs/astra-proxy-client.json
```

Then set your browser proxy to:
```
HTTP proxy: 127.0.0.1:1080
```

## 5) Start/stop
```
sudo systemctl status astra-entry
sudo systemctl restart astra-entry
```

## 6) Troubleshooting
- Check logs:
```
journalctl -u astra-entry -f
```
- Make sure ports are open in firewall.

