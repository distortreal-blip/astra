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

## 4) Start/stop
```
sudo systemctl status astra-entry
sudo systemctl restart astra-entry
```

## 5) Troubleshooting
- Check logs:
```
journalctl -u astra-entry -f
```
- Make sure ports are open in firewall.

