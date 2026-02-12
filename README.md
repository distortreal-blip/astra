# ASTRA

ASTRA is a next‑generation VPN protocol focused on anti‑DPI resilience, adaptive transport selection, and strong cryptographic authentication.  
It is designed to look like ordinary web traffic while dynamically changing profiles to survive blocking.

## Why ASTRA
- Adaptive SNI + transport selection per network
- TLS mimicry with real JA3/ALPN (uTLS)
- Replay‑safe handshake with signed identity + access tokens
- Multi‑hop chain support (Entry → Relay → Exit)
- Built‑in lab for stress testing and block emulation

## How it works (short)
1. Client creates a cryptographic identity (keypair + ClientID)
2. Client signs a handshake (anti‑replay nonce + timestamp)
3. Entry validates identity + token + policy (rate limit / revoke)
4. Traffic flows through Entry → Relay → Exit
5. Client learns which profile works best in each network (Wi‑Fi / 4G / ISP)

## Anti‑DPI features
- TLS mimicry with JA3/ALPN and HTTP/2 preface + frames
- Stream framing + padding to hide traffic patterns
- Adaptive profile rotation (SNI/transport/obfs)

## Architecture
```
Client ──> Entry ──> Relay (optional) ──> Exit ──> Internet
```

## Protocol highlights
- Signed handshake with replay protection
- Token/trial policy and revoke support
- RUDP transport with ACK/retransmit + keepalive
- Multiplexing with priorities and flow control

## Quick start (Linux)
```bash
git clone https://github.com/distortreal-blip/astra.git
cd astra
go mod download

# Start Entry
go run ./cmd/astra-entry -config configs/astra-entry.json

# Start Relay (optional)
go run ./cmd/astra-relay -config configs/astra-relay.json

# Start Exit
go run ./cmd/astra-exit -config configs/astra-exit.json

# Start Client
go run ./cmd/astra-client -config configs/astra-client.json
```

## Full VPN mode (TUN)
Use the TUN client to route all system traffic through ASTRA.
```bash
go run ./cmd/astra-tun-client -config configs/astra-tun-client.json
```
Windows: install WireGuard (Wintun) so the TUN device can be created.

## Config management
Every service accepts a `-config` path (JSON).  
Config values are loaded into environment **only if env vars are not already set**.

Example:
```bash
ASTRA_CONFIG=configs/astra-entry.json go run ./cmd/astra-entry
```

See config examples in `configs/` and `docs/CONFIG_EXAMPLE.md`.
CLI examples: `docs/CLI.md`.

## Services
- `astra-client` — client with adaptive SNI/transport selection
- `astra-tun-client` — TUN client (routes all traffic)
- `astra-entry` — auth + routing to relay/exit
- `astra-relay` — optional hop
- `astra-exit` — egress + policies
- `astra-lab` — DPI lab (proxy + load test)

## Common env keys
- `ENTRY_ADDR`, `ENTRY_TRANSPORT`, `ENTRY_TLS_ALPN`
- `ASTRA_TRANSPORTS`, `ASTRA_MUX_*`, `ASTRA_FRAME_*`
- `OBFS_PREAMBLE_*`, `TLS_APP_PREAMBLE_TEMPLATE`, `TLS_FRAGMENT_MAX`
- `EXIT_ALLOW_*`, `EXIT_DENY_*`, `EXIT_DNS_ONLY`

## Security and policy
- Signed handshake + anti‑replay
- Token/trial access control
- Rate limiting and fail‑blocker

## Building binaries
```bash
go build ./cmd/astra-client
go build ./cmd/astra-tun-client
go build ./cmd/astra-entry
go build ./cmd/astra-relay
go build ./cmd/astra-exit
go build ./cmd/astra-lab
```

## systemd (Linux)
```bash
sudo cp systemd/astra-entry.service /etc/systemd/system/
sudo cp systemd/astra-relay.service /etc/systemd/system/
sudo cp systemd/astra-exit.service /etc/systemd/system/
sudo cp systemd/astra-client.service /etc/systemd/system/

sudo mkdir -p /etc/astra
sudo cp configs/*.json /etc/astra/

sudo systemctl daemon-reload
sudo systemctl enable --now astra-entry astra-relay astra-exit astra-client
```

## systemd install script
```bash
scripts/install-systemd.sh
```

## Release artifacts
```bash
scripts/release.sh
```

## Packages (Linux)
```bash
scripts/package-deb.sh
scripts/package-rpm.sh
```

## User guide
See `docs/USER_GUIDE.md`.
