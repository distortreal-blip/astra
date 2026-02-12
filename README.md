# ASTRA

Adaptive anti‑DPI VPN protocol with dynamic SNI/transport selection, TLS mimicry, and relay chain support.

## Quick start (Linux)
```bash
git clone https://github.com/your-org/astra.git
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
