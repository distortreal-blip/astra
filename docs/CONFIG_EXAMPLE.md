# ASTRA config example (single file)

ASTRA uses JSON configs that map to environment variables.  
Any key in the JSON becomes an env var if it isn't already set.

## Example (node that runs Entry + Relay + Exit in one place)
```json
{
  "ENTRY_ADDR": "0.0.0.0:8443",
  "ENTRY_TRANSPORT": "tls",
  "ENTRY_TLS_ALPN": "h2,http/1.1",
  "ENTRY_ALLOW_TRIAL": true,
  "ENTRY_TRIAL_TTL_MIN": 30,
  "ENTRY_RATE_LIMIT_PER_MIN": 60,
  "ENTRY_RATE_BURST": 20,

  "RELAY_ADDR": "0.0.0.0:9443",
  "RELAY_TRANSPORT": "rudp",
  "RELAY_NEXT_ADDR": "127.0.0.1:10443",
  "RELAY_NEXT_TRANSPORT": "rudp",

  "EXIT_ADDR": "0.0.0.0:10443",
  "EXIT_TRANSPORT": "rudp",
  "EXIT_UPSTREAM_TRANSPORT": "tcp",
  "EXIT_ALLOW_PORTS": "80,443,53",
  "EXIT_DENY_PORTS": "",
  "EXIT_DNS_ONLY": false,

  "ASTRA_MUX_ENABLED": true,
  "ASTRA_MUX_MAX_STREAMS": 64,
  "ASTRA_MUX_STREAM_WINDOW": 262144,
  "ASTRA_MUX_SESSION_WINDOW": 1048576,
  "ASTRA_FRAME_MIN_PAD": 8,
  "ASTRA_FRAME_MAX_PAD": 64
}
```

## Client example
```json
{
  "ENTRY_ADDR": "entry.example.com:8443",
  "ASTRA_TRANSPORTS": "tls,rudp,tcp",
  "ASTRA_MAX_ATTEMPTS": 6,
  "ASTRA_MUX_ENABLED": true,
  "ASTRA_FRAME_MIN_PAD": 8,
  "ASTRA_FRAME_MAX_PAD": 64,
  "OBFS_PREAMBLE_MAX": 128,
  "OBFS_PREAMBLE_TEMPLATE": "random",
  "TLS_APP_PREAMBLE_TEMPLATE": "http2frames",
  "TLS_FRAGMENT_MAX": 128
}
```
