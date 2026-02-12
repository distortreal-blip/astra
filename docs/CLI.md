# ASTRA CLI (для разработчиков)

Все сервисы принимают:
```
-config /path/to/config.json
```
и читают JSON в env (если переменная не задана).

## astra-client
```
astra-client -config configs/astra-client.json \
  -entry entry.example.com:8443 \
  -transports tls,rudp,tcp \
  -network wifi_home \
  -nodes "entry|e1|1.2.3.4:8443;entry|e2|5.6.7.8:8443" \
  -mux true \
  -frame-min 8 \
  -frame-max 64 \
  -obfs-max 128 \
  -obfs-template random \
  -tls-preamble http2frames \
  -tls-frag 128
```

## astra-entry
```
astra-entry -config configs/astra-entry.json \
  -addr 0.0.0.0:8443 \
  -transport tls \
  -next 127.0.0.1:9443 \
  -tls-alpn h2,http/1.1 \
  -rate 60 \
  -burst 20 \
  -frame-min 8 \
  -frame-max 64 \
  -mux true
```

## astra-relay
```
astra-relay -config configs/astra-relay.json \
  -addr 0.0.0.0:9443 \
  -transport rudp \
  -next 127.0.0.1:10443 \
  -next-transport rudp
```

## astra-exit
```
astra-exit -config configs/astra-exit.json \
  -addr 0.0.0.0:10443 \
  -transport rudp \
  -upstream 1.1.1.1:53 \
  -upstream-transport tcp \
  -dns-only true
```

## astra-lab
```
astra-lab -config configs/astra-lab.json \
  -mode proxy \
  -listen 127.0.0.1:18080 \
  -target 127.0.0.1:8443 \
  -drop 10 \
  -delay 20 \
  -reset 1024
```
