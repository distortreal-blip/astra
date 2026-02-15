# Деплой и сборка Astra

## 1. Пуш на GitHub (без папки gui)

Папка `gui/` добавлена в `.gitignore`, в репозиторий она не попадёт.

```bash
cd C:\Users\User\Desktop\Astra

git add .
git status
git commit -m "описание изменений"
git push origin main
```

Если репозиторий ещё не привязан:

```bash
cd C:\Users\User\Desktop\Astra
git init
git remote add origin https://github.com/YOUR_USER/Astra.git
git branch -M main
git add .
git commit -m "Initial commit"
git push -u origin main
```

Проверка, что gui не в коммите: `git status` не должен показывать файлы из `gui/`.

---

## 2. Сервер: pull, билд, перезапуск через systemctl

На сервере (Linux):

```bash
cd /path/to/Astra
git pull origin main

go build -o astra-entry   ./cmd/astra-entry
go build -o astra-relay   ./cmd/astra-relay
go build -o astra-exit    ./cmd/astra-exit

sudo systemctl restart astra-entry
sudo systemctl restart astra-relay
sudo systemctl restart astra-exit
```

Если юниты называются иначе (например `astra@entry`):

```bash
sudo systemctl restart astra@entry
sudo systemctl restart astra@relay
sudo systemctl restart astra@exit
```

Одной строкой (pull + билд + рестарт entry):

```bash
cd /path/to/Astra && git pull origin main && go build -o astra-entry ./cmd/astra-entry && sudo systemctl restart astra-entry
```

### Один юнит на два порта (TCP + QUIC)

Чтобы Entry слушал и TCP (:8443), и QUIC (:8444), используй скрипт и пример юнита из репозитория:

```bash
cd /root/astra
chmod +x scripts/entry-dual-start.sh
sudo cp docs/astra-entry-dual.service.example /etc/systemd/system/astra-entry-dual.service
sudo nano /etc/systemd/system/astra-entry-dual.service   # поправить WorkingDirectory/ExecStart под свой путь
sudo systemctl daemon-reload
sudo systemctl enable astra-entry-dual
sudo systemctl start astra-entry-dual
```

Перезапуск: `sudo systemctl restart astra-entry-dual`.

**Клиент:** чтобы QUIC ходил на порт 8444, в конфиге или env задай `ENTRY_QUIC_ADDR=host:8444` (например `178.208.76.92:8444`). Тогда для транспорта quic будет использоваться этот адрес, для остальных — `ENTRY_ADDR` (например `178.208.76.92:8443`). В `configs/astra-tun-client.json` можно добавить `"ENTRY_QUIC_ADDR":"178.208.76.92:8444"`.

### Exit с TUN (полный туннель: клиент → Entry → Exit → интернет)

Чтобы клиент видел трафик (rx > 0), нужна цепочка: **Entry** проксирует в **Exit**, Exit пишет в TUN.

- **Entry:** в юните `astra-entry-dual` (или entry) обязательно задать `ENTRY_NEXT_ADDR=127.0.0.1:11443` (или адрес твоего Exit). Без этого Entry не шлёт трафик в Exit.
- **Exit:** в конфиге или в юните `astra-exit` задать `EXIT_TUN_ENABLE=true` (по умолчанию false). Иначе Exit обрабатывает соединение как echo, а не как TUN — клиент будет tx расти, rx=0.

Включить TUN на Exit одной командой (drop-in + reload + restart):
```bash
sudo mkdir -p /etc/systemd/system/astra-exit.service.d && echo -e '[Service]\nEnvironment=EXIT_TUN_ENABLE=true' | sudo tee /etc/systemd/system/astra-exit.service.d/tun.conf && sudo systemctl daemon-reload && sudo systemctl restart astra-exit
```

Проверка на сервере после подключения клиента:

```bash
# Exit должен показать "EXIT TUN up" и tun stats с rx > 0
sudo journalctl -u astra-exit -n 30 --no-pager
# Должно быть установленное соединение Entry → Exit
ss -tn state established '( dport = :11443 or sport = :11443 )'
```

Если у клиента tx растёт, а rx=0 — проверь `ENTRY_NEXT_ADDR` и `EXIT_TUN_ENABLE`.

Проверить, что Entry видит ENTRY_NEXT_ADDR и подключается к Exit:
```bash
sudo systemctl cat astra-entry-dual.service | grep ENTRY_NEXT
sudo journalctl -u astra-entry-dual -n 100 --no-pager | grep -E "proxy|dial|echo mode"
```
Если в логах видно «no ENTRY_NEXT_ADDR… echo mode» или ENTRY_NEXT_ADDR нет в юните — задать через drop-in, пересобрать Entry, перезапустить (одной строкой):
```bash
sudo mkdir -p /etc/systemd/system/astra-entry-dual.service.d && echo -e '[Service]\nEnvironment=ENTRY_NEXT_ADDR=127.0.0.1:11443' | sudo tee /etc/systemd/system/astra-entry-dual.service.d/next.conf && sudo systemctl daemon-reload && cd /root/astra && git pull origin main && go build -o astra-entry ./cmd/astra-entry && sudo systemctl restart astra-entry-dual
```
После подключения клиента в логах должно быть: `proxy to 127.0.0.1:11443` и `proxy connected to 127.0.0.1:11443`. Если есть `proxy dial failed` — Exit не слушает на 11443 или порт неверный.

**QUIC:** клиент по умолчанию стучится на ENTRY_ADDR (8443). QUIC у dual-entry слушает на 8444. Чтобы клиент ходил по QUIC на 8444, задай в конфиге клиента или в env: `ENTRY_QUIC_ADDR=IP:8444` (например `ENTRY_QUIC_ADDR=178.208.76.92:8444`). В JSON: `"ENTRY_QUIC_ADDR":"178.208.76.92:8444"`.

---

## 3. Локально: билд клиента (Windows)

В корне проекта:

```bash
cd C:\Users\User\Desktop\Astra
go build -o astra-tun-client.exe ./cmd/astra-tun-client
```

Готовый бинарник: `astra-tun-client.exe` в текущей папке. Запуск от имени администратора (для TUN и маршрутов).

Другие билды при необходимости:

```bash
go build -o astra-entry.exe   ./cmd/astra-entry
go build -o astra-exit.exe   ./cmd/astra-exit
go build -o astra-relay.exe  ./cmd/astra-relay
go build -o astra-lab.exe    ./cmd/astra-lab
```
