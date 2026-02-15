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
