# Astra GUI (Vue + Electron)

Окно 300×600 в стиле Figma: градиент, кнопка Power, статус Connected/Disconnected, пинг.

## Требования

- Node.js 18+
- Собранный `astra-tun-client.exe` в корне Astra (рядом с папкой `gui`)

## Установка и запуск

```bash
cd gui
npm install
```

**Режим разработки** (Vue dev server + Electron):

```bash
npm run electron:dev
```

**Только Electron** (после `npm run build`):

```bash
npm run build
npm run electron
```

При первом запуске Electron ищет `astra-tun-client.exe` в родительской папке (`Astra/`), конфиг — `Astra/configs/astra-tun-client.json`, логи — `Astra/logs/`.

## Сборка установщика

```bash
npm run dist
```

Готовый установщик — в `gui/dist/`. В инсталлятор можно добавить `astra-tun-client.exe` через `extraResources` в `package.json`.
