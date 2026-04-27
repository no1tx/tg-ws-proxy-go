# TG WS Proxy Go

Go-реализация локального MTProto-прокси для Telegram, который принимает клиентский handshake, пересобирает AES-CTR потоки и прокидывает трафик через `wss://kws*.web.telegram.org/apiws`. Проект рассчитан на Linux/OpenWrt, не требует Python и собирается в один статический бинарник.

## Возможности

- Локальный MTProto proxy для Telegram-клиентов
- Работа через WebSocket (`wss://kws*.web.telegram.org/apiws`)
- TCP fallback до Telegram DC при недоступности WebSocket
- Пул WSS-соединений для снижения задержек
- Опциональный Cloudflare fallback через собственный домен
- Сборка в один Go-бинарник без внешних runtime-зависимостей

## Сборка

```bash
go build -trimpath -ldflags="-s -w" -o tg-ws-proxy-go .
```

Пример кросс-сборки для OpenWrt `linux/arm64`:

```bash
GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o tg-ws-proxy-go .
```

## Запуск

Минимальный пример:

```bash
./tg-ws-proxy-go \
  --host 0.0.0.0 \
  --port 1443 \
  --secret 00112233445566778899aabbccddeeff \
  --dc-ip 2:149.154.167.220 \
  --dc-ip 4:149.154.167.220
```

Если `--secret` не указан, программа сгенерирует новый 16-байтный secret и выведет его в лог. Для подключения в Telegram используется значение `dd<32 hex secret>`.

## Параметры

- `--host`, `--port` : адрес и порт прослушивания
- `--secret` : 32 hex символа для MTProto secret
- `--dc-ip DC:IP` : перенаправление на конкретный Telegram DC, флаг можно указывать несколько раз
- `--buf-kb` : размер сетевого буфера в KB
- `--pool-size` : размер пула idle WSS-соединений на один DC
- `--stats-file` : путь к JSON-файлу со статистикой
- `--cfproxy-domain` : базовый домен для собственного Cloudflare fallback, например `example.com`
- `--cfproxy-priority` : пробовать Cloudflare fallback раньше TCP fallback
- `--no-cfproxy` : полностью отключить Cloudflare fallback
- `-v`, `--verbose` : подробный лог

По умолчанию Cloudflare fallback отключён. Он включается только если явно передан `--cfproxy-domain`.

## Подключение в Telegram

Параметры для клиента:

- Тип: `MTProto`
- Сервер: IP или доменное имя машины с прокси
- Порт: значение `--port`
- Secret: `dd<32 hex secret>`

Пример ссылки, которую печатает программа в лог:

```text
tg://proxy?server=192.168.1.1&port=1443&secret=dd00112233445566778899aabbccddeeff
```

## Docker

Локальный запуск:

```bash
docker compose up --build
```

По умолчанию контейнер слушает `0.0.0.0:16443`. Логи и `stats.json` пишутся в `./logs`.

## OpenWrt

Типовой сценарий:

1. Собрать бинарник под архитектуру роутера.
2. Скопировать его на устройство, например в `/usr/bin/tg-ws-proxy-go`.
3. Запускать через свой init-скрипт, `procd` или `rc.local`.
4. Открыть TCP-порт прокси в firewall для нужной зоны.

Минимальная проверка после запуска:

```bash
logread -f
```

## Отличия от исходного Python-проекта

- Нет self-update логики.
- Нет интерактивного shell-меню и OpenWrt installer-обвязки.
- WebSocket-клиент реализован на стандартной библиотеке Go.
- Бинарник проще разворачивать на системах без Python runtime.

## Безопасность

- Не публикуйте рабочий `--secret` из продакшн-инсталляции.
- Не используйте чужой `cfproxy`-домен: для fallback указывайте только домен, который контролируете сами.
- `stats.json` и логи могут содержать сетевые адреса и служебную информацию, поэтому их не стоит коммитить в репозиторий.

## Авторы

- Go-порт и адаптация под OpenWrt workflow: `no1tx`
- Идея и исходный Python-проект: `flowseal` и форк `v1rtuozz/tgwsproxy-openwrt`
