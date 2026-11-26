# Warp Pipe Proxy

> **Русский** · [English](README.en.md)

Установщик личного прокси VLESS Reality на Ubuntu. Трафик идёт через ваш сервер, сайты видят его IP. Установщик настраивает sing-box и создаёт ключи.

## Установка

Понадобятся чистая Ubuntu с systemd, права root или sudo и публичный IPv4 для подключения из интернета. Разрешите входящий **TCP 10443** в firewall провайдера. Серверу нужен доступ к APT, HTTPS и DNS (исходящие TCP и UDP 53).

На сервере или внутри контейнера скачайте проект.

```bash
git clone https://github.com/drewlakee/warp-pipe-proxy.git
cd warp-pipe-proxy
```

### VPS

Запустите установщик из SSH-сеанса.

```bash
sudo --preserve-env=SSH_CONNECTION ./warp-pipe-proxy.sh install
```

При активном UFW сохраняются текущие правила SSH. При первом включении пустого UFW установщик разрешает SSH с адреса текущего сеанса. Для установки из консоли задайте свой административный IP или CIDR в `VPS_SSH_SOURCE`. Если у выключенного UFW уже есть правила, проверьте их, включите UFW и подтвердите доступ новым SSH-соединением.

### Контейнер

Используйте Ubuntu-контейнер с systemd в качестве PID 1. При создании опубликуйте порт `-p 10443:10443/tcp` и разрешите его в firewall хоста. Внутри контейнера выполните команду установки.

```bash
sudo ./warp-pipe-proxy.sh install --container
```

Добавляйте `--container` при каждом запуске `install` и `check`. Firewall настраивается на хосте.

## Подключить устройство

На сервере создайте профиль телефона и выведите QR-код.

```bash
sudo warp-pipe-proxy device-add --device phone
sudo warp-pipe-proxy client-qr --device phone
```

Отсканируйте QR в клиенте с поддержкой VLESS Reality и включите подключение. Для подключения по ссылке выполните `sudo warp-pipe-proxy client-config --device phone`. QR и ссылка дают доступ к прокси.

Для системного туннеля (TUN) и DNS через прокси экспортируйте полный профиль. Перенесите файл на устройство и импортируйте его в sing-box.

```bash
umask 077
sudo warp-pipe-proxy client-profile --device phone > phone.json
```

Если подключаетесь к контейнеру по Wi-Fi, добавьте к `client-qr` или `client-profile` параметры `--endpoint 192.168.1.10 --port 10443`, подставив адрес хоста и опубликованный порт.

## Управление

После установки команды доступны из любого каталога.

| Задача | Команда |
| --- | --- |
| Посмотреть устройства и их статус | `sudo warp-pipe-proxy device-list` |
| Отозвать профиль телефона | `sudo warp-pipe-proxy device-revoke --device phone` |
| Проверить службы и порт | `sudo warp-pipe-proxy status` |
| Проверить конфигурацию, DNS и VLESS | `sudo warp-pipe-proxy check` |
| Проверить доступ к конкретному сайту | `sudo warp-pipe-proxy doctor --url https://example.com` |
| Смотреть журнал подключений | `sudo warp-pipe-proxy logs --follow` |

Добавление и отзыв устройства перезапускают службу. Другие устройства могут переподключиться с прежними профилями. Для смены ключей всех устройств выполните `sudo warp-pipe-proxy rotate-keys` и импортируйте новые профили.

## Настройки и обновление

IP, порты и параметры Reality хранятся в `/etc/warp-pipe-proxy/settings.json`. Чтобы открыть клиентам доступ к внутренней подсети, добавьте в этот файл поле `"allowed_private_subnets": ["192.168.50.0/24"]` со своим CIDR. Исключение действует для всех устройств. Примените изменения командой `sudo warp-pipe-proxy install` (в контейнере — с `--container`).

Для обновления выполните `git pull --ff-only` в каталоге проекта и повторите команду установки из выбранного раздела выше. Прежний UUID сохраняется в профиле `default`. Укажите нужные внутренние подсети до обновления. Если осталось старое правило UFW `warp-pipe-proxy SSH preservation`, подтвердите новый SSH-вход с разрешённого IP перед его удалением.
