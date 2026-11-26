# Warp Pipe Proxy

> **Русский** · [English](README.en.md)

Установщик личного прокси VLESS Reality на Ubuntu. Трафик идёт через ваш сервер, сайты видят его IP. Установщик настраивает sing-box и создаёт ключи.

## Что настраивает установщик

При первом запуске установщик определяет публичный IPv4 и выбирает узел для рукопожатия Reality, проверив TLS 1.3 и HTTP/2. Если sing-box ещё не установлен, он добавляет официальный APT-репозиторий и устанавливает пакет.

| Компонент | Настройка по умолчанию |
| --- | --- |
| Прокси | Настраивает sing-box с VLESS Reality на `0.0.0.0:10443/TCP`. Служба `warp-pipe-proxy` запускается от отдельного системного пользователя и включается при загрузке. |
| DNS | Сервер разрешает имена через Unbound на `127.0.0.1:5353`. Полный клиентский JSON-профиль направляет DNS через прокси к `1.1.1.1` по HTTPS. |
| Ключи и доступ | При первом запуске создаёт пару ключей Reality, Short ID и UUID профиля `default`. Хранит учётные данные в `/etc/warp-pipe-proxy/credentials.json` с правами `0600`. По умолчанию клиентам закрыт доступ к внутренним адресам. |
| Защита SSH и сеть на VPS | Открывает порт прокси в UFW. Fail2ban блокирует источник на час после пяти неудачных входов по SSH за десять минут. При поддержке ядром включает TCP BBR. При запуске с `--container` установщик пропускает UFW, fail2ban и BBR. |
| Проверка и восстановление | Проверяет локальный DNS и выполняет HTTPS-запрос через VLESS. Сохраняет журнал в `/var/log/warp-pipe-proxy-installer/` и резервную копию в `/var/lib/warp-pipe-proxy-installer/`. При сбое применения пытается восстановить управляемые файлы и службы. |

## Установка

В примерах ниже показаны фрагменты вывода. Время, адреса и пути запусков могут отличаться. В ссылках и профилях секреты заменены метками в угловых скобках.

Понадобятся чистая Ubuntu с systemd, права root или sudo и публичный IPv4 для подключения из интернета. Разрешите входящий **TCP 10443** в firewall провайдера. Серверу нужен доступ к APT, HTTPS и DNS (исходящие TCP и UDP 53).

На сервере или внутри контейнера скачайте проект.

```bash
git clone https://github.com/drewlakee/warp-pipe-proxy.git
cd warp-pipe-proxy
```

<details>
<summary>Пример вывода</summary>

```text
Cloning into 'warp-pipe-proxy'...
```

При успехе `cd` ничего не печатает.

</details>

### VPS

Запустите установщик из SSH-сеанса.

```bash
sudo --preserve-env=SSH_CONNECTION ./warp-pipe-proxy.sh install
```

<details>
<summary>Пример вывода</summary>

```text
[SUCCESS] Installed command: /usr/local/bin/warp-pipe-proxy
[SUCCESS] SUCCESS: VLESS Reality configured
```

</details>

При активном UFW сохраняются текущие правила SSH. При первом включении пустого UFW установщик разрешает SSH с адреса текущего сеанса. Для установки из консоли задайте свой административный IP или CIDR в `VPS_SSH_SOURCE`. Если у выключенного UFW уже есть правила, проверьте их, включите UFW и подтвердите доступ новым SSH-соединением.

### Контейнер

Используйте Ubuntu-контейнер с systemd в качестве PID 1. При создании опубликуйте порт `-p 10443:10443/tcp` и разрешите его в firewall хоста. Внутри контейнера выполните команду установки.

```bash
sudo ./warp-pipe-proxy.sh install --container
```

<details>
<summary>Пример вывода</summary>

```text
[SUCCESS] SUCCESS: VLESS Reality configured
[WARN] CONTAINER MODE: proxy checks passed; UFW, fail2ban and BBR were not managed
```

</details>

Добавляйте `--container` при каждом запуске `install` и `check`. Firewall настраивается на хосте.

## Подключить устройство

На сервере создайте профиль телефона и выберите формат для клиента.

```bash
sudo warp-pipe-proxy device-add --device phone
```

<details>
<summary>Пример вывода</summary>

```text
[SUCCESS] Credential change completed: device-add
```

</details>

**QR или ссылка.** Отсканируйте QR в клиенте VLESS Reality или импортируйте ссылку. Оба варианта дают доступ к прокси.

```bash
sudo warp-pipe-proxy client-qr --device phone
```

<details>
<summary>Пример вывода</summary>

```text
VLESS QR contains access credentials. Keep it private. DNS/TUN settings require the JSON profile.
```

Следом терминал рисует QR-код с данными телефона.

</details>

```bash
sudo warp-pipe-proxy client-config --device phone
```

<details>
<summary>Пример вывода</summary>

```text
VLESS Reality:
vless://<UUID>@203.0.113.10:10443?encryption=none&flow=xtls-rprx-vision&security=reality&sni=www.microsoft.com&fp=chrome&pbk=<PUBLIC_KEY>&sid=<SHORT_ID>&type=tcp#vps-reality
```

</details>

**Профиль sing-box.** Для системного туннеля (TUN) и DNS через прокси сохраните JSON, перенесите файл на устройство и импортируйте его в sing-box.

```bash
umask 077
sudo warp-pipe-proxy client-profile --device phone > phone.json
```

<details>
<summary>Результат в phone.json</summary>

```text
      "type": "vless",
      "tag": "proxy",
      "server": "203.0.113.10",
      "server_port": 10443,
      "uuid": "<UUID>",
```

Это фрагмент объекта `outbounds[0]`. Обе команды при успехе ничего не выводят в терминал. Команда `umask` задаёт права для новых файлов, а `>` записывает JSON в `phone.json`.

</details>

При подключении к контейнеру по Wi-Fi добавьте к `client-qr` или `client-profile` параметры `--endpoint 192.168.1.10 --port 10443`, подставив LAN-адрес хоста и опубликованный порт.

## Смена ключей устройств

После успешной ротации **каждому активному устройству потребуется новый профиль**. Перезапуск прокси прерывает текущие соединения. Старые QR-коды, ссылки и JSON больше не подходят для входа.

```bash
sudo warp-pipe-proxy rotate-keys
```

```text
VLESS Reality authenticated HTTPS request passed
[SUCCESS] Credential change completed: rotate-keys
[INFO] Export and import new profiles on every active device
[INFO] Previous credentials are retained in the root-only backup: /var/lib/warp-pipe-proxy-installer/<RUN>
```

Меняются общая пара ключей Reality, Short ID и индивидуальный UUID каждого активного устройства, включая активный `default`. Имена устройств сохраняются. Например, `phone` и `laptop` останутся активными, а отозванный `old-phone` останется отозванным.

После сообщения об успехе выведите новый QR для `phone` или экспортируйте JSON для `laptop` командами из раздела [«Подключить устройство»](#подключить-устройство), указав имя нужного устройства в `--device`. Замените профиль в приложении и переподключитесь. Повторять `device-add` не нужно.

<details>
<summary>Если проверка после перезапуска не прошла</summary>

```text
[WARN] Rolling back managed configuration and service states
[SUCCESS] Managed configuration and service states restored
```

При успешном откате прежние профили снова работают. Сообщение `ROLLBACK INCOMPLETE` означает, что нужно проверить журнал и резервную копию.

</details>

## Управление и диагностика

| Задача | Команда | Пример вывода (фрагмент) |
| --- | --- | --- |
| Отозвать старый телефон | `sudo warp-pipe-proxy device-revoke --device old-phone` | `[SUCCESS] Credential change completed: device-revoke` |
| Список устройств | `sudo warp-pipe-proxy device-list` | `default	active`<br>`laptop	active`<br>`old-phone	revoked`<br>`phone	active` |
| Службы и порт | `sudo warp-pipe-proxy status` | `Proxy service: PASS`<br>`DNS service: PASS`<br>`VLESS TCP port 10443: PASS` |
| Проверить DNS и VLESS | `sudo warp-pipe-proxy check` | `VLESS Reality authenticated HTTPS request passed` |
| Проверить в контейнере | `sudo warp-pipe-proxy check --container` | `[WARN] Container mode: UFW and fail2ban checks skipped; host firewall must protect published ports` |
| Проверить сайт | `sudo warp-pipe-proxy doctor --url https://example.com` | `Direct IPv4 transport: PASS`<br>`VLESS transport passed; inspect the HTTP status above` |
| Следить за журналом | `sudo warp-pipe-proxy logs --follow` | `… inbound/vless[vless-reality]: [phone] inbound connection to example.com:443` |
| Справка | `warp-pipe-proxy --help` | `usage: warp-pipe-proxy.sh [-h] [--container] …` |

Для отключения одного устройства достаточно `device-revoke`. Служба перезапустится, остальные устройства смогут подключиться с прежними профилями. Команда `status` проверяет службы и порт локально; доступность извне проверьте с устройства.

## Настройки и обновление

IP, порты и параметры Reality хранятся в `/etc/warp-pipe-proxy/settings.json`. Чтобы открыть клиентам доступ к внутренней подсети, добавьте в этот файл поле `"allowed_private_subnets": ["192.168.50.0/24"]` со своим CIDR. Исключение действует для всех устройств. Примените изменения командой `sudo warp-pipe-proxy install` (в контейнере — с `--container`).

Для обновления выполните `git pull --ff-only` в каталоге проекта и повторите команду установки из выбранного раздела выше. Прежний UUID сохраняется в профиле `default`. Укажите нужные внутренние подсети до обновления. Если осталось старое правило UFW `warp-pipe-proxy SSH preservation`, подтвердите новый SSH-вход с разрешённого IP перед его удалением.

<details>
<summary>Примеры вывода при обновлении и повторном применении</summary>

```text
$ git pull --ff-only
Already up to date.

$ sudo warp-pipe-proxy install
[SUCCESS] SUCCESS: VLESS Reality configured
```

В примере локальная копия уже актуальна. После скачивания новой версии запускайте установщик из каталога проекта, как показано выше. Вариант `sudo warp-pipe-proxy install` применяет уже установленную версию.

</details>
