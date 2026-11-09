#!/usr/bin/env bash
# Ошибки команд и конвейеров прерывают установку; ERR наследуется функциями.
set -Eeuo pipefail
# Новые файлы, включая ключи и резервные копии, доступны только владельцу.
umask 077
# Комментарии русские, но сообщения скрипта и системных утилит — английские.
export LC_ALL=C
BASE=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
MODE=''
CONTAINER_MODE=0
MODE_SELECTED=0
# Сервисные команды не запускают установку и не создают журналы с секретами профиля.
CLI_ARGS=("$@")
CHECK_URL=''
while (( $# )); do
    case "$1" in
        --container) CONTAINER_MODE=1 ;;
        --help|-h) python3 "$BASE/admin.py" --help; exit 0 ;;
        install|check|status|doctor|logs|client-config|client-profile|rotate-keys)
            if (( MODE_SELECTED )); then echo 'Specify only one command'; exit 2; fi
            MODE=$1
            MODE_SELECTED=1
            ;;
        --url|--endpoint|--port|--since|--filter)
            [[ $# -ge 2 ]] || { echo "Missing value for $1"; exit 2; }
            if [[ $1 == --url ]]; then CHECK_URL=$2; fi
            shift
            ;;
        --follow) ;;
        *) echo "Unknown argument: $1"; exit 2 ;;
    esac
    shift
done
[[ -n $MODE ]] || { python3 "$BASE/admin.py" --help; exit 2; }
# argparse проверяет принадлежность параметров командам до любых изменений системы.
if [[ $MODE == install ]]; then
    for argument in "${CLI_ARGS[@]}"; do
        case "$argument" in install|--container) ;; *) echo 'install only accepts --container'; exit 2 ;; esac
    done
else
    python3 "$BASE/admin.py" "${CLI_ARGS[@]}" --validate-only
fi
case "$MODE" in
    status|doctor|logs|client-profile) exec python3 "$BASE/admin.py" "${CLI_ARGS[@]}" ;;
esac
# Проверяем базовое окружение до создания файлов и запуска служб.
[[ $EUID == 0 ]] || { echo 'Run with sudo/root'; exit 1; }
[[ -f /etc/os-release ]] || exit 1
. /etc/os-release
[[ ${ID:-} == ubuntu ]] || { echo 'Only Ubuntu is supported'; exit 1; }
[[ -d /run/systemd/system ]] || { echo 'Requires systemd on a VPS'; exit 1; }
# Не смешиваем старую установку с новыми путями: иначе можно потерять доступ к ключам.
if [[ -e /etc/vps-proxy || -e /etc/systemd/system/vps-proxy.service ]]; then
    echo 'Legacy vps-proxy installation detected. Automatic migration is not supported.'
    echo 'Preserve its settings and credentials before migrating to warp-pipe-proxy. No changes made.'
    exit 1
fi
ROOT=/etc/warp-pipe-proxy
# Секретные ссылки выводим отдельно, до подключения общего журнала.
if [[ $MODE == client-config ]]; then
    cat "$ROOT/clients.txt"
    exit
fi
command -v flock >/dev/null || { echo 'flock is required'; exit 1; }
# Дескриптор остаётся открытым до выхода, удерживая блокировку от второго установщика.
exec 9>/run/lock/warp-pipe-proxy.lock
flock -n 9 || { echo 'Another installer is running'; exit 1; }
install -d -m 700 /var/log/warp-pipe-proxy-installer
RUN=$(date -u +%Y%m%dT%H%M%SZ)-$$
LOG=/var/log/warp-pipe-proxy-installer/$RUN.log
source "$BASE/logging.sh"
# Цвет печатается напрямую в терминал; tee получает только текст баннера.
if [[ $MODE == install ]]; then
    STARTUP_BANNER=$(cat <<'ART'

       ______________
      |==============|     W A R P   P I P E
      |______________|     P R O X Y
         |  |    |
         |  |    |         YOUR SERVER. YOUR TUNNEL.
         |  |    |
         |  |    |         VLESS REALITY
         |_______|         Powered by sing-box

      ==========================================================
                      READY TO WARP! / SETUP START
      ==========================================================
ART
    )
    BANNER_COLOR=''
    BANNER_RESET=''
    if (( LOG_COLOR_ENABLED )); then
        BANNER_COLOR=$'\033[1;32m'
        BANNER_RESET=$'\033[0m'
    fi
    printf '%s' "$BANNER_COLOR"
    printf '%s\n\n' "$STARTUP_BANNER" | tee -a "$LOG"
    printf '%s' "$BANNER_RESET"
fi
# stdout и stderr записываются в журнал до добавления цвета для терминала.
exec > >(tee -a "$LOG" | colorize_output) 2>&1
CURRENT_STAGE='Preparation'
stage() {
    CURRENT_STAGE=$1
    banner "$CURRENT_STAGE"
}
on_error() {
    local status=$1 line=$2
    banner "ERROR | $CURRENT_STAGE" >&2
    log ERROR "FAILED line=$line exit=$status. See $LOG. Managed configuration will be rolled back if application has started; packages and generated credentials are retained." >&2
    exit "$status"
}
trap 'on_error "$?" "$LINENO"' ERR
# runtime.sh использует общие ROOT, BACKUP, STAGE и LOG и регистрирует EXIT-обработчик отката.
source "$BASE/runtime.sh"
read_setting() {
    python3 "$BASE/configure.py" get --key "$1"
}
# Проверяем реальный трафик, а не только успешный запуск процессов.
check_installation() {
    stage 'Checking services, DNS and VLESS Reality'
    log 'Checking configuration, services, recursive DNS and authenticated VLESS Reality'
    sing-box check -c /etc/sing-box/config.json
    wait_services
    dig +time=8 +tries=1 @127.0.0.1 -p "$(read_setting dns_port)" example.com A | grep -q 'status: NOERROR'
    dig +tcp +time=8 +tries=1 @127.0.0.1 -p "$(read_setting dns_port)" example.com A | grep -q 'status: NOERROR'
    # Временный клиент выполняет HTTPS-запрос через VLESS Reality без прямого обхода.
    python3 "$BASE/probe.py"
    wait_services
    if (( ! CONTAINER_MODE )); then
        fail2ban-client status sshd
        ufw status verbose
    else
        log WARN 'Container mode: UFW and fail2ban checks skipped; host firewall must protect published ports'
    fi
    log SUCCESS 'Local checks passed. Verify VLESS from an external client; provider firewall/NAT cannot be checked locally.'
}

# Проверяем права и существующие службы до изменений конфигурации.
check_installation_prerequisites() {
    local helper item port
    stage 'Checking environment, firewall permissions and SSH ports'
    if (( CONTAINER_MODE )); then
        log WARN 'CONTAINER MODE: UFW, fail2ban and BBR will not be managed; existing rules and services are left unchanged'
        log WARN 'Configure access restrictions on the host and publish only the required container ports'
    fi
    firewall_preflight
    if command -v iptables >/dev/null && command -v ufw >/dev/null; then
        firewall_backend_check
    fi
    for helper in configure.py probe.py; do
        [[ -f $BASE/$helper ]] || { log ERROR "$helper must be next to warp-pipe-proxy.sh"; exit 1; }
    done
    if [[ ! -e $ROOT/managed ]]; then
        local unmanaged_paths=(/etc/sing-box /etc/unbound)
        if (( ! CONTAINER_MODE )); then unmanaged_paths+=(/etc/fail2ban); fi
        for item in "${unmanaged_paths[@]}"; do
            [[ ! -e $item ]] || { log ERROR "Existing $item found: refusing to overwrite an unmanaged installation"; exit 1; }
        done
    fi
    export DEBIAN_FRONTEND=noninteractive NEEDRESTART_MODE=l
    if ! command -v ss >/dev/null; then
        log 'Installing prerequisite iproute2 (ss) before inspecting network listeners'
        apt-get update
        apt-get install -y iproute2
        command -v ss >/dev/null || { log ERROR 'iproute2 installation did not provide ss' >&2; exit 1; }
    fi
    # В контейнере SSH не настраиваем: прокси может работать и без SSH-сервера.
    SSH_PORTS=''
    if (( ! CONTAINER_MODE )); then
        SSH_PORTS=$(/usr/sbin/sshd -T | awk '$1 == "port" {print $2}' | sort -nu)
        [[ -n $SSH_PORTS ]] || { log ERROR 'Cannot determine SSH ports'; exit 1; }
        for port in $SSH_PORTS; do
            [[ $port =~ ^[0-9]+$ ]] && ((port >= 1 && port <= 65535))
        done
        log "Starting $MODE; SSH ports from sshd: $(echo "$SSH_PORTS" | tr '\n' ' '); SSH authentication will not be changed"
    fi
    if [[ -n ${UFW_ACTIVE:-} ]]; then
        protect_listeners
    fi
}

# Сохраняем исходные файлы; маркер позволяет повторить прерванную установку.
backup_existing_configuration() {
    local path
    stage 'Backing up configuration'
    install -d -m 700 "$ROOT" /var/lib/warp-pipe-proxy-installer
    BACKUP=/var/lib/warp-pipe-proxy-installer/$RUN
    install -d -m 700 "$BACKUP"
    local backup_paths=(
        /etc/ufw
        /etc/default/ufw
        /etc/sing-box
        /etc/unbound
        /etc/fail2ban
        "$ROOT"
        /etc/systemd/system/warp-pipe-proxy.service
        /etc/sysctl.d/90-warp-pipe-proxy.conf
        /etc/modules-load.d/warp-pipe-proxy.conf
    )
    for path in "${backup_paths[@]}"; do
        if [[ -e $path ]]; then
            cp -a --parents "$path" "$BACKUP/"
        fi
    done
    log "Backup: $BACKUP; log: $LOG"
    touch "$ROOT/managed"
}

# После установки утилит повторяем проверки firewall и занятых портов.
install_system_dependencies() {
    stage 'Installing system packages'
    apt-get update
    local packages=(curl ca-certificates openssl python3 dnsutils iproute2 unbound dns-root-data)
    if (( ! CONTAINER_MODE )); then packages+=(ufw fail2ban); fi
    apt-get install -y "${packages[@]}"
    firewall_backend_check
    protect_listeners
}

# Добавляем подписанный APT-репозиторий только при отсутствии sing-box.
install_sing_box() {
    stage 'Installing sing-box and checking its version'
    if ! command -v sing-box >/dev/null; then
        log 'Installing sing-box stable from the official APT repository'
        install -d -m 755 /etc/apt/keyrings
        curl -fsSL --retry 3 https://sing-box.app/gpg.key -o /etc/apt/keyrings/sagernet.asc
        chmod 644 /etc/apt/keyrings/sagernet.asc
        cat > /etc/apt/sources.list.d/warp-pipe-proxy-sagernet.sources <<'EOF'
Types: deb
URIs: https://deb.sagernet.org/
Suites: *
Components: *
Enabled: yes
Signed-By: /etc/apt/keyrings/sagernet.asc
EOF
        chmod 644 /etc/apt/sources.list.d/warp-pipe-proxy-sagernet.sources
        apt-get update
        apt-get install -y sing-box
    fi
    sing-box version
}

# Автоопределение выполняется только впервые; повторный запуск сохраняет ключи.
initialize_settings_and_credentials() {
    local candidates selected host key port
    stage 'Detecting IP, selecting Reality host and preparing keys'
    if [[ ! -f $ROOT/settings.json ]]; then
        log 'Detecting public IPv4 (HTTPS to api.ipify.org; fallback checkip.amazonaws.com)'
        VPS_PUBLIC_IP=${VPS_PUBLIC_IP:-$(curl -4fsS --max-time 15 https://api.ipify.org || curl -4fsS --max-time 15 https://checkip.amazonaws.com)}
        export VPS_PUBLIC_IP
        candidates=${VPS_REALITY_HOST:-'www.microsoft.com www.cloudflare.com'}
        selected=''
        for host in $candidates; do
            [[ $host =~ ^[a-zA-Z0-9.-]+$ && $host != -* ]] || { log ERROR 'Invalid Reality host'; exit 1; }
            log "Checking TLS 1.3 and HTTP/2 for Reality host: $host"
            if timeout 20 openssl s_client -connect "$host:443" -servername "$host" -verify_hostname "$host" -verify_return_error -tls1_3 -alpn h2 </dev/null > "$ROOT/tls-check.txt" 2>&1 && grep -q 'ALPN protocol: h2' "$ROOT/tls-check.txt"; then
                selected=$host
                break
            fi
        done
        [[ -n $selected ]] || { log ERROR 'No Reality candidate passed. Set VPS_REALITY_HOST and retry; see tls-check.txt'; exit 1; }
        export VPS_REALITY_HOST=$selected
    fi
    python3 "$BASE/configure.py" init
    python3 "$BASE/configure.py" summary
    log 'Settings are persistent; existing UUID and Reality keys are reused'
    for key in vless_port dns_port; do
        port=$(read_setting "$key")
        if grep -qx "$port" <<< "$SSH_PORTS"; then
            log ERROR 'A configured proxy port collides with SSH'
            exit 1
        fi
    done
}

# Генерируем конфиг во временном каталоге и проверяем до замены рабочего файла.
prepare_proxy_configuration() {
    stage 'Generating and validating proxy configuration'
    STAGE=$(mktemp -d /var/lib/warp-pipe-proxy-installer/stage.XXXXXX)
    python3 "$BASE/configure.py" render --out "$STAGE"
    sing-box check -c "$STAGE/config.json"
    sing-box check -c "$STAGE/client-sing-box.json"
    id warp-pipe-proxy >/dev/null 2>&1 || useradd --system --user-group --home-dir /var/lib/warp-pipe-proxy --create-home --shell /usr/sbin/nologin warp-pipe-proxy
    install -d -m 750 -o root -g warp-pipe-proxy /etc/sing-box
}

# Проверяем полные копии конфигураций Unbound и fail2ban, включая их include-файлы.
prepare_dns_and_ssh_protection() {
    stage 'Preparing DNSSEC trust anchor and validating configurations'
    if [[ ! -s /var/lib/unbound/root.key ]]; then
        log 'Preparing missing Unbound DNSSEC trust anchor from dns-root-data'
        if [[ ! -s /usr/share/dns/root.key ]]; then
            log ERROR 'Cannot initialize DNSSEC: /usr/share/dns/root.key is missing or empty; check dns-root-data installation' >&2
            exit 1
        fi
        install -d -m 755 -o unbound -g unbound /var/lib/unbound
        install -m 644 -o unbound -g unbound /usr/share/dns/root.key /var/lib/unbound/root.key
    else
        log 'Existing Unbound DNSSEC trust anchor preserved'
    fi
    cp -a /etc/unbound "$STAGE/unbound"
    install -m 644 "$STAGE/unbound.conf" "$STAGE/unbound/unbound.conf.d/warp-pipe-proxy.conf"
    # Перенаправляем include-пути в копию, иначе проверялся бы старый рабочий конфиг.
    python3 - "$STAGE" <<'PYTHON'
from pathlib import Path
import sys
stage = Path(sys.argv[1])
for path in (stage / 'unbound').rglob('*.conf'):
    path.write_text(path.read_text().replace('/etc/unbound/', str(stage / 'unbound') + '/'))
PYTHON
    unbound-checkconf "$STAGE/unbound/unbound.conf"
    if (( CONTAINER_MODE )); then
        log WARN 'Container mode: SSH jail configuration skipped'
        return 0
    fi
    cp -a /etc/fail2ban "$STAGE/fail2ban"
    cat > "$STAGE/fail2ban/jail.d/warp-pipe-proxy.local" <<EOF
[sshd]
enabled = true
backend = systemd
port = $(echo "$SSH_PORTS" | paste -sd, -)
maxretry = 5
findtime = 10m
bantime = 1h
EOF
    fail2ban-client -c "$STAGE/fail2ban" -t
}

# Служба работает без root и зависит от локального DNS; пока только создаём unit.
prepare_proxy_service() {
    local sing_box_binary
    stage 'Preparing warp-pipe-proxy service'
    sing_box_binary=$(command -v sing-box)
    cat > "$STAGE/warp-pipe-proxy.service" <<EOF
[Unit]
Description=Managed VLESS Reality proxy
Wants=network-online.target
After=network-online.target unbound.service
Requires=unbound.service
[Service]
User=warp-pipe-proxy
Group=warp-pipe-proxy
StateDirectory=warp-pipe-proxy
WorkingDirectory=/var/lib/warp-pipe-proxy
ExecStart=$sing_box_binary run -c /etc/sing-box/config.json
Restart=on-failure
RestartSec=5
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
LimitNOFILE=65536
[Install]
WantedBy=multi-user.target
EOF
    systemd-analyze verify "$STAGE/warp-pipe-proxy.service"
}

# Снимок отката создаём непосредственно перед заменой конфигов и перезапуском служб.
apply_validated_configuration() {
    firewall_backend_check
    protect_listeners
    begin_transaction
    stage 'Applying validated configurations'
    install -m 600 "$STAGE/settings.json" "$ROOT/settings.json"
    install -m 600 "$STAGE/credentials.json" "$ROOT/credentials.json"
    install -m 640 -o root -g warp-pipe-proxy "$STAGE/config.json" /etc/sing-box/config.json
    install -m 644 "$STAGE/unbound.conf" /etc/unbound/unbound.conf.d/warp-pipe-proxy.conf
    if (( ! CONTAINER_MODE )); then
        install -m 644 "$STAGE/fail2ban/jail.d/warp-pipe-proxy.local" /etc/fail2ban/jail.d/warp-pipe-proxy.local
    fi
    install -m 644 "$STAGE/warp-pipe-proxy.service" /etc/systemd/system/warp-pipe-proxy.service
    unbound-checkconf
    if (( ! CONTAINER_MODE )); then fail2ban-client -t; fi
    systemctl disable --now sing-box
    systemctl daemon-reload
    local dependencies=(unbound)
    if (( ! CONTAINER_MODE )); then dependencies+=(fail2ban); fi
    systemctl enable "${dependencies[@]}" warp-pipe-proxy
    systemctl restart "${dependencies[@]}"
    systemctl restart warp-pipe-proxy
    wait_services
}

# Сначала сохраняем SSH-доступ; существующие правила UFW не сбрасываем.
configure_firewall() {
    if (( CONTAINER_MODE )); then
        stage 'Skipping container firewall management'
        log WARN 'UFW is not managed in container mode; host firewall must protect published ports'
        return 0
    fi
    local port
    stage 'Configuring UFW firewall and opening ports'
    log 'Applying UFW rules without resetting existing rules'
    # Флаг устанавливаем до первой команды UFW, чтобы откат обработал и частичное применение.
    FIREWALL_CHANGED=1
    for port in $SSH_PORTS; do
        ufw allow "$port/tcp" comment 'warp-pipe-proxy SSH preservation'
    done
    log 'Removing legacy installer-managed SOCKS firewall rules'
    python3 "$BASE/configure.py" remove-legacy-socks-rules
    ufw allow "$(read_setting vless_port)/tcp" comment 'warp-pipe-proxy Reality'
    if [[ $UFW_ACTIVE == no ]]; then
        ufw default deny incoming
        ufw default allow outgoing
        ufw --force enable
    fi
}

# Сохраняем результаты только после проверок; затем отключаем откат конфигураций.
save_installation_results() {
    stage 'Saving client links and final settings'
    install -m 600 "$STAGE/clients.txt" "$ROOT/clients.txt"
    install -m 600 "$STAGE/client-sing-box.json" "$ROOT/client-sing-box.json"
    touch "$ROOT/installed"
    python3 "$BASE/configure.py" summary > "$ROOT/summary.json"
    install_cli_command
    # Все обязательные проверки завершены, последующие ошибки не откатывают рабочую установку.
    TRANSACTION=0
}

# BBR выполняется после успешной установки и не должен отменять её результат.
finish_installation() {
    stage 'Configuring TCP BBR (optional)'
    configure_bbr || log WARN 'BBR skipped after an optional optimization error'
    rm -rf -- "$STAGE"
    banner 'DONE | Installation and local checks completed'
    log SUCCESS 'SUCCESS: VLESS Reality configured'
    log "Client links (secrets): $ROOT/clients.txt; settings: $ROOT/settings.json; credentials: $ROOT/credentials.json"
    log "sing-box client profile: $ROOT/client-sing-box.json; import it on the client"
    log WARN 'For LAN access, change the client profile server address to the laptop IP and published port'
    log 'Next: export a profile with client-profile, import it into sing-box and enable VPN/TUN'
    log 'Use --endpoint LAPTOP_LAN_IP --port PUBLISHED_PORT when exporting for Podman'
    log 'Diagnostics: sudo warp-pipe-proxy status; sudo warp-pipe-proxy doctor; sudo warp-pipe-proxy logs --follow'
    log "Allow inbound TCP $(read_setting vless_port) in the provider firewall"
    if (( CONTAINER_MODE )); then
        log WARN 'CONTAINER MODE: proxy checks passed; UFW, fail2ban and BBR were not managed'
        log 'Repeat --container when running install or check in this environment'
    else
        log 'SSH filters enabled; unverified proxy fail2ban filters deliberately not installed'
    fi
    log WARN 'If ports were changed, old UFW allow rules remain; review ufw status numbered. Cloud firewall and end-to-end Reality require an external client check.'
}

# Вызываем этапы обычными командами, не в условиях if/&&: иначе Bash может отключить errexit внутри функций.
run_installation() {
    check_cli_paths
    check_installation_prerequisites
    backup_existing_configuration
    install_system_dependencies
    install_sing_box
    initialize_settings_and_credentials
    prepare_proxy_configuration
    prepare_dns_and_ssh_protection
    prepare_proxy_service
    apply_validated_configuration
    configure_firewall
    check_installation
    save_installation_results
    finish_installation
}

case "$MODE" in
    check)
        check_installation
        if [[ -n $CHECK_URL ]]; then
            python3 "$BASE/admin.py" doctor --url "$CHECK_URL"
        fi
        ;;
    install) run_installation ;;
    rotate-keys) rotate_keys ;;
esac
