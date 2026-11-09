#!/usr/bin/env bash
# Подключается через source: использует ROOT, BASE, BACKUP, SSH_PORTS и функцию log из установщика.
# Флаг включается только после готовности снимка; до этого откатывать нечего.
CONTAINER_MODE=${CONTAINER_MODE:-0}
TRANSACTION=0
FIREWALL_CHANGED=0
# Путь к временным конфигам; EXIT удаляет каталог и при успехе, и при ошибке.
STAGE=''
# Восстановление выполняется без errexit: ошибка одного действия не должна помешать остальным.
rollback() {
    local rollback_failed=0 path service state
    log WARN 'Rolling back managed configuration and service states'
    # Останавливаем потребителей конфигурации перед восстановлением файлов.
    local services_to_stop=(warp-pipe-proxy)
    if (( ! CONTAINER_MODE )); then services_to_stop+=(fail2ban); fi
    services_to_stop+=(unbound)
    if [[ ${MODE:-} == rotate-keys ]]; then services_to_stop=(warp-pipe-proxy); fi
    for service in "${services_to_stop[@]}"; do
        systemctl stop "$service" || rollback_failed=1
    done
    # Убираем созданный автозапуск до удаления нового unit-файла.
    while read -r service state; do
        if [[ $state == not-found || $state == disabled ]]; then
            systemctl disable "$service" || rollback_failed=1
        fi
    done < "$BACKUP/enabled"
    # В списке есть и ранее отсутствовавшие пути: новые файлы удаляются, прежние возвращаются из снимка.
    while IFS= read -r path; do
        rm -rf -- "$path" || rollback_failed=1
        if [[ -e $BACKUP/transaction$path ]]; then
            cp -a "$BACKUP/transaction$path" "$path" || rollback_failed=1
        fi
    done < "$BACKUP/paths"
    systemctl daemon-reload || rollback_failed=1
    if (( FIREWALL_CHANGED )); then
        # Восстановленные файлы нужно применить к работающему firewall.
        if [[ $UFW_ACTIVE == yes ]]; then
            ufw reload || rollback_failed=1
        else
            ufw --force disable || rollback_failed=1
        fi
    fi
    while read -r service state; do
        case "$state" in
            enabled) systemctl enable "$service" || rollback_failed=1 ;;
            enabled-runtime) systemctl enable --runtime "$service" || rollback_failed=1 ;;
            disabled) systemctl disable "$service" || rollback_failed=1 ;;
        esac
    done < "$BACKUP/enabled"
    while read -r service state; do
        if [[ $state == active ]]; then
            systemctl restart "$service" || rollback_failed=1
        elif systemctl cat "$service" >/dev/null 2>&1; then
            systemctl stop "$service" || rollback_failed=1
        fi
    done < "$BACKUP/active"
    if (( rollback_failed )); then
        log ERROR "ROLLBACK INCOMPLETE: inspect services and backup $BACKUP"
    else
        log SUCCESS 'Managed configuration and service states restored'
    fi
}

# Сохраняем исходный код выхода: ошибки уборки не должны скрывать причину сбоя установки.
finish() {
    local exit_status=$?
    # Отключаем обработчики, чтобы ошибка самого отката не вызвала его повторно.
    trap - EXIT ERR INT TERM
    set +e
    if (( exit_status != 0 && TRANSACTION )); then
        rollback
    fi
    if [[ -n $STAGE && -d $STAGE ]]; then
        rm -rf -- "$STAGE"
    fi
    exit "$exit_status"
}

# INT и TERM завершают скрипт через EXIT; там находится общая логика восстановления.
trap finish EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
# Root внутри контейнера может не иметь прав на сеть, поэтому проверяем capability и sysctl отдельно.
firewall_preflight() {
    if (( CONTAINER_MODE )); then return 0; fi
    local effective_capabilities
    local net_admin_mask=4096
    effective_capabilities=$(awk '/^CapEff:/ {print $2}' /proc/self/status)
    if [[ -z $effective_capabilities ]] || (( (16#$effective_capabilities & net_admin_mask) == 0 )); then
        log ERROR 'NET_ADMIN is required for UFW. Container root is insufficient. No service configuration has been changed.'
        return 1
    fi
    if [[ ! -w /proc/sys/net/ipv4/conf/all/accept_redirects ]]; then
        log ERROR 'Network sysctl is read-only; UFW cannot apply its settings. Configure container permissions before retrying.'
        return 1
    fi
}

# Читаем правила без изменения firewall и запоминаем его состояние для возможного отката.
firewall_backend_check() {
    if (( CONTAINER_MODE )); then return 0; fi
    iptables -w 5 -S >/dev/null
    if [[ -e /proc/net/if_inet6 ]] && grep -q '^IPV6=yes' /etc/default/ufw; then
        ip6tables -w 5 -S >/dev/null
    fi
    UFW_ACTIVE=no
    local firewall_status
    firewall_status=$(LC_ALL=C ufw status)
    if grep -q '^Status: active' <<< "$firewall_status"; then
        UFW_ACTIVE=yes
    fi
}

# Default-deny может отключить чужую службу: перед включением UFW проверяем оба протокола.
# При уже активном UFW базовую политику не меняем, поэтому эта проверка не требуется.
protect_listeners() {
    if (( CONTAINER_MODE )); then return 0; fi
    [[ $UFW_ACTIVE == no ]] || return 0
    local protocol listeners address port allowed
    for protocol in tcp udp; do
        if [[ $protocol == tcp ]]; then
            listeners=$(ss -H -ltn)
        else
            listeners=$(ss -H -lun)
        fi
        while read -r address; do
            [[ -n $address ]] || continue
            # Loopback недоступен извне и не требует входящего правила UFW.
            case "$address" in 127.*|\[::1\]:*|::1:*) continue ;; esac
            port=${address##*:}

            allowed=no
            if [[ $protocol == tcp ]] && grep -qx "$port" <<< "$SSH_PORTS"; then
                allowed=yes
            fi
            if [[ $protocol == tcp && -f $ROOT/managed && -f /etc/sing-box/config.json ]]; then
                # Одного номера порта недостаточно: проверяем PID текущей управляемой службы.
                if python3 "$BASE/probe.py" owns-port "$port"; then
                    allowed=yes
                fi
            fi
            if [[ $allowed == no ]]; then
                log ERROR "Unmanaged $protocol listener $address: refusing to enable default-deny UFW"
                return 1
            fi
        done < <(awk '{print $4}' <<< "$listeners")
    done
}

# Фиксируем файлы, активность и автозапуск служб непосредственно перед применением изменений.
begin_transaction() {
    local path service state
    mkdir -p "$BACKUP/transaction"
    : > "$BACKUP/paths"
    local managed_paths=(
        /usr/local/bin/warp-pipe-proxy
        /usr/local/lib/warp-pipe-proxy
        /etc/sing-box/config.json
        /etc/unbound/unbound.conf.d/warp-pipe-proxy.conf
        /etc/systemd/system/warp-pipe-proxy.service
        "$ROOT/settings.json"
        "$ROOT/credentials.json"
        "$ROOT/clients.txt"
        "$ROOT/client-sing-box.json"
        "$ROOT/summary.json"
        "$ROOT/installed"
    )
    # Откат не должен менять firewall и fail2ban, которыми этот запуск не управляет.
    if (( ! CONTAINER_MODE )); then
        managed_paths+=(/etc/fail2ban/jail.d/warp-pipe-proxy.local /etc/ufw /etc/default/ufw)
    fi
    if [[ ${MODE:-} == rotate-keys ]]; then
        managed_paths=(/etc/sing-box/config.json "$ROOT/credentials.json" "$ROOT/clients.txt" "$ROOT/client-sing-box.json")
    fi
    for path in "${managed_paths[@]}"; do
        printf '%s\n' "$path" >> "$BACKUP/paths"
        if [[ -e $path ]]; then
            cp -a --parents "$path" "$BACKUP/transaction/"
        fi
    done
    : > "$BACKUP/active"
    : > "$BACKUP/enabled"
    local managed_services=(unbound)
    if (( ! CONTAINER_MODE )); then managed_services+=(fail2ban); fi
    managed_services+=(sing-box warp-pipe-proxy)
    if [[ ${MODE:-} == rotate-keys ]]; then managed_services=(warp-pipe-proxy); fi
    for service in "${managed_services[@]}"; do
        # Неактивная или отсутствующая служба — допустимое исходное состояние, а не ошибка снимка.
        state=$(systemctl is-active "$service" || true)
        printf '%s %s\n' "$service" "$state" >> "$BACKUP/active"
        state=$(systemctl is-enabled "$service" 2>/dev/null || true)
        printf '%s %s\n' "$service" "${state:-not-found}" >> "$BACKUP/enabled"
    done
    # Включаем откат только после успешной записи всего снимка.
    TRANSACTION=1
}

# systemctl is-active с несколькими именами проверяет «хотя бы одну»; здесь ждём каждую отдельно.
wait_services() {
    local service attempt
    local required_services=(warp-pipe-proxy unbound)
    if (( ! CONTAINER_MODE )); then required_services+=(fail2ban); fi
    for service in "${required_services[@]}"; do
        for attempt in {1..10}; do
            if systemctl is-active --quiet "$service"; then
                break
            fi
            sleep 1
        done
        if ! systemctl is-active --quiet "$service"; then
            log ERROR "Service $service is not active after $attempt attempts"
            return 1
        fi
    done
}

# Подоболочка изолирует set +e и trap: необязательная оптимизация не меняет обработку ошибок установщика.
configure_bbr() (
    set +e
    trap - ERR EXIT INT TERM
    local previous_qdisc previous_congestion_control path
    if (( CONTAINER_MODE )) || systemd-detect-virt --container --quiet; then
        log WARN 'BBR skipped inside container; kernel tuning belongs to the host'
        exit 0
    fi
    previous_qdisc=$(sysctl -n net.core.default_qdisc) || exit 0
    previous_congestion_control=$(sysctl -n net.ipv4.tcp_congestion_control) || exit 0
    if ! grep -qw bbr /proc/sys/net/ipv4/tcp_available_congestion_control; then
        if ! command -v modprobe >/dev/null || ! modprobe tcp_bbr; then
            log WARN 'BBR unavailable; optional optimization skipped'
            exit 0
        fi
    fi
    # Сначала применяем параметры, затем сохраняем их для следующей загрузки.
    if sysctl -w net.core.default_qdisc=fq && sysctl -w net.ipv4.tcp_congestion_control=bbr; then
        if printf 'tcp_bbr\n' > /etc/modules-load.d/warp-pipe-proxy.conf &&
           printf 'net.core.default_qdisc=fq\nnet.ipv4.tcp_congestion_control=bbr\n' > /etc/sysctl.d/90-warp-pipe-proxy.conf; then
            log SUCCESS 'BBR enabled for new TCP connections'
            exit 0
        fi
    fi
    # При частичном сбое возвращаем прежние значения и файлы; проблемы восстановления видны в логе.
    sysctl -w "net.core.default_qdisc=$previous_qdisc" || log WARN 'WARNING: failed to restore qdisc'
    sysctl -w "net.ipv4.tcp_congestion_control=$previous_congestion_control" || log WARN 'WARNING: failed to restore TCP algorithm'
    for path in /etc/modules-load.d/warp-pipe-proxy.conf /etc/sysctl.d/90-warp-pipe-proxy.conf; do
        if [[ -e $BACKUP$path ]]; then
            cp -a "$BACKUP$path" "$path"
        else
            rm -f "$path"
        fi
    done
    log WARN 'BBR could not be configured; installation remains successful'
    exit 0
)

# Не перезаписываем чужую команду или каталог с совпавшим именем.
check_cli_paths() {
    local command_path=/usr/local/bin/warp-pipe-proxy bundle=/usr/local/lib/warp-pipe-proxy
    if [[ -L $command_path ]] || { [[ -e $command_path ]] && ! grep -qx '# Warp Pipe Proxy managed launcher' "$command_path"; }; then
        log ERROR "Refusing to overwrite unmanaged command: $command_path"
        return 1
    fi
    if [[ -L $bundle ]] || { [[ -e $bundle ]] && [[ ! -f $bundle/.managed ]]; }; then
        log ERROR "Refusing to overwrite unmanaged directory: $bundle"
        return 1
    fi
}

# Копия скриптов не зависит от исходной папки. Сначала готовим её целиком,
# поэтому повторная установка через установленную команду не копирует файл сам в себя.
install_cli_command() {
    local file bundle=/usr/local/lib/warp-pipe-proxy
    check_cli_paths
    install -d -m 755 "$STAGE/cli"
    for file in warp-pipe-proxy.sh runtime.sh logging.sh configure.py probe.py admin.py; do
        install -m 644 "$BASE/$file" "$STAGE/cli/$file"
    done
    install -d -m 755 /usr/local/bin "$bundle"
    for file in "$STAGE/cli/"*; do
        install -m 644 "$file" "$bundle/${file##*/}"
    done
    touch "$bundle/.managed"
    chmod 644 "$bundle/.managed"
    cat > "$STAGE/warp-pipe-proxy" <<'LAUNCHER'
#!/bin/sh
# Warp Pipe Proxy managed launcher
exec /bin/bash /usr/local/lib/warp-pipe-proxy/warp-pipe-proxy.sh "$@"
LAUNCHER
    install -m 755 "$STAGE/warp-pipe-proxy" /usr/local/bin/warp-pipe-proxy
    log SUCCESS 'Installed command: /usr/local/bin/warp-pipe-proxy'
}


rotate_keys() {
    stage 'Preparing VLESS credential rotation'
    [[ -f $ROOT/installed && -f $ROOT/settings.json && -f $ROOT/credentials.json ]] || {
        log ERROR 'An existing managed installation is required'
        return 1
    }
    systemctl is-active --quiet warp-pipe-proxy
    sing-box check -c /etc/sing-box/config.json
    install -d -m 700 /var/lib/warp-pipe-proxy-installer
    BACKUP=/var/lib/warp-pipe-proxy-installer/$RUN
    install -d -m 700 "$BACKUP"
    STAGE=$(mktemp -d /var/lib/warp-pipe-proxy-installer/rotate.XXXXXX)
    python3 "$BASE/configure.py" render-rotated --root "$ROOT" --out "$STAGE"
    sing-box check -c "$STAGE/config.json"
    sing-box check -c "$STAGE/client-sing-box.json"
    begin_transaction
    stage 'Applying new VLESS credentials'
    log WARN 'Existing client profiles will stop working after rotation'
    install -m 600 "$STAGE/credentials.json" "$ROOT/credentials.json"
    install -m 640 -o root -g warp-pipe-proxy "$STAGE/config.json" /etc/sing-box/config.json
    systemctl restart warp-pipe-proxy
    stage 'Verifying authenticated VLESS traffic'
    python3 "$BASE/probe.py"
    systemctl is-active --quiet warp-pipe-proxy
    install -m 600 "$STAGE/clients.txt" "$ROOT/clients.txt"
    install -m 600 "$STAGE/client-sing-box.json" "$ROOT/client-sing-box.json"
    TRANSACTION=0
    log SUCCESS 'VLESS UUID, Reality key pair and short ID rotated'
    log "Import the updated profile on every client: $ROOT/client-sing-box.json"
    log "Previous credentials are retained in the root-only backup: $BACKUP"
}
