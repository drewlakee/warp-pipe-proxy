#!/usr/bin/env bash
# Подключается через source: использует ROOT, BASE, BACKUP, SSH_PORTS и функцию log из установщика.
# Флаг включается только после готовности снимка; до этого откатывать нечего.
CONTAINER_MODE=${CONTAINER_MODE:-0}
TRANSACTION=0
FIREWALL_CHANGED=0
# После начала отзыва ошибки не должны возвращать скомпрометированный UUID.
REVOKE_FAIL_CLOSED=0
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
    if [[ ${MODE:-} == rotate-keys || ${MODE:-} == device-* ]]; then services_to_stop=(warp-pipe-proxy); fi
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
        if [[ $path == /etc/ufw || $path == /etc/default/ufw ]] && (( ! FIREWALL_CHANGED )); then
            continue
        fi
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
    if (( exit_status != 0 )); then
        if (( REVOKE_FAIL_CLOSED )); then
            systemctl stop warp-pipe-proxy || log ERROR 'Could not stop the proxy after an incomplete revocation; stop it manually immediately'
            systemctl disable warp-pipe-proxy || log ERROR 'Could not disable proxy autostart after an incomplete revocation'
            rm -f -- "$ROOT/credentials.json.tmp" /etc/sing-box/config.json.tmp
            if systemctl is-active --quiet warp-pipe-proxy; then
                log ERROR 'Proxy is still active; revocation is NOT guaranteed'
            fi
            log ERROR "Revocation did not finish. Old credentials were NOT restored. The proxy was requested to stop and disable; inspect $BACKUP/revocation before recovering. Do not restore the pre-revocation credentials."
        elif (( TRANSACTION )); then
            rollback
        fi
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

# Не запускаем второй firewall поверх чужой политики. Пустые таблицы с ACCEPT
# допустимы: некоторые средства просмотра создают их даже без настроенных правил.
assert_no_other_firewall() {
    local tool rules
    for tool in iptables-save ip6tables-save; do
        if ! command -v "$tool" >/dev/null; then continue; fi
        rules=$("$tool")
        if ! awk '
            /^-A / { exit 1 }
            /^:/ && $2 != "ACCEPT" { exit 1 }
        ' <<< "$rules"; then
            log ERROR "Existing $tool policy detected while UFW is inactive; refusing to enable a competing firewall"
            return 1
        fi
    done
    if command -v nft >/dev/null; then
        rules=$(nft -j list ruleset)
        if ! python3 -c '
import json, sys
entries = json.load(sys.stdin)["nftables"]
for entry in entries:
    if any(key in entry for key in ("rule", "set", "map", "flowtable")):
        sys.exit(1)
    chain = entry.get("chain")
    if chain is not None and ("hook" not in chain or chain.get("policy", "accept") != "accept"):
        sys.exit(1)
' <<< "$rules"; then
            log ERROR 'Existing or unreadable nftables policy detected while UFW is inactive; refusing to enable a competing firewall'
            return 1
        fi
    fi
}

# Читаем правила без изменения firewall и запоминаем его состояние для возможного отката.
firewall_backend_check() {
    if (( CONTAINER_MODE )); then return 0; fi
    UFW_ACTIVE=no
    local firewall_status rules
    if command -v ufw >/dev/null; then
        firewall_status=$(LC_ALL=C ufw status)
        if grep -q '^Status: active' <<< "$firewall_status"; then
            UFW_ACTIVE=yes
            return 0
        fi
        if ! grep -q '^Status: inactive' <<< "$firewall_status"; then
            log ERROR 'Cannot determine UFW state; refusing to change firewall rules'
            return 1
        fi
        rules=$(LC_ALL=C ufw show added)
        if grep -q '^ufw ' <<< "$rules"; then
            log ERROR 'UFW is disabled but has saved user rules; refusing to activate or modify an existing policy'
            return 1
        fi
    fi
    assert_no_other_firewall
}

# Default-deny может отключить чужую службу: перед включением UFW проверяем оба протокола.
# При уже активном UFW базовую политику не меняем, поэтому эта проверка не требуется.
protect_listeners() {
    if (( CONTAINER_MODE )); then return 0; fi
    [[ $UFW_ACTIVE == no ]] || return 0
    local protocol listeners listener address port allowed owner state receive send peer
    for protocol in tcp udp; do
        if [[ $protocol == tcp ]]; then
            listeners=$(ss -H -ltn)
        else
            listeners=$(ss -H -lunp)
        fi
        while IFS= read -r listener; do
            read -r state receive send address peer owner <<< "$listener"
            [[ -n $address ]] || continue
            # Loopback недоступен извне и не требует входящего правила UFW.
            case "$address" in 127.*|\[::1\]:*|::1:*) continue ;; esac
            port=${address##*:}

            allowed=no
            if [[ $protocol == tcp ]] && grep -qx "$port" <<< "$SSH_PORTS"; then
                allowed=yes
            fi
            # DHCP-клиент — часть сетевой настройки хоста, а не публичная служба.
            # Проверяем владельца сокета, чтобы не пропустить произвольный UDP/68.
            if [[ $protocol == udp && ( $port == 68 || $port == 546 ) &&
                  $owner =~ \"(systemd-networkd?|dhclient|dhcpcd|NetworkManager)\" ]]; then
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
        done <<< "$listeners"
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
        "$ROOT/ownership.json"
        "$ROOT/uninstalled.json"
        "$ROOT/revocation-pending.json"
    )
    # Откат не должен менять firewall и fail2ban, которыми этот запуск не управляет.
    if (( ! CONTAINER_MODE )); then
        managed_paths+=(/etc/fail2ban/jail.d/warp-pipe-proxy.local)
        if [[ ${UFW_ACTIVE:-} == no ]]; then managed_paths+=(/etc/ufw /etc/default/ufw); fi
    fi
    if [[ ${MODE:-} == rotate-keys || ${MODE:-} == device-* ]]; then
        managed_paths=(/etc/sing-box/config.json "$ROOT/credentials.json" "$ROOT/clients.txt" "$ROOT/client-sing-box.json" "$ROOT/ownership.json" "$ROOT/revocation-pending.json")
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
    if [[ ${MODE:-} == rotate-keys || ${MODE:-} == device-* ]]; then managed_services=(warp-pipe-proxy); fi
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
    for file in warp-pipe-proxy.sh runtime.sh logging.sh configure.py probe.py admin.py activity.py lifecycle.py; do
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


save_default_exports() {
    local name
    for name in clients.txt client-sing-box.json; do
        if [[ -f $STAGE/$name ]]; then
            install -m 600 "$STAGE/$name" "$ROOT/$name"
        else
            rm -f -- "$ROOT/$name"
        fi
    done
}

update_credentials() {
    stage "Preparing credential change: $MODE"
    if [[ -e $ROOT/revocation-pending.json || -L $ROOT/revocation-pending.json ]]; then
        log ERROR 'An earlier revocation is incomplete; recover its validated credentials and rerun install before changing devices'
        return 1
    fi
    [[ -f $ROOT/installed && -f $ROOT/settings.json && -f $ROOT/credentials.json ]] || {
        log ERROR 'An existing managed installation is required'
        return 1
    }
    # Отзыв разрешён и при остановленном прокси или повреждённом рабочем конфиге:
    # источником истины служат credentials, а новый конфиг проверяется ниже.
    if [[ $MODE != device-revoke ]]; then
        systemctl is-active --quiet warp-pipe-proxy
        sing-box check -c /etc/sing-box/config.json
    fi
    install -d -m 700 /var/lib/warp-pipe-proxy-installer
    BACKUP=/var/lib/warp-pipe-proxy-installer/$RUN
    install -d -m 700 "$BACKUP"
    STAGE=$(mktemp -d /var/lib/warp-pipe-proxy-installer/rotate.XXXXXX)
    local action=$MODE
    if [[ $MODE == rotate-keys ]]; then action=render-rotated; fi
    python3 "$BASE/configure.py" "$action" --root "$ROOT" --out "$STAGE" --device "${DEVICE:-}"
    sing-box check -c "$STAGE/config.json"
    if [[ -f $STAGE/client-sing-box.json ]]; then sing-box check -c "$STAGE/client-sing-box.json"; fi
    begin_transaction
    stage "Applying credential change: $MODE"
    if [[ $MODE == device-revoke ]]; then
        apply_revocation
        return
    fi
    install -m 600 "$STAGE/credentials.json" "$ROOT/credentials.json"
    install -m 640 -o root -g warp-pipe-proxy "$STAGE/config.json" /etc/sing-box/config.json
    systemctl restart warp-pipe-proxy
    stage 'Verifying authenticated VLESS traffic'
    python3 "$BASE/probe.py"
    systemctl is-active --quiet warp-pipe-proxy
    save_default_exports
    python3 "$BASE/lifecycle.py" record-config
    TRANSACTION=0
    log SUCCESS "Credential change completed: $MODE"
    if [[ $MODE == rotate-keys ]]; then log 'Export and import new profiles on every active device'; fi
    log "Previous credentials are retained in the root-only backup: $BACKUP"
}


# Отзыв фиксируется по локальному состоянию. Внешняя проверка не может вернуть
# удалённый доступ. При сбое записи/запуска EXIT оставляет прокси выключенным.
apply_revocation() {
    local was_active=0 was_enabled
    if systemctl is-active --quiet warp-pipe-proxy; then was_active=1; fi
    was_enabled=$(systemctl is-enabled warp-pipe-proxy 2>/dev/null || true)
    # Сохраняем проверенный результат отдельно от старого снимка: даже при
    # частичной записи файлов администратор может завершить отзыв без старых UUID.
    cp -a "$STAGE" "$BACKUP/revocation"
    REVOKE_FAIL_CLOSED=1
    TRANSACTION=0
    python3 "$BASE/lifecycle.py" prepare-revoke --run "$RUN"
    systemctl stop warp-pipe-proxy
    systemctl disable warp-pipe-proxy
    # credentials — источник истины для восстановления. Атомарная замена
    # исключает повреждение файла при неполной записи; конфиг меняется вторым.
    install -m 600 "$STAGE/credentials.json" "$ROOT/credentials.json.tmp"
    mv -f -- "$ROOT/credentials.json.tmp" "$ROOT/credentials.json"
    install -m 640 -o root -g warp-pipe-proxy "$STAGE/config.json" /etc/sing-box/config.json.tmp
    mv -f -- /etc/sing-box/config.json.tmp /etc/sing-box/config.json
    save_default_exports
    if (( was_active )); then
        systemctl restart warp-pipe-proxy
        systemctl is-active --quiet warp-pipe-proxy
    fi
    case "$was_enabled" in
        enabled) systemctl enable warp-pipe-proxy ;;
        enabled-runtime) systemctl enable --runtime warp-pipe-proxy ;;
    esac
    python3 "$BASE/lifecycle.py" record-config
    REVOKE_FAIL_CLOSED=0
    log SUCCESS "Credential change completed: $MODE"
    log "Validated revoked configuration retained in the root-only backup: $BACKUP/revocation"
    if (( ! was_active )); then
        log 'Proxy was inactive and remains stopped; external connectivity was not tested'
        return 0
    fi
    stage 'Checking connectivity after committed revocation (diagnostic only)'
    if ! python3 "$BASE/probe.py"; then
        log WARN 'Device remains revoked. External connectivity check failed; inspect services and run doctor. No credentials were rolled back.'
    fi
}
