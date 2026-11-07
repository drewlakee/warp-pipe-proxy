#!/usr/bin/env bash
# Проверяем терминал до перенаправления stdout в общий журнал.
LOG_COLOR_ENABLED=0
if [[ -t 1 && ${TERM:-dumb} != dumb && ! ${NO_COLOR+x} ]]; then
    LOG_COLOR_ENABLED=1
fi

# Уровень необязателен: существующие вызовы log без уровня считаются INFO.
log() {
    local level=INFO
    case ${1:-} in
        INFO|SUCCESS|WARN|ERROR)
            level=$1
            shift
            ;;
    esac
    printf '[%s] [%s] %s\n' "$(date -u +%FT%TZ)" "$level" "$*"
}

banner() {
    printf '\n%s\n' '========================================================================'
    printf '  %s\n' "$*"
    printf '  UTC: %s\n' "$(date -u +%FT%TZ)"
    printf '%s\n\n' '========================================================================'
}

# Цвет добавляется после tee: в файл журнала записывается исходный текст без наших ANSI-кодов.
# Вывод системных утилит сохраняем как есть; подсвечиваем только наши уровни и плашки.
colorize_output() {
    if (( ! LOG_COLOR_ENABLED )); then
        cat
        return
    fi
    local line color inside_banner=0 banner_color=36
    while IFS= read -r line || [[ -n $line ]]; do
        color=''
        if [[ $line == '========================================================================' ]]; then
            if (( inside_banner )); then
                color=$banner_color
                inside_banner=0
            else
                color=36
                banner_color=36
                inside_banner=1
            fi
        elif (( inside_banner )); then
            case "$line" in
                '  ERROR | '*) banner_color=31 ;;
                '  DONE | '*) banner_color=32 ;;
            esac
            color=$banner_color
        else
            case "$line" in
                '['*'] [ERROR] '*) color=31 ;;
                '['*'] [WARN] '*) color=33 ;;
                '['*'] [SUCCESS] '*) color=32 ;;
                '['*'] [INFO] '*) color=36 ;;
            esac
        fi
        if [[ -n $color ]]; then
            printf '\033[1;%sm%s\033[0m\n' "$color" "$line"
        else
            printf '%s\n' "$line"
        fi
    done
}
