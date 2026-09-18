#!/usr/bin/env bash
# ==============================================================================
# Elise 高性能节点后端管理脚本 (支持完整的命令行体系与交互菜单)
# ==============================================================================

set -u

SCRIPT_VERSION="v1.0.0"
ELISE_DIR="/usr/local/elise"
ELISE_BIN="$ELISE_DIR/elise"

# 兼容寻找核心二进制
if [[ ! -x "$ELISE_BIN" ]]; then
    if [[ -x "/usr/local/bin/elise-core" ]]; then
        ELISE_BIN="/usr/local/bin/elise-core"
    elif [[ -x "/usr/local/bin/elise" && "$(realpath /usr/local/bin/elise 2>/dev/null)" != "$(realpath "${BASH_SOURCE[0]}" 2>/dev/null)" ]]; then
        ELISE_BIN="/usr/local/bin/elise"
    fi
fi

CONF_DIR="/etc/elise"
MAIN_CONF="$CONF_DIR/elise.conf"
SYSTEMD_SERVICE="elise.service"
GITHUB_REPO="Grandova/Elise-Backend"

RED="\033[31m"
GREEN="\033[32m"
YELLOW="\033[33m"
BLUE="\033[36m"
BOLD="\033[1m"
RESET="\033[0m"

# 检测服务管理器
detect_service_manager() {
    if command -v systemctl >/dev/null 2>&1 && [[ -d /run/systemd/system ]]; then
        echo "systemd"
    elif command -v rc-service >/dev/null 2>&1; then
        echo "openrc"
    else
        echo "unknown"
    fi
}
SM=$(detect_service_manager)

check_root() {
    if [[ "$(id -u)" -ne 0 ]]; then
        echo -e "${RED}错误: 请以 root 用户运行此管理脚本 (sudo elise ...)${RESET}" >&2
        exit 1
    fi
}

pause() {
    echo ""
    read -rp "按回车键继续..."
}

# ------------------------------------------------------------------------------
# 键值配置工具函数
# ------------------------------------------------------------------------------
set_conf_kv() {
    local file="$1" key="$2" val="$3"
    mkdir -p "$(dirname "$file")"
    if [[ ! -f "$file" ]]; then touch "$file"; fi
    if grep -qE "^[#[:space:]]*${key}=" "$file"; then
        sed -i -E "s|^[#[:space:]]*${key}=.*|${key}=${val}|" "$file"
    else
        echo "${key}=${val}" >> "$file"
    fi
}

get_conf_kv() {
    local file="$1" key="$2"
    [[ -f "$file" ]] || return 1
    grep -E "^[#[:space:]]*${key}=" "$file" | tail -n 1 | cut -d= -f2-
}

# ------------------------------------------------------------------------------
# 状态查询函数
# ------------------------------------------------------------------------------
get_status_str() {
    local svc="${1:-$SYSTEMD_SERVICE}"
    if [[ "$SM" == "systemd" ]]; then
        if systemctl is-active --quiet "$svc" 2>/dev/null; then
            local pid
            pid=$(systemctl show --property=MainPID --value "$svc" 2>/dev/null)
            if [[ -n "$pid" && "$pid" -gt 0 ]]; then
                echo -e "${GREEN}运行中 (PID: $pid)${RESET}"
            else
                echo -e "${GREEN}运行中${RESET}"
            fi
        else
            echo -e "${RED}未运行${RESET}"
        fi
    elif [[ "$SM" == "openrc" ]]; then
        if rc-service elise status >/dev/null 2>&1; then
            echo -e "${GREEN}运行中${RESET}"
        else
            echo -e "${RED}未运行${RESET}"
        fi
    else
        if pgrep -x "elise" >/dev/null 2>&1; then
            echo -e "${GREEN}运行中 (手动进程)${RESET}"
        else
            echo -e "${RED}未运行${RESET}"
        fi
    fi
}

get_enabled_str() {
    local svc="${1:-$SYSTEMD_SERVICE}"
    if [[ "$SM" == "systemd" ]]; then
        if systemctl is-enabled --quiet "$svc" 2>/dev/null; then
            echo -e "${GREEN}已启用${RESET}"
        else
            echo -e "${YELLOW}已禁用${RESET}"
        fi
    elif [[ "$SM" == "openrc" ]]; then
        if rc-status default 2>/dev/null | grep -q "elise"; then
            echo -e "${GREEN}已启用${RESET}"
        else
            echo -e "${YELLOW}已禁用${RESET}"
        fi
    else
        echo -e "${YELLOW}未知/未配置${RESET}"
    fi
}

# ------------------------------------------------------------------------------
# 基础服务操作命令
# ------------------------------------------------------------------------------
cmd_start() {
    local svc="${1:-$SYSTEMD_SERVICE}"
    check_root
    echo -e "${BLUE}正在启动 $svc ...${RESET}"
    if [[ "$SM" == "systemd" ]]; then
        systemctl start "$svc"
        sleep 1
        if systemctl is-active --quiet "$svc"; then
            echo -e "${GREEN}$svc 启动成功！${RESET}"
        else
            echo -e "${RED}$svc 启动失败，请检查配置与日志：${RESET}"
            systemctl status "$svc" --no-pager
            return 1
        fi
    elif [[ "$SM" == "openrc" ]]; then
        rc-service elise start
    else
        nohup "$ELISE_BIN" run -c "$MAIN_CONF" >/dev/null 2>&1 &
        echo -e "${GREEN}已在后台启动！${RESET}"
    fi
}

cmd_stop() {
    local svc="${1:-$SYSTEMD_SERVICE}"
    check_root
    echo -e "${BLUE}正在停止 $svc ...${RESET}"
    if [[ "$SM" == "systemd" ]]; then
        systemctl stop "$svc"
    elif [[ "$SM" == "openrc" ]]; then
        rc-service elise stop
    else
        pkill -x elise || true
    fi
    echo -e "${GREEN}$svc 已停止。${RESET}"
}

cmd_restart() {
    local svc="${1:-$SYSTEMD_SERVICE}"
    check_root
    echo -e "${BLUE}正在重启 $svc ...${RESET}"
    if [[ "$SM" == "systemd" ]]; then
        systemctl restart "$svc"
        sleep 1
        if systemctl is-active --quiet "$svc"; then
            echo -e "${GREEN}$svc 重启成功！${RESET}"
        else
            echo -e "${RED}$svc 重启失败，错误详情：${RESET}"
            systemctl status "$svc" --no-pager
            return 1
        fi
    elif [[ "$SM" == "openrc" ]]; then
        rc-service elise restart
    else
        pkill -x elise || true
        nohup "$ELISE_BIN" run -c "$MAIN_CONF" >/dev/null 2>&1 &
        echo -e "${GREEN}已重启！${RESET}"
    fi
}

cmd_status() {
    local svc="${1:-$SYSTEMD_SERVICE}"
    echo -e "${BLUE}=== $svc 运行状态 ===${RESET}"
    if [[ "$SM" == "systemd" ]]; then
        systemctl status "$svc" --no-pager -l
    elif [[ "$SM" == "openrc" ]]; then
        rc-service elise status
    else
        ps aux | grep -E "elise" | grep -v grep
    fi
    echo ""
    echo -e "${BLUE}=== 监听端口状态 ===${RESET}"
    if command -v ss >/dev/null 2>&1; then
        ss -tulpn | grep -E "elise" || echo "暂无 elise 端口监听"
    elif command -v netstat >/dev/null 2>&1; then
        netstat -tulpn | grep -E "elise" || echo "暂无 elise 端口监听"
    fi
}

cmd_log() {
    local svc="$SYSTEMD_SERVICE"
    local follow=false
    local lines=50
    
    while [[ $# -gt 0 ]]; do
        case "$1" in
            -f|--follow) follow=true; shift ;;
            -n|--lines) lines="$2"; shift 2 ;;
            elise@*|*.service) svc="$1"; shift ;;
            *) shift ;;
        esac
    done
    
    if [[ "$SM" == "systemd" ]]; then
        if $follow; then
            journalctl -u "$svc" -f -o cat
        else
            journalctl -u "$svc" -n "$lines" --no-pager
        fi
    else
        tail -n "$lines" /var/log/elise.log 2>/dev/null || echo "未找到 /var/log/elise.log"
    fi
}

cmd_enable() {
    local svc="${1:-$SYSTEMD_SERVICE}"
    check_root
    if [[ "$SM" == "systemd" ]]; then
        systemctl enable "$svc"
        echo -e "${GREEN}已成功设置 $svc 开机自启！${RESET}"
    elif [[ "$SM" == "openrc" ]]; then
        rc-update add elise default
        echo -e "${GREEN}已添加至 default runlevel！${RESET}"
    fi
}

cmd_disable() {
    local svc="${1:-$SYSTEMD_SERVICE}"
    check_root
    if [[ "$SM" == "systemd" ]]; then
        systemctl disable "$svc"
        echo -e "${YELLOW}已取消 $svc 开机自启。${RESET}"
    elif [[ "$SM" == "openrc" ]]; then
        rc-update del elise default
        echo -e "${YELLOW}已从 default runlevel 移除。${RESET}"
    fi
}

cmd_version() {
    echo -e "${BOLD}========================================${RESET}"
    echo -e "${BOLD}           Elise 版本与系统环境          ${RESET}"
    echo -e "${BOLD}========================================${RESET}"
    if [[ -x "$ELISE_BIN" ]]; then
        "$ELISE_BIN" --version 2>/dev/null || echo "Elise Core: 可用"
    else
        echo "Elise Core: 未安装或无执行权限"
    fi
    echo "管理脚本版本: $SCRIPT_VERSION"
    echo "----------------------------------------"
    echo "操作系统: $(uname -s) $(uname -r) ($(uname -m))"
    echo "拥塞控制: $(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null || echo '未知')"
    echo "排队算法: $(sysctl -n net.core.default_qdisc 2>/dev/null || echo '未知')"
}

# ------------------------------------------------------------------------------
# 配置与节点操作命令
# ------------------------------------------------------------------------------
cmd_config() {
    local conf_file="$1"; shift
    if [[ $# -eq 0 ]]; then
        if [[ ! -f "$conf_file" ]]; then
            echo -e "${RED}未找到配置文件: $conf_file${RESET}" >&2
            return 1
        fi
        echo -e "${BLUE}# 配置文件内容: $conf_file${RESET}"
        cat "$conf_file"
        return 0
    fi
    
    check_root
    local updated=0
    for kv in "$@"; do
        if [[ "$kv" == *"="* ]]; then
            local key="${kv%%=*}"
            local val="${kv#*=}"
            set_conf_kv "$conf_file" "$key" "$val"
            echo -e "已设置: ${GREEN}$key${RESET} = ${BLUE}$val${RESET}"
            updated=1
        else
            echo -e "${YELLOW}跳过非 k=v 格式参数: $kv${RESET}"
        fi
    done
    if [[ $updated -eq 1 ]]; then
        echo -e "${GREEN}配置已保存至 $conf_file。请执行 'elise restart' 使配置生效。${RESET}"
    fi
}

cmd_modify() {
    local conf_file="$1"
    check_root
    if [[ ! -f "$conf_file" ]]; then
        echo -e "${RED}未找到配置文件: $conf_file${RESET}" >&2
        return 1
    fi
    local editor="vim"
    if command -v vim >/dev/null 2>&1; then
        editor="vim"
    elif command -v vi >/dev/null 2>&1; then
        editor="vi"
    elif command -v nano >/dev/null 2>&1; then
        editor="nano"
    fi
    echo -e "${BLUE}正在使用 $editor 打开 $conf_file ...${RESET}"
    $editor "$conf_file"
    read -rp "是否立即重启 Elise 使新配置生效? [Y/n]: " ans
    case "$ans" in
        [nN]*) ;;
        *) cmd_restart ;;
    esac
}

cmd_setup() {
    local conf_file="$1"
    check_root
    echo -e "${BOLD}========================================${RESET}"
    echo -e "${BOLD}           Elise 节点配置向导            ${RESET}"
    echo -e "${BOLD}========================================${RESET}"
    
    local p_type p_url p_key p_id p_listen
    echo "1. 请选择对接面板类型："
    echo "   1) XBoard"
    echo "   2) V2Board"
    echo "   3) PPanel"
    echo "   4) SSPanel"
    read -rp "请选择 [1-4，默认 1]: " t_opt
    case "$t_opt" in
        2) p_type="v2board" ;;
        3) p_type="ppanel" ;;
        4) p_type="sspanel" ;;
        *) p_type="xboard" ;;
    esac
    
    read -rp "2. 请输入面板地址 (如 https://panel.example.com): " p_url
    p_url="${p_url%/}"
    read -rp "3. 请输入通信密钥 (panel_key / token): " p_key
    read -rp "4. 请输入节点 ID (node_id，多节点用逗号分隔): " p_id
    read -rp "5. 请输入监听地址 [默认 0.0.0.0]: " p_listen
    p_listen="${p_listen:-0.0.0.0}"
    
    if [[ -z "$p_url" || -z "$p_key" || -z "$p_id" ]]; then
        echo -e "${RED}错误: 面板地址、通信密钥和节点 ID 为必填项！配置中止。${RESET}"
        return 1
    fi
    
    mkdir -p "$(dirname "$conf_file")"
    if [[ -f "$conf_file" ]]; then
        cp -p "$conf_file" "$conf_file.bak.$(date +%s)"
    fi
    
    cat <<EOF > "$conf_file"
# Elise 原生高性能服务端配置文件
type=$p_type
panel_url=$p_url
panel_key=$p_key
node_id=$p_id

check_interval=60
submit_interval=60

listen=$p_listen
multi_node_listen_strategy=auto

auto_tls=true
fake_sni=localhost

proxy_protocol=off
force_proxy_protocol=false

routes_file=/etc/elise/routes.toml
block_list_file=/etc/elise/blockList
white_list_file=/etc/elise/whiteList

dns_strategy=prefer_ipv4
auto_out_ip=false
out_ip_ipv4=
out_ip_ipv6=

device_limit_window=300
device_limit_prefix_ipv4=32
device_limit_prefix_ipv6=64

domain_sniff=true
sniff_redirect=false
forbidden_bit_torrent=true
forbidden_ports=
ban_private_ip=false

submit_traffic_min_traffic=0
submit_alive_ip_min_traffic=0

log_level=info
log_file=
audit_log_file=
EOF
    echo -e "${GREEN}配置文件已生成并写入: $conf_file${RESET}"
    read -rp "是否立即重启 Elise 使配置生效? [Y/n]: " ans
    case "$ans" in
        [nN]*) ;;
        *) cmd_restart ;;
    esac
}

cmd_node() {
    local conf_file="$1"; shift
    local action="${1:-list}"
    local target_id="${2:-}"
    
    local current_nodes
    current_nodes=$(get_conf_kv "$conf_file" "node_id" || echo "")
    
    case "$action" in
        list)
            echo -e "${BLUE}=== 配置文件中的节点列表 ($conf_file) ===${RESET}"
            if [[ -z "$current_nodes" ]]; then
                echo "暂未配置任何 node_id"
            else
                IFS=',' read -ra ADDR <<< "$current_nodes"
                local idx=1
                for i in "${ADDR[@]}"; do
                    local clean_id
                    clean_id=$(echo "$i" | xargs)
                    echo -e "  $idx. 节点 ID: ${GREEN}$clean_id${RESET}"
                    ((idx++))
                done
            fi
            ;;
        add)
            check_root
            if [[ -z "$target_id" ]]; then
                echo -e "${RED}用法: elise node add <ID>${RESET}" >&2
                return 1
            fi
            if [[ -z "$current_nodes" ]]; then
                set_conf_kv "$conf_file" "node_id" "$target_id"
            else
                # 检查是否已存在
                if [[ ",$current_nodes," == *",$target_id,"* ]]; then
                    echo -e "${YELLOW}节点 ID $target_id 已存在于配置中，无需重复添加。${RESET}"
                    return 0
                fi
                set_conf_kv "$conf_file" "node_id" "${current_nodes},${target_id}"
            fi
            echo -e "${GREEN}成功添加节点 ID: $target_id${RESET}"
            echo -e "当前节点列表: $(get_conf_kv "$conf_file" "node_id")"
            echo -e "请运行 'elise restart' 使配置生效。"
            ;;
        del|delete|rm)
            check_root
            if [[ -z "$target_id" ]]; then
                echo -e "${RED}用法: elise node del <ID>${RESET}" >&2
                return 1
            fi
            if [[ -z "$current_nodes" ]]; then
                echo -e "${YELLOW}当前未配置任何节点。${RESET}"
                return 0
            fi
            local new_nodes=""
            IFS=',' read -ra ADDR <<< "$current_nodes"
            local found=0
            for i in "${ADDR[@]}"; do
                local clean_id
                clean_id=$(echo "$i" | xargs)
                if [[ "$clean_id" == "$target_id" ]]; then
                    found=1
                else
                    if [[ -z "$new_nodes" ]]; then
                        new_nodes="$clean_id"
                    else
                        new_nodes="${new_nodes},${clean_id}"
                    fi
                fi
            done
            if [[ $found -eq 0 ]]; then
                echo -e "${YELLOW}节点 ID $target_id 未在当前配置中找到。${RESET}"
            else
                set_conf_kv "$conf_file" "node_id" "$new_nodes"
                echo -e "${GREEN}已成功移除节点 ID: $target_id${RESET}"
                echo -e "剩余节点列表: ${new_nodes:-无}"
                echo -e "请运行 'elise restart' 使配置生效。"
            fi
            ;;
        *)
            echo -e "${RED}未知 node 子命令: $action (可用: list, add <ID>, del <ID>)${RESET}" >&2
            return 1
            ;;
    esac
}

# ------------------------------------------------------------------------------
# 多实例管理命令
# ------------------------------------------------------------------------------
cmd_instance() {
    local subcmd="${1:-list}"; shift || true
    case "$subcmd" in
        list)
            echo -e "${BOLD}=== Elise 实例列表 ===${RESET}"
            echo -e "  [默认实例] /etc/elise/elise.conf -> $(get_status_str 'elise.service')"
            for c in "$CONF_DIR"/*/elise.conf; do
                if [[ -f "$c" ]]; then
                    local iname
                    iname=$(basename "$(dirname "$c")")
                    echo -e "  [实例: ${BLUE}$iname${RESET}] $c -> $(get_status_str "elise@$iname.service")"
                fi
            done
            ;;
        add|setup)
            check_root
            local iname="${1:-}"
            if [[ -z "$iname" ]]; then
                echo -e "${RED}用法: elise instance $subcmd <实例名> [k=v ...]${RESET}" >&2
                return 1
            fi
            shift
            local idir="$CONF_DIR/$iname"
            local iconf="$idir/elise.conf"
            mkdir -p "$idir"
            if [[ ! -f "$iconf" ]]; then
                if [[ -f "$MAIN_CONF" ]]; then
                    cp -p "$MAIN_CONF" "$iconf"
                fi
            fi
            if [[ $# -gt 0 ]]; then
                cmd_config "$iconf" "$@"
            else
                cmd_setup "$iconf"
            fi
            echo -e "${GREEN}实例 $iname 配置完成: $iconf${RESET}"
            ;;
        start)
            local iname="${1:-}"
            [[ -n "$iname" ]] || { echo -e "${RED}用法: elise instance start <实例名>${RESET}" >&2; return 1; }
            cmd_start "elise@$iname.service"
            ;;
        stop)
            local iname="${1:-}"
            [[ -n "$iname" ]] || { echo -e "${RED}用法: elise instance stop <实例名>${RESET}" >&2; return 1; }
            cmd_stop "elise@$iname.service"
            ;;
        restart)
            local iname="${1:-}"
            [[ -n "$iname" ]] || { echo -e "${RED}用法: elise instance restart <实例名>${RESET}" >&2; return 1; }
            cmd_restart "elise@$iname.service"
            ;;
        status)
            local iname="${1:-}"
            [[ -n "$iname" ]] || { echo -e "${RED}用法: elise instance status <实例名>${RESET}" >&2; return 1; }
            cmd_status "elise@$iname.service"
            ;;
        log)
            local iname="${1:-}"
            [[ -n "$iname" ]] || { echo -e "${RED}用法: elise instance log <实例名> [-f] [-n NUM]${RESET}" >&2; return 1; }
            shift
            cmd_log "elise@$iname.service" "$@"
            ;;
        enable)
            local iname="${1:-}"
            [[ -n "$iname" ]] || { echo -e "${RED}用法: elise instance enable <实例名>${RESET}" >&2; return 1; }
            cmd_enable "elise@$iname.service"
            ;;
        disable)
            local iname="${1:-}"
            [[ -n "$iname" ]] || { echo -e "${RED}用法: elise instance disable <实例名>${RESET}" >&2; return 1; }
            cmd_disable "elise@$iname.service"
            ;;
        config)
            local iname="${1:-}"
            [[ -n "$iname" ]] || { echo -e "${RED}用法: elise instance config <实例名> [k=v ...]${RESET}" >&2; return 1; }
            shift
            cmd_config "$CONF_DIR/$iname/elise.conf" "$@"
            ;;
        modify)
            local iname="${1:-}"
            [[ -n "$iname" ]] || { echo -e "${RED}用法: elise instance modify <实例名>${RESET}" >&2; return 1; }
            cmd_modify "$CONF_DIR/$iname/elise.conf"
            ;;
        node)
            local iname="${1:-}"
            [[ -n "$iname" ]] || { echo -e "${RED}用法: elise instance node <实例名> [list|add|del] [ID]${RESET}" >&2; return 1; }
            shift
            cmd_node "$CONF_DIR/$iname/elise.conf" "$@"
            ;;
        del|remove)
            check_root
            local iname="${1:-}"
            [[ -n "$iname" ]] || { echo -e "${RED}用法: elise instance del <实例名>${RESET}" >&2; return 1; }
            cmd_stop "elise@$iname.service" 2>/dev/null || true
            cmd_disable "elise@$iname.service" 2>/dev/null || true
            rm -rf "$CONF_DIR/$iname"
            echo -e "${GREEN}实例 $iname 及配置已清理。${RESET}"
            ;;
        *)
            echo -e "${RED}未知 instance 子命令: $subcmd${RESET}" >&2
            return 1
            ;;
    esac
}

# ------------------------------------------------------------------------------
# 证书与 Reality 操作
# ------------------------------------------------------------------------------
cmd_x25519() {
    if ! command -v openssl >/dev/null 2>&1; then
        echo -e "${RED}错误: 系统缺少 openssl 工具${RESET}" >&2
        return 1
    fi
    local priv_raw pub_raw priv pub
    # 使用 openssl 生成 x25519 原始 32 字节私钥与公钥并做 base64 url-safe 转换
    local tmp_key
    tmp_key=$(mktemp)
    openssl genpkey -algorithm X25519 -out "$tmp_key" 2>/dev/null
    priv=$(openssl pkey -in "$tmp_key" -outform DER 2>/dev/null | tail -c 32 | base64 | tr '/+' '_-' | tr -d '=')
    pub=$(openssl pkey -in "$tmp_key" -pubout -outform DER 2>/dev/null | tail -c 32 | base64 | tr '/+' '_-' | tr -d '=')
    rm -f "$tmp_key"
    
    echo -e "${BOLD}========================================${RESET}"
    echo -e "${BOLD}           X25519 密钥对生成结果         ${RESET}"
    echo -e "${BOLD}========================================${RESET}"
    echo -e "私钥 (Private Key): ${GREEN}$priv${RESET}"
    echo -e "公钥 (Public Key) : ${BLUE}$pub${RESET}"
    echo "----------------------------------------"
    echo "请将公钥填写到面板对应节点配置中供客户端使用；私钥保留在服务端。"
}

cmd_reality() {
    local action="${1:-menu}"; shift || true
    case "$action" in
        gen)
            cmd_x25519
            ;;
        show)
            echo -e "${BLUE}=== 当前 Reality 配置 ===${RESET}"
            local pk pb sni
            pk=$(get_conf_kv "$MAIN_CONF" "reality_private_key" || echo "未设置")
            pb=$(get_conf_kv "$MAIN_CONF" "reality_public_key" || echo "未设置")
            sni=$(get_conf_kv "$MAIN_CONF" "fake_sni" || echo "未设置")
            echo "reality_private_key = $pk"
            echo "reality_public_key  = $pb"
            echo "fake_sni            = $sni"
            ;;
        set)
            check_root
            if [[ $# -eq 0 ]]; then
                echo -e "${RED}用法: elise reality set [reality_private_key=... reality_public_key=... fake_sni=...]${RESET}" >&2
                return 1
            fi
            cmd_config "$MAIN_CONF" "$@"
            ;;
        menu)
            cmd_x25519
            ;;
        *)
            echo -e "${RED}未知 reality 子命令: $action (可用: gen, show, set)${RESET}" >&2
            return 1
            ;;
    esac
}

cmd_cert() {
    local action="${1:-menu}"; shift || true
    case "$action" in
        status)
            echo -e "${BLUE}=== 证书文件列表 (/etc/elise/cert/) ===${RESET}"
            ls -la /etc/elise/*.crt /etc/elise/*.key /etc/elise/cert/ 2>/dev/null || echo "未检测到静态证书文件（当前使用动态内存证书）"
            ;;
        gen)
            check_root
            mkdir -p /etc/elise/cert
            openssl ecparam -genkey -name prime256v1 -out /etc/elise/cert/server.key
            openssl req -new -x509 -days 3650 -key /etc/elise/cert/server.key -out /etc/elise/cert/server.crt -subj "/CN=localhost"
            echo -e "${GREEN}10 年有效期自签名 ECDSA P-256 证书已生成：${RESET}"
            echo "证书路径: /etc/elise/cert/server.crt"
            echo "私钥路径: /etc/elise/cert/server.key"
            ;;
        *)
            echo "  elise cert status: 查看证书文件状态"
            echo "  elise cert gen   : 生成自签名 ECDSA P-256 证书"
            ;;
    esac
}

# ------------------------------------------------------------------------------
# 更新与维护命令
# ------------------------------------------------------------------------------
cmd_update() {
    check_root
    local target="${1:-stable}"
    echo -e "${BLUE}准备更新 Elise ($target) ...${RESET}"
    if [[ "$target" == "beta" || "$target" == "--beta" ]]; then
        bash <(curl -fsSL "https://raw.githubusercontent.com/$GITHUB_REPO/main/scripts/install.sh") --beta
    elif [[ "$target" == "stable" ]]; then
        bash <(curl -fsSL "https://raw.githubusercontent.com/$GITHUB_REPO/main/scripts/install.sh")
    else
        bash <(curl -fsSL "https://raw.githubusercontent.com/$GITHUB_REPO/main/scripts/install.sh") "$target"
    fi
}

cmd_uninstall() {
    check_root
    echo -e "${RED}${BOLD}警告: 即将卸载 Elise 后端服务！${RESET}"
    read -rp "确定要卸载吗? [y/N]: " confirm
    if [[ "$confirm" != "y" && "$confirm" != "Y" ]]; then
        echo "已取消卸载。"
        return 0
    fi
    echo "正在停止服务并清理配置..."
    systemctl stop "$SYSTEMD_SERVICE" 2>/dev/null || true
    systemctl disable "$SYSTEMD_SERVICE" 2>/dev/null || true
    rm -f "/etc/systemd/system/$SYSTEMD_SERVICE" "/etc/systemd/system/elise@.service"
    systemctl daemon-reload 2>/dev/null || true
    rm -rf "/usr/local/elise" "/usr/local/bin/elise" "/usr/bin/elise"
    read -rp "是否删除配置目录 /etc/elise? [y/N]: " del_cfg
    if [[ "$del_cfg" == "y" || "$del_cfg" == "Y" ]]; then
        rm -rf "$CONF_DIR"
    fi
    echo -e "${GREEN}Elise 卸载完成。${RESET}"
}

# ------------------------------------------------------------------------------
# 帮助信息
# ------------------------------------------------------------------------------
cmd_help() {
    cat <<EOF
${BOLD}Elise - 高性能节点后端管理工具 (${SCRIPT_VERSION})${RESET}

用法: elise [命令] [参数...]

不带参数运行 elise 会打开交互式管理菜单。

${BOLD}基础管理:${RESET}
  elise start                   启动 Elise 服务
  elise stop                    停止 Elise 服务
  elise restart                 重启 Elise 服务
  elise status                  查看 Elise 运行状态与端口
  elise log [-f] [-n NUM]       查看服务日志 (-f 实时跟随, -n 指定行数)
  elise enable                  设置开机自启
  elise disable                 取消开机自启
  elise version                 查看版本与环境信息
  elise help                    查看命令帮助

${BOLD}配置与节点:${RESET}
  elise config                  查看当前主配置文件内容
  elise config k=v [k2=v2 ...]  快速修改配置项 (如: elise config node_id=25)
  elise modify                  交互式编辑主配置文件
  elise setup                   启动交互式配置向导
  elise node list               查看主配置中的节点 ID 列表
  elise node add <ID>           添加节点 ID 到配置 (如: elise node add 25)
  elise node del <ID>           从配置中删除节点 ID (如: elise node del 25)

${BOLD}多实例管理:${RESET}
  elise instance list           查看所有多实例列表与运行状态
  elise instance add <N> [k=v]  新建实例配置 (/etc/elise/<N>/elise.conf)
  elise instance setup <N>      向导式配置指定实例
  elise instance start <N>      启动指定实例 (elise@<N>.service)
  elise instance stop <N>       停止指定实例 (elise@<N>.service)
  elise instance restart <N>    重启指定实例 (elise@<N>.service)
  elise instance status <N>     查看指定实例运行状态
  elise instance log <N> [-f]   查看指定实例日志
  elise instance enable <N>     设置指定实例开机自启
  elise instance disable <N>    取消指定实例开机自启
  elise instance config <N>     查看或快速修改指定实例配置
  elise instance modify <N>     交互式编辑指定实例配置
  elise instance node <N> ...   管理指定实例内的节点 (list|add|del)

${BOLD}证书与 Reality:${RESET}
  elise cert                    证书管理
  elise reality                 Reality 密钥管理
  elise reality gen             生成全新 X25519 密钥对
  elise reality show            查看当前配置的 Reality 信息
  elise reality set [k=v ...]   快速设置 Reality 配置
  elise x25519                  直接生成并输出 X25519 密钥对

${BOLD}更新与维护:${RESET}
  elise update                  更新到最新正式版
  elise update beta             更新到最新测试版
  elise update <version>        更新到指定版本 (如: elise update v1.0.1)
  elise uninstall               卸载 Elise 服务与相关文件

${BOLD}核心程序命令:${RESET}
  elise run -c <conf>           原生前台启动运行核心程序
  elise test -c <conf>          原生测试配置文件语法与连通性
EOF
}

# ------------------------------------------------------------------------------
# 交互式菜单界面
# ------------------------------------------------------------------------------
interactive_menu() {
    check_root
    while true; do
        clear
        echo -e "${BOLD}========================================${RESET}"
        echo -e "${BOLD}          Elise 管理脚本 ${SCRIPT_VERSION}         ${RESET}"
        echo -e "${BOLD}========================================${RESET}"
        echo ""
        echo -e "当前状态: $(get_status_str)"
        echo -e "开机自启: $(get_enabled_str)"
        echo "----------------------------------------"
        echo -e "   ${BOLD}1.${RESET} 启动 Elise"
        echo -e "   ${BOLD}2.${RESET} 停止 Elise"
        echo -e "   ${BOLD}3.${RESET} 重启 Elise"
        echo -e "   ${BOLD}4.${RESET} 查看状态"
        echo -e "   ${BOLD}5.${RESET} 查看日志"
        echo "----------------------------------------"
        echo -e "   ${BOLD}6.${RESET} 查看配置"
        echo -e "   ${BOLD}7.${RESET} 修改配置"
        echo -e "   ${BOLD}8.${RESET} 节点管理"
        echo -e "   ${BOLD}9.${RESET} 重新配置引导"
        echo "----------------------------------------"
        echo -e "  ${BOLD}10.${RESET} 证书管理"
        echo -e "  ${BOLD}11.${RESET} Reality 密钥管理"
        echo "----------------------------------------"
        echo -e "  ${BOLD}12.${RESET} 设置开机自启"
        echo -e "  ${BOLD}13.${RESET} 取消开机自启"
        echo -e "  ${BOLD}14.${RESET} 更新 Elise（正式版）"
        echo -e "  ${BOLD}15.${RESET} 更新 Elise（测试版）"
        echo -e "  ${BOLD}16.${RESET} 卸载 Elise"
        echo -e "  ${BOLD}17.${RESET} 查看版本"
        echo "----------------------------------------"
        echo -e "   ${BOLD}0.${RESET} 退出"
        echo ""
        read -rp "请输入选项 [0-17]: " choice
        case "$choice" in
            1) cmd_start; pause ;;
            2) cmd_stop; pause ;;
            3) cmd_restart; pause ;;
            4) cmd_status; pause ;;
            5)
                echo "1. 实时跟踪日志; 2. 查看最近50行"
                read -rp "请选择 [1-2]: " l_opt
                if [[ "$l_opt" == "1" ]]; then cmd_log -f; else cmd_log -n 50; pause; fi
                ;;
            6) cmd_config "$MAIN_CONF"; pause ;;
            7) cmd_modify "$MAIN_CONF" ;;
            8)
                echo "1. 查看节点列表; 2. 新增节点ID; 3. 删除节点ID"
                read -rp "请选择 [1-3]: " n_opt
                case "$n_opt" in
                    1) cmd_node "$MAIN_CONF" list; pause ;;
                    2) read -rp "请输入新增节点 ID: " nid; cmd_node "$MAIN_CONF" add "$nid"; pause ;;
                    3) read -rp "请输入删除节点 ID: " nid; cmd_node "$MAIN_CONF" del "$nid"; pause ;;
                esac
                ;;
            9) cmd_setup "$MAIN_CONF" ;;
            10) cmd_cert gen; pause ;;
            11) cmd_x25519; pause ;;
            12) cmd_enable; pause ;;
            13) cmd_disable; pause ;;
            14) cmd_update stable; pause ;;
            15) cmd_update beta; pause ;;
            16) cmd_uninstall ;;
            17) cmd_version; pause ;;
            0) echo "已退出 Elise 管理。"; exit 0 ;;
            *) echo -e "${RED}输入无效，请重新输入！${RESET}"; sleep 1 ;;
        esac
    done
}

# ------------------------------------------------------------------------------
# 主分发入口 (CLI Dispatcher)
# ------------------------------------------------------------------------------
main() {
    if [[ $# -eq 0 ]]; then
        interactive_menu
        return
    fi
    
    local cmd="$1"; shift
    case "$cmd" in
        start) cmd_start "$@" ;;
        stop) cmd_stop "$@" ;;
        restart) cmd_restart "$@" ;;
        status) cmd_status "$@" ;;
        log|logs) cmd_log "$@" ;;
        enable) cmd_enable "$@" ;;
        disable) cmd_disable "$@" ;;
        version|-v|--version) cmd_version "$@" ;;
        help|-h|--help) cmd_help "$@" ;;
        
        config) cmd_config "$MAIN_CONF" "$@" ;;
        modify) cmd_modify "$MAIN_CONF" "$@" ;;
        setup) cmd_setup "$MAIN_CONF" "$@" ;;
        node) cmd_node "$MAIN_CONF" "$@" ;;
        
        instance) cmd_instance "$@" ;;
        
        cert) cmd_cert "$@" ;;
        reality) cmd_reality "$@" ;;
        x25519) cmd_x25519 "$@" ;;
        
        update) cmd_update "$@" ;;
        install) cmd_update stable ;;
        uninstall) cmd_uninstall "$@" ;;
        
        # 原生二进制命令透传
        run|test|geo)
            if [[ -x "$ELISE_BIN" ]]; then
                exec "$ELISE_BIN" "$cmd" "$@"
            else
                echo -e "${RED}错误: 找不到 Elise 原生程序 ($ELISE_BIN)${RESET}" >&2
                exit 1
            fi
            ;;
        *)
            # 如果是其他任意选项，尝试作为原生程序参数执行
            if [[ -x "$ELISE_BIN" ]]; then
                exec "$ELISE_BIN" "$cmd" "$@"
            else
                echo -e "${RED}未知命令: $cmd (运行 'elise help' 查看帮助)${RESET}" >&2
                exit 1
            fi
            ;;
    esac
}

main "$@"
