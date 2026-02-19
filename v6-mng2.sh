#!/bin/bash
# --- 版本控制 ---
CURRENT_VERSION="v8.0"
# 版本号检测地址 (内容只需包含版本号字符串, 如 "v8.1")
UPDATE_API_URL="https://files.leikwanhost.com/version-v6-mng"
# 新脚本下载地址
UPDATE_SCRIPT_URL="https://files.leikwanhost.com/ipv6_manager.sh"

# --- 强制环境 ---
export LC_ALL=C
export LANG=C

# --- 颜色定义 ---
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

# --- 全局配置 ---
CONFIG_FILE="/etc/ipv6_manager.conf"
LOG_FILE="/var/log/ipv6_manager.log"
PING_TARGET="2400:3200::1"

# --- 依赖检查 ---
check_dependencies() {
    local missing=0
    for cmd in ip ping curl jq awk grep sed sort tr openssl; do
        if ! command -v $cmd &> /dev/null; then
            echo -e "${RED}错误: 缺少依赖 $cmd${NC}"
            missing=1
        fi
    done
    if [ "$missing" -eq 1 ]; then echo "请先安装: apt install iproute2 iputils-ping curl jq openssl"; exit 1; fi
}

# --- 辅助函数 ---
log() { echo -e "$(date '+%Y-%m-%d %H:%M:%S') - $1" | tee -a "${LOG_FILE}" >&2; }

kv_save() {
    local KEY="$1"; local VALUE="$2"
    touch "$CONFIG_FILE"
    if grep -q "^${KEY}=" "$CONFIG_FILE"; then
        sed -i.bak "s|^${KEY}=.*|${KEY}=\"${VALUE}\"|" "$CONFIG_FILE" && rm -f "${CONFIG_FILE}.bak"
    else
        echo "${KEY}=\"${VALUE}\"" >> "$CONFIG_FILE"
    fi
}

load_config() {
    # 默认值
    DEFAULT_OUTBOUND_ISP=""
    IP_SELECT_MODE="latency"
    POLICY_ROUTE_ENABLED="false"; POLICY_ROUTE_ISP=""; POLICY_ROUTE_DEST_IP=""
    IFACE_CT="auto"; IFACE_CU="auto"
    
    # DDNS
    DDNS_CT_ENABLE="false"; DDNS_CT_PROVIDER=""; DDNS_CT_TOKEN=""; DDNS_CT_ID=""; DDNS_CT_SECRET=""; DDNS_CT_DOMAIN=""; DDNS_CT_HOST=""; DDNS_CT_WEBHOOK=""; DDNS_CT_EMAIL=""; DDNS_CT_TTL="1"
    DDNS_CU_ENABLE="false"; DDNS_CU_PROVIDER=""; DDNS_CU_TOKEN=""; DDNS_CU_ID=""; DDNS_CU_SECRET=""; DDNS_CU_DOMAIN=""; DDNS_CU_HOST=""; DDNS_CU_WEBHOOK=""; DDNS_CU_EMAIL=""; DDNS_CU_TTL="1"

    if [ -f "$CONFIG_FILE" ]; then
        while IFS='=' read -r key value; do
            value=$(echo "$value" | sed -e "s/^\"//" -e "s/\"$//")
            case "$key" in
                DEFAULT_OUTBOUND_ISP) DEFAULT_OUTBOUND_ISP="$value" ;;
                IP_SELECT_MODE) IP_SELECT_MODE="$value" ;;
                POLICY_ROUTE_ENABLED) POLICY_ROUTE_ENABLED="$value" ;;
                POLICY_ROUTE_ISP) POLICY_ROUTE_ISP="$value" ;;
                POLICY_ROUTE_DEST_IP) POLICY_ROUTE_DEST_IP="$value" ;;
                IFACE_CT) IFACE_CT="$value" ;;
                IFACE_CU) IFACE_CU="$value" ;;
                DDNS_CT_*) eval ${key}="\"$value\"" ;;
                DDNS_CU_*) eval ${key}="\"$value\"" ;;
            esac
        done < "$CONFIG_FILE"
    fi
}

show_header() {
    clear
    echo -e "${CYAN}==============================================================${NC}"
    echo -e "${CYAN}        利群主機 | LeiKwan Host  IPv6 智能管家 ${CURRENT_VERSION}          ${NC}"
    echo -e "${CYAN}==============================================================${NC}"
}

show_status_bar() {
    load_config
    local curr_src=$(ip -6 route show default | grep -oP 'src \K[^ ]+')
    local curr_dev=$(ip -6 route show default | grep -oP 'dev \K[^ ]+')
    local curr_isp="未知"
    if [[ "$curr_src" == 240e* ]]; then curr_isp="电信"; elif [[ "$curr_src" == 2408* ]]; then curr_isp="联通"; fi
    
    echo -e "当前出口 IP : ${GREEN}${curr_src:-未设置}${NC} ($curr_isp @ $curr_dev)"
    echo -e "接口锁定状态: 电信[${YELLOW}${IFACE_CT:-auto}${NC}] | 联通[${YELLOW}${IFACE_CU:-auto}${NC}]"
    local ip_mode="延迟最佳"; [[ "$IP_SELECT_MODE" == "latest" ]] && ip_mode="最新下发"
    echo -e "IP选择策略 : ${BLUE}${ip_mode}${NC}"
    
    local ct_st="${RED}关${NC}"; [[ "$DDNS_CT_ENABLE" == "true" ]] && ct_st="${GREEN}开${NC}"
    local cu_st="${RED}关${NC}"; [[ "$DDNS_CU_ENABLE" == "true" ]] && cu_st="${GREEN}开${NC}"
    echo -e "双线 DDNS   : 电信[${ct_st}] | 联通[${cu_st}]"
    echo -e "${CYAN}--------------------------------------------------------------${NC}"
}

# ==================================================================
# 在线更新模块
# ==================================================================
check_for_update() {
    echo -e "${YELLOW}正在连接服务器检查更新...${NC}"
    # 设置超时时间为 5 秒
    local remote_ver=$(curl -s --max-time 5 "$UPDATE_API_URL" | tr -d ' \n\r')

    if [[ -z "$remote_ver" ]]; then
        echo -e "${RED}检查失败: 无法连接更新服务器或版本号为空。${NC}"
        read -p "按回车返回..."
        return
    fi

    if [[ "$remote_ver" != "$CURRENT_VERSION" ]]; then
        echo -e "${GREEN}发现新版本: ${remote_ver}${NC} (当前: $CURRENT_VERSION)"
        echo -e "更新内容请关注官方公告。"
        echo
        read -p "是否立即更新并替换当前脚本? [y/N]: " yn
        if [[ "$yn" =~ ^[Yy]$ ]]; then
            echo "正在下载新版本..."
            local temp_file="/tmp/ipv6_manager_new.sh"
            curl -L -o "$temp_file" --progress-bar "$UPDATE_SCRIPT_URL"
            
            # 简单校验下载的文件是否完整 (检查是否包含 bash 头)
            if grep -q "#!/bin/bash" "$temp_file"; then
                echo "备份旧版本至 ${0}.bak ..."
                cp "$0" "${0}.bak"
                mv "$temp_file" "$0"
                chmod +x "$0"
                echo -e "${GREEN}更新成功! 正在重启脚本...${NC}"
                sleep 2
                exec "$0"
            else
                echo -e "${RED}错误: 下载的文件校验失败，已取消更新。${NC}"
                rm -f "$temp_file"
            fi
        else
            echo "已取消更新。"
        fi
    else
        echo -e "${GREEN}当前已是最新版本 ($CURRENT_VERSION)。${NC}"
    fi
    read -p "按回车返回..."
}

# ==================================================================
# 核心功能: 深度清理与扫描
# ==================================================================
clean_and_scan() {
    # 1. 清理 Deprecated
    ip addr show | awk '
        BEGIN { current_dev=""; current_ip=""; is_deprecated=0 }
        /^[0-9]+:/ { name=$2; gsub(":", "", name); current_dev=name; }
        /inet6/ { current_ip=$2; if ($0 ~ /deprecated/) is_deprecated=1; else is_deprecated=0; }
        /valid_lft/ {
            if (current_dev != "" && current_ip != "") {
                pref_lft_val="999"; 
                for(i=1;i<=NF;i++) { if($i=="preferred_lft") { val=$(i+1); gsub("sec","",val); if(val=="forever") val="999"; pref_lft_val=val; } }
                if(is_deprecated==1 || pref_lft_val=="0") print current_ip, current_dev;
                current_ip="";
            }
        }
    ' | while read ip dev; do
        if [[ -n "$ip" ]]; then ip -6 addr del "$ip" dev "$dev" 2>/dev/null; fi
    done

    # 2. 选择 IP (支持延迟最佳 / 最新下发)
    BEST_TELECOM_IP=""; BEST_TELECOM_IFACE=""
    BEST_UNICOM_IP=""; BEST_UNICOM_IFACE=""
    
    local raw_list=$(ip -6 addr show scope global | awk '
        BEGIN { curr_ip=""; curr_iface=""; keep=0 }
        /^[0-9]+:/ {
            iface=$2
            gsub(":", "", iface)
            curr_iface=iface
            next
        }
        /inet6.*scope global/ {
            curr_ip=""
            keep=0
            if ($0 ~ /deprecated/) next
            curr_ip=$2
            keep=1
            next
        }
        /valid_lft/ {
            if (keep!=1 || curr_ip=="") next
            pref=-1
            for (i=1; i<=NF; i++) {
                if ($i=="preferred_lft" && (i+1)<=NF) {
                    val=$(i+1)
                    gsub("sec", "", val)
                    if (val=="forever") pref=2147483647
                    else pref=val+0
                }
            }
            print curr_ip, curr_iface, pref
            curr_ip=""
            keep=0
        }
    ')
    [ -z "$raw_list" ] && return

    local min_tele_lat=9999; local min_uni_lat=9999
    local best_tele_pref=-1; local best_uni_pref=-1

    while read -r ip_full iface pref; do
        local ip=${ip_full%/*}
        local isp=""
        if [[ "$ip" == 240e:* ]]; then isp="电信"; elif [[ "$ip" == 2408:* ]]; then isp="联通"; else continue; fi

        # 接口锁定检查
        if [[ "$isp" == "电信" && "$IFACE_CT" != "auto" && "$iface" != "$IFACE_CT" ]]; then continue; fi
        if [[ "$isp" == "联通" && "$IFACE_CU" != "auto" && "$iface" != "$IFACE_CU" ]]; then continue; fi

        if [[ "$IP_SELECT_MODE" == "latest" ]]; then
            # 同运营商取 preferred_lft 最大的地址；相等时取最后出现
            if [[ "$isp" == "电信" && "$pref" -ge "$best_tele_pref" ]]; then
                best_tele_pref=$pref; BEST_TELECOM_IP=$ip; BEST_TELECOM_IFACE=$iface
            elif [[ "$isp" == "联通" && "$pref" -ge "$best_uni_pref" ]]; then
                best_uni_pref=$pref; BEST_UNICOM_IP=$ip; BEST_UNICOM_IFACE=$iface
            fi
        else
            # 默认策略: 延迟最佳
            local lat=9999
            local res=$(ping -6 -c 1 -w 1 -I "$ip" "$PING_TARGET" 2>/dev/null)
            if [ $? -eq 0 ]; then lat=$(echo "$res" | tail -1 | awk -F'/' '{print $5}' | awk '{printf "%.0f", $1}'); fi

            if [[ "$isp" == "电信" && "$lat" -lt "$min_tele_lat" ]]; then
                min_tele_lat=$lat; BEST_TELECOM_IP=$ip; BEST_TELECOM_IFACE=$iface
            elif [[ "$isp" == "联通" && "$lat" -lt "$min_uni_lat" ]]; then
                min_uni_lat=$lat; BEST_UNICOM_IP=$ip; BEST_UNICOM_IFACE=$iface
            fi
        fi
    done <<< "$raw_list"
}

apply_route() {
    local target_isp="$1"; local ip="$2"; local iface="$3"
    if [[ -z "$ip" ]]; then return 1; fi
    local gw=$(ip -6 route show default dev "$iface" 2>/dev/null | grep "via" | awk '{print $3}' | head -n1)
    if [ -z "$gw" ]; then gw=$(ip -6 route show default 2>/dev/null | grep "via" | awk '{print $3}' | head -n1); fi
    if [ -n "$gw" ]; then
        ip -6 route replace default via "$gw" dev "$iface" src "$ip"
        return $?
    fi
    return 1
}

# ==================================================================
# DDNS API
# ==================================================================
ddns_api_webhook() {
    local ip="$1"; local url="${2//\{ip\}/$ip}"; log "Webhook: $url"
    local res=$(curl -s -w "%{http_code}" -o /dev/null "$url")
    if [[ "$res" == "200" ]]; then return 0; else log "Webhook Error: HTTP $res"; return 1; fi
}
ddns_api_cf() {
    local ip="$1"; local token="$2"; local domain="$3"; local host="$4"; local email="$5"; local ttl="$6"
    [[ -z "$ttl" ]] && ttl="1"
    if ! [[ "$ttl" =~ ^[0-9]+$ ]]; then ttl="1"; fi
    if [[ "$ttl" != "1" && ( "$ttl" -lt 60 || "$ttl" -gt 86400 ) ]]; then ttl="1"; fi
    local headers=("-H" "Content-Type: application/json")
    if [[ -n "$email" ]]; then headers+=("-H" "X-Auth-Email: $email" "-H" "X-Auth-Key: $token"); else headers+=("-H" "Authorization: Bearer $token"); fi
    local zid=$(curl -s "${headers[@]}" "https://api.cloudflare.com/client/v4/zones?name=$domain" | jq -r '.result[0].id')
    if [[ "$zid" == "null" ]]; then log "CF Error: ZoneID not found"; return 1; fi
    local rid=$(curl -s "${headers[@]}" "https://api.cloudflare.com/client/v4/zones/$zid/dns_records?type=AAAA&name=$host" | jq -r '.result[0].id')
    local method="POST"; local url="https://api.cloudflare.com/client/v4/zones/$zid/dns_records"; [[ "$rid" != "null" ]] && { method="PATCH"; url="$url/$rid"; }
    local res=$(curl -s -X "$method" "$url" "${headers[@]}" --data "{\"type\":\"AAAA\",\"name\":\"$host\",\"content\":\"$ip\",\"ttl\":$ttl,\"proxied\":false}")
    if [[ $(echo "$res" | jq -r '.success') == "true" ]]; then return 0; else log "CF Error: $(echo "$res" | jq -r '.errors[0].message // .messages[0]')"; return 1; fi
}
ddns_api_dnspod() {
    local ip="$1"; local token="$2"; local domain="$3"; local host="$4"
    local c="login_token=$token&format=json&domain=$domain&sub_domain=$host"
    local rid=$(curl -s -X POST "https://dnsapi.cn/Record.List" -d "$c&record_type=AAAA" | jq -r '.records[0].id')
    local api="Record.Create"; local ex="&record_line=默认"; [[ "$rid" != "null" ]] && { api="Record.Modify"; ex="$ex&record_id=$rid"; }
    local res=$(curl -s -X POST "https://dnsapi.cn/$api" -d "$c&record_type=AAAA&value=$ip&ttl=600$ex")
    if [[ $(echo "$res" | jq -r '.status.code') == "1" ]]; then return 0; else log "DNSPOD Error: $(echo "$res" | jq -r '.status.message')"; return 1; fi
}
percent_encode() { echo -n "$1" | od -An -tx1 | tr ' ' '%' | tr '[:lower:]' '[:upper:]'; }
ddns_api_alidns() {
    local ip="$1"; local id="$2"; local secret="$3"; local domain="$4"; local rr="$5"
    local ts=$(date -u "+%Y-%m-%dT%H%%3A%M%%3A%SZ"); local nonce=$(date +%s%N)
    local p="AccessKeyId=$id&Action=DescribeDomainRecords&DomainName=$domain&Format=JSON&RRKeyWord=$rr&SignatureMethod=HMAC-SHA1&SignatureNonce=$nonce&SignatureVersion=1.0&Timestamp=$ts&Type=AAAA&Version=2015-01-01"
    local s=$(echo -n "$p" | tr '&' '\n' | sort | tr '\n' '&' | sed 's/&$//'); local str="GET&%2F&$(percent_encode "$s" | sed 's/%3D/=/g' | sed 's/%26/&/g')"
    local sig=$(echo -n "$str" | openssl dgst -sha1 -hmac "$secret&" -binary | base64)
    local res_find=$(curl -s "http://alidns.aliyuncs.com/?$p&Signature=$(percent_encode "$sig")")
    if [[ $(echo "$res_find" | jq -r '.Code') != "null" ]]; then log "AliDNS Find Error: $(echo "$res_find" | jq -r '.Message')"; return 1; fi
    local rid=$(echo "$res_find" | jq -r '.DomainRecords.Record[0].RecordId')
    local act="AddDomainRecord"; local ex=""; [[ "$rid" != "null" ]] && { act="UpdateDomainRecord"; ex="&RecordId=$rid"; }
    nonce=$(date +%s%N); p="AccessKeyId=$id&Action=$act&DomainName=$domain$ex&Format=JSON&RR=$rr&SignatureMethod=HMAC-SHA1&SignatureNonce=$nonce&SignatureVersion=1.0&TTL=600&Timestamp=$ts&Type=AAAA&Value=$ip&Version=2015-01-01"
    s=$(echo -n "$p" | tr '&' '\n' | sort | tr '\n' '&' | sed 's/&$//'); str="GET&%2F&$(percent_encode "$s" | sed 's/%3D/=/g' | sed 's/%26/&/g')"
    sig=$(echo -n "$str" | openssl dgst -sha1 -hmac "$secret&" -binary | base64)
    local res=$(curl -s "http://alidns.aliyuncs.com/?$p&Signature=$(percent_encode "$sig")")
    if [[ -n $(echo "$res" | jq -r '.RecordId // empty') ]]; then return 0; else log "AliDNS Update Error: $(echo "$res" | jq -r '.Message')"; return 1; fi
}

# ==================================================================
# 自动任务
# ==================================================================
run_ddns_worker() {
    local LINE="$1"; local IP="$2"
    eval ENABLE="\$DDNS_${LINE}_ENABLE"; eval PROVIDER="\$DDNS_${LINE}_PROVIDER"
    eval TOKEN="\$DDNS_${LINE}_TOKEN"; eval ID="\$DDNS_${LINE}_ID"; eval SECRET="\$DDNS_${LINE}_SECRET"; eval TTL="\$DDNS_${LINE}_TTL"
    eval DOMAIN="\$DDNS_${LINE}_DOMAIN"; eval HOST="\$DDNS_${LINE}_HOST"; eval WEBHOOK="\$DDNS_${LINE}_WEBHOOK"; eval EMAIL="\$DDNS_${LINE}_EMAIL"
    if [[ "$ENABLE" != "true" || -z "$IP" ]]; then return; fi
    local last_file="/tmp/ipv6_last_ddns_${LINE}.txt"; local last_ip=$(cat "$last_file" 2>/dev/null)
    if [[ "$IP" == "$last_ip" ]]; then return; fi
    log "DDNS [$LINE]: 变动 ($last_ip -> $IP)，更新中..."
    local res=1
    case "$PROVIDER" in
        "cloudflare") ddns_api_cf "$IP" "$TOKEN" "$DOMAIN" "$HOST" "$EMAIL" "$TTL"; res=$? ;;
        "dnspod") ddns_api_dnspod "$IP" "$TOKEN" "$DOMAIN" "$HOST"; res=$? ;;
        "alidns") ddns_api_alidns "$IP" "$ID" "$SECRET" "$DOMAIN" "$HOST"; res=$? ;;
        "webhook") ddns_api_webhook "$IP" "$WEBHOOK"; res=$? ;;
    esac
    if [ $res -eq 0 ]; then echo "$IP" > "$last_file"; log "DDNS [$LINE]: 成功 -> $HOST"; else log "DDNS [$LINE]: 失败!"; fi
}

run_auto_task() {
    log ">>> 自动任务启动 <<<"
    load_config
    clean_and_scan
    if [ -n "$DEFAULT_OUTBOUND_ISP" ]; then
        local target_ip=""; local target_iface=""
        if [[ "$DEFAULT_OUTBOUND_ISP" == "电信" ]]; then target_ip="$BEST_TELECOM_IP"; target_iface="$BEST_TELECOM_IFACE";
        elif [[ "$DEFAULT_OUTBOUND_ISP" == "联通" ]]; then target_ip="$BEST_UNICOM_IP"; target_iface="$BEST_UNICOM_IFACE"; fi
        if [ -n "$target_ip" ]; then
            local curr=$(ip -6 route show default | grep -oP 'src \K[^ ]+')
            if [[ "$curr" != "$target_ip" ]]; then
                log "路由更新: $curr -> $target_ip ($target_iface)"
                apply_route "$DEFAULT_OUTBOUND_ISP" "$target_ip" "$target_iface"
            fi
        fi
    fi
    run_ddns_worker "CT" "$BEST_TELECOM_IP"
    run_ddns_worker "CU" "$BEST_UNICOM_IP"
    if [[ "$POLICY_ROUTE_ENABLED" == "true" && -n "$POLICY_ROUTE_DEST_IP" ]]; then
        local p_ip=""; local p_if=""
        if [[ "$POLICY_ROUTE_ISP" == "电信" ]]; then p_ip="$BEST_TELECOM_IP"; p_if="$BEST_TELECOM_IFACE";
        elif [[ "$POLICY_ROUTE_ISP" == "联通" ]]; then p_ip="$BEST_UNICOM_IP"; p_if="$BEST_UNICOM_IFACE"; fi
        if [ -n "$p_ip" ]; then
             local gw=$(ip -6 route show default dev "$p_if" | grep "via" | awk '{print $3}' | head -n1)
             if [ -n "$gw" ]; then
                 ip -6 rule add to "$POLICY_ROUTE_DEST_IP" lookup 101 priority 1000 2>/dev/null
                 ip -6 route replace "$POLICY_ROUTE_DEST_IP" via "$gw" dev "$p_if" src "$p_ip" table 101
             fi
        fi
    fi
    log ">>> 完成 <<<"
}

# ==================================================================
# 菜单
# ==================================================================
configure_interfaces() {
    while true; do
        clear; show_header; show_status_bar
        echo -e "${YELLOW}--- 网络接口绑定 (防跳动设置) ---${NC}"
        echo -e "当前电信: ${GREEN}${IFACE_CT:-auto}${NC} | 联通: ${GREEN}${IFACE_CU:-auto}${NC}"
        local ifaces=$(ip -o link show | awk -F': ' '{print $2}' | grep -v "lo")
        echo " 1. 设置 电信 接口"
        echo " 2. 设置 联通 接口"
        echo " 0. 返回"
        read -p "选择: " c
        case $c in
            1|2)
                local target="CT"; local tname="电信"; [[ "$c" == "2" ]] && { target="CU"; tname="联通"; }
                echo -e "\n请选择 ${tname} 要绑定的网卡:"
                select iface in "auto" $ifaces; do if [ -n "$iface" ]; then kv_save "IFACE_${target}" "$iface"; echo "已锁定"; sleep 1; break; fi; done ;;
            0) break ;;
        esac
    done; load_config
}

configure_ddns_entry() {
    local LINE="$1"; local LINE_NAME="$2"
    while true; do
        clear; show_header
        echo -e "${YELLOW}--- 配置 ${LINE_NAME} DDNS ---${NC}"
        eval curr_prov="\$DDNS_${LINE}_PROVIDER"; eval curr_host="\$DDNS_${LINE}_HOST"
        echo -e "当前: ${curr_prov:-未配置} -> ${curr_host:-未配置}"
        echo " 1. Cloudflare"
        echo " 2. DNSPOD (腾讯云)"
        echo " 3. AliDNS (阿里云)"
        echo " 4. Webhook"
        echo " 5. 禁用/清除"
        echo " 0. 返回"
        read -p "选择: " c
        case $c in
            1) echo "1. Token 2. Global Key"; read -p "Type: " cf_type; 
                if [[ "$cf_type" == "2" ]]; then read -p "Email: " e; read -p "Key: " t; kv_save "DDNS_${LINE}_EMAIL" "$e";
                else read -p "Token: " t; kv_save "DDNS_${LINE}_EMAIL" ""; fi
               echo "Cloudflare 输入说明:"
               echo " - Domain: Zone 主域名，例如 example.com"
               echo " - Host: 完整记录名(FQDN)，例如 abc.example.com"
               read -p "Domain(如 example.com): " d
               read -p "Host(完整域名, 如 abc.example.com): " h
               read -p "TTL(秒, 1=自动, 60-86400): " ttl
               [[ -z "$ttl" ]] && ttl="1"
               if ! [[ "$ttl" =~ ^[0-9]+$ ]]; then ttl="1"; fi
               if [[ "$ttl" != "1" && ( "$ttl" -lt 60 || "$ttl" -gt 86400 ) ]]; then ttl="1"; fi
               kv_save "DDNS_${LINE}_PROVIDER" "cloudflare"; kv_save "DDNS_${LINE}_TOKEN" "$t"; kv_save "DDNS_${LINE}_DOMAIN" "$d"; kv_save "DDNS_${LINE}_HOST" "$h"; kv_save "DDNS_${LINE}_TTL" "$ttl"; kv_save "DDNS_${LINE}_ENABLE" "true"; break ;;
            2) read -p "ID,Token: " t; read -p "Domain: " d; read -p "Sub: " h
               kv_save "DDNS_${LINE}_PROVIDER" "dnspod"; kv_save "DDNS_${LINE}_TOKEN" "$t"; kv_save "DDNS_${LINE}_DOMAIN" "$d"; kv_save "DDNS_${LINE}_HOST" "$h"; kv_save "DDNS_${LINE}_ENABLE" "true"; break ;;
            3) read -p "ID: " i; read -p "Secret: " s; read -p "Domain: " d; read -p "Sub: " h
               kv_save "DDNS_${LINE}_PROVIDER" "alidns"; kv_save "DDNS_${LINE}_ID" "$i"; kv_save "DDNS_${LINE}_SECRET" "$s"; kv_save "DDNS_${LINE}_DOMAIN" "$d"; kv_save "DDNS_${LINE}_HOST" "$h"; kv_save "DDNS_${LINE}_ENABLE" "true"; break ;;
            4) read -p "URL: " u; kv_save "DDNS_${LINE}_PROVIDER" "webhook"; kv_save "DDNS_${LINE}_WEBHOOK" "$u"; kv_save "DDNS_${LINE}_ENABLE" "true"; break ;;
            5) kv_save "DDNS_${LINE}_ENABLE" "false"; break ;;
            0) break ;;
        esac
    done; load_config
}

install_service() {
    local SCRIPT_PATH=$(realpath "$0")
    read -p "检查频率 (分钟, 建议 2): " INTERVAL; [[ -z "$INTERVAL" ]] && INTERVAL=2
    cat > "/etc/systemd/system/ipv6_manager.service" <<EOF
[Unit]
Description=LeiKwan Host IPv6 Manager
After=network-online.target
[Service]
Type=oneshot
ExecStart=${SCRIPT_PATH} auto
User=root
EOF
    cat > "/etc/systemd/system/ipv6_manager.timer" <<EOF
[Unit]
Description=Run IPv6 Manager
[Timer]
OnBootSec=1min
OnUnitActiveSec=${INTERVAL}m
Unit=ipv6_manager.service
[Install]
WantedBy=timers.target
EOF
    systemctl daemon-reload; systemctl enable --now ipv6_manager.timer
    echo -e "${GREEN}服务安装成功！${NC}"; sleep 2
}

# --- 启动 ---
if [[ $EUID -ne 0 ]]; then echo "Need Root."; exit 1; fi
check_dependencies; touch "$LOG_FILE" "$CONFIG_FILE"
if [ "$1" == "auto" ]; then run_auto_task; exit 0; fi

while true; do
    show_header; show_status_bar
    echo -e " 1. 自动选路 (指定默认出口)"
    echo -e " 2. DDNS 配置 (双线独立)"
    echo -e " 3. 网络接口绑定 (防跳动设置)"
    echo -e " 4. 策略路由"
    echo -e " 5. 立即运行 (清理+更新)"
    echo -e " 6. 安装守护服务"
    echo -e " 7. 查看日志"
    echo -e " 8. 检查更新 [NEW]"
    echo -e " 9. IP选择策略"
    echo -e " 0. 退出"
    read -p "选项: " choice
    case $choice in
        1) echo "优先出口:"; select isp in "电信" "联通" "禁用"; do [[ "$isp" == "禁用" ]] && isp=""; kv_save "DEFAULT_OUTBOUND_ISP" "$isp"; echo "已保存"; break; done ;;
        2) while true; do show_header; show_status_bar; echo -e "${YELLOW}DDNS配置${NC}"; echo "[1]电信 [2]联通 [3]日志 [0]返回"; read -p "选: " c; case $c in 1) configure_ddns_entry "CT" "电信" ;; 2) configure_ddns_entry "CU" "联通" ;; 3) tail -n10 "$LOG_FILE"; read -p ".";; 0) break ;; esac; done ;;
        3) configure_interfaces ;;
        4) read -p "目标IP: " d; echo "线路:"; select i in "电信" "联通"; do kv_save "POLICY_ROUTE_ENABLED" "true"; kv_save "POLICY_ROUTE_DEST_IP" "$d"; kv_save "POLICY_ROUTE_ISP" "$i"; break; done ;;
        5) run_auto_task; read -p "完成..." ;;
        6) install_service ;;
        7) tail -n 20 "$LOG_FILE"; read -p "回车..." ;;
        8) check_for_update ;;
        9) echo "IP获取策略:"; select m in "延迟最佳" "最新下发"; do
               if [[ "$m" == "最新下发" ]]; then kv_save "IP_SELECT_MODE" "latest"; else kv_save "IP_SELECT_MODE" "latency"; fi
               echo "已保存"; break
           done ;;
        0) exit 0 ;;
    esac
done
