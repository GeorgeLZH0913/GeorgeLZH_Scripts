#!/bin/bash
# ============================================================================== 
# 自动化策略路由管理脚本 (PBR) v3.7
# ============================================================================== 

set -u

if [[ ${EUID:-$(id -u)} -ne 0 ]]; then
  echo "错误: 此脚本必须以 root 权限运行。"
  exit 1
fi

CONFIG_FILE="/etc/custom_policy_routes.conf"
DDNS_CONFIG_FILE="/etc/custom_policy_ddns.conf"
RT_TABLES_FILE="/etc/iproute2/rt_tables"
SERVICE_FILE="/etc/systemd/system/custom-routing.service"
SCRIPT_PATH="$(realpath "$0")"

touch "$CONFIG_FILE" "$DDNS_CONFIG_FILE"

# 格式: 名称 网关IP 正则
RAW_DEFINITIONS=$(cat <<'EOF'
9929 10.7.0.1 ^10\.7\.
CN2 10.8.0.1 ^10\.8\.
JPSDWAN 10.3.0.1 ^10\.3\.[0-3]\.
DESDWAN 10.3.10.1 ^10\.3\.(8|9|10|11)\.
KRSDWAN 10.4.0.1 ^10\.4\.[0-3]\.
HKSDWAN 10.3.50.1 ^10\.3\.(48|49|50|51)\.
TWSDWAN 10.3.100.1 ^10\.3\.(100|101|102|103)\.
SEATTLE 10.3.160.1 ^10\.3\.(160|161)\.
MOSCOW 10.3.170.1 ^10\.3\.(170|171)\.
EOF
)

PRIO_STATIC=15000
PRIO_DDNS=15005

declare -a FOUND_NAMES=()
declare -a FOUND_GWS=()
declare -a FOUND_IDS=()
SELECTED_IDX=0

fix_multigateway_conflict() {
  local verbose=true
  [[ "${1:-}" == "quiet" ]] && verbose=false

  local default_count
  default_count=$(ip route show default | wc -l)
  [[ "$default_count" -le 1 ]] && return 0

  while read -r name gw _pattern; do
    [[ -z "$name" ]] && continue
    if ip route show default | grep -q "via $gw"; then
      local remaining
      remaining=$(ip route show default | grep -v "via $gw" | wc -l)
      if [[ "$remaining" -ge 1 ]]; then
        $verbose && echo "[路由冲突修复] 剔除冲突网关: $gw ($name)"
        ip route del default via "$gw" 2>/dev/null || true
      fi
    fi
  done <<< "$RAW_DEFINITIONS"
}

detect_available_routes() {
  local mode="${1:-}"
  [[ "$mode" != "silent" && "$mode" != "quiet" ]] && echo "正在检测本机可用线路组..."

  fix_multigateway_conflict quiet

  FOUND_NAMES=()
  FOUND_GWS=()
  FOUND_IDS=()

  local table_base_id=101
  local added_count=0
  local all_ips
  all_ips=$(ip -4 addr show | awk '/inet / {print $2}' | cut -d/ -f1)

  while read -r def_name def_gw def_pattern; do
    [[ -z "$def_name" || "$def_name" =~ ^# ]] && continue

    local matched=0
    local ip
    for ip in $all_ips; do
      if [[ "$ip" =~ $def_pattern ]]; then
        matched=1
        break
      fi
    done

    if [[ "$matched" -eq 1 ]]; then
      FOUND_NAMES+=("$def_name")
      FOUND_GWS+=("$def_gw")
      local current_id=$((table_base_id + added_count))
      FOUND_IDS+=("$current_id")

      if ! grep -qE "^[0-9]+[[:space:]]+T_${def_name}([[:space:]]|$)" "$RT_TABLES_FILE"; then
        echo "$current_id T_${def_name}" >> "$RT_TABLES_FILE"
      fi
      added_count=$((added_count + 1))
    fi
  done <<< "$RAW_DEFINITIONS"

  if [[ ${#FOUND_NAMES[@]} -eq 0 ]]; then
    [[ "$mode" != "silent" && "$mode" != "quiet" ]] && echo "错误: 未检测到任何匹配线路。"
    return 1
  fi

  if [[ "$mode" != "silent" && "$mode" != "quiet" ]]; then
    echo "检测完成，可用线路如下:"
    printf "%-4s %-12s %-15s\n" "No." "线路名称" "网关"
    echo "--------------------------------"
    local i
    for ((i=0; i<${#FOUND_NAMES[@]}; i++)); do
      printf "%-4d %-12s %-15s\n" "$((i+1))" "${FOUND_NAMES[$i]}" "${FOUND_GWS[$i]}"
    done
  fi
}

select_route_group() {
  detect_available_routes silent || return 1
  local count=${#FOUND_NAMES[@]}
  [[ "$count" -eq 0 ]] && return 1

  echo "------------------------------"
  printf "%-4s %-12s %-15s\n" "No." "线路名称" "网关IP"
  echo "------------------------------"
  local i
  for ((i=0; i<count; i++)); do
    printf "%-4d %-12s %-15s\n" "$((i+1))" "${FOUND_NAMES[$i]}" "${FOUND_GWS[$i]}"
  done

  local choice
  read -rp "请输入数字选择线路: " choice
  if ! [[ "$choice" =~ ^[0-9]+$ ]] || [[ "$choice" -lt 1 ]] || [[ "$choice" -gt "$count" ]]; then
    echo "错误: 无效选项。"
    return 1
  fi

  SELECTED_IDX=$((choice - 1))
  return 0
}

add_rule() {
  select_route_group || return 1
  local idx=$SELECTED_IDX

  local selected_name="${FOUND_NAMES[$idx]}"
  local gateway="${FOUND_GWS[$idx]}"
  local table_id="${FOUND_IDS[$idx]}"
  local table_name="T_${selected_name}"

  local input_cidrs
  read -rp "请输入目标 IP/CIDR（可多个，逗号分隔，如 8.8.8.8,1.1.1.0/24）: " input_cidrs
  [[ -z "$input_cidrs" ]] && { echo "未输入内容。"; return 1; }

  local cleaned
  cleaned=$(echo "$input_cidrs" | tr -d '[:space:]')
  IFS=',' read -r -a cidr_items <<< "$cleaned"
  [[ ${#cidr_items[@]} -eq 0 ]] && { echo "未识别到有效输入。"; return 1; }

  local success=0 skipped=0
  ip route replace default via "$gateway" table "$table_id" 2>/dev/null

  local cidr
  for cidr in "${cidr_items[@]}"; do
    [[ -z "$cidr" ]] && { skipped=$((skipped+1)); continue; }

    if [[ "$cidr" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
      cidr="${cidr}/32"
      echo "已自动补全为: $cidr"
    fi

    if ! [[ "$cidr" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}/[0-9]{1,2}$ ]]; then
      echo "跳过无效 CIDR: $cidr"
      skipped=$((skipped+1))
      continue
    fi

    if grep -qE "^${cidr}[[:space:]]+${selected_name}$" "$CONFIG_FILE"; then
      echo "跳过已存在规则: $cidr -> $selected_name"
      skipped=$((skipped+1))
      continue
    fi

    ip rule del to "$cidr" table "$table_name" 2>/dev/null || true
    ip rule add to "$cidr" table "$table_name" priority "$PRIO_STATIC"
    echo "$cidr $selected_name" >> "$CONFIG_FILE"
    success=$((success+1))
  done

  echo "处理完成：成功 $success 条，跳过 $skipped 条。"
  [[ "$success" -gt 0 ]] && return 0 || return 1
}

add_ddns_rule() {
  echo "=== 添加 DDNS 域名分流规则 ==="
  select_route_group || return 1
  local idx=$SELECTED_IDX
  local selected_name="${FOUND_NAMES[$idx]}"

  local input_domains
  read -rp "请输入域名(A记录)（可多个，逗号分隔）: " input_domains
  [[ -z "$input_domains" ]] && { echo "域名不能为空。"; return 1; }

  local cleaned
  cleaned=$(echo "$input_domains" | tr -d '[:space:]')
  IFS=',' read -r -a domain_items <<< "$cleaned"
  [[ ${#domain_items[@]} -eq 0 ]] && { echo "未识别到有效输入。"; return 1; }

  local success=0 skipped=0
  local domain
  for domain in "${domain_items[@]}"; do
    [[ -z "$domain" ]] && { skipped=$((skipped+1)); continue; }

    if ! getent hosts "$domain" >/dev/null; then
      echo "警告: 当前无法解析域名 '$domain'。"
      read -rp "是否继续强制添加该域名? (y/n): " confirm
      if [[ "$confirm" != "y" ]]; then
        skipped=$((skipped+1))
        continue
      fi
    fi

    if grep -qE "^${domain}[[:space:]]+${selected_name}$" "$DDNS_CONFIG_FILE"; then
      echo "跳过已存在规则: $domain -> $selected_name"
      skipped=$((skipped+1))
      continue
    fi

    echo "$domain $selected_name" >> "$DDNS_CONFIG_FILE"
    success=$((success+1))
  done

  if [[ "$success" -gt 0 ]]; then
    echo "规则已保存，立即执行一次刷新..."
    refresh_ddns_rules
  fi
  echo "处理完成：成功 $success 条，跳过 $skipped 条。"
  [[ "$success" -eq 0 ]] && return 1

  local cron_cmd="$SCRIPT_PATH ddns_update"
  if ! crontab -l 2>/dev/null | grep -q "$cron_cmd"; then
    echo "提示: DDNS 规则需要定时刷新。"
    read -rp "是否立即添加每 5 分钟刷新任务? (y/n): " ask_cron
    if [[ "$ask_cron" == "y" ]]; then
      (crontab -l 2>/dev/null; echo "*/5 * * * * $cron_cmd >/dev/null 2>&1") | crontab -
      echo "已添加定时任务。"
    fi
  fi
}

delete_rule() {
  echo "1) 删除静态 IP 规则"
  echo "2) 删除 DDNS 域名规则"
  read -rp "请选择: " dtype

  local target_file=""
  if [[ "$dtype" == "1" ]]; then
    target_file="$CONFIG_FILE"
  elif [[ "$dtype" == "2" ]]; then
    target_file="$DDNS_CONFIG_FILE"
  else
    echo "无效选择。"
    return 1
  fi

  [[ ! -s "$target_file" ]] && { echo "配置为空。"; return 1; }

  awk '{print NR") "$0}' "$target_file"
  local input_nums
  read -rp "输入要删除的编号（可多选，逗号分隔，如 1,3,5）: " input_nums
  [[ -z "$input_nums" ]] && { echo "未输入编号。"; return 1; }

  local total_lines
  total_lines=$(wc -l < "$target_file")
  local cleaned
  cleaned=$(echo "$input_nums" | tr -d '[:space:]')

  IFS=',' read -r -a nums <<< "$cleaned"
  [[ ${#nums[@]} -eq 0 ]] && { echo "无效编号。"; return 1; }

  local -a valid_nums=()
  declare -A seen=()
  local n
  for n in "${nums[@]}"; do
    if ! [[ "$n" =~ ^[0-9]+$ ]] || [[ "$n" -lt 1 ]] || [[ "$n" -gt "$total_lines" ]]; then
      echo "无效编号: $n"
      return 1
    fi
    if [[ -z "${seen[$n]+x}" ]]; then
      valid_nums+=("$n")
      seen[$n]=1
    fi
  done

  mapfile -t sorted_nums < <(printf "%s\n" "${valid_nums[@]}" | sort -rn)

  local line_num content
  for line_num in "${sorted_nums[@]}"; do
    content=$(sed -n "${line_num}p" "$target_file")
    if [[ "$dtype" == "1" ]]; then
      local cidr
      cidr=$(echo "$content" | awk '{print $1}')
      ip rule del to "$cidr" priority "$PRIO_STATIC" 2>/dev/null || true
    fi
    sed -i "${line_num}d" "$target_file"
  done

  [[ "$dtype" == "2" ]] && refresh_ddns_rules quiet
  echo "已删除编号: $(IFS=,; echo "${sorted_nums[*]}")"
}

modify_rule() {
  echo "1) 修改静态 IP 规则"
  echo "2) 修改 DDNS 域名规则"
  read -rp "请选择: " mtype

  if [[ "$mtype" == "1" ]]; then
    [[ ! -s "$CONFIG_FILE" ]] && { echo "静态规则为空。"; return 1; }
    awk '{print NR") "$0}' "$CONFIG_FILE"

    local line_num total_lines
    read -rp "输入要修改的编号: " line_num
    total_lines=$(wc -l < "$CONFIG_FILE")
    if ! [[ "$line_num" =~ ^[0-9]+$ ]] || [[ "$line_num" -lt 1 ]] || [[ "$line_num" -gt "$total_lines" ]]; then
      echo "无效编号。"
      return 1
    fi

    local old_content old_cidr old_name
    old_content=$(sed -n "${line_num}p" "$CONFIG_FILE")
    old_cidr=$(echo "$old_content" | awk '{print $1}')
    old_name=$(echo "$old_content" | awk '{print $2}')

    local new_cidr new_name
    read -rp "请输入新的目标IP/CIDR（回车保持 ${old_cidr}）: " new_cidr
    [[ -z "$new_cidr" ]] && new_cidr="$old_cidr"
    if ! [[ "$new_cidr" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}/[0-9]{1,2}$ ]]; then
      echo "错误: CIDR 格式不正确。"
      return 1
    fi

    detect_available_routes silent || return 1
    echo "可用线路组（当前: ${old_name}）:"
    local i
    for ((i=0; i<${#FOUND_NAMES[@]}; i++)); do
      printf "%d) %s\n" "$((i+1))" "${FOUND_NAMES[$i]}"
    done

    local route_choice
    read -rp "请输入新的线路组编号（回车保持 ${old_name}）: " route_choice
    if [[ -z "$route_choice" ]]; then
      new_name="$old_name"
    else
      if ! [[ "$route_choice" =~ ^[0-9]+$ ]] || [[ "$route_choice" -lt 1 ]] || [[ "$route_choice" -gt "${#FOUND_NAMES[@]}" ]]; then
        echo "无效线路编号。"
        return 1
      fi
      new_name="${FOUND_NAMES[$((route_choice-1))]}"
    fi

    if awk -v n="$line_num" -v c="$new_cidr" -v g="$new_name" 'NR!=n && $1==c && $2==g{found=1} END{exit !found}' "$CONFIG_FILE"; then
      echo "警告: 规则已存在。"
      return 1
    fi

    if [[ "$new_cidr" == "$old_cidr" && "$new_name" == "$old_name" ]]; then
      echo "未修改，保持原规则。"
      return 0
    fi

    sed -i "${line_num}c${new_cidr} ${new_name}" "$CONFIG_FILE"
    ip rule del to "$old_cidr" priority "$PRIO_STATIC" 2>/dev/null || true
    apply_saved_rules
    echo "修改成功。"
    return 0
  fi

  if [[ "$mtype" == "2" ]]; then
    [[ ! -s "$DDNS_CONFIG_FILE" ]] && { echo "DDNS 规则为空。"; return 1; }
    awk '{print NR") "$0}' "$DDNS_CONFIG_FILE"

    local line_num total_lines
    read -rp "输入要修改的编号: " line_num
    total_lines=$(wc -l < "$DDNS_CONFIG_FILE")
    if ! [[ "$line_num" =~ ^[0-9]+$ ]] || [[ "$line_num" -lt 1 ]] || [[ "$line_num" -gt "$total_lines" ]]; then
      echo "无效编号。"
      return 1
    fi

    local old_content old_domain old_name
    old_content=$(sed -n "${line_num}p" "$DDNS_CONFIG_FILE")
    old_domain=$(echo "$old_content" | awk '{print $1}')
    old_name=$(echo "$old_content" | awk '{print $2}')

    local new_domain new_name
    read -rp "请输入新的域名(A记录)（回车保持 ${old_domain}）: " new_domain
    [[ -z "$new_domain" ]] && new_domain="$old_domain"

    if ! getent hosts "$new_domain" >/dev/null; then
      echo "警告: 当前无法解析域名 '$new_domain'。"
      read -rp "是否继续强制修改 (y/n): " confirm
      [[ "$confirm" != "y" ]] && return 1
    fi

    detect_available_routes silent || return 1
    echo "可用线路组（当前: ${old_name}）:"
    local i
    for ((i=0; i<${#FOUND_NAMES[@]}; i++)); do
      printf "%d) %s\n" "$((i+1))" "${FOUND_NAMES[$i]}"
    done

    local route_choice
    read -rp "请输入新的线路组编号（回车保持 ${old_name}）: " route_choice
    if [[ -z "$route_choice" ]]; then
      new_name="$old_name"
    else
      if ! [[ "$route_choice" =~ ^[0-9]+$ ]] || [[ "$route_choice" -lt 1 ]] || [[ "$route_choice" -gt "${#FOUND_NAMES[@]}" ]]; then
        echo "无效线路编号。"
        return 1
      fi
      new_name="${FOUND_NAMES[$((route_choice-1))]}"
    fi

    if awk -v n="$line_num" -v d="$new_domain" -v g="$new_name" 'NR!=n && $1==d && $2==g{found=1} END{exit !found}' "$DDNS_CONFIG_FILE"; then
      echo "警告: 规则已存在。"
      return 1
    fi

    if [[ "$new_domain" == "$old_domain" && "$new_name" == "$old_name" ]]; then
      echo "未修改，保持原规则。"
      return 0
    fi

    sed -i "${line_num}c${new_domain} ${new_name}" "$DDNS_CONFIG_FILE"
    refresh_ddns_rules
    echo "修改成功。"
    return 0
  fi

  echo "无效选择。"
  return 1
}

refresh_ddns_rules() {
  while ip rule del priority "$PRIO_DDNS" 2>/dev/null; do :; done
  [[ ! -s "$DDNS_CONFIG_FILE" ]] && return 0

  detect_available_routes quiet || return 0

  while IFS= read -r line || [[ -n "$line" ]]; do
    [[ -z "$line" || "$line" =~ ^[[:space:]]*# ]] && continue

    local domain group
    domain=$(echo "$line" | awk '{print $1}')
    group=$(echo "$line" | awk '{print $2}')

    local found_idx=-1
    local i
    for ((i=0; i<${#FOUND_NAMES[@]}; i++)); do
      if [[ "${FOUND_NAMES[$i]}" == "$group" ]]; then
        found_idx=$i
        break
      fi
    done

    if [[ "$found_idx" -ge 0 ]]; then
      local gateway="${FOUND_GWS[$found_idx]}"
      local table_id="${FOUND_IDS[$found_idx]}"
      local table_name="T_${group}"

      ip route replace default via "$gateway" table "$table_id" 2>/dev/null

      local ips
      ips=$(getent hosts "$domain" | awk '{print $1}' | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' || true)
      if [[ -n "$ips" ]]; then
        local ip_addr
        for ip_addr in $ips; do
          ip rule add to "${ip_addr}/32" table "$table_name" priority "$PRIO_DDNS" 2>/dev/null || true
        done
        [[ "${1:-}" != "quiet" ]] && echo "DDNS更新: $domain -> $group"
      fi
    fi
  done < "$DDNS_CONFIG_FILE"
}

manage_cron() {
  echo "=== DDNS 自动更新配置 (Crontab) ==="
  local cron_cmd="$SCRIPT_PATH ddns_update"

  if crontab -l 2>/dev/null | grep -q "$cron_cmd"; then
    echo "状态: 已启用"
    read -rp "是否移除自动更新? (y/n): " remove_opt
    if [[ "$remove_opt" == "y" ]]; then
      crontab -l 2>/dev/null | grep -v "$cron_cmd" | crontab -
      echo "已移除。"
    fi
  else
    echo "状态: 未启用"
    read -rp "是否添加每5分钟自动更新任务? (y/n): " add_opt
    if [[ "$add_opt" == "y" ]]; then
      (crontab -l 2>/dev/null; echo "*/5 * * * * $cron_cmd >/dev/null 2>&1") | crontab -
      echo "已添加。"
    fi
  fi
}

apply_saved_rules() {
  echo "正在初始化网络规则..."
  fix_multigateway_conflict
  detect_available_routes quiet || true

  if [[ -s "$CONFIG_FILE" ]]; then
    while ip rule del priority "$PRIO_STATIC" 2>/dev/null; do :; done

    while IFS= read -r rule || [[ -n "$rule" ]]; do
      [[ -z "$rule" || "$rule" =~ ^[[:space:]]*# ]] && continue

      local cidr name
      cidr=$(echo "$rule" | awk '{print $1}')
      name=$(echo "$rule" | awk '{print $2}')

      local found_idx=-1
      local i
      for ((i=0; i<${#FOUND_NAMES[@]}; i++)); do
        [[ "${FOUND_NAMES[$i]}" == "$name" ]] && found_idx=$i && break
      done

      if [[ "$found_idx" -ge 0 ]]; then
        local gateway="${FOUND_GWS[$found_idx]}"
        local table_id="${FOUND_IDS[$found_idx]}"
        ip route replace default via "$gateway" table "$table_id" 2>/dev/null
        ip rule add to "$cidr" table "T_${name}" priority "$PRIO_STATIC" 2>/dev/null || true
      fi
    done < "$CONFIG_FILE"
  fi

  refresh_ddns_rules quiet
  echo "所有规则应用完成。"
}

list_rules() {
  echo "--- 静态规则 ($CONFIG_FILE) ---"
  [[ -s "$CONFIG_FILE" ]] && cat "$CONFIG_FILE" || echo "无"
  echo
  echo "--- DDNS 规则 ($DDNS_CONFIG_FILE) ---"
  [[ -s "$DDNS_CONFIG_FILE" ]] && cat "$DDNS_CONFIG_FILE" || echo "无"
  echo
  echo "--- 系统规则 (Partial) ---"
  ip rule show | grep -E "priority ($PRIO_STATIC|$PRIO_DDNS)" || echo "无生效规则"
}

manage_service() {
  if [[ -f "$SERVICE_FILE" ]]; then
    echo "服务状态: $(systemctl is-active custom-routing.service 2>/dev/null || true)"
    read -rp "是否卸载服务? (y/n): " opt
    if [[ "$opt" == "y" ]]; then
      systemctl stop custom-routing.service 2>/dev/null || true
      systemctl disable custom-routing.service 2>/dev/null || true
      rm -f "$SERVICE_FILE"
      systemctl daemon-reload
      echo "已卸载。"
    fi
  else
    read -rp "是否安装开机自启服务? (y/n): " opt
    if [[ "$opt" == "y" ]]; then
      cat > "$SERVICE_FILE" <<EOF
[Unit]
Description=Apply Custom Policy-Based Routing Rules
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=${SCRIPT_PATH} apply
RemainAfterExit=true

[Install]
WantedBy=multi-user.target
EOF
      systemctl daemon-reload
      systemctl enable custom-routing.service
      systemctl start custom-routing.service
      echo "已安装并启动。"
    fi
  fi
}

main_menu() {
  detect_available_routes quiet || true
  while true; do
    echo
    echo "========================================="
    echo "   利群主機 LeiKwan Host 多出口调控 v3.7"
    echo "========================================="
    echo "1. 添加静态路由 (IP/CIDR)"
    echo "2. 添加动态路由 (DDNS 域名)"
    echo "3. 删除规则"
    echo "4. 修改现有规则"
    echo "5. 查看所有配置"
    echo "6. 配置自动更新 (Cron/DDNS)"
    echo "7. 管理开机自启服务"
    echo "8. 强制刷新所有规则 (含网关修复)"
    echo "0. 退出"
    echo "-----------------------------------------"

    read -rp "选择: " choice
    case "$choice" in
      1) add_rule ;;
      2) add_ddns_rule ;;
      3) delete_rule ;;
      4) modify_rule ;;
      5) list_rules ;;
      6) manage_cron ;;
      7) manage_service ;;
      8) apply_saved_rules ;;
      0) exit 0 ;;
      *) echo "无效输入。" ;;
    esac

    read -n 1 -s -r -p "按任意键继续..."
    echo
  done
}

case "${1:-}" in
  apply) apply_saved_rules ;;
  ddns_update) refresh_ddns_rules quiet ;;
  *) main_menu ;;
esac
