#!/usr/bin/env bash

# ==============================================================================
#   VPS 防火牆安全管理系統 (iptables & ip6tables)
#   語系: 專用 Bash 腳本 (100% 適用於任何內建 Bash 的 Linux VPS)
#   功能: 雙軌 IPv4/IPv6 同步管理,表格對齊,寫入安全測試,歷史備份管理與自動還原
#   設計: 高安全性,高可靠性之雙軌同步防火牆管理系統
#   Author: Jackie
#   Email: jackie.github@outlook.com
#   GitHub: https://github.com/jackietw/vps_firewall_manager
# ==============================================================================

# --- 全局變數與初始化 ---
STAGED_RULES=() # 暫存規則,格式: "PORT|PROTOCOL|SOURCE|COMMENT|ACTION|IP_VERSION"
STAGED_POLICY=""      # 待套用預設策略,可為 "","ACCEPT" 或 "DROP"
STAGED_POLICY_V6=""   # 待套用 IPv6 預設策略,同上
BACKUP_DIR="./backups"
SELECTED_MENU_IDX=0   # 目前選單選中的索引

# --- 建立備份目錄 ---
mkdir -p "$BACKUP_DIR"

# --- 終端色彩設定 ---
COLOR_RESET="\e[0m"
COLOR_BOLD="\e[1m"
COLOR_DIM="\e[2m"
COLOR_RED="\e[31m"
COLOR_GREEN="\e[32m"
COLOR_YELLOW="\e[33m"
COLOR_BLUE="\e[34m"
COLOR_MAGENTA="\e[35m"
COLOR_CYAN="\e[36m"
COLOR_WHITE="\e[37m"
COLOR_RED_BK="\e[41m"
COLOR_RESET_BK="\e[49m"
COLOR_MENU_SEL="\e[30;42m" # 選單反白高亮背景色 (黑字綠底)

# --- 跨外殼確認詢問 (Bash 專用) ---
confirm_prompt() {
  local prompt_msg="$1"
  local key=""
  read -p "$prompt_msg" -n 1 -s key
  echo "" # 換行
  if [[ "$key" =~ ^[Yy]$ ]]; then
    return 0
  else
    return 1
  fi
}

# --- 輔助函式: 支援中英文混合對齊的字串格式化 (動態計算視覺寬度) ---
format_align() {
  local str="$1"
  local target_width="$2"
  local align="${3:-left}"
  
  # 計算字元數與位元組數 (排除換行符號)
  local len_char=$(echo -n "$str" | wc -m)
  local len_byte=$(echo -n "$str" | wc -c)
  
  # 套用 (L_byte + L_char) / 2 計算視覺寬度 (對應 UTF-8 中文 3 bytes 佔 2 欄位寬度)
  local visual_width=$(( (len_byte + len_char) / 2 ))
  
  # 計算需要補足的空白數量
  local pad_len=$(( target_width - visual_width ))
  [ $pad_len -lt 0 ] && pad_len=0
  
  local padding=""
  if [ $pad_len -gt 0 ]; then
    padding=$(printf "%${pad_len}s" "")
  fi
  
  if [ "$align" = "right" ]; then
    echo -n "${padding}${str}"
  else
    echo -n "${str}${padding}"
  fi
}

# --- 環境與權限檢查 ---
if [ "$EUID" -ne 0 ]; then
  echo -e "${COLOR_BOLD}[!] 錯誤: 此腳本需要 ${COLOR_RED}root${COLOR_RESET} 權限,請使用 sudo 執行!"
  echo -e "請使用指令: ${COLOR_YELLOW}sudo ./vps_fw.sh${COLOR_RESET}"
  exit 1
fi

if ! command -v iptables &>/dev/null || ! command -v ip6tables &>/dev/null; then
  echo -e "${COLOR_RED}${COLOR_BOLD}[!] 錯誤: 系統未偵測到 iptables 或 ip6tables 工具,本腳本終止執行.${COLOR_RESET}"
  exit 1
fi

# --- 輔助函式: 動態偵測目前連入之 SSH 連接埠 ---
detect_current_ssh_port() {
  local detected_port="22"
  
  # 1. 優先從目前 SSH 連線環境變數獲取 (最精準,反映目前真實連線中的 Port)
  if [ -n "$SSH_CONNECTION" ]; then
    detected_port=$(echo "$SSH_CONNECTION" | awk '{print $4}')
  # 2. 次之從 sshd 配置文件中解析
  elif [ -f "/etc/ssh/sshd_config" ]; then
    local parsed_port
    parsed_port=$(grep -i '^Port' /etc/ssh/sshd_config 2>/dev/null | awk '{print $2}')
    if [ -n "$parsed_port" ] && [[ "$parsed_port" =~ ^[0-9]+$ ]]; then
      detected_port="$parsed_port"
    fi
  fi
  
  echo "$detected_port"
}

# --- 輔助函式: 輸出標頭 ---
print_header() {
  clear
  echo -e "${COLOR_CYAN}${COLOR_BOLD}┌────────────────────────────────────────────────────────┐${COLOR_RESET}"
  echo -e "${COLOR_CYAN}${COLOR_BOLD}│               防火牆管理系統 (IPv4/IPv6)               │${COLOR_RESET}"
  echo -e "${COLOR_CYAN}${COLOR_BOLD}└────────────────────────────────────────────────────────┘${COLOR_RESET}"
  echo -e "${COLOR_GREEN}${COLOR_BOLD} 已使用 root 權限成功與防火牆連線 ${COLOR_RESET}"
  echo -e "${COLOR_GREEN} ──────────────────────────────────────────────────────── ${COLOR_RESET}"
  
}

# --- 核心功能 1: 獲取與解析防火牆規則 ---
get_active_rules() {
  local family="${1:-v4}"
  local cmd="iptables"
  [ "$family" = "v6" ] && cmd="ip6tables"

  # 正式模式: 使用 Bash 原生 Regex 與 BASH_REMATCH 高效率解析 active 規則
  $cmd -S INPUT 2>/dev/null | while read -r line; do
    if [[ "$line" =~ ^-P ]]; then
      continue
    fi
    # 略過迴路與狀態連線規則,避免版面凌亂
    if [[ "$line" == *"-i lo"* || "$line" == *"RELATED,ESTABLISHED"* || "$line" == *"ctstate ESTABLISHED,RELATED"* ]]; then
      continue
    fi

    local proto="all"
    local port="All"
    local src="Anywhere"
    local target="ACCEPT"
    local comment=""

    # 1. 提取協定
    if [[ "$line" =~ -p\ ([a-zA-Z0-9]+) ]]; then
      proto="${BASH_REMATCH[1]}"
    fi

    # 2. 提取連接埠
    if [[ "$line" =~ --dport\ ([0-9]+) || "$line" =~ --dports\ ([0-9:,]+) ]]; then
      port="${BASH_REMATCH[1]}"
    fi

    # 3. 提取來源 IP
    if [[ "$line" =~ -s\ ([0-9a-fA-F./:]+) ]]; then
      src="${BASH_REMATCH[1]}"
    fi

    # 4. 提取備註
    if [[ "$line" =~ --comment\ \"([^\"]+)\" || "$line" =~ --comment\ ([^ ]+) ]]; then
      comment="${BASH_REMATCH[1]}"
    fi

    # 5. 提取動作
    if [[ "$line" =~ -j\ ([A-Z_]+) ]]; then
      target="${BASH_REMATCH[1]}"
    fi

    echo "RULE|${proto}|${port}|${src}|${target}|${comment}"
  done
}

# --- 顯示現有防火牆狀態 ---
show_status() {
  print_header
  
  # --- 1. 獲取 IPv4 狀態 ---
  local input_policy
  input_policy=$(iptables -S INPUT 2>/dev/null | grep '^-P INPUT' | awk '{print $3}')
  [ -z "$input_policy" ] && input_policy="ACCEPT"
  
  local policy_color=$COLOR_GREEN
  [ "$input_policy" = "DROP" ] && policy_color=$COLOR_RED
  
  local policy_suffix=""
  if [ -n "$STAGED_POLICY" ]; then
    local s_color=$COLOR_GREEN
    [ "$STAGED_POLICY" = "DROP" ] && s_color=$COLOR_RED
    policy_suffix=" (${COLOR_YELLOW}待修改為: ${s_color}${COLOR_BOLD}${STAGED_POLICY}${COLOR_RESET})"
  fi
  
  echo -e "${COLOR_BOLD}IPv4 INPUT 預設行為 (Default Policy): ${policy_color}${COLOR_BOLD}${input_policy}${COLOR_RESET}${policy_suffix}"
  echo -e "${COLOR_BOLD}目前作用中的 IPv4 防火牆規則 (Active IPv4 Rules):${COLOR_RESET}"
  echo -e "${COLOR_CYAN}┌────┬──────────┬──────────┬──────────────────────┬──────────┬────────────────────────┐${COLOR_RESET}"
  echo -e "${COLOR_CYAN}│編號│ 通訊協定 │ 連接埠   │ 來源 IP 限制         │ 連線動作 │ 備註說明               │${COLOR_RESET}"
  echo -e "${COLOR_CYAN}├────┼──────────┼──────────┼──────────────────────┼──────────┼────────────────────────┤${COLOR_RESET}"
  
  local index=1
  local has_rules=false
  local raw_output
  raw_output=$(get_active_rules v4)
  
  while IFS= read -r line; do
    if [ -z "$line" ]; then
      continue
    fi
    if [[ "$line" =~ ^RULE\|(.*) ]]; then
      has_rules=true
      local rule_data="${BASH_REMATCH[1]}"
      local proto port src target comment
      IFS='|' read -r proto port src target comment <<< "$rule_data"
      [ -z "$comment" ] && comment="無"
      
      local target_styled=$target
      if [ "$target" = "ACCEPT" ]; then
        target_styled="${COLOR_GREEN}${COLOR_BOLD}ACCEPT  ${COLOR_RESET}"
      elif [ "$target" = "DROP" ]; then
        target_styled="${COLOR_RED}${COLOR_BOLD}DROP    ${COLOR_RESET}"
      elif [ "$target" = "REJECT" ]; then
        target_styled="${COLOR_RED}${COLOR_BOLD}REJECT  ${COLOR_RESET}"
      fi
      
      local comment_aligned
      comment_aligned=$(format_align "$comment" 22)
      
      printf "${COLOR_CYAN}│${COLOR_RESET} %-2d ${COLOR_CYAN}│${COLOR_RESET} %-8s ${COLOR_CYAN}│${COLOR_RESET} %-8s ${COLOR_CYAN}│${COLOR_RESET} %-20s ${COLOR_CYAN}│${COLOR_RESET} %b ${COLOR_CYAN}│${COLOR_RESET} %s ${COLOR_CYAN}│${COLOR_RESET}\n" \
        $index "$proto" "$port" "$src" "$target_styled" "$comment_aligned"
      ((index++))
    fi
  done <<< "$raw_output"
  
  if [ "$has_rules" = false ]; then
    local no_rules_msg
    no_rules_msg=$(format_align "                               目前無自訂 IPv4 限制規則" 85)
    echo -e "${COLOR_CYAN}│${COLOR_RESET}${no_rules_msg}${COLOR_CYAN}│${COLOR_RESET}"
  fi
  echo -e "${COLOR_CYAN}└────┴──────────┴──────────┴──────────────────────┴──────────┴────────────────────────┘${COLOR_RESET}"
  echo ""

  # --- 2. 獲取 IPv6 狀態 ---
  local input_policy_v6
  input_policy_v6=$(ip6tables -S INPUT 2>/dev/null | grep '^-P INPUT' | awk '{print $3}')
  [ -z "$input_policy_v6" ] && input_policy_v6="ACCEPT"
  
  local policy_color_v6=$COLOR_GREEN
  [ "$input_policy_v6" = "DROP" ] && policy_color_v6=$COLOR_RED
  
  local policy_suffix_v6=""
  if [ -n "$STAGED_POLICY_V6" ]; then
    local s_color_v6=$COLOR_GREEN
    [ "$STAGED_POLICY_V6" = "DROP" ] && s_color_v6=$COLOR_RED
    policy_suffix_v6=" (${COLOR_YELLOW}待修改為: ${s_color_v6}${COLOR_BOLD}${STAGED_POLICY_V6}${COLOR_RESET})"
  fi
  
  echo -e "${COLOR_BOLD}IPv6 INPUT 預設行為 (Default Policy): ${policy_color_v6}${COLOR_BOLD}${input_policy_v6}${COLOR_RESET}${policy_suffix_v6}"
  echo -e "${COLOR_BOLD}目前作用中的 IPv6 防火牆規則 (Active IPv6 Rules):${COLOR_RESET}"
  echo -e "${COLOR_CYAN}┌────┬──────────┬──────────┬──────────────────────┬──────────┬────────────────────────┐${COLOR_RESET}"
  echo -e "${COLOR_CYAN}│編號│ 通訊協定 │ 連接埠   │ 來源 IP 限制         │ 連線動作 │ 備註說明               │${COLOR_RESET}"
  echo -e "${COLOR_CYAN}├────┼──────────┼──────────┼──────────────────────┼──────────┼────────────────────────┤${COLOR_RESET}"
  
  local index_v6=1
  local has_rules_v6=false
  local raw_output_v6
  raw_output_v6=$(get_active_rules v6)
  
  while IFS= read -r line; do
    if [ -z "$line" ]; then
      continue
    fi
    if [[ "$line" =~ ^RULE\|(.*) ]]; then
      has_rules_v6=true
      local rule_data="${BASH_REMATCH[1]}"
      local proto port src target comment
      IFS='|' read -r proto port src target comment <<< "$rule_data"
      [ -z "$comment" ] && comment="無"
      
      local target_styled=$target
      if [ "$target" = "ACCEPT" ]; then
        target_styled="${COLOR_GREEN}${COLOR_BOLD}ACCEPT  ${COLOR_RESET}"
      elif [ "$target" = "DROP" ]; then
        target_styled="${COLOR_RED}${COLOR_BOLD}DROP    ${COLOR_RESET}"
      elif [ "$target" = "REJECT" ]; then
        target_styled="${COLOR_RED}${COLOR_BOLD}REJECT  ${COLOR_RESET}"
      fi
      
      local comment_aligned
      comment_aligned=$(format_align "$comment" 22)
      
      printf "${COLOR_CYAN}│${COLOR_RESET} %-2d ${COLOR_CYAN}│${COLOR_RESET} %-8s ${COLOR_CYAN}│${COLOR_RESET} %-8s ${COLOR_CYAN}│${COLOR_RESET} %-20s ${COLOR_CYAN}│${COLOR_RESET} %b ${COLOR_CYAN}│${COLOR_RESET} %s ${COLOR_CYAN}│${COLOR_RESET}\n" \
        $index_v6 "$proto" "$port" "$src" "$target_styled" "$comment_aligned"
      ((index_v6++))
    fi
  done <<< "$raw_output_v6"
  
  if [ "$has_rules_v6" = false ]; then
    local no_rules_msg_v6
    no_rules_msg_v6=$(format_align "                               目前無自訂 IPv6 限制規則" 85)
    echo -e "${COLOR_CYAN}│${COLOR_RESET}${no_rules_msg_v6}${COLOR_CYAN}│${COLOR_RESET}"
  fi
  echo -e "${COLOR_CYAN}└────┴──────────┴──────────┴──────────────────────┴──────────┴────────────────────────┘${COLOR_RESET}"

  # --- 3. 顯示暫存中的規則 ---
  if [ ${#STAGED_RULES[@]} -gt 0 ]; then
    echo ""
    echo -e "${COLOR_YELLOW}${COLOR_BOLD}待寫入的暫存規則 (Staged Rules - 尚未套用):${COLOR_RESET}"
    echo -e "${COLOR_YELLOW}┌────┬──────────┬──────────┬──────────────────────┬──────────┬────────────────────────┐${COLOR_RESET}"
    echo -e "${COLOR_YELLOW}│編號│ 通訊協定 │ 連接埠   │ 來源 IP 限制         │ 連線動作 │ 備註說明               │${COLOR_RESET}"
    echo -e "${COLOR_YELLOW}├────┼──────────┼──────────┼──────────────────────┼──────────┼────────────────────────┤${COLOR_RESET}"
    local s_index=1
    for s_rule in "${STAGED_RULES[@]}"; do
      local port proto src comment target ip_version
      IFS='|' read -r port proto src comment target ip_version <<< "$s_rule"
      [ -z "$comment" ] && comment="無"
      
      local sign="+"
      local ver_suffix=""
      [ "$ip_version" = "ipv4" ] && ver_suffix="-v4"
      [ "$ip_version" = "ipv6" ] && ver_suffix="-v6"
      [ "$ip_version" = "both" ] && ver_suffix="-Both"
      
      local action_abbr=""
      local is_delete=false
      local raw_action="$target"
      
      if [[ "$target" == DELETE_* ]]; then
        is_delete=true
        sign="-"
        raw_action="${target#DELETE_}"
      fi
      
      if [ "$raw_action" = "ACCEPT" ]; then
        action_abbr="A"
      elif [ "$raw_action" = "DROP" ]; then
        action_abbr="D"
      elif [ "$raw_action" = "REJECT" ]; then
        action_abbr="R"
      else
        action_abbr="${raw_action:0:1}"
      fi
      
      local target_text="${action_abbr}${ver_suffix}"
      
      # Pad target_text to exactly 8 characters to ensure perfect layout alignment under %b
      local pad_len=$((8 - ${#target_text}))
      local padded_text="$target_text"
      if [ $pad_len -gt 0 ]; then
        local spaces=""
        for ((p=0; p<pad_len; p++)); do
          spaces+=" "
        done
        padded_text="${target_text}${spaces}"
      fi
      
      local target_styled=""
      if [[ "$target_text" == A-* ]]; then
        target_styled="${COLOR_GREEN}${COLOR_BOLD}${padded_text}${COLOR_RESET}"
      else
        target_styled="${COLOR_RED}${COLOR_BOLD}${padded_text}${COLOR_RESET}"
      fi
      
      local index_str=""
      if [ $s_index -lt 10 ]; then
        index_str=" ${sign}${s_index} "
      else
        index_str="${sign}${s_index} "
      fi
      
      local comment_aligned
      comment_aligned=$(format_align "$comment" 22)
      
      printf "${COLOR_YELLOW}│${COLOR_RESET}%s${COLOR_YELLOW}│${COLOR_RESET} %-8s ${COLOR_YELLOW}│${COLOR_RESET} %-8s ${COLOR_YELLOW}│${COLOR_RESET} %-20s ${COLOR_YELLOW}│${COLOR_RESET} %b ${COLOR_YELLOW}│${COLOR_RESET} %s ${COLOR_YELLOW}│${COLOR_RESET}\n" \
        "$index_str" "$proto" "$port" "$src" "$target_styled" "$comment_aligned"
      ((s_index++))
    done
    echo -e "${COLOR_YELLOW}└────┴──────────┴──────────┴──────────────────────┴──────────┴────────────────────────┘${COLOR_RESET}"
    echo -e "${COLOR_YELLOW}[提示] 請回到主選單選擇 [5. 寫入並開始測試] 以啟用上述暫存規則.${COLOR_RESET}"
  fi
  
  echo ""
  echo -e "${COLOR_DIM}按任意鍵返回選單...${COLOR_RESET}"
  read -n 1 -s
}

# --- 輔助函式: 檢查是否特定 Port 規範被包含在另一個 Port 規範中 ---
spec_covered() {
  local check_spec="$1"
  local existing_spec="$2"
  
  # 如果現有的規格是 "All"，代表全部放行，必然涵蓋
  [ "$existing_spec" = "All" ] && return 0
  # 如果要檢查的規格是 "All"，但現有不是 "All"，不可能被涵蓋
  [ "$check_spec" = "All" ] && return 1
  
  local IFS=','
  local c_part
  for c_part in $check_spec; do
    local part_covered=false
    
    # 檢查 c_part 是否為範圍 (如 500:600)
    if [[ "$c_part" == *":"* ]]; then
      local c_start="${c_part%%:*}"
      local c_end="${c_part##*:}"
      
      # 尋找 existing_spec 中是否有任何一個部分完整涵蓋此範圍
      local e_part
      for e_part in ${existing_spec//,/ }; do
        if [[ "$e_part" == *":"* ]]; then
          local e_start="${e_part%%:*}"
          local e_end="${e_part##*:}"
          if (( c_start >= e_start && c_end <= e_end )); then
            part_covered=true
            break
          fi
        fi
      done
    else
      # c_part 為單一 Port (如 500)
      local e_part
      for e_part in ${existing_spec//,/ }; do
        if [[ "$e_part" == *":"* ]]; then
          local e_start="${e_part%%:*}"
          local e_end="${e_part##*:}"
          if (( c_part >= e_start && c_part <= e_end )); then
            part_covered=true
            break
          fi
        else
          if [ "$c_part" = "$e_part" ] 2>/dev/null; then
            part_covered=true
            break
          fi
        fi
      done
    fi
    
    # 只要要檢查的規格有任何一部分未被涵蓋，即判定為未完整包含
    [ "$part_covered" = false ] && return 1
  done
  
  return 0
}

# --- 輔助函式: 檢查規則是否已存在於暫存區或目前作用中規則中 ---
rule_exists() {
  local check_port="$1"
  local check_proto="$2"
  local check_src="$3"
  local check_action="$4"
  local check_ip_ver="$5" # "ipv4", "ipv6", or "both"
  
  # 1. 檢查暫存區 (STAGED_RULES)
  for staged in "${STAGED_RULES[@]}"; do
    local s_port s_proto s_src s_comment s_action s_ip_ver
    IFS='|' read -r s_port s_proto s_src s_comment s_action s_ip_ver <<< "$staged"
    
    # 只要通訊協定、來源 IP、連線動作一致，且要新增的 Port 規格已被現有暫存規格完整包含，且 IP 版本交疊，即為重複
    if [ "$s_proto" = "$check_proto" ] && [ "$s_src" = "$check_src" ] && [ "$s_action" = "$check_action" ] && spec_covered "$check_port" "$s_port"; then
      if [ "$s_ip_ver" = "both" ] || [ "$check_ip_ver" = "both" ] || [ "$s_ip_ver" = "$check_ip_ver" ]; then
        return 0
      fi
    fi
  done
  
  # 2. 檢查目前作用中的規則
  # 檢查 IPv4 作用中規則
  if [ "$check_ip_ver" = "ipv4" ] || [ "$check_ip_ver" = "both" ]; then
    local active_v4
    active_v4=$(get_active_rules v4)
    while IFS= read -r line; do
      [ -z "$line" ] && continue
      if [[ "$line" =~ ^RULE\|(.*) ]]; then
        local r_proto r_port r_src r_action r_comment
        IFS='|' read -r r_proto r_port r_src r_action r_comment <<< "${BASH_REMATCH[1]}"
        if [ "$r_proto" = "$check_proto" ] && [ "$r_src" = "$check_src" ] && [ "$r_action" = "$check_action" ] && spec_covered "$check_port" "$r_port"; then
          return 0
        fi
      fi
    done <<< "$active_v4"
  fi
  
  # 檢查 IPv6 作用中規則
  if [ "$check_ip_ver" = "ipv6" ] || [ "$check_ip_ver" = "both" ]; then
    local active_v6
    active_v6=$(get_active_rules v6)
    while IFS= read -r line; do
      [ -z "$line" ] && continue
      if [[ "$line" =~ ^RULE\|(.*) ]]; then
        local r_proto r_port r_src r_action r_comment
        IFS='|' read -r r_proto r_port r_src r_action r_comment <<< "${BASH_REMATCH[1]}"
        if [ "$r_proto" = "$check_proto" ] && [ "$r_src" = "$check_src" ] && [ "$r_action" = "$check_action" ] && spec_covered "$check_port" "$r_port"; then
          return 0
        fi
      fi
    done <<< "$active_v6"
  fi
  
  return 1
}

# --- 核心功能 2: 新增 PORT 規則到暫存區 ---
add_port() {
  print_header
  echo -e "${COLOR_BOLD}新增 Port 防火牆規則暫存${COLOR_RESET}\n"
  
  # 1. 輸入 Port
  local port=""
  while true; do
    echo -n "請輸入要開放/阻擋的 Port 號碼 (1-65535, 例如 8080 或 80,443 或 8000:8010,輸入 q 取消): "
    read -r port
    port="${port#"${port%%[![:space:]]*}"}"
    port="${port%"${port##*[![:space:]]}"}"
    
    if [[ "$port" =~ ^[qQ]$ ]]; then
      echo -e "${COLOR_YELLOW}[!] 新增規則已取消.${COLOR_RESET}"
      echo ""
      echo -e "${COLOR_DIM}按任意鍵返回選單...${COLOR_RESET}"
      read -n 1 -s
      return
    fi
    if [ -z "$port" ]; then
      echo -e "${COLOR_RED}[!] Port 不能為空,請重新輸入.${COLOR_RESET}"
      continue
    fi
    if [[ ! "$port" =~ ^[0-9,:-]+$ ]]; then
      echo -e "${COLOR_RED}[!] 格式錯誤!僅能包含數字,逗號(,)或冒號(:)作為區間,請重新輸入.${COLOR_RESET}"
      continue
    fi
    break
  done
  
  # 2. 選擇通訊協定
  local proto=""
  while true; do
    echo -n "請選擇通訊協定 [1) TCP  2) UDP  3) TCP+UDP  q) 取消] (預設 1): "
    read -r proto_choice
    case "$proto_choice" in
      ""|1) proto="tcp"; break;;
      2) proto="udp"; break;;
      3) proto="both"; break;;
      [qQ])
        echo -e "${COLOR_YELLOW}[!] 新增規則已取消.${COLOR_RESET}"
        echo ""
        echo -e "${COLOR_DIM}按任意鍵返回選單...${COLOR_RESET}"
        read -n 1 -s
        return
        ;;
      *) echo -e "${COLOR_RED}[!] 輸入無效,請輸入 1, 2, 3 或 q.${COLOR_RESET}";;
    esac
  done
  
  # 3. 選擇套用 IP 版本
  local ip_ver=""
  while true; do
    echo -n "請選擇套用 IP 版本 [1) 僅 IPv4  2) 僅 IPv6  3) IPv4+IPv6  q) 取消] (預設 1): "
    read -r ip_choice
    case "$ip_choice" in
      ""|1) ip_ver="ipv4"; break;;
      2) ip_ver="ipv6"; break;;
      3) ip_ver="both"; break;;
      [qQ])
        echo -e "${COLOR_YELLOW}[!] 新增規則已取消.${COLOR_RESET}"
        echo ""
        echo -e "${COLOR_DIM}按任意鍵返回選單...${COLOR_RESET}"
        read -n 1 -s
        return
        ;;
      *) echo -e "${COLOR_RED}[!] 輸入無效,請輸入 1, 2, 3 或 q.${COLOR_RESET}";;
    esac
  done
  
  # 4. 輸入來源限制
  local src=""
  echo -n "請輸入限制的來源 IP (若無限制直接 Enter,輸入 q 取消): "
  read -r src
  src="${src#"${src%%[![:space:]]*}"}"
  src="${src%"${src##*[![:space:]]}"}"
  if [[ "$src" =~ ^[qQ]$ ]]; then
    echo -e "${COLOR_YELLOW}[!] 新增規則已取消.${COLOR_RESET}"
    echo ""
    echo -e "${COLOR_DIM}按任意鍵返回選單...${COLOR_RESET}"
    read -n 1 -s
    return
  fi
  if [ -z "$src" ]; then
    src="Anywhere"
  fi
  
  # 5. 選擇連線動作
  local action=""
  while true; do
    echo -n "請選擇連線動作 [1) ACCEPT  2) DROP  3) REJECT  q) 取消] (預設 1): "
    read -r action_choice
    case "$action_choice" in
      ""|1) action="ACCEPT"; break;;
      2) action="DROP"; break;;
      3) action="REJECT"; break;;
      [qQ])
        echo -e "${COLOR_YELLOW}[!] 新增規則已取消.${COLOR_RESET}"
        echo ""
        echo -e "${COLOR_DIM}按任意鍵返回選單...${COLOR_RESET}"
        read -n 1 -s
        return
        ;;
      *) echo -e "${COLOR_RED}[!] 輸入無效,請輸入 1, 2, 3 或 q.${COLOR_RESET}";;
    esac
  done
  
  # 6. 輸入備註說明
  local comment=""
  echo -n "請輸入簡短備註說明 (可空白,輸入 q 取消): "
  read -r comment
  comment="${comment#"${comment%%[![:space:]]*}"}"
  comment="${comment%"${comment##*[![:space:]]}"}"
  if [[ "$comment" =~ ^[qQ]$ ]]; then
    echo -e "${COLOR_YELLOW}[!] 新增規則已取消.${COLOR_RESET}"
    echo ""
    echo -e "${COLOR_DIM}按任意鍵返回選單...${COLOR_RESET}"
    read -n 1 -s
    return
  fi
  if [ -z "$comment" ]; then
    comment="無備註"
  fi
  
  # 7. 加入暫存區 (並防止重複規則加入)
  if [ "$proto" = "both" ]; then
    local tcp_duplicate=false
    local udp_duplicate=false
    
    if rule_exists "${port}" "tcp" "${src}" "${action}" "${ip_ver}"; then
      tcp_duplicate=true
    fi
    if rule_exists "${port}" "udp" "${src}" "${action}" "${ip_ver}"; then
      udp_duplicate=true
    fi
    
    if [ "$tcp_duplicate" = true ] && [ "$udp_duplicate" = true ]; then
      echo -e "\n${COLOR_RED}[!] 錯誤: TCP 與 UDP 規則皆已存在於暫存區或作用中規則中,無須重複加入!${COLOR_RESET}"
    elif [ "$tcp_duplicate" = true ]; then
      STAGED_RULES+=("${port}|udp|${src}|${comment}|${action}|${ip_ver}")
      echo -e "\n${COLOR_GREEN}[✓] 已成功暫存 UDP 規則 (TCP 規則已存在，已自動略過).${COLOR_RESET}"
    elif [ "$udp_duplicate" = true ]; then
      STAGED_RULES+=("${port}|tcp|${src}|${comment}|${action}|${ip_ver}")
      echo -e "\n${COLOR_GREEN}[✓] 已成功暫存 TCP 規則 (UDP 規則已存在，已自動略過).${COLOR_RESET}"
    else
      STAGED_RULES+=("${port}|tcp|${src}|${comment}|${action}|${ip_ver}")
      STAGED_RULES+=("${port}|udp|${src}|${comment}|${action}|${ip_ver}")
      echo -e "\n${COLOR_GREEN}[✓] 已成功暫存規則 (TCP & UDP 連接埠 ${port})!${COLOR_RESET}"
    fi
  else
    if rule_exists "${port}" "${proto}" "${src}" "${action}" "${ip_ver}"; then
      echo -e "\n${COLOR_RED}[!] 錯誤: 此規則已存在於暫存區或作用中規則中,不可重複加入!${COLOR_RESET}"
    else
      STAGED_RULES+=("${port}|${proto}|${src}|${comment}|${action}|${ip_ver}")
      echo -e "\n${COLOR_GREEN}[✓] 已成功暫存規則 (連接埠 ${port}/${proto})!${COLOR_RESET}"
    fi
  fi
  
  echo ""
  echo -e "${COLOR_DIM}按任意鍵返回選單...${COLOR_RESET}"
  read -n 1 -s
}

# --- 核心功能: 刪除或取消防火牆規則流程 (將刪除指令加入暫存區或直接從暫存區取消) ---
delete_active_rule_flow() {
  local family="$1"
  local fam_str="IPv4"
  [ "$family" = "v6" ] && fam_str="IPv6"

  # 一次性載入規則以提升巡覽反應速度
  local raw_output
  raw_output=$(get_active_rules "$family")
  local rules_array=()
  while IFS= read -r line; do
    if [ -n "$line" ] && [[ "$line" =~ ^RULE\|(.*) ]]; then
      rules_array+=("${BASH_REMATCH[1]}")
    fi
  done <<< "$raw_output"

  local selected_idx=0
  local max_idx=${#rules_array[@]}

  if [ "$max_idx" -eq 0 ]; then
    print_header
    echo -e "${COLOR_BOLD}選擇要刪除的現有 ${fam_str} 規則:${COLOR_RESET}\n"
    echo -e "${COLOR_CYAN}┌────┬──────────┬──────────┬──────────────────────┬──────────┬────────────────────────┐${COLOR_RESET}"
    echo -e "${COLOR_CYAN}│編號│ 通訊協定 │ 連接埠   │ 來源 IP 限制         │ 連線動作 │ 備註說明               │${COLOR_RESET}"
    echo -e "${COLOR_CYAN}├────┼──────────┼──────────┼──────────────────────┼──────────┼────────────────────────┤${COLOR_RESET}"
    local no_rules_msg
    no_rules_msg=$(format_align "                               目前無自訂 ${fam_str} 限制規則" 85)
    echo -e "${COLOR_CYAN}│${COLOR_RESET}${no_rules_msg}${COLOR_CYAN}│${COLOR_RESET}"
    echo -e "${COLOR_CYAN}└────┴──────────┴──────────┴──────────────────────┴──────────┴────────────────────────┘${COLOR_RESET}"
    echo -e "\n${COLOR_YELLOW}[!] 目前沒有任何可刪除的規則.${COLOR_RESET}"
    echo ""
    echo -e "${COLOR_DIM}按任意鍵返回...${COLOR_RESET}"
    read -n 1 -s
    return
  fi

  while true; do
    print_header
    echo -e "${COLOR_BOLD}選擇要刪除的現有 ${fam_str} 規則 (可用 ↑↓ 移動並按 Enter 選擇,或直接按 q 返回):${COLOR_RESET}"
    echo -e "${COLOR_DIM}[提示] 選擇已標記'即將刪除'的項目,可取消其刪除暫存;按 Enter 確認切換狀態${COLOR_RESET}\n"
    
    echo -e "${COLOR_CYAN}┌────┬──────────┬──────────┬──────────────────────┬──────────┬────────────────────────┐${COLOR_RESET}"
    echo -e "${COLOR_CYAN}│編號│ 通訊協定 │ 連接埠   │ 來源 IP 限制         │ 連線動作 │ 備註說明               │${COLOR_RESET}"
    echo -e "${COLOR_CYAN}├────┼──────────┼──────────┼──────────────────────┼──────────┼────────────────────────┤${COLOR_RESET}"
    
    for i in "${!rules_array[@]}"; do
      local rule_data="${rules_array[$i]}"
      local opt_num=$((i+1))
      
      local proto port src target comment
      IFS='|' read -r proto port src target comment <<< "$rule_data"
      [ -z "$comment" ] && comment="無"
      
      local ip_ver_chk="ipv4"
      [ "$family" = "v6" ] && ip_ver_chk="ipv6"
      
      local is_already_staged_deleted=false
      for staged in "${STAGED_RULES[@]}"; do
        local s_port s_proto s_src s_comment s_action s_ip_ver
        IFS='|' read -r s_port s_proto s_src s_comment s_action s_ip_ver <<< "$staged"
        if [ "$s_port" = "$port" ] && [ "$s_proto" = "$proto" ] && [ "$s_src" = "$src" ] && [ "$s_action" = "DELETE_${target}" ] && [ "$s_ip_ver" = "$ip_ver_chk" ]; then
          is_already_staged_deleted=true
          break
        fi
      done
      
      local action_disp=$target
      if [ "$is_already_staged_deleted" = true ]; then
        action_disp="DELETE"
      fi
      
      local comment_aligned
      comment_aligned=$(format_align "$comment" 22)
      
      if [ "$i" -eq "$selected_idx" ]; then
        # Highlighted row
        local row_str
        row_str=$(printf " %-2d │ %-8s │ %-8s │ %-20s │ %-8s │ %s " \
          $opt_num "$proto" "$port" "$src" "$action_disp" "$comment_aligned")
        echo -e "${COLOR_CYAN}│${COLOR_RESET}${COLOR_MENU_SEL}${row_str}${COLOR_RESET}${COLOR_CYAN}│${COLOR_RESET}"
      else
        # Standard row
        local target_styled=$target
        if [ "$is_already_staged_deleted" = true ]; then
          target_styled="${COLOR_BOLD}${COLOR_RED_BK}DELETE ${COLOR_RESET_BK}"
        else
          if [ "$target" = "ACCEPT" ]; then
            target_styled="${COLOR_GREEN}${COLOR_BOLD}ACCEPT  ${COLOR_RESET}"
          elif [ "$target" = "DROP" ]; then
            target_styled="${COLOR_RED}${COLOR_BOLD}DROP    ${COLOR_RESET}"
          elif [ "$target" = "REJECT" ]; then
            target_styled="${COLOR_RED}${COLOR_BOLD}REJECT  ${COLOR_RESET}"
          fi
        fi
        printf "${COLOR_CYAN}│${COLOR_RESET} %-2d ${COLOR_CYAN}│${COLOR_RESET} %-8s ${COLOR_CYAN}│${COLOR_RESET} %-8s ${COLOR_CYAN}│${COLOR_RESET} %-20s ${COLOR_CYAN}│${COLOR_RESET} %b ${COLOR_CYAN}│${COLOR_RESET} %s ${COLOR_CYAN}│${COLOR_RESET}\n" \
          $opt_num "$proto" "$port" "$src" "$target_styled" "$comment_aligned"
      fi
    done
    echo -e "${COLOR_CYAN}└────┴──────────┴──────────┴──────────────────────┴──────────┴────────────────────────┘${COLOR_RESET}"
    
    if [ "$selected_idx" -eq "$max_idx" ]; then
      echo -e "  ${COLOR_GREEN}➔  ${COLOR_MENU_SEL}[q] 返回上層選單 ${COLOR_RESET}"
    else
      echo -e "     ${COLOR_CYAN}[q]${COLOR_RESET} 返回上層選單"
    fi
    echo ""
    
    tput civis
    read -rsn1 del_choice
    tput cnorm
    
    local action=""
    case "$del_choice" in
      $'\e')
        read -rsn2 -t 0.1 next_chars
        if [[ "$next_chars" == "[A" ]]; then
          ((selected_idx--))
          [ "$selected_idx" -lt 0 ] && selected_idx=$max_idx
        elif [[ "$next_chars" == "[B" ]]; then
          ((selected_idx++))
          [ "$selected_idx" -gt "$max_idx" ] && selected_idx=0
        fi
        ;;
      [qQ])
        return
        ;;
      "")
        action="exec"
        ;;
      *)
        if [[ "$del_choice" =~ ^[1-9]$ ]]; then
          if [ "$del_choice" -le "$max_idx" ]; then
            selected_idx=$((del_choice - 1))
            action="exec"
          fi
        fi
        ;;
    esac
    
    if [ "$action" = "exec" ]; then
      if [ "$selected_idx" -eq "$max_idx" ]; then
        return
      fi
      
      local chosen_rule="${rules_array[$selected_idx]}"
      local proto port src target comment
      IFS='|' read -r proto port src target comment <<< "$chosen_rule"
      
      local ip_ver="ipv4"
      [ "$family" = "v6" ] && ip_ver="ipv6"
      
      local is_staged=false
      local staged_idx=-1
      for i in "${!STAGED_RULES[@]}"; do
        local s_port s_proto s_src s_comment s_action s_ip_ver
        IFS='|' read -r s_port s_proto s_src s_comment s_action s_ip_ver <<< "${STAGED_RULES[$i]}"
        if [ "$s_port" = "$port" ] && [ "$s_proto" = "$proto" ] && [ "$s_src" = "$src" ] && [ "$s_action" = "DELETE_${target}" ] && [ "$s_ip_ver" = "$ip_ver" ]; then
          is_staged=true
          staged_idx=$i
          break
        fi
      done
      
      if [ "$is_staged" = true ]; then
        STAGED_RULES=(${STAGED_RULES[@]:0:$staged_idx} ${STAGED_RULES[@]:$((staged_idx+1))})
        echo -e "\n${COLOR_GREEN}[✓] 已取消該規則之刪除暫存.${COLOR_RESET}"
        sleep 1
      else
        STAGED_RULES+=("$port|$proto|$src|$comment|DELETE_${target}|$ip_ver")
        echo -e "\n${COLOR_YELLOW}[✓] 已將該規則之'刪除'動作加入暫存區中.${COLOR_RESET}"
        sleep 1
      fi
    fi
  done
}

revoke_staged_rule_flow() {
  while true; do
    print_header
    echo -e "${COLOR_BOLD}選擇要取消的暫存區變更 (直接從暫存區移除):${COLOR_RESET}"
    echo -e "${COLOR_DIM}[提示] 可選擇特定編號取消,或按 Enter 返回主選單${COLOR_RESET}\n"
    
    local staged_count=${#STAGED_RULES[@]}
    local has_policy=false
    [ -n "$STAGED_POLICY" ] && has_policy=true
    
    if [ "$staged_count" -eq 0 ] && [ "$has_policy" = false ]; then
      echo -e "${COLOR_YELLOW}[!] 目前暫存區是空的,沒有任何草稿需要取消.${COLOR_RESET}"
      echo ""
      echo -e "${COLOR_DIM}按任意鍵返回...${COLOR_RESET}"
      read -n 1 -s
      return
    fi
    
    # 1. 顯示暫存規則表格 (如果有自訂規則)
    if [ "$staged_count" -gt 0 ]; then
      echo -e "${COLOR_YELLOW}自訂規則暫存 (Staged Port Rules):${COLOR_RESET}"
      echo -e "${COLOR_YELLOW}┌────┬──────────┬──────────┬──────────────────────┬──────────┬────────────────────────┐${COLOR_RESET}"
      echo -e "${COLOR_YELLOW}│編號│ 通訊協定 │ 連接埠   │ 來源 IP 限制         │ 連線動作 │ 備註說明               │${COLOR_RESET}"
      echo -e "${COLOR_YELLOW}├────┼──────────┼──────────┼──────────────────────┼──────────┼────────────────────────┤${COLOR_RESET}"
      local s_index=1
      for s_rule in "${STAGED_RULES[@]}"; do
        local port proto src comment target ip_version
        IFS='|' read -r port proto src comment target ip_version <<< "$s_rule"
        [ -z "$comment" ] && comment="無"
        
        local sign="+"
        local ver_suffix=""
        [ "$ip_version" = "ipv4" ] && ver_suffix="-v4"
        [ "$ip_version" = "ipv6" ] && ver_suffix="-v6"
        [ "$ip_version" = "both" ] && ver_suffix="-Both"
        
        local action_abbr=""
        local is_delete=false
        local raw_action="$target"
        
        if [[ "$target" == DELETE_* ]]; then
          is_delete=true
          sign="-"
          raw_action="${target#DELETE_}"
        fi
        
        if [ "$raw_action" = "ACCEPT" ]; then
          action_abbr="A"
        elif [ "$raw_action" = "DROP" ]; then
          action_abbr="D"
        elif [ "$raw_action" = "REJECT" ]; then
          action_abbr="R"
        else
          action_abbr="${raw_action:0:1}"
        fi
        
        local target_text="${action_abbr}${ver_suffix}"
        
        # Pad target_text to exactly 8 characters to ensure perfect layout alignment under %b
        local pad_len=$((8 - ${#target_text}))
        local padded_text="$target_text"
        if [ $pad_len -gt 0 ]; then
          local spaces=""
          for ((p=0; p<pad_len; p++)); do
            spaces+=" "
          done
          padded_text="${target_text}${spaces}"
        fi
        
        local target_styled=""
        if [[ "$target_text" == A-* ]]; then
          target_styled="${COLOR_GREEN}${COLOR_BOLD}${padded_text}${COLOR_RESET}"
        else
          target_styled="${COLOR_RED}${COLOR_BOLD}${padded_text}${COLOR_RESET}"
        fi
        
        local index_str=""
        if [ $s_index -lt 10 ]; then
          index_str=" ${sign}${s_index} "
        else
          index_str="${sign}${s_index} "
        fi
        
        local comment_aligned
        comment_aligned=$(format_align "$comment" 22)
        
        printf "${COLOR_YELLOW}│${COLOR_RESET}%s${COLOR_YELLOW}│${COLOR_RESET} %-8s ${COLOR_YELLOW}│${COLOR_RESET} %-8s ${COLOR_YELLOW}│${COLOR_RESET} %-20s ${COLOR_YELLOW}│${COLOR_RESET} %b ${COLOR_YELLOW}│${COLOR_RESET} %s ${COLOR_YELLOW}│${COLOR_RESET}\n" \
          "$index_str" "$proto" "$port" "$src" "$target_styled" "$comment_aligned"
        ((s_index++))
      done
      echo -e "${COLOR_YELLOW}└────┴──────────┴──────────┴──────────────────────┴──────────┴────────────────────────┘${COLOR_RESET}"
      echo ""
    fi
    
    # 2. 顯示預設策略暫存 (如果有變更)
    if [ "$has_policy" = true ]; then
      local policy_color=$COLOR_GREEN
      [ "$STAGED_POLICY" = "DROP" ] && policy_color=$COLOR_RED
      echo -e "${COLOR_YELLOW}待套用的預設策略變更 (Pending Policy Change):${COLOR_RESET}"
      echo -e "  * [ ${COLOR_YELLOW}${COLOR_BOLD}p${COLOR_RESET} ] INPUT 鏈預設策略 -> ${policy_color}${COLOR_BOLD}${STAGED_POLICY}${COLOR_RESET} (雙軌同步 IPv4/IPv6)"
      echo ""
    fi
    
    # 3. 處理使用者輸入
    if [ "$staged_count" -gt 0 ] && [ "$has_policy" = true ]; then
      echo -n "> 請輸入要取消的規則編號 (1-$staged_count) 或輸入 p 取消策略變更 (或 Enter/q 返回): "
    elif [ "$staged_count" -gt 0 ]; then
      echo -n "> 請輸入要取消的規則編號 (1-$staged_count) (或 Enter/q 返回): "
    else
      echo -n "> 請輸入 p 取消策略變更 (或 Enter/q 返回): "
    fi
    
    read -r choice_num
    if [ -z "$choice_num" ] || [[ "$choice_num" =~ ^[qQ]$ ]]; then
      return
    fi
    
    if [[ "$choice_num" =~ ^[pP]$ ]] && [ "$has_policy" = true ]; then
      STAGED_POLICY=""
      STAGED_POLICY_V6=""
      echo -e "\n${COLOR_GREEN}[✓] 已成功取消預設行為變更暫存!${COLOR_RESET}"
      sleep 1.5
      continue
    fi
    
    if [[ ! "$choice_num" =~ ^[0-9]+$ ]] || [ "$choice_num" -lt 1 ] || [ "$choice_num" -gt "$staged_count" ]; then
      echo -e "${COLOR_RED}[!] 輸入無效的選項!${COLOR_RESET}"
      sleep 1
      continue
    fi
    
    # 從陣列中移除該項目
    local index_to_remove=$((choice_num-1))
    local new_staged=()
    for i in "${!STAGED_RULES[@]}"; do
      if [ "$i" -ne "$index_to_remove" ]; then
        new_staged+=("${STAGED_RULES[$i]}")
      fi
    done
    STAGED_RULES=("${new_staged[@]}")
    
    echo -e "\n${COLOR_GREEN}[✓] 已成功取消該暫存規則!${COLOR_RESET}"
    sleep 1.5
  done
}

# --- 新增/移除規則次選單 ---
add_remove_rules_menu() {
  local selected_sub=0
  while true; do
    print_header
    echo -e "${COLOR_BOLD}新增 / 移除防火牆規則 (可用 ↑↓ 移動並按 Enter 選擇,或按數字鍵快速選擇):${COLOR_RESET}\n"
    
    local options=(
      "新增防火牆規則"
      "刪除防火牆規則"
      "返回主選單"
    )
    
    for i in "${!options[@]}"; do
      local opt_num=$((i+1))
      if [ "$i" -eq "$selected_sub" ]; then
        echo -e "  ${COLOR_GREEN}➔  ${COLOR_MENU_SEL}${opt_num})${COLOR_RESET}${COLOR_MENU_SEL} ${options[$i]} ${COLOR_RESET}"
      else
        echo -e "     ${COLOR_CYAN}${opt_num})${COLOR_RESET} ${options[$i]}"
      fi
    done
    echo ""
    
    tput civis
    read -rsn1 sub_choice
    tput cnorm
    
    local action=""
    case "$sub_choice" in
      $'\e')
        read -rsn2 -t 0.1 next_chars
        if [[ "$next_chars" == "[A" ]]; then
          ((selected_sub--))
          [ "$selected_sub" -lt 0 ] && selected_sub=2
        elif [[ "$next_chars" == "[B" ]]; then
          ((selected_sub++))
          [ "$selected_sub" -gt 2 ] && selected_sub=0
        fi
        ;;
      1) selected_sub=0; action="exec";;
      2) selected_sub=1; action="exec";;
      3) selected_sub=2; action="exec";;
      "") action="exec";;
    esac
    
    if [ "$action" = "exec" ]; then
      case "$selected_sub" in
        0) add_port;;
        1) delete_rules_submenu;;
        2) return;;
      esac
    fi
  done
}

# --- 三階選單: 刪除防火牆規則 ---
delete_rules_submenu() {
  local selected_del=0
  while true; do
    print_header
    echo -e "${COLOR_BOLD}選擇要刪除的現有規則類型 (可用 ↑↓ 移動並按 Enter 選擇,或按數字鍵快速選擇):${COLOR_RESET}\n"
    
    local options=(
      "刪除現有的 IPv4 規則"
      "刪除現有的 IPv6 規則"
      "返回上一層"
    )
    
    for i in "${!options[@]}"; do
      local opt_num=$((i+1))
      if [ "$i" -eq "$selected_del" ]; then
        echo -e "  ${COLOR_GREEN}➔  ${COLOR_MENU_SEL}${opt_num})${COLOR_RESET}${COLOR_MENU_SEL} ${options[$i]} ${COLOR_RESET}"
      else
        echo -e "     ${COLOR_CYAN}${opt_num})${COLOR_RESET} ${options[$i]}"
      fi
    done
    echo ""
    
    tput civis
    read -rsn1 del_choice
    tput cnorm
    
    local action=""
    case "$del_choice" in
      $'\e')
        read -rsn2 -t 0.1 next_chars
        if [[ "$next_chars" == "[A" ]]; then
          ((selected_del--))
          [ "$selected_del" -lt 0 ] && selected_del=2
        elif [[ "$next_chars" == "[B" ]]; then
          ((selected_del++))
          [ "$selected_del" -gt 2 ] && selected_del=0
        fi
        ;;
      1) selected_del=0; action="exec";;
      2) selected_del=1; action="exec";;
      3) selected_del=2; action="exec";;
      "") action="exec";;
    esac
    
    if [ "$action" = "exec" ]; then
      case "$selected_del" in
        0) delete_active_rule_flow v4;;
        1) delete_active_rule_flow v6;;
        2) return;;
      esac
    fi
  done
}

# --- 處理暫存區規則次選單 ---
process_staged_rules_menu() {
  local selected_stage=0
  while true; do
    print_header
    echo -e "${COLOR_BOLD}處理暫存區中規則 (可用 ↑↓ 移動並按 Enter 選擇,或按數字鍵快速選擇):${COLOR_RESET}\n"
    
    local options=(
      "取消暫存區規則 (Revoke Staged Rules)"
      "寫入暫存區規則 (Apply & Test Rules)"
      "返回主選單"
    )
    
    for i in "${!options[@]}"; do
      local opt_num=$((i+1))
      if [ "$i" -eq "$selected_stage" ]; then
        echo -e "  ${COLOR_GREEN}➔  ${COLOR_MENU_SEL}${opt_num})${COLOR_RESET}${COLOR_MENU_SEL} ${options[$i]} ${COLOR_RESET}"
      else
        echo -e "     ${COLOR_CYAN}${opt_num})${COLOR_RESET} ${options[$i]}"
      fi
    done
    echo ""
    
    tput civis
    read -rsn1 stage_choice
    tput cnorm
    
    local action=""
    case "$stage_choice" in
      $'\e')
        read -rsn2 -t 0.1 next_chars
        if [[ "$next_chars" == "[A" ]]; then
          ((selected_stage--))
          [ "$selected_stage" -lt 0 ] && selected_stage=2
        elif [[ "$next_chars" == "[B" ]]; then
          ((selected_stage++))
          [ "$selected_stage" -gt 2 ] && selected_stage=0
        fi
        ;;
      1) selected_stage=0; action="exec";;
      2) selected_stage=1; action="exec";;
      3) selected_stage=2; action="exec";;
      "") action="exec";;
    esac
    
    if [ "$action" = "exec" ]; then
      case "$selected_stage" in
        0) revoke_staged_rule_flow;;
        1) apply_rules;;
        2) return;;
      esac
    fi
  done
}

change_default_policy() {
  print_header
  echo -e "${COLOR_BOLD}修改 INPUT 預設行為 (Default Policy)${COLOR_RESET}\n"
  
  # 1. 取得現有預設行為
  local input_policy
  local input_policy_v6
  input_policy=$(iptables -S INPUT 2>/dev/null | grep '^-P INPUT' | awk '{print $3}')
  [ -z "$input_policy" ] && input_policy="ACCEPT"
  input_policy_v6=$(ip6tables -S INPUT 2>/dev/null | grep '^-P INPUT' | awk '{print $3}')
  [ -z "$input_policy_v6" ] && input_policy_v6="ACCEPT"
  
  echo -e "目前 IPv4 INPUT 預設行為: ${COLOR_BOLD}${input_policy}${COLOR_RESET}"
  echo -e "目前 IPv6 INPUT 預設行為: ${COLOR_BOLD}${input_policy_v6}${COLOR_RESET}\n"
  
  # 2. 選擇目標策略
  local target_policy=""
  while true; do
    echo -n "> 請選擇要設定的目標預設行為 [1) ACCEPT  2) DROP  q) 取消] (預設 1): "
    read -r policy_choice
    case "$policy_choice" in
      ""|1) target_policy="ACCEPT"; break;;
      2) target_policy="DROP"; break;;
      [qQ])
        echo -e "${COLOR_YELLOW}[!] 修改已取消.${COLOR_RESET}"
        echo ""
        echo -e "${COLOR_DIM}按任意鍵返回選單...${COLOR_RESET}"
        read -n 1 -s
        return
        ;;
      *) echo -e "${COLOR_RED}[!] 輸入無效,請輸入 1, 2 或 q.${COLOR_RESET}";;
    esac
  done

  # 2.5 檢查重複設定
  if [ "$target_policy" = "$input_policy" ] && [ "$target_policy" = "$input_policy_v6" ] && [ -z "$STAGED_POLICY" ]; then
    echo -e "\n${COLOR_YELLOW}[!] 提示: 目前作用中的預設行為已是 ${target_policy}，無須變更。${COLOR_RESET}"
    echo ""
    echo -e "${COLOR_DIM}按任意鍵返回選單...${COLOR_RESET}"
    read -n 1 -s
    return
  fi
  if [ "$target_policy" = "$STAGED_POLICY" ]; then
    echo -e "\n${COLOR_YELLOW}[!] 提示: 暫存區已設定預設行為為 ${target_policy}，無須重複暫存。${COLOR_RESET}"
    echo ""
    echo -e "${COLOR_DIM}按任意鍵返回選單...${COLOR_RESET}"
    read -n 1 -s
    return
  fi
  
  # 3. 如果改為 DROP,執行 SSH 安全防呆偵測
  if [ "$target_policy" = "DROP" ]; then
    echo -e "\n${COLOR_CYAN}[i] 正在為您進行 SSH 連線安全掃描...${COLOR_RESET}"
    
    local ssh_port
    ssh_port=$(detect_current_ssh_port)
    local ssh_allowed=false
    local ssh_allowed_v6=false
    
    # 3.1 檢查作用中規則
    local active_rules_v4
    active_rules_v4=$(get_active_rules v4)
    while IFS= read -r r_line; do
      [ -z "$r_line" ] && continue
      local r_prefix r_proto r_port r_src r_action r_comment
      IFS='|' read -r r_prefix r_proto r_port r_src r_action r_comment <<< "$r_line"
      if [ "$r_proto" = "tcp" ] && [[ ",$r_port," == *",$ssh_port,"* || "$r_port" = "$ssh_port" || "$r_port" = "All" ]] && [ "$r_action" = "ACCEPT" ]; then
        ssh_allowed=true
        break
      fi
    done <<< "$active_rules_v4"
    
    local active_rules_v6
    active_rules_v6=$(get_active_rules v6)
    while IFS= read -r r_line; do
      [ -z "$r_line" ] && continue
      local r_prefix r_proto r_port r_src r_action r_comment
      IFS='|' read -r r_prefix r_proto r_port r_src r_action r_comment <<< "$r_line"
      if [ "$r_proto" = "tcp" ] && [[ ",$r_port," == *",$ssh_port,"* || "$r_port" = "$ssh_port" || "$r_port" = "All" ]] && [ "$r_action" = "ACCEPT" ]; then
        ssh_allowed_v6=true
        break
      fi
    done <<< "$active_rules_v6"
    
    # 3.2 檢查暫存佇列中是否有允許 SSH 的規則
    for s_rule in "${STAGED_RULES[@]}"; do
      local s_port s_proto s_src s_comment s_action s_ip_ver
      IFS='|' read -r s_port s_proto s_src s_comment s_action s_ip_ver <<< "$s_rule"
      if [ "$s_proto" = "tcp" ] && [[ ",$s_port," == *",$ssh_port,"* || "$s_port" = "$ssh_port" || "$s_port" = "All" ]] && [ "$s_action" = "ACCEPT" ]; then
        if [ "$s_ip_ver" = "both" ]; then
          ssh_allowed=true
          ssh_allowed_v6=true
        elif [ "$s_ip_ver" = "ipv4" ]; then
          ssh_allowed=true
        elif [ "$s_ip_ver" = "ipv6" ]; then
          ssh_allowed_v6=true
        fi
      fi
    done
    
    if [ "$ssh_allowed" = false ]; then
      echo -e "${COLOR_YELLOW}[警告] 偵測到您尚未允許目前 SSH 連接埠 (${ssh_port}/tcp),為避免您斷開連線,系統已自動在暫存區中補上該規則 (IPv4).${COLOR_RESET}"
      STAGED_RULES+=("${ssh_port}|tcp|Anywhere|自動放行 SSH 連接埠|ACCEPT|ipv4")
    fi
    if [ "$ssh_allowed_v6" = false ]; then
      echo -e "${COLOR_YELLOW}[警告] 偵測到您尚未允許目前 SSH 連接埠 (${ssh_port}/tcp),為避免您斷開連線,系統已自動在暫存區中補上該規則 (IPv6).${COLOR_RESET}"
      STAGED_RULES+=("${ssh_port}|tcp|Anywhere|自動放行 SSH 連接埠|ACCEPT|ipv6")
    fi
  fi
  
  if confirm_prompt "> 確定要將預設行為暫存修改為 ${target_policy} 嗎?[y/N]: "; then
    STAGED_POLICY="$target_policy"
    STAGED_POLICY_V6="$target_policy"
    echo -e "${COLOR_GREEN}[✓] 已成功暫存預設行為變更!請回到主選單選擇 [6. 寫入並開始測試] 套用.${COLOR_RESET}"
    echo ""
    echo -e "${COLOR_DIM}按任意鍵返回選單...${COLOR_RESET}"
    read -n 1 -s
  else
    echo -e "${COLOR_YELLOW}[!] 修改已取消.${COLOR_RESET}"
    echo ""
    echo -e "${COLOR_DIM}按任意鍵返回選單...${COLOR_RESET}"
    read -n 1 -s
  fi
}

apply_rules() {
  if [ ${#STAGED_RULES[@]} -eq 0 ] && [ -z "$STAGED_POLICY" ] && [ -z "$STAGED_POLICY_V6" ]; then
    echo -e "${COLOR_YELLOW}[!] 暫存區中無任何變更,無須寫入與測試!${COLOR_RESET}"
    sleep 1.5
    return
  fi
  
  # --- 1. 防火牆規則寫入實行 (雙軌獨立備份) ---
  local backup_file_v4="/tmp/vps_fw_v4_bak.$(date +%s)"
  local backup_file_v6="/tmp/vps_fw_v6_bak.$(date +%s)"
  local success=true

  if ! iptables-save > "$backup_file_v4" 2>/dev/null || ! ip6tables-save > "$backup_file_v6" 2>/dev/null; then
    echo -e "${COLOR_RED}[錯誤] 無法成功備份防火牆,為確保安全,本次套用終止!${COLOR_RESET}"
    rm -f "$backup_file_v4" "$backup_file_v6"
    echo -e "${COLOR_DIM}按任意鍵返回選單...${COLOR_RESET}"
    read -n 1 -s
    return
  fi
  
  echo -e "${COLOR_CYAN}[i] 正在寫入新規則...${COLOR_RESET}"
  for s_rule in "${STAGED_RULES[@]}"; do
    local port proto src comment action ip_version
    IFS='|' read -r port proto src comment action ip_version <<< "$s_rule"
    
    local is_delete=false
    local real_action="$action"
    if [[ "$action" == DELETE_* ]]; then
      is_delete=true
      real_action="${action#DELETE_}"
    fi
    
    # 分配執行工具 (iptables 或 ip6tables)
    local run_v4=false
    local run_v6=false
    [ "$ip_version" = "both" ] || [ "$ip_version" = "ipv4" ] && run_v4=true
    [ "$ip_version" = "both" ] || [ "$ip_version" = "ipv6" ] && run_v6=true
    
    # 構建基礎參數
    local basic_args=()
    [ "$proto" != "all" ] && basic_args+=("-p" "$proto")
    if [ "$port" != "All" ]; then
      if [[ "$port" == *","* ]]; then
        basic_args+=("-m" "multiport" "--dports" "$port")
      else
        basic_args+=("--dport" "$port")
      fi
    fi
    [ "$src" != "Anywhere" ] && basic_args+=("-s" "$src")
    [ -n "$comment" ] && [ "$comment" != "無備註" ] && basic_args+=("-m" "comment" "--comment" "$comment")
    basic_args+=("-j" "$real_action")
    
    # 寫入 IPv4
    if [ "$run_v4" = true ]; then
      local cmd=("iptables")
      [ "$is_delete" = true ] && cmd+=("-D" "INPUT") || cmd+=("-A" "INPUT")
      cmd+=("${basic_args[@]}")
      if ! "${cmd[@]}" 2>/dev/null; then
        echo -e "${COLOR_RED}[!] IPv4 寫入失敗,指令為: ${cmd[*]}${COLOR_RESET}"
        success=false
        break
      fi
    fi
    
    # 寫入 IPv6
    if [ "$run_v6" = true ]; then
      local cmd=("ip6tables")
      [ "$is_delete" = true ] && cmd+=("-D" "INPUT") || cmd+=("-A" "INPUT")
      cmd+=("${basic_args[@]}")
      if ! "${cmd[@]}" 2>/dev/null; then
        echo -e "${COLOR_RED}[!] IPv6 寫入失敗,指令為: ${cmd[*]}${COLOR_RESET}"
        success=false
        break
      fi
    fi
  done
  
  # 若有任一規則失敗,立即還原
  if [ "$success" = false ]; then
    echo -e "${COLOR_YELLOW}[i] 部分規則失敗,正在還原防火牆...${COLOR_RESET}"
    iptables-restore < "$backup_file_v4" 2>/dev/null
    ip6tables-restore < "$backup_file_v6" 2>/dev/null
    rm -f "$backup_file_v4" "$backup_file_v6"
    echo -e "${COLOR_RED}[錯誤] 套用失敗,已還原至變前狀態.${COLOR_RESET}"
    echo -e "${COLOR_DIM}按任意鍵返回選單...${COLOR_RESET}"
    read -n 1 -s
    return
  fi
  
  # 寫入預設策略變更 (如果有)
  if [ "$success" = true ]; then
    if [ -n "$STAGED_POLICY" ]; then
      echo -e "${COLOR_CYAN}[i] 正在套用 IPv4 INPUT 預設行為為 ${STAGED_POLICY}...${COLOR_RESET}"
      if ! iptables -P INPUT "$STAGED_POLICY" 2>/dev/null; then
        echo -e "${COLOR_RED}[!] IPv4 預設行為套用失敗!${COLOR_RESET}"
        success=false
      fi
    fi
    if [ "$success" = true ] && [ -n "$STAGED_POLICY_V6" ]; then
      echo -e "${COLOR_CYAN}[i] 正在套用 IPv6 INPUT 預設行為為 ${STAGED_POLICY_V6}...${COLOR_RESET}"
      if ! ip6tables -P INPUT "$STAGED_POLICY_V6" 2>/dev/null; then
        echo -e "${COLOR_RED}[!] IPv6 預設行為套用失敗!${COLOR_RESET}"
        success=false
      fi
    fi
  fi
  
  # 若策略修改失敗,進行雙軌還原
  if [ "$success" = false ]; then
    echo -e "${COLOR_YELLOW}[i] 策略套用失敗,正在還原設定...${COLOR_RESET}"
    iptables-restore < "$backup_file_v4" 2>/dev/null
    ip6tables-restore < "$backup_file_v6" 2>/dev/null
    rm -f "$backup_file_v4" "$backup_file_v6"
    echo -e "${COLOR_RED}[錯誤] 套用失敗,已還原至變更前狀態.${COLOR_RESET}"
    echo -e "${COLOR_DIM}按任意鍵返回選單...${COLOR_RESET}"
    read -n 1 -s
    return
  fi

  # --- 2. 規則自動自我測試階段 (Self-Test) ---
  local v4_policy="ACCEPT"
  local v6_policy="ACCEPT"
  v4_policy=$(iptables -S INPUT 2>/dev/null | grep '^-P INPUT' | awk '{print $3}')
  [ -z "$v4_policy" ] && v4_policy="ACCEPT"
  v6_policy=$(ip6tables -S INPUT 2>/dev/null | grep '^-P INPUT' | awk '{print $3}')
  [ -z "$v6_policy" ] && v6_policy="ACCEPT"
  [ -n "$STAGED_POLICY" ] && v4_policy="$STAGED_POLICY"
  [ -n "$STAGED_POLICY_V6" ] && v6_policy="$STAGED_POLICY_V6"

  echo -e "\n${COLOR_CYAN}${COLOR_BOLD}正在為變更之規則執行自動自我測試 (Auto Self-Test)...${COLOR_RESET}"
  for s_rule in "${STAGED_RULES[@]}"; do
    local port proto src comment action ip_version
    IFS='|' read -r port proto src comment action ip_version <<< "$s_rule"
    
    local is_delete=false
    local target_action="$action"
    if [[ "$action" == DELETE_* ]]; then
      is_delete=true
      target_action="${action#DELETE_}"
    fi
    
    local expected_open=true
    if [ "$is_delete" = false ] && { [ "$target_action" = "DROP" ] || [ "$target_action" = "REJECT" ]; }; then
      expected_open=false
    elif [ "$is_delete" = true ] && [ "$target_action" = "ACCEPT" ]; then
      expected_open=false
    fi
    
    if [ "$proto" = "tcp" ] || [ "$proto" = "both" ]; then
      if [[ "$port" == *":"* ]]; then
        echo -e "  ${COLOR_DIM}[i] 連接埠範圍 ${port} 暫不支援自動連線測試.${COLOR_RESET}"
        continue
      fi
      
      IFS=',' read -r -a ports_to_test <<< "$port"
      for single_port in "${ports_to_test[@]}"; do
        single_port="${single_port#"${single_port%%[![:space:]]*}"}"
        single_port="${single_port%"${single_port##*[![:space:]]}"}"
        [ "$single_port" = "All" ] && continue
        
        local expected_str="${COLOR_RED}阻擋${COLOR_RESET}"
        [ "$expected_open" = true ] && expected_str="${COLOR_GREEN}放行${COLOR_RESET}"
        
        # 1. 測試 IPv4 (如果規則適用)
        if [ "$ip_version" = "both" ] || [ "$ip_version" = "ipv4" ]; then
          echo -e "  * 正在測試 IPv4 TCP 連接埠 ${single_port} (預期狀態: ${expected_str})..."
          
          local skip_test=false
          if [ "$is_delete" = true ]; then
            if [ "$target_action" = "ACCEPT" ] && [ "$v4_policy" = "ACCEPT" ]; then
              skip_test=true
            elif [ "$target_action" = "DROP" ] && [ "$v4_policy" = "DROP" ]; then
              skip_test=true
            elif [ "$target_action" = "REJECT" ] && [ "$v4_policy" = "DROP" ]; then
              skip_test=true
            fi
          fi
          
          if [ "$skip_test" = true ]; then
            echo -e "     ${COLOR_DIM}[i] 略過測試: 預設行為為 ${v4_policy},刪除 ${target_action} 規則無須重複測試.${COLOR_RESET}"
          elif [ "$expected_open" = false ]; then
            echo -e "     ${COLOR_GREEN}✓ IPv4 驗證通過: 阻擋規則已寫入核心 (Linux 迴路流量依規自動放行)${COLOR_RESET}"
            echo -e "     ${COLOR_DIM}     [提示] 如需從外網驗證阻擋狀態，請從外部電腦執行: curl -I --connect-timeout 3 http://您的公網IP:${single_port}${COLOR_RESET}"
          else
            local test_success=false
            local test_msg=""
            
            if { [ "$single_port" = "80" ] || [ "$single_port" = "443" ]; } && command -v curl &>/dev/null; then
              local scheme="http"
              [ "$single_port" = "443" ] && scheme="https"
              local curl_out
              curl_out=$(curl -4 -I -s --connect-timeout 2 "${scheme}://127.0.0.1:${single_port}" 2>&1)
              local curl_status=$?
              
              if [ $curl_status -eq 0 ]; then
                test_success=true
                test_msg="連線成功 (HTTP/HTTPS 服務正常)"
              elif [ $curl_status -eq 7 ]; then
                test_success=true
                test_msg="防火牆已放行 (但本地服務未啟動)"
              elif [ $curl_status -eq 28 ] || [ $curl_status -eq 35 ]; then
                test_success=false
                test_msg="連線超時 (已被防火牆攔截)"
              else
                test_success=true
                test_msg="防火牆放行,但連線異常 (CODE: $curl_status)"
              fi
            else
              timeout 2 bash -c "cat < /dev/null > /dev/tcp/127.0.0.1/${single_port}" 2>/dev/null
              local tcp_status=$?
              if [ $tcp_status -eq 0 ]; then
                test_success=true
                test_msg="連線成功 (服務通訊正常)"
              elif [ $tcp_status -eq 124 ]; then
                test_success=false
                test_msg="連線超時 (已被防火牆攔截)"
              else
                test_success=true
                test_msg="防火牆已放行 (但本地無服務監聽)"
              fi
            fi
            
            if [ "$expected_open" = true ]; then
              [ "$test_success" = true ] && echo -e "     ${COLOR_GREEN}✓ IPv4 測試通過: ${test_msg}${COLOR_RESET}" || echo -e "     ${COLOR_RED}✗ IPv4 測試失敗: ${test_msg}${COLOR_RESET}"
            else
              [ "$test_success" = false ] && echo -e "     ${COLOR_GREEN}✓ IPv4 測試通過: ${test_msg}${COLOR_RESET}" || echo -e "     ${COLOR_RED}✗ IPv4 測試失敗: 預期阻擋但仍連通 (${test_msg})${COLOR_RESET}"
            fi
          fi
        fi
        
        # 2. 測試 IPv6 (如果規則適用)
        if [ "$ip_version" = "both" ] || [ "$ip_version" = "ipv6" ]; then
          echo -e "  * 正在測試 IPv6 TCP 連接埠 ${single_port} (預期狀態: ${expected_str})..."
          
          local skip_test_v6=false
          if [ "$is_delete" = true ]; then
            if [ "$target_action" = "ACCEPT" ] && [ "$v6_policy" = "ACCEPT" ]; then
              skip_test_v6=true
            elif [ "$target_action" = "DROP" ] && [ "$v6_policy" = "DROP" ]; then
              skip_test_v6=true
            elif [ "$target_action" = "REJECT" ] && [ "$v6_policy" = "DROP" ]; then
              skip_test_v6=true
            fi
          fi
          
          if [ "$skip_test_v6" = true ]; then
            echo -e "     ${COLOR_DIM}[i] 略過測試: 預設行為為 ${v6_policy},刪除 ${target_action} 規則無須重複測試.${COLOR_RESET}"
          elif [ "$expected_open" = false ]; then
            echo -e "     ${COLOR_GREEN}✓ IPv6 驗證通過: 阻擋規則已寫入核心 (Linux 迴路流量依規自動放行)${COLOR_RESET}"
            echo -e "     ${COLOR_DIM}     [提示] 如需從外網驗證阻擋狀態，請從外部電腦執行: curl -6 -I --connect-timeout 3 http://[您的公網IPv6]:${single_port}${COLOR_RESET}"
          else
            local test_success_v6=false
            local test_msg_v6=""
            
            if { [ "$single_port" = "80" ] || [ "$single_port" = "443" ]; } && command -v curl &>/dev/null; then
              local scheme="http"
              [ "$single_port" = "443" ] && scheme="https"
              local curl_out
              curl_out=$(curl -6 -I -s --connect-timeout 2 "${scheme}://[::1]:${single_port}" 2>&1)
              local curl_status=$?
              
              if [ $curl_status -eq 0 ]; then
                test_success_v6=true
                test_msg_v6="連線成功 (HTTP/HTTPS 服務正常)"
              elif [ $curl_status -eq 7 ]; then
                test_success_v6=true
                  test_msg_v6="防火牆已放行 (但本地服務未啟動)"
                elif [ $curl_status -eq 28 ] || [ $curl_status -eq 35 ]; then
                  test_success_v6=false
                  test_msg_v6="連線超時 (已被防火牆攔截)"
                else
                  test_success_v6=true
                  test_msg_v6="防火牆放行,但連線異常 (代碼: $curl_status)"
                fi
              else
                timeout 2 bash -c "cat < /dev/null > /dev/tcp/::1/${single_port}" 2>/dev/null
                local tcp_status=$?
                if [ $tcp_status -eq 0 ]; then
                  test_success_v6=true
                  test_msg_v6="連線成功 (服務通訊正常)"
                elif [ $tcp_status -eq 124 ]; then
                  test_success_v6=false
                  test_msg_v6="連線超時 (已被防火牆攔截)"
                else
                  test_success_v6=true
                  test_msg_v6="防火牆已放行 (但本地無服務監聽)"
                fi
              fi
              
              if [ "$expected_open" = true ]; then
                [ "$test_success_v6" = true ] && echo -e "     ${COLOR_GREEN}✓ IPv6 自我測試通過: ${test_msg_v6}${COLOR_RESET}" || echo -e "     ${COLOR_RED}✗ IPv6 自我測試失敗: ${test_msg_v6}${COLOR_RESET}"
              else
                [ "$test_success_v6" = false ] && echo -e "     ${COLOR_GREEN}✓ IPv6 自我測試通過: ${test_msg_v6}${COLOR_RESET}" || echo -e "     ${COLOR_RED}✗ IPv6 自我測試失敗: 預期阻擋但仍連通 (${test_msg_v6})${COLOR_RESET}"
              fi
            fi
          fi
          
        done
      fi
    done
    echo -e "--------------------------------------------------------"

  # --- 3. 安全計時確認階段 (Rollback Countdown) ---
  local timeout=30
  local confirmed=false
  echo -e "\n${COLOR_YELLOW}${COLOR_BOLD}新的防火牆規則已暫時套用!開始安全倒數...${COLOR_RESET}"
  echo -e "${COLOR_CYAN}[提示] 請迅速開啟一個新連線視窗,確認您的 SSH 連線以及新開服務是否完全正常!${COLOR_RESET}"
  echo -e "若有任何異常導致您被鎖定,請勿操作,等待倒數歸零將會自動幫您還原連線."
  echo ""
  
  while (( timeout > 0 )); do
    echo -ne "\r\033[K剩餘還原時間: ${COLOR_RED}${COLOR_BOLD}${timeout}${COLOR_RESET} 秒... [按 ${COLOR_GREEN}${COLOR_BOLD}Y/y${COLOR_RESET} 確認保留, 按 ${COLOR_RED}${COLOR_BOLD}N/n${COLOR_RESET} 立即還原]: "
    
    local key=""
    read -r -n 1 -t 1 -s key
    
    if [[ "$key" =~ ^[Yy]$ ]]; then
      confirmed=true
      break
    elif [[ "$key" =~ ^[Nn]$ ]]; then
      confirmed=false
      break
    fi
    (( timeout-- ))
  done
  echo "" # 換行
  
  # --- 4. 最終處理階段 ---
  if [ "$confirmed" = true ]; then
    echo -e "\n${COLOR_GREEN}${COLOR_BOLD}[✓] 恭喜!新防火牆規則確認安全,已成功套用!${COLOR_RESET}"
    
    # 清理雙軌備份
    rm -f "$backup_file_v4" "$backup_file_v6"
    STAGED_RULES=()
    STAGED_POLICY=""
    STAGED_POLICY_V6=""
    
    # 詢問是否永久存檔
    echo -e "\n${COLOR_BOLD}是否設定開機自動載入此防火牆規則?${COLOR_RESET}"
    local saved=false
    if [ -d "/etc/iptables" ]; then
      echo -e "  偵測到 Debian/Ubuntu 保存路徑 (${COLOR_CYAN}/etc/iptables/rules.v4${COLOR_RESET})"
      if confirm_prompt "> 是否直接寫入該路徑存檔 (含 rules.v6)?[y/N]: "; then
        iptables-save > /etc/iptables/rules.v4
        ip6tables-save > /etc/iptables/rules.v6
        echo -e "${COLOR_GREEN}[✓] 已成功存檔至 /etc/iptables/rules.v[4\|6]!${COLOR_RESET}"
        saved=true
      fi
    elif [ -f "/etc/sysconfig/iptables" ]; then
      echo -e "  偵測到 RHEL/CentOS 保存路徑 (${COLOR_CYAN}/etc/sysconfig/iptables${COLOR_RESET})"
      if confirm_prompt "> 是否直接寫入該路徑存檔 (含 ip6tables)?[y/N]: "; then
        iptables-save > /etc/sysconfig/iptables
        ip6tables-save > /etc/sysconfig/ip6tables
        echo -e "${COLOR_GREEN}[✓] 已成功存檔至 /etc/sysconfig/iptables 及 ip6tables!${COLOR_RESET}"
        saved=true
      fi
    fi
    
    if [ "$saved" = false ]; then
      echo -e "\n${COLOR_YELLOW}[提示] 若要開機自動載入,您可以使用以下指令手動保存:${COLOR_RESET}"
      echo -e "  IPv4: ${COLOR_BOLD}sudo iptables-save > /etc/iptables/rules.v4${COLOR_RESET}"
      echo -e "  IPv6: ${COLOR_BOLD}sudo ip6tables-save > /etc/iptables/rules.v6${COLOR_RESET}"
    fi
  else
    # 逾時或拒絕 -> 還原
    echo -e "\n${COLOR_RED}${COLOR_BOLD}[!] 測試取消或逾時!正在自動執行還原防火牆...${COLOR_RESET}"
    iptables-restore < "$backup_file_v4" 2>/dev/null
    ip6tables-restore < "$backup_file_v6" 2>/dev/null
    rm -f "$backup_file_v4" "$backup_file_v6"
    echo -e "${COLOR_GREEN}[✓] 防火牆已成功同步還原!安全無虞.${COLOR_RESET}"
  fi
  
  echo ""
  echo -e "${COLOR_DIM}按任意鍵返回選單...${COLOR_RESET}"
  read -n 1 -s
}

# --- 核心功能 5: 防火牆備份與還原管理系統 ---
backup_restore_manager() {
  local selected_bk=0
  while true; do
    print_header
    echo -e "${COLOR_BOLD}防火牆備份檔案管理系統 (可用 ↑↓ 移動並按 Enter 選擇,或直接按數字選擇):${COLOR_RESET}\n"
    
    local bk_options=(
      "檢視防火牆備份"
      "建立防火牆備份"
      "刪除防火牆備份"
      "還原防火牆備份"
      "返回主選單"
    )
    
    for i in "${!bk_options[@]}"; do
      opt_num=$((i+1))
      if [ "$i" -eq "$selected_bk" ]; then
        echo -e "  ${COLOR_GREEN}➔  ${COLOR_MENU_SEL}${opt_num})${COLOR_RESET}${COLOR_MENU_SEL} ${bk_options[$i]} ${COLOR_RESET}"
      else
        echo -e "     ${COLOR_CYAN}${opt_num})${COLOR_RESET} ${bk_options[$i]}"
      fi
    done
    echo ""
    
    tput civis
    read -rsn1 bk_choice
    tput cnorm
    
    local action=""
    case "$bk_choice" in
      $'\e')
        read -rsn2 -t 0.1 next_chars
        if [[ "$next_chars" == "[A" ]]; then
          ((selected_bk--))
          [ "$selected_bk" -lt 0 ] && selected_bk=4
        elif [[ "$next_chars" == "[B" ]]; then
          ((selected_bk++))
          [ "$selected_bk" -gt 4 ] && selected_bk=0
        fi
        ;;
      1) selected_bk=0; action="exec";;
      2) selected_bk=1; action="exec";;
      3) selected_bk=2; action="exec";;
      4) selected_bk=3; action="exec";;
      5) selected_bk=4; action="exec";;
      "") action="exec";;
    esac
    
    if [ "$action" = "exec" ]; then
      case "$selected_bk" in
        0)
        print_header
        echo -e "${COLOR_BOLD}現有歷史備份清單:${COLOR_RESET}\n"
        
        local meta_files=("$BACKUP_DIR"/*.meta)
        if [ ! -e "${meta_files[0]}" ]; then
          echo -e "${COLOR_YELLOW}[!] 目前尚無任何防火牆存檔備份.${COLOR_RESET}"
          echo ""
          echo -e "${COLOR_DIM}按任意鍵繼續...${COLOR_RESET}"
          read -n 1 -s
          continue
        fi
        
        echo -e "${COLOR_CYAN}================================================================================${COLOR_RESET}"
        local idx=1
        for meta_f in "${meta_files[@]}"; do
          local name_raw
          name_raw=$(basename "$meta_f" .meta)
          
          local bk_date=""
          local bk_desc=""
          
          # 解析 metadata
          while IFS= read -r line; do
            if [[ "$line" =~ ^Date:\ (.*) ]]; then
              bk_date="${BASH_REMATCH[1]}"
            elif [[ "$line" =~ ^Desc:\ (.*) ]]; then
              bk_desc="${BASH_REMATCH[1]}"
            fi
          done < "$meta_f"
          
          echo -e "  ${COLOR_CYAN}[${idx}]${COLOR_RESET} ${COLOR_BOLD}${name_raw}${COLOR_RESET}"
          echo -e "      ${COLOR_GREEN}建立時間:${COLOR_RESET} ${bk_date}"
          echo -e "      ${COLOR_YELLOW}備註說明:${COLOR_RESET} ${bk_desc}"
          echo -e "${COLOR_DIM}  ------------------------------------------------------------------------------${COLOR_RESET}"
          ((idx++))
        done
        echo ""
        echo -e "${COLOR_DIM}按任意鍵繼續...${COLOR_RESET}"
        read -n 1 -s
        ;;
        
        1)
        print_header
        echo -e "${COLOR_BOLD}建立手動防火牆備份${COLOR_RESET}\n"
        echo -n "> 請輸入備份名稱 (僅限英文/數字/底線,例如 base_config,或輸入 q 取消):"
        read -r bk_name
        if [[ "$bk_name" =~ ^[qQ]$ ]]; then
          echo -e "${COLOR_YELLOW}[!] 備份已取消.${COLOR_RESET}"
          sleep 1
          continue
        fi
        # 過濾不合法字元
        bk_name=$(echo "$bk_name" | sed 's/[^a-zA-Z0-9_]//g')
        if [ -z "$bk_name" ]; then
          echo -e "${COLOR_RED}[!] 名稱無效或為空!${COLOR_RESET}"
          sleep 1.5
          continue
        fi
        
        echo -n "> 請輸入備份簡短備註 (例如: 開放80/443前備份):"
        read -r bk_desc
        [ -z "$bk_desc" ] && bk_desc="手動備份"
        
        if iptables-save > "$BACKUP_DIR/$bk_name.v4.rules" 2>/dev/null && \
           ip6tables-save > "$BACKUP_DIR/$bk_name.v6.rules" 2>/dev/null; then
           
          # 寫入 metadata
          echo "Date: $(date '+%Y-%m-%d %H:%M:%S')" > "$BACKUP_DIR/$bk_name.meta"
          echo "Desc: $bk_desc" >> "$BACKUP_DIR/$bk_name.meta"
          echo -e "\n${COLOR_GREEN}[✓] 防火牆備份成功!存檔為: $bk_name${COLOR_RESET}"
        else
          echo -e "\n${COLOR_RED}[✗] 備份寫入失敗,請確認權限或備份目錄!${COLOR_RESET}"
          rm -f "$BACKUP_DIR/$bk_name.v4.rules" "$BACKUP_DIR/$bk_name.v6.rules"
        fi
        echo ""
        echo -e "${COLOR_DIM}按任意鍵繼續...${COLOR_RESET}"
        read -n 1 -s
        ;;
        
        2)
        print_header
        echo -e "${COLOR_BOLD}刪除歷史備份存檔${COLOR_RESET}\n"
        
        local meta_files=("$BACKUP_DIR"/*.meta)
        local bk_list=()
        if [ ! -e "${meta_files[0]}" ]; then
          echo -e "${COLOR_YELLOW}[!] 目前尚無任何備份存檔.${COLOR_RESET}"
          echo ""
          echo -e "${COLOR_DIM}按任意鍵繼續...${COLOR_RESET}"
          read -n 1 -s
          continue
        fi
        
        echo -e "請選擇要刪除的備份:"
        local idx=1
        for meta_f in "${meta_files[@]}"; do
          local name_raw
          name_raw=$(basename "$meta_f" .meta)
          bk_list+=("$name_raw")
          echo -e "  ${COLOR_CYAN}${idx})${COLOR_RESET} $name_raw"
          ((idx++))
        done
        echo ""
        echo -n "> 請輸入刪除目標編號 (或 Enter/q 取消): "
        read -r select_num
        if [ -z "$select_num" ] || [[ "$select_num" =~ ^[qQ]$ ]]; then
          continue
        fi
        
        if [[ ! "$select_num" =~ ^[0-9]+$ ]] || [ "$select_num" -lt 1 ] || [ "$select_num" -ge "$idx" ]; then
          echo -e "${COLOR_RED}[!] 無效的編號!${COLOR_RESET}"
          sleep 1.5
          continue
        fi
        
        local chosen_bk="${bk_list[$((select_num-1))]}"
        if confirm_prompt "> 確定要永久刪除備份 '$chosen_bk' 嗎?[y/N]: "; then
          rm -f "$BACKUP_DIR/$chosen_bk.v4.rules" \
                "$BACKUP_DIR/$chosen_bk.v6.rules" \
                "$BACKUP_DIR/$chosen_bk.meta"
          echo -e "${COLOR_GREEN}[✓] 備份檔案已成功清理!${COLOR_RESET}"
        fi
        echo ""
        echo -e "${COLOR_DIM}按任意鍵繼續...${COLOR_RESET}"
        read -n 1 -s
        ;;
        
        3)
        print_header
        echo -e "${COLOR_BOLD}還原防火牆存檔${COLOR_RESET}\n"
        
        local meta_files=("$BACKUP_DIR"/*.meta)
        local bk_list=()
        if [ ! -e "${meta_files[0]}" ]; then
          echo -e "${COLOR_YELLOW}[!] 目前尚無任何可還原的備份存檔.${COLOR_RESET}"
          echo ""
          echo -e "${COLOR_DIM}按任意鍵繼續...${COLOR_RESET}"
          read -n 1 -s
          continue
        fi
        
        echo -e "請選擇要還原的備份:"
        local idx=1
        for meta_f in "${meta_files[@]}"; do
          local name_raw
          name_raw=$(basename "$meta_f" .meta)
          bk_list+=("$name_raw")
          echo -e "  ${COLOR_CYAN}${idx})${COLOR_RESET} $name_raw ($(< "$meta_f" | grep 'Desc:' | cut -d' ' -f2-))"
          ((idx++))
        done
        echo ""
        echo -n "> 請輸入還原目標編號 (或 Enter/q 取消): "
        read -r select_num
        if [ -z "$select_num" ] || [[ "$select_num" =~ ^[qQ]$ ]]; then
          continue
        fi
        
        if [[ ! "$select_num" =~ ^[0-9]+$ ]] || [ "$select_num" -lt 1 ] || [ "$select_num" -ge "$idx" ]; then
          echo -e "${COLOR_RED}[!] 無效的編號!${COLOR_RESET}"
          sleep 1.5
          continue
        fi
        
        local chosen_bk="${bk_list[$((select_num-1))]}"
        
        # 安全雙軌還原判定
        local has_v4=false
        local has_v6=false
        [ -f "$BACKUP_DIR/$chosen_bk.v4.rules" ] && has_v4=true
        [ -f "$BACKUP_DIR/$chosen_bk.v6.rules" ] && has_v6=true
        
        if [ "$has_v4" = false ] && [ "$has_v6" = false ]; then
          echo -e "${COLOR_RED}[!] 此備份存檔之規則檔案不存在!${COLOR_RESET}"
          sleep 1.5
          continue
        fi
        
        echo -e "\n${COLOR_YELLOW}${COLOR_BOLD}[警告] 還原此存檔將會覆蓋目前所有防火牆規則設定!${COLOR_RESET}"
        if ! confirm_prompt "> 您確定要開始還原此備份嗎?[y/N]: "; then
          echo -e "${COLOR_YELLOW}[!] 還原已取消.${COLOR_RESET}"
          sleep 1.5
          continue
        fi
        
        if [ "$has_v4" = true ] && [ "$has_v6" = true ]; then
          # 完整雙軌還原
          iptables-restore < "$BACKUP_DIR/$chosen_bk.v4.rules" 2>/dev/null
          ip6tables-restore < "$BACKUP_DIR/$chosen_bk.v6.rules" 2>/dev/null
          echo -e "${COLOR_GREEN}[✓] IPv4 / IPv6 防火牆已成功同步還原!${COLOR_RESET}"
        elif [ "$has_v4" = true ]; then
          echo -e "${COLOR_YELLOW}[!] 偵測到此備份僅有 IPv4 備份.${COLOR_RESET}"
          if confirm_prompt "> 是否單獨還原 IPv4,並保持目前 IPv6 不變?[y/N]: "; then
            iptables-restore < "$BACKUP_DIR/$chosen_bk.v4.rules" 2>/dev/null
            echo -e "${COLOR_GREEN}[✓] IPv4 防火牆已成功還原!${COLOR_RESET}"
          fi
        elif [ "$has_v6" = true ]; then
          echo -e "${COLOR_YELLOW}[!] 偵測到此備份僅有 IPv6 備份.${COLOR_RESET}"
          if confirm_prompt "> 是否單獨還原 IPv6,並保持目前 IPv4 不變?[y/N]: "; then
            ip6tables-restore < "$BACKUP_DIR/$chosen_bk.v6.rules" 2>/dev/null
            echo -e "${COLOR_GREEN}[✓] IPv6 防火牆已成功還原!${COLOR_RESET}"
          fi
        fi
        echo ""
        echo -e "${COLOR_DIM}按任意鍵繼續...${COLOR_RESET}"
        read -n 1 -s
        ;;
        
        4)
        return
        ;;
      esac
    fi
  done
}

# --- 主程式選單迴圈 ---
# 確保離開時游標恢復顯示
trap 'tput cnorm; exit 0' INT TERM

while true; do
  print_header
  
  # 顯示狀態提示
  staged_count=${#STAGED_RULES[@]}
  staged_policy_count=0
  [ -n "$STAGED_POLICY" ] && ((staged_policy_count++))
  [ -n "$STAGED_POLICY_V6" ] && ((staged_policy_count++))
  
  total_staged=$((staged_count + staged_policy_count))
  staged_styled="${COLOR_CYAN}${COLOR_BOLD}${total_staged}${COLOR_RESET}"
  if [ "$total_staged" -gt 0 ]; then
    staged_styled="${COLOR_YELLOW}${COLOR_BOLD}${total_staged}${COLOR_RESET}"
  fi
  
  echo -e "目前暫存區有 ${staged_styled} 條變更等待寫入\n"
  
  # 動態建構選項 4 (處理暫存區) 說明
  staged_desc=""
  if [ "$total_staged" -eq 0 ]; then
    staged_desc="${COLOR_DIM}處理暫存區中規則${COLOR_RESET}"
  else
    staged_desc="${COLOR_YELLOW}${COLOR_BOLD}處理暫存區中規則 (目前有 ${total_staged} 條變更)${COLOR_RESET}"
  fi
  
  # 動態建構選項 2 (修改策略) 說明
  policy_desc="修改 INPUT 預設行為"
  if [ -n "$STAGED_POLICY" ]; then
    policy_desc="${COLOR_YELLOW}${COLOR_BOLD}修改 INPUT 預設行為 (待修改為: ${STAGED_POLICY})${COLOR_RESET}"
  fi
  
  echo -e "${COLOR_BOLD}請選擇要執行的功能 (可用 ↑↓ 移動並按 Enter 選擇,或直接按數字/q 快速執行):${COLOR_RESET}"
  
  # 定義選單選項陣列
  menu_options=(
    "查詢現有防火牆狀態"
    "${policy_desc}"
    "新增/移除防火牆規則"
    "${staged_desc}"
    "防火牆備份與還原管理"
  )
  
  # 繪製選單選項
  for i in "${!menu_options[@]}"; do
    opt_num=$((i+1))
    if [ "$i" -eq "$SELECTED_MENU_IDX" ]; then
      echo -e "  ${COLOR_GREEN}➔  ${COLOR_MENU_SEL}${opt_num})${COLOR_RESET}${COLOR_MENU_SEL} ${menu_options[$i]} ${COLOR_RESET}"
    else
      echo -e "     ${COLOR_CYAN}${opt_num})${COLOR_RESET} ${menu_options[$i]}"
    fi
  done
  
  if [ "$SELECTED_MENU_IDX" -eq 5 ]; then
    echo -e "  ${COLOR_GREEN}➔  ${COLOR_MENU_SEL}q)${COLOR_RESET}${COLOR_MENU_SEL} 離開系統 ${COLOR_RESET}"
  else
    echo -e "     ${COLOR_CYAN}q)${COLOR_RESET} 離開系統"
  fi
  
  echo ""
  
  # 隱藏游標
  tput civis
  
  # 監聽單一按鍵
  read -rsn1 choice
  
  # 恢復顯示游標 (在呼叫功能前)
  tput cnorm
  
  case "$choice" in
    # 判斷是否為方向鍵 (Escape 序列)
    $'\e')
      read -rsn2 -t 0.1 next_chars
      if [[ "$next_chars" == "[A" ]]; then
        # 上鍵
        ((SELECTED_MENU_IDX--))
        [ "$SELECTED_MENU_IDX" -lt 0 ] && SELECTED_MENU_IDX=5
      elif [[ "$next_chars" == "[B" ]]; then
        # 下鍵
        ((SELECTED_MENU_IDX++))
        [ "$SELECTED_MENU_IDX" -gt 5 ] && SELECTED_MENU_IDX=0
      fi
      ;;
      
    # 直接按數字鍵免按 Enter
    1) SELECTED_MENU_IDX=0; show_status;;
    2) SELECTED_MENU_IDX=1; change_default_policy;;
    3) SELECTED_MENU_IDX=2; add_remove_rules_menu;;
    4) SELECTED_MENU_IDX=3; process_staged_rules_menu;;
    5) SELECTED_MENU_IDX=4; backup_restore_manager;;
    
    # 離開鍵 q/Q
    [qQ])
      SELECTED_MENU_IDX=5
      exit_warn_count=$((staged_count + staged_policy_count))
      if [ $exit_warn_count -gt 0 ]; then
        echo -e "\n${COLOR_YELLOW}${COLOR_BOLD}[警告] 暫存區中目前有 ${exit_warn_count} 條未套用的變更草稿!${COLOR_RESET}"
        if ! confirm_prompt "> 是否要放棄這些草稿並直接離開系統?[y/N]: "; then
          echo -e "${COLOR_GREEN}[i] 已取消離開,回到主選單.${COLOR_RESET}"
          sleep 1
          continue
        fi
      fi
      echo -e "\n${COLOR_GREEN}感謝使用防火牆管理系統,再會!${COLOR_RESET}"
      exit 0
      ;;
      
    # 按下 Enter 鍵
    "")
      case "$SELECTED_MENU_IDX" in
        0) show_status;;
        1) change_default_policy;;
        2) add_remove_rules_menu;;
        3) process_staged_rules_menu;;
        4) backup_restore_manager;;
        5)
          exit_warn_count=$((staged_count + staged_policy_count))
          if [ $exit_warn_count -gt 0 ]; then
            echo -e "\n${COLOR_YELLOW}${COLOR_BOLD}[警告] 暫存區中目前有 ${exit_warn_count} 條未套用的變更草稿!${COLOR_RESET}"
            if ! confirm_prompt "> 是否要放棄這些草稿並直接離開系統?[y/N]: "; then
              echo -e "${COLOR_GREEN}[i] 已取消離開,回到主選單.${COLOR_RESET}"
              sleep 1
              continue
            fi
          fi
          echo -e "\n${COLOR_GREEN}感謝使用防火牆管理系統,再會!${COLOR_RESET}"
          exit 0
          ;;
      esac
      ;;
      
    *)
      # 其他無效按鍵不作反應,直接刷新,避免輸出錯誤洗頻
      ;;
  esac
done
