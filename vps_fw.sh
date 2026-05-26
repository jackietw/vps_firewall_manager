#!/usr/bin/env bash

# ==============================================================================
#   VPS 防火牆安全管理系統 (iptables & ip6tables)
#   語系: 專用 Bash 腳本 (100% 適用於任何內建 Bash 的 Linux VPS)
#   功能: 雙軌 IPv4/IPv6 同步管理、表格對齊、寫入安全測試、歷史備份管理與自動還原
#   設計: 高安全性、高可靠性之雙軌同步防火牆管理系統
# ==============================================================================

# --- 全局變數與初始化 ---
STAGED_RULES=() # 暫存規則，格式: "PORT|PROTOCOL|SOURCE|COMMENT|ACTION|IP_VERSION"
STAGED_POLICY=""      # 待套用預設策略，可為 ""、"ACCEPT" 或 "DROP"
STAGED_POLICY_V6=""   # 待套用 IPv6 預設策略，同上
BACKUP_DIR="./backups"

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
  echo -e "${COLOR_RED}${COLOR_BOLD}[!] 錯誤: 此腳本需要 root 權限，請使用 sudo 執行！${COLOR_RESET}"
  echo -e "${COLOR_RED}👉 請使用指令: sudo ./vps_fw.sh${COLOR_RESET}"
  exit 1
fi

if ! command -v iptables &>/dev/null || ! command -v ip6tables &>/dev/null; then
  echo -e "${COLOR_RED}${COLOR_BOLD}[!] 錯誤: 系統未偵測到 iptables 或 ip6tables 工具，本腳本終止執行。${COLOR_RESET}"
  exit 1
fi

# --- 輔助函式: 動態偵測當前連入之 SSH 端口 ---
detect_current_ssh_port() {
  local detected_port="22"
  
  # 1. 優先從當前 SSH 連線環境變數獲取 (最精準，反映當前真實連線中的 Port)
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
  echo -e "${COLOR_GREEN}${COLOR_BOLD}   已使用 root 權限 (Bash) 成功對接系統防火牆 ${COLOR_RESET}"
  echo -e "${COLOR_GREEN}   ----------------------------------------------------- ${COLOR_RESET}"
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
    # 略過迴路與狀態連線規則，避免版面凌亂
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

    # 2. 提取端口
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
    policy_suffix=" (${COLOR_YELLOW}⏳ 待修改為: ${s_color}${COLOR_BOLD}${STAGED_POLICY}${COLOR_RESET})"
  fi
  
  echo -e "${COLOR_BOLD}🛡️  IPv4 INPUT 鏈預設行為 (Default Policy): ${policy_color}${COLOR_BOLD}${input_policy}${COLOR_RESET}${policy_suffix}"
  echo -e "${COLOR_BOLD}📊 當前作用中的 IPv4 防火牆規則 (Active IPv4 Rules):${COLOR_RESET}"
  echo -e "${COLOR_CYAN}┌────┬──────────┬──────────┬──────────────────────┬──────────┬────────────────────────┐${COLOR_RESET}"
  echo -e "${COLOR_CYAN}│編號│ 通訊協定 │ 端口(Port│ 來源 IP 限制         │ 連線動作 │ 備註說明               │${COLOR_RESET}"
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
    policy_suffix_v6=" (${COLOR_YELLOW}⏳ 待修改為: ${s_color_v6}${COLOR_BOLD}${STAGED_POLICY_V6}${COLOR_RESET})"
  fi
  
  echo -e "${COLOR_BOLD}🛡️  IPv6 INPUT 鏈預設行為 (Default Policy): ${policy_color_v6}${COLOR_BOLD}${input_policy_v6}${COLOR_RESET}${policy_suffix_v6}"
  echo -e "${COLOR_BOLD}📊 當前作用中的 IPv6 防火牆規則 (Active IPv6 Rules):${COLOR_RESET}"
  echo -e "${COLOR_CYAN}┌────┬──────────┬──────────┬──────────────────────┬──────────┬────────────────────────┐${COLOR_RESET}"
  echo -e "${COLOR_CYAN}│編號│ 通訊協定 │ 端口(Port│ 來源 IP 限制         │ 連線動作 │ 備註說明               │${COLOR_RESET}"
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
    echo -e "${COLOR_YELLOW}${COLOR_BOLD}⏳ 待寫入的暫存規則 (Staged Rules - 尚未套用):${COLOR_RESET}"
    echo -e "${COLOR_YELLOW}┌────┬──────────┬──────────┬──────────────────────┬──────────┬────────────────────────┐${COLOR_RESET}"
    local s_index=1
    for s_rule in "${STAGED_RULES[@]}"; do
      local port proto src comment target ip_version
      IFS='|' read -r port proto src comment target ip_version <<< "$s_rule"
      [ -z "$comment" ] && comment="無"
      
      local sign="+"
      local ver_suffix=""
      [ "$ip_version" = "ipv4" ] && ver_suffix="-v4"
      [ "$ip_version" = "ipv6" ] && ver_suffix="-v6"
      [ "$ip_version" = "both" ] && ver_suffix="-雙"
      
      local action_abbr=""
      local is_delete=false
      local raw_action="$target"
      
      if [[ "$target" == DELETE_* ]]; then
        is_delete=true
        sign="-"
        raw_action="${target#DELETE_}"
      fi
      
      if [ "$raw_action" = "ACCEPT" ]; then
        action_abbr="ACC"
      elif [ "$raw_action" = "DROP" ]; then
        action_abbr="DRP"
      elif [ "$raw_action" = "REJECT" ]; then
        action_abbr="REJ"
      else
        action_abbr="${raw_action:0:3}"
      fi
      
      local target_text=""
      if [ "$is_delete" = true ]; then
        target_text="D-${action_abbr}${ver_suffix}"
      else
        target_text="${action_abbr}${ver_suffix}"
      fi
      
      # 針對含有「雙」這個中文字元（視覺寬度佔2）進行精準 8 寬度對齊計算
      local target_aligned=""
      if [[ "$target_text" == *"雙"* ]]; then
        if [ "$is_delete" = true ]; then
          target_aligned="${target_text} "
        else
          target_aligned="${target_text}   "
        fi
      else
        if [ "$is_delete" = true ]; then
          target_aligned="${target_text}"
        else
          target_aligned="${target_text}  "
        fi
      fi
      
      local target_styled=""
      if [ "$is_delete" = true ]; then
        target_styled="${COLOR_RED}${COLOR_BOLD}${target_aligned}${COLOR_RESET}"
      else
        if [ "$raw_action" = "ACCEPT" ]; then
          target_styled="${COLOR_GREEN}${COLOR_BOLD}${target_aligned}${COLOR_RESET}"
        elif [ "$raw_action" = "DROP" ]; then
          target_styled="${COLOR_RED}${COLOR_BOLD}${target_aligned}${COLOR_RESET}"
        else
          target_styled="${COLOR_YELLOW}${COLOR_BOLD}${target_aligned}${COLOR_RESET}"
        fi
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
    echo -e "${COLOR_YELLOW}💡 提示: 請回到主選單選擇 [5. 寫入並開始測試] 以啟用上述暫存規則。${COLOR_RESET}"
  fi
  
  echo ""
  echo -e "${COLOR_DIM}按任意鍵返回選單...${COLOR_RESET}"
  read -n 1 -s
}

# --- 核心功能 2: 新增 PORT 規則到暫存區 ---
add_port() {
  print_header
  echo -e "${COLOR_BOLD}➕ 新增 Port 防火牆規則暫存${COLOR_RESET}\n"
  
  # 1. 輸入 Port
  local port=""
  while true; do
    echo -n "👉 請輸入要開放/阻擋的 Port 號碼 (1-65535, 例如 8080 或 80,443 或 8000:8010): "
    read -r port
    port="${port#"${port%%[![:space:]]*}"}"
    port="${port%"${port##*[![:space:]]}"}"
    
    if [ -z "$port" ]; then
      echo -e "${COLOR_RED}[!] Port 不能為空，請重新輸入。${COLOR_RESET}"
      continue
    fi
    if [[ ! "$port" =~ ^[0-9,:-]+$ ]]; then
      echo -e "${COLOR_RED}[!] 格式錯誤！僅能包含數字、逗號(,)或冒號(:)作為區間，請重新輸入。${COLOR_RESET}"
      continue
    fi
    break
  done
  
  # 2. 選擇通訊協定
  local proto=""
  while true; do
    echo -n "👉 請選擇通訊協定 [1) TCP  2) UDP  3) 雙通(TCP+UDP)] (預設 1): "
    read -r proto_choice
    case "$proto_choice" in
      ""|1) proto="tcp"; break;;
      2) proto="udp"; break;;
      3) proto="both"; break;;
      *) echo -e "${COLOR_RED}[!] 輸入無效，請輸入 1, 2 或 3。${COLOR_RESET}";;
    esac
  done
  
  # 3. 選擇套用 IP 版本
  local ip_ver=""
  while true; do
    echo -n "👉 請選擇套用 IP 版本 [1) 雙軌同步(v4+v6)  2) 僅 IPv4  3) 僅 IPv6] (預設 1): "
    read -r ip_choice
    case "$ip_choice" in
      ""|1) ip_ver="both"; break;;
      2) ip_ver="ipv4"; break;;
      3) ip_ver="ipv6"; break;;
      *) echo -e "${COLOR_RED}[!] 輸入無效，請輸入 1, 2 或 3。${COLOR_RESET}";;
    esac
  done
  
  # 4. 輸入來源限制
  local src=""
  echo -n "👉 請輸入限制的來源 IP (若無限制直接 Enter 即可，IPv6 例如 ::1): "
  read -r src
  src="${src#"${src%%[![:space:]]*}"}"
  src="${src%"${src##*[![:space:]]}"}"
  if [ -z "$src" ]; then
    src="Anywhere"
  fi
  
  # 5. 選擇連線動作
  local action=""
  while true; do
    echo -n "👉 請選擇連線動作 [1) ACCEPT (接受/開啟)  2) DROP (阻擋/關閉)] (預設 1): "
    read -r action_choice
    case "$action_choice" in
      ""|1) action="ACCEPT"; break;;
      2) action="DROP"; break;;
      *) echo -e "${COLOR_RED}[!] 輸入無效，請輸入 1 或 2。${COLOR_RESET}";;
    esac
  done
  
  # 6. 輸入備註說明
  local comment=""
  echo -n "👉 請輸入簡短備註說明 (例如 Web Server，方便以後辨識，可空白): "
  read -r comment
  comment="${comment#"${comment%%[![:space:]]*}"}"
  comment="${comment%"${comment##*[![:space:]]}"}"
  if [ -z "$comment" ]; then
    comment="無備註"
  fi
  
  # 7. 加入暫存區
  if [ "$proto" = "both" ]; then
    STAGED_RULES+=("${port}|tcp|${src}|${comment}|${action}|${ip_ver}")
    STAGED_RULES+=("${port}|udp|${src}|${comment}|${action}|${ip_ver}")
    echo -e "\n${COLOR_GREEN}[✓] 已成功暫存 2 條雙軌規則 (TCP & UDP 端口 ${port})！${COLOR_RESET}"
  else
    STAGED_RULES+=("${port}|${proto}|${src}|${comment}|${action}|${ip_ver}")
    echo -e "\n${COLOR_GREEN}[✓] 已成功暫存規則 (端口 ${port}/${proto})！${COLOR_RESET}"
  fi
  
  echo ""
  echo -e "${COLOR_DIM}按任意鍵返回選單...${COLOR_RESET}"
  read -n 1 -s
}

# --- 核心功能: 刪除或撤銷防火牆規則流程 (將刪除指令加入暫存區或直接從暫存區撤銷) ---
delete_active_rule_flow() {
  local family="$1"
  local fam_str="IPv4"
  [ "$family" = "v6" ] && fam_str="IPv6"

  while true; do
    print_header
    echo -e "${COLOR_BOLD}🗑️  選擇要刪除的現有 ${fam_str} 規則 (將新增「刪除」指令至暫存區)：${COLOR_RESET}"
    echo -e "${COLOR_DIM}💡 可連續選擇多筆刪除，按 Enter 返回上級選單${COLOR_RESET}\n"
    
    echo -e "${COLOR_CYAN}┌────┬──────────┬──────────┬──────────────────────┬──────────┬────────────────────────┐${COLOR_RESET}"
    echo -e "${COLOR_CYAN}│編號│ 通訊協定 │ 端口(Port│ 來源 IP 限制         │ 連線動作 │ 備註說明               │${COLOR_RESET}"
    echo -e "${COLOR_CYAN}├────┼──────────┼──────────┼──────────────────────┼──────────┼────────────────────────┤${COLOR_RESET}"
    
    local index=1
    local has_rules=false
    local raw_output
    raw_output=$(get_active_rules "$family")
    local rules_array=()
    
    while IFS= read -r line; do
      if [ -z "$line" ]; then
        continue
      fi
      if [[ "$line" =~ ^RULE\|(.*) ]]; then
        has_rules=true
        local rule_data="${BASH_REMATCH[1]}"
        
        # 檢查該規則是否已經在暫存區被標記為 DELETE
        local proto_chk port_chk src_chk target_chk comment_chk
        IFS='|' read -r proto_chk port_chk src_chk target_chk comment_chk <<< "$rule_data"
        local ip_ver_chk="ipv4"
        [ "$family" = "v6" ] && ip_ver_chk="ipv6"
        
        local is_already_staged_deleted=false
        for staged in "${STAGED_RULES[@]}"; do
          local s_port s_proto s_src s_comment s_action s_ip_ver
          IFS='|' read -r s_port s_proto s_src s_comment s_action s_ip_ver <<< "$staged"
          if [ "$s_port" = "$port_chk" ] && [ "$s_proto" = "$proto_chk" ] && [ "$s_src" = "$src_chk" ] && [ "$s_action" = "DELETE_${target_chk}" ] && [ "$s_ip_ver" = "$ip_ver_chk" ]; then
            is_already_staged_deleted=true
            break
          fi
        done
        
        # 已暫存刪除的規則直接略過，不重複列出，使列表動態遞減
        if [ "$is_already_staged_deleted" = true ]; then
          continue
        fi
        
        rules_array+=("$rule_data")
        
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
    
    if [ ${#rules_array[@]} -eq 0 ]; then
      local no_rules_msg
      no_rules_msg=$(format_align "                               目前無自訂 ${fam_str} 限制規則" 85)
      echo -e "${COLOR_CYAN}│${COLOR_RESET}${no_rules_msg}${COLOR_CYAN}│${COLOR_RESET}"
      echo -e "${COLOR_CYAN}└────┴──────────┴──────────┴──────────────────────┴──────────┴────────────────────────┘${COLOR_RESET}"
      echo -e "\n${COLOR_YELLOW}[!] 目前沒有任何可刪除的規則。${COLOR_RESET}"
      echo -e "${COLOR_DIM}按任意鍵返回...${COLOR_RESET}"
      read -n 1 -s
      return
    fi
    echo -e "${COLOR_CYAN}└────┴──────────┴──────────┴──────────────────────┴──────────┴────────────────────────┘${COLOR_RESET}"
    
    echo ""
    echo -n "👉 請輸入要刪除的規則編號 (1-$((index-1)))，或直接 Enter 返回: "
    read -r choice_num
    if [ -z "$choice_num" ]; then
      return
    fi
    
    if [[ ! "$choice_num" =~ ^[0-9]+$ ]] || [ "$choice_num" -lt 1 ] || [ "$choice_num" -ge "$index" ]; then
      echo -e "${COLOR_RED}[!] 輸入無效的編號！${COLOR_RESET}"
      sleep 1
      continue
    fi
    
    # 取得選定規則的資訊
    local chosen_rule="${rules_array[$((choice_num-1))]}"
    local proto port src target comment
    IFS='|' read -r proto port src target comment <<< "$chosen_rule"
    
    # 將該規則加入暫存，動作標記為 DELETE_<target>
    local ip_ver="ipv4"
    [ "$family" = "v6" ] && ip_ver="ipv6"
    STAGED_RULES+=("${port}|${proto}|${src}|${comment}|DELETE_${target}|${ip_ver}")
    
    echo -e "\n${COLOR_GREEN}[✓] 已成功將「刪除 ${fam_str} 端口 ${port}/${proto}」的規則加入暫存區！${COLOR_RESET}"
    echo -e "${COLOR_YELLOW}💡 提示: 刪除規則尚未實際生效，請至選單選擇 [5. 寫入並開始測試] 套用變更。${COLOR_RESET}"
    sleep 1.5
  done
}

revoke_staged_rule_flow() {
  while true; do
    print_header
    echo -e "${COLOR_BOLD}⏳ 選擇要撤銷的暫存區規則 (直接從暫存區移除)：${COLOR_RESET}"
    echo -e "${COLOR_DIM}💡 可連續選擇多筆撤銷，按 Enter 返回主選單${COLOR_RESET}\n"
    
    if [ ${#STAGED_RULES[@]} -eq 0 ]; then
      echo -e "${COLOR_YELLOW}[!] 目前暫存區是空的，沒有任何草稿需要撤銷。${COLOR_RESET}"
      echo ""
      echo -e "${COLOR_DIM}按任意鍵返回...${COLOR_RESET}"
      read -n 1 -s
      return
    fi
    
    echo -e "${COLOR_YELLOW}┌────┬──────────┬──────────┬──────────────────────┬──────────┬────────────────────────┐${COLOR_RESET}"
    local s_index=1
    for s_rule in "${STAGED_RULES[@]}"; do
      local port proto src comment target ip_version
      IFS='|' read -r port proto src comment target ip_version <<< "$s_rule"
      [ -z "$comment" ] && comment="無"
      
      local sign="+"
      local ver_suffix=""
      [ "$ip_version" = "ipv4" ] && ver_suffix="-v4"
      [ "$ip_version" = "ipv6" ] && ver_suffix="-v6"
      [ "$ip_version" = "both" ] && ver_suffix="-雙"
      
      local action_abbr=""
      local is_delete=false
      local raw_action="$target"
      
      if [[ "$target" == DELETE_* ]]; then
        is_delete=true
        sign="-"
        raw_action="${target#DELETE_}"
      fi
      
      if [ "$raw_action" = "ACCEPT" ]; then
        action_abbr="ACC"
      elif [ "$raw_action" = "DROP" ]; then
        action_abbr="DRP"
      elif [ "$raw_action" = "REJECT" ]; then
        action_abbr="REJ"
      else
        action_abbr="${raw_action:0:3}"
      fi
      
      local target_text=""
      if [ "$is_delete" = true ]; then
        target_text="D-${action_abbr}${ver_suffix}"
      else
        target_text="${action_abbr}${ver_suffix}"
      fi
      
      # 針對含有「雙」這個中文字元（視覺寬度佔2）進行精準 8 寬度對齊計算
      local target_aligned=""
      if [[ "$target_text" == *"雙"* ]]; then
        if [ "$is_delete" = true ]; then
          target_aligned="${target_text} "
        else
          target_aligned="${target_text}   "
        fi
      else
        if [ "$is_delete" = true ]; then
          target_aligned="${target_text}"
        else
          target_aligned="${target_text}  "
        fi
      fi
      
      local target_styled=""
      if [ "$is_delete" = true ]; then
        target_styled="${COLOR_RED}${COLOR_BOLD}${target_aligned}${COLOR_RESET}"
      else
        if [ "$raw_action" = "ACCEPT" ]; then
          target_styled="${COLOR_GREEN}${COLOR_BOLD}${target_aligned}${COLOR_RESET}"
        elif [ "$raw_action" = "DROP" ]; then
          target_styled="${COLOR_RED}${COLOR_BOLD}${target_aligned}${COLOR_RESET}"
        else
          target_styled="${COLOR_YELLOW}${COLOR_BOLD}${target_aligned}${COLOR_RESET}"
        fi
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
    echo -n "👉 請輸入要撤銷的暫存規則編號 (1-$((s_index-1)))，或直接 Enter 返回: "
    read -r choice_num
    if [ -z "$choice_num" ]; then
      return
    fi
    
    if [[ ! "$choice_num" =~ ^[0-9]+$ ]] || [ "$choice_num" -lt 1 ] || [ "$choice_num" -ge "$s_index" ]; then
      echo -e "${COLOR_RED}[!] 輸入無效的編號！${COLOR_RESET}"
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
    
    echo -e "\n${COLOR_GREEN}[✓] 已成功撤銷該暫存規則！${COLOR_RESET}"
    sleep 1.5
  done
}

delete_active_rules_menu() {
  while true; do
    print_header
    echo -e "${COLOR_BOLD}❌ 刪除已生效的現有規則 (新增刪除指令至暫存區)${COLOR_RESET}\n"
    echo -e "  ${COLOR_CYAN}1)${COLOR_RESET} 刪除「已生效的現有 IPv4 規則」"
    echo -e "  ${COLOR_CYAN}2)${COLOR_RESET} 刪除「已生效的現有 IPv6 規則」"
    echo -e "  ${COLOR_CYAN}3)${COLOR_RESET} 返回主選單"
    echo ""
    echo -n "👉 請輸入選擇 (1-3): "
    read -r del_choice
    case "$del_choice" in
      1) delete_active_rule_flow v4;;
      2) delete_active_rule_flow v6;;
      3|*) return;;
    esac
  done
}

change_default_policy() {
  print_header
  echo -e "${COLOR_BOLD}🛡️  修改 INPUT 鏈預設行為 (Default Policy)${COLOR_RESET}\n"
  
  # 1. 取得現有預設行為
  local input_policy
  local input_policy_v6
  input_policy=$(iptables -S INPUT 2>/dev/null | grep '^-P INPUT' | awk '{print $3}')
  [ -z "$input_policy" ] && input_policy="ACCEPT"
  input_policy_v6=$(ip6tables -S INPUT 2>/dev/null | grep '^-P INPUT' | awk '{print $3}')
  [ -z "$input_policy_v6" ] && input_policy_v6="ACCEPT"
  
  echo -e "當前 IPv4 INPUT 預設行為: ${COLOR_BOLD}${input_policy}${COLOR_RESET}"
  echo -e "當前 IPv6 INPUT 預設行為: ${COLOR_BOLD}${input_policy_v6}${COLOR_RESET}\n"
  
  # 2. 選擇目標策略
  local target_policy=""
  while true; do
    echo -n "👉 請選擇要設定的目標預設行為 [1) ACCEPT (預設放行)  2) DROP (預設阻擋)] (預設 1): "
    read -r policy_choice
    case "$policy_choice" in
      ""|1) target_policy="ACCEPT"; break;;
      2) target_policy="DROP"; break;;
      *) echo -e "${COLOR_RED}[!] 輸入無效，請輸入 1 或 2。${COLOR_RESET}";;
    esac
  done
  
  # 3. 如果改為 DROP，執行 SSH 安全防呆偵測
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
      echo -e "${COLOR_YELLOW}[⚠️  警告] 偵測到您尚未允許當前 SSH 端口 (${ssh_port}/tcp)，為避免您斷開連線，系統已自動在暫存區中補上該規則 (IPv4)。${COLOR_RESET}"
      STAGED_RULES+=("${ssh_port}|tcp|Anywhere|自動放行 SSH 端口|ACCEPT|ipv4")
    fi
    if [ "$ssh_allowed_v6" = false ]; then
      echo -e "${COLOR_YELLOW}[⚠️  警告] 偵測到您尚未允許當前 SSH 端口 (${ssh_port}/tcp)，為避免您斷開連線，系統已自動在暫存區中補上該規則 (IPv6)。${COLOR_RESET}"
      STAGED_RULES+=("${ssh_port}|tcp|Anywhere|自動放行 SSH 端口|ACCEPT|ipv6")
    fi
  fi
  
  if confirm_prompt "👉 確定要將預設行為暫存修改為 ${target_policy} 嗎？[y/N]: "; then
    STAGED_POLICY="$target_policy"
    STAGED_POLICY_V6="$target_policy"
    echo -e "${COLOR_GREEN}[✓] 已成功暫存預設行為變更！請回到主選單選擇 [5. 寫入並開始測試] 套用。${COLOR_RESET}"
  else
    echo -e "${COLOR_YELLOW}[!] 修改已取消。${COLOR_RESET}"
  fi
  
  echo ""
  echo -e "${COLOR_DIM}按任意鍵返回選單...${COLOR_RESET}"
  read -n 1 -s
}

apply_rules() {
  if [ ${#STAGED_RULES[@]} -eq 0 ] && [ -z "$STAGED_POLICY" ] && [ -z "$STAGED_POLICY_V6" ]; then
    echo -e "${COLOR_YELLOW}[!] 暫存區中無任何變更，無須寫入與測試！${COLOR_RESET}"
    sleep 1.5
    return
  fi
  
  # --- 1. 防火牆規則寫入實行 (雙軌獨立備份) ---
  local backup_file_v4="/tmp/vps_fw_v4_bak.$(date +%s)"
  local backup_file_v6="/tmp/vps_fw_v6_bak.$(date +%s)"
  local success=true

  if ! iptables-save > "$backup_file_v4" 2>/dev/null || ! ip6tables-save > "$backup_file_v6" 2>/dev/null; then
    echo -e "${COLOR_RED}[錯誤] 無法成功備份防火牆，為確保安全，本次套用終止！${COLOR_RESET}"
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
        echo -e "${COLOR_RED}[!] IPv4 寫入失敗，指令為: ${cmd[*]}${COLOR_RESET}"
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
        echo -e "${COLOR_RED}[!] IPv6 寫入失敗，指令為: ${cmd[*]}${COLOR_RESET}"
        success=false
        break
      fi
    fi
  done
  
  # 若有任一規則失敗，立即同步雙軌還原
  if [ "$success" = false ]; then
    echo -e "${COLOR_YELLOW}[i] 部分規則失敗，正在雙軌還原防火牆...${COLOR_RESET}"
    iptables-restore < "$backup_file_v4" 2>/dev/null
    ip6tables-restore < "$backup_file_v6" 2>/dev/null
    rm -f "$backup_file_v4" "$backup_file_v6"
    echo -e "${COLOR_RED}[錯誤] 套用失敗，已還原至變更前狀態。${COLOR_RESET}"
    echo -e "${COLOR_DIM}按任意鍵返回選單...${COLOR_RESET}"
    read -n 1 -s
    return
  fi
  
  # 寫入預設策略變更 (如果有)
  if [ "$success" = true ]; then
    if [ -n "$STAGED_POLICY" ]; then
      echo -e "${COLOR_CYAN}[i] 正在套用 IPv4 INPUT 預設行為為 ${STAGED_POLICY}...${COLOR_RESET}"
      if ! iptables -P INPUT "$STAGED_POLICY" 2>/dev/null; then
        echo -e "${COLOR_RED}[!] IPv4 預設行為套用失敗！${COLOR_RESET}"
        success=false
      fi
    fi
    if [ "$success" = true ] && [ -n "$STAGED_POLICY_V6" ]; then
      echo -e "${COLOR_CYAN}[i] 正在套用 IPv6 INPUT 預設行為為 ${STAGED_POLICY_V6}...${COLOR_RESET}"
      if ! ip6tables -P INPUT "$STAGED_POLICY_V6" 2>/dev/null; then
        echo -e "${COLOR_RED}[!] IPv6 預設行為套用失敗！${COLOR_RESET}"
        success=false
      fi
    fi
  fi
  
  # 若策略修改失敗，進行雙軌還原
  if [ "$success" = false ]; then
    echo -e "${COLOR_YELLOW}[i] 策略套用失敗，正在還原設定...${COLOR_RESET}"
    iptables-restore < "$backup_file_v4" 2>/dev/null
    ip6tables-restore < "$backup_file_v6" 2>/dev/null
    rm -f "$backup_file_v4" "$backup_file_v6"
    echo -e "${COLOR_RED}[錯誤] 套用失敗，已還原至變更前狀態。${COLOR_RESET}"
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

  echo -e "\n${COLOR_CYAN}${COLOR_BOLD}🔍 正在為變更之規則執行自動自我測試 (Auto Self-Test)...${COLOR_RESET}"
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
    if [ "$is_delete" = false ] && [ "$target_action" = "DROP" ]; then
      expected_open=false
    elif [ "$is_delete" = true ] && [ "$target_action" = "ACCEPT" ]; then
      expected_open=false
    fi
    
    if [ "$proto" = "tcp" ] || [ "$proto" = "both" ]; then
      if [[ "$port" == *":"* ]]; then
        echo -e "  ${COLOR_DIM}[i] 端口範圍 ${port} 暫不支援自動連線測試。${COLOR_RESET}"
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
          echo -e "  👉 正在測試 IPv4 TCP 端口 ${single_port} (預期狀態: ${expected_str})..."
          
          local skip_test=false
          if [ "$is_delete" = true ]; then
            if [ "$target_action" = "ACCEPT" ] && [ "$v4_policy" = "ACCEPT" ]; then
              skip_test=true
            elif [ "$target_action" = "DROP" ] && [ "$v4_policy" = "DROP" ]; then
              skip_test=true
            fi
          fi
          
          if [ "$skip_test" = true ]; then
            echo -e "     ${COLOR_DIM}[i] 略過測試: 預設行為為 ${v4_policy}，刪除 ${target_action} 規則無須重複測試。${COLOR_RESET}"
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
                test_msg="防火牆放行，但連線異常 (代碼: $curl_status)"
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
              [ "$test_success" = true ] && echo -e "     ${COLOR_GREEN}✓ IPv4 自我測試通過: ${test_msg}${COLOR_RESET}" || echo -e "     ${COLOR_RED}✗ IPv4 自我測試失敗: ${test_msg}${COLOR_RESET}"
            else
              [ "$test_success" = false ] && echo -e "     ${COLOR_GREEN}✓ IPv4 自我測試通過: ${test_msg}${COLOR_RESET}" || echo -e "     ${COLOR_RED}✗ IPv4 自我測試失敗: 預期阻擋但仍連通 (${test_msg})${COLOR_RESET}"
            fi
          fi
        fi
        
        # 2. 測試 IPv6 (如果規則適用)
        if [ "$ip_version" = "both" ] || [ "$ip_version" = "ipv6" ]; then
          echo -e "  👉 正在測試 IPv6 TCP 端口 ${single_port} (預期狀態: ${expected_str})..."
          
          local skip_test_v6=false
          if [ "$is_delete" = true ]; then
            if [ "$target_action" = "ACCEPT" ] && [ "$v6_policy" = "ACCEPT" ]; then
              skip_test_v6=true
            elif [ "$target_action" = "DROP" ] && [ "$v6_policy" = "DROP" ]; then
              skip_test_v6=true
            fi
          fi
          
          if [ "$skip_test_v6" = true ]; then
            echo -e "     ${COLOR_DIM}[i] 略過測試: 預設行為為 ${v6_policy}，刪除 ${target_action} 規則無須重複測試。${COLOR_RESET}"
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
                  test_msg_v6="防火牆放行，但連線異常 (代碼: $curl_status)"
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
  echo -e "\n${COLOR_YELLOW}${COLOR_BOLD}🔥 新的防火牆規則已暫時套用！開始安全倒數...${COLOR_RESET}"
  echo -e "${COLOR_CYAN}💡 請迅速開啟一個新連線視窗，確認您的 SSH 連線以及新開服務是否完全正常！${COLOR_RESET}"
  echo -e "若有任何異常導致您被鎖定，請勿操作，等待倒數歸零將會自動幫您還原連線。"
  echo ""
  
  while (( timeout > 0 )); do
    echo -ne "\r\033[K🕒 剩餘還原時間: ${COLOR_RED}${COLOR_BOLD}${timeout}${COLOR_RESET} 秒... [按 ${COLOR_GREEN}${COLOR_BOLD}Y/y${COLOR_RESET} 確認保留, 按 ${COLOR_RED}${COLOR_BOLD}N/n${COLOR_RESET} 立即還原]: "
    
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
    echo -e "\n${COLOR_GREEN}${COLOR_BOLD}[✓] 恭喜！新防火牆規則確認安全，已成功套用！${COLOR_RESET}"
    
    # 清理雙軌備份
    rm -f "$backup_file_v4" "$backup_file_v6"
    STAGED_RULES=()
    STAGED_POLICY=""
    STAGED_POLICY_V6=""
    
    # 詢問是否永久存檔
    echo -e "\n${COLOR_BOLD}💾 是否設定開機自動載入此防火牆規則？${COLOR_RESET}"
    local saved=false
    if [ -d "/etc/iptables" ]; then
      echo -e "  偵測到 Debian/Ubuntu 保存路徑 (${COLOR_CYAN}/etc/iptables/rules.v4${COLOR_RESET})"
      if confirm_prompt "👉 是否直接寫入該路徑存檔 (含 rules.v6)？[y/N]: "; then
        iptables-save > /etc/iptables/rules.v4
        ip6tables-save > /etc/iptables/rules.v6
        echo -e "${COLOR_GREEN}[✓] 已成功存檔至 /etc/iptables/rules.v[4\|6]！${COLOR_RESET}"
        saved=true
      fi
    elif [ -f "/etc/sysconfig/iptables" ]; then
      echo -e "  偵測到 RHEL/CentOS 保存路徑 (${COLOR_CYAN}/etc/sysconfig/iptables${COLOR_RESET})"
      if confirm_prompt "👉 是否直接寫入該路徑存檔 (含 ip6tables)？[y/N]: "; then
        iptables-save > /etc/sysconfig/iptables
        ip6tables-save > /etc/sysconfig/ip6tables
        echo -e "${COLOR_GREEN}[✓] 已成功存檔至 /etc/sysconfig/iptables 及 ip6tables！${COLOR_RESET}"
        saved=true
      fi
    fi
    
    if [ "$saved" = false ]; then
      echo -e "\n${COLOR_YELLOW}[提示] 若要開機自動載入，您可以使用以下指令手動保存：${COLOR_RESET}"
      echo -e "  IPv4: ${COLOR_BOLD}sudo iptables-save > /etc/iptables/rules.v4${COLOR_RESET}"
      echo -e "  IPv6: ${COLOR_BOLD}sudo ip6tables-save > /etc/iptables/rules.v6${COLOR_RESET}"
    fi
  else
    # 逾時或拒絕 -> 還原
    echo -e "\n${COLOR_RED}${COLOR_BOLD}[!] 測試取消或逾時！正在自動執行雙軌還原 (Rollback) 防火牆...${COLOR_RESET}"
    iptables-restore < "$backup_file_v4" 2>/dev/null
    ip6tables-restore < "$backup_file_v6" 2>/dev/null
    rm -f "$backup_file_v4" "$backup_file_v6"
    echo -e "${COLOR_GREEN}[✓] 雙軌防火牆已成功同步還原！安全無虞。${COLOR_RESET}"
  fi
  
  echo ""
  echo -e "${COLOR_DIM}按任意鍵返回選單...${COLOR_RESET}"
  read -n 1 -s
}

# --- 核心功能 5: 防火牆歷史備份與還原管理系統 (全新功能) ---
backup_restore_manager() {
  while true; do
    print_header
    echo -e "${COLOR_BOLD}💾 防火牆備份與歷史存檔管理系統${COLOR_RESET}\n"
    echo -e "  ${COLOR_CYAN}1)${COLOR_RESET} 建立手動防火牆快照備份 (一鍵雙軌存檔)"
    echo -e "  ${COLOR_CYAN}2)${COLOR_RESET} 檢視現有歷史備份清單"
    echo -e "  ${COLOR_CYAN}3)${COLOR_RESET} 還原指定歷史防火牆存檔 (雙軌自動偵測還原)"
    echo -e "  ${COLOR_CYAN}4)${COLOR_RESET} 刪除指定歷史存檔"
    echo -e "  ${COLOR_CYAN}5)${COLOR_RESET} 返回主選單"
    echo ""
    echo -n "👉 請輸入選擇 (1-5): "
    read -r bk_choice
    
    case "$bk_choice" in
      1)
        print_header
        echo -e "${COLOR_BOLD}📸 建立手動防火牆快照備份${COLOR_RESET}\n"
        echo -n "👉 請輸入備份名稱 (僅限英文/數字/底線，例如 base_config)："
        read -r bk_name
        # 過濾不合法字元
        bk_name=$(echo "$bk_name" | sed 's/[^a-zA-Z0-9_]//g')
        if [ -z "$bk_name" ]; then
          echo -e "${COLOR_RED}[!] 名稱無效或為空！${COLOR_RESET}"
          sleep 1.5
          continue
        fi
        
        echo -n "👉 請輸入備份簡短備註 (例如: 開放80/443前備份)："
        read -r bk_desc
        [ -z "$bk_desc" ] && bk_desc="手動備份"
        
        if iptables-save > "$BACKUP_DIR/$bk_name.v4.rules" 2>/dev/null && \
           ip6tables-save > "$BACKUP_DIR/$bk_name.v6.rules" 2>/dev/null; then
           
          # 寫入 metadata
          echo "Date: $(date '+%Y-%m-%d %H:%M:%S')" > "$BACKUP_DIR/$bk_name.meta"
          echo "Desc: $bk_desc" >> "$BACKUP_DIR/$bk_name.meta"
          echo -e "\n${COLOR_GREEN}[✓] 防火牆雙軌備份成功！存檔為: $bk_name${COLOR_RESET}"
        else
          echo -e "\n${COLOR_RED}[✗] 備份寫入失敗，請確認權限或備份目錄！${COLOR_RESET}"
          rm -f "$BACKUP_DIR/$bk_name.v4.rules" "$BACKUP_DIR/$bk_name.v6.rules"
        fi
        echo ""
        echo -e "${COLOR_DIM}按任意鍵繼續...${COLOR_RESET}"
        read -n 1 -s
        ;;
        
      2)
        print_header
        echo -e "${COLOR_BOLD}📋 現有歷史備份清單：${COLOR_RESET}\n"
        
        local meta_files=("$BACKUP_DIR"/*.meta)
        if [ ! -e "${meta_files[0]}" ]; then
          echo -e "${COLOR_YELLOW}[!] 目前尚無任何防火牆存檔備份。${COLOR_RESET}"
          echo ""
          echo -e "${COLOR_DIM}按任意鍵繼續...${COLOR_RESET}"
          read -n 1 -s
          continue
        fi
        
        echo -e "${COLOR_CYAN}┌────┬────────────────────────┬─────────────────────┬────────────────────────────────┐${COLOR_RESET}"
        echo -e "${COLOR_CYAN}│編號│ 備份存檔名稱           │ 建立時間            │ 備份備註說明                   │${COLOR_RESET}"
        echo -e "${COLOR_CYAN}├────┼────────────────────────┼─────────────────────┼────────────────────────────────┤${COLOR_RESET}"
        
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
          
          local name_aligned
          name_aligned=$(format_align "$name_raw" 22)
          local desc_aligned
          desc_aligned=$(format_align "$bk_desc" 30)
          
          printf "${COLOR_CYAN}│${COLOR_RESET} %-2d ${COLOR_CYAN}│${COLOR_RESET} %s ${COLOR_CYAN}│${COLOR_RESET} %-19s │ %s ${COLOR_CYAN}│${COLOR_RESET}\n" \
            $idx "$name_aligned" "$bk_date" "$desc_aligned"
          ((idx++))
        done
        echo -e "${COLOR_CYAN}└────┴────────────────────────┴─────────────────────┴────────────────────────────────┘${COLOR_RESET}"
        echo ""
        echo -e "${COLOR_DIM}按任意鍵繼續...${COLOR_RESET}"
        read -n 1 -s
        ;;
        
      3)
        print_header
        echo -e "${COLOR_BOLD}⏪ 還原指定歷史防火牆存檔${COLOR_RESET}\n"
        
        local meta_files=("$BACKUP_DIR"/*.meta)
        local bk_list=()
        if [ ! -e "${meta_files[0]}" ]; then
          echo -e "${COLOR_YELLOW}[!] 目前尚無任何可還原的備份存檔。${COLOR_RESET}"
          echo ""
          echo -e "${COLOR_DIM}按任意鍵繼續...${COLOR_RESET}"
          read -n 1 -s
          continue
        fi
        
        echo -e "請選擇要還原的備份："
        local idx=1
        for meta_f in "${meta_files[@]}"; do
          local name_raw
          name_raw=$(basename "$meta_f" .meta)
          bk_list+=("$name_raw")
          echo -e "  ${COLOR_CYAN}${idx})${COLOR_RESET} $name_raw ($(< "$meta_f" | grep 'Desc:' | cut -d' ' -f2-))"
          ((idx++))
        done
        echo ""
        echo -n "👉 請輸入還原目標編號 (或 Enter 取消): "
        read -r select_num
        if [ -z "$select_num" ]; then
          continue
        fi
        
        if [[ ! "$select_num" =~ ^[0-9]+$ ]] || [ "$select_num" -lt 1 ] || [ "$select_num" -ge "$idx" ]; then
          echo -e "${COLOR_RED}[!] 無效的編號！${COLOR_RESET}"
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
          echo -e "${COLOR_RED}[!] 此備份存檔之規則檔案不存在！${COLOR_RESET}"
          sleep 1.5
          continue
        fi
        
        echo -e "\n${COLOR_YELLOW}${COLOR_BOLD}⚠️  警告: 還原此歷史存檔將會覆蓋當前所有防火牆規則設定！${COLOR_RESET}"
        if ! confirm_prompt "👉 您確定要開始還原此歷史備份嗎？[y/N]: "; then
          echo -e "${COLOR_YELLOW}[!] 還原已取消。${COLOR_RESET}"
          sleep 1.5
          continue
        fi
        
        if [ "$has_v4" = true ] && [ "$has_v6" = true ]; then
          # 完整雙軌還原
          iptables-restore < "$BACKUP_DIR/$chosen_bk.v4.rules" 2>/dev/null
          ip6tables-restore < "$BACKUP_DIR/$chosen_bk.v6.rules" 2>/dev/null
          echo -e "${COLOR_GREEN}[✓] IPv4 / IPv6 雙軌防火牆已成功同步還原！${COLOR_RESET}"
        elif [ "$has_v4" = true ]; then
          echo -e "${COLOR_YELLOW}[!] 偵測到此備份僅有 IPv4 快照。${COLOR_RESET}"
          if confirm_prompt "👉 是否單獨還原 IPv4，並保持當前 IPv6 不變？[y/N]: "; then
            iptables-restore < "$BACKUP_DIR/$chosen_bk.v4.rules" 2>/dev/null
            echo -e "${COLOR_GREEN}[✓] IPv4 防火牆已成功還原！${COLOR_RESET}"
          fi
        elif [ "$has_v6" = true ]; then
          echo -e "${COLOR_YELLOW}[!] 偵測到此備份僅有 IPv6 快照。${COLOR_RESET}"
          if confirm_prompt "👉 是否單獨還原 IPv6，並保持當前 IPv4 不變？[y/N]: "; then
            ip6tables-restore < "$BACKUP_DIR/$chosen_bk.v6.rules" 2>/dev/null
            echo -e "${COLOR_GREEN}[✓] IPv6 防火牆已成功還原！${COLOR_RESET}"
          fi
        fi
        echo ""
        echo -e "${COLOR_DIM}按任意鍵繼續...${COLOR_RESET}"
        read -n 1 -s
        ;;
        
      4)
        print_header
        echo -e "${COLOR_BOLD}❌ 刪除歷史備份存檔${COLOR_RESET}\n"
        
        local meta_files=("$BACKUP_DIR"/*.meta)
        local bk_list=()
        if [ ! -e "${meta_files[0]}" ]; then
          echo -e "${COLOR_YELLOW}[!] 目前尚無任何備份存檔。${COLOR_RESET}"
          echo ""
          echo -e "${COLOR_DIM}按任意鍵繼續...${COLOR_RESET}"
          read -n 1 -s
          continue
        fi
        
        echo -e "請選擇要刪除的備份："
        local idx=1
        for meta_f in "${meta_files[@]}"; do
          local name_raw
          name_raw=$(basename "$meta_f" .meta)
          bk_list+=("$name_raw")
          echo -e "  ${COLOR_CYAN}${idx})${COLOR_RESET} $name_raw"
          ((idx++))
        done
        echo ""
        echo -n "👉 請輸入刪除目標編號 (或 Enter 取消): "
        read -r select_num
        if [ -z "$select_num" ]; then
          continue
        fi
        
        if [[ ! "$select_num" =~ ^[0-9]+$ ]] || [ "$select_num" -lt 1 ] || [ "$select_num" -ge "$idx" ]; then
          echo -e "${COLOR_RED}[!] 無效的編號！${COLOR_RESET}"
          sleep 1.5
          continue
        fi
        
        local chosen_bk="${bk_list[$((select_num-1))]}"
        if confirm_prompt "👉 確定要永久刪除備份 '$chosen_bk' 嗎？[y/N]: "; then
          rm -f "$BACKUP_DIR/$chosen_bk.v4.rules" \
                "$BACKUP_DIR/$chosen_bk.v6.rules" \
                "$BACKUP_DIR/$chosen_bk.meta"
          echo -e "${COLOR_GREEN}[✓] 備份檔案已成功清理！${COLOR_RESET}"
        fi
        echo ""
        echo -e "${COLOR_DIM}按任意鍵繼續...${COLOR_RESET}"
        read -n 1 -s
        ;;
        
      5|*)
        return
        ;;
    esac
  done
}

# --- 主程式選單迴圈 ---
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
  
  echo -e "📌 目前暫存區有 ${staged_styled} 條變更等待寫入測試\n"
  
  # 動態建構選項 4 (撤銷草稿) 說明
  revoke_desc=""
  if [ "$staged_count" -eq 0 ]; then
    revoke_desc="${COLOR_DIM}撤銷暫存區中的規則 (目前無草稿)${COLOR_RESET}"
  else
    revoke_desc="${COLOR_YELLOW}${COLOR_BOLD}撤銷暫存區中的規則 (🔥 目前有 ${staged_count} 條草稿)${COLOR_RESET}"
  fi
  
  # 動態建構選項 7 (修改策略) 說明
  policy_desc="修改 INPUT 鏈預設行為 (ACCEPT / DROP)"
  if [ -n "$STAGED_POLICY" ]; then
    policy_desc="${COLOR_YELLOW}${COLOR_BOLD}修改 INPUT 鏈預設行為 (⏳ 待修改為: ${STAGED_POLICY})${COLOR_RESET}"
  fi
  
  echo -e "${COLOR_BOLD}請選擇要執行的功能：${COLOR_RESET}"
  echo -e "  ${COLOR_CYAN}1)${COLOR_RESET} 查詢現有防火牆狀態"
  echo -e "  ${COLOR_CYAN}2)${COLOR_RESET} 新增 Port 限制規則至暫存區 (TCP/UDP)"
  echo -e "  ${COLOR_CYAN}3)${COLOR_RESET} 刪除已生效的現有規則 (新增刪除指令至暫存區)"
  echo -e "  ${COLOR_CYAN}4)${COLOR_RESET} ${revoke_desc}"
  echo -e "  ${COLOR_CYAN}5)${COLOR_RESET} 寫入暫存規則並開始 30 秒安全測試"
  echo -e "  ${COLOR_CYAN}6)${COLOR_RESET} 防火牆歷史快照備份與存檔還原管理"
  echo -e "  ${COLOR_CYAN}7)${COLOR_RESET} ${policy_desc}"
  echo -e "  ${COLOR_CYAN}q)${COLOR_RESET} 離開系統"
  echo ""
  echo -n "👉 請輸入選擇 (1-7, 或 q 離開): "
  
  read -r choice
  case "$choice" in
    1) show_status;;
    2) add_port;;
    3) delete_active_rules_menu;;
    4) revoke_staged_rule_flow;;
    5) apply_rules;;
    6) backup_restore_manager;;
    7) change_default_policy;;
    [Qq]) 
      exit_warn_count=$((staged_count + staged_policy_count))
      if [ $exit_warn_count -gt 0 ]; then
        echo -e "\n${COLOR_YELLOW}${COLOR_BOLD}⚠️  警告: 暫存區中目前有 ${exit_warn_count} 條未套用的變更草稿！${COLOR_RESET}"
        if ! confirm_prompt "👉 是否要放棄這些草稿並直接離開系統？[y/N]: "; then
          echo -e "${COLOR_GREEN}[i] 已取消離開，回到主選單。${COLOR_RESET}"
          sleep 1
          continue
        fi
      fi
      echo -e "\n${COLOR_GREEN}感謝使用防火牆管理系統，再會！${COLOR_RESET}"
      exit 0
      ;;
    *)
      echo -e "${COLOR_RED}[!] 輸入錯誤，請輸入 1 至 7 之間的數字，或輸入 q 離開！${COLOR_RESET}"
      sleep 1
      ;;
  esac
done
