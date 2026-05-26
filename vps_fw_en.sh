#!/usr/bin/env bash

# ==============================================================================
#   VPS Firewall Security Management System (iptables & ip6tables)
#   Language: Shell Script (100% compatible with Linux VPS running Bash)
#   Features: Dual-track IPv4/IPv6 sync, aligned tables, safety auto-test,
#             backup history management, and secure auto-rollback.
#   Design: High security and high reliability dual-track sync system.
# ==============================================================================

# --- Global Variables & Initialization ---
STAGED_RULES=()      # Format: "PORT|PROTOCOL|SOURCE|COMMENT|ACTION|IP_VERSION"
STAGED_POLICY=""     # Staged IPv4 policy: "", "ACCEPT", or "DROP"
STAGED_POLICY_V6=""  # Staged IPv6 policy: "", "ACCEPT", or "DROP"
BACKUP_DIR="./backups"

# --- Create Backup Directory ---
mkdir -p "$BACKUP_DIR"

# --- Terminal Color Settings ---
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

# --- Interactive Confirmation Ask ---
confirm_prompt() {
  local prompt_msg="$1"
  local key=""
  read -p "$prompt_msg" -n 1 -s key
  echo "" # Newline
  if [[ "$key" =~ ^[Yy]$ ]]; then
    return 0
  else
    return 1
  fi
}

# --- Helper: Dynamic Width-calculation for Aligned Tables ---
format_align() {
  local str="$1"
  local target_width="$2"
  local align="${3:-left}"
  
  # Calculate characters and bytes (excluding newlines)
  local len_char=$(echo -n "$str" | wc -m)
  local len_byte=$(echo -n "$str" | wc -c)
  
  # visual width = (len_byte + len_char) / 2 (accounts for double-width multi-byte chars)
  local visual_width=$(( (len_byte + len_char) / 2 ))
  
  # Calculate spaces to pad
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

# --- Privilege and Tools Check ---
if [ "$EUID" -ne 0 ]; then
  echo -e "${COLOR_RED}${COLOR_BOLD}[!] Error: Root privileges required. Please execute with sudo!${COLOR_RESET}"
  echo -e "${COLOR_RED}👉 Command: sudo ./vps_fw_en.sh${COLOR_RESET}"
  exit 1
fi

if ! command -v iptables &>/dev/null || ! command -v ip6tables &>/dev/null; then
  echo -e "${COLOR_RED}${COLOR_BOLD}[!] Error: iptables or ip6tables tools not detected! Terminating script.${COLOR_RESET}"
  exit 1
fi

# --- Helper: Detect Current Connected SSH Port ---
detect_current_ssh_port() {
  local detected_port="22"
  
  # 1. Parse from SSH_CONNECTION variable (highly accurate for active sessions)
  if [ -n "$SSH_CONNECTION" ]; then
    detected_port=$(echo "$SSH_CONNECTION" | awk '{print $4}')
  # 2. Parse from SSH daemon configuration file
  elif [ -f "/etc/ssh/sshd_config" ]; then
    local parsed_port
    parsed_port=$(grep -i '^Port' /etc/ssh/sshd_config 2>/dev/null | awk '{print $2}')
    if [ -n "$parsed_port" ] && [[ "$parsed_port" =~ ^[0-9]+$ ]]; then
      detected_port="$parsed_port"
    fi
  fi
  echo "$detected_port"
}

# --- Header Printing ---
print_header() {
  clear
  echo -e "${COLOR_CYAN}${COLOR_BOLD}=================================================================${COLOR_RESET}"
  echo -e "${COLOR_CYAN}${COLOR_BOLD}   VPS Firewall Security Management System (iptables/ip6tables)  ${COLOR_RESET}"
  echo -e "${COLOR_CYAN}${COLOR_BOLD}=================================================================${COLOR_RESET}"
  echo -e "${COLOR_GREEN}${COLOR_BOLD}   Successfully connected to system firewall with Root (Bash)${COLOR_RESET}"
  echo -e "${COLOR_GREEN}   -------------------------------------------------------------${COLOR_RESET}"
}

# --- Core Function 1: Fetch and Parse Firewall Rules ---
get_active_rules() {
  local family="${1:-v4}"
  local cmd="iptables"
  [ "$family" = "v6" ] && cmd="ip6tables"

  # High-efficiency regex parsing of active rules
  $cmd -S INPUT 2>/dev/null | while read -r line; do
    if [[ "$line" =~ ^-P ]]; then
      continue
    fi
    # Skip loopback and established connection states to keep output clean
    if [[ "$line" == *"-i lo"* || "$line" == *"RELATED,ESTABLISHED"* || "$line" == *"ctstate ESTABLISHED,RELATED"* ]]; then
      continue
    fi

    local proto="all"
    local port="All"
    local src="Anywhere"
    local target="ACCEPT"
    local comment=""

    # 1. Extract protocol
    if [[ "$line" =~ -p\ ([a-zA-Z0-9]+) ]]; then
      proto="${BASH_REMATCH[1]}"
    fi

    # 2. Extract port
    if [[ "$line" =~ --dport\ ([0-9]+) || "$line" =~ --dports\ ([0-9:,]+) ]]; then
      port="${BASH_REMATCH[1]}"
    fi

    # 3. Extract source IP
    if [[ "$line" =~ -s\ ([0-9a-fA-F./:]+) ]]; then
      src="${BASH_REMATCH[1]}"
    fi

    # 4. Extract comment
    if [[ "$line" =~ --comment\ \"([^\"]+)\" || "$line" =~ --comment\ ([^ ]+) ]]; then
      comment="${BASH_REMATCH[1]}"
    fi

    # 5. Extract action
    if [[ "$line" =~ -j\ ([A-Z_]+) ]]; then
      target="${BASH_REMATCH[1]}"
    fi

    echo "RULE|${proto}|${port}|${src}|${target}|${comment}"
  done
}

# --- Display Current Firewall Status ---
show_status() {
  print_header
  
  # --- 1. IPv4 Status ---
  local input_policy
  input_policy=$(iptables -S INPUT 2>/dev/null | grep '^-P INPUT' | awk '{print $3}')
  [ -z "$input_policy" ] && input_policy="ACCEPT"
  
  local policy_color=$COLOR_GREEN
  [ "$input_policy" = "DROP" ] && policy_color=$COLOR_RED
  
  local policy_suffix=""
  if [ -n "$STAGED_POLICY" ]; then
    local s_color=$COLOR_GREEN
    [ "$STAGED_POLICY" = "DROP" ] && s_color=$COLOR_RED
    policy_suffix=" (${COLOR_YELLOW}⏳ Change to: ${s_color}${COLOR_BOLD}${STAGED_POLICY}${COLOR_RESET})"
  fi
  
  echo -e "${COLOR_BOLD}🛡️  IPv4 INPUT Default Policy: ${policy_color}${COLOR_BOLD}${input_policy}${COLOR_RESET}${policy_suffix}"
  echo -e "${COLOR_BOLD}📊 Active IPv4 Rules:${COLOR_RESET}"
  echo -e "${COLOR_CYAN}┌────┬──────────┬──────────┬──────────────────────┬──────────┬────────────────────────┐${COLOR_RESET}"
  echo -e "${COLOR_CYAN}│ ID │ Protocol │ Port(s)  │ Source IP/CIDR       │ Action   │ Comment / Description  │${COLOR_RESET}"
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
      [ -z "$comment" ] && comment="None"
      
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
    no_rules_msg=$(format_align "                       No active custom IPv4 restriction rules." 85)
    echo -e "${COLOR_CYAN}│${COLOR_RESET}${no_rules_msg}${COLOR_CYAN}│${COLOR_RESET}"
  fi
  echo -e "${COLOR_CYAN}└────┴──────────┴──────────┴──────────────────────┴──────────┴────────────────────────┘${COLOR_RESET}"
  echo ""

  # --- 2. IPv6 Status ---
  local input_policy_v6
  input_policy_v6=$(ip6tables -S INPUT 2>/dev/null | grep '^-P INPUT' | awk '{print $3}')
  [ -z "$input_policy_v6" ] && input_policy_v6="ACCEPT"
  
  local policy_color_v6=$COLOR_GREEN
  [ "$input_policy_v6" = "DROP" ] && policy_color_v6=$COLOR_RED
  
  local policy_suffix_v6=""
  if [ -n "$STAGED_POLICY_V6" ]; then
    local s_color_v6=$COLOR_GREEN
    [ "$STAGED_POLICY_V6" = "DROP" ] && s_color_v6=$COLOR_RED
    policy_suffix_v6=" (${COLOR_YELLOW}⏳ Change to: ${s_color_v6}${COLOR_BOLD}${STAGED_POLICY_V6}${COLOR_RESET})"
  fi
  
  echo -e "${COLOR_BOLD}🛡️  IPv6 INPUT Default Policy: ${policy_color_v6}${COLOR_BOLD}${input_policy_v6}${COLOR_RESET}${policy_suffix_v6}"
  echo -e "${COLOR_BOLD}📊 Active IPv6 Rules:${COLOR_RESET}"
  echo -e "${COLOR_CYAN}┌────┬──────────┬──────────┬──────────────────────┬──────────┬────────────────────────┐${COLOR_RESET}"
  echo -e "${COLOR_CYAN}│ ID │ Protocol │ Port(s)  │ Source IP/CIDR       │ Action   │ Comment / Description  │${COLOR_RESET}"
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
      [ -z "$comment" ] && comment="None"
      
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
    no_rules_msg_v6=$(format_align "                       No active custom IPv6 restriction rules." 85)
    echo -e "${COLOR_CYAN}│${COLOR_RESET}${no_rules_msg_v6}${COLOR_CYAN}│${COLOR_RESET}"
  fi
  echo -e "${COLOR_CYAN}└────┴──────────┴──────────┴──────────────────────┴──────────┴────────────────────────┘${COLOR_RESET}"

  # --- 3. Staged / Draft Rules ---
  if [ ${#STAGED_RULES[@]} -gt 0 ]; then
    echo ""
    echo -e "${COLOR_YELLOW}${COLOR_BOLD}⏳ Pending / Staged Rules (Staged - Not yet applied):${COLOR_RESET}"
    echo -e "${COLOR_YELLOW}┌────┬──────────┬──────────┬──────────────────────┬──────────┬────────────────────────┐${COLOR_RESET}"
    local s_index=1
    for s_rule in "${STAGED_RULES[@]}"; do
      local port proto src comment target ip_version
      IFS='|' read -r port proto src comment target ip_version <<< "$s_rule"
      [ -z "$comment" ] && comment="None"
      
      local sign="+"
      local ver_suffix=""
      [ "$ip_version" = "ipv4" ] && ver_suffix="-v4"
      [ "$ip_version" = "ipv6" ] && ver_suffix="-v6"
      [ "$ip_version" = "both" ] && ver_suffix="-dual"
      
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
      
      local target_aligned=""
      if [[ "$target_text" == *"dual"* ]]; then
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
    echo -e "${COLOR_YELLOW}💡 Tip: Return to Main Menu and choose [5] to apply and test staged drafts.${COLOR_RESET}"
  fi
  
  echo ""
  echo -e "${COLOR_DIM}Press any key to return to menu...${COLOR_RESET}"
  read -n 1 -s
}

# --- Core Function 2: Add PORT Restriction Rule to Staging Area ---
add_port() {
  print_header
  echo -e "${COLOR_BOLD}➕ Add Firewall Port Rule (Staged Draft)${COLOR_RESET}\n"
  
  # 1. Input Port
  local port=""
  while true; do
    echo -n "👉 Enter Port(s) to allow/block (1-65535, e.g. 8080 or 80,443 or 8000:8010): "
    read -r port
    port="${port#"${port%%[![:space:]]*}"}"
    port="${port%"${port##*[![:space:]]}"}"
    
    if [ -z "$port" ]; then
      echo -e "${COLOR_RED}[!] Port cannot be empty, please re-enter.${COLOR_RESET}"
      continue
    fi
    if [[ ! "$port" =~ ^[0-9,:-]+$ ]]; then
      echo -e "${COLOR_RED}[!] Format error! Only numbers, commas (,) or colons (:) are allowed.${COLOR_RESET}"
      continue
    fi
    break
  done
  
  # 2. Select Protocol
  local proto=""
  while true; do
    echo -n "👉 Select Protocol [1) TCP  2) UDP  3) Dual (TCP+UDP)] (Default 1): "
    read -r proto_choice
    case "$proto_choice" in
      ""|1) proto="tcp"; break;;
      2) proto="udp"; break;;
      3) proto="both"; break;;
      *) echo -e "${COLOR_RED}[!] Invalid choice! Enter 1, 2 or 3.${COLOR_RESET}";;
    esac
  done
  
  # 3. Select IP Version
  local ip_ver=""
  while true; do
    echo -n "👉 Select IP Version [1) Dual-track (v4+v6)  2) IPv4 Only  3) IPv6 Only] (Default 1): "
    read -r ip_choice
    case "$ip_choice" in
      ""|1) ip_ver="both"; break;;
      2) ip_ver="ipv4"; break;;
      3) ip_ver="ipv6"; break;;
      *) echo -e "${COLOR_RED}[!] Invalid choice! Enter 1, 2 or 3.${COLOR_RESET}";;
    esac
  done
  
  # 4. Input Source Restriction
  local src=""
  echo -n "👉 Enter Source IP restriction (Press Enter for Anywhere, IPv6 e.g. ::1): "
  read -r src
  src="${src#"${src%%[![:space:]]*}"}"
  src="${src%"${src##*[![:space:]]}"}"
  if [ -z "$src" ]; then
    src="Anywhere"
  fi
  
  # 5. Select Connection Action
  local action=""
  while true; do
    echo -n "👉 Select Action [1) ACCEPT (Allow)  2) DROP (Block)] (Default 1): "
    read -r action_choice
    case "$action_choice" in
      ""|1) action="ACCEPT"; break;;
      2) action="DROP"; break;;
      *) echo -e "${COLOR_RED}[!] Invalid choice! Enter 1 or 2.${COLOR_RESET}";;
    esac
  done
  
  # 6. Input Remark / Comment
  local comment=""
  echo -n "👉 Enter brief comment/memo (e.g. Web Server, can be empty): "
  read -r comment
  comment="${comment#"${comment%%[![:space:]]*}"}"
  comment="${comment%"${comment##*[![:space:]]}"}"
  if [ -z "$comment" ]; then
    comment="No remark"
  fi
  
  # 7. Add to Staged Rules
  if [ "$proto" = "both" ]; then
    STAGED_RULES+=("${port}|tcp|${src}|${comment}|${action}|${ip_ver}")
    STAGED_RULES+=("${port}|udp|${src}|${comment}|${action}|${ip_ver}")
    echo -e "\n${COLOR_GREEN}[✓] Successfully staged 2 dual-track rules (TCP & UDP Port ${port})!${COLOR_RESET}"
  else
    STAGED_RULES+=("${port}|${proto}|${src}|${comment}|${action}|${ip_ver}")
    echo -e "\n${COLOR_GREEN}[✓] Successfully staged rule (Port ${port}/${proto})!${COLOR_RESET}"
  fi
  
  echo ""
  echo -e "${COLOR_DIM}Press any key to return to menu...${COLOR_RESET}"
  read -n 1 -s
}

# --- Core Function 3: Continuous Stage Rules for Deletion ---
delete_active_rule_flow() {
  local family="$1"
  local fam_str="IPv4"
  [ "$family" = "v6" ] && fam_str="IPv6"

  while true; do
    print_header
    echo -e "${COLOR_BOLD}🗑️  Select active ${fam_str} rules to DELETE (This adds 'DELETE' draft to staging area):${COLOR_RESET}"
    echo -e "${COLOR_DIM}💡 Multiple continuous choices supported. Press Enter to return to menu.${COLOR_RESET}\n"
    
    echo -e "${COLOR_CYAN}┌────┬──────────┬──────────┬──────────────────────┬──────────┬────────────────────────┐${COLOR_RESET}"
    echo -e "${COLOR_CYAN}│ ID │ Protocol │ Port(s)  │ Source IP/CIDR       │ Action   │ Comment / Description  │${COLOR_RESET}"
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
        
        # Check if this rule is already staged for deletion
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
        
        # Skip rules already staged for deletion to make the list dynamically shrink
        if [ "$is_already_staged_deleted" = true ]; then
          continue
        fi
        
        rules_array+=("$rule_data")
        
        local proto port src target comment
        IFS='|' read -r proto port src target comment <<< "$rule_data"
        [ -z "$comment" ] && comment="None"
        
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
      no_rules_msg=$(format_align "                       No active custom ${fam_str} rules found." 85)
      echo -e "${COLOR_CYAN}│${COLOR_RESET}${no_rules_msg}${COLOR_CYAN}│${COLOR_RESET}"
      echo -e "${COLOR_CYAN}└────┴──────────┴──────────┴──────────────────────┴──────────┴────────────────────────┘${COLOR_RESET}"
      echo -e "\n${COLOR_YELLOW}[!] Currently no rules available for deletion.${COLOR_RESET}"
      echo -e "${COLOR_DIM}Press any key to return...${COLOR_RESET}"
      read -n 1 -s
      return
    fi
    echo -e "${COLOR_CYAN}└────┴──────────┴──────────┴──────────────────────┴──────────┴────────────────────────┘${COLOR_RESET}"
    
    echo ""
    echo -n "👉 Enter ID of the rule to delete (1-$((index-1))), or directly press Enter to return: "
    read -r choice_num
    if [ -z "$choice_num" ]; then
      return
    fi
    
    if [[ ! "$choice_num" =~ ^[0-9]+$ ]] || [ "$choice_num" -lt 1 ] || [ "$choice_num" -ge "$index" ]; then
      echo -e "${COLOR_RED}[!] Invalid ID! Please re-enter.${COLOR_RESET}"
      sleep 1
      continue
    fi
    
    # Extract chosen rule details
    local chosen_rule="${rules_array[$((choice_num-1))]}"
    local proto port src target comment
    IFS='|' read -r proto port src target comment <<< "$chosen_rule"
    
    # Store deletion instruction in Staged Rules (DELETE_<action>)
    local ip_ver="ipv4"
    [ "$family" = "v6" ] && ip_ver="ipv6"
    STAGED_RULES+=("${port}|${proto}|${src}|${comment}|DELETE_${target}|${ip_ver}")
    
    echo -e "\n${COLOR_GREEN}[✓] Successfully staged 'DELETE ${fam_str} Port ${port}/${proto}' in staging queue!${COLOR_RESET}"
    echo -e "${COLOR_YELLOW}💡 Tip: Rule deletion is pending. Choose [5] from Main Menu to write and test changes.${COLOR_RESET}"
    sleep 1.5
  done
}

# --- Core Function 4: Continuous Revoke Rules from Staging Area ---
revoke_staged_rule_flow() {
  while true; do
    print_header
    echo -e "${COLOR_BOLD}⏳ Select staged rules to REVOKE (This removes drafts directly from queue):${COLOR_RESET}"
    echo -e "${COLOR_DIM}💡 Multiple continuous choices supported. Press Enter to return to Main Menu.${COLOR_RESET}\n"
    
    if [ ${#STAGED_RULES[@]} -eq 0 ]; then
      echo -e "${COLOR_YELLOW}[!] Staging area is currently empty. No draft rules to revoke.${COLOR_RESET}"
      echo ""
      echo -e "${COLOR_DIM}Press any key to return...${COLOR_RESET}"
      read -n 1 -s
      return
    fi
    
    echo -e "${COLOR_YELLOW}┌────┬──────────┬──────────┬──────────────────────┬──────────┬────────────────────────┐${COLOR_RESET}"
    local s_index=1
    for s_rule in "${STAGED_RULES[@]}"; do
      local port proto src comment target ip_version
      IFS='|' read -r port proto src comment target ip_version <<< "$s_rule"
      [ -z "$comment" ] && comment="None"
      
      local sign="+"
      local ver_suffix=""
      [ "$ip_version" = "ipv4" ] && ver_suffix="-v4"
      [ "$ip_version" = "ipv6" ] && ver_suffix="-v6"
      [ "$ip_version" = "both" ] && ver_suffix="-dual"
      
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
      
      local target_aligned=""
      if [[ "$target_text" == *"dual"* ]]; then
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
    echo -n "👉 Enter ID of staged rule to revoke (1-$((s_index-1))), or directly press Enter to return: "
    read -r choice_num
    if [ -z "$choice_num" ]; then
      return
    fi
    
    if [[ ! "$choice_num" =~ ^[0-9]+$ ]] || [ "$choice_num" -lt 1 ] || [ "$choice_num" -ge "$s_index" ]; then
      echo -e "${COLOR_RED}[!] Invalid ID! Please re-enter.${COLOR_RESET}"
      sleep 1
      continue
    fi
    
    # Remove item from array
    local index_to_remove=$((choice_num-1))
    local new_staged=()
    for i in "${!STAGED_RULES[@]}"; do
      if [ "$i" -ne "$index_to_remove" ]; then
        new_staged+=("${STAGED_RULES[$i]}")
      fi
    done
    STAGED_RULES=("${new_staged[@]}")
    
    echo -e "\n${COLOR_GREEN}[✓] Successfully revoked staged rule draft from queue!${COLOR_RESET}"
    sleep 1.5
  done
}

# --- Submenu: Delete Active Rules ---
delete_active_rules_menu() {
  while true; do
    print_header
    echo -e "${COLOR_BOLD}❌ Delete Active Rules (Adds 'DELETE' commands to staging area)${COLOR_RESET}\n"
    echo -e "  ${COLOR_CYAN}1)${COLOR_RESET} Delete Active IPv4 Rules"
    echo -e "  ${COLOR_CYAN}2)${COLOR_RESET} Delete Active IPv6 Rules"
    echo -e "  ${COLOR_CYAN}3)${COLOR_RESET} Return to Main Menu"
    echo ""
    echo -n "👉 Please choose option (1-3): "
    read -r del_choice
    case "$del_choice" in
      1) delete_active_rule_flow v4;;
      2) delete_active_rule_flow v6;;
      3|*) return;;
    esac
  done
}

# --- Core Function: Modify INPUT Default Policy (ACCEPT/DROP) ---
change_default_policy() {
  print_header
  echo -e "${COLOR_BOLD}🛡️  Modify INPUT Chain Default Policy (Default Action)${COLOR_RESET}\n"
  
  # 1. Fetch current default actions
  local input_policy
  local input_policy_v6
  input_policy=$(iptables -S INPUT 2>/dev/null | grep '^-P INPUT' | awk '{print $3}')
  [ -z "$input_policy" ] && input_policy="ACCEPT"
  input_policy_v6=$(ip6tables -S INPUT 2>/dev/null | grep '^-P INPUT' | awk '{print $3}')
  [ -z "$input_policy_v6" ] && input_policy_v6="ACCEPT"
  
  echo -e "Current IPv4 INPUT policy: ${COLOR_BOLD}${input_policy}${COLOR_RESET}"
  echo -e "Current IPv6 INPUT policy: ${COLOR_BOLD}${input_policy_v6}${COLOR_RESET}\n"
  
  # 2. Select target policy
  local target_policy=""
  while true; do
    echo -n "👉 Select target policy [1) ACCEPT (Allow-all)  2) DROP (Block-all)] (Default 1): "
    read -r policy_choice
    case "$policy_choice" in
      ""|1) target_policy="ACCEPT"; break;;
      2) target_policy="DROP"; break;;
      *) echo -e "${COLOR_RED}[!] Invalid choice! Enter 1 or 2.${COLOR_RESET}";;
    esac
  done
  
  # 3. If switching to DROP, run active SSH fail-safe scan
  if [ "$target_policy" = "DROP" ]; then
    echo -e "\n${COLOR_CYAN}[i] Scanning active SSH configuration for fail-safe check...${COLOR_RESET}"
    
    local ssh_port
    ssh_port=$(detect_current_ssh_port)
    local ssh_allowed=false
    local ssh_allowed_v6=false
    
    # 3.1 Check active firewall rules
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
    
    # 3.2 Check staged rules queue
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
      echo -e "${COLOR_YELLOW}[⚠️  WARNING] Current SSH port (${ssh_port}/tcp) is NOT allowed. To prevent lockout, system has auto-staged an ACCEPT rule for IPv4 SSH port!${COLOR_RESET}"
      STAGED_RULES+=("${ssh_port}|tcp|Anywhere|Auto-staged SSH port allow|ACCEPT|ipv4")
    fi
    if [ "$ssh_allowed_v6" = false ]; then
      echo -e "${COLOR_YELLOW}[⚠️  WARNING] Current SSH port (${ssh_port}/tcp) is NOT allowed. To prevent lockout, system has auto-staged an ACCEPT rule for IPv6 SSH port!${COLOR_RESET}"
      STAGED_RULES+=("${ssh_port}|tcp|Anywhere|Auto-staged SSH port allow|ACCEPT|ipv6")
    fi
  fi
  
  if confirm_prompt "👉 Are you sure you want to stage default policy change to ${target_policy}? [y/N]: "; then
    STAGED_POLICY="$target_policy"
    STAGED_POLICY_V6="$target_policy"
    echo -e "${COLOR_GREEN}[✓] Successfully staged default policy changes! Please return to Main Menu and choose [5] to apply and test changes.${COLOR_RESET}"
  else
    echo -e "${COLOR_YELLOW}[!] Modification cancelled.${COLOR_RESET}"
  fi
  
  echo ""
  echo -e "${COLOR_DIM}Press any key to return to menu...${COLOR_RESET}"
  read -n 1 -s
}

# --- Core Function 5: Apply Staged Rules with Safety Auto-rollback Test ---
apply_rules() {
  if [ ${#STAGED_RULES[@]} -eq 0 ] && [ -z "$STAGED_POLICY" ] && [ -z "$STAGED_POLICY_V6" ]; then
    echo -e "${COLOR_YELLOW}[!] Staging queue is empty. No rules to write or test!${COLOR_RESET}"
    sleep 1.5
    return
  fi
  
  # --- 1. Dual-track Independent Safety Backup ---
  local backup_file_v4="/tmp/vps_fw_v4_bak.$(date +%s)"
  local backup_file_v6="/tmp/vps_fw_v6_bak.$(date +%s)"
  local success=true

  if ! iptables-save > "$backup_file_v4" 2>/dev/null || ! ip6tables-save > "$backup_file_v6" 2>/dev/null; then
    echo -e "${COLOR_RED}[Error] Could not back up firewall! To ensure safety, this application has been terminated.${COLOR_RESET}"
    rm -f "$backup_file_v4" "$backup_file_v6"
    echo -e "${COLOR_DIM}Press any key to return to menu...${COLOR_RESET}"
    read -n 1 -s
    return
  fi
  
  echo -e "${COLOR_CYAN}[i] Writing new rules to active system...${COLOR_RESET}"
  for s_rule in "${STAGED_RULES[@]}"; do
    local port proto src comment action ip_version
    IFS='|' read -r port proto src comment action ip_version <<< "$s_rule"
    
    local is_delete=false
    local real_action="$action"
    if [[ "$action" == DELETE_* ]]; then
      is_delete=true
      real_action="${action#DELETE_}"
    fi
    
    local run_v4=false
    local run_v6=false
    [ "$ip_version" = "both" ] || [ "$ip_version" = "ipv4" ] && run_v4=true
    [ "$ip_version" = "both" ] || [ "$ip_version" = "ipv6" ] && run_v6=true
    
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
    [ -n "$comment" ] && [ "$comment" != "No remark" ] && basic_args+=("-m" "comment" "--comment" "$comment")
    basic_args+=("-j" "$real_action")
    
    # Apply to IPv4
    if [ "$run_v4" = true ]; then
      local cmd=("iptables")
      [ "$is_delete" = true ] && cmd+=("-D" "INPUT") || cmd+=("-A" "INPUT")
      cmd+=("${basic_args[@]}")
      if ! "${cmd[@]}" 2>/dev/null; then
        echo -e "${COLOR_RED}[!] IPv4 application failed, instruction: ${cmd[*]}${COLOR_RESET}"
        success=false
        break
      fi
    fi
    
    # Apply to IPv6
    if [ "$run_v6" = true ]; then
      local cmd=("ip6tables")
      [ "$is_delete" = true ] && cmd+=("-D" "INPUT") || cmd+=("-A" "INPUT")
      cmd+=("${basic_args[@]}")
      if ! "${cmd[@]}" 2>/dev/null; then
        echo -e "${COLOR_RED}[!] IPv6 application failed, instruction: ${cmd[*]}${COLOR_RESET}"
        success=false
        break
      fi
    fi
  done
  
  # If any rule failed, execute instant dual-track rollback
  if [ "$success" = false ]; then
    echo -e "${COLOR_YELLOW}[i] Some rules failed! Restoring firewall configuration...${COLOR_RESET}"
    iptables-restore < "$backup_file_v4" 2>/dev/null
    ip6tables-restore < "$backup_file_v6" 2>/dev/null
    rm -f "$backup_file_v4" "$backup_file_v6"
    echo -e "${COLOR_RED}[Error] Application failed. Restored to pre-change state.${COLOR_RESET}"
    echo -e "${COLOR_DIM}Press any key to return to menu...${COLOR_RESET}"
    read -n 1 -s
    return
  fi
  
  # Apply Default Policy Staged Changes (if any)
  if [ "$success" = true ]; then
    if [ -n "$STAGED_POLICY" ]; then
      echo -e "${COLOR_CYAN}[i] Applying IPv4 INPUT default policy to ${STAGED_POLICY}...${COLOR_RESET}"
      if ! iptables -P INPUT "$STAGED_POLICY" 2>/dev/null; then
        echo -e "${COLOR_RED}[!] IPv4 default policy application failed!${COLOR_RESET}"
        success=false
      fi
    fi
    if [ "$success" = true ] && [ -n "$STAGED_POLICY_V6" ]; then
      echo -e "${COLOR_CYAN}[i] Applying IPv6 INPUT default policy to ${STAGED_POLICY_V6}...${COLOR_RESET}"
      if ! ip6tables -P INPUT "$STAGED_POLICY_V6" 2>/dev/null; then
        echo -e "${COLOR_RED}[!] IPv6 default policy application failed!${COLOR_RESET}"
        success=false
      fi
    fi
  fi
  
  # If policy modification failed, rollback
  if [ "$success" = false ]; then
    echo -e "${COLOR_YELLOW}[i] Policy application failed. Restoring firewall configuration...${COLOR_RESET}"
    iptables-restore < "$backup_file_v4" 2>/dev/null
    ip6tables-restore < "$backup_file_v6" 2>/dev/null
    rm -f "$backup_file_v4" "$backup_file_v6"
    echo -e "${COLOR_RED}[Error] Application failed. Restored to pre-change state.${COLOR_RESET}"
    echo -e "${COLOR_DIM}Press any key to return to menu...${COLOR_RESET}"
    read -n 1 -s
    return
  fi

  # --- 2. Automatic Self-Test Stage ---
  local v4_policy="ACCEPT"
  local v6_policy="ACCEPT"
  v4_policy=$(iptables -S INPUT 2>/dev/null | grep '^-P INPUT' | awk '{print $3}')
  [ -z "$v4_policy" ] && v4_policy="ACCEPT"
  v6_policy=$(ip6tables -S INPUT 2>/dev/null | grep '^-P INPUT' | awk '{print $3}')
  [ -z "$v6_policy" ] && v6_policy="ACCEPT"
  [ -n "$STAGED_POLICY" ] && v4_policy="$STAGED_POLICY"
  [ -n "$STAGED_POLICY_V6" ] && v6_policy="$STAGED_POLICY_V6"

  echo -e "\n${COLOR_CYAN}${COLOR_BOLD}🔍 Running automatic self-test for modified rules (Auto Self-Test)...${COLOR_RESET}"
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
        echo -e "  ${COLOR_DIM}[i] Port ranges (${port}) are not supported in automatic self-test. Skipping.${COLOR_RESET}"
        continue
      fi
      
      IFS=',' read -r -a ports_to_test <<< "$port"
      for single_port in "${ports_to_test[@]}"; do
        single_port="${single_port#"${single_port%%[![:space:]]*}"}"
        single_port="${single_port%"${single_port##*[![:space:]]}"}"
        [ "$single_port" = "All" ] && continue
        
        local expected_str="${COLOR_RED}BLOCKED${COLOR_RESET}"
        [ "$expected_open" = true ] && expected_str="${COLOR_GREEN}ALLOWED${COLOR_RESET}"
        
        # 2.1 Test IPv4 (if rule applies)
        if [ "$ip_version" = "both" ] || [ "$ip_version" = "ipv4" ]; then
          echo -e "  👉 Testing IPv4 TCP Port ${single_port} (Expected Status: ${expected_str})..."
          
          local skip_test=false
          if [ "$is_delete" = true ]; then
            if [ "$target_action" = "ACCEPT" ] && [ "$v4_policy" = "ACCEPT" ]; then
              skip_test=true
            elif [ "$target_action" = "DROP" ] && [ "$v4_policy" = "DROP" ]; then
              skip_test=true
            fi
          fi
          
          if [ "$skip_test" = true ]; then
            echo -e "     ${COLOR_DIM}[i] Skip test: Default policy is ${v4_policy}; no need to test deletion of a ${target_action} rule.${COLOR_RESET}"
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
                test_msg="Connection successful (HTTP/HTTPS service active)"
              elif [ $curl_status -eq 7 ]; then
                test_success=true
                test_msg="Firewall allowed (but local service not active)"
              elif [ $curl_status -eq 28 ] || [ $curl_status -eq 35 ]; then
                test_success=false
                test_msg="Connection timed out (blocked by firewall)"
              else
                test_success=true
                test_msg="Firewall allowed, but connection anomalous (CODE: $curl_status)"
              fi
            else
              timeout 2 bash -c "cat < /dev/null > /dev/tcp/127.0.0.1/${single_port}" 2>/dev/null
              local tcp_status=$?
              if [ $tcp_status -eq 0 ]; then
                test_success=true
                test_msg="Connection successful (TCP handshake complete)"
              elif [ $tcp_status -eq 124 ]; then
                test_success=false
                test_msg="Connection timed out (blocked by firewall)"
              else
                test_success=true
                test_msg="Firewall allowed (but no local listener active)"
              fi
            fi
            
            if [ "$expected_open" = true ]; then
              [ "$test_success" = true ] && echo -e "     ${COLOR_GREEN}✓ IPv4 Test PASSED: ${test_msg}${COLOR_RESET}" || echo -e "     ${COLOR_RED}✗ IPv4 Test FAILED: ${test_msg}${COLOR_RESET}"
            else
              [ "$test_success" = false ] && echo -e "     ${COLOR_GREEN}✓ IPv4 Test PASSED: ${test_msg}${COLOR_RESET}" || echo -e "     ${COLOR_RED}✗ IPv4 Test FAILED: Expected blocked but connection succeeded (${test_msg})${COLOR_RESET}"
            fi
          fi
        fi
        
        # 2.2 Test IPv6 (if rule applies)
        if [ "$ip_version" = "both" ] || [ "$ip_version" = "ipv6" ]; then
          echo -e "  👉 Testing IPv6 TCP Port ${single_port} (Expected Status: ${expected_str})..."
          
          local skip_test_v6=false
          if [ "$is_delete" = true ]; then
            if [ "$target_action" = "ACCEPT" ] && [ "$v6_policy" = "ACCEPT" ]; then
              skip_test_v6=true
            elif [ "$target_action" = "DROP" ] && [ "$v6_policy" = "DROP" ]; then
              skip_test_v6=true
            fi
          fi
          
          if [ "$skip_test_v6" = true ]; then
            echo -e "     ${COLOR_DIM}[i] Skip test: Default policy is ${v6_policy}; no need to test deletion of a ${target_action} rule.${COLOR_RESET}"
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
                test_msg_v6="Connection successful (HTTP/HTTPS service active)"
              elif [ $curl_status -eq 7 ]; then
                test_success_v6=true
                test_msg_v6="Firewall allowed (but local service not active)"
              elif [ $curl_status -eq 28 ] || [ $curl_status -eq 35 ]; then
                test_success_v6=false
                test_msg_v6="Connection timed out (blocked by firewall)"
              else
                test_success_v6=true
                test_msg_v6="Firewall allowed, but connection anomalous (CODE: $curl_status)"
              fi
            else
              timeout 2 bash -c "cat < /dev/null > /dev/tcp/::1/${single_port}" 2>/dev/null
              local tcp_status=$?
              if [ $tcp_status -eq 0 ]; then
                test_success_v6=true
                test_msg_v6="Connection successful (TCP handshake complete)"
              elif [ $tcp_status -eq 124 ]; then
                test_success_v6=false
                test_msg_v6="Connection timed out (blocked by firewall)"
              else
                test_success_v6=true
                test_msg_v6="Firewall allowed (but no local listener active)"
              fi
            fi
            
            if [ "$expected_open" = true ]; then
              [ "$test_success_v6" = true ] && echo -e "     ${COLOR_GREEN}✓ IPv6 Test PASSED: ${test_msg_v6}${COLOR_RESET}" || echo -e "     ${COLOR_RED}✗ IPv6 Test FAILED: ${test_msg_v6}${COLOR_RESET}"
            else
              [ "$test_success_v6" = false ] && echo -e "     ${COLOR_GREEN}✓ IPv6 Test PASSED: ${test_msg_v6}${COLOR_RESET}" || echo -e "     ${COLOR_RED}✗ IPv6 Test FAILED: Expected blocked but connection succeeded (${test_msg_v6})${COLOR_RESET}"
            fi
          fi
        fi
        
      done
    fi
  done
  echo -e "--------------------------------------------------------"

  # --- 3. Safety Countdown Confirmation Block (Rollback Countdown) ---
  local timeout=30
  local confirmed=false
  echo -e "\n${COLOR_YELLOW}${COLOR_BOLD}🔥 New firewall rules temporarily applied! Starting safety countdown...${COLOR_RESET}"
  echo -e "${COLOR_CYAN}💡 Quickly open a NEW connection/window to verify SSH & services are fully active!${COLOR_RESET}"
  echo -e "If any anomaly occurs and blocks you, do NOT operate; countdown expiration will auto-rollback."
  echo ""
  
  while (( timeout > 0 )); do
    echo -ne "\r\033[K🕒 Time remaining before rollback: ${COLOR_RED}${COLOR_BOLD}${timeout}${COLOR_RESET} seconds... [Press ${COLOR_GREEN}${COLOR_BOLD}Y/y${COLOR_RESET} to KEEP rules, ${COLOR_RED}${COLOR_BOLD}N/n${COLOR_RESET} to ROLLBACK immediately]: "
    
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
  echo "" # Newline
  
  # --- 4. Final Processing Stage ---
  if [ "$confirmed" = true ]; then
    echo -e "\n${COLOR_GREEN}${COLOR_BOLD}[✓] Congratulations! New firewall rules confirmed stable and permanently applied!${COLOR_RESET}"
    
    # Save a permanent backup of pre-applied firewall state
    local auto_bk_name="auto_before_apply_$(date +%Y%m%d_%H%M%S)"
    if cp "$backup_file_v4" "$BACKUP_DIR/${auto_bk_name}.v4.rules" 2>/dev/null && \
       cp "$backup_file_v6" "$BACKUP_DIR/${auto_bk_name}.v6.rules" 2>/dev/null; then
      echo "Date: $(date '+%Y-%m-%d %H:%M:%S')" > "$BACKUP_DIR/${auto_bk_name}.meta"
      echo "Desc: Auto-backup before applying modifications" >> "$BACKUP_DIR/${auto_bk_name}.meta"
      echo -e "${COLOR_CYAN}[i] System has auto-generated a backup of previous stable state: ${auto_bk_name}${COLOR_RESET}"
    fi

    # Clean temporary backups
    rm -f "$backup_file_v4" "$backup_file_v6"
    STAGED_RULES=()
    STAGED_POLICY=""
    STAGED_POLICY_V6=""
    
    # Prompt for boot persistence
    echo -e "\n${COLOR_BOLD}💾 Enable automatic loading of firewall rules on system boot?${COLOR_RESET}"
    local saved=false
    if [ -d "/etc/iptables" ]; then
      echo -e "  Detected Debian/Ubuntu persistence path (${COLOR_CYAN}/etc/iptables/rules.v4${COLOR_RESET})"
      if confirm_prompt "👉 Write rules to persistence path (v4 & v6 files)? [y/N]: "; then
        iptables-save > /etc/iptables/rules.v4
        ip6tables-save > /etc/iptables/rules.v6
        echo -e "${COLOR_GREEN}[✓] Persistent rules saved to /etc/iptables/rules.v[4|6]!${COLOR_RESET}"
        saved=true
      fi
    elif [ -f "/etc/sysconfig/iptables" ]; then
      echo -e "  Detected RHEL/CentOS persistence path (${COLOR_CYAN}/etc/sysconfig/iptables${COLOR_RESET})"
      if confirm_prompt "👉 Write rules to persistence path (iptables & ip6tables)? [y/N]: "; then
        iptables-save > /etc/sysconfig/iptables
        ip6tables-save > /etc/sysconfig/ip6tables
        echo -e "${COLOR_GREEN}[✓] Persistent rules saved to /etc/sysconfig/iptables & ip6tables!${COLOR_RESET}"
        saved=true
      fi
    fi
    
    if [ "$saved" = false ]; then
      echo -e "\n${COLOR_YELLOW}[Tip] To persist manually on boot, you may run the following command: ${COLOR_RESET}"
      echo -e "  IPv4: ${COLOR_BOLD}sudo iptables-save > /etc/iptables/rules.v4${COLOR_RESET}"
      echo -e "  IPv6: ${COLOR_BOLD}sudo ip6tables-save > /etc/iptables/rules.v6${COLOR_RESET}"
    fi
  else
    # Rollback execution due to timeout or user denial
    echo -e "\n${COLOR_RED}${COLOR_BOLD}[!] Test cancelled or timed out! Automatically restoring firewall (Rollback)...${COLOR_RESET}"
    iptables-restore < "$backup_file_v4" 2>/dev/null
    ip6tables-restore < "$backup_file_v6" 2>/dev/null
    rm -f "$backup_file_v4" "$backup_file_v6"
    echo -e "${COLOR_GREEN}[✓] Firewall successfully rolled back! Secure and safe.${COLOR_RESET}"
  fi
  
  echo ""
  echo -e "${COLOR_DIM}Press any key to return to menu...${COLOR_RESET}"
  read -n 1 -s
}

# --- Core Function 6: Firewall Backup & Restore Manager ---
backup_restore_manager() {
  while true; do
    print_header
    echo -e "${COLOR_BOLD}💾 Firewall Backup File Management System${COLOR_RESET}\n"
    echo -e "  ${COLOR_CYAN}1)${COLOR_RESET} Create Manual Firewall Backup"
    echo -e "  ${COLOR_CYAN}2)${COLOR_RESET} View Existing Backup List"
    echo -e "  ${COLOR_CYAN}3)${COLOR_RESET} Restore Specific Firewall Backup"
    echo -e "  ${COLOR_CYAN}4)${COLOR_RESET} Delete Specific Backup"
    echo -e "  ${COLOR_CYAN}5)${COLOR_RESET} Return to Main Menu"
    echo ""
    echo -n "👉 Please choose option (1-5): "
    read -r bk_choice
    
    case "$bk_choice" in
      1)
        print_header
        echo -e "${COLOR_BOLD}📸 Create Manual Firewall Backup${COLOR_RESET}\n"
        echo -n "👉 Enter backup name (A-Z, 0-9, under_score only, e.g. base_config): "
        read -r bk_name
        # Filter non-alphanumeric/underscore
        bk_name=$(echo "$bk_name" | sed 's/[^a-zA-Z0-9_]//g')
        if [ -z "$bk_name" ]; then
          echo -e "${COLOR_RED}[!] Invalid name or empty!${COLOR_RESET}"
          sleep 1.5
          continue
        fi
        
        echo -n "👉 Enter brief description/memo for the backup: "
        read -r bk_desc
        [ -z "$bk_desc" ] && bk_desc="Manual backup"
        
        if iptables-save > "$BACKUP_DIR/$bk_name.v4.rules" 2>/dev/null && \
           ip6tables-save > "$BACKUP_DIR/$bk_name.v6.rules" 2>/dev/null; then
           
          # Write metadata
          echo "Date: $(date '+%Y-%m-%d %H:%M:%S')" > "$BACKUP_DIR/$bk_name.meta"
          echo "Desc: $bk_desc" >> "$BACKUP_DIR/$bk_name.meta"
          echo -e "\n${COLOR_GREEN}[✓] Firewall backup successfully created! Stored as: $bk_name${COLOR_RESET}"
        else
          echo -e "\n${COLOR_RED}[✗] Backup failed! Check folder write permissions.${COLOR_RESET}"
          rm -f "$BACKUP_DIR/$bk_name.v4.rules" "$BACKUP_DIR/$bk_name.v6.rules"
        fi
        echo ""
        echo -e "${COLOR_DIM}Press any key to continue...${COLOR_RESET}"
        read -n 1 -s
        ;;
        
      2)
        print_header
        echo -e "${COLOR_BOLD}📋 Existing Backup History List:${COLOR_RESET}\n"
        
        local meta_files=("$BACKUP_DIR"/*.meta)
        if [ ! -e "${meta_files[0]}" ]; then
          echo -e "${COLOR_YELLOW}[!] No backup files currently exist in historical records.${COLOR_RESET}"
          echo ""
          echo -e "${COLOR_DIM}Press any key to continue...${COLOR_RESET}"
          read -n 1 -s
          continue
        fi
        
        echo -e "${COLOR_CYAN}┌────┬────────────────────────┬─────────────────────┬────────────────────────────────┐${COLOR_RESET}"
        echo -e "${COLOR_CYAN}│ ID │ Backup Snapshot Name   │ Generation Time     │ Remark / Description           │${COLOR_RESET}"
        echo -e "${COLOR_CYAN}├────┼────────────────────────┼─────────────────────┼────────────────────────────────┤${COLOR_RESET}"
        
        local idx=1
        for meta_f in "${meta_files[@]}"; do
          local name_raw
          name_raw=$(basename "$meta_f" .meta)
          
          local bk_date=""
          local bk_desc=""
          
          # Parse metadata
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
          
          printf "${COLOR_CYAN}│${COLOR_RESET} %-2d ${COLOR_CYAN}│${COLOR_RESET} %s │ %-19s │ %s ${COLOR_CYAN}│${COLOR_RESET}\n" \
            $idx "$name_aligned" "$bk_date" "$desc_aligned"
          ((idx++))
        done
        echo -e "${COLOR_CYAN}└────┴────────────────────────┴─────────────────────┴────────────────────────────────┘${COLOR_RESET}"
        echo ""
        echo -e "${COLOR_DIM}Press any key to continue...${COLOR_RESET}"
        read -n 1 -s
        ;;
        
      3)
        print_header
        echo -e "${COLOR_BOLD}⏪ Restore Historical Firewall Snapshot${COLOR_RESET}\n"
        
        local meta_files=("$BACKUP_DIR"/*.meta)
        local bk_list=()
        if [ ! -e "${meta_files[0]}" ]; then
          echo -e "${COLOR_YELLOW}[!] No backup files currently exist for restoration.${COLOR_RESET}"
          echo ""
          echo -e "${COLOR_DIM}Press any key to continue...${COLOR_RESET}"
          read -n 1 -s
          continue
        fi
        
        echo -e "Please select a backup to restore:"
        local idx=1
        for meta_f in "${meta_files[@]}"; do
          local name_raw
          name_raw=$(basename "$meta_f" .meta)
          bk_list+=("$name_raw")
          echo -e "  ${COLOR_CYAN}${idx})${COLOR_RESET} $name_raw ($(< "$meta_f" | grep 'Desc:' | cut -d' ' -f2-))"
          ((idx++))
        done
        echo ""
        echo -n "👉 Enter ID of backup to restore (or press Enter to cancel): "
        read -r select_num
        if [ -z "$select_num" ]; then
          continue
        fi
        
        if [[ ! "$select_num" =~ ^[0-9]+$ ]] || [ "$select_num" -lt 1 ] || [ "$select_num" -ge "$idx" ]; then
          echo -e "${COLOR_RED}[!] Invalid ID!${COLOR_RESET}"
          sleep 1.5
          continue
        fi
        
        local chosen_bk="${bk_list[$((select_num-1))]}"
        
        # Dual-track presence checks
        local has_v4=false
        local has_v6=false
        [ -f "$BACKUP_DIR/$chosen_bk.v4.rules" ] && has_v4=true
        [ -f "$BACKUP_DIR/$chosen_bk.v6.rules" ] && has_v6=true
        
        if [ "$has_v4" = false ] && [ "$has_v6" = false ]; then
          echo -e "${COLOR_RED}[!] Snapshot rule files for this backup are missing!${COLOR_RESET}"
          sleep 1.5
          continue
        fi
        
        echo -e "\n${COLOR_YELLOW}${COLOR_BOLD}⚠️  WARNING: Restoring this historical snapshot will overwrite all active firewall rules!${COLOR_RESET}"
        if ! confirm_prompt "👉 Are you sure you want to perform this rollback? [y/N]: "; then
          echo -e "${COLOR_YELLOW}[!] Restoration cancelled.${COLOR_RESET}"
          sleep 1.5
          continue
        fi
        
        if [ "$has_v4" = true ] && [ "$has_v6" = true ]; then
          # Full Dual-track Restore
          iptables-restore < "$BACKUP_DIR/$chosen_bk.v4.rules" 2>/dev/null
          ip6tables-restore < "$BACKUP_DIR/$chosen_bk.v6.rules" 2>/dev/null
          echo -e "${COLOR_GREEN}[✓] IPv4 / IPv6 firewall rules successfully restored!${COLOR_RESET}"
        elif [ "$has_v4" = true ]; then
          echo -e "${COLOR_YELLOW}[!] Warning: This backup only contains an IPv4 snapshot.${COLOR_RESET}"
          if confirm_prompt "👉 Restore IPv4 only and keep current IPv6 unchanged? [y/N]: "; then
            iptables-restore < "$BACKUP_DIR/$chosen_bk.v4.rules" 2>/dev/null
            echo -e "${COLOR_GREEN}[✓] IPv4 firewall successfully restored!${COLOR_RESET}"
          fi
        elif [ "$has_v6" = true ]; then
          echo -e "${COLOR_YELLOW}[!] Warning: This backup only contains an IPv6 snapshot.${COLOR_RESET}"
          if confirm_prompt "👉 Restore IPv6 only and keep current IPv4 unchanged? [y/N]: "; then
            ip6tables-restore < "$BACKUP_DIR/$chosen_bk.v6.rules" 2>/dev/null
            echo -e "${COLOR_GREEN}[✓] IPv6 firewall successfully restored!${COLOR_RESET}"
          fi
        fi
        echo ""
        echo -e "${COLOR_DIM}Press any key to continue...${COLOR_RESET}"
        read -n 1 -s
        ;;
        
      4)
        print_header
        echo -e "${COLOR_BOLD}❌ Delete Backup Snapshot File${COLOR_RESET}\n"
        
        local meta_files=("$BACKUP_DIR"/*.meta)
        local bk_list=()
        if [ ! -e "${meta_files[0]}" ]; then
          echo -e "${COLOR_YELLOW}[!] No backup files currently exist in directory.${COLOR_RESET}"
          echo ""
          echo -e "${COLOR_DIM}Press any key to continue...${COLOR_RESET}"
          read -n 1 -s
          continue
        fi
        
        echo -e "Please select a backup to delete:"
        local idx=1
        for meta_f in "${meta_files[@]}"; do
          local name_raw
          name_raw=$(basename "$meta_f" .meta)
          bk_list+=("$name_raw")
          echo -e "  ${COLOR_CYAN}${idx})${COLOR_RESET} $name_raw"
          ((idx++))
        done
        echo ""
        echo -n "👉 Enter ID of backup to delete (or press Enter to cancel): "
        read -r select_num
        if [ -z "$select_num" ]; then
          continue
        fi
        
        if [[ ! "$select_num" =~ ^[0-9]+$ ]] || [ "$select_num" -lt 1 ] || [ "$select_num" -ge "$idx" ]; then
          echo -e "${COLOR_RED}[!] Invalid ID!${COLOR_RESET}"
          sleep 1.5
          continue
        fi
        
        local chosen_bk="${bk_list[$((select_num-1))]}"
        
        if confirm_prompt "👉 Are you sure you want to permanently delete backup '$chosen_bk'? [y/N]: "; then
          rm -f "$BACKUP_DIR/$chosen_bk.v4.rules"
          rm -f "$BACKUP_DIR/$chosen_bk.v6.rules"
          rm -f "$BACKUP_DIR/$chosen_bk.meta"
          echo -e "${COLOR_GREEN}[✓] Backup snapshot successfully deleted!${COLOR_RESET}"
        else
          echo -e "${COLOR_YELLOW}[!] Deletion cancelled.${COLOR_RESET}"
        fi
        echo ""
        echo -e "${COLOR_DIM}Press any key to continue...${COLOR_RESET}"
        read -n 1 -s
        ;;
        
      5)
        return
        ;;
        
      *)
        echo -e "${COLOR_RED}[!] Invalid choice! Enter 1 to 5.${COLOR_RESET}"
        sleep 1.5
        ;;
    esac
  done
}

# --- Main Program Loop ---
while true; do
  print_header
  
  # Fetch staging details count
  staged_count=${#STAGED_RULES[@]}
  staged_policy_count=0
  [ -n "$STAGED_POLICY" ] && ((staged_policy_count++))
  [ -n "$STAGED_POLICY_V6" ] && ((staged_policy_count++))
  
  total_staged=$((staged_count + staged_policy_count))
  staged_styled="${COLOR_CYAN}${COLOR_BOLD}${total_staged}${COLOR_RESET}"
  if [ "$total_staged" -gt 0 ]; then
    staged_styled="${COLOR_YELLOW}${COLOR_BOLD}${total_staged}${COLOR_RESET}"
  fi
  
  echo -e "📌 Staging queue: ${staged_styled} pending modifications waiting to be applied.\n"
  
  # Construct menu option 4 description
  revoke_desc=""
  if [ "$staged_count" -eq 0 ]; then
    revoke_desc="${COLOR_DIM}Revoke Staged Rules from Staging Queue (No drafts)${COLOR_RESET}"
  else
    revoke_desc="${COLOR_YELLOW}${COLOR_BOLD}Revoke Staged Rules from Staging Queue (🔥 ${staged_count} drafts pending)${COLOR_RESET}"
  fi
  
  # Construct menu option 7 description
  policy_desc="Modify INPUT Chain Default Policy (ACCEPT / DROP)"
  if [ -n "$STAGED_POLICY" ]; then
    policy_desc="${COLOR_YELLOW}${COLOR_BOLD}Modify INPUT Chain Default Policy (⏳ Pending change to: ${STAGED_POLICY})${COLOR_RESET}"
  fi
  
  echo -e "${COLOR_BOLD}Please select a function option:${COLOR_RESET}"
  echo -e "  ${COLOR_CYAN}1)${COLOR_RESET} Check Current Firewall Status"
  echo -e "  ${COLOR_CYAN}2)${COLOR_RESET} Add Port Restriction Rule to Staging Area (TCP/UDP)"
  echo -e "  ${COLOR_CYAN}3)${COLOR_RESET} Delete Active Rules (Add 'DELETE' commands to staging area)"
  echo -e "  ${COLOR_CYAN}4)${COLOR_RESET} ${revoke_desc}"
  echo -e "  ${COLOR_CYAN}5)${COLOR_RESET} Apply Staged Rules and Start 30s Safety Test"
  echo -e "  ${COLOR_CYAN}6)${COLOR_RESET} Firewall Backup & Restore Manager"
  echo -e "  ${COLOR_CYAN}7)${COLOR_RESET} ${policy_desc}"
  echo -e "  ${COLOR_CYAN}q)${COLOR_RESET} Exit System"
  echo ""
  echo -n "👉 Enter your choice (1-7, or q to exit): "
  
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
        echo -e "\n${COLOR_YELLOW}${COLOR_BOLD}⚠️  WARNING: You have ${exit_warn_count} pending unapplied staged drafts!${COLOR_RESET}"
        if ! confirm_prompt "👉 Are you sure you want to discard these drafts and exit? [y/N]: "; then
          echo -e "${COLOR_GREEN}[i] Exit cancelled. Returning to main menu.${COLOR_RESET}"
          sleep 1
          continue
        fi
      fi
      echo -e "\n${COLOR_GREEN}Thank you for using VPS Firewall Security Management System. Goodbye!${COLOR_RESET}"
      exit 0
      ;;
    *)
      echo -e "${COLOR_RED}[!] Invalid entry. Enter numbers 1 to 7, or press q to exit!${COLOR_RESET}"
      sleep 1
      ;;
  esac
done
