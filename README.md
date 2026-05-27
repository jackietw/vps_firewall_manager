# VPS Firewall Security Management System (iptables & ip6tables)

[中文](#中文) | [English](#english)

---

## 中文

這是一個專為 Linux 虛擬專用伺服器 (VPS) 設計的**高效能、高可靠性雙軌同步防火牆安全管理系統**。它使用純 Bash 編寫，完美兼容各類主流 Linux 發行版（如 Debian、Ubuntu、CentOS、Rocky Linux 等），在終端提供優雅、對齊的表格視覺介面，並以 100% 安全的防鎖定設計（安全測試與自動還原）保障您的連線。

### 核心特色

1. **IPv4 / IPv6 同步管理**：支援將規則一鍵雙軌套用至 IPv4 (`iptables`) 與 IPv6 (`ip6tables`)，確保伺服器全面安全。
2. **智慧型自我測試系統 (Intelligent Self-Test)**：套用變更時會執行對應測試：
   * **放行規則 (ACCEPT)**：執行本地連線測試，防止您將自己（尤其是 SSH 連線）鎖在外面。
   * **阻擋規則 (DROP/REJECT)**：核心自動識別 Linux 本機迴路（lo）的物理限制，**跳過會引起誤報的本地連線測試**，改為執行 **「核心寫入狀態驗證」**，免除 false failure 誤報並給出外網驗證提示。
3. **安全測試與自動還原 (Fail-Safe Rollback)**：套用規則後啟動 **30 秒安全測試倒數**。若您因規則錯誤而與伺服器中斷連線，系統將於倒數結束後自動將防火牆還原至變更前的安全狀態，拒絕意外鎖定！
4. **重疊規則數學過濾 (Mathematical Overlap Checking)**：內建先進的 `spec_covered` 數學區間檢測演算法，在您輸入單一 Port、多重 Port 列表或 Port 範圍區間時，自動檢測暫存區與作用中規則是否已覆蓋該範圍，拒絕重複/多餘的規則寫入。
5. **套用前自動永久備份**：每次確認套用修改前，系統會自動在背景為您建立該次防火牆的永久存檔，方便您隨時還原到任何歷史節點。
6. **卓越的對齊與視覺系統**：精緻的黑字綠底反白選單、對齊的 ASCII 邊框、極佳的配色，並特別針對中英文混合字元寬度進行精準動態計算，提供完美的對齊視覺效果。
7. **開機自動存檔啟動**：支援 Debian/Ubuntu (`rules.v4/v6`) 與 RHEL/CentOS 的防火牆設定自動持久化，重啟不失效。

---

### 安裝與執行說明

將指令檔下載到您的 Linux 伺服器，賦予執行權限後使用 `sudo` 執行：

```bash
# 賦予執行權限
chmod +x vps_fw.sh

# 執行
sudo ./vps_fw.sh
```

---

### 功能選單說明

* **1) 查詢現有防火牆狀態**：以精緻的雙軌表格秀出作用中的 IPv4/IPv6 規則與暫存規則草稿。
* **2) 修改 INPUT 預設行為**：切換預設放行 (ACCEPT) 或預設阻擋 (DROP)。在切換至 DROP 時會自動執行 SSH 防呆安全檢測，若未開放 SSH，系統會強制在暫存區自動補上，避免自我阻擋！
* **3) 新增/移除防火牆規則**：
  * **新增規則**：快速開放或阻擋指定連接埠（支援單一、多個逗號、或冒號範圍），可限制來源 IP，並提供 `ACCEPT`、`DROP`、`REJECT` 三大動作。
  * **刪除規則**：進入支援連續刪除的互動式高亮子選單，規則在清單中被刪除後列表會動態重新渲染。
* **4) 處理暫存區中規則**：
  * **取消暫存區規則**：可在暫存區中以連續操作方式撤銷多筆變更草稿。
  * **寫入暫存區規則**：一鍵套用暫存變更，並啟用 30 秒安全測試倒數與智慧自檢。
* **5) 防火牆備份與還原管理**：手動備份、檢視歷史備份（包含系統自動備份）、刪除多餘備份，或一鍵還原到任何歷史防火牆狀態。

---
---

## English

An **ultra-reliable, high-security dual-track synchronous firewall management system** specially crafted for Linux Virtual Private Servers (VPS). Written entirely in Bash, it is 100% compatible with mainstream Linux distributions (Debian, Ubuntu, CentOS, Rocky Linux, etc.). It offers an elegant, perfectly aligned table UI directly inside your terminal, backed by an absolute fail-safe auto-rollback mechanism to prevent accidental lockout.

### Key Features

1. **IPv4 / IPv6 Synchronous Management**: Apply rules concurrently to IPv4 (`iptables`) and IPv6 (`ip6tables`) to secure your dual-stack VPS comprehensively.
2. **Intelligent Self-Test Engine**: Committing changes fires smart test suites:
   * **Allowed Rules (ACCEPT)**: Runs local loopback TCP connection tests to guarantee SSH accessibility, preventing lockouts.
   * **Blocked Rules (DROP/REJECT)**: Intelligently skips local TCP handshakes to bypass Linux loopback (`lo`) restrictions (preventing false failures), performs **kernel state verification**, and prints clean external verification guidance.
3. **Safety Countdown & Auto-Rollback (Fail-Safe)**: Applying changes starts a **30-second golden test countdown**. If you lose connection due to a misconfiguration, the system automatically detects it and rolls back to the previous stable state.
4. **Mathematical Overlap Detection**: Equipped with a advanced `spec_covered` math range checking algorithm. It dynamically validates single ports, multiport lists, and port ranges against active rules and staging queue, preventing duplicate or redundant rules.
5. **Auto-Backup on Application**: Before committing modifications, the system automatically creates a permanent stable backup in the history directory—no more worries about forgetting to back up.
6. **Outstanding Alignment & Visual UI**: Sleek high-contrast inverted menu (black-on-green), crisp ASCII borders, and precise dynamic byte-width calculations for clean, aligned table output regardless of character languages.
7. **Persistence on Boot**: Directly supports boot-persistence saving for Debian/Ubuntu (`rules.v4/v6`) and RHEL/CentOS systems.

---

### Download & Execution

Upload the script to your Linux server, make it executable, and run with `sudo`:

```bash
# Set execution permission
chmod +x vps_fw_en.sh

# Run
sudo ./vps_fw_en.sh
```

---

### Functions & Navigation Menu

* **1) Check Current Firewall Status**: View active IPv4/IPv6 rules along with pending staged rules in formatted, aligned tables.
* **2) Modify INPUT Chain Default Policy**: Switch between `ACCEPT` (allow-all) and `DROP` (block-all). Activating DROP triggers an active SSH fail-safe check to prevent locking yourself out!
* **3) Add/Remove Firewall Rules**:
  * **Add Rules**: Easily stage rules (supports single port, comma-separated, or colon ranges) with specific source IP limits, protocol selections (TCP/UDP/Dual), and action triggers (`ACCEPT`, `DROP`, `REJECT`).
  * **Delete Active Rules**: Access the continuous deletion sub-menu; rule selections immediately shrink the displayed active table in real-time.
* **4) Process Staged Rules**:
  * **Revoke Staged Rules**: Easily discard multiple draft modifications from your staging queue at once.
  * **Apply & Test Rules**: Apply all staged changes concurrently and trigger the 30-second rollback safety timer and intelligent self-test.
* **5) Firewall Backup & Restore Manager**: Create manual backups, list backups (including pre-apply system auto-generated backups), delete obsolete snapshots, or execute a one-key rollback to any historic snapshot.

---

### 📄 License

This project is released under the MIT License. Feel free to use, modify, and distribute it!
