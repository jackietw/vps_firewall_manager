# 🛡️ VPS Firewall Security Management System (iptables & ip6tables)

[中文](#中文) | [English](#english)

---

## 中文

這是一個專為 Linux 虛擬專用伺服器 (VPS) 設計的**高效能、高可靠性雙軌同步防火牆安全管理系統**。它使用純 Bash 編寫，完美兼容各類主流 Linux 發行版，可直接在終端提供優雅、對齊的表格視覺介面，並以 100% 安全的防鎖定設計（安全測試與自動還原）保障您的連線。

### 🌟 核心特色

1. **IPv4 / IPv6 同步管理**：支援將規則一鍵套用至 IPv4 (`iptables`) 與 IPv6 (`ip6tables`)，確保伺服器在雙棧網路下的全面安全。
2. **安全測試與自動還原 (Rollback)**：套用規則時會啟動 **30秒黃金測試倒數**。在此期間若您不幸因規則錯誤而斷線，伺服器會自動偵測並還原至原先正常的狀態，拒絕意外鎖定！
3. **套用前自動永久備份**：每次確認套用修改前，系統會自動在背景為您抓取穩定的防火牆快照並永久存檔，免去忘記備份的後顧之憂。
4. **流暢的「連續」規則處理**：
   * **連續刪除**：選擇刪除後，列表會動態重新渲染並過濾已暫存項目，不需反覆進出選單。
   * **連續撤銷**：可在暫存區（Staging queue）中一口氣撤銷多筆變更草稿。
5. **卓越的對齊與視覺系統**：高質感的配色與邊框，針對中英文混合字元寬度進行精準動態計算，提供完美的對齊視覺效果。
6. **開機啟動與存檔**：支援 Debian/Ubuntu 與 RHEL/CentOS 的防火牆設定自動載入，重啟不失效。

---

### 🚀 安裝與執行說明

將指令檔下載到您的 Linux 伺服器，賦予執行權限後使用 `sudo` 執行：

```bash
# 賦予執行權限
chmod +x vps_fw.sh

# 執行
sudo ./vps_fw.sh
```

---

### 📂 功能選單說明

* **1) 查詢現有防火牆狀態**：以精緻的表格一併秀出作用中的 IPv4/IPv6 規則與暫存規則草稿。
* **2) 新增 Port 限制規則至暫存區**：快速開放或阻擋指定連接埠（支援單一、多個逗號、或區間範圍），限制特定 IP，並將變更暫存。
* **3) 刪除已生效的現有規則**：進入連續刪除選單，規則在清單中被刪除後列表會動態遞減。
* **4) 撤銷暫存區中的規則**：在寫入前反悔？進入連續撤銷選單將變更直接從暫存草稿中移出。
* **5) 寫入暫存規則並開始 30 秒安全測試**：一鍵套用暫存變更，並啟用 30 秒安全黃金測試與自動還原計時器。
* **6) 防火牆備份與還原管理**：建立手動備份、檢視歷史清單（包含每次套用前系統自動建立的備份），或一鍵還原到任何歷史節點。
* **7) 修改 INPUT 鏈預設行為**：切換預設放行 (ACCEPT) 或預設阻擋 (DROP)。在切換至 DROP 時會自動執行 SSH 防呆安全檢測，避免您將自己阻擋在外！

---
---

## English

An **ultra-reliable, high-security dual-track synchronous firewall management system** specially crafted for Linux Virtual Private Servers (VPS). Written entirely in Bash, it is 100% compatible with mainstream Linux distributions. It offers an elegant, perfectly aligned table UI directly inside your terminal, backed by an absolute fail-safe auto-rollback mechanism to prevent accidental lockout.

### 🌟 Key Features

1. **IPv4 / IPv6 Synchronous Management**: Apply rules concurrently to IPv4 (`iptables`) and IPv6 (`ip6tables`) to secure your dual-stack VPS comprehensively.
2. **Safety Countdown & Auto-Rollback (Fail-Safe)**: Applying changes starts a **30-second golden test countdown**. If you lose connection due to a misconfiguration, the system automatically detects it and rolls back to the previous stable state.
3. **Auto-Backup on Application**: Before committing new modifications, the system automatically creates a permanent stable backup in the history directory—no more worries about forgetting to back up.
4. **Smooth "Continuous" Operations**:
   * **Continuous Deletion**: Staged deletions are processed in a loop; the rule table dynamically shrinks in real-time as rules are queued for deletion.
   * **Continuous Revocation**: Easily discard multiple draft modifications from your staging queue at once.
5. **Outstanding Alignment & Visual UI**: Curated color schemes and border characters with precise dynamic byte-width calculations for clean, aligned table output regardless of character languages.
6. **Persistence on Boot**: Directly supports boot-persistence saving for Debian/Ubuntu (`rules.v4/v6`) and RHEL/CentOS systems.

---

### 🚀 Download & Execution

Upload the script to your Linux server, make it executable, and run with `sudo`:

```bash
# Set execution permission
chmod +x vps_fw_en.sh

# Run
sudo ./vps_fw_en.sh
```

---

### 📂 Functions & Navigation Menu

* **1) Check Current Firewall Status**: View active IPv4/IPv6 rules along with pending staged rules in formatted, aligned tables.
* **2) Add Port Restriction Rule to Staging Area**: Add port rules (supports single port, comma-separated, or colon ranges) with specific source IP limits, and keep them in staging queue.
* **3) Delete Active Rules**: Access the continuous deletion sub-menu; rule selections immediately shrink the displayed active table.
* **4) Revoke Staged Rules from Staging Queue**: Regretting a staged modification? Access the continuous revocation flow to remove drafts.
* **5) Apply Staged Rules and Start 30s Safety Test**: Apply all staged changes concurrently and trigger the 30-second rollback safety timer.
* **6) Firewall Backup & Restore Manager**: Create manual backups, list backups (including pre-apply system auto-generated backups), or execute a one-key rollback to any historic snapshot.
* **7) Modify INPUT Chain Default Policy**: Switch between ACCEPT (allow-all) and DROP (block-all). Activating DROP triggers an active SSH fail-safe check to prevent locking yourself out!

---

### 📄 License

This project is released under the MIT License. Feel free to use, modify, and distribute it!
