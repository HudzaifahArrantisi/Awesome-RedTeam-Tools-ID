#!/bin/bash
# ==============================================================
# fix-ssh-dc.sh — Fix all SSH disconnect causes on Kali Linux
# ==============================================================
# Menangani:
#   1. Auto sleep / suspend
#   2. Screen lock / screensaver
#   3. SSH keepalive (client + server)
#   4. Network power saving
#   5. TCP keepalive kernel
#   6. Auto-jalankan tools via tmux
# ==============================================================

BOLD='\033[1m'; RED='\033[91m'; GREEN='\033[92m'; YELLOW='\033[93m'; CYAN='\033[96m'; NC='\033[0m'
ok="echo -e ${GREEN}[✓]${NC}"; info="echo -e ${CYAN}[i]${NC}"; wrn="echo -e ${YELLOW}[!]${NC}"; err="echo -e ${RED}[✗]${NC}"

echo -e "${BOLD}${RED}"
echo "╔══════════════════════════════════════════════╗"
echo "║        ${GREEN}KALI SSH DISCONNECT FIXER${RED}            ║"
echo "╚══════════════════════════════════════════════╝"
echo -e "${NC}"

# ─── Cek root ───
if [ "$EUID" -ne 0 ]; then
    $err "Jalankan sebagai root: sudo bash fix-ssh-dc.sh"
    exit 1
fi

# ================================================================
# 1. MATIKAN AUTO SLEEP / SUSPEND
# ================================================================
echo -e "\n${BOLD}[1] Disable system sleep / suspend${NC}"

# Systemd targets
systemctl mask sleep.target suspend.target hibernate.target hybrid-sleep.target 2>/dev/null
$ok "Systemd sleep targets masked (sleep, suspend, hibernate, hybrid-sleep)"

# Matikan lid switch (laptop)
if [ -f /etc/systemd/logind.conf ]; then
    sed -i 's/^#*HandleLidSwitch=.*/HandleLidSwitch=ignore/' /etc/systemd/logind.conf
    sed -i 's/^#*HandleLidSwitchExternalPower=.*/HandleLidSwitchExternalPower=ignore/' /etc/systemd/logind.conf
    sed -i 's/^#*HandleLidSwitchDocked=.*/HandleLidSwitchDocked=ignore/' /etc/systemd/logind.conf
    $ok "Lid switch disabled in logind.conf"
fi

# Prevent screen blanking (X11)
gsettings set org.gnome.desktop.session idle-delay 0 2>/dev/null
gsettings set org.gnome.desktop.screensaver lock-enabled false 2>/dev/null
gsettings set org.gnome.desktop.screensaver idle-activation-enabled false 2>/dev/null
$ok "GNOME idle/screensaver disabled"

# xset (X11 session)
if command -v xset &>/dev/null; then
    xset s off 2>/dev/null
    xset s noblank 2>/dev/null
    xset -dpms 2>/dev/null
    $ok "xset: screen saver off, DPMS disabled"
fi

# Mask systemd-suspend services
for svc in systemd-suspend.service systemd-hibernate.service systemd-hybrid-sleep.service systemd-suspend-then-hibernate.service; do
    systemctl mask "$svc" 2>/dev/null
done
$ok "Systemd suspend services masked"

# ================================================================
# 2. SSH KEEPALIVE — CLIENT
# ================================================================
echo -e "\n${BOLD}[2] Configure SSH keepalive (client)${NC}"

SSH_CONFIG="$HOME/.ssh/config"
mkdir -p "$HOME/.ssh"
chmod 700 "$HOME/.ssh"

# Hapus Host * block lama biar nggak duplikat
sed -i '/^Host \*$/,/^$/d; /^Host \*$/,/^[[:space:]]*$/d' "$SSH_CONFIG" 2>/dev/null

cat >> "$SSH_CONFIG" << 'EOF'

Host *
    ServerAliveInterval 15
    ServerAliveCountMax 6
    TCPKeepAlive yes
    IPQoS throughput
EOF
chmod 600 "$SSH_CONFIG"
$ok "SSH client keepalive configured (interval=15, count=6)"

# ================================================================
# 3. SSH KEEPALIVE — SERVER
# ================================================================
echo -e "\n${BOLD}[3] Configure SSH keepalive (server)${NC}"

SSHD_CONFIG="/etc/ssh/sshd_config"
if [ -f "$SSHD_CONFIG" ]; then
    # Backup
    cp "$SSHD_CONFIG" "${SSHD_CONFIG}.bak.$(date +%s)"

    # Set values
    for opt in "ClientAliveInterval 15" "ClientAliveCountMax 6" "TCPKeepAlive yes"; do
        key="${opt%% *}"
        sed -i "/^${key}[[:space:]]/d" "$SSHD_CONFIG"
        sed -i "/^#${key}[[:space:]]/d" "$SSHD_CONFIG"
    done
    echo -e "\nClientAliveInterval 15\nClientAliveCountMax 6\nTCPKeepAlive yes" >> "$SSHD_CONFIG"

    systemctl restart sshd 2>/dev/null || systemctl restart ssh 2>/dev/null
    $ok "SSH server keepalive configured & restarted"
fi

# ================================================================
# 4. TCP KEEPALIVE KERNEL
# ================================================================
echo -e "\n${BOLD}[4] Configure TCP keepalive (kernel)${NC}"

SYSCTL_FILE="/etc/sysctl.d/90-tcp-keepalive.conf"
cat > "$SYSCTL_FILE" << 'EOF'
# TCP keepalive — mencegah idle timeout
net.ipv4.tcp_keepalive_time = 60
net.ipv4.tcp_keepalive_intvl = 10
net.ipv4.tcp_keepalive_probes = 6
EOF
sysctl -p "$SYSCTL_FILE" 2>&1 | sed 's/^/  /'
$ok "Kernel TCP keepalive: time=60s, interval=10s, probes=6"

# ================================================================
# 5. NETWORK POWER MANAGEMENT
# ================================================================
echo -e "\n${BOLD}[5] Disable network power saving${NC}"

# Wireless
for iface in $(iw dev 2>/dev/null | awk '/Interface/{print $2}'); do
    iw dev "$iface" set power_save off 2>/dev/null && $ok "WiFi power save OFF: $iface" || $wrn "Can't set power_save on $iface"
done

# Disable NetworkManager wifi power save
NM_CONF="/etc/NetworkManager/conf.d/wifi-power-save-off.conf"
mkdir -p /etc/NetworkManager/conf.d
cat > "$NM_CONF" << 'EOF'
[connection]
wifi.powersave = 2
EOF
systemctl restart NetworkManager 2>/dev/null
$ok "NetworkManager WiFi powersave disabled"

# ================================================================
# 6. BUAT LAUNCHER SCRIPT (tmux wrapper)
# ================================================================
echo -e "\n${BOLD}[6] Create tmux launcher for RedTeam-Tools${NC}"

cat > /usr/local/bin/rtoolkit-tmux << 'SCRIPTLAUNCHER'
#!/bin/bash
# rtoolkit-tmux — Jalankan rtoolkit-kali.py di dalam tmux
# Biar aman walau SSH disconnect, process tetap jalan.

SESSION="redteam"
TOOL_DIR="/root/RedTeam-Tools"
SCRIPT="rtoolkit-kali.py"

# Cek tool dir
if [ ! -d "$TOOL_DIR" ]; then
    # Coba relatif dari home
    TOOL_DIR="$HOME/RedTeam-Tools"
fi

if [ ! -f "$TOOL_DIR/$SCRIPT" ]; then
    echo "[!] $TOOL_DIR/$SCRIPT not found!"
    echo "    Set TOOL_DIR di script ini sesuai lokasi repo."
    exit 1
fi

# Cek tmux installed
if ! command -v tmux &>/dev/null; then
    echo "[!] tmux not installed. Install dulu:"
    echo "    sudo apt install tmux -y"
    exit 1
fi

# Cek apakah session udah ada
tmux has-session -t "$SESSION" 2>/dev/null

if [ $? -eq 0 ]; then
    echo "[i] Session '$SESSION' sudah ada."
    echo "    Attach: tmux attach -t $SESSION"
    echo "    Kill:   tmux kill-session -t $SESSION"
    exit 0
fi

# Buat session baru
cd "$TOOL_DIR"
tmux new-session -d -s "$SESSION" -n "rtoolkit"
tmux send-keys -t "$SESSION" "cd $TOOL_DIR && python3 $SCRIPT" Enter

echo "[✓] Session '$SESSION' created!"
echo ""
echo "    Attach: tmux attach -t $SESSION"
echo "    Detach: Ctrl+B, D"
echo "    Status: tmux ls"
echo ""
echo "    SSH disconnect? Tenang, process tetap jalan."
echo "    Reconnect SSH lalu: tmux attach -t $SESSION"
SCRIPTLAUNCHER

chmod +x /usr/local/bin/rtoolkit-tmux
$ok "Launcher created: /usr/local/bin/rtoolkit-tmux"

# ================================================================
# 7. INSTALL tmux (kalau belum)
# ================================================================
echo -e "\n${BOLD}[7] Ensure tmux is installed${NC}"
apt install tmux -y 2>/dev/null && $ok "tmux installed" || $wrn "Could not install tmux"

# ================================================================
# DONE
# ================================================================
echo -e "\n${BOLD}${GREEN}══════════════════════════════════════════════${NC}"
echo -e "${BOLD}${GREEN}  ALL FIXES APPLIED SUCCESSFULLY${NC}"
echo -e "${BOLD}${GREEN}══════════════════════════════════════════════${NC}"
echo ""
echo -e "  ${CYAN}PENTING:${NC} Re-login SSH atau reboot biar semua effect jalan."
echo ""
echo -e "  ${BOLD}Cara pakai:${NC}"
echo -e "    ${GREEN}rtoolkit-tmux${NC}           → jalankan tools di tmux"
echo -e "    ${GREEN}tmux attach -t redteam${NC}  → balik ke session"
echo -e "    ${GREEN}Ctrl+B, D${NC}               → detach (biar jalan terus)"
echo ""
echo -e "  ${BOLD}Config baru di v4.0:${NC}"
echo -e "    ${GREEN}~/.rtoolkit/config.json${NC}  → ubah LHOST, timeout, wordlist, dll"
echo -e "    ${GREEN}nano ~/.rtoolkit/config.json${NC}"
echo ""
echo -e "  ${BOLD}Testing SSH keepalive:${NC}"
echo -e "    ${GREEN}ssh -o ServerAliveInterval=15 -o ServerAliveCountMax=6 user@kali-ip${NC}"
echo ""
