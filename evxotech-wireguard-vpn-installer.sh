#!/usr/bin/env bash
#
# evxotech-wireguard-vpn-installer.sh
# EvxoTech WireGuard VPN Installer — version: v1.3.2-02112025
# Purpose: Install WireGuard + wg-dashboard-pro (advanced GUI) with Docker fallback.
# - Semi-automated: auto-detects defaults, asks single confirmation before proceeding.
# - Works in LXC (nesting enabled) and on VMs/hosts.
# - Default GUI ports: HTTP 10080, HTTPS 10443
#
set -euo pipefail

VERSION="v1.3.2-02112025"
LOGDIR="/var/log/evxotech-wireguard"
LOGFILE="${LOGDIR}/install.log"
WORKDIR="/opt/evxotech"
DASHBOARD_DIR="${WORKDIR}/wg-dashboard"
COMPOSE_FILE="${DASHBOARD_DIR}/docker-compose.yml"
SYSTEMD_SERVICE="/etc/systemd/system/evxotech-wg-dashboard.service"
UNINSTALL_SCRIPT="/root/evxotech-wireguard-uninstaller.sh"

# Defaults
WG_PORT_DEFAULT="5555"
DASH_HTTP_DEFAULT="10080"
DASH_HTTPS_DEFAULT="10443"
ADMIN_USER_DEFAULT="admin"
ADMIN_PASS_DEFAULT="Admin@123"
WG_CIDR_DEFAULT="10.120.80.0/24"
CLIENTS_DEFAULT="1"
CLIENT_DNS_DEFAULT="10.120.80.10"
WG_DASHBOARD_IMAGE_DEFAULT="wg-dashboard-pro:latest"
WG_EASY_FALLBACK="weejewel/wg-easy:latest"

# Colors
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BLUE='\033[0;34m'; NC='\033[0m'

mkdir -p "$LOGDIR" "$WORKDIR"
touch "$LOGFILE"

log()   { echo -e "[$(date '+%F %T')] $*" | tee -a "$LOGFILE"; }
info()  { echo -e "${BLUE}$*${NC}" | tee -a "$LOGFILE"; }
ok()    { echo -e "${GREEN}$*${NC}" | tee -a "$LOGFILE"; }
warn()  { echo -e "${YELLOW}$*${NC}" | tee -a "$LOGFILE"; }
fatal() { echo -e "${RED}$*${NC}" | tee -a "$LOGFILE"; exit 1; }

require_root() {
  if [ "$(id -u)" -ne 0 ]; then
    fatal "This script must be run as root."
  fi
}

# Early uninstall path
FORCE_UNINSTALL=false
if [[ "${1:-}" == "--uninstall" ]]; then
  if [[ "${2:-}" == "--force" || "${3:-}" == "--force" ]]; then
    FORCE_UNINSTALL=true
  fi
  echo
  echo -e "${YELLOW}==== EvxoTech WireGuard Full Uninstall ====${NC}"
  if [ "$FORCE_UNINSTALL" != "true" ]; then
    read -rp $'\e[33mAre you sure you want to completely remove WireGuard, GUI, and all data? (y/N): \e[0m' CONFIRM
    if [[ ! "$CONFIRM" =~ ^[Yy]$ ]]; then
      echo "Aborted."
      exit 0
    fi
  else
    echo -e "${YELLOW}Force uninstall selected — proceeding without confirmation.${NC}"
  fi

  log "Stopping services and removing containers..."
  systemctl stop evxotech-wg-dashboard.service 2>/dev/null || true
  systemctl disable evxotech-wg-dashboard.service 2>/dev/null || true
  if command -v docker >/dev/null 2>&1; then
    docker-compose -f "$COMPOSE_FILE" down 2>/dev/null || docker compose -f "$COMPOSE_FILE" down 2>/dev/null || true
    docker rm -f evxotech-wg-dashboard 2>/dev/null || true
  fi

  log "Removing data and configs..."
  rm -rf "$DASHBOARD_DIR" "$WORKDIR/wg-data" /etc/evxotech 2>/dev/null || true
  rm -f "$SYSTEMD_SERVICE" 2>/dev/null || true
  rm -f /usr/local/bin/evxotech-wg-add-client 2>/dev/null || true
  rm -f "$UNINSTALL_SCRIPT" 2>/dev/null || true
  rm -rf "$LOGDIR" 2>/dev/null || true
  systemctl daemon-reload || true

  ok "Uninstall complete. Backups (if any) left in /etc/wireguard-backup-*"
  exit 0
fi

# -------------------------
# Precheck (runs on all installs; if Docker present certain kernel checks are skipped)
# -------------------------
precheck() {
  log "Running precheck..."
  # detect Docker presence
  if command -v docker >/dev/null 2>&1; then
    DOCKER_AVAILABLE=true
    ok "Docker detected."
  else
    DOCKER_AVAILABLE=false
    warn "Docker not detected."
  fi

  # detect LXC
  IS_LXC=false
  if grep -qa "container=lxc" /proc/1/environ 2>/dev/null || systemd-detect-virt -v 2>/dev/null | grep -qi lxc; then
    IS_LXC=true
    ok "LXC detected."
  fi

  # check /dev/net/tun
  if [ -c /dev/net/tun ]; then
    ok "/dev/net/tun exists."
  else
    warn "/dev/net/tun missing."
    # try to create (may fail if host blocks)
    mkdir -p /dev/net 2>/dev/null || true
    if mknod /dev/net/tun c 10 200 2>/dev/null; then
      chmod 0666 /dev/net/tun || true
      ok "Created /dev/net/tun."
    else
      warn "Could not create /dev/net/tun. Host must provide TUN or run privileged container/VM."
    fi
  fi

  # check sysctl forwarding
  CURRENT_FWD=$(sysctl -n net.ipv4.ip_forward 2>/dev/null || echo "0")
  if [ "$CURRENT_FWD" = "1" ]; then
    ok "IPv4 forwarding already enabled."
  else
    warn "IPv4 forwarding is disabled (will enable during install)."
  fi

  # check existing wg tools
  if command -v wg >/dev/null 2>&1 || command -v wg-quick >/dev/null 2>&1; then
    ok "WireGuard tools detected."
  else
    warn "WireGuard tools not present; will install if needed."
  fi

  # show public IP detection attempt
  PUBLIC_IP_AUTO=$(curl -fs4 ifconfig.co 2>/dev/null || curl -fs4 icanhazip.com 2>/dev/null || echo "")
  if [ -n "$PUBLIC_IP_AUTO" ]; then
    ok "Auto-detected public IP: $PUBLIC_IP_AUTO"
  else
    warn "Could not detect public IP automatically."
  fi
}

# -------------------------
# Helpers
# -------------------------
detect_docker_compose_cmd() {
  if docker compose version >/dev/null 2>&1; then
    DOCKER_COMPOSE_CMD="docker compose"
  elif command -v docker-compose >/dev/null 2>&1; then
    DOCKER_COMPOSE_CMD="docker-compose"
  else
    DOCKER_COMPOSE_CMD=""
  fi
}

install_docker_if_needed() {
  if command -v docker >/dev/null 2>&1; then
    ok "Docker already installed."
  else
    info "Installing Docker..."
    apt-get update -y >>"$LOGFILE" 2>&1
    apt-get install -y ca-certificates curl gnupg lsb-release >>"$LOGFILE" 2>&1
    curl -fsSL https://get.docker.com -o /tmp/get-docker.sh >>"$LOGFILE" 2>&1
    sh /tmp/get-docker.sh >>"$LOGFILE" 2>&1 || fatal "Docker install failed. See $LOGFILE"
    rm -f /tmp/get-docker.sh
    ok "Docker installed."
  fi

  detect_docker_compose_cmd
  if [ -z "${DOCKER_COMPOSE_CMD:-}" ]; then
    info "Installing docker-compose (standalone)..."
    COMPOSE_BIN="/usr/local/bin/docker-compose"
    curl -fsSL "https://github.com/docker/compose/releases/latest/download/docker-compose-$(uname -s)-$(uname -m)" -o "$COMPOSE_BIN" >>"$LOGFILE" 2>&1 || fatal "docker-compose download failed."
    chmod +x "$COMPOSE_BIN"
    ln -sf "$COMPOSE_BIN" /usr/bin/docker-compose
    DOCKER_COMPOSE_CMD="docker-compose"
    ok "docker-compose installed."
  else
    ok "Docker compose available: ${DOCKER_COMPOSE_CMD}"
  fi

  systemctl enable docker >/dev/null 2>&1 || true
  systemctl start docker >/dev/null 2>&1 || true
}

# -------------------------
# Compose file creation (Docker path)
# -------------------------
create_compose_file() {
  local host="$1"; local wg_port="$2"; local gui_http="$3"; local gui_https="$4"; local admin_pass="$5"
  mkdir -p "$DASHBOARD_DIR/data"
  local dashboard_image="${WG_DASHBOARD_IMAGE:-$WG_DASHBOARD_IMAGE_DEFAULT}"
  cat > "$COMPOSE_FILE" <<EOF
version: '3.8'
services:
  evxotech-wg-dashboard:
    image: ${dashboard_image}
    container_name: evxotech-wg-dashboard
    restart: unless-stopped
    environment:
      - WG_HOST=${host}
      - PASSWORD=${admin_pass}
      - WG_PORT=${wg_port}
      - WG_DEFAULT_ADDRESS=10.120.80.x
      - WG_MTU=1420
      - WG_PERSISTENT_KEEPALIVE=25
    ports:
      - "${wg_port}:${wg_port}/udp"
      - "${gui_http}:10080/tcp"
      - "${gui_https}:10443/tcp"
    volumes:
      - ${DASHBOARD_DIR}/data:/etc/wireguard
    cap_add:
      - NET_ADMIN
      - SYS_MODULE
    sysctls:
      - net.ipv4.ip_forward=1
EOF
  log "docker-compose written to ${COMPOSE_FILE} (image: ${dashboard_image})"
}

# -------------------------
# Start stack with fallback
# -------------------------
start_dashboard_stack() {
  detect_docker_compose_cmd
  if [ -z "${DOCKER_COMPOSE_CMD:-}" ]; then
    fatal "docker-compose not available. Aborting."
  fi

  info "Attempting to pull dashboard image: ${WG_DASHBOARD_IMAGE:-$WG_DASHBOARD_IMAGE_DEFAULT}"
  if ! docker pull "${WG_DASHBOARD_IMAGE:-$WG_DASHBOARD_IMAGE_DEFAULT}" >>"$LOGFILE" 2>&1; then
    warn "Failed to pull ${WG_DASHBOARD_IMAGE:-$WG_DASHBOARD_IMAGE_DEFAULT}. Falling back to ${WG_EASY_FALLBACK}."
    WG_DASHBOARD_IMAGE="$WG_EASY_FALLBACK"
    create_compose_file "$PUBLIC_HOST" "$WG_PORT" "$DASH_HTTP" "$DASH_HTTPS" "$ADMIN_PASS"
    docker pull "$WG_DASHBOARD_IMAGE" >>"$LOGFILE" 2>&1 || fatal "Failed to pull fallback image ${WG_DASHBOARD_IMAGE}. Check network."
  fi

  info "Starting dashboard stack via ${DOCKER_COMPOSE_CMD}..."
  $DOCKER_COMPOSE_CMD -f "$COMPOSE_FILE" up -d >>"$LOGFILE" 2>&1 || fatal "docker-compose up failed. See $LOGFILE"
  ok "Dashboard stack started (container: evxotech-wg-dashboard)."
}

# -------------------------
# Systemd service for compose stack
# -------------------------
create_systemd_service() {
  cat > "$SYSTEMD_SERVICE" <<EOF
[Unit]
Description=EvxoTech WG Dashboard (Docker Compose)
Requires=docker.service
After=docker.service

[Service]
Type=oneshot
WorkingDirectory=${DASHBOARD_DIR}
ExecStart=${DOCKER_COMPOSE_CMD} -f ${COMPOSE_FILE} up -d
ExecStop=${DOCKER_COMPOSE_CMD} -f ${COMPOSE_FILE} down
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF
  systemctl daemon-reload
  systemctl enable evxotech-wg-dashboard.service >/dev/null 2>&1 || true
  ok "Systemd service created at ${SYSTEMD_SERVICE}"
}

# -------------------------
# Native WireGuard install (if Docker not available)
# -------------------------
install_native_wireguard() {
  info "Installing native WireGuard packages..."
  apt-get update -y >>"$LOGFILE" 2>&1
  apt-get install -y wireguard qrencode iptables iproute2 curl >>"$LOGFILE" 2>&1 || fatal "Failed to install WireGuard packages."
  ok "WireGuard packages installed."

  # create /etc/wireguard and server keys
  mkdir -p /etc/wireguard
  chmod 700 /etc/wireguard
  umask 077
  if [ ! -f /etc/wireguard/server_private.key ]; then
    wg genkey | tee /etc/wireguard/server_private.key >/dev/null
    wg pubkey < /etc/wireguard/server_private.key > /etc/wireguard/server_public.key
  fi
  SERVER_PRIV_KEY=$(cat /etc/wireguard/server_private.key)

  # server IP address derived from CIDR base (.1)
  BASE_PREFIX=$(echo "$WG_CIDR_DEFAULT" | cut -d'/' -f1 | awk -F. '{print $1"."$2"."$3}')
  SERVER_WG_IP="${BASE_PREFIX}.1"

  cat > /etc/wireguard/wg0.conf <<EOF
[Interface]
Address = ${SERVER_WG_IP}/24
ListenPort = ${WG_PORT}
PrivateKey = ${SERVER_PRIV_KEY}
SaveConfig = true
EOF

  sysctl -w net.ipv4.ip_forward=1 >>"$LOGFILE" 2>&1 || true
  sed -i '/^net.ipv4.ip_forward/ s/.*/net.ipv4.ip_forward=1/' /etc/sysctl.conf || echo "net.ipv4.ip_forward=1" >> /etc/sysctl.conf

  systemctl enable "wg-quick@wg0" >/dev/null 2>&1 || true
  if wg-quick up wg0 >>"$LOGFILE" 2>&1; then
    ok "wg0 interface started."
  else
    warn "wg-quick up wg0 failed. Check $LOGFILE and /etc/wireguard/wg0.conf"
  fi
}

# -------------------------
# Helper script to add client (optional)
# -------------------------
install_helper() {
  cat > /usr/local/bin/evxotech-wg-add-client <<'BASH'
#!/usr/bin/env bash
# Simple helper: create a client.conf for native WireGuard installs or instruct GUI for Docker installs.
NAME="$1"
if [ -z "$NAME" ]; then echo "Usage: $0 <clientname>"; exit 1; fi
if [ -d /opt/evxotech/wg-dashboard/data ]; then
  echo "Dashboard-managed installation detected. Use GUI to add clients, or exec into container."
  echo "Example: docker exec -it evxotech-wg-dashboard /bin/sh"
else
  CLIENT_DIR="/root/wireguard-clients"
  mkdir -p "$CLIENT_DIR"
  CLIENT_PRIV=$(wg genkey)
  CLIENT_PUB=$(echo "$CLIENT_PRIV" | wg pubkey)
  BASE=$(echo "$WG_CIDR_DEFAULT" | awk -F. '{print $1"."$2"."$3}')
  # naive allocation: find free addresses in 10.120.80.2-250
  USED=$(grep -h "^Address" $CLIENT_DIR/*.conf 2>/dev/null | awk '{print $3}' | cut -d'/' -f1 || true)
  IP=""
  for i in $(seq 2 250); do
    CAND="${BASE}.${i}"
    if ! echo "$USED" | grep -q "^${CAND}$"; then IP="${CAND}"; break; fi
  done
  if [ -z "$IP" ]; then echo "No free IP"; exit 1; fi
  SERVER_PUB=$(wg pubkey < /etc/wireguard/server_private.key 2>/dev/null || true)
  cat > "${CLIENT_DIR}/${NAME}.conf" <<EOF
[Interface]
PrivateKey = ${CLIENT_PRIV}
Address = ${IP}/24
DNS = ${CLIENT_DNS_DEFAULT}

[Peer]
PublicKey = ${SERVER_PUB}
Endpoint = ${PUBLIC_HOST}:${WG_PORT}
AllowedIPs = ${WG_CIDR_DEFAULT}
PersistentKeepalive = 25
EOF
  chmod 600 "${CLIENT_DIR}/${NAME}.conf"
  echo "Client config written: ${CLIENT_DIR}/${NAME}.conf"
fi
BASH
  chmod +x /usr/local/bin/evxotech-wg-add-client
  ok "Installed helper /usr/local/bin/evxotech-wg-add-client (GUI recommended for Docker installs)."
}

# -------------------------
# Write uninstaller helper script
# -------------------------
write_uninstaller_file() {
  cat > "$UNINSTALL_SCRIPT" <<'SH'
#!/usr/bin/env bash
echo "EvxoTech WireGuard full uninstaller helper"
read -rp "Type YES to permanently remove data and containers: " CONF
if [[ "$CONF" != "YES" ]]; then echo "Aborted."; exit 0; fi
systemctl stop evxotech-wg-dashboard.service 2>/dev/null || true
systemctl disable evxotech-wg-dashboard.service 2>/dev/null || true
if command -v docker >/dev/null 2>&1; then
  docker-compose -f /opt/evxotech/wg-dashboard/docker-compose.yml down 2>/dev/null || docker compose -f /opt/evxotech/wg-dashboard/docker-compose.yml down 2>/dev/null || true
  docker rm -f evxotech-wg-dashboard 2>/dev/null || true
fi
rm -rf /opt/evxotech/wg-dashboard /opt/evxotech/wg-data /etc/evxotech 2>/dev/null || true
rm -f /usr/local/bin/evxotech-wg-add-client /root/evxotech-wireguard-uninstaller.sh 2>/dev/null || true
echo "Uninstall complete."
SH
  chmod +x "$UNINSTALL_SCRIPT"
  ok "Uninstaller written to ${UNINSTALL_SCRIPT}"
}

# -------------------------
# Open firewall ports (ufw preferred)
# -------------------------
open_firewall() {
  local wg="$1" gui="$2"
  if command -v ufw >/dev/null 2>&1; then
    ufw allow "${wg}/udp" >/dev/null 2>&1 || true
    ufw allow "${gui}/tcp" >/dev/null 2>&1 || true
    ok "Opened ports ${wg}/udp and ${gui}/tcp via ufw."
  else
    iptables -I INPUT -p udp --dport "$wg" -j ACCEPT || true
    iptables -I INPUT -p tcp --dport "$gui" -j ACCEPT || true
    ok "Inserted iptables rules for ${wg}/udp and ${gui}/tcp (non-persistent)."
  fi
}

# -------------------------
# Main installer (semi-automated)
# -------------------------
main() {
  require_root
  precheck

  # auto-detect values
  PUBLIC_HOST="${PUBLIC_IP_AUTO:-$(curl -fs4 ifconfig.co 2>/dev/null || echo "")}"
  SERVER_LAN_IP="$(hostname -I 2>/dev/null | awk '{print $1}' || true)"
  WG_PORT="${WG_PORT_DEFAULT}"
  DASH_HTTP="${DASH_HTTP_DEFAULT}"
  DASH_HTTPS="${DASH_HTTPS_DEFAULT}"
  ADMIN_USER="${ADMIN_USER_DEFAULT}"
  ADMIN_PASS="${ADMIN_PASS_DEFAULT}"
  WG_CIDR="${WG_CIDR_DEFAULT}"
  CLIENTS="${CLIENTS_DEFAULT}"
  CLIENT_DNS="${CLIENT_DNS_DEFAULT}"
  WG_DASHBOARD_IMAGE="${WG_DASHBOARD_IMAGE_DEFAULT}"

  echo
  echo -e "${BLUE}EvxoTech WireGuard Installer — ${VERSION}${NC}"
  echo -e "${CYAN}Auto-detected values (edit in code if you want different defaults):${NC}"
  echo " Public host: ${PUBLIC_HOST}"
  echo " Server LAN IP: ${SERVER_LAN_IP}"
  echo " WireGuard UDP port: ${WG_PORT}"
  echo " Dashboard HTTP (host port): ${DASH_HTTP}"
  echo " Dashboard HTTPS (host port): ${DASH_HTTPS}"
  echo " Dashboard admin user: ${ADMIN_USER}"
  echo " Dashboard admin pass: ${ADMIN_PASS}"
  echo " WG internal CIDR: ${WG_CIDR}"
  echo " Initial clients to create: ${CLIENTS}"
  echo " DNS to push to clients: ${CLIENT_DNS}"
  echo

  read -rp $'\e[33mProceed with these values? (y/N): \e[0m' PROCEED
  if [[ ! "${PROCEED}" =~ ^[Yy]$ ]]; then
    fatal "Aborted by user."
  fi

  # If Docker is available, prefer Docker-based GUI install
  if command -v docker >/dev/null 2>&1; then
    info "Docker detected — using Docker-based dashboard (preferred for LXC)."
    install_docker_if_needed
    # ensure docker-compose cmd is set
    detect_docker_compose_cmd
    if [ -z "${DOCKER_COMPOSE_CMD:-}" ]; then
      fatal "docker compose/tool not available after install."
    fi

    # create compose file and try to start dashboard, with fallback
    create_compose_file "${PUBLIC_HOST}" "${WG_PORT}" "${DASH_HTTP}" "${DASH_HTTPS}" "${ADMIN_PASS}"
    start_dashboard_stack
    create_systemd_service
    install_helper
    write_uninstaller_file
    open_firewall "${WG_PORT}" "${DASH_HTTP}"
    ok "Installation complete (Docker-based GUI)."
    echo
    ok "Web GUI (HTTP): http://${PUBLIC_HOST}:${DASH_HTTP}"
    ok "Web GUI (HTTPS): https://${PUBLIC_HOST}:${DASH_HTTPS}"
    ok "Admin user: ${ADMIN_USER}  (password: ${ADMIN_PASS})"
    ok "Persistent data: ${DASHBOARD_DIR}/data"
  else
    info "Docker not detected — using native WireGuard + local dashboard setup."
    install_native_wireguard
    # For native GUI: attempt to fetch wg-dashboard-pro repository (if exists) or instruct user
    mkdir -p "$DASHBOARD_DIR"
    info "Attempting to install wg-dashboard-pro in ${DASHBOARD_DIR} (native path)."
    if command -v git >/dev/null 2>&1; then
      if git clone --depth 1 "https://github.com/evxotech/wg-dashboard-pro.git" "$DASHBOARD_DIR" >>"$LOGFILE" 2>&1; then
        ok "Cloned wg-dashboard-pro into ${DASHBOARD_DIR} (if repo exists)."
        # Node/PM2 install
        if command -v npm >/dev/null 2>&1; then
          info "Installing Node dependencies..."
          (cd "$DASHBOARD_DIR" && npm install --production) >>"$LOGFILE" 2>&1 || warn "npm install failed."
        else
          warn "npm not found; GUI may not install fully. Install Node.js & npm to enable dashboard."
        fi
        # Create simple systemd service stub (user may need to edit)
        cat > /etc/systemd/system/evxotech-wg-dashboard.service <<EOF
[Unit]
Description=EvxoTech WG Dashboard (native)
After=network.target

[Service]
Type=simple
WorkingDirectory=${DASHBOARD_DIR}
ExecStart=/usr/bin/npm start
Restart=always

[Install]
WantedBy=multi-user.target
EOF
        systemctl daemon-reload
        systemctl enable evxotech-wg-dashboard.service >/dev/null 2>&1 || true
        systemctl start evxotech-wg-dashboard.service >/dev/null 2>&1 || true
        ok "Native dashboard service created as evxotech-wg-dashboard.service (may require manual tuning)."
      else
        warn "Could not clone wg-dashboard-pro. GUI not installed. Please install GUI manually."
      fi
    else
      warn "git not available; cannot fetch dashboard repository. GUI installation skipped."
    fi

    install_helper
    write_uninstaller_file
    open_firewall "${WG_PORT}" "${DASH_HTTP}"
    ok "Installation complete (native WireGuard + optional dashboard)."
    echo
    ok "WireGuard server: ensure wg-quick@wg0 is running and dashboard installed manually if needed."
  fi

  log "Installation finished."
  ok "Logs: ${LOGFILE}"
  ok "To remove everything later: sudo ${0} --uninstall"
}

# Run main
main

exit 0
