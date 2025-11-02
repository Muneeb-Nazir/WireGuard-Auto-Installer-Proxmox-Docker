#!/bin/bash
# Save as: wireguard-installer.sh
# Usage: ./wireguard-installer.sh {install|uninstall|status}

set -e

# Color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Configuration
WG_DIR="/opt/wireguard"
COMPOSE_FILE="$WG_DIR/docker-compose.yml"
SERVICE_FILE="/etc/systemd/system/wireguard.service"
CONTAINER_NAME="wg-easy"

# Functions
print_status() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

detect_os() {
    if [[ -f /etc/os-release ]]; then
        source /etc/os-release
        echo "$NAME $VERSION_ID"
    else
        echo "Unknown"
    fi
}

get_ip() {
    PUBLIC_IP=$(curl -s -4 ifconfig.co || curl -s -4 icanhazip.com || echo "unknown")
    PRIVATE_IP=$(hostname -I | awk '{print $1}')
    echo "$PUBLIC_IP"
}

check_dependencies() {
    local missing=()
    
    if ! command -v docker &> /dev/null; then
        missing+=("docker")
    fi
    
    if ! command -v docker-compose &> /dev/null; then
        missing+=("docker-compose")
    fi
    
    if [[ ${#missing[@]} -ne 0 ]]; then
        print_status "Installing missing dependencies: ${missing[*]}"
        install_dependencies
    fi
}

install_dependencies() {
    apt update
    apt install -y curl
    
    # Install Docker
    if ! command -v docker &> /dev/null; then
        curl -fsSL https://get.docker.com -o get-docker.sh
        sh get-docker.sh
        usermod -aG docker $USER
    fi
    
    # Install Docker Compose
    if ! command -v docker-compose &> /dev/null; then
        curl -L "https://github.com/docker/compose/releases/latest/download/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
        chmod +x /usr/local/bin/docker-compose
        ln -sf /usr/local/bin/docker-compose /usr/bin/docker-compose
    fi
    
    # Start and enable Docker
    systemctl enable docker
    systemctl start docker
}

create_docker_compose() {
    local server_ip=$1
    local admin_password=$2
    
    cat > "$COMPOSE_FILE" << EOF
version: '3.8'
services:
  wg-easy:
    image: weejewel/wg-easy
    container_name: $CONTAINER_NAME
    restart: unless-stopped
    environment:
      - WG_HOST=$server_ip
      - PASSWORD=$admin_password
      - WG_PORT=51820
      - WG_DEFAULT_ADDRESS=10.8.0.x
      - WG_DEFAULT_DNS=1.1.1.1,8.8.8.8
      - WG_MTU=1420
      - WG_PERSISTENT_KEEPALIVE=25
    ports:
      - "51820:51820/udp"
      - "51821:51821/tcp"
    volumes:
      - $WG_DIR/data:/etc/wireguard
    cap_add:
      - NET_ADMIN
      - SYS_MODULE
    sysctls:
      - net.ipv4.ip_forward=1
      - net.ipv4.conf.all.src_valid_mark=1
    logging:
      driver: "json-file"
      options:
        max-size: "10m"
        max-file: "3"
EOF
}

create_systemd_service() {
    cat > "$SERVICE_FILE" << EOF
[Unit]
Description=WireGuard VPN with Web GUI
Requires=docker.service
After=docker.service

[Service]
Type=oneshot
RemainAfterExit=yes
WorkingDirectory=$WG_DIR
ExecStart=/usr/bin/docker-compose up -d
ExecStop=/usr/bin/docker-compose down
TimeoutStartSec=0

[Install]
WantedBy=multi-user.target
EOF
}

install_wireguard() {
    print_status "Starting WireGuard installation..."
    
    # Detect system info
    OS_INFO=$(detect_os)
    SERVER_IP=$(get_ip)
    
    print_status "Detected OS: $OS_INFO"
    print_status "Server IP: $SERVER_IP"
    
    # Check dependencies
    check_dependencies
    
    # Create directory
    mkdir -p "$WG_DIR"
    
    # Get admin password
    read -sp "Set admin password for Web GUI (default: ChangeMe123): " ADMIN_PASSWORD
    ADMIN_PASSWORD=${ADMIN_PASSWORD:-ChangeMe123}
    echo
    
    # Create docker-compose file
    print_status "Creating Docker Compose configuration..."
    create_docker_compose "$SERVER_IP" "$ADMIN_PASSWORD"
    
    # Create systemd service
    print_status "Creating systemd service..."
    create_systemd_service
    
    # Start the service
    print_status "Starting WireGuard service..."
    systemctl daemon-reload
    systemctl enable wireguard.service
    systemctl start wireguard.service
    
    # Wait for container to start
    print_status "Waiting for services to start..."
    sleep 10
    
    # Check if running
    if docker ps | grep -q "$CONTAINER_NAME"; then
        print_success "WireGuard installation completed successfully!"
        show_connection_info "$SERVER_IP" "$ADMIN_PASSWORD"
    else
        print_error "Container failed to start. Check logs with: docker logs $CONTAINER_NAME"
        exit 1
    fi
}

uninstall_wireguard() {
    print_status "Starting WireGuard uninstallation..."
    
    # Stop and disable service
    if systemctl is-active --quiet wireguard.service; then
        print_status "Stopping WireGuard service..."
        systemctl stop wireguard.service
        systemctl disable wireguard.service
    fi
    
    # Remove service file
    if [[ -f "$SERVICE_FILE" ]]; then
        rm -f "$SERVICE_FILE"
        systemctl daemon-reload
    fi
    
    # Stop and remove container
    if docker ps -a | grep -q "$CONTAINER_NAME"; then
        print_status "Removing Docker container..."
        docker stop "$CONTAINER_NAME" 2>/dev/null || true
        docker rm "$CONTAINER_NAME" 2>/dev/null || true
    fi
    
    # Remove Docker Compose setup
    if [[ -d "$WG_DIR" ]]; then
        print_status "Removing Docker Compose setup..."
        cd "$WG_DIR" 2>/dev/null && docker-compose down 2>/dev/null || true
    fi
    
    # Ask about data removal
    read -p "Remove all WireGuard data and configurations? (y/N): " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        rm -rf "$WG_DIR"
        print_success "All WireGuard data removed."
    else
        print_warning "WireGuard data kept in $WG_DIR"
    fi
    
    print_success "WireGuard uninstallation completed!"
}

show_status() {
    print_status "=== WireGuard Installation Status ==="
    
    # Check Docker
    if command -v docker &> /dev/null; then
        print_success "Docker: Installed"
    else
        print_error "Docker: Not installed"
    fi
    
    # Check Docker Compose
    if command -v docker-compose &> /dev/null; then
        print_success "Docker Compose: Installed"
    else
        print_error "Docker Compose: Not installed"
    fi
    
    # Check service
    if systemctl is-enabled wireguard.service &> /dev/null; then
        print_success "Systemd Service: Enabled"
    else
        print_warning "Systemd Service: Not enabled"
    fi
    
    if systemctl is-active wireguard.service &> /dev/null; then
        print_success "Systemd Service: Active"
    else
        print_warning "Systemd Service: Not active"
    fi
    
    # Check container
    if docker ps | grep -q "$CONTAINER_NAME"; then
        print_success "Container: Running"
        local container_ip=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$CONTAINER_NAME" 2>/dev/null || echo "unknown")
        print_status "Container IP: $container_ip"
    else
        print_warning "Container: Not running"
    fi
    
    # Check ports
    if netstat -tuln | grep -q ':51821'; then
        print_success "Web GUI Port (51821): Listening"
    else
        print_warning "Web GUI Port (51821): Not listening"
    fi
    
    if netstat -tuln | grep -q ':51820'; then
        print_success "WireGuard Port (51820/udp): Listening"
    else
        print_warning "WireGuard Port (51820/udp): Not listening"
    fi
}

show_connection_info() {
    local server_ip=$1
    local password=$2
    
    echo
    print_success "=== Connection Information ==="
    echo -e "${GREEN}Web GUI URL:${NC} http://$server_ip:51821"
    echo -e "${GREEN}Username:${NC} admin"
    echo -e "${GREEN}Password:${NC} $password"
    echo -e "${GREEN}WireGuard Port:${NC} 51820/udp"
    echo
    echo -e "${YELLOW}Important:${NC}"
    echo "- Make sure port 51820/udp is open in your firewall"
    echo "- Server will auto-start after reboot"
    echo "- Check status with: ./$(basename "$0") status"
    echo "- Uninstall with: ./$(basename "$0") uninstall"
    echo
}

# Main script
case "${1:-}" in
    install)
        install_wireguard
        ;;
    uninstall)
        uninstall_wireguard
        ;;
    status)
        show_status
        ;;
    *)
        echo "Usage: $0 {install|uninstall|status}"
        echo
        echo "Options:"
        echo "  install   - Install WireGuard with auto-start"
        echo "  uninstall - Remove WireGuard installation"
        echo "  status    - Show current installation status"
        exit 1
        ;;
esac
