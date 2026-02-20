#!/usr/bin/env bash
# Install Terraform Registry as a standalone binary service.
# Usage: sudo ./install.sh [--binary PATH] [--frontend PATH]
#
# Prerequisites:
#   - Linux system with systemd
#   - PostgreSQL installed and running
#   - nginx installed
#   - (Optional) certbot for Let's Encrypt TLS
#
# This script:
#   1. Creates registry user/group
#   2. Creates directory structure
#   3. Copies binary and frontend files
#   4. Installs systemd service
#   5. Installs nginx site config
#   6. Prints next steps

set -euo pipefail

INSTALL_DIR="/opt/terraform-registry"
CONFIG_DIR="/etc/terraform-registry"
LOG_DIR="/var/log/terraform-registry"
BINARY_PATH=""
FRONTEND_PATH=""

# Parse arguments
while [[ $# -gt 0 ]]; do
  case "$1" in
    --binary)  BINARY_PATH="$2"; shift 2 ;;
    --frontend) FRONTEND_PATH="$2"; shift 2 ;;
    -h|--help)
      echo "Usage: sudo $0 [--binary PATH_TO_BINARY] [--frontend PATH_TO_FRONTEND_DIST]"
      exit 0
      ;;
    *) echo "Unknown option: $1"; exit 1 ;;
  esac
done

# Must be root
if [ "$(id -u)" -ne 0 ]; then
  echo "ERROR: This script must be run as root (use sudo)." >&2
  exit 1
fi

echo "==> Installing Terraform Registry"
echo "    Install directory: ${INSTALL_DIR}"
echo "    Config directory:  ${CONFIG_DIR}"
echo ""

# Create system user
echo "==> Creating system user 'registry'..."
if ! id -u registry &>/dev/null; then
  useradd --system --home-dir "$INSTALL_DIR" --shell /usr/sbin/nologin registry
fi

# Create directories
echo "==> Creating directories..."
mkdir -p "$INSTALL_DIR"/{storage,frontend}
mkdir -p "$CONFIG_DIR"
mkdir -p "$LOG_DIR"

# Copy binary
if [ -n "$BINARY_PATH" ] && [ -f "$BINARY_PATH" ]; then
  echo "==> Copying binary..."
  cp "$BINARY_PATH" "$INSTALL_DIR/terraform-registry"
  chmod 755 "$INSTALL_DIR/terraform-registry"
else
  echo "    SKIP: No --binary provided. Copy the binary to $INSTALL_DIR/terraform-registry manually."
fi

# Copy frontend
if [ -n "$FRONTEND_PATH" ] && [ -d "$FRONTEND_PATH" ]; then
  echo "==> Copying frontend files..."
  cp -r "$FRONTEND_PATH"/* "$INSTALL_DIR/frontend/"
else
  echo "    SKIP: No --frontend provided. Copy frontend dist to $INSTALL_DIR/frontend/ manually."
fi

# Install environment file (don't overwrite existing)
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [ ! -f "$CONFIG_DIR/environment" ]; then
  echo "==> Installing environment template..."
  cp "$SCRIPT_DIR/environment" "$CONFIG_DIR/environment"
  chmod 640 "$CONFIG_DIR/environment"
  chown root:registry "$CONFIG_DIR/environment"
else
  echo "    SKIP: ${CONFIG_DIR}/environment already exists."
fi

# Install systemd service
echo "==> Installing systemd service..."
cp "$SCRIPT_DIR/terraform-registry.service" /etc/systemd/system/terraform-registry.service
systemctl daemon-reload

# Install nginx config (don't overwrite existing)
if [ -d /etc/nginx/sites-available ]; then
  if [ ! -f /etc/nginx/sites-available/terraform-registry ]; then
    echo "==> Installing nginx site config..."
    cp "$SCRIPT_DIR/nginx-registry.conf" /etc/nginx/sites-available/terraform-registry
    echo "    Enable with: ln -s /etc/nginx/sites-available/terraform-registry /etc/nginx/sites-enabled/"
  else
    echo "    SKIP: nginx config already exists."
  fi
else
  echo "    SKIP: /etc/nginx/sites-available not found. Install nginx and copy nginx-registry.conf manually."
fi

# Set ownership
echo "==> Setting file ownership..."
chown -R registry:registry "$INSTALL_DIR"
chown -R registry:registry "$LOG_DIR"

echo ""
echo "==> Installation complete!"
echo ""
echo "Next steps:"
echo "  1. Edit ${CONFIG_DIR}/environment with your database and secret values:"
echo "       sudo editor ${CONFIG_DIR}/environment"
echo ""
echo "  2. Create the PostgreSQL database and user:"
echo "       sudo -u postgres createuser registry"
echo "       sudo -u postgres createdb -O registry terraform_registry"
echo ""
echo "  3. Update the nginx config with your domain name:"
echo "       sudo editor /etc/nginx/sites-available/terraform-registry"
echo ""
echo "  4. (Optional) Set up TLS with Let's Encrypt:"
echo "       sudo certbot --nginx -d registry.example.com"
echo ""
echo "  5. Enable and start the services:"
echo "       sudo ln -s /etc/nginx/sites-available/terraform-registry /etc/nginx/sites-enabled/"
echo "       sudo nginx -t && sudo systemctl reload nginx"
echo "       sudo systemctl enable --now terraform-registry"
echo ""
echo "  6. Check status:"
echo "       sudo systemctl status terraform-registry"
echo "       curl -s http://localhost:8080/health"
