#!/bin/bash
set -e

if [ "$EUID" -ne 0 ]; then
    echo "Please run this installer as root (sudo)."
    exit 1
fi

echo "==> Installing Wazuh bootstrap..."

mkdir -p /opt/wazuh-bootstrap /etc/wazuh-bootstrap

cp wazuh_bootstrap.sh wazuh_enroll.sh /opt/wazuh-bootstrap/
chmod +x /opt/wazuh-bootstrap/*.sh

cp bootstrap.conf.example /etc/wazuh-bootstrap/bootstrap.conf
chmod 600 /etc/wazuh-bootstrap/bootstrap.conf

echo "==> Installing systemd units..."

cp wazuh-bootstrap.service wazuh-bootstrap.timer /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now wazuh-bootstrap.timer
systemctl start wazuh-bootstrap.service

echo "==> Done. wazuh-bootstrap.timer is enabled and running."