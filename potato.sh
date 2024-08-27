#!/bin/bash

# Prompt for network variables
read -p "Enter the network interface name (e.g., eth0): " interface_name
read -p "Enter the gateway IP (e.g., 1.1.1.254): " gateway
read -p "Enter the subnet mask in CIDR format (e.g., 25 for 255.255.255.128): " netmask
read -p "Enter the starting IP last octet (e.g., 129): " ip_start
read -p "Enter the ending IP last octet (e.g., 253): " ip_end
read -p "Enter the network address in CIDR format (e.g., 1.1.1.0/25): " network
whitelist_file="/etc/squid/whitelist.txt"

# Extract the base IP from the network address
IFS='/' read -r base_ip cidr <<< "$network"
IFS='.' read -r ip1 ip2 ip3 ip4 <<< "$base_ip"

# Update and Upgrade the System
echo "Updating system packages..."
sudo apt-get update && sudo apt-get upgrade -y

# Install Squid and UFW
echo "Installing Squid proxy server and UFW..."
sudo apt-get install squid ufw -y

# Setup UFW rules
echo "Setting up UFW rules..."
sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw allow 3128/tcp
sudo ufw allow 22/tcp
sudo ufw enable

# Generate addresses for netplan
addresses=""
for ((i=$ip_start; i<=$ip_end; i++)); do
    addresses+="- $ip1.$ip2.$ip3.$i/$netmask"$'\n'"        "
done

# Setup netplan configuration for static IPs
echo "Setting up static IPs..."
sudo bash -c "cat << EOF > /etc/netplan/01-netcfg.yaml
network:
  version: 2
  renderer: networkd
  ethernets:
    $interface_name:
      addresses:
        $addresses
      gateway4: $gateway
      nameservers:
        addresses:
          - 8.8.8.8
          - 8.8.4.4
EOF"

# Apply netplan changes
echo "Applying netplan changes..."
sudo netplan apply

# Enable IP forwarding
echo "Enabling IP forwarding..."
sudo sysctl -w net.ipv4.ip_forward=1
sudo bash -c 'echo "net.ipv4.ip_forward = 1" >> /etc/sysctl.conf'

# Setup IP tables for routing
echo "Setting up IP tables for routing..."
sudo iptables -t nat -A POSTROUTING -s $network -o $interface_name -j MASQUERADE

# Backup the original Squid configuration
echo "Backing up original Squid config..."
sudo cp /etc/squid/squid.conf /etc/squid/squid.conf.backup

# Create whitelist file with appropriate IPs
echo "Creating whitelist file..."
sudo bash -c 'for i in $(seq 2 254); do echo "192.168.1.$i"; done > '"$whitelist_file"''

# Configure Squid with IP-specific rules, whitelist, and access control
echo "Configuring Squid with IP-specific rules and whitelist..."
sudo bash -c 'cat << EOF > /etc/squid/squid.conf
acl allowed_ips src "/etc/squid/whitelist.txt"
http_access allow allowed_ips
acl localnet src $network  # ACL for local network
http_access allow localnet
http_access deny all
visible_hostname proxyserver
forwarded_for delete
via off
request_header_access X-Forwarded-For deny all
EOF'

# Append http_port, acl, and tcp_outgoing_address for each IP
for ((i=$ip_start; i<=$ip_end; i++)); do
    ip="$ip1.$ip2.$ip3.$i"
    sudo bash -c "echo 'acl ip$i myip $ip' >> /etc/squid/squid.conf"
    sudo bash -c "echo 'http_port $ip:3128' >> /etc/squid/squid.conf"
    sudo bash -c "echo 'tcp_outgoing_address $ip ip$i' >> /etc/squid/squid.conf"
done

# Check for configuration errors in Squid
sudo squid -k parse

# Restart Squid
echo "Restarting Squid service..."
sudo systemctl restart squid

echo "Proxy setup complete. Squid is running and configured with static IPs, IP whitelist, and specific ACLs for each IP."
